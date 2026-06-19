#!/usr/bin/env python3
"""
Brother ADS-1350W push-to-scan daemon (newer Brother protocol).

Registers with the scanner via SNMP, listens for button press events
on TCP 54950, then connects to the scanner's data channel on TCP 54921
to receive scan data.

Usage:
    python3 brother_scan.py <scanner_ip> [--hostname NAME] [--output-dir DIR]
"""

import argparse
import configparser
import json
import logging
import os
import socket
import time
import threading

from PIL import Image

log = logging.getLogger("brother-scan")

# Brother-specific SNMP OIDs
OID_PRINTER_STATUS = (1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 4, 2, 1, 5, 5, 6, 0)
OID_REGISTER_KEY_V2 = (1, 3, 6, 1, 4, 1, 2435, 2, 4, 3, 2435, 5, 58, 2, 0)

SNMP_PORT = 161
BUTTON_PORT = 54950       # TCP — scanner connects to us here
DATA_PORT = 54921         # TCP — we connect to scanner here
REGISTER_DURATION_SEC = 360

VALID_STATUSES = {10001: "ready", 10006: "low ink/toner",
                  40000: "unknown (OK)", 40038: "empty ink/toner"}

# Protocol commands (ESC sequences)
CMD_HANDSHAKE  = b"\x1b\x51\x0a\x80"         # Initial handshake
CMD_QUERY_CAPS = b"\x1b\x51\x44\x49\x0a\x80" # Query detailed capabilities
CMD_GET_PAGE   = b"\x1b\x47\x43\x50\x0a\x80" # Get current page info

# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

def load_config(config_path: str) -> tuple[dict, dict[int, dict], dict]:
    """Load scanner settings and scan profiles from a config file.

    Returns (scanner_settings, profiles_dict, default_profile).
    """
    cp = configparser.ConfigParser()
    cp.read(config_path)

    scanner = {
        "ip": "192.168.4.158",
        "hostname": "scan",
        "output_dir": ".",
    }
    if cp.has_section("scanner"):
        for key in scanner:
            if cp.has_option("scanner", key):
                scanner[key] = cp.get("scanner", key)
        # Expand ~ in output_dir
        scanner["output_dir"] = os.path.expanduser(scanner["output_dir"])

    profiles = {}
    default = {
        "name": "Duplex Color PDF",
        "reso": "300,300",
        "color": "C24BIT",
        "duplex": "ON",
        "output": "pdf",
    }

    for section in cp.sections():
        profile = dict(cp[section])
        if section == "default":
            default = profile
        elif section.startswith("button."):
            try:
                num = int(section.split(".", 1)[1])
                profiles[num] = profile
            except ValueError:
                log.warning("Ignoring invalid section: %s", section)

    return scanner, profiles, default


# Base scan parameters template (format with profile values)
SCAN_PARAMS_TEMPLATE = (
    "OS=LINUX\n"
    "PSRC=AUTO\n"
    "RESO={reso}\n"
    "CLR={color}\n"
    "AREA=ATDSKW\n"
    "MRGN=0,0,0,0\n"
    "DPLX={duplex}\n"
    "BRIT=50\n"
    "CONT=50\n"
    "COMP=JPEG\n"
    "JSF=420\n"
    "IPRC=NORMAL\n"
    "PTYPE=NORMAL\n"
    "PAGE=0\n"
    "LONG=OFF\n"
    "CARR=OFF\n"
    "RMGC=OFF\n"
    "DTDF=OFF\n"
    "DT4V=OFF\n"
    "DSKW=ON\n"
    "LSMD=OFF\n"
    "RMBP=OFF\n"
    "RMMR=OFF\n"
    "GMMA=OFF\n"
    "TONE=OFF\n"
    "QTFD=OFF\n"
    "ATCN=OFF\n"
    "ATCRP=ON\n"
)

# ---------------------------------------------------------------------------
# Minimal BER / SNMPv1 codec
# ---------------------------------------------------------------------------

def ber_encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

def ber_encode_int(value: int) -> bytes:
    if value == 0:
        payload = b"\x00"
    else:
        neg = value < 0
        if neg:
            payload = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
        else:
            octets = []
            v = value
            while v > 0:
                octets.append(v & 0xFF)
                v >>= 8
            octets.reverse()
            if octets[0] & 0x80:
                octets.insert(0, 0)
            payload = bytes(octets)
    return b"\x02" + ber_encode_length(len(payload)) + payload

def ber_encode_string(value: bytes) -> bytes:
    return b"\x04" + ber_encode_length(len(value)) + value

def ber_encode_null() -> bytes:
    return b"\x05\x00"

def ber_encode_oid(oid: tuple) -> bytes:
    body = bytes([40 * oid[0] + oid[1]])
    for component in oid[2:]:
        if component < 128:
            body += bytes([component])
        else:
            parts = []
            val = component
            parts.append(val & 0x7F)
            val >>= 7
            while val > 0:
                parts.append(0x80 | (val & 0x7F))
                val >>= 7
            parts.reverse()
            body += bytes(parts)
    return b"\x06" + ber_encode_length(len(body)) + body

def ber_encode_sequence(contents: bytes) -> bytes:
    return b"\x30" + ber_encode_length(len(contents)) + contents

def ber_encode_tagged(tag: int, contents: bytes) -> bytes:
    return bytes([0xA0 | (tag & 0x1F)]) + ber_encode_length(len(contents)) + contents

def ber_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    num_bytes = b & 0x7F
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes

def ber_decode_int(data: bytes, offset: int) -> tuple[int, int]:
    assert data[offset] == 0x02
    length, offset = ber_decode_length(data, offset + 1)
    value = int.from_bytes(data[offset : offset + length], "big", signed=True)
    return value, offset + length

def ber_decode_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    length, off = ber_decode_length(data, offset + 1)
    value = data[off : off + length]
    return tag, value, off + length


# ---------------------------------------------------------------------------
# SNMP helpers
# ---------------------------------------------------------------------------

def build_snmp_get(community: str, request_id: int, oid: tuple) -> bytes:
    varbind = ber_encode_sequence(ber_encode_oid(oid) + ber_encode_null())
    varbind_list = ber_encode_sequence(varbind)
    pdu = ber_encode_tagged(0, ber_encode_int(request_id) +
                            ber_encode_int(0) + ber_encode_int(0) + varbind_list)
    return ber_encode_sequence(ber_encode_int(0) +
                               ber_encode_string(community.encode()) + pdu)

def build_snmp_set(community: str, request_id: int,
                   oid: tuple, values: list[str]) -> bytes:
    varbinds = b""
    for val in values:
        varbinds += ber_encode_sequence(
            ber_encode_oid(oid) + ber_encode_string(val.encode()))
    varbind_list = ber_encode_sequence(varbinds)
    pdu = ber_encode_tagged(3, ber_encode_int(request_id) +
                            ber_encode_int(0) + ber_encode_int(0) + varbind_list)
    return ber_encode_sequence(ber_encode_int(0) +
                               ber_encode_string(community.encode()) + pdu)

def parse_snmp_response(data: bytes) -> tuple[int, int, int, int | None]:
    _, seq_data, _ = ber_decode_tlv(data, 0)
    off = 0
    _, off = ber_decode_int(seq_data, off)
    _, _, off = ber_decode_tlv(seq_data, off)
    _, pdu_data, _ = ber_decode_tlv(seq_data, off)
    poff = 0
    request_id, poff = ber_decode_int(pdu_data, poff)
    error_status, poff = ber_decode_int(pdu_data, poff)
    error_index, poff = ber_decode_int(pdu_data, poff)
    _, vbl_data, _ = ber_decode_tlv(pdu_data, poff)
    _, vb_data, _ = ber_decode_tlv(vbl_data, 0)
    _, _, voff = ber_decode_tlv(vb_data, 0)
    val_tag, val_bytes, _ = ber_decode_tlv(vb_data, voff)
    int_val = None
    if val_tag == 0x02:
        int_val = int.from_bytes(val_bytes, "big", signed=True)
    return request_id, error_status, error_index, int_val


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class BrotherScanner:
    def __init__(self, scanner_ip: str, hostname: str = "scan",
                 output_dir: str = ".",
                 profiles: dict[int, dict] | None = None,
                 default_profile: dict | None = None):
        self.scanner_ip = scanner_ip
        self.hostname = hostname
        self.output_dir = output_dir
        self.profiles = profiles or {}
        self.default_profile = default_profile or {
            "name": "Duplex Color PDF",
            "reso": "300,300",
            "color": "C24BIT",
            "duplex": "ON",
            "output": "pdf",
        }
        self.request_id = 0

        # UDP socket for SNMP (ephemeral port is fine)
        self.snmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.snmp_sock.settimeout(3)

        # Determine our local IP
        self.local_ip = self._get_local_ip()
        log.info("Local IP: %s", self.local_ip)

    def _get_local_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((self.scanner_ip, SNMP_PORT))
            return s.getsockname()[0]
        finally:
            s.close()

    def _next_id(self) -> int:
        self.request_id += 1
        return self.request_id

    def get_status(self) -> int:
        pkt = build_snmp_get("public", self._next_id(), OID_PRINTER_STATUS)
        self.snmp_sock.sendto(pkt, (self.scanner_ip, SNMP_PORT))
        try:
            data, _ = self.snmp_sock.recvfrom(1024)
        except socket.timeout:
            return -1
        _, es, ei, val = parse_snmp_response(data)
        if es != 0 or ei != 0:
            return -1
        return val

    def register(self) -> bool:
        reg = (f'USER="{self.hostname}";'
               f'HOST={self.local_ip}:{BUTTON_PORT};'
               f'DURATION={REGISTER_DURATION_SEC}')
        pkt = build_snmp_set("internal", self._next_id(),
                             OID_REGISTER_KEY_V2, [reg])
        self.snmp_sock.sendto(pkt, (self.scanner_ip, SNMP_PORT))
        try:
            data, _ = self.snmp_sock.recvfrom(1024)
        except socket.timeout:
            log.error("Registration timed out")
            return False
        _, es, ei, _ = parse_snmp_response(data)
        if es != 0 or ei != 0:
            log.error("Registration error: status=%d index=%d", es, ei)
            return False
        log.info("Registered as '%s'", self.hostname)
        return True

    # ----- button event listener (TCP 54950) -----

    def _handle_button_event(self, conn: socket.socket, addr: tuple):
        """Handle an incoming button press TCP connection from the scanner."""
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if not data:
                return

            # Parse JSON from payload (skip proprietary header bytes)
            json_start = data.find(b"{")
            if json_start < 0:
                log.warning("No JSON in button event: %s", data.hex())
                return

            event = json.loads(data[json_start:])
            log.info("Button pressed! %s", json.dumps(event))
            log.info("Raw header bytes: %s", data[:json_start].hex())
            button_num = event.get("button_number", "unknown")
            log.info("Button number: %s", button_num)

            # Send acknowledgment
            ack_json = json.dumps({"button_number": None,
                                   "model_name": None,
                                   "serial_number": None}).encode()
            header = b"\x01\x04" + len(ack_json).to_bytes(2, "big") + b"\x00\x00\x00"
            conn.sendall(header + ack_json)

        except Exception as e:
            log.error("Button event error: %s", e)
        finally:
            conn.close()

        # Now initiate the scan with the appropriate profile
        self._do_scan(button_num)

    # ----- data channel (TCP 54921) -----

    def _recv_all(self, sock: socket.socket, timeout: float = 5) -> bytes:
        """Receive data until timeout, for protocol responses."""
        sock.settimeout(timeout)
        chunks = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                # Short timeout for follow-up data
                sock.settimeout(0.5)
        except socket.timeout:
            pass
        return b"".join(chunks)

    def _do_scan(self, button_num=1):
        """Connect to scanner data channel and receive scan data."""
        profile = self.profiles.get(button_num, self.default_profile)
        log.info("Scan profile: %s (button %s)", profile["name"], button_num)
        log.info("Connecting to scanner data channel %s:%d...",
                 self.scanner_ip, DATA_PORT)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((self.scanner_ip, DATA_PORT))
        except Exception as e:
            log.error("Cannot connect to data channel: %s", e)
            return

        try:
            # 1. Receive welcome "+OK 200\r\n"
            welcome = sock.recv(1024)
            if not welcome.startswith(b"+OK"):
                log.error("Unexpected welcome: %r", welcome)
                return
            log.info("Data channel: %s", welcome.strip().decode())

            # 2. Handshake
            sock.sendall(CMD_HANDSHAKE)
            info = self._recv_all(sock)
            log.info("Received device info (%d bytes)", len(info))

            # 3. Query capabilities
            sock.sendall(CMD_QUERY_CAPS)
            caps = self._recv_all(sock)
            log.info("Received capabilities (%d bytes)", len(caps))

            # 4. Send scan settings
            params = SCAN_PARAMS_TEMPLATE.format(**profile).encode()
            sock.sendall(b"\x1b\x53\x53\x50\x0a" + params + b"\x80")
            confirm = self._recv_all(sock)
            log.info("Scan settings response (%d bytes): %s",
                     len(confirm), confirm[:40].hex())

            # 5. Get page info
            sock.sendall(CMD_GET_PAGE)
            page_header = self._recv_all(sock)
            log.info("Page header (%d bytes): %s",
                     len(page_header), page_header[:40].hex())

            # 6. Start scan
            scan_req = f"RESO={profile['reso']}\nAREA=ATDSKW\nMODE=NORMAL\n".encode()
            sock.sendall(b"\x1b\x58\x53\x43\x0a" + scan_req + b"\x80")

            # 10. Receive scan data (JPEG)
            scan_id = time.strftime("%Y-%m-%d_%H%M%S")
            page_num = 0
            leftover = b""
            page_files = []

            while True:
                page_data, leftover = self._receive_page(sock, leftover)
                if page_data is None:
                    break
                page_num += 1

                filename = os.path.join(
                    self.output_dir,
                    f"scan_{scan_id}_p{page_num}.jpg")
                with open(filename, "wb") as f:
                    f.write(page_data)
                log.info("Saved page %d: %s (%d bytes)",
                         page_num, filename, len(page_data))
                self._post_process(filename, profile.get("crop", "gray_only"))

                # Skip blank pages (e.g. empty back side of duplex scan)
                if self._is_blank_page(filename):
                    log.info("Page %d is blank, skipping", page_num)
                    os.remove(filename)
                else:
                    page_files.append(filename)

            log.info("Scan complete: %d page(s)", page_num)

            # Output based on profile
            if page_files:
                if profile["output"] == "pdf":
                    self._make_pdf(scan_id, page_files)
                else:
                    log.info("Output: %d JPEG file(s)", len(page_files))

        except Exception as e:
            log.error("Scan error: %s", e)
        finally:
            sock.close()

    def _is_blank_page(self, filepath: str, threshold: int = 200,
                       min_content_pct: float = 0.5) -> bool:
        """Detect if a scanned page is blank (mostly white).

        Samples pixels and checks what percentage are darker than
        `threshold`. If less than `min_content_pct`% are dark,
        the page is considered blank.
        """
        try:
            img = Image.open(filepath)
            gray = img.convert("L")
            w, h = img.size

            # Sample every 10th pixel in each direction
            step = 10
            dark = 0
            total = 0
            for y in range(0, h, step):
                for x in range(0, w, step):
                    total += 1
                    if gray.getpixel((x, y)) < threshold:
                        dark += 1

            pct = (dark / total) * 100 if total > 0 else 0
            log.debug("Blank check %s: %.2f%% content (threshold: %.1f%%)",
                      filepath, pct, min_content_pct)
            return pct < min_content_pct

        except Exception as e:
            log.error("Blank page check failed for %s: %s", filepath, e)
            return False

    def _make_pdf(self, scan_id: str, page_files: list[str]):
        """Combine scanned page JPEGs into a single multi-page PDF."""
        try:
            pdf_path = os.path.join(self.output_dir, f"scan_{scan_id}.pdf")
            pages = [Image.open(f) for f in page_files]
            if len(pages) == 1:
                pages[0].save(pdf_path, "PDF", resolution=300)
            else:
                pages[0].save(pdf_path, "PDF", resolution=300,
                              save_all=True, append_images=pages[1:])
            log.info("Created PDF: %s (%d pages)", pdf_path, len(pages))

            # Clean up individual JPEG files
            for f in page_files:
                os.remove(f)
            log.info("Removed %d JPEG page files", len(page_files))

        except Exception as e:
            log.error("PDF creation failed: %s", e)

    def _post_process(self, filepath: str, crop_mode: str = "gray_only"):
        """Auto-crop scanner background from page.

        crop_mode:
          'gray_only' - Only trim uniform gray scanner fill,
                        preserving white page margins.
          'tight'     - Trim both gray and white borders for
                        a tight crop to content.
        """
        try:
            img = Image.open(filepath)
            gray = img.convert("L")
            w, h = img.size

            tight = (crop_mode == "tight")

            def row_stats(y, samples=50):
                step = max(1, w // samples)
                vals = [gray.getpixel((x, y)) for x in range(0, w, step)]
                avg = sum(vals) / len(vals)
                if len(vals) < 2:
                    return avg, 0.0
                variance = sum((v - avg) ** 2 for v in vals) / (len(vals) - 1)
                return avg, variance ** 0.5

            def col_stats(x, y_start, y_end, samples=50):
                step = max(1, (y_end - y_start) // samples)
                vals = [gray.getpixel((x, y))
                        for y in range(y_start, y_end, step)]
                avg = sum(vals) / len(vals)
                if len(vals) < 2:
                    return avg, 0.0
                variance = sum((v - avg) ** 2 for v in vals) / (len(vals) - 1)
                return avg, variance ** 0.5

            def is_background_row(y):
                avg, stdev = row_stats(y)
                # Uniform scanner gray (~128 with no variation)
                if 100 < avg < 160 and stdev < 5:
                    return True
                # White border (only trim in tight/photo mode)
                if tight and avg > 220:
                    return True
                return False

            def is_background_col(x, y_start, y_end):
                avg, stdev = col_stats(x, y_start, y_end)
                if 100 < avg < 160 and stdev < 5:
                    return True
                if tight and avg > 220:
                    return True
                return False

            # Find top of page (skip background at top)
            top = 0
            for y in range(0, h):
                if not is_background_row(y):
                    top = y
                    break

            # Find bottom of page (from bottom, find first non-background row)
            bottom = h
            for y in range(h - 1, top, -1):
                if not is_background_row(y):
                    bottom = y
                    break

            # Find left edge (skip background columns)
            left = 0
            for x in range(0, w):
                if not is_background_col(x, top, bottom):
                    left = x
                    break

            # Find right edge
            right = w
            for x in range(w - 1, left, -1):
                if not is_background_col(x, top, bottom):
                    right = x
                    break

            # Only crop if we found meaningful borders (at least 1% trimmed)
            if (left > 5 or top > 5 or
                    (w - right) > 5 or (h - bottom) > 5):
                margin = 10
                crop_left = max(0, left - margin)
                crop_top = max(0, top - margin)
                crop_right = min(w, right + margin)
                crop_bottom = min(h, bottom + margin)
                img = img.crop((crop_left, crop_top, crop_right, crop_bottom))
                log.info("Cropped to %dx%d (was %dx%d)",
                         img.width, img.height, w, h)
            else:
                log.info("No significant borders detected, skipping crop")

            img.save(filepath, "JPEG", quality=90)
            log.info("Post-processed: %s", filepath)

        except Exception as e:
            log.error("Post-processing failed for %s: %s", filepath, e)

    def _receive_page(self, sock: socket.socket,
                       leftover: bytes = b"") -> tuple[bytes | None, bytes]:
        """Receive one page of JPEG data from the data channel.

        The scanner sends data in chunks with 14-byte framing headers
        injected every ~512 KB.  Headers match ``00 02 xx 00 15 00``
        (xx = page number).  We strip these to get clean JPEG output.

        Returns (jpeg_bytes, leftover) where leftover is any data read
        past the JPEG EOI that belongs to the next page.
        """
        CHUNK_HDR_LEN = 14

        raw = bytearray(leftover)
        sock.settimeout(30)

        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                raw.extend(data)

                # Only break once we have a JPEG SOI and EOI
                soi = raw.find(b"\xff\xd8")
                if soi >= 0:
                    eoi = raw.find(b"\xff\xd9", soi + 2)
                    if eoi >= 0:
                        break
        except socket.timeout:
            pass

        if not raw:
            return None, b""

        # End-of-scan marker only (2 bytes or less)
        if len(raw) <= 2:
            return None, b""

        # Strip 14-byte chunk headers injected by the scanner.
        cleaned = bytearray()
        pos = 0
        while pos < len(raw):
            if (pos + CHUNK_HDR_LEN <= len(raw)
                    and raw[pos] == 0x00 and raw[pos+1] == 0x02
                    and raw[pos+3] == 0x00
                    and raw[pos+4] == 0x15 and raw[pos+5] == 0x00):
                log.debug("Stripping chunk header at offset %d: %s",
                          pos, raw[pos:pos+CHUNK_HDR_LEN].hex())
                pos += CHUNK_HDR_LEN
            else:
                cleaned.append(raw[pos])
                pos += 1

        # Extract JPEG and pass remaining data back as leftover
        jpeg_start = cleaned.find(b"\xff\xd8")
        if jpeg_start < 0:
            log.warning("No JPEG found in %d bytes (header: %s)",
                        len(cleaned), cleaned[:20].hex())
            return None, b""

        jpeg_end = cleaned.find(b"\xff\xd9", jpeg_start)
        if jpeg_end < 0:
            log.warning("Incomplete JPEG (%d bytes)", len(cleaned))
            return bytes(cleaned[jpeg_start:]), b""

        jpeg_data = bytes(cleaned[jpeg_start : jpeg_end + 2])
        remaining = bytes(cleaned[jpeg_end + 2:])

        return jpeg_data, remaining

    # ----- main loop -----

    def run(self):
        """Main loop: register, listen for button events, handle scans."""
        # Check scanner status
        status = self.get_status()
        if status not in VALID_STATUSES:
            log.error("Scanner at %s returned status %d — may be offline",
                      self.scanner_ip, status)
            return
        log.info("Scanner status: %d (%s)", status, VALID_STATUSES[status])

        # Register
        if not self.register():
            log.error("Failed to register with scanner")
            return

        # Start registration keepalive thread
        stop_event = threading.Event()
        def keepalive():
            while not stop_event.is_set():
                stop_event.wait(REGISTER_DURATION_SEC - 30)
                if not stop_event.is_set():
                    self.register()
        ka_thread = threading.Thread(target=keepalive, daemon=True)
        ka_thread.start()

        # Listen for button press events on TCP 54950
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", BUTTON_PORT))
        server.listen(5)
        log.info("Listening for scan events on TCP %d...", BUTTON_PORT)

        try:
            while True:
                conn, addr = server.accept()
                log.info("Connection from %s:%d", addr[0], addr[1])
                # Handle in a thread so we can accept the next event
                t = threading.Thread(target=self._handle_button_event,
                                     args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            log.info("Shutting down...")
            stop_event.set()
        finally:
            server.close()


def main():
    parser = argparse.ArgumentParser(
        description="Brother scanner push-to-scan daemon")
    parser.add_argument("scanner_ip", nargs="?", default=None,
                        help="Scanner IP address (overrides config)")
    parser.add_argument("--hostname", default=None,
                        help="Name shown on scanner (overrides config)")
    parser.add_argument("--output-dir", default=None,
                        help="Directory to save scans (overrides config)")
    parser.add_argument("--config", default=None,
                        help="Path to config file")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    # Load config file
    scanner_cfg, profiles, default_profile = {}, {}, None
    config_path = args.config
    if config_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_config = os.path.join(script_dir, "profiles.conf")
        if os.path.exists(default_config):
            config_path = default_config

    if config_path:
        scanner_cfg, profiles, default_profile = load_config(config_path)
        log.info("Loaded config from %s", config_path)
        if profiles:
            log.info("Profiles:")
            for num, prof in sorted(profiles.items()):
                log.info("  Button %d: %s", num, prof["name"])

    # CLI args override config file
    scanner_ip = args.scanner_ip or scanner_cfg.get("ip")
    hostname = args.hostname or scanner_cfg.get("hostname", "scan")
    output_dir = args.output_dir or scanner_cfg.get("output_dir", ".")

    if not scanner_ip:
        parser.error("scanner_ip is required (via argument or config file)")

    os.makedirs(output_dir, exist_ok=True)

    scanner = BrotherScanner(scanner_ip, hostname, output_dir,
                             profiles=profiles, default_profile=default_profile)
    scanner.run()


if __name__ == "__main__":
    main()
