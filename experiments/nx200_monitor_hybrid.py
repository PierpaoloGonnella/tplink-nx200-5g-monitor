#!/usr/bin/env python3
"""
nx200_monitor_hybrid.py
---------------------------------------------------------------------------
Polling ibrido: Selenium per il login, API GDPR criptate per i dati.

Approccio:
  1. Usa Selenium + browser per il login (che ha problemi di popup)
  2. Dopo il login, estrae i cookie dalla sessione
  3. Usa socket SSL raw per interrogare le API GDPR (come v4)

Dipendenze:
    pip install selenium pycryptodome
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import random
import re
import signal
import socket
import sqlite3
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any
from urllib.parse import urlparse

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
except ImportError:
    print("ERRORE: pip install selenium", file=sys.stderr)
    sys.exit(1)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("ERRORE: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nx200_hybrid")


# ===========================================================================
# CRYPTO HELPERS (copiati da v4)
# ===========================================================================

def _rand_hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _aes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))


def _aes_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), AES.block_size)


def _rsa_encrypt(message: str, n_hex: str, e_hex: str,
                 chunk_size: int | None = None) -> str:
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    n_bytes = (n.bit_length() + 7) // 8
    if chunk_size is None:
        chunk_size = n_bytes - 11

    msg_bytes = message.encode("utf-8")
    out_hex = []
    for i in range(0, len(msg_bytes), chunk_size):
        chunk = msg_bytes[i:i + chunk_size]
        padded = chunk + b"\x00" * (n_bytes - len(chunk))
        m = int.from_bytes(padded, "big")
        c = pow(m, e, n)
        h = format(c, "x")
        if len(h) % 2 == 1:
            h = "0" + h
        out_hex.append(h)
    return "".join(out_hex)


def _decode_chunked(data: bytes) -> bytes:
    """Decodifica HTTP chunked transfer-encoding."""
    out = []
    pos = 0
    while pos < len(data):
        end_line = data.find(b"\r\n", pos)
        if end_line < 0:
            break
        size_line = data[pos:end_line].decode("latin-1", errors="replace").strip()
        size_hex = size_line.split(";")[0].strip()
        if not size_hex:
            pos = end_line + 2
            continue
        try:
            chunk_size = int(size_hex, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        chunk_start = end_line + 2
        chunk_end = chunk_start + chunk_size
        if chunk_end > len(data):
            out.append(data[chunk_start:])
            break
        out.append(data[chunk_start:chunk_end])
        pos = chunk_end + 2
    return b"".join(out)


# ===========================================================================
# RAW HTTP CLIENT (copiato da v4)
# ===========================================================================

class RawHttpsClient:
    def __init__(self, base_url: str):
        u = urlparse(base_url)
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.scheme = u.scheme
        self.base_url = base_url.rstrip("/")
        self.cookies: dict[str, str] = {}
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/148.0.0.0 Safari/537.36",
            "Accept": "text/plain, */*; q=0.01",
            "Accept-Language": "it-IT,it;q=0.9",
            "Origin": self.base_url,
            "Referer": self.base_url + "/",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "keep-alive",
        }

    def set_cookies(self, cookies: dict[str, str]):
        """Imposta i cookie da una sessione Selenium."""
        self.cookies = cookies.copy()
        log.info("Cookie impostati: %s", list(cookies.keys()))

    def post(self, path: str, body: bytes,
             extra_headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        """Ritorna (status_code, headers_dict, body_bytes)."""
        headers = dict(self.default_headers)
        if extra_headers:
            headers.update(extra_headers)
        headers["Host"] = self.host
        headers["Content-Length"] = str(len(body))
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        req_lines = [f"POST {path} HTTP/1.1"]
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")
        req_lines.extend(["", ""])
        req_head = "\r\n".join(req_lines).encode("utf-8")

        sock = socket.create_connection((self.host, self.port), timeout=15)
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)

        try:
            sock.sendall(req_head + body)
            sock.settimeout(5)
            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                buf = b"".join(chunks)
                if b"\r\n0\r\n\r\n" in buf:
                    break
        finally:
            try:
                sock.close()
            except Exception:
                pass

        raw = b"".join(chunks)
        return self._parse_response(raw)

    def _parse_response(self, raw: bytes) -> tuple[int, dict[str, str], bytes]:
        if raw.startswith(b"HTTP/"):
            sep = raw.find(b"\r\n\r\n")
            if sep < 0:
                return 0, {}, b""
            head = raw[:sep].decode("latin-1", errors="replace")
            body = raw[sep + 4:]
            lines = head.split("\r\n")
            status_line = lines[0]
            try:
                status = int(status_line.split()[1])
            except Exception:
                status = 0
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            if headers.get("transfer-encoding", "").lower() == "chunked":
                body = _decode_chunked(body)
            return status, headers, body
        else:
            body = _decode_chunked(raw)
            return 200, {}, body


# ===========================================================================
# GDPR DATA MODEL (copiato da v4)
# ===========================================================================

class DataModel:
    OP_GET = 1
    OP_GL = 5

    def __init__(self, client: RawHttpsClient):
        self.client = client

    def get(self, oid: str, fields: list[str],
            stack: str = "0,0,0,0,0,0") -> dict[str, Any]:
        nfields = len(fields)
        body = f"{self.OP_GET}\r\n[{oid}#{stack}#0,0,0,0,0,0]0,{nfields}\r\n"
        for f in fields:
            body += f"{f}\r\n"
        log.debug("DM GET %s: %d fields", oid, nfields)
        
        status, _, resp_body = self.client.post("/cgi_gdpr?9", body.encode())
        if not resp_body:
            log.warning("DM GET %s: risposta vuota (HTTP %d)", oid, status)
            return {}

        text = resp_body.decode("utf-8", errors="replace")
        return self._parse(text, as_list=False)

    def get_list(self, oid: str, fields: list[str],
                 stack: str = "0,0,0,0,0,0") -> list[dict[str, Any]]:
        nfields = len(fields)
        body = f"{self.OP_GL}\r\n[{oid}#{stack}#0,0,0,0,0,0]0,{nfields}\r\n"
        for f in fields:
            body += f"{f}\r\n"
        log.debug("DM GET_LIST %s: %d fields", oid, nfields)
        print(f"DEBUG: GET_LIST {oid} sending {nfields} fields", flush=True)
        
        status, hdrs, resp_body = self.client.post("/cgi_gdpr?9", body.encode())
        print(f"DEBUG: GET_LIST {oid} response: status={status}, len={len(resp_body) if resp_body else 0}", flush=True)
        print(f"DEBUG: GET_LIST {oid} body: {resp_body[:500] if resp_body else b''}", flush=True)
        
        if not resp_body:
            log.warning("DM GET_LIST %s: risposta vuota (HTTP %d)", oid, status)
            return []

        text = resp_body.decode("utf-8", errors="replace")
        print(f"DEBUG: GET_LIST {oid} decoded text: {text[:300]}", flush=True)
        r = self._parse(text, as_list=True)
        print(f"DEBUG: GET_LIST {oid} parsed {len(r) if isinstance(r, list) else 1} records: {r}", flush=True)
        return r if isinstance(r, list) else ([r] if r else [])

    @staticmethod
    def _parse(text: str, as_list: bool) -> Any:
        text = text.strip()
        if not text:
            return [] if as_list else {}

        if text.startswith("{") or text.startswith("["):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict) and "data" in obj:
                    return obj["data"]
                return obj
            except json.JSONDecodeError:
                pass

        records = []
        current = {}
        in_record = False
        for raw in text.splitlines():
            line = raw.rstrip("\r")
            if not line or line.startswith("$."):
                continue
            if line.startswith("["):
                if in_record and current:
                    records.append(current)
                    current = {}
                in_record = "error" not in line
                continue
            if in_record and "=" in line:
                k, _, v = line.partition("=")
                current[k.strip()] = v.strip()
        if current:
            records.append(current)
        return records if as_list else (records[0] if records else {})


# ===========================================================================
# SELENIUM LOGIN
# ===========================================================================

class SeleniumLogin:
    def __init__(self, host: str, password: str, username: str = "admin"):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.driver: webdriver.Chrome | None = None

    def __enter__(self):
        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--ignore-ssl-errors")
        opts.set_capability("acceptInsecureCerts", True)
        log.info("Avvio browser headless...")
        self.driver = webdriver.Chrome(options=opts)
        self.driver.set_page_load_timeout(60)
        self.driver.set_script_timeout(60)
        return self

    def __exit__(self, *a):
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass

    def login(self):
        assert self.driver
        log.info("Login con Selenium...")
        self.driver.get(self.host)
        time.sleep(5)  # Aumentato da 2

        try:
            pwd_input = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
            )
        except TimeoutException:
            log.info("Nessun campo password, forse gia' loggati")
            time.sleep(2)
            return self.driver  # Ritorna il driver stesso

        pwd_input.send_keys(self.password)
        time.sleep(0.5)

        self.driver.execute_script(
            "if (window.jQuery) { jQuery('#pc-login-btn').click(); } "
            "else { document.getElementById('pc-login-btn').click(); }"
        )

        time.sleep(1)
        try:
            confirm_btn = self.driver.find_elements(By.ID, "confirm-yes")
            if confirm_btn and confirm_btn[0].is_displayed():
                log.info("Popup force logout rilevato, clicco...")
                self.driver.execute_script("arguments[0].click();", confirm_btn[0])
                time.sleep(2)
        except Exception:
            pass

        log.info("Attendo UI principale...")
        for attempt in range(40):
            try:
                ui = self.driver.find_elements(By.CSS_SELECTOR, "#main, .navi-side")
                if ui and any(e.is_displayed() for e in ui):
                    log.info("Login OK")
                    time.sleep(2)
                    return self.driver  # Ritorna il driver stesso
            except Exception:
                pass
            time.sleep(0.5)

        log.warning("Timeout login, provo comunque")
        return self.driver
    
    def gdpr_get_list(self, oid: str, fields: list[str]) -> list[dict[str, Any]]:
        """Interroga l'API GDPR navigando tramite il browser (POST implicito tramite form)."""
        assert self.driver
        nfields = len(fields)
        body = f"5\r\n[{oid}#0,0,0,0,0,0#0,0,0,0,0,0]0,{nfields}\r\n"
        for f in fields:
            body += f"{f}\r\n"
        
        # Encoda il body in base64 per evitare problemi di escape
        body_b64 = base64.b64encode(body.encode()).decode()
        
        # Usa XHR dal browser con sincronous mode (deprecato ma potrebbe funzionare)
        host_url = self.driver.execute_script("return window.location.origin;")
        
        script = f"""
        var body_str = atob('{body_b64}');
        var url = '{host_url}/cgi_gdpr?9';
        var xhr = new XMLHttpRequest();
        xhr.open('POST', url, false);  // Synchronous
        xhr.setRequestHeader('Content-Type', 'text/plain');
        try {{
            xhr.send(body_str);
            if (xhr.status >= 200 && xhr.status < 300) {{
                return xhr.responseText;
            }} else {{
                return 'ERROR: HTTP ' + xhr.status;
            }}
        }} catch (e) {{
            return 'ERROR: ' + e.message;
        }}
        """
        
        try:
            response_text = self.driver.execute_script(script)
            print(f"DEBUG: GDPR response ({len(response_text)} chars): {response_text[:300]}", flush=True)
            return self._parse_gdpr_response(response_text)
        except Exception as e:
            print(f"DEBUG: GDPR XHR error: {e}", flush=True)
            return []
    
    @staticmethod
    def _parse_gdpr_response(text: str) -> list[dict[str, Any]]:
        """Parsa la risposta GDPR."""
        if not text or text.startswith("ERROR"):
            return []
        
        records = []
        current = {}
        in_record = False
        for line in text.strip().split('\n'):
            line = line.rstrip('\r')
            if not line or line.startswith("$."):
                continue
            if line.startswith("["):
                if in_record and current:
                    records.append(current)
                    current = {}
                in_record = "error" not in line
                continue
            if in_record and "=" in line:
                k, _, v = line.partition("=")
                current[k.strip()] = v.strip()
        if current:
            records.append(current)
        return records


# ===========================================================================
# POLLING E STORAGE
# ===========================================================================

SERVING_CELL_FIELDS = [
    "networkType", "cellConnectionStatus", "band", "cid", "TAC", "PCI",
    "ARFCN", "signalStrength",
    "RSRP", "RSRQ", "SNR",
    "SSRSRP", "SSRSRQ", "SSSINR",
    "CQI", "RI", "numRbs",
    "downMCS", "upMCS",
    "downFreq", "upFreq", "downBandWidth", "upBandWidth",
    "downlinkModType", "uplinkModType",
    "txPowerPUCCH",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
    network_type TEXT, isp TEXT,
    nr_band TEXT, nr_pci INTEGER, ss_rsrp REAL, ss_rsrq REAL, ss_sinr REAL,
    lte_band TEXT, lte_pci INTEGER, lte_rsrp REAL, lte_rsrq REAL, lte_snr REAL,
    dl_speed INTEGER, ul_speed INTEGER,
    raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
"""


def _to_float(v):
    try:
        return float(v) if v not in (None, "", "--") else None
    except (ValueError, TypeError):
        return None


def _to_int(v):
    try:
        return int(float(v)) if v not in (None, "", "--") else None
    except (ValueError, TypeError):
        return None


class Store:
    def __init__(self, p: Path):
        self.conn = sqlite3.connect(p)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert_sample(self, s: dict[str, Any]) -> int:
        cols = [
            "ts", "network_type", "isp",
            "nr_band", "nr_pci", "ss_rsrp", "ss_rsrq", "ss_sinr",
            "lte_band", "lte_pci", "lte_rsrp", "lte_rsrq", "lte_snr",
            "dl_speed", "ul_speed",
        ]
        vals = [s.get(c) for c in cols] + [json.dumps(s, default=str)]
        sql = f"INSERT INTO samples ({','.join(cols + ['raw_json'])}) VALUES ({','.join('?' * (len(cols)+1))})"
        cur = self.conn.execute(sql, vals)
        self.conn.commit()
        return cur.lastrowid  # type: ignore

    def close(self):
        self.conn.close()


def poll_once(dm: DataModel) -> dict[str, Any]:
    """Interroga il modem e ritorna un campione."""
    sample = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    # Serving cell info (NR + LTE)
    cells = dm.get_list("DEV2_LTE_SERVING_CELL_INFO", SERVING_CELL_FIELDS)
    nr = lte = None
    for c in cells:
        ntc = _to_int(c.get("networkType"))
        if str(c.get("cellConnectionStatus", "")) != "1":
            continue
        if ntc == 8:
            nr = c
        elif ntc in (3, 7):
            lte = c

    if nr:
        sample["nr_band"] = f"N{nr.get('band')}"
        sample["nr_pci"] = _to_int(nr.get("PCI"))
        sample["ss_rsrp"] = _to_float(nr.get("SSRSRP"))
        sample["ss_rsrq"] = _to_float(nr.get("SSRSRQ"))
        v = _to_float(nr.get("SSSINR"))
        sample["ss_sinr"] = v / 10.0 if v else None

    if lte:
        sample["lte_band"] = f"B{lte.get('band')}"
        sample["lte_pci"] = _to_int(lte.get("PCI"))
        sample["lte_rsrp"] = _to_float(lte.get("RSRP"))
        sample["lte_rsrq"] = _to_float(lte.get("RSRQ"))
        v = _to_float(lte.get("SNR"))
        sample["lte_snr"] = v / 10.0 if v else None

    # ISP info
    prof = dm.get("DEV2_LTE_PROF_STAT", ["ispName"])
    sample["isp"] = prof.get("ispName")

    # Network type
    link = dm.get("DEV2_LTE_LINK_CFG", ["networkType"])
    nt = _to_int(link.get("networkType"))
    if nt == 8:
        sample["network_type"] = "5G NR"
    elif nt in (3, 7):
        sample["network_type"] = "LTE"

    # Speed
    xtp = dm.get("DEV2_XTP_LTE_INTF_CFG", ["curTxSpeed", "curRxSpeed"])
    sample["dl_speed"] = _to_int(xtp.get("curRxSpeed"))
    sample["ul_speed"] = _to_int(xtp.get("curTxSpeed"))

    return sample


_RUN = True


def _sigint(signum, frame):
    global _RUN
    _RUN = False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True, help="Es. https://192.168.1.1")
    p.add_argument("--password", required=True)
    p.add_argument("--username", default="admin")
    p.add_argument("--db", default="nx200_monitor.db")
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--once", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    store = Store(Path(args.db))

    try:
        # Step 1: Login con Selenium e mantieni il driver aperto
        sl = SeleniumLogin(args.host, args.password, args.username)
        with sl:
            driver = sl.login()

            log.info("Avvio polling...")
            if args.once:
                # Interroga i dati via Selenium/browser
                cells = sl.gdpr_get_list("DEV2_LTE_SERVING_CELL_INFO", SERVING_CELL_FIELDS)
                print(f"DEBUG: cells result: {cells}", flush=True)
                
                sample = {
                    "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                
                # Parse cells
                nr = lte = None
                for c in cells:
                    ntc = _to_int(c.get("networkType"))
                    if str(c.get("cellConnectionStatus", "")) != "1":
                        continue
                    if ntc == 8:
                        nr = c
                    elif ntc in (3, 7):
                        lte = c

                if nr:
                    sample["nr_band"] = f"N{nr.get('band')}"
                    sample["nr_pci"] = _to_int(nr.get("PCI"))
                    sample["ss_rsrp"] = _to_float(nr.get("SSRSRP"))
                    sample["ss_rsrq"] = _to_float(nr.get("SSRSRQ"))
                    v = _to_float(nr.get("SSSINR"))
                    sample["ss_sinr"] = v / 10.0 if v else None

                if lte:
                    sample["lte_band"] = f"B{lte.get('band')}"
                    sample["lte_pci"] = _to_int(lte.get("PCI"))
                    sample["lte_rsrp"] = _to_float(lte.get("RSRP"))
                    sample["lte_rsrq"] = _to_float(lte.get("RSRQ"))
                    v = _to_float(lte.get("SNR"))
                    sample["lte_snr"] = v / 10.0 if v else None
                
                sid = store.insert_sample(sample)
                rsrp = sample.get("ss_rsrp") or sample.get("lte_rsrp")
                sinr = sample.get("ss_sinr") or sample.get("lte_snr")
                log.info("sample #%d net=%s RSRP=%s SINR=%s",
                         sid, sample.get("network_type"),
                         f"{rsrp:.1f}" if rsrp else "n/a",
                         f"{sinr:.1f}" if sinr else "n/a")
    finally:
        store.close()
        log.info("Bye.")


if __name__ == "__main__":
    main()
