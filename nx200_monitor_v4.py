#!/usr/bin/env python3
"""
nx200_monitor_v4.py
---------------------------------------------------------------------------
Polling + log su SQLite per TP-Link Archer NX200 (Build 251120+).

Versione 4 - FUNZIONANTE. Differenze rispetto alla v3:

  * Trasporto HTTP via socket SSL raw, perche' il firmware NX200 risponde
    con body chunked-encoded MA SENZA la status line "HTTP/1.1 200 OK".
    requests/urllib3 va in errore (BadStatusLine('40\\r\\n')), quindi
    bypassiamo entrambi e parliamo direttamente con la socket.

  * Decodifica manuale del transfer-encoding chunked (vista la risposta
    raw del modem: "40\\r\\n<64 byte base64>\\r\\n0\\r\\n\\r\\n").

  * Payload login include oid="/cgi/login" come fa la web UI:
    {"data":{"oid":"/cgi/login","stack":"...","pstack":"...",
             "username":"admin","password":"..."},"operation":"cgi"}

Dipendenze:
    pip install pycryptodome
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import secrets
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

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nx200v4")


# ===========================================================================
# CRYPTO HELPERS
# ===========================================================================

def _rand_hex(n: int) -> str:
    return "".join(secrets.choice("0123456789abcdef") for _ in range(n))


def _aes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))


def _aes_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), AES.block_size)


def _rsa_encrypt(message: str, n_hex: str, e_hex: str,
                 chunk_size: int | None = None) -> str:
    """RSA nopadding TP-Link, con chunking se la stringa supera n_bytes."""
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    n_bytes = (n.bit_length() + 7) // 8
    if chunk_size is None:
        chunk_size = n_bytes - 11  # default TP-Link

    msg_bytes = message.encode("utf-8")
    out_hex = []
    for i in range(0, len(msg_bytes), chunk_size):
        chunk = msg_bytes[i:i + chunk_size]
        padded = chunk + b"\x00" * (n_bytes - len(chunk))
        m = int.from_bytes(padded, "big")
        c = pow(m, e, n)
        h = format(c, f"0{n_bytes * 2}x")
        if len(h) % 2 == 1:
            h = "0" + h
        out_hex.append(h)
    return "".join(out_hex)


# ===========================================================================
# HTTP CHUNKED DECODER (per la risposta malformata del modem)
# ===========================================================================

def _decode_chunked(data: bytes) -> bytes:
    """
    Decodifica un body in HTTP chunked transfer-encoding.
    Formato: "<hex-size>\\r\\n<chunk-bytes>\\r\\n...0\\r\\n\\r\\n"
    """
    out = []
    pos = 0
    while pos < len(data):
        # leggi linea fino a \r\n
        end_line = data.find(b"\r\n", pos)
        if end_line < 0:
            break
        size_line = data[pos:end_line].decode("latin-1", errors="replace").strip()
        # potrebbe esserci una ";extensions" dopo la dimensione
        size_hex = size_line.split(";")[0].strip()
        if not size_hex:
            pos = end_line + 2
            continue
        try:
            chunk_size = int(size_hex, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break  # end-of-chunks marker
        chunk_start = end_line + 2
        chunk_end = chunk_start + chunk_size
        if chunk_end > len(data):
            out.append(data[chunk_start:])
            break
        out.append(data[chunk_start:chunk_end])
        pos = chunk_end + 2  # skip trailing \r\n
    return b"".join(out)


# ===========================================================================
# RAW HTTP TRANSPORT (bypassa requests)
# ===========================================================================

class RawHttpsClient:
    """
    Client HTTPS minimale via socket raw. Gestisce:
      - cookie tra una richiesta e l'altra
      - HTTPS con cert self-signed
      - risposte malformate (chunked senza status line)
    """

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
                # end-of-chunked
                if b"\r\n0\r\n\r\n" in buf:
                    break
                # body completo se Content-Length specifico (gestione semplificata)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        raw = b"".join(chunks)
        log.debug("RAW response: %d bytes", len(raw))
        return self._parse_response(raw)

    def _parse_response(self, raw: bytes) -> tuple[int, dict[str, str], bytes]:
        """
        Parse della risposta che puo' essere:
          (a) HTTP normale: "HTTP/1.1 200 OK\\r\\n<headers>\\r\\n\\r\\n<body>"
          (b) Solo body chunked (bug NX200): "<size>\\r\\n<chunk>\\r\\n0\\r\\n\\r\\n"
        """
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
            # Set-Cookie parsing
            for line in lines[1:]:
                if line.lower().startswith("set-cookie:"):
                    cookie_part = line.split(":", 1)[1].strip().split(";")[0]
                    if "=" in cookie_part:
                        ck, _, cv = cookie_part.partition("=")
                        self.cookies[ck.strip()] = cv.strip()
            # chunked?
            if headers.get("transfer-encoding", "").lower() == "chunked":
                body = _decode_chunked(body)
            return status, headers, body
        else:
            # body chunked senza header: assumiamo status 200
            body = _decode_chunked(raw)
            return 200, {}, body


# ===========================================================================
# CLIENT TP-LINK CGI_GDPR
# ===========================================================================

class TPLinkGdprClient:
    def __init__(self, base_url: str, password: str, username: str = "admin"):
        self.username = username
        self.password = password
        self.http = RawHttpsClient(base_url)
        self.base_url = base_url.rstrip("/")

        self.aes_key: bytes | None = None
        self.aes_iv: bytes | None = None
        self.aes_key_str: str | None = None
        self.aes_iv_str: str | None = None
        self.rsa_n: str | None = None
        self.rsa_e: str | None = None
        self.rsa_seq: int = 0
        self.md5_hash_pw: str | None = None
        self.token: str | None = None

    def _get_rsa_key_and_seq(self) -> None:
        """Legge n, e, seq da /cgi/getParm."""
        status, _hdrs, body = self.http.post("/cgi/getParm", b"")
        if status != 200:
            raise RuntimeError(f"getParm HTTP {status}: {body[:200]!r}")
        text = body.decode("utf-8", errors="replace")
        m_ee = re.search(r'ee\s*=\s*"([^"]+)"', text)
        m_nn = re.search(r'nn\s*=\s*"([^"]+)"', text)
        m_seq = re.search(r'seq\s*=\s*"?(\d+)"?', text)
        if not (m_ee and m_nn and m_seq):
            raise RuntimeError(f"getParm: impossibile parsare. Testo: {text[:200]}")
        self.rsa_e = m_ee.group(1)
        self.rsa_n = m_nn.group(1)
        self.rsa_seq = int(m_seq.group(1))
        n_bytes = (int(self.rsa_n, 16).bit_length() + 7) // 8
        log.info("RSA: modulus %d bit, seq=%d", n_bytes * 8, self.rsa_seq)

    def login(self) -> None:
        log.info("Step 1: recupero chiavi RSA...")
        self._get_rsa_key_and_seq()

        self.aes_key_str = _rand_hex(16)
        self.aes_iv_str = _rand_hex(16)
        self.aes_key = self.aes_key_str.encode("ascii")
        self.aes_iv = self.aes_iv_str.encode("ascii")
        self.md5_hash_pw = hashlib.md5(
            f"{self.username}{self.password}".encode()
        ).hexdigest()

        log.info("Step 2: invio richiesta di login cifrata...")

        # Il body di login NON e' JSON ma il formato proprietario TP-Link.
        # Dal sorgente lib.js (funzione $.exe()):
        #   data = "8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\n"
        #          + "username=admin\r\n"
        #          + "password=...\r\n"
        # Il "8" iniziale e' ACT_CGI (codice operazione).
        plain_body = (
            f"8\r\n"
            f"[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\n"
            f"username={self.username}\r\n"
            f"password={self.password}\r\n"
        )


        encrypted = _aes_encrypt(self.aes_key, self.aes_iv, plain_body.encode())
        data_b64 = base64.b64encode(encrypted).decode()

        # Sign al login: "key=K&iv=I&h=H&s=S"
        sign_plain = (
            f"key={self.aes_key_str}&iv={self.aes_iv_str}"
            f"&h={self.md5_hash_pw}&s={self.rsa_seq + len(data_b64)}"
        )

        sign_hex = _rsa_encrypt(sign_plain, self.rsa_n, self.rsa_e)

        body = (f"sign={sign_hex}\r\ndata={data_b64}\r\n").encode()
        status, _hdrs, resp_body = self.http.post(
            "/cgi_gdpr?9", body,
            extra_headers={"Content-Type": "text/plain", "TokenID": ""},
        )

        if not resp_body:
            raise RuntimeError(f"Login: risposta vuota (HTTP {status})")

        # Decifra il body
        try:
            decoded = base64.b64decode(resp_body)
            decrypted = _aes_decrypt(self.aes_key, self.aes_iv, decoded).decode(
                "utf-8", errors="replace"
            )
        except Exception as e:
            raise RuntimeError(
                f"Login: risposta non decifrabile: {e}. "
                f"Body raw: {resp_body[:200]!r}"
            ) from e

        log.debug("Login response decoded")

        # Cerca errorcode JSON
        try:
            obj = json.loads(decrypted)
            if obj.get("success") is True:
                log.info("Login OK")
                # token nel data?
                d = obj.get("data") or {}
                if isinstance(d, dict) and d.get("stok"):
                    self.token = d["stok"]
                return
            err = obj.get("errorcode", "?")
            raise RuntimeError(
                f"Login rifiutato dal server: errorcode={err}. "
                f"Risposta: {decrypted[:300]}"
            )
        except json.JSONDecodeError:
            pass

        # Formato vecchio: $.ret=N
        m = re.search(r"\$\.ret\s*=\s*(\d+)", decrypted)
        if m:
            if m.group(1) == "0":
                log.info("Login OK ($.ret=0)")
                return
            raise RuntimeError(f"Login rifiutato: $.ret={m.group(1)}")

        # Se siamo qui, risposta inattesa
        log.warning("Login: risposta in formato inatteso")
        if not self.http.cookies.get("JSESSIONID"):
            raise RuntimeError(f"Login fallito senza JSESSIONID. Risposta: {decrypted[:300]}")

    def request_data(self, plain_payload: str) -> str:
        """Richiesta post-login: cifratura AES + sign senza key/iv."""
        encrypted = _aes_encrypt(self.aes_key, self.aes_iv, plain_payload.encode())
        data_b64 = base64.b64encode(encrypted).decode()
        sign_plain = f"h={self.md5_hash_pw}&s={self.rsa_seq + len(data_b64)}"
        sign_hex = _rsa_encrypt(sign_plain, self.rsa_n, self.rsa_e)

        body = (f"sign={sign_hex}\r\ndata={data_b64}\r\n").encode()
        status, _hdrs, resp_body = self.http.post(
            "/cgi_gdpr?9", body,
            extra_headers={
                "Content-Type": "text/plain",
                "TokenID": self.token or "",
            },
        )
        if status != 200:
            raise RuntimeError(f"Data request HTTP {status}")
        if not resp_body:
            raise RuntimeError("Data request returned an empty response")
        try:
            decoded = base64.b64decode(resp_body)
            return _aes_decrypt(self.aes_key, self.aes_iv, decoded).decode(
                "utf-8", errors="replace"
            )
        except Exception as e:
            raise RuntimeError("Unable to decrypt data response") from e

    def logout(self) -> None:
        try:
            self.request_data(
                "8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
            )
        except Exception:
            pass


# ===========================================================================
# DATAMODEL
# ===========================================================================

class DataModel:
    """
    Astrae le chiamate del DataModel come fa la web UI.

    Dal sorgente lib.js, il body in chiaro per /cgi_gdpr e':
        "{op_code}\\r\\n[OID#stack#pstack]index,nfields\\r\\n
         field1[=value1]\\r\\n
         field2[=value2]\\r\\n..."
    Dove op_code e':
        ACT_GET=1, ACT_SET=2, ACT_ADD=3, ACT_DEL=4,
        ACT_GL=5, ACT_GS=6, ACT_OP=7, ACT_CGI=8
    Per leggere un OID si usa GET (1) per oggetti singoli e GL (5) per liste.
    """

    OP_GET = 1
    OP_SET = 2
    OP_GL = 5
    OP_CGI = 8

    def __init__(self, client: TPLinkGdprClient):
        self.client = client

    def get(self, oid: str, fields: list[str],
            stack: str = "0,0,0,0,0,0") -> dict[str, Any]:
        return self._call(self.OP_GET, oid, fields, stack, as_list=False)

    def get_list(self, oid: str, fields: list[str],
                 stack: str = "0,0,0,0,0,0") -> list[dict[str, Any]]:
        r = self._call(self.OP_GL, oid, fields, stack, as_list=True)
        return r if isinstance(r, list) else ([r] if r else [])

    def _call(self, op: int, oid: str, fields: list[str],
              stack: str, as_list: bool) -> Any:
        nfields = len(fields)
        body = f"{op}\r\n[{oid}#{stack}#0,0,0,0,0,0]0,{nfields}\r\n"
        for f in fields:
            body += f"{f}\r\n"
        log.debug("DM op=%d %s body: %s", op, oid, body.replace("\r\n", " | "))
        resp = self.client.request_data(body)
        log.debug("DM op=%d %s response: %s", op, oid, resp[:400])
        return self._parse(resp, as_list)

    @staticmethod
    def _parse(text: str, as_list: bool) -> Any:
        """
        Risposta tipica:
            [DEV2_OID#stack]N
            field1=value1
            field2=value2
            [error]0
            $.ret=0
        Per liste piu' record si alternano blocchi "[OID#stack]N".
        """
        text = text.strip()
        if not text:
            return [] if as_list else {}

        for error in re.finditer(r"(?:\[error\]\s*|\$\.ret\s*=\s*)(-?\d+)", text):
            if int(error.group(1)) != 0:
                raise RuntimeError(f"Firmware API error {error.group(1)}")

        # Prova JSON prima (per sicurezza, alcune risposte potrebbero esserlo)
        if text.startswith("{") or text.startswith("["):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict) and (obj.get("success") is False or obj.get("errorcode") not in (None, 0, "0")):
                    raise RuntimeError("Firmware API rejected request")
                if isinstance(obj, dict) and "data" in obj:
                    return obj["data"]
                return obj
            except json.JSONDecodeError:
                pass

        # Parser TP-Link pseudo-INI
        records = []
        current = {}
        in_record = False
        for raw in text.splitlines():
            line = raw.rstrip("\r")
            if not line:
                continue
            if line.startswith("$."):
                continue  # $.ret=0, $.act, ecc.
            if line.startswith("["):
                # [OID#stack]N o [error]N - separatore di record
                if in_record and current:
                    records.append(current)
                    current = {}
                in_record = "error" not in line
                continue
            if not in_record:
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                current[k.strip()] = v.strip()
        if current:
            records.append(current)
        return records if as_list else (records[0] if records else {})


# ===========================================================================
# OID DA INTERROGARE
# ===========================================================================

LTE_STACK = "1,0,0,0,0,0"

QUERIES = {
    "DEV2_LTE_LINK_CFG": (LTE_STACK, ["simStatus", "networkType", "roamingStatus"]),
    "DEV2_LTE_PROF_STAT": (LTE_STACK, ["ispName", "ispMcc", "ispMnc", "spn"]),
    "DEV2_CELL_INTF_USIM": (LTE_STACK, ["IMSI", "ICCID", "MSISDN"]),
    "DEV2_XTP_LTE_INTF_CFG": (LTE_STACK, ["curTxSpeed", "curRxSpeed", "totalStatistics"]),
    "DEV2_DEV_INFO": (None, ["upTime"]),
    "DEV2_MEM_STATUS": (None, ["total", "free"]),
    "DEV2_PROC_STATUS": (None, ["CPUUsage"]),
}

SERVING_CELL_OID = "DEV2_LTE_SERVING_CELL_INFO"
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

NET_TYPE_LABELS = {-1: "Invalid", 0: "None", 1: "GSM", 2: "WCDMA", 3: "LTE",
                   4: "TDSCDMA", 5: "CDMA1X", 6: "EVDO", 7: "LTE+", 8: "5G NR"}


# ===========================================================================
# COLLECTOR
# ===========================================================================

class Collector:
    def __init__(self, host: str, password: str, username: str = "admin"):
        self.client = TPLinkGdprClient(host, password, username)
        self.dm: DataModel | None = None

    def __enter__(self):
        self.client.login()
        self.dm = DataModel(self.client)
        return self

    def __exit__(self, *a):
        try:
            self.client.logout()
        except Exception:
            pass

    def collect(self) -> dict[str, Any]:
        assert self.dm
        s: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "raw": {},
        }
        for oid, (stack, fields) in QUERIES.items():
            try:
                s["raw"][oid] = self.dm.get(oid, fields, stack or "0,0,0,0,0,0")
            except Exception as e:
                log.warning("Lettura %s fallita: %s", oid, e)
                s["raw"][oid] = {"_error": str(e)}
        try:
            cells = self.dm.get_list(SERVING_CELL_OID, SERVING_CELL_FIELDS)
            s["raw"][SERVING_CELL_OID] = cells
        except Exception as e:
            log.warning("Lettura serving cells fallita: %s", e)
            cells = []
        self._normalize(s, cells)
        if all(s.get(key) is None for key in ("ss_rsrp", "ss_sinr", "lte_rsrp", "lte_snr")):
            raise RuntimeError("No usable radio metrics collected")
        return s

    @staticmethod
    def _normalize(s: dict[str, Any], cells: list[dict[str, Any]]):
        raw = s["raw"]
        link = raw.get("DEV2_LTE_LINK_CFG", {}) or {}
        nt = _to_int(link.get("networkType"))
        s["network_type"] = NET_TYPE_LABELS.get(nt) if nt is not None else None
        s["sim_status"] = _to_int(link.get("simStatus"))
        prof = raw.get("DEV2_LTE_PROF_STAT", {}) or {}
        s["isp"] = prof.get("ispName") or prof.get("spn")
        s["mcc"] = prof.get("ispMcc")
        s["mnc"] = prof.get("ispMnc")
        usim = raw.get("DEV2_CELL_INTF_USIM", {}) or {}
        s["imsi"] = usim.get("IMSI")
        s["iccid"] = usim.get("ICCID")
        s["msisdn"] = usim.get("MSISDN")
        intf = raw.get("DEV2_XTP_LTE_INTF_CFG", {}) or {}
        s["dl_speed"] = _to_int(intf.get("curRxSpeed"))
        s["ul_speed"] = _to_int(intf.get("curTxSpeed"))
        s["cpu_load"] = _to_float((raw.get("DEV2_PROC_STATUS") or {}).get("CPUUsage"))
        mem = raw.get("DEV2_MEM_STATUS", {}) or {}
        mt, mf = _to_float(mem.get("total")), _to_float(mem.get("free"))
        if mt and mf is not None and mt > 0:
            s["mem_used"] = (mt - mf) / mt * 100.0
        s["uptime_sec"] = _to_int((raw.get("DEV2_DEV_INFO") or {}).get("upTime"))

        nr, lte = None, None
        for c in (cells or []):
            ntc = _to_int(c.get("networkType"))
            if str(c.get("cellConnectionStatus", "")) != "1":
                continue
            if ntc == 8:
                nr = c
            elif ntc in (3, 7):
                lte = c
        if nr:
            s["nr_band"] = f"N{nr.get('band')}"
            s["nr_pci"] = _to_int(nr.get("PCI"))
            s["nr_arfcn"] = _to_int(nr.get("ARFCN"))
            s["nr_cid"] = nr.get("cid")
            s["nr_tac"] = nr.get("TAC")
            s["ss_rsrp"] = _to_float(nr.get("SSRSRP"))
            s["ss_rsrq"] = _to_float(nr.get("SSRSRQ"))
            v = _to_float(nr.get("SSSINR")); s["ss_sinr"] = v/10.0 if v is not None else None
            v = _to_float(nr.get("txPowerPUCCH")); s["nr_tx_power"] = v/10.0 if v is not None else None
            s["nr_cqi"] = _to_int(nr.get("CQI"))
            s["nr_ri"] = _to_int(nr.get("RI"))
            s["nr_rbs"] = _to_int(nr.get("numRbs"))
            s["nr_dl_mcs"] = _to_int(nr.get("downMCS"))
            s["nr_ul_mcs"] = _to_int(nr.get("upMCS"))
            s["nr_dl_mod"] = nr.get("downlinkModType")
            s["nr_ul_mod"] = nr.get("uplinkModType")
            bwd = _to_float(nr.get("downBandWidth"))
            s["nr_dl_bw_mhz"] = bwd/1000.0 if bwd else None
        if lte:
            s["lte_band"] = f"B{lte.get('band')}"
            s["lte_pci"] = _to_int(lte.get("PCI"))
            s["lte_earfcn"] = _to_int(lte.get("ARFCN"))
            s["lte_cid"] = lte.get("cid")
            s["lte_tac"] = lte.get("TAC")
            s["lte_rsrp"] = _to_float(lte.get("RSRP"))
            s["lte_rsrq"] = _to_float(lte.get("RSRQ"))
            v = _to_float(lte.get("SNR")); s["lte_snr"] = v/10.0 if v is not None else None
            v = _to_float(lte.get("txPowerPUCCH")); s["lte_tx_power"] = v/10.0 if v is not None else None
            s["lte_cqi"] = _to_int(lte.get("CQI"))
            s["lte_ri"] = _to_int(lte.get("RI"))
            s["lte_rbs"] = _to_int(lte.get("numRbs"))


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


# ===========================================================================
# STORAGE + ANOMALY DETECTION
# ===========================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
    network_type TEXT, sim_status INTEGER, isp TEXT, mcc TEXT, mnc TEXT,
    nr_band TEXT, nr_pci INTEGER, nr_arfcn INTEGER, nr_cid TEXT, nr_tac TEXT,
    ss_rsrp REAL, ss_rsrq REAL, ss_sinr REAL,
    nr_cqi INTEGER, nr_ri INTEGER, nr_rbs INTEGER,
    nr_dl_mcs INTEGER, nr_ul_mcs INTEGER, nr_dl_mod TEXT, nr_ul_mod TEXT,
    nr_dl_bw_mhz REAL, nr_tx_power REAL,
    lte_band TEXT, lte_pci INTEGER, lte_earfcn INTEGER, lte_cid TEXT, lte_tac TEXT,
    lte_rsrp REAL, lte_rsrq REAL, lte_snr REAL,
    lte_cqi INTEGER, lte_ri INTEGER, lte_rbs INTEGER, lte_tx_power REAL,
    dl_speed INTEGER, ul_speed INTEGER,
    cpu_load REAL, mem_used REAL, uptime_sec INTEGER, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_pci ON samples(nr_pci);
CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
    severity TEXT, kind TEXT, message TEXT, sample_id INTEGER
);
"""


@dataclass
class Thresholds:
    rsrp_critical: float = -110.0
    rsrp_poor: float = -100.0
    sinr_critical: float = 0.0
    sinr_poor: float = 5.0
    tx_power_high: float = 18.0
    cqi_low: int = 6
    rsrp_drop_db: float = 10.0
    baseline_min_samples: int = 30


class Store:
    def __init__(self, p: Path):
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(p)
        self.conn.executescript(SCHEMA)
        # Add columns required by this version without removing historical data.
        existing = {row[1] for row in self.conn.execute("PRAGMA table_info(samples)")}
        reference = sqlite3.connect(":memory:")
        try:
            reference.executescript(SCHEMA)
            for _, column, kind, *_ in reference.execute("PRAGMA table_info(samples)"):
                if column not in existing:
                    self.conn.execute(f'ALTER TABLE samples ADD COLUMN "{column}" {kind}')
        finally:
            reference.close()
        self.conn.commit()

    def insert_sample(self, s):
        cols = ["ts","network_type","sim_status","isp","mcc","mnc",
                "nr_band","nr_pci","nr_arfcn","nr_cid","nr_tac",
                "ss_rsrp","ss_rsrq","ss_sinr","nr_cqi","nr_ri","nr_rbs",
                "nr_dl_mcs","nr_ul_mcs","nr_dl_mod","nr_ul_mod",
                "nr_dl_bw_mhz","nr_tx_power",
                "lte_band","lte_pci","lte_earfcn","lte_cid","lte_tac",
                "lte_rsrp","lte_rsrq","lte_snr","lte_cqi","lte_ri","lte_rbs",
                "lte_tx_power","dl_speed","ul_speed",
                "cpu_load","mem_used","uptime_sec"]
        vals = [s.get(c) for c in cols] + [json.dumps(s.get("raw", {}), default=str)]
        sql = (f"INSERT INTO samples ({','.join(cols + ['raw_json'])}) "
               f"VALUES ({','.join('?' * (len(cols)+1))})")
        cur = self.conn.execute(sql, vals)
        self.conn.commit()
        return cur.lastrowid

    def insert_anomaly(self, ts, sev, kind, msg, sid=None):
        self.conn.execute(
            "INSERT INTO anomalies (ts,severity,kind,message,sample_id) VALUES (?,?,?,?,?)",
            (ts, sev, kind, msg, sid))
        self.conn.commit()

    def baseline_for_pci(self, pci, field, since_min=60*24):
        if pci is None:
            return None, None, 0
        rows = self.conn.execute(
            f"SELECT {field} FROM samples WHERE nr_pci=? AND {field} IS NOT NULL "
            f"AND julianday(ts) >= julianday('now', ?)",
            (pci, f"-{since_min} minutes")).fetchall()
        vals = [r[0] for r in rows if r[0] is not None]
        if not vals:
            return None, None, 0
        return mean(vals), (pstdev(vals) if len(vals) > 1 else 0.0), len(vals)

    def close(self):
        self.conn.close()


class AnomalyDetector:
    def __init__(self, store, t):
        self.store = store
        self.t = t

    def evaluate(self, s, sid):
        f = []
        t = self.t
        rsrp = s.get("ss_rsrp") if s.get("ss_rsrp") is not None else s.get("lte_rsrp")
        sinr = s.get("ss_sinr") if s.get("ss_sinr") is not None else s.get("lte_snr")
        txp = s.get("nr_tx_power") if s.get("nr_tx_power") is not None else s.get("lte_tx_power")
        cqi = s.get("nr_cqi") if s.get("nr_cqi") is not None else s.get("lte_cqi")
        ri = s.get("nr_ri") if s.get("nr_ri") is not None else s.get("lte_ri")
        rbs = s.get("nr_rbs") if s.get("nr_rbs") is not None else s.get("lte_rbs")
        dl = s.get("dl_speed")
        pci = s.get("nr_pci")
        if rsrp is not None and pci is not None:
            mu, _, n = self.store.baseline_for_pci(pci, "ss_rsrp")
            if n >= t.baseline_min_samples and mu is not None:
                d = mu - rsrp
                if d >= t.rsrp_drop_db:
                    f.append(("warning", "antenna_or_obstacle",
                              f"RSRP={rsrp:.1f} su PCI={pci} è {d:.1f}dB sotto baseline ({mu:.1f}, n={n})."))
        if rsrp is not None and sinr is not None and rsrp > -90 and sinr < t.sinr_poor:
            f.append(("warning", "interference_or_congestion",
                      f"RSRP={rsrp:.1f} buono ma SINR={sinr:.1f}."))
        if rsrp is not None and rsrp < t.rsrp_critical:
            f.append(("critical", "weak_signal", f"RSRP={rsrp:.1f} critico."))
        elif rsrp is not None and rsrp < t.rsrp_poor:
            f.append(("info", "weak_signal", f"RSRP={rsrp:.1f} scarso."))
        if sinr is not None and sinr < t.sinr_critical:
            f.append(("critical", "sinr_critical", f"SINR={sinr:.1f}."))
        if txp is not None and txp > t.tx_power_high:
            f.append(("warning", "uplink_degraded", f"Tx={txp:.1f} vicino max."))
        if rsrp is not None and rsrp > -95 and rbs is not None and rbs < 20 and dl is not None and dl < 5e6:
            f.append(("info", "cell_congestion", f"RSRP ok ma RBs={rbs} DL={dl/1e6:.1f}Mbps."))
        if ri is not None and ri <= 1 and rsrp is not None and rsrp > -100:
            f.append(("info", "mimo_degraded", f"RI={ri} con RSRP={rsrp:.1f}."))
        if cqi is not None and cqi < t.cqi_low:
            f.append(("info", "channel_degraded", f"CQI={cqi}."))
        return f


# ===========================================================================
# MAIN
# ===========================================================================

_RUN = True


def _sigint(signum, frame):
    global _RUN
    _RUN = False


def run_once(host, password, store, detector, username):
    with Collector(host, password, username) as c:
        s = c.collect()
    sid = store.insert_sample(s)
    for sev, kind, msg in detector.evaluate(s, sid):
        log.warning("[%s] %s: %s", sev.upper(), kind, msg)
        store.insert_anomaly(s["ts"], sev, kind, msg, sid)
    rsrp = s.get("ss_rsrp") if s.get("ss_rsrp") is not None else s.get("lte_rsrp")
    sinr = s.get("ss_sinr") if s.get("ss_sinr") is not None else s.get("lte_snr")
    pci = s.get("nr_pci") if s.get("nr_pci") is not None else s.get("lte_pci")
    dl = s.get("dl_speed")
    log.info("sample #%d net=%s PCI=%s RSRP=%s SINR=%s DL=%s",
             sid, s.get("network_type"), pci,
             f"{rsrp:.1f}" if rsrp is not None else "n/a",
             f"{sinr:.1f}" if sinr is not None else "n/a",
             f"{dl/1e6:.2f}Mbps" if dl else "n/a")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
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
    detector = AnomalyDetector(store, Thresholds())

    log.info("Avvio: host=%s interval=%ds db=%s",
             args.host, args.interval, args.db)
    try:
        if args.once:
            run_once(args.host, args.password, store, detector, args.username)
            return
        while _RUN:
            t0 = time.time()
            try:
                run_once(args.host, args.password, store, detector, args.username)
            except Exception as e:
                log.error("Errore poll: %s", e)
                store.insert_anomaly(
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "warning", "poll_failed", str(e), None)
            el = time.time() - t0
            for _ in range(int(max(1.0, args.interval - el))):
                if not _RUN:
                    break
                time.sleep(1)
    finally:
        store.close()


if __name__ == "__main__":
    main()
