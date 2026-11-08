#!/usr/bin/env python3
"""
nx200_monitor_v3.py
---------------------------------------------------------------------------
Polling + log su SQLite per TP-Link Archer NX200 (firmware Build 251120+).

Versione 3: client COMPLETAMENTE STANDALONE.
Non dipende piu' da tplinkrouterc6u perche' la libreria non supporta
questa generazione di firmware. Implementa direttamente lo schema
"cgi_gdpr" di TP-Link: AES-128-CBC sul payload, RSA sulla signature,
JSESSIONID per la sessione.

Riferimenti per il reverse engineering:
  - https://hex.fish/2021/05/10/tp-link-gdpr/
  - https://github.com/Electry/TPLink-W9960-APIClient
  - https://github.com/0xf15h/tp_link_gdpr

Uso:
    python nx200_monitor_v3.py --host https://192.168.1.1 --password TUA_PWD --once -v
    python nx200_monitor_v3.py --host https://192.168.1.1 --password TUA_PWD --interval 60

Dipendenze:
    pip install requests pycryptodome
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
import sqlite3
import string
import sys
import time
import urllib3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nx200v3")


# ===========================================================================
# CRYPTO HELPERS
# ===========================================================================

def _rand_hex(n: int) -> str:
    """n caratteri hex casuali (0-9, a-f). TP-Link AES key/iv sono 16 hex char."""
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _aes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))


def _aes_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)


def _rsa_encrypt(message: str, n_hex: str, e_hex: str,
                 chunk_size_override: int | None = None) -> str:
    """
    RSA "nopadding" come fa TP-Link. Replica RSAEncrypt + il wrapper
    rsaEncrypt (globale) che spezza la stringa in chunks.

    Comportamento (verificato dal sorgente):
      - La stringa viene spezzata in chunks da `chunk_size` byte
      - Ogni chunk viene encoded UTF-8 char-by-char
      - Ogni chunk viene zero-padded a destra fino a n_bytes byte
      - BigInteger big-endian, poi m^e mod n
      - Risultato concatenato in hex (con leading "0" se dispari)

    chunk_size_override permette di forzare la dim del chunk:
      - Per TP-Link CPE recenti (NX200) il chunk_size standard e' n_bytes - 11
        (53 byte per modulus 512 bit), un retaggio PKCS#1 anche con nopadding.
      - Per altri firmware: n_bytes (64 byte per modulus 512 bit).
    """
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    n_bytes = (n.bit_length() + 7) // 8

    chunk_size = chunk_size_override if chunk_size_override is not None else (n_bytes - 11)

    msg_bytes = message.encode("utf-8")
    out_hex: list[str] = []
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


# ===========================================================================
# CLIENT
# ===========================================================================

class TPLinkGdprClient:
    """
    Client per l'endpoint /cgi_gdpr di TP-Link.
    Gestisce login (RSA+AES) e richieste successive (solo AES + sequence).
    """

    def __init__(self, base_url: str, password: str, username: str = "admin"):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password

        self.session = requests.Session()
        self.session.verify = False  # cert self-signed del modem
        # Riproduciamo ESATTAMENTE gli header del browser visti nel cURL reale.
        # Alcuni firmware TP-Link sono pignoli su questi header e rispondono
        # in modo non-HTTP-conforme se ne mancano alcuni.
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/148.0.0.0 Safari/537.36",
            "Accept": "text/plain, */*; q=0.01",
            "Accept-Language": "it-IT,it;q=0.9",
            "Origin": self.base_url,
            "Referer": self.base_url + "/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Connection": "keep-alive",
        })

        # popolati al login
        self.aes_key: bytes | None = None
        self.aes_iv: bytes | None = None
        self.aes_key_str: str | None = None  # versione hex 16 char
        self.aes_iv_str: str | None = None
        self.rsa_n: str | None = None
        self.rsa_e: str | None = None
        self.rsa_seq: int = 0
        self.md5_hash_pw: str | None = None
        self.jsessionid: str | None = None
        self.token: str | None = None  # alcuni firmware: extra "TokenID" header
        self._rsa_chunk_size: int | None = None  # popolato al login con il chunk vincente

    # ----- low-level helpers ------------------------------------------------

    def _get_rsa_key_and_seq(self) -> None:
        """
        Recupera modulus/exponent RSA e il sequence number iniziale.
        Su firmware vecchi: GET /cgi/getParm
        Su firmware GDPR (NX200 build 251120): POST /cgi-bin/luci/;stok=/login?form=keys
        """
        # Tenta prima il path "moderno" (NX200) - POST verso login?form=keys
        url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=keys&operation=read"
        try:
            r = self.session.post(url, timeout=10)
            if r.ok and r.text.strip().startswith("{"):
                obj = r.json()
                # struttura tipica: {"success": true, "data": {"password": ["e","n"]}}
                data = obj.get("data") or obj
                pw = data.get("password") or data.get("key")
                if pw and isinstance(pw, list) and len(pw) >= 2:
                    self.rsa_e = pw[0]
                    self.rsa_n = pw[1]
                    log.debug("RSA key via /login?form=keys: n=%s... e=%s",
                              self.rsa_n[:16], self.rsa_e)
                    # Seq separato:
                    self._get_seq_modern()
                    return
        except Exception as e:
            log.debug("login?form=keys non disponibile: %s", e)

        # Fallback: /cgi/getParm (firmware piu' vecchi)
        url = f"{self.base_url}/cgi/getParm"
        r = self.session.post(url, timeout=10)
        if not r.ok:
            raise RuntimeError(f"getParm fallito: HTTP {r.status_code}")
        text = r.text
        m_ee = re.search(r'ee\s*=\s*"([^"]+)"', text)
        m_nn = re.search(r'nn\s*=\s*"([^"]+)"', text)
        m_seq = re.search(r'seq\s*=\s*"?(\d+)"?', text)
        if not (m_ee and m_nn and m_seq):
            raise RuntimeError(
                f"getParm: non riesco a estrarre ee/nn/seq.\n"
                f"Risposta: {text[:300]}"
            )
        self.rsa_e = m_ee.group(1)
        self.rsa_n = m_nn.group(1)
        self.rsa_seq = int(m_seq.group(1))
        log.debug("RSA key via getParm: n=%s... e=%s seq=%d",
                  self.rsa_n[:16], self.rsa_e, self.rsa_seq)

    def _get_seq_modern(self) -> None:
        """Recupera il sequence number sui firmware GDPR moderni (login?form=auth)."""
        url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=auth"
        # Alcuni firmware espongono seq qui, altri lo emettono al primo cgi_gdpr.
        # Proviamo, ma se fallisce partiamo da seq=0 (verra' settato dalla risposta login).
        try:
            r = self.session.post(url, data={"operation": "read"}, timeout=10)
            if r.ok and r.text.strip().startswith("{"):
                obj = r.json()
                data = obj.get("data") or {}
                seq = data.get("seq")
                if seq is not None:
                    self.rsa_seq = int(seq)
                    log.debug("Seq da login?form=auth: %d", self.rsa_seq)
                    return
        except Exception as e:
            log.debug("login?form=auth non disponibile: %s", e)
        # Lasciamo seq = 0 e speriamo che il server ce lo dia nel response
        self.rsa_seq = 0

    # ----- login ------------------------------------------------------------

    def login(self) -> None:
        log.info("Step 1: recupero chiavi RSA...")
        self._get_rsa_key_and_seq()

        # AES key/iv: 16 caratteri hex random, usati come stringa ASCII.
        # AES.getKeyString() del JS ritorna "key=%key%&iv=%iv%" sostituendo
        # %key% e %iv% con i valori.
        self.aes_key_str = _rand_hex(16)
        self.aes_iv_str = _rand_hex(16)
        self.aes_key = self.aes_key_str.encode("ascii")
        self.aes_iv = self.aes_iv_str.encode("ascii")
        aes_key_string = f"key={self.aes_key_str}&iv={self.aes_iv_str}"

        # Encryptor.setHash(user, pwd) => MD5(user + pwd) [no separatori]
        self.md5_hash_pw = hashlib.md5(
            f"{self.username}{self.password}".encode()
        ).hexdigest()

        log.info("Step 2: invio richiesta di login cifrata...")

        # Body pre-cifratura: il browser usa il formato "stringa $.dm.Proxy",
        # ma per il login specifico passa attraverso $.tpAjax che invia
        # "username=...&password=..." come body raw (cgi/login lo accetta cosi').
        # Provo il formato piu' affidabile mostrato dal $.dm.Proxy dutPrefilter:
        # un JSON serializzato + "\r\n".
        login_payload = {
            "data": {"username": self.username, "password": self.password},
            "operation": "cgi",
        }
        plain_body = json.dumps(login_payload) + "\r\n"

        encrypted = _aes_encrypt(self.aes_key, self.aes_iv, plain_body.encode())
        data_b64 = base64.b64encode(encrypted).decode()

        # sign al login (isLogin=1):  aesKeyString + "&h=" + hash + "&s=" + (seq+dataLen)
        assert self.rsa_n and self.rsa_e
        sign_plain = (
            f"{aes_key_string}"
            f"&h={self.md5_hash_pw}"
            f"&s={self.rsa_seq + len(data_b64)}"
        )
        log.debug("Sign in chiaro (login): %s", sign_plain)
        log.debug("Sign length: %d byte", len(sign_plain.encode()))

        # Proviamo diversi chunk size per RSA, perche' il wrapper $.rsa.encrypt
        # (esterno al sorgente che abbiamo visto) decide la dim chunk e
        # non abbiamo certezza assoluta su quale sia. Le due varianti
        # piu' comuni in implementazioni TP-Link:
        #   - n_bytes - 11 (53 byte per modulus 512 bit) - retaggio PKCS#1
        #   - n_bytes      (64 byte) - chunk pieno
        # Inoltre alcuni firmware usano:
        #   - n_bytes - 1  (63 byte) - margine di 1 bit per stare sotto n
        rsa_n_bytes = (int(self.rsa_n, 16).bit_length() + 7) // 8
        chunk_sizes = [
            rsa_n_bytes - 11,   # piu' comune in TP-Link
            rsa_n_bytes - 1,    # margine 1 byte
            rsa_n_bytes,        # chunk pieno (zero padding solo se l'ultimo)
        ]

        last_err = None
        for cs in chunk_sizes:
            log.debug("Tentativo login con RSA chunk_size=%d byte", cs)
            try:
                sign_hex = _rsa_encrypt(sign_plain, self.rsa_n, self.rsa_e,
                                         chunk_size_override=cs)
            except Exception as e:
                last_err = f"chunk={cs}: errore RSA: {e}"
                continue

            body = f"sign={sign_hex}\r\ndata={data_b64}\r\n"
            body_bytes = body.encode("utf-8")
            url = f"{self.base_url}/cgi_gdpr?9"
            headers = {
                "Content-Type": "text/plain",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "text/plain, */*; q=0.01",
                "TokenID": "",
                "Content-Length": str(len(body_bytes)),
            }
            try:
                r = self.session.post(url, data=body_bytes, headers=headers, timeout=15)
            except requests.exceptions.ConnectionError as e:
                # Caso speciale: il modem a volte risponde con una "status line"
                # malformata. Catturiamo BadStatusLine per vedere cosa contiene.
                err_str = str(e)
                if "BadStatusLine" in err_str:
                    log.debug("chunk=%d: BadStatusLine (server risponde con body raw "
                              "senza header HTTP). Errore: %s", cs, err_str)
                    last_err = (f"chunk={cs}: BadStatusLine - server invia body raw "
                                f"senza header HTTP")
                else:
                    last_err = f"chunk={cs}: connessione chiusa dal server"
                    log.debug("chunk=%d: %s", cs, e)
                continue

            log.debug("chunk=%d -> HTTP %d, len=%d, cookies=%s",
                      cs, r.status_code, len(r.text), dict(r.cookies))

            if r.status_code != 200:
                last_err = f"chunk={cs}: HTTP {r.status_code}"
                continue
            if not r.text.strip():
                last_err = f"chunk={cs}: risposta vuota"
                continue

            # Successo HTTP. Memorizziamo il chunk_size vincente per le richieste
            # successive (sara' usato anche da request_data).
            self._rsa_chunk_size = cs

            # Decifra
            try:
                decoded = base64.b64decode(r.text)
                decrypted = _aes_decrypt(self.aes_key, self.aes_iv,
                                          decoded).decode("utf-8", errors="replace")
                log.debug("Risposta login decifrata (chunk=%d):\n%s",
                          cs, decrypted[:500])
            except Exception as e:
                last_err = f"chunk={cs}: risposta non decifrabile: {e}"
                log.debug("Risposta raw chunk=%d: %s", cs, r.text[:200])
                continue

            # $.ret nella risposta
            m = re.search(r"\$\.ret\s*=\s*(\d+)", decrypted)
            if m and m.group(1) != "0":
                # password sbagliata o altro errore applicativo
                raise RuntimeError(
                    f"Login rifiutato dal server: $.ret={m.group(1)}. "
                    f"Risposta: {decrypted[:300]}"
                )

            jsess = (r.cookies.get("JSESSIONID")
                     or self.session.cookies.get("JSESSIONID"))
            if jsess:
                self.jsessionid = jsess
                log.info("Login OK (RSA chunk_size=%d)", cs)
            else:
                log.warning("Login: no JSESSIONID. Proseguo, potrebbe essere "
                            "autenticato via altro meccanismo (chunk=%d).", cs)

            m_tok = re.search(r'stok\s*=?\s*"?([a-f0-9]+)"?', decrypted)
            if m_tok:
                self.token = m_tok.group(1)
                log.info("Token estratto: %s...", self.token[:8])

            return  # vittoria!

        raise RuntimeError(
            f"Login fallito con tutti i chunk size provati ({chunk_sizes}). "
            f"Ultimo errore: {last_err}. "
            f"Possibili cause: password errata, altro utente loggato, "
            f"oppure il firmware usa uno schema RSA chunking diverso."
        )

    # ----- richieste cifrate ------------------------------------------------

    def request_data(self, plain_payload: str) -> str:
        """
        Richiesta cifrata "post-login":
          - sign = RSA("h=<md5>&s=<seq+dataLen>")  [isLogin=0]
          - body cifrato AES, base64
          - POST /cgi_gdpr?9
          - risposta AES-cifrata, viene decifrata e ritornata in chiaro
        """
        assert self.aes_key and self.aes_iv and self.md5_hash_pw
        assert self.rsa_n and self.rsa_e

        encrypted = _aes_encrypt(self.aes_key, self.aes_iv, plain_payload.encode())
        data_b64 = base64.b64encode(encrypted).decode()

        # Post-login (isLogin=0): "h=" + hash + "&s=" + (seq+dataLen)
        sign_plain = f"h={self.md5_hash_pw}&s={self.rsa_seq + len(data_b64)}"
        sign_hex = _rsa_encrypt(sign_plain, self.rsa_n, self.rsa_e,
                                 chunk_size_override=self._rsa_chunk_size)

        body = f"sign={sign_hex}\r\ndata={data_b64}\r\n"

        url = f"{self.base_url}/cgi_gdpr?9"
        headers = {
            "Content-Type": "text/plain",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "text/plain, */*; q=0.01",
            "TokenID": self.token or "",
        }
        r = self.session.post(url, data=body, headers=headers, timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"Richiesta HTTP {r.status_code}: {r.text[:200]}")
        if not r.text.strip():
            return ""
        decoded = base64.b64decode(r.text)
        return _aes_decrypt(self.aes_key, self.aes_iv, decoded).decode(
            "utf-8", errors="replace"
        )

    def logout(self) -> None:
        try:
            self.request_data("8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
        except Exception as e:
            log.debug("Logout fallito (ignorato): %s", e)


# ===========================================================================
# DATAMODEL HELPER (richiede TPLinkGdprClient gia' loggato)
# ===========================================================================

class DataModel:
    """
    Astrae le chiamate $.dm.get/getList della web UI.

    Dal sorgente JS (gdprProxy.js, dutPrefilter):
        return JSON.stringify(data) + "\\r\\n";
    Dove data e':
        {"data": {"oid": "...", "stack": "...", "pstack": "..."},
         "operation": "go"|"gl"|"so"|"op"|"cgi"|...}
    """

    OP_GET = "go"
    OP_GETLIST = "gl"
    OP_SET = "so"
    OP_OP = "op"

    def __init__(self, client: TPLinkGdprClient):
        self.client = client

    def get(self, oid: str, fields: list[str] | None = None,
            stack: str = "0,0,0,0,0,0") -> dict[str, Any]:
        return self._call(self.OP_GET, oid, fields, stack)

    def get_list(self, oid: str, fields: list[str] | None = None,
                 stack: str = "0,0,0,0,0,0") -> list[dict[str, Any]]:
        result = self._call(self.OP_GETLIST, oid, fields, stack, as_list=True)
        if isinstance(result, list):
            return result
        return [result] if result else []

    def _call(self, operation: str, oid: str, fields: list[str] | None,
              stack: str, as_list: bool = False) -> Any:
        # Costruiamo il JSON come fa dutPrefilter
        data: dict[str, Any] = {
            "oid": oid,
            "stack": stack,
            "pstack": "0,0,0,0,0,0",
        }
        # I "fields" nella UI vengono inclusi come chiavi del data con valore ""
        if fields:
            for f in fields:
                data[f] = ""
        payload = {"data": data, "operation": operation}
        body = json.dumps(payload) + "\r\n"

        log.debug("DM %s %s: body=%s", operation, oid, body.strip()[:200])
        resp = self.client.request_data(body)
        log.debug("DM %s %s: response=%s", operation, oid, resp[:300])
        return self._parse_response(resp, as_list=as_list)

    @staticmethod
    def _parse_response(text: str, as_list: bool = False) -> Any:
        """
        Risposta del modem dopo decifratura AES.
        Puo' essere:
          - JSON: {"success": true, "data": {...} | [...], "errorcode": 0}
          - oppure formato "$.ret=0\\n[stack]idx\\nkey=value\\n..."
        Proviamo prima JSON, poi fallback al parser INI.
        """
        text = text.strip()
        if not text:
            return [] if as_list else {}

        # Caso 1: JSON
        if text.startswith("{") or text.startswith("["):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    # struttura tipica: {"success": true, "data": {...}, ...}
                    if "data" in obj:
                        return obj["data"]
                    return obj
                return obj
            except json.JSONDecodeError as e:
                log.debug("Risposta non e' JSON pulito (%s), provo INI parser", e)

        # Caso 2: formato $.act / pseudo-INI (vecchio stile $.dm)
        records: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.rstrip("\r")
            if not line:
                continue
            if line.startswith("$."):
                continue
            if line.startswith("["):
                # nuovo record / separatore
                if current:
                    records.append(current)
                    current = {}
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                current[k.strip()] = v.strip()
        if current:
            records.append(current)

        if as_list:
            return records
        return records[0] if records else {}


# ===========================================================================
# OID E CAMPI DA INTERROGARE (mappati dal JS della pagina status.htm)
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

NET_TYPE_LABELS = {
    -1: "Invalid", 0: "None", 1: "GSM", 2: "WCDMA", 3: "LTE",
    4: "TDSCDMA", 5: "CDMA1X", 6: "EVDO", 7: "LTE+", 8: "5G NR",
}


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

    def __exit__(self, exc_type, exc, tb):
        try:
            self.client.logout()
        except Exception:
            pass

    def collect(self) -> dict[str, Any]:
        assert self.dm
        sample: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "raw": {},
        }

        for oid, (stack, fields) in QUERIES.items():
            try:
                data = self.dm.get(oid, fields, stack or "0,0,0,0,0,0")
                sample["raw"][oid] = data
            except Exception as e:
                log.warning("Lettura %s fallita: %s", oid, e)
                sample["raw"][oid] = {"_error": str(e)}

        try:
            cells = self.dm.get_list(SERVING_CELL_OID, SERVING_CELL_FIELDS)
            sample["raw"][SERVING_CELL_OID] = cells
        except Exception as e:
            log.warning("Lettura %s fallita: %s", SERVING_CELL_OID, e)
            cells = []

        self._normalize(sample, cells)
        return sample

    @staticmethod
    def _normalize(sample, cells):
        raw = sample["raw"]

        link = raw.get("DEV2_LTE_LINK_CFG", {}) or {}
        nt = _to_int(link.get("networkType"))
        sample["network_type"] = NET_TYPE_LABELS.get(nt) if nt is not None else None
        sample["sim_status"] = _to_int(link.get("simStatus"))

        prof = raw.get("DEV2_LTE_PROF_STAT", {}) or {}
        sample["isp"] = prof.get("ispName") or prof.get("spn")
        sample["mcc"] = prof.get("ispMcc")
        sample["mnc"] = prof.get("ispMnc")

        usim = raw.get("DEV2_CELL_INTF_USIM", {}) or {}
        sample["imsi"] = usim.get("IMSI")
        sample["iccid"] = usim.get("ICCID")
        sample["msisdn"] = usim.get("MSISDN")

        intf = raw.get("DEV2_XTP_LTE_INTF_CFG", {}) or {}
        sample["dl_speed"] = _to_int(intf.get("curRxSpeed"))
        sample["ul_speed"] = _to_int(intf.get("curTxSpeed"))

        sample["cpu_load"] = _to_float((raw.get("DEV2_PROC_STATUS") or {}).get("CPUUsage"))
        mem = raw.get("DEV2_MEM_STATUS", {}) or {}
        mt, mf = _to_float(mem.get("total")), _to_float(mem.get("free"))
        if mt and mf is not None and mt > 0:
            sample["mem_used"] = (mt - mf) / mt * 100.0
        sample["uptime_sec"] = _to_int((raw.get("DEV2_DEV_INFO") or {}).get("upTime"))

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
            sample["nr_band"] = f"N{nr.get('band')}"
            sample["nr_pci"] = _to_int(nr.get("PCI"))
            sample["nr_arfcn"] = _to_int(nr.get("ARFCN"))
            sample["nr_cid"] = nr.get("cid")
            sample["nr_tac"] = nr.get("TAC")
            sample["ss_rsrp"] = _to_float(nr.get("SSRSRP"))
            sample["ss_rsrq"] = _to_float(nr.get("SSRSRQ"))
            v = _to_float(nr.get("SSSINR"))
            sample["ss_sinr"] = v / 10.0 if v is not None else None
            v = _to_float(nr.get("txPowerPUCCH"))
            sample["nr_tx_power"] = v / 10.0 if v is not None else None
            sample["nr_cqi"] = _to_int(nr.get("CQI"))
            sample["nr_ri"] = _to_int(nr.get("RI"))
            sample["nr_rbs"] = _to_int(nr.get("numRbs"))
            sample["nr_dl_mcs"] = _to_int(nr.get("downMCS"))
            sample["nr_ul_mcs"] = _to_int(nr.get("upMCS"))
            sample["nr_dl_mod"] = nr.get("downlinkModType")
            sample["nr_ul_mod"] = nr.get("uplinkModType")
            bwd = _to_float(nr.get("downBandWidth"))
            sample["nr_dl_bw_mhz"] = bwd / 1000.0 if bwd else None

        if lte:
            sample["lte_band"] = f"B{lte.get('band')}"
            sample["lte_pci"] = _to_int(lte.get("PCI"))
            sample["lte_earfcn"] = _to_int(lte.get("ARFCN"))
            sample["lte_cid"] = lte.get("cid")
            sample["lte_tac"] = lte.get("TAC")
            sample["lte_rsrp"] = _to_float(lte.get("RSRP"))
            sample["lte_rsrq"] = _to_float(lte.get("RSRQ"))
            v = _to_float(lte.get("SNR"))
            sample["lte_snr"] = v / 10.0 if v is not None else None
            v = _to_float(lte.get("txPowerPUCCH"))
            sample["lte_tx_power"] = v / 10.0 if v is not None else None
            sample["lte_cqi"] = _to_int(lte.get("CQI"))
            sample["lte_ri"] = _to_int(lte.get("RI"))
            sample["lte_rbs"] = _to_int(lte.get("numRbs"))


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
# STORAGE + ANOMALY DETECTION (uguali alla v2)
# ===========================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
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
    cpu_load REAL, mem_used REAL, uptime_sec INTEGER,
    raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_pci ON samples(nr_pci);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, severity TEXT, kind TEXT, message TEXT, sample_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(ts);
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
    cell_changes_per_hour: int = 5


class Store:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert_sample(self, s: dict[str, Any]) -> int:
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
        return cur.lastrowid  # type: ignore

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
            f"AND ts >= datetime('now', ?)",
            (pci, f"-{since_min} minutes")).fetchall()
        vals = [r[0] for r in rows if r[0] is not None]
        if not vals:
            return None, None, 0
        return mean(vals), (pstdev(vals) if len(vals) > 1 else 0.0), len(vals)

    def recent_cell_changes(self, minutes=60):
        rows = self.conn.execute(
            "SELECT nr_pci FROM samples WHERE nr_pci IS NOT NULL "
            "AND ts >= datetime('now', ?) ORDER BY ts",
            (f"-{minutes} minutes",)).fetchall()
        if len(rows) < 2:
            return 0
        ch, prev = 0, rows[0][0]
        for (p,) in rows[1:]:
            if p != prev:
                ch += 1
                prev = p
        return ch

    def close(self):
        self.conn.close()


class AnomalyDetector:
    def __init__(self, store: Store, t: Thresholds):
        self.store = store
        self.t = t

    def evaluate(self, s, sid):
        f = []
        t = self.t
        rsrp = s.get("ss_rsrp") or s.get("lte_rsrp")
        sinr = s.get("ss_sinr") or s.get("lte_snr")
        txp = s.get("nr_tx_power") or s.get("lte_tx_power")
        cqi = s.get("nr_cqi") or s.get("lte_cqi")
        ri = s.get("nr_ri") or s.get("lte_ri")
        rbs = s.get("nr_rbs") or s.get("lte_rbs")
        dl = s.get("dl_speed")
        pci = s.get("nr_pci")

        if rsrp is not None and pci is not None:
            mu, _, n = self.store.baseline_for_pci(pci, "ss_rsrp")
            if n >= t.baseline_min_samples and mu is not None:
                d = mu - rsrp
                if d >= t.rsrp_drop_db:
                    f.append(("warning", "antenna_or_obstacle",
                              f"RSRP={rsrp:.1f}dBm su PCI={pci} è {d:.1f}dB sotto baseline "
                              f"({mu:.1f}dBm, n={n})."))
        if rsrp and sinr and rsrp > -90 and sinr < t.sinr_poor:
            f.append(("warning", "interference_or_congestion",
                      f"RSRP={rsrp:.1f}dBm buono ma SINR={sinr:.1f}dB."))
        if rsrp is not None and rsrp < t.rsrp_critical:
            f.append(("critical", "weak_signal", f"RSRP={rsrp:.1f}dBm critico."))
        elif rsrp is not None and rsrp < t.rsrp_poor:
            f.append(("info", "weak_signal", f"RSRP={rsrp:.1f}dBm scarso."))
        if sinr is not None and sinr < t.sinr_critical:
            f.append(("critical", "sinr_critical", f"SINR={sinr:.1f}dB."))
        if txp is not None and txp > t.tx_power_high:
            f.append(("warning", "uplink_degraded", f"Tx={txp:.1f}dBm vicino max."))
        if rsrp and rsrp > -95 and rbs and rbs < 20 and dl and dl < 5e6:
            f.append(("info", "cell_congestion",
                      f"Segnale ok ma RBs={rbs} e DL={dl/1e6:.1f}Mbps."))
        if ri is not None and ri <= 1 and rsrp and rsrp > -100:
            f.append(("info", "mimo_degraded", f"RI={ri} con RSRP={rsrp:.1f}dBm."))
        if cqi is not None and cqi < t.cqi_low:
            f.append(("info", "channel_degraded", f"CQI={cqi}."))
        if sid % 10 == 0:
            ch = self.store.recent_cell_changes(60)
            if ch >= t.cell_changes_per_hour:
                f.append(("warning", "cell_ping_pong", f"{ch} cambi PCI/ora."))
        return f


# ===========================================================================
# MAIN
# ===========================================================================

_RUN = True


def _sigint(signum, frame):
    global _RUN
    _RUN = False
    log.info("Interruzione richiesta...")


def run_once(host, password, store, detector, username):
    with Collector(host, password, username) as c:
        sample = c.collect()
    sid = store.insert_sample(sample)
    for sev, kind, msg in detector.evaluate(sample, sid):
        log.warning("[%s] %s: %s", sev.upper(), kind, msg)
        store.insert_anomaly(sample["ts"], sev, kind, msg, sid)
    rsrp = sample.get("ss_rsrp") or sample.get("lte_rsrp")
    sinr = sample.get("ss_sinr") or sample.get("lte_snr")
    pci = sample.get("nr_pci") or sample.get("lte_pci")
    dl = sample.get("dl_speed")
    log.info("sample #%d net=%s PCI=%s RSRP=%s SINR=%s DL=%s",
             sid, sample.get("network_type"), pci,
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
        log.info("Bye.")


if __name__ == "__main__":
    main()
