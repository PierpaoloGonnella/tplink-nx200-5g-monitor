#!/usr/bin/env python3
"""
nx200_monitor_v2.py
---------------------------------------------------------------------------
Polling + log su SQLite per TP-Link Archer NX200 (firmware Build 251120+).

Differenze rispetto alla v1:
  - Bypassa i metodi get_status/get_lte_status della libreria che non
    funzionano sui firmware recenti (errore 'script0').
  - Usa la libreria SOLO per il login (gestione cifratura RSA/AES).
  - Implementa direttamente il protocollo $.dm.get usato dalla web UI:
    POST verso un endpoint CGI con body in formato proprietario TP-Link,
    chiedendo dati per OID specifici (DEV2_LTE_SERVING_CELL_INFO, ecc).
  - Al primo avvio rileva automaticamente quale combinazione di
    endpoint + formato funziona sul tuo firmware specifico e la riusa.

Uso:
    python nx200_monitor_v2.py --host http://192.168.1.1 --password TUA_PWD --once -v
    python nx200_monitor_v2.py --host http://192.168.1.1 --password TUA_PWD --interval 60

Dipendenze:
    pip install tplinkrouterc6u
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import signal
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

try:
    from tplinkrouterc6u import TplinkRouterProvider
except ImportError:
    print("ERRORE: pip install tplinkrouterc6u", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("nx200v2")


# ---------------------------------------------------------------------------
# COSA INTERROGHIAMO (OID + i campi richiesti)
# Tradotto dal JavaScript della pagina status.htm del modem.
# ---------------------------------------------------------------------------

LTE_STACK = "1,0,0,0,0,0"

QUERIES = {
    # Stato connessione cellulare (sim, network type, roaming)
    "DEV2_LTE_LINK_CFG": {
        "stack": LTE_STACK,
        "fields": [
            "simStatus", "networkType", "roamingStatus", "connectStatus",
        ],
    },
    # Stato registrazione di rete (regStat)
    "DEV2_LTE_NET_STATUS": {
        "stack": LTE_STACK,
        "fields": ["regStat"],
    },
    # ISP, MCC, MNC
    "DEV2_LTE_PROF_STAT": {
        "stack": LTE_STACK,
        "fields": ["ispName", "ispMcc", "ispMnc", "spn"],
    },
    # IMSI, ICCID, MSISDN
    "DEV2_CELL_INTF_USIM": {
        "stack": LTE_STACK,
        "fields": ["IMSI", "ICCID", "MSISDN", "SPN", "PNN"],
    },
    # Throughput istantaneo + data usage
    "DEV2_XTP_LTE_INTF_CFG": {
        "stack": LTE_STACK,
        "fields": [
            "curTxSpeed", "curRxSpeed", "totalStatistics",
            "enableDataLimit", "dataLimit", "limitation",
        ],
    },
    # CPU / RAM / uptime
    "DEV2_DEV_INFO": {"fields": ["upTime"]},
    "DEV2_MEM_STATUS": {"fields": ["total", "free"]},
    "DEV2_PROC_STATUS": {"fields": ["CPUUsage"]},
}

# Serving cell info e' una "list" (non un singolo oggetto): contiene
# piu' record (cella NR primaria, cella LTE primaria, eventuali SCC).
# La chiediamo a parte come getList.
SERVING_CELL_OID = "DEV2_LTE_SERVING_CELL_INFO"
SERVING_CELL_FIELDS = [
    "networkType", "cellConnectionStatus", "band", "cid", "TAC", "PCI",
    "ARFCN", "signalStrength",
    "RSRP", "RSRQ", "SNR",                  # LTE
    "SSRSRP", "SSRSRQ", "SSSINR",           # NR
    "CQI", "RI", "PMI", "tbSize", "numRbs",
    "downMCS", "upMCS",
    "downFreq", "upFreq", "downBandWidth", "upBandWidth",
    "downlinkModType", "uplinkModType",
    "txPowerPUCCH",
]

NET_TYPE_LABELS = {
    -1: "Invalid", 0: "None", 1: "GSM", 2: "WCDMA", 3: "LTE",
    4: "TDSCDMA", 5: "CDMA1X", 6: "EVDO", 7: "LTE+", 8: "5G NR",
}


# ---------------------------------------------------------------------------
# CLIENT $.dm CON AUTODETECT
# ---------------------------------------------------------------------------

class DmClient:
    """
    Client per il "DataModel" CGI di TP-Link. Riusa la sessione HTTP
    autenticata da tplinkrouterc6u, ma fa le richieste raw nel formato
    proprietario `[OID_NAME#stack#scope]index,N\\r\\nfield1\\r\\nfield2\\r\\n...`.

    Al primo uso prova varie combinazioni (endpoint URL + formato del body)
    finche' non ne trova una che risponde con dati validi, poi la riusa.
    """

    # Endpoint CGI candidati - i firmware TP-Link CPE ne usano uno tra questi.
    CANDIDATE_PATHS = [
        "/cgi_gdpr",
        "/cgi",
        "/cgi-bin/luci/;stok={stok}/admin/network/lte/status",
        "/cgi-bin/luci/;stok={stok}/admin/network",
    ]

    # Formati di body candidati.
    # Stile A: proprietario TP-Link (DataModel "form")
    #   body: "[OID#stack#0,0,0,0,0,0]0,N\r\nfield1\r\nfield2\r\n..."
    #   form data: form=getValue (o getList)
    # Stile B: JSON
    # Stile C: query string
    FORMATS = ["form_proprietary", "json", "querystring"]

    def __init__(self, router: Any):
        self._router = router
        self._session = self._find_session()
        self._host = self._find_host()
        self._stok = self._find_stok()

        # Endpoint + formato vincenti, popolati al primo successo
        self._path: str | None = None
        self._format: str | None = None

    # --- helpers per pescare interna lib --------------------------------

    def _find_session(self):
        for attr in ("_session", "session", "_request_session"):
            s = getattr(self._router, attr, None)
            if s is not None and hasattr(s, "post"):
                return s
        raise RuntimeError("Non riesco ad accedere alla sessione HTTP della libreria")

    def _find_host(self) -> str:
        for attr in ("host", "_host", "_url"):
            v = getattr(self._router, attr, None)
            if v:
                return v.rstrip("/")
        raise RuntimeError("Non riesco a determinare l'host del modem")

    def _find_stok(self) -> str:
        for attr in ("_stok", "stok", "_token"):
            v = getattr(self._router, attr, None)
            if v:
                return v
        return ""

    # --- formattazione body ---------------------------------------------

    @staticmethod
    def _body_proprietary(oid: str, fields: list[str], stack: str | None,
                          is_list: bool) -> tuple[str, dict[str, str]]:
        """
        Formato che TP-Link usa internamente (visto nel JS della UI):
            [OID_NAME#stack#0,0,0,0,0,0]0,N
            field1
            field2
            ...
        + form key `form=getValue` o `form=getList`.
        Lo stack di default e' "0,0,0,0,0,0", quello LTE e' "1,0,0,0,0,0".
        """
        stk = stack if stack else "0,0,0,0,0,0"
        # Per "getList" l'indice e' lasciato a 0 ma la risposta contiene N record.
        header = f"[{oid}#{stk}#0,0,0,0,0,0]0,{len(fields)}"
        body = "\r\n".join([header] + fields) + "\r\n"
        form = "getList" if is_list else "getValue"
        return body, {"form": form}

    @staticmethod
    def _body_json(oid: str, fields: list[str], stack: str | None,
                   is_list: bool) -> tuple[str, dict[str, str]]:
        payload = {
            "method": "do",
            "list" if is_list else "get": {
                "oid": oid,
                "stack": stack or "0,0,0,0,0,0",
                "fields": fields,
            },
        }
        return json.dumps(payload), {}

    @staticmethod
    def _body_querystring(oid: str, fields: list[str], stack: str | None,
                          is_list: bool) -> tuple[str, dict[str, str]]:
        from urllib.parse import urlencode
        params = {
            "oid": oid,
            "stack": stack or "0,0,0,0,0,0",
            "form": "getList" if is_list else "getValue",
        }
        for i, f in enumerate(fields):
            params[f"field{i}"] = f
        return urlencode(params), {}

    def _make_body(self, fmt: str, oid: str, fields: list[str],
                   stack: str | None, is_list: bool) -> tuple[str, dict[str, str], dict[str, str]]:
        """Ritorna (body, headers, extra_query)"""
        if fmt == "form_proprietary":
            body, extra = self._body_proprietary(oid, fields, stack, is_list)
            headers = {"Content-Type": "text/plain"}
            return body, headers, extra
        if fmt == "json":
            body, extra = self._body_json(oid, fields, stack, is_list)
            headers = {"Content-Type": "application/json"}
            return body, headers, extra
        if fmt == "querystring":
            body, extra = self._body_querystring(oid, fields, stack, is_list)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            return body, headers, extra
        raise ValueError(fmt)

    # --- parsing risposta -----------------------------------------------

    @staticmethod
    def _parse_response(text: str) -> Any:
        """
        Le risposte TP-Link DM possono essere:
          - JSON: {"data": {...}, "success": true, ...}  → restituiamo data
          - "ID" pseudo-INI:
              id 0
              field1 value1
              field2 value2
            Lo convertiamo in dict.
          - Lista pseudo-INI con piu' record separati da "id N".
        """
        text = text.strip()
        if not text:
            return None
        # JSON?
        if text.startswith("{") or text.startswith("["):
            try:
                obj = json.loads(text)
                # se contiene una sotto-chiave "data" la restituiamo
                if isinstance(obj, dict) and "data" in obj:
                    return obj["data"]
                return obj
            except json.JSONDecodeError:
                pass

        # pseudo-INI?
        # Linee del tipo "key value" oppure "id 0" come separatori di record.
        records: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.rstrip("\r")
            if not line:
                continue
            # alcuni firmware mettono "[error]0" o "[cgi]0" prima dei dati
            if line.startswith("["):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts
            if key == "id":
                # nuovo record
                if current:
                    records.append(current)
                current = {"id": val}
                continue
            current[key] = val
        if current:
            records.append(current)

        if not records:
            return None
        if len(records) == 1:
            return records[0]
        return records

    # --- core: get / get_list -------------------------------------------

    def _request(self, oid: str, fields: list[str], stack: str | None,
                 is_list: bool) -> Any:
        """Esegue una richiesta. Se non abbiamo ancora autorilevato il
        formato, prova tutte le combinazioni finche' una funziona."""
        last_err = None
        if self._path and self._format:
            combos = [(self._path, self._format)]
        else:
            combos = [
                (p, f) for p in self.CANDIDATE_PATHS for f in self.FORMATS
            ]

        for path, fmt in combos:
            body, headers, extra = self._make_body(fmt, oid, fields, stack, is_list)
            url = self._host + path.format(stok=self._stok)
            if extra:
                # accodiamo come querystring
                from urllib.parse import urlencode
                sep = "&" if "?" in url else "?"
                url = url + sep + urlencode(extra)

            try:
                r = self._session.post(url, data=body, headers=headers,
                                       timeout=10, verify=False)
            except Exception as e:  # noqa: BLE001
                last_err = f"{path}/{fmt}: {e}"
                continue

            if r.status_code != 200:
                last_err = f"{path}/{fmt}: HTTP {r.status_code}"
                continue

            parsed = self._parse_response(r.text)
            if parsed is None:
                last_err = f"{path}/{fmt}: risposta vuota"
                continue

            # Verifica plausibilita': se chiedevamo un campo specifico,
            # deve esserci almeno una chiave riconoscibile nella risposta
            if not self._looks_valid(parsed, fields):
                last_err = f"{path}/{fmt}: risposta non riconoscibile"
                log.debug("Risposta scartata da %s/%s: %r", path, fmt, r.text[:300])
                continue

            # Funziona! Memorizza
            if not self._path:
                log.info("Endpoint autorilevato: path=%s format=%s", path, fmt)
            self._path = path
            self._format = fmt
            return parsed

        raise RuntimeError(f"Nessuna combinazione endpoint/formato ha funzionato. "
                           f"Ultimo errore: {last_err}")

    @staticmethod
    def _looks_valid(parsed: Any, expected_fields: list[str]) -> bool:
        """Heuristic: la risposta contiene almeno un campo atteso."""
        if parsed is None:
            return False
        # case-insensitive check
        wanted = {f.lower() for f in expected_fields}
        def keys_of(obj):
            if isinstance(obj, dict):
                return {str(k).lower() for k in obj.keys()}
            if isinstance(obj, list):
                ks = set()
                for it in obj:
                    if isinstance(it, dict):
                        ks |= {str(k).lower() for k in it.keys()}
                return ks
            return set()
        return bool(wanted & keys_of(parsed))

    def get(self, oid: str, fields: list[str], stack: str | None = None) -> dict[str, Any]:
        result = self._request(oid, fields, stack, is_list=False)
        if isinstance(result, list):
            result = result[0] if result else {}
        return result or {}

    def get_list(self, oid: str, fields: list[str], stack: str | None = None) -> list[dict[str, Any]]:
        result = self._request(oid, fields, stack, is_list=True)
        if isinstance(result, dict):
            return [result]
        return result or []


# ---------------------------------------------------------------------------
# COLLECTOR
# ---------------------------------------------------------------------------

class NX200Collector:
    def __init__(self, host: str, password: str, username: str = "admin"):
        self.host = host
        self.password = password
        self.username = username
        self._router = None
        self._dm: DmClient | None = None

    def __enter__(self):
        if self.host.startswith("http://"):
            log.warning(
                "Stai usando HTTP. I firmware NX200 recenti reindirizzano "
                "alla welcome page e impediscono il login via HTTP. "
                "Prova con https://192.168.1.1"
            )
        self._router = TplinkRouterProvider.get_client(
            self.host, self.password, self.username, log
        )
        # authorize() puo' sollevare eccezioni che la lib swallow-a in alcuni
        # path; rendiamo esplicito il fallimento controllando che esista una
        # sessione utilizzabile prima di proseguire.
        try:
            self._router.authorize()
        except Exception as e:
            raise RuntimeError(f"Login fallito: {e}") from e

        # Verifica che il login abbia effettivamente prodotto una sessione
        has_session = any(
            getattr(self._router, attr, None) for attr in
            ("_session", "session", "_request_session")
        )
        has_token = any(
            getattr(self._router, attr, None) for attr in
            ("_stok", "stok", "_token")
        )
        if not has_session:
            raise RuntimeError(
                "Login completato senza errori ma la libreria non ha creato "
                "una sessione HTTP. Probabilmente l'autenticazione è fallita "
                "silenziosamente (welcome page o firmware non supportato). "
                "Verifica di usare HTTPS e che la password sia corretta."
            )
        if not has_token:
            log.warning("Sessione presente ma nessun token di login trovato. "
                        "Le richieste DataModel potrebbero fallire.")
        self._dm = DmClient(self._router)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._router:
                self._router.logout()
        except Exception:
            pass

    def collect(self) -> dict[str, Any]:
        assert self._dm is not None
        sample: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "raw": {},
        }

        # --- stato modem ----------------------------------------------
        for oid, spec in QUERIES.items():
            try:
                data = self._dm.get(oid, spec["fields"], spec.get("stack"))
                sample["raw"][oid] = data
            except Exception as e:  # noqa: BLE001
                log.warning("Lettura %s fallita: %s", oid, e)
                sample["raw"][oid] = {"_error": str(e)}

        # --- serving cell info (lista) --------------------------------
        try:
            cells = self._dm.get_list(SERVING_CELL_OID, SERVING_CELL_FIELDS)
            sample["raw"][SERVING_CELL_OID] = cells
        except Exception as e:  # noqa: BLE001
            log.warning("Lettura %s fallita: %s", SERVING_CELL_OID, e)
            sample["raw"][SERVING_CELL_OID] = []
            cells = []

        # --- normalizzazione campi ------------------------------------
        self._normalize(sample, cells)
        return sample

    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(sample: dict[str, Any], cells: list[dict[str, Any]]):
        raw = sample["raw"]

        # network type / sim
        link = raw.get("DEV2_LTE_LINK_CFG", {}) or {}
        nt = _to_int(link.get("networkType"))
        sample["network_type"] = NET_TYPE_LABELS.get(nt) if nt is not None else None
        sample["network_type_code"] = nt
        sample["sim_status"] = _to_int(link.get("simStatus"))
        sample["roaming"] = _to_int(link.get("roamingStatus"))

        # ISP / MCC / MNC
        prof = raw.get("DEV2_LTE_PROF_STAT", {}) or {}
        sample["isp"] = prof.get("ispName") or prof.get("spn")
        sample["mcc"] = prof.get("ispMcc")
        sample["mnc"] = prof.get("ispMnc")

        # USIM
        usim = raw.get("DEV2_CELL_INTF_USIM", {}) or {}
        sample["imsi"] = usim.get("IMSI")
        sample["iccid"] = usim.get("ICCID")
        sample["msisdn"] = usim.get("MSISDN")

        # speed / data
        intf = raw.get("DEV2_XTP_LTE_INTF_CFG", {}) or {}
        sample["dl_speed"] = _to_int(intf.get("curRxSpeed"))   # bytes/s
        sample["ul_speed"] = _to_int(intf.get("curTxSpeed"))
        sample["data_total"] = _to_int(intf.get("totalStatistics"))

        # CPU / RAM / uptime
        sample["cpu_load"] = _to_float(
            (raw.get("DEV2_PROC_STATUS") or {}).get("CPUUsage")
        )
        mem = raw.get("DEV2_MEM_STATUS", {}) or {}
        mt, mf = _to_float(mem.get("total")), _to_float(mem.get("free"))
        if mt and mf is not None and mt > 0:
            sample["mem_used"] = (mt - mf) / mt * 100.0
        sample["uptime_sec"] = _to_int(
            (raw.get("DEV2_DEV_INFO") or {}).get("upTime")
        )

        # serving cells: separiamo NR primaria, LTE primaria
        nr_cell, lte_cell = None, None
        for c in cells:
            nt_c = _to_int(c.get("networkType"))
            conn = str(c.get("cellConnectionStatus", "")).strip()
            if conn != "1":  # solo celle attive primarie
                continue
            if nt_c == 8:  # NR
                nr_cell = c
            elif nt_c in (3, 7):  # LTE / LTE+
                lte_cell = c

        if nr_cell:
            sample["nr_band"] = f"N{nr_cell.get('band')}"
            sample["nr_pci"] = _to_int(nr_cell.get("PCI"))
            sample["nr_arfcn"] = _to_int(nr_cell.get("ARFCN"))
            sample["nr_cid"] = nr_cell.get("cid")
            sample["nr_tac"] = nr_cell.get("TAC")
            sample["ss_rsrp"] = _to_float(nr_cell.get("SSRSRP"))
            sample["ss_rsrq"] = _to_float(nr_cell.get("SSRSRQ"))
            # SSSINR e txPowerPUCCH nel JS vengono divisi per 10
            sssinr_raw = _to_float(nr_cell.get("SSSINR"))
            sample["ss_sinr"] = sssinr_raw / 10.0 if sssinr_raw is not None else None
            txp_raw = _to_float(nr_cell.get("txPowerPUCCH"))
            sample["nr_tx_power"] = txp_raw / 10.0 if txp_raw is not None else None
            sample["nr_cqi"] = _to_int(nr_cell.get("CQI"))
            sample["nr_ri"] = _to_int(nr_cell.get("RI"))
            sample["nr_rbs"] = _to_int(nr_cell.get("numRbs"))
            sample["nr_dl_mcs"] = _to_int(nr_cell.get("downMCS"))
            sample["nr_ul_mcs"] = _to_int(nr_cell.get("upMCS"))
            sample["nr_dl_mod"] = nr_cell.get("downlinkModType")
            sample["nr_ul_mod"] = nr_cell.get("uplinkModType")
            sample["nr_dl_freq"] = _to_float(nr_cell.get("downFreq"))
            sample["nr_ul_freq"] = _to_float(nr_cell.get("upFreq"))
            # bandwidth nel JS divisa per 1000 → MHz
            bwd = _to_float(nr_cell.get("downBandWidth"))
            bwu = _to_float(nr_cell.get("upBandWidth"))
            sample["nr_dl_bw_mhz"] = bwd / 1000.0 if bwd else None
            sample["nr_ul_bw_mhz"] = bwu / 1000.0 if bwu else None
            sig = _to_float(nr_cell.get("signalStrength"))
            sample["nr_signal_pct"] = sig * 25.0 if sig is not None else None

        if lte_cell:
            sample["lte_band"] = f"B{lte_cell.get('band')}"
            sample["lte_pci"] = _to_int(lte_cell.get("PCI"))
            sample["lte_earfcn"] = _to_int(lte_cell.get("ARFCN"))
            sample["lte_cid"] = lte_cell.get("cid")
            sample["lte_tac"] = lte_cell.get("TAC")
            sample["lte_rsrp"] = _to_float(lte_cell.get("RSRP"))
            sample["lte_rsrq"] = _to_float(lte_cell.get("RSRQ"))
            snr_raw = _to_float(lte_cell.get("SNR"))
            sample["lte_snr"] = snr_raw / 10.0 if snr_raw is not None else None
            txp_raw = _to_float(lte_cell.get("txPowerPUCCH"))
            sample["lte_tx_power"] = txp_raw / 10.0 if txp_raw is not None else None
            sample["lte_cqi"] = _to_int(lte_cell.get("CQI"))
            sample["lte_ri"] = _to_int(lte_cell.get("RI"))
            sample["lte_rbs"] = _to_int(lte_cell.get("numRbs"))
            sample["lte_dl_mcs"] = _to_int(lte_cell.get("downMCS"))
            sample["lte_ul_mcs"] = _to_int(lte_cell.get("upMCS"))
            sample["lte_dl_mod"] = lte_cell.get("downlinkModType")
            sample["lte_ul_mod"] = lte_cell.get("uplinkModType")
            sample["lte_dl_freq"] = _to_float(lte_cell.get("downFreq"))
            sample["lte_ul_freq"] = _to_float(lte_cell.get("upFreq"))
            bwd = _to_float(lte_cell.get("downBandWidth"))
            bwu = _to_float(lte_cell.get("upBandWidth"))
            sample["lte_dl_bw_mhz"] = bwd / 1000.0 if bwd else None
            sample["lte_ul_bw_mhz"] = bwu / 1000.0 if bwu else None


def _to_float(v: Any) -> float | None:
    try:
        return float(v) if v not in (None, "", "--") else None
    except (ValueError, TypeError):
        return None


def _to_int(v: Any) -> int | None:
    try:
        return int(float(v)) if v not in (None, "", "--") else None
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# STORAGE + ANOMALY DETECTION
# (semplificati rispetto alla v1 ma stessa logica)
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    network_type TEXT, sim_status INTEGER, isp TEXT, mcc TEXT, mnc TEXT,
    nr_band TEXT, nr_pci INTEGER, nr_arfcn INTEGER, nr_cid TEXT, nr_tac TEXT,
    ss_rsrp REAL, ss_rsrq REAL, ss_sinr REAL,
    nr_cqi INTEGER, nr_ri INTEGER, nr_rbs INTEGER,
    nr_dl_mcs INTEGER, nr_ul_mcs INTEGER, nr_dl_mod TEXT, nr_ul_mod TEXT,
    nr_dl_freq REAL, nr_ul_freq REAL, nr_dl_bw_mhz REAL, nr_ul_bw_mhz REAL,
    nr_tx_power REAL, nr_signal_pct REAL,
    lte_band TEXT, lte_pci INTEGER, lte_earfcn INTEGER, lte_cid TEXT, lte_tac TEXT,
    lte_rsrp REAL, lte_rsrq REAL, lte_snr REAL,
    lte_cqi INTEGER, lte_ri INTEGER, lte_rbs INTEGER,
    lte_dl_mcs INTEGER, lte_ul_mcs INTEGER, lte_dl_mod TEXT, lte_ul_mod TEXT,
    lte_dl_freq REAL, lte_ul_freq REAL, lte_dl_bw_mhz REAL, lte_ul_bw_mhz REAL,
    lte_tx_power REAL,
    dl_speed INTEGER, ul_speed INTEGER, data_total INTEGER,
    cpu_load REAL, mem_used REAL, uptime_sec INTEGER,
    raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_pci ON samples(nr_pci);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    sample_id INTEGER
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
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert_sample(self, sample: dict[str, Any]) -> int:
        # tutte le colonne tranne id e raw_json
        cols = [c for c in [
            "ts","network_type","sim_status","isp","mcc","mnc",
            "nr_band","nr_pci","nr_arfcn","nr_cid","nr_tac",
            "ss_rsrp","ss_rsrq","ss_sinr","nr_cqi","nr_ri","nr_rbs",
            "nr_dl_mcs","nr_ul_mcs","nr_dl_mod","nr_ul_mod",
            "nr_dl_freq","nr_ul_freq","nr_dl_bw_mhz","nr_ul_bw_mhz",
            "nr_tx_power","nr_signal_pct",
            "lte_band","lte_pci","lte_earfcn","lte_cid","lte_tac",
            "lte_rsrp","lte_rsrq","lte_snr","lte_cqi","lte_ri","lte_rbs",
            "lte_dl_mcs","lte_ul_mcs","lte_dl_mod","lte_ul_mod",
            "lte_dl_freq","lte_ul_freq","lte_dl_bw_mhz","lte_ul_bw_mhz",
            "lte_tx_power",
            "dl_speed","ul_speed","data_total",
            "cpu_load","mem_used","uptime_sec",
        ]]
        values = [sample.get(c) for c in cols]
        values.append(json.dumps(sample.get("raw", {}), default=str))
        sql = (f"INSERT INTO samples ({','.join(cols + ['raw_json'])}) "
               f"VALUES ({','.join('?' * (len(cols)+1))})")
        cur = self.conn.execute(sql, values)
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def insert_anomaly(self, ts: str, severity: str, kind: str, message: str,
                       sid: int | None = None):
        self.conn.execute(
            "INSERT INTO anomalies (ts,severity,kind,message,sample_id) "
            "VALUES (?,?,?,?,?)",
            (ts, severity, kind, message, sid),
        )
        self.conn.commit()

    def baseline_for_pci(self, pci: int | None, field: str,
                         since_minutes: int = 60 * 24):
        if pci is None:
            return None, None, 0
        rows = self.conn.execute(
            f"SELECT {field} FROM samples WHERE nr_pci=? AND {field} IS NOT NULL "
            f"AND ts >= datetime('now', ?)",
            (pci, f"-{since_minutes} minutes"),
        ).fetchall()
        vals = [r[0] for r in rows if r[0] is not None]
        if not vals:
            return None, None, 0
        return mean(vals), (pstdev(vals) if len(vals) > 1 else 0.0), len(vals)

    def recent_cell_changes(self, minutes: int = 60) -> int:
        rows = self.conn.execute(
            "SELECT nr_pci FROM samples WHERE nr_pci IS NOT NULL "
            "AND ts >= datetime('now', ?) ORDER BY ts",
            (f"-{minutes} minutes",),
        ).fetchall()
        if len(rows) < 2:
            return 0
        changes, prev = 0, rows[0][0]
        for (pci,) in rows[1:]:
            if pci != prev:
                changes += 1
                prev = pci
        return changes

    def close(self):
        self.conn.close()


class AnomalyDetector:
    def __init__(self, store: Store, t: Thresholds):
        self.store = store
        self.t = t

    def evaluate(self, sample: dict[str, Any], sid: int) -> list[tuple[str, str, str]]:
        f: list[tuple[str, str, str]] = []
        t = self.t

        rsrp = sample.get("ss_rsrp") or sample.get("lte_rsrp")
        sinr = sample.get("ss_sinr") or sample.get("lte_snr")
        txp = sample.get("nr_tx_power") or sample.get("lte_tx_power")
        cqi = sample.get("nr_cqi") or sample.get("lte_cqi")
        ri = sample.get("nr_ri") or sample.get("lte_ri")
        rbs = sample.get("nr_rbs") or sample.get("lte_rbs")
        dl = sample.get("dl_speed")
        pci = sample.get("nr_pci")

        if rsrp is not None and pci is not None:
            mu, _, n = self.store.baseline_for_pci(pci, "ss_rsrp")
            if n >= t.baseline_min_samples and mu is not None:
                delta = mu - rsrp
                if delta >= t.rsrp_drop_db:
                    f.append(("warning", "antenna_or_obstacle",
                              f"RSRP={rsrp:.1f}dBm su PCI={pci} è {delta:.1f}dB "
                              f"sotto la baseline storica ({mu:.1f}dBm, n={n}). "
                              f"Possibile guasto antenna/cavo o nuovo ostacolo."))

        if rsrp is not None and sinr is not None and rsrp > -90 and sinr < t.sinr_poor:
            f.append(("warning", "interference_or_congestion",
                      f"RSRP buono ({rsrp:.1f}dBm) ma SINR={sinr:.1f}dB: "
                      f"interferenza o cella sovraccarica."))

        if rsrp is not None and rsrp < t.rsrp_critical:
            f.append(("critical", "weak_signal",
                      f"RSRP={rsrp:.1f}dBm sotto soglia critica."))
        elif rsrp is not None and rsrp < t.rsrp_poor:
            f.append(("info", "weak_signal", f"RSRP={rsrp:.1f}dBm: segnale debole."))

        if sinr is not None and sinr < t.sinr_critical:
            f.append(("critical", "sinr_critical",
                      f"SINR={sinr:.1f}dB sotto zero: forte interferenza."))

        if txp is not None and txp > t.tx_power_high:
            f.append(("warning", "uplink_degraded",
                      f"Tx Power={txp:.1f}dBm vicino al massimo."))

        if (rsrp is not None and rsrp > -95 and rbs is not None and rbs < 20
                and dl is not None and dl < 5_000_000):
            f.append(("info", "cell_congestion",
                      f"Segnale ok (RSRP={rsrp:.1f}dBm) ma RBs={rbs} e "
                      f"DL={dl/1e6:.1f}Mbps: probabile congestione cella."))

        if ri is not None and ri <= 1 and rsrp is not None and rsrp > -100:
            f.append(("info", "mimo_degraded",
                      f"RI={ri} con RSRP={rsrp:.1f}dBm: perdita layer MIMO."))

        if cqi is not None and cqi < t.cqi_low:
            f.append(("info", "channel_degraded", f"CQI={cqi}: canale degradato."))

        if sid % 10 == 0:
            ch = self.store.recent_cell_changes(60)
            if ch >= t.cell_changes_per_hour:
                f.append(("warning", "cell_ping_pong",
                          f"{ch} cambi di PCI nell'ultima ora."))

        return f


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

_RUN = True


def _sigint(signum, frame):  # noqa: ARG001
    global _RUN
    _RUN = False
    log.info("Interruzione richiesta, esco al prossimo ciclo...")


def run_once(host, password, store, detector, username):
    with NX200Collector(host, password, username) as col:
        sample = col.collect()
    sid = store.insert_sample(sample)
    findings = detector.evaluate(sample, sid)
    for sev, kind, msg in findings:
        log.warning("[%s] %s: %s", sev.upper(), kind, msg)
        store.insert_anomaly(sample["ts"], sev, kind, msg, sid)

    rsrp = sample.get("ss_rsrp") or sample.get("lte_rsrp")
    sinr = sample.get("ss_sinr") or sample.get("lte_snr")
    pci = sample.get("nr_pci") or sample.get("lte_pci")
    dl = sample.get("dl_speed")
    log.info(
        "sample #%d net=%s PCI=%s RSRP=%s SINR=%s DL=%s anomalie=%d",
        sid, sample.get("network_type"), pci,
        f"{rsrp:.1f}" if rsrp is not None else "n/a",
        f"{sinr:.1f}" if sinr is not None else "n/a",
        f"{dl/1e6:.2f}Mbps" if dl else "n/a",
        len(findings),
    )


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--username", default="admin")
    p.add_argument("--db", default="nx200_monitor.db")
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--once", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    # disable urllib3 SSL warnings (modem usa cert self-signed)
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    store = Store(Path(args.db))
    detector = AnomalyDetector(store, Thresholds())

    log.info("Avvio: host=%s interval=%ds db=%s", args.host, args.interval, args.db)
    try:
        if args.once:
            run_once(args.host, args.password, store, detector, args.username)
            return
        while _RUN:
            t0 = time.time()
            try:
                run_once(args.host, args.password, store, detector, args.username)
            except Exception as e:  # noqa: BLE001
                log.error("Errore poll: %s", e)
                store.insert_anomaly(
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "warning", "poll_failed", str(e), None,
                )
            elapsed = time.time() - t0
            for _ in range(int(max(1.0, args.interval - elapsed))):
                if not _RUN:
                    break
                time.sleep(1)
    finally:
        store.close()
        log.info("Bye.")


if __name__ == "__main__":
    main()
