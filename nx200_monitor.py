#!/usr/bin/env python3
"""
nx200_monitor.py
---------------------------------------------------------------------------
Polling locale + log su SQLite per modem TP-Link Archer NX200 (5G CPE).

Cosa fa:
  1. Si autentica al modem usando la libreria `tplinkrouterc6u` (gestisce
     la cifratura RSA/AES tipica delle interfacce TP-Link).
  2. Recupera lo stato LTE/NR direttamente dal CGI interno del modem
     (la libreria espone solo un sottoinsieme; qui leggiamo tutto).
  3. Salva un sample per ogni poll su database SQLite.
  4. Mantiene una baseline rolling (media/std per cella) e segnala
     anomalie con regole correlate (es. RSRP stabile + SINR basso = interferenza).

Uso:
    python nx200_monitor.py --host http://192.168.1.1 --password TUA_PWD
    python nx200_monitor.py --host http://192.168.1.1 --password TUA_PWD --interval 30
    python nx200_monitor.py --host http://192.168.1.1 --password TUA_PWD --once   # un solo poll, utile per debug

Dipendenze:
    pip install tplinkrouterc6u
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sqlite3
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

# La libreria gestisce l'autenticazione cifrata per noi.
# Se non e' installata: pip install tplinkrouterc6u
try:
    from tplinkrouterc6u import TplinkRouterProvider
except ImportError:
    print("ERRORE: installa la libreria con `pip install tplinkrouterc6u`", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CONFIGURAZIONE LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("nx200")


# ---------------------------------------------------------------------------
# SOGLIE PER LA RILEVAZIONE ANOMALIE
# Adattabili da CLI o file di config se servisse; tenute qui per chiarezza.
# ---------------------------------------------------------------------------
@dataclass
class Thresholds:
    # Valori assoluti (dBm / dB)
    rsrp_critical: float = -110.0      # sotto questo: critico
    rsrp_poor: float = -100.0          # sotto questo: scarso
    sinr_critical: float = 0.0         # sotto: probabile interferenza grave
    sinr_poor: float = 5.0             # sotto: interferenza/congestione
    rsrq_poor: float = -15.0
    tx_power_high: float = 18.0        # sopra: uplink in difficolta'
    cqi_low: int = 6                   # sotto: canale degradato

    # Deviazione dalla baseline storica della singola cella
    rsrp_drop_db: float = 10.0         # caduta >10dB rispetto alla media storica
    sinr_drop_db: float = 8.0

    # Numero minimo di campioni storici per ritenere la baseline affidabile
    baseline_min_samples: int = 30

    # Soglie per "ping-pong" tra celle
    cell_changes_per_hour: int = 5


# ---------------------------------------------------------------------------
# SCHEMA DATABASE
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,           -- ISO 8601 UTC
    -- identificazione cella
    network_type    TEXT,                       -- '5G NSA', 'LTE', ecc.
    nr_band         TEXT,
    nr_pci          INTEGER,
    nr_arfcn        INTEGER,
    lte_band        TEXT,
    lte_pci         INTEGER,
    lte_cell_id     TEXT,
    lte_tac         TEXT,
    lte_earfcn      INTEGER,
    -- radio NR (5G)
    ss_rsrp         REAL,
    ss_rsrq         REAL,
    ss_sinr         REAL,
    nr_cqi          INTEGER,
    nr_dl_mcs       INTEGER,
    nr_ul_mcs       INTEGER,
    nr_dl_mod       TEXT,
    nr_ul_mod       TEXT,
    nr_ri           INTEGER,
    nr_rbs          INTEGER,
    nr_tx_power     REAL,
    -- radio LTE
    lte_rsrp        REAL,
    lte_rsrq        REAL,
    lte_snr         REAL,
    lte_cqi         INTEGER,
    lte_dl_mcs      INTEGER,
    lte_ul_mcs      INTEGER,
    lte_ri          INTEGER,
    lte_rbs         INTEGER,
    lte_tx_power    REAL,
    -- throughput istantaneo (bps)
    dl_speed        INTEGER,
    ul_speed        INTEGER,
    -- system
    cpu_load        REAL,
    mem_used        REAL,
    uptime_sec      INTEGER,
    -- raw json originale (sempre utile per debug)
    raw_json        TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_pci ON samples(nr_pci);

CREATE TABLE IF NOT EXISTS anomalies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    severity        TEXT    NOT NULL,           -- info | warning | critical
    kind            TEXT    NOT NULL,           -- antenna_drop, interference, congestion, ...
    message         TEXT    NOT NULL,
    sample_id       INTEGER REFERENCES samples(id)
);
CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(ts);
"""


# ---------------------------------------------------------------------------
# ACQUISIZIONE DATI DAL MODEM
# ---------------------------------------------------------------------------
class NX200Collector:
    """
    Wrapper che usa la libreria per il login (cifratura inclusa) e poi
    chiama gli endpoint CGI interni per ottenere lo stato 5G NR completo.

    NB: gli endpoint esatti possono variare tra firmware. Qui usiamo prima
    la libreria (che copre i dati LTE base), poi tentiamo una chiamata al
    CGI del 5G status. Se il CGI non risponde sul tuo firmware, lo script
    funziona comunque con i dati LTE; nel raw_json troverai cosa serve
    aggiungere per il tuo specifico build.
    """

    # Endpoint CGI che TP-Link usa per la pagina "Mobile" sulla UI del NX200.
    # Tipicamente: /cgi-bin/luci/;stok=<token>/admin/network/mobile_status
    # ma il "form" piu' compatibile con la lib c6u e' tramite _request_pwd.
    # Manteniamo un elenco di possibili form names da tentare.
    NR_STATUS_FORMS = [
        "mobile_status",     # firmware piu' recenti
        "lte_status",        # fallback
        "wan_status",
    ]

    def __init__(self, host: str, password: str, username: str = "admin"):
        self.host = host
        self.password = password
        self.username = username
        self._router = None

    def __enter__(self):
        self._router = TplinkRouterProvider.get_client(
            self.host, self.password, self.username, log
        )
        self._router.authorize()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._router:
                self._router.logout()
        except Exception:  # noqa: BLE001  - il logout puo' fallire silently
            pass

    def collect(self) -> dict[str, Any]:
        """Ritorna un dict normalizzato con tutti i campi utili."""
        out: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "raw": {},
        }

        # --- 1. Stato base + LTE dalla libreria (gia' parsato) ---------------
        try:
            status = self._router.get_status()
            out["cpu_load"] = float(status.cpu_usage) if status.cpu_usage is not None else None
            out["mem_used"] = float(status.mem_usage) if status.mem_usage is not None else None
            out["uptime_sec"] = status.wan_ipv4_uptime
            out["raw"]["status"] = self._dataclass_safe(status)
        except Exception as e:
            log.warning("get_status failed: %s", e)

        try:
            lte = self._router.get_lte_status()
            out["lte_rsrp"] = lte.rsrp
            out["lte_rsrq"] = lte.rsrq
            out["lte_snr"] = lte.snr
            out["dl_speed"] = lte.cur_rx_speed
            out["ul_speed"] = lte.cur_tx_speed
            out["network_type"] = self._network_type_label(lte.network_type)
            out["raw"]["lte"] = self._dataclass_safe(lte)
        except Exception as e:
            log.debug("get_lte_status failed (normale se solo 5G/wired): %s", e)

        # --- 2. CGI raw per i campi 5G NR specifici del NX200 ---------------
        # Tentiamo gli endpoint noti finche' uno risponde.
        raw_nr = None
        for form in self.NR_STATUS_FORMS:
            try:
                # La lib c6u espone _request_pwd / _request_get a basso livello
                # (varia tra versioni). Usiamo il path piu' generico se c'e'.
                if hasattr(self._router, "request"):
                    raw_nr = self._router.request(form, {})  # type: ignore[attr-defined]
                elif hasattr(self._router, "_request_pwd"):
                    raw_nr = self._router._request_pwd(form)  # type: ignore[attr-defined]
                if raw_nr:
                    out["raw"][form] = raw_nr
                    self._extract_nr_fields(raw_nr, out)
                    break
            except Exception as e:
                log.debug("CGI form %s non disponibile: %s", form, e)

        return out

    # ----- helpers ---------------------------------------------------------

    @staticmethod
    def _network_type_label(code: Any) -> str | None:
        # Mapping euristico — i firmware TP-Link usano codici interi
        # diversi tra build. Lasciamo passare anche il valore raw.
        mapping = {0: "Unknown", 1: "2G", 2: "3G", 3: "4G LTE",
                   4: "5G NSA", 5: "5G SA"}
        if isinstance(code, int):
            return mapping.get(code, f"code={code}")
        return str(code) if code is not None else None

    @staticmethod
    def _dataclass_safe(obj: Any) -> dict[str, Any]:
        try:
            return asdict(obj)
        except Exception:
            return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}

    @staticmethod
    def _extract_nr_fields(raw: Any, out: dict[str, Any]) -> None:
        """
        Pesca i campi NR dal blob CGI. I nomi sono mappati in modo difensivo
        perche' i firmware li chiamano in modo leggermente diverso.
        """
        if not isinstance(raw, dict):
            return

        def pick(*keys):
            for k in keys:
                if k in raw and raw[k] not in (None, "", "--"):
                    return raw[k]
            return None

        # NR
        out["ss_rsrp"] = _to_float(pick("ss_rsrp", "nr_rsrp", "rsrp_5g"))
        out["ss_rsrq"] = _to_float(pick("ss_rsrq", "nr_rsrq", "rsrq_5g"))
        out["ss_sinr"] = _to_float(pick("ss_sinr", "nr_sinr", "sinr_5g"))
        out["nr_cqi"] = _to_int(pick("nr_cqi", "cqi_5g"))
        out["nr_dl_mcs"] = _to_int(pick("nr_dl_mcs", "dl_mcs_5g"))
        out["nr_ul_mcs"] = _to_int(pick("nr_ul_mcs", "ul_mcs_5g"))
        out["nr_dl_mod"] = pick("nr_dl_mod", "dl_mod_5g")
        out["nr_ul_mod"] = pick("nr_ul_mod", "ul_mod_5g")
        out["nr_ri"] = _to_int(pick("nr_ri", "ri_5g"))
        out["nr_rbs"] = _to_int(pick("nr_rbs", "rbs_5g"))
        out["nr_tx_power"] = _to_float(pick("nr_tx_power", "tx_power_5g", "pucch_5g"))
        out["nr_band"] = pick("nr_band", "band_5g")
        out["nr_pci"] = _to_int(pick("nr_pci", "pci_5g"))
        out["nr_arfcn"] = _to_int(pick("nr_arfcn"))

        # LTE (anchor in NSA)
        out["lte_cqi"] = _to_int(pick("lte_cqi", "cqi"))
        out["lte_dl_mcs"] = _to_int(pick("lte_dl_mcs"))
        out["lte_ul_mcs"] = _to_int(pick("lte_ul_mcs"))
        out["lte_ri"] = _to_int(pick("lte_ri"))
        out["lte_rbs"] = _to_int(pick("lte_rbs"))
        out["lte_tx_power"] = _to_float(pick("lte_tx_power", "tx_power"))
        out["lte_band"] = pick("lte_band", "band")
        out["lte_pci"] = _to_int(pick("lte_pci", "pci"))
        out["lte_cell_id"] = pick("cell_id", "lte_cell_id")
        out["lte_tac"] = pick("tac", "lte_tac")
        out["lte_earfcn"] = _to_int(pick("earfcn", "lte_earfcn"))


def _to_float(v: Any) -> float | None:
    try:
        return float(v) if v is not None else None
    except (ValueError, TypeError):
        return None


def _to_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# PERSISTENZA
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
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

    def insert_sample(self, sample: dict[str, Any]) -> int:
        # Costruiamo l'insert in modo difensivo: solo le colonne che esistono.
        cols = [
            "ts", "network_type", "nr_band", "nr_pci", "nr_arfcn",
            "lte_band", "lte_pci", "lte_cell_id", "lte_tac", "lte_earfcn",
            "ss_rsrp", "ss_rsrq", "ss_sinr",
            "nr_cqi", "nr_dl_mcs", "nr_ul_mcs", "nr_dl_mod", "nr_ul_mod",
            "nr_ri", "nr_rbs", "nr_tx_power",
            "lte_rsrp", "lte_rsrq", "lte_snr",
            "lte_cqi", "lte_dl_mcs", "lte_ul_mcs", "lte_ri", "lte_rbs", "lte_tx_power",
            "dl_speed", "ul_speed",
            "cpu_load", "mem_used", "uptime_sec",
            "raw_json",
        ]
        values = [sample.get(c) for c in cols if c != "raw_json"]
        values.append(json.dumps(sample.get("raw", {}), default=str))

        placeholders = ",".join("?" * len(cols))
        sql = f"INSERT INTO samples ({','.join(cols)}) VALUES ({placeholders})"
        cur = self.conn.execute(sql, values)
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def insert_anomaly(self, ts: str, severity: str, kind: str,
                       message: str, sample_id: int | None = None) -> None:
        self.conn.execute(
            "INSERT INTO anomalies (ts, severity, kind, message, sample_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (ts, severity, kind, message, sample_id),
        )
        self.conn.commit()

    def baseline_for_pci(self, pci: int | None, field: str,
                         since_minutes: int = 60 * 24) -> tuple[float | None, float | None, int]:
        """Ritorna (media, stddev, n_campioni) per `field` sulla cella `pci`."""
        if pci is None:
            return None, None, 0
        rows = self.conn.execute(
            f"SELECT {field} FROM samples "
            f"WHERE nr_pci = ? AND {field} IS NOT NULL "
            f"AND julianday(ts) >= julianday('now', ?)",
            (pci, f"-{since_minutes} minutes"),
        ).fetchall()
        vals = [r[0] for r in rows if r[0] is not None]
        if not vals:
            return None, None, 0
        return mean(vals), (pstdev(vals) if len(vals) > 1 else 0.0), len(vals)

    def recent_cell_changes(self, minutes: int = 60) -> int:
        """Conta quante volte il PCI 5G e' cambiato negli ultimi `minutes`."""
        rows = self.conn.execute(
            "SELECT nr_pci FROM samples "
            "WHERE julianday(ts) >= julianday('now', ?) AND nr_pci IS NOT NULL "
            "ORDER BY julianday(ts), id",
            (f"-{minutes} minutes",),
        ).fetchall()
        if len(rows) < 2:
            return 0
        changes = 0
        prev = rows[0][0]
        for (pci,) in rows[1:]:
            if pci != prev:
                changes += 1
                prev = pci
        return changes

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# ANALISI ANOMALIE
# ---------------------------------------------------------------------------
class AnomalyDetector:
    """
    Regole correlate: nessuna metrica viene valutata da sola.
    Le regole emergono dai pattern descritti nella analisi diagnostica:
      - RSRP buono + SINR scarso          -> interferenza
      - RSRP buono + RBS basso + DL bassa -> congestione cella
      - RSRP crollato vs baseline         -> antenna/ostacolo
      - Tx Power saturo                   -> uplink degradato
      - RI basso persistente              -> MIMO degradato
      - PCI che cambia spesso             -> instabilita' copertura
    """

    def __init__(self, store: Store, thresholds: Thresholds):
        self.store = store
        self.t = thresholds

    def evaluate(self, sample: dict[str, Any], sample_id: int) -> list[tuple[str, str, str]]:
        """Ritorna lista di (severity, kind, message) per il campione."""
        findings: list[tuple[str, str, str]] = []
        ts = sample["ts"]
        t = self.t

        # Scegliamo RSRP/SINR primario: 5G se disponibile, altrimenti LTE
        rsrp = sample.get("ss_rsrp") if sample.get("ss_rsrp") is not None else sample.get("lte_rsrp")
        sinr = sample.get("ss_sinr") if sample.get("ss_sinr") is not None else sample.get("lte_snr")
        tx_power = sample.get("nr_tx_power") if sample.get("nr_tx_power") is not None else sample.get("lte_tx_power")
        cqi = sample.get("nr_cqi") if sample.get("nr_cqi") is not None else sample.get("lte_cqi")
        ri = sample.get("nr_ri") if sample.get("nr_ri") is not None else sample.get("lte_ri")
        rbs = sample.get("nr_rbs") if sample.get("nr_rbs") is not None else sample.get("lte_rbs")
        dl_speed = sample.get("dl_speed")

        # --- 1. Crollo RSRP rispetto alla baseline storica della cella -----
        pci = sample.get("nr_pci")
        if rsrp is not None and pci is not None:
            mu, sigma, n = self.store.baseline_for_pci(pci, "ss_rsrp")
            if n >= t.baseline_min_samples and mu is not None:
                delta = mu - rsrp
                if delta >= t.rsrp_drop_db:
                    findings.append((
                        "warning",
                        "antenna_or_obstacle",
                        f"RSRP={rsrp:.1f}dBm sulla cella PCI={pci} è "
                        f"{delta:.1f}dB sotto la baseline storica "
                        f"({mu:.1f}dBm, n={n}). Possibile guasto antenna/cavo "
                        f"o nuovo ostacolo sul percorso radio.",
                    ))

        # --- 2. RSRP buono + SINR scarso = interferenza --------------------
        if rsrp is not None and sinr is not None:
            if rsrp > -90 and sinr < t.sinr_poor:
                findings.append((
                    "warning",
                    "interference_or_congestion",
                    f"RSRP buono ({rsrp:.1f}dBm) ma SINR={sinr:.1f}dB: "
                    f"interferenza o cella sovraccarica.",
                ))

        # --- 3. RSRP scarso assoluto ---------------------------------------
        if rsrp is not None and rsrp < t.rsrp_critical:
            findings.append((
                "critical",
                "weak_signal",
                f"RSRP={rsrp:.1f}dBm sotto la soglia critica "
                f"({t.rsrp_critical}dBm). Servizio probabilmente compromesso.",
            ))
        elif rsrp is not None and rsrp < t.rsrp_poor:
            findings.append((
                "info",
                "weak_signal",
                f"RSRP={rsrp:.1f}dBm: segnale debole.",
            ))

        # --- 4. SINR critico ----------------------------------------------
        if sinr is not None and sinr < t.sinr_critical:
            findings.append((
                "critical",
                "sinr_critical",
                f"SINR={sinr:.1f}dB sotto zero: forte interferenza, "
                f"il decodificatore farà fatica anche con segnale forte.",
            ))

        # --- 5. Tx Power saturo = uplink in difficolta' --------------------
        if tx_power is not None and tx_power > t.tx_power_high:
            findings.append((
                "warning",
                "uplink_degraded",
                f"Tx Power={tx_power:.1f}dBm vicino al massimo: il modem "
                f"sta spingendo molto in uplink (cella lontana, antenna TX "
                f"degradata, oppure interferenza in uplink).",
            ))

        # --- 6. Congestione cella: segnale ok ma poche risorse + DL bassa -
        if (rsrp is not None and rsrp > -95
                and rbs is not None and rbs < 20
                and dl_speed is not None and dl_speed < 5_000_000):  # <5 Mbps
            findings.append((
                "info",
                "cell_congestion",
                f"Segnale ok (RSRP={rsrp:.1f}dBm) ma RBS basso ({rbs}) "
                f"e throughput limitato ({dl_speed/1e6:.1f} Mbps): "
                f"probabile congestione della cella.",
            ))

        # --- 7. RI degradato: MIMO compromesso -----------------------------
        if ri is not None and ri <= 1 and rsrp is not None and rsrp > -100:
            findings.append((
                "info",
                "mimo_degraded",
                f"RI={ri} con segnale ancora discreto (RSRP={rsrp:.1f}dBm): "
                f"perdita di layer MIMO, possibile problema antenna a "
                f"polarizzazione singola.",
            ))

        # --- 8. CQI basso --------------------------------------------------
        if cqi is not None and cqi < t.cqi_low:
            findings.append((
                "info",
                "channel_degraded",
                f"CQI={cqi}: canale degradato, modulazione spinta verso "
                f"schemi piu' robusti ma piu' lenti.",
            ))

        # --- 9. Ping-pong tra celle ----------------------------------------
        # Valutato a parte (e meno spesso) per non sporcare ogni poll:
        # lo facciamo solo se il sample_id e' multiplo di un certo numero.
        if sample_id % 10 == 0:
            changes = self.store.recent_cell_changes(minutes=60)
            if changes >= t.cell_changes_per_hour:
                findings.append((
                    "warning",
                    "cell_ping_pong",
                    f"{changes} cambi di PCI nell'ultima ora: instabilita' "
                    f"di copertura, posizione borderline o cella vicina instabile.",
                ))

        return findings


# ---------------------------------------------------------------------------
# LOOP PRINCIPALE
# ---------------------------------------------------------------------------
_RUN = True


def _handle_sigint(signum, frame):  # noqa: ARG001
    global _RUN
    _RUN = False
    log.info("Interruzione richiesta, esco al prossimo ciclo...")


def run_once(host: str, password: str, store: Store, detector: AnomalyDetector,
             username: str = "admin") -> None:
    with NX200Collector(host, password, username) as col:
        sample = col.collect()

    sid = store.insert_sample(sample)
    findings = detector.evaluate(sample, sid)
    for severity, kind, message in findings:
        log.warning("[%s] %s: %s", severity.upper(), kind, message)
        store.insert_anomaly(sample["ts"], severity, kind, message, sid)

    # Riassunto a una riga, utile in console
    rsrp = sample.get("ss_rsrp") if sample.get("ss_rsrp") is not None else sample.get("lte_rsrp")
    sinr = sample.get("ss_sinr") if sample.get("ss_sinr") is not None else sample.get("lte_snr")
    pci = sample.get("nr_pci") if sample.get("nr_pci") is not None else sample.get("lte_pci")
    dl = sample.get("dl_speed")
    log.info(
        "sample #%d  net=%s  PCI=%s  RSRP=%s  SINR=%s  DL=%s  anomalie=%d",
        sid,
        sample.get("network_type"),
        pci,
        f"{rsrp:.1f}" if rsrp is not None else "n/a",
        f"{sinr:.1f}" if sinr is not None else "n/a",
        f"{dl/1e6:.1f}Mbps" if dl else "n/a",
        len(findings),
    )


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True, help="Es. http://192.168.1.1")
    p.add_argument("--password", required=True, help="Password admin del modem")
    p.add_argument("--username", default="admin")
    p.add_argument("--db", default="nx200_monitor.db", help="Percorso SQLite (default: ./nx200_monitor.db)")
    p.add_argument("--interval", type=int, default=60, help="Secondi tra un poll e l'altro (default 60)")
    p.add_argument("--once", action="store_true", help="Un solo poll e termina (utile per debug)")
    p.add_argument("--verbose", "-v", action="store_true", help="Log di debug")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigint)

    store = Store(Path(args.db))
    detector = AnomalyDetector(store, Thresholds())

    log.info("Avvio polling: host=%s, intervallo=%ds, db=%s",
             args.host, args.interval, args.db)

    try:
        if args.once:
            run_once(args.host, args.password, store, detector, args.username)
            return

        while _RUN:
            t0 = time.time()
            try:
                run_once(args.host, args.password, store, detector, args.username)
            except Exception as e:  # noqa: BLE001
                log.error("Errore durante il poll: %s", e)
                store.insert_anomaly(
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "warning", "poll_failed", str(e), None,
                )

            elapsed = time.time() - t0
            sleep_for = max(1.0, args.interval - elapsed)
            # sleep "interrompibile" da SIGINT
            for _ in range(int(sleep_for)):
                if not _RUN:
                    break
                time.sleep(1)
    finally:
        store.close()
        log.info("Database chiuso, arrivederci.")


if __name__ == "__main__":
    main()
