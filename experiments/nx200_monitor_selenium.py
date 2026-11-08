#!/usr/bin/env python3
"""
nx200_monitor_selenium.py
---------------------------------------------------------------------------
Polling + log su SQLite per TP-Link Archer NX200 via Selenium.

Visto che il firmware NX200 (Build 251120+) usa uno schema cifrato
proprietario complesso e non documentato, invece di replicarlo lasciamo
che sia un vero browser (Chromium) a fare il lavoro per noi:
  - Apriamo la web UI in headless con Selenium
  - Facciamo login normalmente
  - Navighiamo alla pagina Status e leggiamo i campi dal DOM
  - Estraiamo RSRP, SINR, PCI, ecc. dai campi input

Vantaggi: zero crittografia da gestire, funziona "per costruzione" finche'
la web UI funziona.
Svantaggi: ~3 secondi per poll, ~200 MB RAM, dipende da Chromium installato.

Dipendenze:
    pip install selenium

Inoltre serve Google Chrome o Brave installato (per il binary del browser),
e ChromeDriver. Da Selenium 4.6+ il driver e' gestito automaticamente
tramite Selenium Manager, quindi nessuna installazione manuale.

Uso:
    python nx200_monitor_selenium.py --host https://192.168.1.1 --password TUA_PWD --once -v
    python nx200_monitor_selenium.py --host https://192.168.1.1 --password TUA_PWD --interval 60
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
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
except ImportError:
    print("ERRORE: pip install selenium", file=sys.stderr)
    sys.exit(1)


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nx200_sel")


# ===========================================================================
# CAMPI DA SCRAPARE DAL DOM
# I selettori sono gli id HTML che ho visto nella pagina status.htm.
# ===========================================================================

# Campi NR (5G) - dalla sezione id="nr_servingcell_info"
NR_FIELDS = {
    "nr_band":          "nr_band",
    "nr_cid":           "nr_cid",
    "nr_arfcn":         "nr_arfcn",
    "nr_pci":           "nr_pci",
    "nr_tac":           "nr_tac",
    "nr_bw_down":       "nr_bw_down",
    "nr_freq_down":     "nr_freq_down",
    "nr_dl_mod":        "nr_down_mode_type",
    "nr_dl_mcs":        "nr_mcs_down",
    "nr_cqi":           "nr_cqi",
    "nr_signal_pct":    "nr_signalstrength",
    "ss_rsrp":          "nr_ssrsrp",
    "ss_rsrq":          "nr_ssrsrq",
    "ss_sinr":          "nr_sssinr",
    "nr_tx_power":      "nr_tx_power_pucch",
    "nr_bw_up":         "nr_bw_up",
    "nr_freq_up":       "nr_freq_up",
    "nr_ul_mod":        "nr_up_mode_type",
    "nr_ul_mcs":        "nr_mcs_up",
    "nr_ri":            "nr_rank_indicator",
    "nr_rbs":           "nr_rbs_num",
}

# Campi LTE - dalla sezione id="lte_servingcell_info"
LTE_FIELDS = {
    "lte_band":         "lte_band",
    "lte_cid":          "lte_cid",
    "lte_earfcn":       "lte_arfcn",
    "lte_pci":          "lte_pci",
    "lte_tac":          "lte_tac",
    "lte_bw_down":      "lte_bw_down",
    "lte_freq_down":    "lte_freq_down",
    "lte_dl_mod":       "lte_down_mode_type",
    "lte_dl_mcs":       "lte_mcs_down",
    "lte_cqi":          "lte_cqi",
    "lte_signal_pct":   "lte_signalstrength",
    "lte_rsrp":         "lte_rsrp",
    "lte_rsrq":         "lte_rsrq",
    "lte_snr":          "lte_snr",
    "lte_tx_power":     "lte_tx_power_pucch",
    "lte_bw_up":        "lte_bw_up",
    "lte_freq_up":      "lte_freq_up",
    "lte_ul_mod":       "lte_up_mode_type",
    "lte_ul_mcs":       "lte_mcs_up",
    "lte_ri":           "lte_rank_indicator",
    "lte_rbs":          "lte_rbs_num",
}

# Campi mobile/general
GENERAL_FIELDS = {
    "isp":             "isp",
    "network_type":    "networkType",
    "mcc":             "mcc",
    "mnc":             "mnc",
    "imsi":            "imsi",
    "iccid":           "iccid",
    "msisdn":          "msisdn",
    "dl_speed_str":    "downSpeed",
    "ul_speed_str":    "uploadSpeed",
    "data_str":        "data",
    "sim_status_str":  "simCardStatus",  # questo e' uno <span> non un input
}

# Performance
PERFORMANCE_FIELDS = {
    "uptime_str":      "UpTime",
    "cpu_str":         "cpu_gitem",
    "mem_str":         "mem_gitem",
}


# ===========================================================================
# SCRAPER SELENIUM
# ===========================================================================

class StatusScraper:
    def __init__(self, host: str, password: str, username: str = "admin",
                 headless: bool = True, browser_binary: str | None = None):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.headless = headless
        self.browser_binary = browser_binary
        self.driver: webdriver.Chrome | None = None

    def __enter__(self):
        opts = Options()
        if self.headless:
            opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--ignore-ssl-errors")
        opts.add_argument("--allow-insecure-localhost")
        opts.add_argument("--window-size=1400,1000")
        opts.set_capability("acceptInsecureCerts", True)
        if self.browser_binary:
            opts.binary_location = self.browser_binary

        log.info("Avvio browser %s...", "(headless)" if self.headless else "")
        self.driver = webdriver.Chrome(options=opts)
        self.driver.set_page_load_timeout(30)
        return self

    def __exit__(self, *a):
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass

    # ---- login ---------------------------------------------------------

    def login(self):
        assert self.driver
        log.info("Apro la web UI %s ...", self.host)
        self.driver.get(self.host)
        time.sleep(2)  # piccolo settle iniziale

        # Welcome page TP-Link (richiede di accettare HTTPS)
        try:
            cont = WebDriverWait(self.driver, 3).until(
                EC.element_to_be_clickable((By.ID, "click-continue"))
            )
            log.info("Welcome page rilevata, accetto...")
            cont.click()
            time.sleep(1)
            # Modal "Notice" che chiede conferma
            for sel in [".msg-btn-ok", ".ok", "button:contains('OK')",
                         "#welcome-modal-container button"]:
                try:
                    btn = self.driver.find_element(By.CSS_SELECTOR, sel)
                    if btn.is_displayed():
                        btn.click()
                        log.debug("Cliccato modal ok: %s", sel)
                        time.sleep(1)
                        break
                except NoSuchElementException:
                    continue
        except TimeoutException:
            pass

        # Cerco campo password
        log.info("Cerco campo password...")
        try:
            pwd_input = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
            )
        except TimeoutException:
            log.info("Nessun campo password, forse gia' loggati")
            return

        # Salva HTML di diagnostica della pagina di login
        try:
            with open("nx200_login_page.html", "w", encoding="utf-8") as f:
                f.write(self.driver.page_source)
            log.debug("Pagina login salvata in nx200_login_page.html")
        except Exception:
            pass

        pwd_input.clear()
        pwd_input.send_keys(self.password)
        time.sleep(0.5)

        # Il pulsante login del NX200 e' esattamente #pc-login-btn.
        # Per essere sicuri che gli handler jQuery attivino tutto il flusso
        # crittografico (setHash, genAESKey, ecc.), usiamo jQuery .click()
        # invece del click DOM nativo.
        log.debug("Clicco #pc-login-btn via jQuery...")
        try:
            self.driver.execute_script(
                "if (window.jQuery) { jQuery('#pc-login-btn').click(); } "
                "else { document.getElementById('pc-login-btn').click(); }"
            )
            clicked = True
        except Exception as e:
            log.debug("Click via jQuery fallito: %s", e)
            clicked = False

        # Fallback: cerco altri selettori tipici
        if not clicked:
            for sel in ["#pc-login-btn", "#ph-login-btn",
                        "button[aria-label='Log in ']",
                        ".pc-login-btn", "button.button-button"]:
                try:
                    btn = self.driver.find_element(By.CSS_SELECTOR, sel)
                    if btn.is_displayed():
                        self.driver.execute_script("arguments[0].click();", btn)
                        clicked = True
                        log.debug("Cliccato login via JS: %s", sel)
                        break
                except NoSuchElementException:
                    continue

        if not clicked:
            from selenium.webdriver.common.keys import Keys
            pwd_input.send_keys(Keys.RETURN)
            log.debug("Submit via Invio sul campo password")

        # Aspetta che il login sia completato, ma controlla il popup intermediatamente.
        # Il flusso puo' essere:
        # - Click login → popup "force logout" → clicca confirm-yes → UI principale carica
        # - Click login → UI principale carica direttamente (nessun popup)
        log.info("Attendo completamento login (con gestione popup)...")
        time.sleep(1)

        popup_handled = False
        for attempt in range(40):  # 40 * 0.5sec = 20 secondi
            try:
                # Prova a trovare il popup confirm-yes
                confirm_btn = self.driver.find_elements(By.ID, "confirm-yes")
                if confirm_btn and confirm_btn[0].is_displayed():
                    log.info("Popup 'force logout' rilevato, clicco il pulsante...")
                    try:
                        self.driver.execute_script("arguments[0].click();", confirm_btn[0])
                        log.info("Pulsante cliccato via JavaScript")
                    except Exception as e:
                        log.debug("JS click fallito, provo Selenium click: %s", e)
                        confirm_btn[0].click()
                    time.sleep(2)
                    popup_handled = True
                    log.info("Popup chiuso, attendo UI principale...")
                    break
            except Exception as e:
                log.debug("Errore durante ricerca popup: %s", e)

            # Controlla se la UI principale e' gia' caricata
            try:
                ui_elements = self.driver.find_elements(
                    By.CSS_SELECTOR, "#main, #menu_basic, .navi-side, #adv_status"
                )
                if ui_elements and any(e.is_displayed() for e in ui_elements):
                    log.info("UI principale rilevata, login completato!")
                    time.sleep(2)
                    return  # ← Login riuscito!
            except Exception:
                pass

            # Se il pulsante login e' scomparso, significaa che stiamo progredendo
            try:
                login_btn = self.driver.find_elements(By.ID, "pc-login-btn")
                if not login_btn:
                    log.debug("Pulsante login scomparso, progresso in corso...")
            except Exception:
                pass

            time.sleep(0.5)

        # Se siamo qui, il login ha impiegato tempo. Verifichiamo lo stato finale
        log.info("Fine attesa login. Verifico stato pagina...")
        try:
            page_source = self.driver.page_source.lower()
            if any(s in page_source for s in ["incorrect", "wrong password", "errata", "non valida"]):
                raise RuntimeError("Login: password errata")
        except Exception:
            pass

        # Diagnostica: salva pagina + screenshot
        try:
            ui_els = self.driver.find_elements(
                By.CSS_SELECTOR, "#main, #menu_basic, .navi-side, #adv_status"
            )
            if not ui_els or not any(e.is_displayed() for e in ui_els):
                log.warning("UI principale non visibile. Salvo diagnostica...")
                with open("nx200_after_login.html", "w", encoding="utf-8") as f:
                    f.write(self.driver.page_source)
                self.driver.save_screenshot("nx200_after_login.png")
        except Exception:
            pass

        log.info("Login completato. URL=%s", self.driver.current_url)
        
        # Aspetta che la UI principale sia VERAMENTE caricata
        # prima di tentare di navigare a status.htm
        log.info("Attendo che la UI principale sia pronta...")
        try:
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "#main, #menu_basic, .navi-side"))
            )
            time.sleep(2)
            log.info("UI principale rilevata, pronto per navigazione")
        except TimeoutException:
            log.warning("UI principale non rilevata entro 10 sec, procedo comunque")
            time.sleep(3)

    # ---- navigazione alla pagina Status -------------------------------

    def go_to_status(self):
        assert self.driver
        print("DEBUG: go_to_status() iniziato", flush=True)
        
        # Navighiamo a status.htm via JavaScript interno per evitare
        # problemi HTTP 406 con il GET diretto.
        status_url = self.host + "/main/status.htm"
        log.info("Navigo a %s via JavaScript interno...", status_url)
        print(f"DEBUG: status_url = {status_url}", flush=True)
        
        try:
            # Usa window.location.href per navigazione interna (SPA-like)
            print("DEBUG: eseguo navigate via JS", flush=True)
            self.driver.execute_script(f"window.location.href = '{status_url}';")
            time.sleep(3)  # Attendi caricamento pagina
            print("DEBUG: navigate JS completato", flush=True)
        except Exception as e:
            print(f"DEBUG: navigate JS fallita: {e}", flush=True)
            log.warning("Navigazione via JS fallita, provo GET diretto: %s", e)
            self.driver.get(status_url)
            time.sleep(2)

        # Ora aspetta che il JS della pagina carichi i dati via XHR/fetch
        # verso le API GDPR criptate del modem
        log.info("Attendo caricamento dati radio dal modem...")
        
        for attempt in range(60):  # 60 * 0.5sec = 30 secondi (dà più tempo)
            try:
                # Controlla se qualsiasi campo radio ha dati
                has_nr = self._field_has_value("nr_ssrsrp")
                has_lte = self._field_has_value("lte_rsrp")
                has_general = self._field_has_value("isp")
                
                if has_nr or has_lte or has_general:
                    log.info("Dati radio caricati (NR=%s, LTE=%s, ISP=%s)", 
                             has_nr, has_lte, has_general)
                    time.sleep(1)
                    return
                
                # Debug ogni 15 secondi
                if attempt % 30 == 0:
                    # Controlla quanti elementi ci sono nel DOM
                    try:
                        inputs = self.driver.find_elements(By.TAG_NAME, "input")
                        spans = self.driver.find_elements(By.TAG_NAME, "span")
                        log.debug("Attempt %d: trovati %d input, %d span", 
                                 attempt, len(inputs), len(spans))
                    except Exception:
                        pass

            except Exception as e:
                log.debug("Errore verifica campi (attempt %d): %s", attempt, e)

            time.sleep(0.5)

        # Timeout: salva diagnostica
        log.warning("Timeout attesa dati radio dopo 30 secondi")
        try:
            with open("nx200_status_page.html", "w", encoding="utf-8") as f:
                html = self.driver.page_source
                f.write(html[:10000])  # Salva primi 10000 char
            log.info("HTML status salvato in nx200_status_page.html")
            
            # Lista gli ID degli input trovati
            inputs = self.driver.find_elements(By.TAG_NAME, "input")
            found_ids = [el.get_attribute("id") for el in inputs[:50] if el.get_attribute("id")]
            log.info("Input IDs trovati (primi 50): %s", found_ids)
            
            # Prova a eseguire uno script che mostra il contenuto di alcuni input
            script = """
            var results = {};
            var ids = ['nr_ssrsrp', 'lte_rsrp', 'isp', 'nr_band', 'lte_band'];
            ids.forEach(id => {
                var el = document.getElementById(id);
                results[id] = el ? (el.value || el.textContent || 'not found') : 'null';
            });
            return results;
            """
            field_values = self.driver.execute_script(script)
            log.info("Valori dei campi target: %s", field_values)
        except Exception as e:
            log.debug("Errore salvataggio diagnostica: %s", e)

    def _field_has_value(self, field_id: str) -> bool:
        """Ritorna True se l'input con questo id ha un valore non '--'."""
        assert self.driver
        try:
            el = self.driver.find_element(By.ID, field_id)
            v = el.get_attribute("value") or el.text or ""
            return v.strip() not in ("", "--")
        except NoSuchElementException:
            return False

    # ---- scraping ------------------------------------------------------

    def scrape(self) -> dict[str, Any]:
        """Raccoglie tutti i campi dal DOM in un singolo dict."""
        assert self.driver
        sample: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

        all_fields = {}
        all_fields.update(GENERAL_FIELDS)
        all_fields.update(NR_FIELDS)
        all_fields.update(LTE_FIELDS)
        all_fields.update(PERFORMANCE_FIELDS)

        for our_name, dom_id in all_fields.items():
            try:
                el = self.driver.find_element(By.ID, dom_id)
                value = el.get_attribute("value") or el.text or ""
                value = value.strip()
                if value in ("", "--"):
                    sample[our_name] = None
                else:
                    sample[our_name] = value
            except NoSuchElementException:
                sample[our_name] = None

        self._normalize(sample)
        return sample

    @staticmethod
    def _normalize(s: dict[str, Any]):
        """Converte i campi DOM (stringhe con unita') in numeri."""
        # ss_rsrp: "-85dBm" → -85.0
        for k in ("ss_rsrp", "ss_rsrq", "lte_rsrp", "lte_rsrq"):
            s[k] = _parse_num(s.get(k), strip=("dBm", "dB"))
        # ss_sinr / lte_snr: "12.3dB" → 12.3 (gia' diviso /10 dalla UI)
        for k in ("ss_sinr", "lte_snr"):
            s[k] = _parse_num(s.get(k), strip=("dB",))
        # tx_power: "-3.2dBm" → -3.2 (gia' diviso /10 dalla UI)
        for k in ("nr_tx_power", "lte_tx_power"):
            s[k] = _parse_num(s.get(k), strip=("dBm",))
        # bandwidth: "100MHz" → 100.0
        for k in ("nr_bw_down", "nr_bw_up", "lte_bw_down", "lte_bw_up"):
            s[k] = _parse_num(s.get(k), strip=("MHz",))
        # frequency: "3500MHz" → 3500.0
        for k in ("nr_freq_down", "nr_freq_up", "lte_freq_down", "lte_freq_up"):
            s[k] = _parse_num(s.get(k), strip=("MHz",))
        # signal strength: "75%" → 75.0
        for k in ("nr_signal_pct", "lte_signal_pct"):
            s[k] = _parse_num(s.get(k), strip=("%",))
        # interi
        for k in ("nr_pci", "nr_arfcn", "nr_cqi", "nr_ri", "nr_rbs",
                  "nr_dl_mcs", "nr_ul_mcs",
                  "lte_pci", "lte_earfcn", "lte_cqi", "lte_ri", "lte_rbs",
                  "lte_dl_mcs", "lte_ul_mcs"):
            v = s.get(k)
            try:
                s[k] = int(v) if v not in (None, "") else None
            except (ValueError, TypeError):
                s[k] = None
        # download/upload speed: "12.345MB/s" → 12345000 bytes/s
        s["dl_speed"] = _parse_speed(s.pop("dl_speed_str", None))
        s["ul_speed"] = _parse_speed(s.pop("ul_speed_str", None))
        # cpu / mem: "7%" → 7.0
        s["cpu_load"] = _parse_num(s.pop("cpu_str", None), strip=("%",))
        s["mem_used"] = _parse_num(s.pop("mem_str", None), strip=("%",))
        # uptime: "0 days 00:36:36" → secondi
        s["uptime_sec"] = _parse_uptime(s.pop("uptime_str", None))
        # sim status normalize
        sim_str = s.pop("sim_status_str", None) or ""
        s["sim_status"] = sim_str
        # data left/used: lasciamo come stringa
        s["data_str"] = s.get("data_str") or ""


def _parse_num(v: Any, strip: tuple[str, ...] = ()) -> float | None:
    if v is None:
        return None
    s = str(v).strip()
    for tok in strip:
        s = s.replace(tok, "")
    s = s.strip()
    try:
        return float(s)
    except ValueError:
        return None


def _parse_speed(v: Any) -> int | None:
    """'12.345MB/s' / '500KB/s' / '0B/s' → bytes/sec (int)"""
    if v is None:
        return None
    s = str(v).strip().lower().replace("/s", "")
    m = re.match(r"([\d.]+)\s*(b|kb|mb|gb)", s)
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2)
    mult = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3}[unit]
    return int(num * mult)


def _parse_uptime(v: Any) -> int | None:
    if v is None:
        return None
    # formato: "N days HH:MM:SS"
    m = re.match(r"(\d+)\s+\S+\s+(\d+):(\d+):(\d+)", str(v))
    if not m:
        return None
    d, h, mi, s = map(int, m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


# ===========================================================================
# STORAGE + ANOMALY DETECTION (uguale alle versioni precedenti)
# ===========================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
    network_type TEXT, sim_status TEXT, isp TEXT, mcc TEXT, mnc TEXT,
    imsi TEXT, iccid TEXT, msisdn TEXT,
    nr_band TEXT, nr_pci INTEGER, nr_arfcn INTEGER, nr_cid TEXT, nr_tac TEXT,
    ss_rsrp REAL, ss_rsrq REAL, ss_sinr REAL,
    nr_cqi INTEGER, nr_ri INTEGER, nr_rbs INTEGER,
    nr_dl_mcs INTEGER, nr_ul_mcs INTEGER, nr_dl_mod TEXT, nr_ul_mod TEXT,
    nr_bw_down REAL, nr_bw_up REAL, nr_freq_down REAL, nr_freq_up REAL,
    nr_tx_power REAL, nr_signal_pct REAL,
    lte_band TEXT, lte_pci INTEGER, lte_earfcn INTEGER, lte_cid TEXT, lte_tac TEXT,
    lte_rsrp REAL, lte_rsrq REAL, lte_snr REAL,
    lte_cqi INTEGER, lte_ri INTEGER, lte_rbs INTEGER,
    lte_dl_mcs INTEGER, lte_ul_mcs INTEGER, lte_dl_mod TEXT, lte_ul_mod TEXT,
    lte_bw_down REAL, lte_bw_up REAL, lte_freq_down REAL, lte_freq_up REAL,
    lte_tx_power REAL, lte_signal_pct REAL,
    dl_speed INTEGER, ul_speed INTEGER, data_str TEXT,
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
        self.conn = sqlite3.connect(p)
        # Migrazione schema: se la tabella esiste ma manca una colonna che ci serve,
        # la droppiamo e ricreiamo. Conserviamo i dati solo se lo schema combacia.
        try:
            cols = {r[1] for r in self.conn.execute(
                "PRAGMA table_info(samples)").fetchall()}
            required = {"sim_status", "ss_rsrp", "nr_pci"}
            if cols and not required.issubset(cols):
                log.warning("Schema DB obsoleto, ricreo le tabelle (i dati precedenti vengono persi)")
                self.conn.execute("DROP TABLE IF EXISTS samples")
                self.conn.execute("DROP TABLE IF EXISTS anomalies")
                self.conn.commit()
        except sqlite3.Error:
            pass
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert_sample(self, s: dict[str, Any]) -> int:
        cols = [
            "ts","network_type","sim_status","isp","mcc","mnc",
            "imsi","iccid","msisdn",
            "nr_band","nr_pci","nr_arfcn","nr_cid","nr_tac",
            "ss_rsrp","ss_rsrq","ss_sinr","nr_cqi","nr_ri","nr_rbs",
            "nr_dl_mcs","nr_ul_mcs","nr_dl_mod","nr_ul_mod",
            "nr_bw_down","nr_bw_up","nr_freq_down","nr_freq_up",
            "nr_tx_power","nr_signal_pct",
            "lte_band","lte_pci","lte_earfcn","lte_cid","lte_tac",
            "lte_rsrp","lte_rsrq","lte_snr","lte_cqi","lte_ri","lte_rbs",
            "lte_dl_mcs","lte_ul_mcs","lte_dl_mod","lte_ul_mod",
            "lte_bw_down","lte_bw_up","lte_freq_down","lte_freq_up",
            "lte_tx_power","lte_signal_pct",
            "dl_speed","ul_speed","data_str",
            "cpu_load","mem_used","uptime_sec",
        ]
        vals = [s.get(c) for c in cols] + [json.dumps(
            {k: v for k, v in s.items() if k not in cols}, default=str
        )]
        sql = (f"INSERT INTO samples ({','.join(cols + ['raw_json'])}) "
               f"VALUES ({','.join('?' * (len(cols)+1))})")
        cur = self.conn.execute(sql, vals)
        self.conn.commit()
        return cur.lastrowid  # type: ignore

    def insert_anomaly(self, ts, sev, kind, msg, sid=None):
        self.conn.execute(
            "INSERT INTO anomalies (ts,severity,kind,message,sample_id) "
            "VALUES (?,?,?,?,?)",
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

    def close(self):
        self.conn.close()


class AnomalyDetector:
    def __init__(self, store, t):
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
                              f"RSRP={rsrp:.1f} su PCI={pci} è {d:.1f}dB "
                              f"sotto baseline ({mu:.1f}, n={n})."))
        if rsrp and sinr and rsrp > -90 and sinr < t.sinr_poor:
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
        if rsrp and rsrp > -95 and rbs and rbs < 20 and dl and dl < 5e6:
            f.append(("info", "cell_congestion",
                      f"RSRP ok ma RBs={rbs} DL={dl/1e6:.1f}Mbps."))
        if ri is not None and ri <= 1 and rsrp and rsrp > -100:
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


def run_once(host, password, store, detector, username,
             headless, browser_binary):
    with StatusScraper(host, password, username,
                        headless=headless,
                        browser_binary=browser_binary) as sc:
        sc.login()
        sc.go_to_status()
        sample = sc.scrape()

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
    p.add_argument("--no-headless", action="store_true",
                   help="Mostra il browser (utile per debug iniziale)")
    p.add_argument("--browser-binary", default=None,
                   help="Path al binario Chrome/Brave/Chromium se non auto-rilevato")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    store = Store(Path(args.db))
    detector = AnomalyDetector(store, Thresholds())

    log.info("Avvio: host=%s interval=%ds db=%s headless=%s",
             args.host, args.interval, args.db, not args.no_headless)
    try:
        if args.once:
            run_once(args.host, args.password, store, detector, args.username,
                     not args.no_headless, args.browser_binary)
            return
        while _RUN:
            t0 = time.time()
            try:
                run_once(args.host, args.password, store, detector, args.username,
                         not args.no_headless, args.browser_binary)
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