#!/usr/bin/env python3
"""
nx200_monitor_html.py - Monitor che estrae i dati dal HTML della pagina di status
Approccio: Selenium + DOM scraping (non API)
"""

import argparse
import logging
import sys
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time
import re

def setup_logging(log_file: str = None):
    """Configura logging a console e file opzionalmente."""
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.info("Log salvato in: %s", log_file)
    
    return logger

log = logging.getLogger(__name__)

def init_db(db_path: str):
    """Crea/prepara il database."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS samples (
        id INTEGER PRIMARY KEY,
        ts TEXT,
        network_type TEXT,
        nr_pci INTEGER,
        nr_rsrp REAL,
        nr_sinr REAL,
        nr_band TEXT,
        lte_pci INTEGER,
        lte_rsrp REAL,
        lte_sinr REAL,
        lte_band TEXT,
        raw_response TEXT
    )""")
    conn.commit()
    return conn

import sys as _sys, pathlib as _pl; _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
from nx200_monitor_prod import do_login_selenium

def extract_data_from_page(driver) -> dict:
    """Estrae i dati dalla pagina HTML usando Selenium."""
    
    from urllib.parse import urljoin
    log.info("Navigating to status page...")
    driver.get(urljoin(driver.current_url, "/main/status.htm"))

    time.sleep(3)
    
    try:
        # Prova a trovare i dati nel DOM
        page_source = driver.page_source
        
        # Cerca valori nel JavaScript o HTML
        result = {
            "nr_pci": None,
            "nr_rsrp": None,
            "nr_sinr": None,
            "nr_band": None,
            "lte_pci": None,
            "lte_rsrp": None,
            "lte_sinr": None,
            "lte_band": None,
            "network_type": None,
        }
        
        # Ricerca pattern comuni nel codice sorgente
        # Cerco variabili JavaScript come: PCI=..., RSRP=..., ecc
        
        # Pattern per 5G NR
        nr_pci_match = re.search(r'nr_pci["\']?\s*[=:]\s*["\']?(\d+)', page_source, re.IGNORECASE)
        if nr_pci_match:
            result["nr_pci"] = int(nr_pci_match.group(1))
        
        nr_rsrp_match = re.search(r'(?:nr_rsrp|ss_rsrp)["\']?\s*[=:]\s*["\']?(-?\d+(?:\.\d+)?)', page_source, re.IGNORECASE)
        if nr_rsrp_match:
            result["nr_rsrp"] = float(nr_rsrp_match.group(1))
        
        nr_sinr_match = re.search(r'(?:nr_sinr|ss_sinr)["\']?\s*[=:]\s*["\']?(-?\d+(?:\.\d+)?)', page_source, re.IGNORECASE)
        if nr_sinr_match:
            result["nr_sinr"] = float(nr_sinr_match.group(1))
        
        # Pattern per LTE
        lte_pci_match = re.search(r'lte_pci["\']?\s*[=:]\s*["\']?(\d+)', page_source, re.IGNORECASE)
        if lte_pci_match:
            result["lte_pci"] = int(lte_pci_match.group(1))
        
        lte_rsrp_match = re.search(r'(?:lte_rsrp|rsrp)["\']?\s*[=:]\s*["\']?(-?\d+(?:\.\d+)?)', page_source, re.IGNORECASE)
        if lte_rsrp_match:
            result["lte_rsrp"] = float(lte_rsrp_match.group(1))
        
        lte_sinr_match = re.search(r'(?:lte_sinr|snr)["\']?\s*[=:]\s*["\']?(-?\d+(?:\.\d+)?)', page_source, re.IGNORECASE)
        if lte_sinr_match:
            result["lte_sinr"] = float(lte_sinr_match.group(1))
        
        # Determina network type
        if result["nr_rsrp"]:
            result["network_type"] = "5G"
        elif result["lte_rsrp"]:
            result["network_type"] = "LTE"
        
        log.info("Extracted data: %s", result)
        return result
        
    except Exception as e:
        log.error("Error extracting data: %s", e)
        return {
            "nr_pci": None,
            "nr_rsrp": None,
            "nr_sinr": None,
            "nr_band": None,
            "lte_pci": None,
            "lte_rsrp": None,
            "lte_sinr": None,
            "lte_band": None,
            "network_type": None,
        }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="https://192.168.1.1")
    parser.add_argument("--password", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--db", default="nx200_html.db")
    parser.add_argument("--log", help="File per salvare i log (optional)")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    
    from nx200_monitor_prod import setup_logging as configure_logging
    configure_logging(args.log)
    if args.interval < 10:
        parser.error("--interval must be at least 10 seconds")
    
    driver = None
    conn = None
    
    try:
        conn = init_db(args.db)
        log.info("Database initialized: %s", args.db)
        
        driver = do_login_selenium(args.host, args.password, args.username)
        log.info("Logged in successfully")
        
        while True:
            data = extract_data_from_page(driver)
            
            if all(data.get(k) is None for k in ("nr_rsrp", "nr_sinr", "lte_rsrp", "lte_sinr")):
                raise RuntimeError("No usable metrics found in the status page")
            c = conn.cursor()
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            c.execute("""
                INSERT INTO samples 
                (ts, network_type, nr_pci, nr_rsrp, nr_sinr, nr_band,
                 lte_pci, lte_rsrp, lte_sinr, lte_band, raw_response) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts,
                data.get("network_type"),
                data.get("nr_pci"),
                data.get("nr_rsrp"),
                data.get("nr_sinr"),
                data.get("nr_band"),
                data.get("lte_pci"),
                data.get("lte_rsrp"),
                data.get("lte_sinr"),
                data.get("lte_band"),
                str(data)
            ))
            conn.commit()
            
            rsrp = data.get("nr_rsrp") or data.get("lte_rsrp")
            sinr = data.get("nr_sinr") or data.get("lte_sinr")
            log.info("Sample saved: network=%s RSRP=%s SINR=%s",
                     data.get("network_type") or "unknown",
                     f"{rsrp:.1f}" if rsrp else "n/a",
                     f"{sinr:.1f}" if sinr else "n/a")
        
            if args.once:
                break
            time.sleep(args.interval)
        log.info("Done")
        
    except Exception as e:
        log.error("Error: %s", e, exc_info=True)
        sys.exit(1)
        
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
