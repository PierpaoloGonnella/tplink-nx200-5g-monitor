#!/usr/bin/env python3
"""
nx200_monitor_simple.py - Monitor semplice usando socket raw come v4
"""
import sys as _sys, pathlib as _pl; _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
from nx200_monitor_v4 import TPLinkGdprClient
import argparse
import logging
import sys
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger()

# Campi per le query GDPR
SERVING_CELL_FIELDS = [
    "PCI", "band", "networkType", "cellConnectionStatus",
    "RSRP", "SINR", "RSRQ", "SNR", "earfcn",
    "SSRSRP", "SSSINR", "SSRSRQ"
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="https://192.168.1.1")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    try:
        log.info("Connessione al modem...")
        client = TPLinkGdprClient(args.host, args.password, args.username)
        
        log.info("Login...")
        client.login()
        
        log.info("Query dati...")
        # Formato di query GDPR
        nfields = len(SERVING_CELL_FIELDS)
        query_body = f"5\r\n[DEV2_LTE_SERVING_CELL_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,{nfields}\r\n"
        for f in SERVING_CELL_FIELDS:
            query_body += f"{f}\r\n"
        
        response_text = client.request_data(query_body)
        log.info("Response: %s", response_text[:200])
        
    except Exception as e:
        log.error("Errore: %s", e, exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
