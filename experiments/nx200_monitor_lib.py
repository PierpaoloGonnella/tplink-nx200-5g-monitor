#!/usr/bin/env python3
"""
nx200_monitor_lib.py - Monitor che usa la libreria tplinkrouterc6u
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from tplinkrouterc6u import Archer
import sqlite3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.1.1")
    parser.add_argument("--password", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--db", default="nx200_data.db")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    
    try:
        log.info("Connessione al modem %s...", args.host)
        # Crea un'istanza Archer - potrebbe richiedere HTTP o HTTPS
        router = Archer(args.host, args.password, args.username)
        
        log.info("Recupero status...")
        status = router.get_status()
        log.info("Status: %s", status)
        
        # Crea il database
        conn = sqlite3.connect(args.db)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY,
            ts TEXT,
            raw_status TEXT
        )""")
        
        # Salva il sample
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        c.execute("INSERT INTO samples (ts, raw_status) VALUES (?, ?)",
                  (ts, str(status)))
        conn.commit()
        log.info("Sample salvato")
        conn.close()
        
    except Exception as e:
        log.error("Errore: %s", e, exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
