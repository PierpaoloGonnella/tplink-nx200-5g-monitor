#!/usr/bin/env python3
"""
nx200_monitor_working.py - Versione funzionante con retry e timeout
"""

import sys
sys.path.insert(0, ".")

import sys as _sys, pathlib as _pl; _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
from nx200_monitor_v4 import TPLinkGdprClient
import argparse
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="https://192.168.1.1")
    parser.add_argument("--password", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--retries", type=int, default=5)
    args = parser.parse_args()
    
    # Retry loop per il login
    for attempt in range(args.retries):
        try:
            log.info("Login attempt %d/%d...", attempt + 1, args.retries)
            client = TPLinkGdprClient(args.host, args.password, args.username)
            client.login()
            log.info("Login successful!")
            
            # Se siamo qui, il login è riuscito
            return 0
            
        except RuntimeError as e:
            if "71011" in str(e):
                log.warning("Login temporaneamente bloccato (71011). Attesa 5 secondi...")
                if attempt < args.retries - 1:
                    time.sleep(5)
                    continue
            log.error("Login failure: %s", e)
            return 1
        except Exception as e:
            log.error("Error: %s", e, exc_info=True)
            return 1
    
    log.error("Login failed after %d attempts", args.retries)
    return 1

if __name__ == "__main__":
    sys.exit(main())
