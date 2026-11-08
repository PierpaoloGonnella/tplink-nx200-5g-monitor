#!/usr/bin/env python3
"""
nx200_tail_log.py - Mostra il log in tempo reale (come 'tail -f')
"""

import argparse
import sys
import time
from pathlib import Path

def tail_log(log_file: str, lines: int = 20):
    """Mostra il log e attende nuovi contenuti."""
    path = Path(log_file)
    
    if not path.exists():
        print(f"❌ File non trovato: {log_file}")
        return 1
    
    # Leggi la posizione iniziale
    pos = path.stat().st_size
    print(f"📋 Monitorando: {log_file}")
    print(f"📍 Premere Ctrl+C per uscire\n")
    
    # Mostra le ultime linee
    try:
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            for line in all_lines[-lines:]:
                print(line.rstrip())
    except Exception as e:
        print(f"❌ Errore: {e}")
        return 1
    
    print("\n--- Nuovi messaggi ---\n")
    
    # Attendi nuovi contenuti
    try:
        while True:
            try:
                with open(log_file, 'r') as f:
                    f.seek(pos)
                    new_lines = f.readlines()
                    
                    for line in new_lines:
                        # Colora i messaggi
                        if "[ERROR]" in line:
                            print(f"❌ {line.rstrip()}")
                        elif "[WARNING]" in line:
                            print(f"⚠️  {line.rstrip()}")
                        elif "[INFO]" in line:
                            print(f"ℹ️  {line.rstrip()}")
                        else:
                            print(f"   {line.rstrip()}")
                    
                    if new_lines:
                        pos = f.tell()
            except Exception:
                pass
            
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\n\n👋 Uscito dal monitoraggio")
        return 0

def main():
    parser = argparse.ArgumentParser(
        description="Mostra il log in tempo reale (come 'tail -f')"
    )
    parser.add_argument("--log", default="test.log",
                        help="File log da monitorare")
    parser.add_argument("--lines", type=int, default=20,
                        help="Linee iniziali da mostrare")
    args = parser.parse_args()
    
    return tail_log(args.log, args.lines)

if __name__ == "__main__":
    sys.exit(main())
