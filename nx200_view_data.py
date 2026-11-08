#!/usr/bin/env python3
"""
nx200_view_data.py - Visualizza dati dal database SQLite e esporta CSV
"""

import sqlite3
import csv
import argparse
import sys
from pathlib import Path
from tabulate import tabulate

def view_database(db_path: str, limit: int = 100):
    """Mostra i dati del database in formato tabella."""
    if not Path(db_path).exists():
        print(f"Database non trovato: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Conta i record
    c.execute("SELECT COUNT(*) FROM samples")
    count = c.fetchone()[0]
    print(f"\nDatabase: {db_path}")
    print(f"Record totali: {count}")
    
    # Mostra gli ultimi record
    c.execute("""
        SELECT 
            id, ts, network_type, nr_pci, nr_rsrp, nr_sinr, 
            lte_pci, lte_rsrp, lte_sinr
        FROM samples 
        ORDER BY id DESC 
        LIMIT ?
    """, (limit,))
    
    rows = c.fetchall()
    if not rows:
        print("Nessun dato nel database")
        conn.close()
        return
    
    # Formatta per tabella
    headers = ["ID", "Timestamp", "Type", "NR-PCI", "NR-RSRP", "NR-SINR", 
               "LTE-PCI", "LTE-RSRP", "LTE-SINR"]
    
    formatted_rows = []
    for row in rows:
        formatted_row = [
            row[0],
            row[1][:19],  # timestamp senza millisecondi
            row[2] or "-",
            row[3] if row[3] is not None else "-",
            f"{row[4]:.1f}" if row[4] is not None else "-",
            f"{row[5]:.1f}" if row[5] is not None else "-",
            row[6] if row[6] is not None else "-",
            f"{row[7]:.1f}" if row[7] is not None else "-",
            f"{row[8]:.1f}" if row[8] is not None else "-",
        ]
        formatted_rows.append(formatted_row)
    
    print("\n" + tabulate(formatted_rows, headers=headers, tablefmt="grid", disable_numparse=True))
    print(f"\nMostrando ultimi {min(limit, count)} record\n")
    
    conn.close()

def export_csv(db_path: str, csv_path: str = None):
    """Esporta i dati in CSV."""
    if not Path(db_path).exists():
        print(f"Database non trovato: {db_path}")
        return
    
    if not csv_path:
        csv_path = Path(db_path).stem + "_export.csv"
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    c.execute("SELECT * FROM samples ORDER BY id DESC")
    rows = c.fetchall()
    
    if not rows:
        print("Nessun dato da esportare")
        conn.close()
        return
    
    # Get column names
    c.execute("PRAGMA table_info(samples)")
    columns = [col[1] for col in c.fetchall()]
    
    # Scrivi CSV
    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        writer.writerows(rows)
    
    print(f"Esportato in CSV: {csv_path}")
    print(f"   {len(rows)} record salvati")
    conn.close()

def get_stats(db_path: str):
    """Mostra statistiche sui dati."""
    if not Path(db_path).exists():
        print(f"Database non trovato: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Stats RSRP
    c.execute("""
        SELECT 
            COUNT(*) as count,
            AVG(nr_rsrp) as nr_avg,
            MIN(nr_rsrp) as nr_min,
            MAX(nr_rsrp) as nr_max,
            AVG(lte_rsrp) as lte_avg,
            MIN(lte_rsrp) as lte_min,
            MAX(lte_rsrp) as lte_max
        FROM samples
    """)
    
    result = c.fetchone()
    if not result[0]:
        print("Nessun dato disponibile")
        conn.close()
        return
    
    count, nr_avg, nr_min, nr_max, lte_avg, lte_min, lte_max = result
    
    print(f"\nStatistiche segnale (su {count} campioni)")
    print("\n5G NR:")
    if nr_avg is not None:
        print(f"  RSRP medio:  {nr_avg:.1f} dBm")
        print(f"  RSRP min:    {nr_min:.1f} dBm")
        print(f"  RSRP max:    {nr_max:.1f} dBm")
    else:
        print("  Nessun dato 5G")
    
    print("\nLTE:")
    if lte_avg is not None:
        print(f"  RSRP medio:  {lte_avg:.1f} dBm")
        print(f"  RSRP min:    {lte_min:.1f} dBm")
        print(f"  RSRP max:    {lte_max:.1f} dBm")
    else:
        print("  Nessun dato LTE")
    
    print()
    conn.close()

def main():
    parser = argparse.ArgumentParser(
        description="Visualizza e esporta dati dal database NX200"
    )
    parser.add_argument("--db", default="nx200_prod.db", 
                        help="Percorso al database SQLite")
    parser.add_argument("--limit", type=int, default=50,
                        help="Numero di record da mostrare (default: 50)")
    parser.add_argument("--csv", action="store_true",
                        help="Esporta i dati in CSV")
    parser.add_argument("--csv-file", 
                        help="Nome del file CSV (default: nx200_prod_export.csv)")
    parser.add_argument("--stats", action="store_true",
                        help="Mostra statistiche sui segnali")
    args = parser.parse_args()
    
    if args.csv:
        export_csv(args.db, args.csv_file)
    elif args.stats:
        get_stats(args.db)
    else:
        view_database(args.db, args.limit)

if __name__ == "__main__":
    main()
