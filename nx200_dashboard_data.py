"""Read-only snapshots shared by the live dashboard and its tests."""
from contextlib import closing
from pathlib import Path
import sqlite3
import pandas as pd
from nx200_radio_fields import LINK_COLUMNS, extract_link_adaptation

RADIO_COLUMNS = ('nr_rsrp', 'nr_sinr', 'lte_rsrp', 'lte_sinr')
ALIASES = {
    'nr_rsrp': ('nr_rsrp', 'ss_rsrp'),
    'nr_sinr': ('nr_sinr', 'ss_sinr'),
    'lte_rsrp': ('lte_rsrp',),
    'lte_sinr': ('lte_sinr', 'lte_snr'),
    'nr_pci': ('nr_pci',), 'lte_pci': ('lte_pci',),
    'network_type': ('network_type',),
}
ALIASES.update({name: (name,) for name in LINK_COLUMNS})


def load_snapshot(db_path, hours=None, limit=5000):
    path = Path(db_path).resolve()
    if not path.is_file():
        raise FileNotFoundError('Database non ancora disponibile. Avvia il monitor per raccogliere dati.')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)) as conn:
        conn.execute('BEGIN')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(samples)')}
        if not {'id', 'ts'}.issubset(columns):
            raise ValueError('Il database selezionato non contiene una tabella samples compatibile.')
        expressions = {}
        for name, candidates in ALIASES.items():
            available = [f'"{c}"' for c in candidates if c in columns]
            expressions[name] = ('COALESCE(' + ','.join(available) + ')' if len(available) > 1
                                 else available[0] if available else 'NULL')
        selection = 'id,ts,' + ','.join(f'{expr} AS "{name}"' for name, expr in expressions.items())
        if 'raw_response' in columns:
            missing_link = ' OR '.join(f'{expressions[name]} IS NULL' for name in LINK_COLUMNS)
            selection += f',CASE WHEN {missing_link} THEN raw_response ELSE NULL END AS _raw_link'
        valid = '(' + ' OR '.join(f'{expressions[name]} IS NOT NULL' for name in RADIO_COLUMNS) + ')'
        total, valid_total = conn.execute(f'SELECT count(*),coalesce(sum({valid}),0) FROM samples').fetchone()
        query = f'SELECT {selection} FROM samples WHERE {valid}'
        latest = pd.read_sql_query(query + ' ORDER BY julianday(ts) DESC,id DESC LIMIT 1', conn)
        params = []
        if hours is not None:
            query += " AND julianday(ts) >= julianday('now', ?)"
            params.append(f'-{int(hours)} hours')
        query += ' ORDER BY julianday(ts) DESC,id DESC LIMIT ?'
        params.append(int(limit))
        frame = pd.read_sql_query(query, conn, params=params)
        has_errors = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='poll_errors'").fetchone()
        errors = pd.read_sql_query('SELECT ts,message FROM poll_errors ORDER BY id DESC LIMIT 20', conn) if has_errors else pd.DataFrame(columns=['ts', 'message'])
    for data in (frame, latest):
        if '_raw_link' in data:
            for index, raw in data['_raw_link'].items():
                for name, value in extract_link_adaptation(raw).items():
                    if pd.isna(data.at[index, name]) and value is not None:
                        if name.endswith('_mod'):
                            data[name] = data[name].astype(object)
                        data.at[index, name] = value
            del data['_raw_link']
        for name in LINK_COLUMNS:
            if name.endswith('_mcs'):
                data[name] = pd.to_numeric(data[name], errors='coerce')
        data['ts'] = pd.to_datetime(data['ts'], utc=True, errors='coerce', format='ISO8601')
        for name in RADIO_COLUMNS:
            data[name] = pd.to_numeric(data[name], errors='coerce')
    frame = frame.dropna(subset=['ts']).sort_values(['ts', 'id']).reset_index(drop=True)
    return {'samples': frame, 'latest': latest, 'errors': errors,
            'total': total, 'excluded': total - valid_total, 'limit': limit}
