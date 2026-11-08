"""Categorical modulation timelines that preserve missing data and gaps."""
import pandas as pd

MODULATION_COLUMNS = ('nr_dl_mod', 'nr_ul_mod', 'lte_dl_mod', 'lte_ul_mod')
KNOWN_ORDER = ('BPSK', 'QPSK', '16QAM', '64QAM', '256QAM', '1024QAM')


def modulation_timeline(frame, column, pci_column, expected_interval=60):
    data = frame[['ts', column, pci_column]].copy()
    data.columns = ['ts', 'Modulazione', 'PCI']
    data['ts'] = pd.to_datetime(data['ts'], utc=True, errors='coerce', format='ISO8601')
    data = data.dropna(subset=['ts']).sort_values('ts', kind='stable').reset_index(drop=True)
    data['Modulazione'] = data['Modulazione'].astype('string').str.strip()
    data['Modulazione'] = data['Modulazione'].replace({'': pd.NA, '-': pd.NA, '--': pd.NA})
    changes = (data['ts'].diff().dt.total_seconds().gt(max(180, expected_interval * 3))
               | data['Modulazione'].isna() | data['Modulazione'].shift().isna()
               | data['PCI'].ne(data['PCI'].shift()).fillna(True))
    data['Segmento'] = changes.cumsum()
    data = data.dropna(subset=['Modulazione'])
    data['Ora locale'] = data['ts'].dt.tz_convert('Europe/Rome').dt.strftime('%d/%m/%Y %H:%M:%S %Z')
    return data


def modulation_order(frame):
    values = set()
    for name in MODULATION_COLUMNS:
        values.update(frame[name].dropna().astype(str).str.strip())
    values.difference_update(('', '-', '--'))
    # Stable axes across all four plots. Preserve unknown firmware labels.
    return [name for name in reversed(KNOWN_ORDER) if name in values] + sorted(values.difference(KNOWN_ORDER))
