"""Descriptive radio trends; no forecast or inferred cause of degradation."""
import pandas as pd

METRICS = {
    'nr_rsrp': ('5G RSRP', 'nr_pci', 3.0, 6.0),
    'nr_sinr': ('5G SINR', 'nr_pci', 2.0, 4.0),
    'lte_rsrp': ('LTE RSRP', 'lte_pci', 3.0, 6.0),
    'lte_sinr': ('LTE SINR', 'lte_pci', 2.0, 4.0),
}


def analyse_radio(frame, expected_interval=60, now=None):
    """Compare minute medians in the last 10 min with the preceding 20 min.

    Require five recent and ten baseline minute bins, with at least 20 min
    of continuous history. Reset at cell changes and acquisition gaps.
    This prevents dense bursts, stale data and handovers becoming alerts.
    """
    now = pd.Timestamp.now(tz='UTC') if now is None else pd.Timestamp(now)
    now = now.tz_localize('UTC') if now.tzinfo is None else now.tz_convert('UTC')
    results = []
    if frame.empty:
        return results
    data = frame.copy()
    data['ts'] = pd.to_datetime(data['ts'], utc=True, errors='coerce', format='ISO8601')
    data = data.dropna(subset=['ts']).sort_values('ts')
    data = data[(data['ts'] <= now) & (data['ts'] >= now - pd.Timedelta(minutes=30))]
    max_gap = max(180, expected_interval * 3)
    for metric, (label, pci_name, trend_db, alert_db) in METRICS.items():
        result = {'metric': metric, 'label': label, 'state': 'insufficient', 'delta_db': None,
                  'alert': False, 'recent_bins': 0, 'baseline_bins': 0}
        results.append(result)
        if data.empty or metric not in data or pci_name not in data:
            continue
        # Include rows without this radio when segmenting: disappearance of a
        # radio interrupts its baseline even if the other radio remains online.
        radio = data[['ts', metric, pci_name]].copy()
        radio[metric] = pd.to_numeric(radio[metric], errors='coerce')
        radio[metric] = radio[metric].where(radio[metric].abs() != float('inf'))
        if pd.isna(radio.iloc[-1][metric]) or pd.isna(radio.iloc[-1][pci_name]):
            continue
        last_ts = radio.iloc[-1]['ts']
        if (now - last_ts).total_seconds() > max_gap:
            result['state'] = 'stale'
            continue
        breaks = (radio[pci_name].ne(radio[pci_name].shift())
                  | radio[pci_name].isna() | radio[metric].isna() | radio[metric].shift().isna()
                  | radio['ts'].diff().dt.total_seconds().gt(max_gap))
        radio = radio.loc[breaks.cumsum().eq(breaks.cumsum().iloc[-1])]
        bins = radio.set_index('ts')[metric].resample('1min').median().dropna()
        split = now.floor('min') - pd.Timedelta(minutes=10)
        recent, baseline = bins[bins.index >= split], bins[bins.index < split]
        result.update(recent_bins=len(recent), baseline_bins=len(baseline))
        if len(recent) < 5 or len(baseline) < 10 or (last_ts - radio.iloc[0]['ts']).total_seconds() < 1200:
            continue
        delta = float(recent.median() - baseline.median())
        result.update(delta_db=round(delta, 2), alert=delta <= -alert_db,
                      state='degrading' if delta <= -trend_db else 'improving' if delta >= trend_db else 'stable')
    return results
