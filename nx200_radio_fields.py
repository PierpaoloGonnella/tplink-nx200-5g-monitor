"""MCS indices and modulation strings as reported by active serving cells."""
import json
import math

LINK_COLUMNS = {f'{radio}_{direction}_{kind}': 'INTEGER' if kind == 'mcs' else 'TEXT'
                for radio in ('nr', 'lte') for direction in ('dl', 'ul') for kind in ('mcs', 'mod')}


def extract_link_adaptation(cells):
    if isinstance(cells, str):
        try:
            cells = json.loads(cells)
        except (ValueError, TypeError):
            return {}
    if isinstance(cells, dict):
        cells = cells.get('data')
    if not isinstance(cells, list):
        return {}
    result = {}
    for cell in cells:
        if not isinstance(cell, dict) or str(cell.get('cellConnectionStatus')) != '1':
            continue
        network = str(cell.get('networkType'))
        radio = 'nr' if network == '8' else 'lte' if network in ('3', '7') else None
        if radio is None:
            continue
        for direction, mcs_key, mod_key in (('dl', 'downMCS', 'downlinkModType'), ('ul', 'upMCS', 'uplinkModType')):
            value = cell.get(mcs_key)
            try:
                number = float(value)
                value = int(number) if math.isfinite(number) and number.is_integer() and number >= 0 else None
            except (ValueError, TypeError, OverflowError):
                value = None
            result[f'{radio}_{direction}_mcs'] = value
            modulation = cell.get(mod_key)
            result[f'{radio}_{direction}_mod'] = modulation.strip() if isinstance(modulation, str) and modulation.strip() not in ('', '--', '-') else None
    return result
