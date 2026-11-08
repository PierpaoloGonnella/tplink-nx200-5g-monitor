from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing
import json
import sqlite3
import tempfile
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import pandas as pd

from nx200_analysis import analyse_radio
import nx200_collection as collection
import nx200_monitor_prod as monitor

NOW = pd.Timestamp('2026-10-25T12:00:00Z')


def history(recent=-93, baseline=-85):
    times = pd.date_range(NOW - pd.Timedelta(minutes=30), NOW, freq='min')
    values = [recent if time >= NOW - pd.Timedelta(minutes=10) else baseline for time in times]
    return pd.DataFrame({'ts': times, 'nr_rsrp': values, 'nr_sinr': 10,
                         'lte_rsrp': -95, 'lte_sinr': 0, 'nr_pci': 0, 'lte_pci': 1})


class AnalysisTests(unittest.TestCase):
    def test_relative_drop_on_same_pci_triggers_alert(self):
        nr = analyse_radio(history(), now=NOW)[0]
        self.assertEqual(nr['delta_db'], -8)
        self.assertEqual(nr['state'], 'degrading')
        self.assertTrue(nr['alert'])

    def test_stable_and_improving_are_not_alerts(self):
        for recent, state in [(-85, 'stable'), (-80, 'improving')]:
            result = analyse_radio(history(recent=recent), now=NOW)[0]
            self.assertEqual(result['state'], state)
            self.assertFalse(result['alert'])

    def test_cell_change_resets_reference(self):
        data = history()
        data.loc[data.index[-7:], 'nr_pci'] = 100
        result = analyse_radio(data, now=NOW)[0]
        self.assertEqual(result['state'], 'insufficient')
        self.assertFalse(result['alert'])

    def test_gaps_and_radio_disappearance_reset_reference(self):
        for missing in (False, True):
            data = history()
            if missing:
                data.loc[22, 'nr_rsrp'] = float('nan')
            else:
                data = data.drop(index=range(18, 24))
            result = analyse_radio(data, now=NOW)[0]
            self.assertEqual(result['state'], 'insufficient')
            self.assertFalse(result['alert'])

    def test_stale_data_do_not_trigger_fresh_alerts(self):
        result = analyse_radio(history().iloc[:-5], now=NOW)[0]
        self.assertEqual(result['state'], 'stale')
        self.assertFalse(result['alert'])

    def test_dense_short_burst_is_insufficient(self):
        data = history().iloc[-3:]
        data = pd.concat([data] * 100)
        self.assertEqual(analyse_radio(data, now=NOW)[0]['state'], 'insufficient')

    def test_zero_sinr_is_a_valid_value(self):
        data = history()
        data['nr_sinr'] = [0 if time >= NOW - pd.Timedelta(minutes=10) else 6 for time in data['ts']]
        result = analyse_radio(data, now=NOW)[1]
        self.assertEqual(result['delta_db'], -6)
        self.assertTrue(result['alert'])

    def test_missing_current_radio_and_future_samples_are_ignored(self):
        data = history()
        data.loc[data.index[-1], 'nr_rsrp'] = float('nan')
        self.assertEqual(analyse_radio(data, now=NOW)[0]['state'], 'insufficient')
        data['ts'] += pd.Timedelta(days=1)
        self.assertTrue(all(item['state'] == 'insufficient' for item in analyse_radio(data, now=NOW)))


class CollectionTests(unittest.TestCase):
    def test_background_worker_lifecycle_across_processes(self):
        code = '''
import sys,time
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import nx200_collection as c
import nx200_monitor_prod as monitor
root=Path(sys.argv[1])
c.STATE=root/'state.json'; c.STOP=root/'stop'; c.LOCK=root/'lock'
def collect():
    while not c.STOP.exists(): time.sleep(0.02)
    return 0
with patch.object(monitor,'main',side_effect=collect):
    raise SystemExit(c.worker(SimpleNamespace(db=str(root/'data.db'),interval=60,credentials_file='unused')))
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            process = subprocess.Popen([sys.executable, '-c', code, folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                with patch.object(collection, 'STATE', root/'state.json'), patch.object(collection, 'STOP', root/'stop'), patch.object(collection, 'LOCK', root/'lock'):
                    for _ in range(100):
                        if collection.status()['running']:
                            break
                        time.sleep(0.05)
                    self.assertTrue(collection.status()['running'])
                    collection.STOP.touch()
                    self.assertEqual(process.wait(timeout=10), 0)
                    self.assertFalse(collection.status()['running'])
                    self.assertEqual(collection.status()['state'], 'stopped')
            finally:
                if process.poll() is None:
                    (root/'stop').touch()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=5)

    def test_exclusive_lock_is_released(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'worker.lock'
            with collection.CollectionLock(path):
                with self.assertRaises(RuntimeError):
                    with collection.CollectionLock(path):
                        pass
            with collection.CollectionLock(path):
                pass

    def test_stop_file_interrupts_wait_without_sleeping(self):
        with tempfile.TemporaryDirectory() as folder:
            stop = Path(folder) / 'stop'
            stop.touch()
            with patch.object(monitor.time, 'sleep') as sleep:
                monitor.wait_for_poll(60, stop)
            sleep.assert_not_called()

    def test_status_reports_interrupted_worker_without_killing_any_pid(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'state.json'
            state.write_text(json.dumps({'state':'running','pid':999999,'db':str(Path(folder)/'missing.db')}))
            with patch.object(collection, 'STATE', state), patch.object(collection, 'CollectionLock'):
                result = collection.status()
            self.assertFalse(result['running'])
            self.assertEqual(result['state'], 'interrupted')

    def test_monitor_honors_preexisting_stop_request_before_login(self):
        with tempfile.TemporaryDirectory() as folder:
            stop = Path(folder) / 'stop'
            stop.touch()
            with patch('sys.argv', ['monitor','--password','sample','--db',str(Path(folder)/'data.db'),'--stop-file',str(stop)]), \
                 patch.object(monitor, 'setup_logging'), patch.object(monitor, 'do_login_selenium') as login:
                self.assertEqual(monitor.main(), 0)
                login.assert_not_called()

if __name__ == '__main__':
    unittest.main()
