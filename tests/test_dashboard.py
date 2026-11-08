from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from nx200_dashboard_data import load_snapshot
from streamlit.testing.v1 import AppTest
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'samples.db'
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('''CREATE TABLE samples(id INTEGER PRIMARY KEY,ts TEXT,network_type TEXT,
                nr_pci INTEGER, nr_rsrp REAL, ss_rsrp REAL,nr_sinr REAL,ss_sinr REAL,
                lte_pci INTEGER,lte_rsrp REAL,lte_snr REAL)''')
            conn.commit()
        st.cache_data.clear()

    def insert(self, rsrp=-85, sinr=0, age=0):
        when = (datetime.now(timezone.utc) - timedelta(hours=age)).isoformat()
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('''INSERT INTO samples(ts,network_type,nr_pci,ss_rsrp,ss_sinr,lte_pci,lte_rsrp,lte_snr)
                VALUES (?,?,?,?,?,?,?,?)''', (when,'5G',0,rsrp,sinr,1,-95,12.5))
            conn.commit()

    def app(self):
        with patch.dict(os.environ, {'NX200_DASHBOARD_DB': str(self.db)}):
            return AppTest.from_file(str(ROOT / 'nx200_dashboard.py'), default_timeout=15).run()

    def test_missing_database_is_not_created(self):
        missing = Path(self.tmp.name) / 'missing.db'
        with self.assertRaises(FileNotFoundError):
            load_snapshot(missing)
        self.assertFalse(missing.exists())

    def test_snapshot_aliases_zero_and_read_only(self):
        self.insert()
        before = self.db.read_bytes()
        snapshot = load_snapshot(self.db)
        row = snapshot['samples'].iloc[0]
        self.assertEqual(row['nr_rsrp'], -85)
        self.assertEqual(row['nr_sinr'], 0)
        self.assertEqual(row['lte_sinr'], 12.5)
        self.assertEqual(self.db.read_bytes(), before)

    def test_period_filter_excludes_old_and_empty_records(self):
        self.insert(age=48)
        self.insert()
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('INSERT INTO samples(ts) VALUES (?)',(datetime.now(timezone.utc).isoformat(),))
            conn.commit()
        data = load_snapshot(self.db, hours=1)
        self.assertEqual(len(data['samples']),1)
        self.assertEqual(data['excluded'],1)
        self.assertEqual(len(load_snapshot(self.db)['samples']),2)

    def test_dashboard_renders_and_reads_new_commits(self):
        self.insert()
        app = self.app()
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[0].value, '-85.0 dBm')
        self.assertEqual(app.metric[1].value, '0.0 dB')
        self.assertTrue(app.success)
        self.insert(rsrp=-90)
        st.cache_data.clear()
        app.run()
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[0].value, '-90.0 dBm')

    def test_stale_samples_are_not_reported_as_live(self):
        self.insert(age=48)
        app = self.app()
        self.assertFalse(app.exception)
        self.assertFalse(app.success)
        self.assertTrue(any('Dati non aggiornati' in item.value for item in app.warning))

    def test_dashboard_displays_relative_degradation_alert(self):
        for minute in range(31):
            self.insert(rsrp=-94 if minute <= 10 else -85, age=minute / 60)
        app = self.app()
        self.assertFalse(app.exception)
        self.assertTrue(any('Calo rilevato su 5G RSRP' in item.value for item in app.warning))

    def test_empty_database_and_missing_path_render_without_crash(self):
        app = self.app()
        self.assertFalse(app.exception)
        self.assertTrue(app.warning)
        app.text_input[0].set_value(str(Path(self.tmp.name) / 'missing.db')).run()
        self.assertFalse(app.exception)
        self.assertTrue(app.info)

if __name__ == '__main__':
    unittest.main()
