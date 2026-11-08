from contextlib import closing
from pathlib import Path
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch
import nx200_monitor_prod as monitor
from nx200_dashboard_data import load_snapshot
from nx200_radio_fields import extract_link_adaptation
from nx200_modulation import modulation_timeline, modulation_order
import pandas as pd
from streamlit.testing.v1 import AppTest
import streamlit as st

CELLS = [
 {'networkType':'8','cellConnectionStatus':'1','PCI':'559','SSRSRP':'-110','SSSINR':'85',
  'downMCS':'0','upMCS':'10','downlinkModType':'64QAM','uplinkModType':'16QAM'},
 {'networkType':'3','cellConnectionStatus':'1','PCI':'55','RSRP':'-108','SNR':'-50',
  'downMCS':'11','upMCS':'19','downlinkModType':'QPSK','uplinkModType':'16QAM'},
 {'networkType':'8','cellConnectionStatus':'2','downMCS':'31','downlinkModType':'256QAM'},
]

class MCSTests(unittest.TestCase):
    def test_active_cells_and_zero_index(self):
        result = extract_link_adaptation(CELLS)
        self.assertEqual(result['nr_dl_mcs'], 0)
        self.assertEqual(result['nr_dl_mod'], '64QAM')
        self.assertEqual(result['lte_ul_mcs'], 19)
        self.assertEqual(result['lte_dl_mod'], 'QPSK')

    def test_invalid_and_unavailable_values_remain_missing(self):
        for value in ['--', '', '-1', 'nan', 'inf', '1.2', None]:
            cells = [{'networkType':'8','cellConnectionStatus':'1','downMCS':value,'downlinkModType':'--'}]
            self.assertIsNone(extract_link_adaptation(cells)['nr_dl_mcs'])
            self.assertIsNone(extract_link_adaptation(cells)['nr_dl_mod'])
        self.assertEqual(extract_link_adaptation('ERROR_406'), {})

    def test_store_and_recover_historical_raw_without_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'data.db'
            conn = monitor.init_db(path)
            try:
                driver = Mock()
                driver.execute_async_script.return_value = {'status':'ok','data':CELLS}
                monitor.poll_once(driver,conn)
                row = conn.execute('select nr_dl_mcs,nr_dl_mod,lte_ul_mcs from samples').fetchone()
                self.assertEqual(row,(0,'64QAM',19))
                # Simulate a row collected by the old monitor before flat MCS fields existed.
                conn.execute('update samples set nr_dl_mcs=NULL,nr_dl_mod=NULL,lte_ul_mcs=NULL')
                conn.commit()
                frame = load_snapshot(path)['samples']
                self.assertEqual(frame.iloc[0]['nr_dl_mcs'],0)
                self.assertEqual(frame.iloc[0]['nr_dl_mod'],'64QAM')
                self.assertNotIn('_raw_link',frame)
                self.assertIsNone(conn.execute('select nr_dl_mcs from samples').fetchone()[0])
            finally:
                conn.close()

    def test_dashboard_displays_and_charts_mcs(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'data.db'
            conn = monitor.init_db(path)
            try:
                driver = Mock()
                driver.execute_async_script.return_value = {'status':'ok','data':CELLS}
                monitor.poll_once(driver,conn)
            finally:
                conn.close()
            st.cache_data.clear()
            with patch.dict(os.environ,{'NX200_DASHBOARD_DB':str(path)}):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1]/'nx200_dashboard.py'),default_timeout=15).run()
            self.assertFalse(app.exception)
            links = [table.value for table in app.dataframe if 'Modulazione download' in table.value.columns][0]
            self.assertEqual(links.iloc[0]['MCS download'],'0')
            self.assertEqual(links.iloc[0]['Modulazione download'],'64QAM')
            titles = [item.value for item in app.subheader]
            for title in ('5G · modulazione download', '5G · modulazione upload',
                          'LTE · modulazione download', 'LTE · modulazione upload'):
                self.assertIn(title, titles)
            app.toggle(key='mcs_history').set_value(True).run()
            self.assertFalse(app.exception)
            # New commits must reach the charts through the normal dashboard refresh.
            conn = monitor.init_db(path)
            try:
                new_cells = [dict(cell) for cell in CELLS]
                new_cells[0]['downlinkModType'] = '256QAM'
                driver.execute_async_script.return_value = {'status':'ok','data':new_cells}
                monitor.poll_once(driver,conn)
            finally:
                conn.close()
            st.cache_data.clear()
            app.run()
            self.assertFalse(app.exception)
            links = [table.value for table in app.dataframe if 'Modulazione download' in table.value.columns][0]
            self.assertEqual(links.iloc[0]['Modulazione download'], '256QAM')

    def test_modulation_timeline_breaks_at_missing_samples_gaps_and_cell_changes(self):
        frame = pd.DataFrame({
            'ts': pd.to_datetime(['2026-10-25T12:00Z','2026-10-25T12:01Z','2026-10-25T12:02Z',
                                  '2026-10-25T12:03Z','2026-10-25T12:10Z','2026-10-25T12:11Z']),
            'nr_dl_mod': ['QPSK','16QAM',None,'64QAM','64QAM','256QAM'],
            'nr_pci': [0,0,0,0,0,1],
        })
        data = modulation_timeline(frame, 'nr_dl_mod', 'nr_pci')
        self.assertEqual(data['Modulazione'].tolist(), ['QPSK','16QAM','64QAM','64QAM','256QAM'])
        segments = data['Segmento'].tolist()
        self.assertEqual(segments[0], segments[1])
        self.assertNotEqual(segments[1], segments[2])
        self.assertNotEqual(segments[2], segments[3])
        self.assertNotEqual(segments[3], segments[4])
        self.assertIn('CET', data['Ora locale'].iloc[0])

    def test_modulation_order_preserves_unfamiliar_firmware_labels(self):
        frame = pd.DataFrame({'nr_dl_mod':['64QAM','QPSK'], 'nr_ul_mod':['16QAM',None],
                              'lte_dl_mod':['CUSTOM-QAM','--'], 'lte_ul_mod':['','QPSK']})
        self.assertEqual(modulation_order(frame), ['64QAM','16QAM','QPSK','CUSTOM-QAM'])

    def test_missing_modulation_has_no_invented_points(self):
        frame = pd.DataFrame({'ts':pd.to_datetime(['2026-10-25T12:00Z','2026-10-25T12:01Z']),
                              'nr_dl_mod':[None,'--'], 'nr_pci':[0,0]})
        self.assertTrue(modulation_timeline(frame,'nr_dl_mod','nr_pci').empty)

if __name__ == '__main__':
    unittest.main()
