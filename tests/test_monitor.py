import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
import shutil
import subprocess
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import nx200_monitor as original
import nx200_monitor_prod as prod
import nx200_monitor_v4 as v4
import nx200_view_data as viewer
from selenium.common.exceptions import TimeoutException

CELLS = [
    {'networkType': '8', 'cellConnectionStatus': '1', 'PCI': '0',
     'SSRSRP': '-85', 'SSSINR': '0', 'band': '78', 'CQI': '0'},
    {'networkType': '3', 'cellConnectionStatus': '1', 'PCI': '12',
     'RSRP': '-95', 'SNR': '125', 'band': '3'},
]

class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'data' / 'samples.db'

    def connection(self):
        conn = prod.init_db(str(self.db))
        self.addCleanup(conn.close)
        return conn

    def test_save_both_radios_and_zero_values(self):
        conn = self.connection()
        driver = Mock()
        driver.execute_async_script.return_value = {'status': 'ok', 'data': CELLS}
        prod.poll_once(driver, conn)
        row = conn.execute('select network_type,nr_pci,nr_rsrp,nr_sinr,lte_rsrp,lte_sinr,raw_response from samples').fetchone()
        self.assertEqual(row[:6], ('5G', 0, -85, 0, -95, 12.5))
        self.assertEqual(json.loads(row[6]), CELLS)

    def test_failed_and_empty_queries_never_save_samples(self):
        conn = self.connection()
        for response in [{'status': 'error', 'error': 'HTTP 406'}, 'ERROR_406',
                         {'status': 'ok', 'data': []}, {'status': 'ok', 'data': [{}]},
                         {'status': 'ok', 'data': 'ERROR_406'}]:
            with self.subTest(response=response):
                driver = Mock()
                driver.execute_async_script.return_value = response
                with self.assertRaises(RuntimeError):
                    prod.poll_once(driver, conn)
        self.assertEqual(conn.execute('select count(*) from samples').fetchone()[0], 0)

    def run_main(self, once=True, failures=None):
        driver = Mock()
        driver.execute_async_script.return_value = {'status': 'ok', 'data': CELLS}
        argv = ['monitor', '--password', 'test-secret', '--db', str(self.db)]
        if once:
            argv.append('--once')
        with patch('sys.argv', argv), patch.object(prod, 'setup_logging'), \
             patch.object(prod, 'do_login_selenium', return_value=driver), \
             patch.object(prod.time, 'sleep', side_effect=KeyboardInterrupt) as sleep:
            if failures:
                driver.execute_async_script.side_effect = failures
            result = prod.main()
        return result, driver, sleep

    def test_once_success_exit_and_cleanup(self):
        code, driver, sleep = self.run_main()
        self.assertEqual(code, 0)
        driver.quit.assert_called_once()
        sleep.assert_not_called()
        with contextlib.closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('select count(*) from samples').fetchone()[0], 1)

    def test_once_failure_records_error_and_nonzero_exit(self):
        code, driver, _ = self.run_main(failures=[{'status': 'error', 'error': 'HTTP 406 test-secret'}])
        self.assertEqual(code, 1)
        driver.quit.assert_called_once()
        with contextlib.closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('select count(*) from samples').fetchone()[0], 0)
            message = conn.execute('select message from poll_errors').fetchone()[0]
            self.assertIn('406', message)
            self.assertNotIn('test-secret', message)

    def test_continuous_mode_polls_and_waits(self):
        code, driver, sleep = self.run_main(once=False)
        self.assertEqual(code, 0)
        sleep.assert_called_once()
        self.assertGreater(sleep.call_args.args[0], 0)
        driver.execute_async_script.assert_called_once()

    def test_continuous_mode_retries_after_failure(self):
        driver = Mock()
        driver.execute_async_script.return_value = {'status': 'error', 'error': 'HTTP 406'}
        with patch('sys.argv', ['monitor', '--password', 'secret', '--db', str(self.db)]), \
             patch.object(prod, 'setup_logging'), \
             patch.object(prod, 'do_login_selenium', return_value=driver) as login, \
             patch.object(prod.time, 'sleep', side_effect=[None, KeyboardInterrupt]):
            self.assertEqual(prod.main(), 0)
        self.assertEqual(login.call_count, 2)
        with contextlib.closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('select count(*) from poll_errors').fetchone()[0], 2)

    def test_invalid_interval_rejected_before_login(self):
        with patch('sys.argv', ['monitor', '--interval', '0']), patch.object(prod, 'do_login_selenium') as login:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                prod.main()
        self.assertEqual(error.exception.code, 2)
        login.assert_not_called()

    def test_login_timeout_closes_browser_and_raises(self):
        driver = Mock()
        with patch.object(prod.webdriver, 'Chrome', return_value=driver), \
             patch.object(prod, 'WebDriverWait') as wait:
            wait.return_value.until.side_effect = TimeoutException('no dashboard')
            with self.assertRaises(TimeoutException):
                prod.do_login_selenium('https://example.invalid', 'secret')
        driver.quit.assert_called_once()

    def test_navigation_failure_closes_browser(self):
        driver = Mock()
        driver.get.side_effect = RuntimeError('navigation failed')
        with patch.object(prod.webdriver, 'Chrome', return_value=driver):
            with self.assertRaises(RuntimeError):
                prod.do_login_selenium('https://example.invalid', 'secret')
        driver.quit.assert_called_once()

    def test_host_without_scheme_defaults_to_https(self):
        driver = Mock()
        driver.find_elements.return_value = [Mock()]
        with patch.object(prod.webdriver, 'Chrome', return_value=driver), patch.object(prod, 'WebDriverWait'):
            self.assertIs(prod.do_login_selenium('192.168.1.1', 'secret'), driver)
        driver.get.assert_called_once_with('https://192.168.1.1')

    def test_local_credentials_formats(self):
        from verify_modem import read_credentials
        path = Path(self.tmp.name) / 'credentials.local.json'
        for text in ('{"host":"192.168.1.1","username":"admin","password":"sample"}',
                     'host: {192.168.1.1}\nusername: {admin}\npassword: {sample}'):
            path.write_text(text, encoding='utf-8')
            self.assertEqual(read_credentials(path)['password'], 'sample')

    def test_existing_database_migration_preserves_history(self):
        self.db.parent.mkdir()
        with contextlib.closing(sqlite3.connect(self.db)) as conn:
            conn.execute('create table samples(id integer primary key, ts text, nr_pci integer)')
            conn.execute("insert into samples(ts,nr_pci) values('old',123)")
            conn.commit()
        for _ in range(2):
            store = v4.Store(self.db)
            try:
                self.assertEqual(store.conn.execute('select nr_pci from samples where id=1').fetchone()[0], 123)
                store.insert_sample({'ts': 'new', 'nr_dl_bw_mhz': 100})
            finally:
                store.close()
        with contextlib.closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('select count(*) from samples').fetchone()[0], 3)

    def test_time_windows_exclude_expired_samples(self):
        for module in [original, v4]:
            with self.subTest(module=module.__name__):
                store = module.Store(Path(self.tmp.name) / (module.__name__ + '.db'))
                try:
                    now = datetime.now(timezone.utc)
                    store.insert_sample({'ts': (now - timedelta(minutes=90)).isoformat(), 'nr_pci': 1, 'ss_rsrp': -40})
                    store.insert_sample({'ts': now.isoformat(), 'nr_pci': 1, 'ss_rsrp': -80})
                    if module is original:
                        result = store.baseline_for_pci(1, 'ss_rsrp', since_minutes=60)
                        self.assertEqual(store.recent_cell_changes(minutes=60), 0)
                    else:
                        result = store.baseline_for_pci(1, 'ss_rsrp', since_min=60)
                    self.assertEqual(result, (-80, 0, 1))
                finally:
                    store.close()

    def test_zero_sinr_and_cqi_remain_primary(self):
        detector = v4.AnomalyDetector(Mock(), v4.Thresholds())
        findings = detector.evaluate({'ss_rsrp': -80, 'ss_sinr': 0, 'lte_snr': 20, 'nr_cqi': 0, 'lte_cqi': 15}, 1)
        self.assertIn('interference_or_congestion', [f[1] for f in findings])
        self.assertIn('channel_degraded', [f[1] for f in findings])

    def test_viewer_displays_zero_metrics(self):
        conn = self.connection()
        conn.execute("insert into samples(ts,nr_pci,nr_sinr) values('2026-10-25T00:00:00+00:00',0,0)")
        conn.commit()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            viewer.view_database(str(self.db))
        self.assertIn('0.0', output.getvalue())

    def test_viewer_cli_works_with_windows_output_encoding(self):
        conn = self.connection()
        conn.execute("insert into samples(ts,nr_pci,nr_rsrp,nr_sinr) values('2026-10-25T00:00:00+00:00',0,-85,0)")
        conn.commit()
        for args in ([], ['--stats'], ['--csv', '--csv-file', str(Path(self.tmp.name) / 'export.csv')]):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, 'nx200_view_data.py', '--db', str(self.db)] + args,
                                        env={**os.environ, 'PYTHONIOENCODING': 'cp1252'},
                                        capture_output=True, check=False, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode('cp1252'))

    def test_html_module_imports_and_uses_shared_login(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments'))
        import nx200_monitor_html as html
        self.assertIs(html.do_login_selenium, prod.do_login_selenium)

    def test_original_database_copies_remain_writable_after_migration(self):
        for filename in ('local/nx200_monitor.db', 'nx200_prod.db'):
            source_path = Path(filename).resolve()
            if not source_path.exists():
                continue
            for module in (original, v4, prod):
                with self.subTest(source=filename, module=module.__name__):
                    target = Path(self.tmp.name) / (module.__name__ + Path(filename).name)
                    with contextlib.closing(sqlite3.connect(source_path.as_uri() + '?mode=ro', uri=True)) as source:
                        with contextlib.closing(sqlite3.connect(target)) as destination:
                            source.backup(destination)
                            count = destination.execute('select count(*) from samples').fetchone()[0]
                    if module is prod:
                        conn = prod.init_db(str(target))
                        store = None
                    else:
                        store = module.Store(target)
                        conn = store.conn
                    try:
                        if store:
                            store.insert_sample({'ts': datetime.now(timezone.utc).isoformat(), 'ss_rsrp': -80})
                        else:
                            driver = Mock()
                            driver.execute_async_script.return_value = {'status': 'ok', 'data': CELLS}
                            prod.poll_once(driver, conn)
                        self.assertEqual(conn.execute('select count(*) from samples').fetchone()[0], count + 1)
                    finally:
                        conn.close()

    def test_protocol_errors_are_rejected(self):
        for response in ('[error]406', '[error]0\n$.ret=7', '{"success":false,"errorcode":71011}'):
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                v4.DataModel._parse(response, True)

    def test_raw_transport_http_error_is_not_empty_success(self):
        client = v4.TPLinkGdprClient('https://example.invalid', 'secret')
        client.aes_key = client.aes_iv = b'0' * 16
        client.http = Mock()
        client.http.post.return_value = (406, {}, b'rejected')
        with patch.object(v4, '_rsa_encrypt', return_value='signature'):
            with self.assertRaisesRegex(RuntimeError, 'HTTP 406'):
                client.request_data('read-only request')

    def test_failed_poll_survives_browser_cleanup_failure(self):
        driver = Mock()
        driver.execute_async_script.return_value = {'status': 'error', 'error': 'HTTP 406'}
        driver.quit.side_effect = RuntimeError('driver gone')
        with patch('sys.argv', ['monitor', '--password', 'secret', '--db', str(self.db), '--once']), \
             patch.object(prod, 'setup_logging'), patch.object(prod, 'do_login_selenium', return_value=driver):
            self.assertEqual(prod.main(), 1)

    @unittest.skipUnless(shutil.which('node'), 'Node.js unavailable for JavaScript bridge test')
    def test_javascript_bridge_success_error_unavailable_and_timeout(self):
        driver = Mock()
        driver.execute_async_script.return_value = {'status': 'ok', 'data': CELLS}
        prod.query_data_via_browser(driver, 'OID', ['PCI'])
        script = driver.execute_async_script.call_args.args[0]
        setups = {
            'success': "global.$ = {dm: {getList: settings => {settings.callback.success(cells);return {abort:()=>{}};}}};",
            'error': "global.$ = {dm: {getList: settings => settings.callback.fail(406)}};",
            'unavailable': 'delete global.$;',
            'timeout': "global.$ = {dm: {getList: settings => ({abort:()=>{}})}}; const realTimer = setTimeout; global.setTimeout = cb => realTimer(cb, 1);",
        }
        for name, setup in setups.items():
            with self.subTest(case=name):
                program = ('global.window = global; const cells = ' + json.dumps(CELLS) + ';' + setup
                           + '\nnew Function(' + json.dumps(script) + ")(\"OID\", result => console.log(JSON.stringify(result)));")
                result = subprocess.run(['node', '-e', program], capture_output=True, text=True, check=True, timeout=5)
                response = json.loads(result.stdout)
                self.assertEqual(response['status'], 'ok' if name == 'success' else 'error')
                if name == 'success':
                    self.assertEqual(response['data'], CELLS)

if __name__ == '__main__':
    unittest.main()
