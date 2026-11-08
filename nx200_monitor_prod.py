"""Monitor NX200 via browser e API cifrate native del firmware."""
import argparse
import getpass
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from nx200_monitor_v4 import Collector, SERVING_CELL_FIELDS, SERVING_CELL_OID
from nx200_credentials import read_credentials
from nx200_radio_fields import LINK_COLUMNS, extract_link_adaptation

log = logging.getLogger(__name__)

def setup_logging(log_file=None):
    handlers = [logging.StreamHandler()]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3, encoding='utf-8'))
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', handlers=handlers, force=True)

def init_db(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('''CREATE TABLE IF NOT EXISTS samples (
        id INTEGER PRIMARY KEY, ts TEXT, network_type TEXT,
        nr_pci INTEGER, nr_rsrp REAL, nr_sinr REAL,
        lte_pci INTEGER, lte_rsrp REAL, lte_sinr REAL, raw_response TEXT)''')
    existing = {row[1] for row in conn.execute("PRAGMA table_info(samples)")}
    required = {"network_type": "TEXT", "nr_pci": "INTEGER", "nr_rsrp": "REAL",
                "nr_sinr": "REAL", "lte_pci": "INTEGER", "lte_rsrp": "REAL",
                "lte_sinr": "REAL", "raw_response": "TEXT"}
    required.update(LINK_COLUMNS)
    for column, kind in required.items():
        if column not in existing:
            conn.execute(f'ALTER TABLE samples ADD COLUMN "{column}" {kind}')
    conn.execute('''CREATE TABLE IF NOT EXISTS poll_errors (
        id INTEGER PRIMARY KEY, ts TEXT NOT NULL, message TEXT NOT NULL)''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_samples_time ON samples(julianday(ts),id)')
    conn.commit()
    return conn

def dashboard_ready(driver):
    return any(e.is_displayed() for e in driver.find_elements(By.CSS_SELECTOR, '#main, .navi-side'))

def do_login_selenium(host, password, username='admin'):
    host = host.strip()
    if '://' not in host:
        host = 'https://' + host
    parsed = urlsplit(host)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Host must be an HTTP(S) modem address')
    opts = Options()
    opts.add_argument('--headless=new')
    opts.set_capability('acceptInsecureCerts', True)
    driver = webdriver.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(60)
        driver.set_script_timeout(15)
        driver.get(host)
        wait = WebDriverWait(driver, 20)
        wait.until(lambda d: dashboard_ready(d) or any(e.is_displayed() for e in d.find_elements(By.CSS_SELECTOR, "input[type='password']")))
        if not dashboard_ready(driver):
            for element in driver.find_elements(By.CSS_SELECTOR, "input[type='text']"):
                if element.is_displayed() and element.is_enabled():
                    element.clear()
                    element.send_keys(username)
                    break
            pwd = next(e for e in driver.find_elements(By.CSS_SELECTOR, "input[type='password']") if e.is_displayed())
            pwd.send_keys(password)
            wait.until(EC.element_to_be_clickable((By.ID, 'pc-login-btn'))).click()
            def logged_in(d):
                for button in d.find_elements(By.ID, 'confirm-yes'):
                    if button.is_displayed():
                        button.click()
                return dashboard_ready(d)
            wait.until(logged_in)
        log.info('Dashboard authenticated')
        return driver
    except Exception:
        try:
            driver.quit()
        except Exception:
            log.warning("Browser cleanup failed after login error")
        raise

def query_data_via_browser(driver, oid, fields):
    # This firmware uses the JSON dm proxy, not the legacy $.act/$.exe protocol.
    # Request full serving-cell records just as the dashboard does. The native
    # proxy restores the encryptor and supplies TokenID and /cgi_gdpr?9.
    result = driver.execute_async_script("""
        const oid = arguments[0], done = arguments[1];
        let finished = false, request = null;
        const finish = result => { if (!finished) { finished = true; clearTimeout(timer); done(result); } };
        const timer = setTimeout(() => {
            finish({status: 'error', error: 'API timeout'});
            if (request && typeof request.abort === 'function') request.abort();
        }, 10000);
        try {
            if (!window.$ || !$.dm || typeof $.dm.getList !== 'function') {
                finish({status: 'error', error: 'Firmware JSON API bridge unavailable'}); return;
            }
            request = $.dm.getList({oid: oid, data: {}, callback: {
                success: data => finish({status: 'ok', data: data}),
                fail: code => finish({status: 'error', error: 'Firmware API rejected request: ' + code}),
                error: status => finish({status: 'error', error: 'Firmware transport error: ' + status})
            }});
        } catch (e) { finish({status: 'error', error: String(e)}); }
    """, oid)
    if not isinstance(result, dict) or result.get('status') != 'ok':
        raise RuntimeError(result.get('error', 'Invalid API response') if isinstance(result, dict) else 'Invalid API response')
    data = result.get('data')
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data or not all(isinstance(row, dict) for row in data):
        raise RuntimeError('Serving cell response is empty or invalid')
    return data

def poll_once(driver, conn):
    cells = query_data_via_browser(driver, SERVING_CELL_OID, SERVING_CELL_FIELDS)
    sample = {'raw': {}}
    Collector._normalize(sample, cells)
    metrics = [sample.get(k) for k in ('ss_rsrp', 'ss_sinr', 'lte_rsrp', 'lte_snr')]
    if all(value is None for value in metrics):
        raise RuntimeError('Response contains no usable radio metrics')
    network = '5G' if sample.get('ss_rsrp') is not None or sample.get('ss_sinr') is not None else 'LTE'
    values = dict(zip(('ts', 'network_type', 'nr_pci', 'nr_rsrp', 'nr_sinr',
                       'lte_pci', 'lte_rsrp', 'lte_sinr', 'raw_response'), (
        datetime.now(timezone.utc).isoformat(timespec='seconds'), network,
        sample.get('nr_pci'), metrics[0], metrics[1], sample.get('lte_pci'),
        metrics[2], metrics[3], json.dumps(cells))))
    values.update(extract_link_adaptation(cells))
    with conn:
        conn.execute(f"INSERT INTO samples ({','.join(values)}) VALUES ({','.join('?' for _ in values)})",
                     list(values.values()))
    log.info('Radio sample saved (%s)', network)

def wait_for_poll(seconds, stop_file=None):
    if not stop_file:
        time.sleep(seconds)
        return
    deadline = time.monotonic() + seconds
    while not Path(stop_file).exists():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='https://192.168.1.1')
    parser.add_argument('--password', help='Prefer NX200_PASSWORD or the interactive prompt')
    parser.add_argument('--credentials-file', help='Local file with host, username and password')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--db', default='nx200_prod.db')
    parser.add_argument('--log')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval', type=int, default=60)
    parser.add_argument('--stop-file', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.interval < 10:
        parser.error('--interval must be at least 10 seconds')
    credentials = read_credentials(args.credentials_file) if args.credentials_file else {}
    if credentials:
        args.host = credentials['host']
        args.username = credentials.get('username', args.username)
    password = args.password or credentials.get('password') or os.environ.get('NX200_PASSWORD') or getpass.getpass('Modem password: ')
    setup_logging(args.log)
    conn = driver = None
    try:
        conn = init_db(args.db)
        while not (args.stop_file and Path(args.stop_file).exists()):
            started = time.monotonic()
            try:
                if driver is None:
                    driver = do_login_selenium(args.host, password, args.username)
                poll_once(driver, conn)
            except Exception as error:
                log.error('Poll failed (%s): %s', type(error).__name__, str(error).replace(password, '[redacted]'))
                with conn:
                    conn.execute('INSERT INTO poll_errors(ts,message) VALUES (?,?)', (
                        datetime.now(timezone.utc).isoformat(timespec='seconds'), str(error).replace(password, '[redacted]')))
                if driver is not None:
                    try:
                        driver.quit()
                    except Exception:
                        log.warning("Browser cleanup failed")
                    finally:
                        driver = None
                if args.once:
                    return 1
            if args.once:
                return 0
            wait_for_poll(max(0, args.interval - (time.monotonic() - started)), args.stop_file)
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                log.warning('Browser cleanup failed')
        if conn is not None:
            conn.close()

if __name__ == '__main__':
    raise SystemExit(main())
