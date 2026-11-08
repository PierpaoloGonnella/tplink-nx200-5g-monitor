"""One authenticated, read-only smoke test; credentials and raw responses stay local."""
import argparse
import json
import re
from pathlib import Path
import nx200_monitor_prod as monitor


from nx200_credentials import read_credentials

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials-file', default='modem-access.local.json')
    parser.add_argument('--db', default='verification/nx200_live.db')
    args = parser.parse_args()
    config = read_credentials(args.credentials_file)
    password = config['password']
    monitor.setup_logging()
    driver = conn = None
    try:
        driver = monitor.do_login_selenium(config['host'], password, config.get('username', 'admin'))
        print('LIVE_LOGIN_OK')
        conn = monitor.init_db(args.db)
        monitor.poll_once(driver, conn)
        row = conn.execute('''select network_type,nr_pci,nr_rsrp,nr_sinr,lte_pci,lte_rsrp,lte_sinr
                              from samples order by id desc limit 1''').fetchone()
        print('LIVE_SAMPLE', dict(zip(('network_type','nr_pci','nr_rsrp','nr_sinr','lte_pci','lte_rsrp','lte_sinr'), row)))
        return 0
    except Exception as error:
        print('LIVE_FAILURE', type(error).__name__, str(error).replace(password, '[redacted]')[:1000])
        if driver:
            print('API_DIAGNOSTICS', driver.execute_script('''return {
                act: typeof window.$?.act, exe: typeof window.$?.exe,
                title: document.title,
                scripts: Array.from(document.scripts).map(s=>s.src.split('?')[0]).filter(Boolean)
            }'''))
        return 1
    finally:
        if driver:
            driver.quit()
        if conn:
            conn.close()


if __name__ == '__main__':
    raise SystemExit(main())
