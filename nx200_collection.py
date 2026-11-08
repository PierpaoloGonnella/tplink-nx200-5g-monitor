"""Start, inspect and gracefully stop one background collection for this project."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'nx200_collection.local.json'
LOCK = ROOT / 'nx200_collection.local.lock'
STOP = ROOT / 'nx200_collection.local.stop'


class CollectionLock:
    def __init__(self, path=None):
        self.path = Path(LOCK if path is None else path)

    def __enter__(self):
        self.handle = self.path.open('a+b')
        self.handle.seek(0, 2)
        if self.handle.tell() == 0:
            self.handle.write(b'0')
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise RuntimeError('Collection already running') from None
        return self

    def __exit__(self, *args):
        self.handle.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()


def write_state(state):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2), encoding='utf-8')
    for attempt in range(20):
        try:
            temporary.replace(STATE)
            return
        except PermissionError:  # Windows: lettore concorrente in status()
            if attempt == 19:
                raise
            time.sleep(0.05)


def status():
    state = {}
    for _ in range(20):
        try:
            state = json.loads(STATE.read_text(encoding='utf-8'))
            break
        except (FileNotFoundError, json.JSONDecodeError):
            break
        except PermissionError:  # Windows: replace concorrente in write_state()
            time.sleep(0.05)
    try:
        with CollectionLock():
            running = False
    except RuntimeError:
        running = True
    state['running'] = running
    state['stop_requested'] = running and STOP.exists()
    if not running and state.get('state') == 'running':
        state['state'] = 'interrupted'
    db = Path(state.get('db', str(ROOT / 'nx200_prod.db')))
    if db.is_file():
        try:
            with closing(sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True, timeout=1)) as conn:
                state['samples'] = conn.execute('SELECT count(*) FROM samples').fetchone()[0]
                state['last_sample_utc'] = conn.execute('SELECT ts FROM samples ORDER BY id DESC LIMIT 1').fetchone()
                if state['last_sample_utc']:
                    state['last_sample_utc'] = state['last_sample_utc'][0]
                state['poll_errors'] = conn.execute('SELECT count(*) FROM poll_errors').fetchone()[0]
        except sqlite3.Error:
            state['database_readable'] = False
    return state


def worker(args):
    with CollectionLock():
        STOP.unlink(missing_ok=True)
        state = {'state': 'running', 'pid': os.getpid(), 'db': str(Path(args.db).resolve()),
                 'interval': args.interval, 'started_utc': datetime.now(timezone.utc).isoformat()}
        write_state(state)
        code = 1
        try:
            import nx200_monitor_prod as monitor
            sys.argv = ['nx200_monitor_prod.py', '--credentials-file', args.credentials_file,
                        '--db', args.db, '--interval', str(args.interval),
                        '--log', str(ROOT / 'collection.log'), '--stop-file', str(STOP)]
            code = monitor.main()
            return code
        except Exception as error:
            state['error_type'] = type(error).__name__
            return 1
        finally:
            state.update(state='stopped' if code == 0 else 'failed', exit_code=code,
                         stopped_utc=datetime.now(timezone.utc).isoformat())
            write_state(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'status', 'stop', 'worker'])
    parser.add_argument('--credentials-file', default=str(ROOT / 'modem-access.local.json'))
    parser.add_argument('--db', default=str(ROOT / 'nx200_prod.db'))
    parser.add_argument('--interval', type=int, default=60)
    args = parser.parse_args()
    if args.interval < 10:
        parser.error('--interval must be at least 10 seconds')
    if args.action == 'worker':
        return worker(args)
    if args.action == 'start':
        current = status()
        if current['running']:
            print(json.dumps(current, indent=2))
            return 0
        from nx200_credentials import read_credentials
        read_credentials(args.credentials_file)  # Validate locally before detaching.
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), 'worker', '--credentials-file', str(Path(args.credentials_file).resolve()),
             '--db', str(Path(args.db).resolve()), '--interval', str(args.interval)],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            start_new_session=os.name != 'nt', close_fds=True)
        for _ in range(100):
            if process.poll() is not None:
                print(json.dumps(status(), indent=2))
                return 1
            current = status()
            if current['running']:
                print(json.dumps(current, indent=2))
                return 0
            time.sleep(0.1)
        print('Background worker did not acquire its lock within 10 seconds')
        return 1
    if args.action == 'stop' and status()['running']:
        STOP.write_text('stop requested', encoding='utf-8')
        print('Stop requested. The monitor will close its browser and database after the current operation.')
    print(json.dumps(status(), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
