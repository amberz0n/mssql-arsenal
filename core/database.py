import sqlite3
import threading
import time
import json
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from .logger import logger

class DBWriter:
    def __init__(self, db_path: str = 'arsenal.db', batch_size: int = 500):
        self.db_path = db_path
        self.batch_size = batch_size
        self._queue = []
        self._condition = threading.Condition()
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._worker, daemon=True)
        self._worker_thread.start()
        self._init_db()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    ip TEXT PRIMARY KEY, port INTEGER, status TEXT, open_time REAL,
                    username TEXT, password TEXT, version TEXT, os_type TEXT,
                    is_xp_cmdshell INTEGER, env_checked INTEGER, last_error TEXT,
                    attempts INTEGER, honeypot_score REAL, honeypot_reasons TEXT,
                    cve_list TEXT, service_banner TEXT, updated_at REAL
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT, password TEXT, target_ip TEXT,
                    success INTEGER, attempt_time REAL, error_msg TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT, action TEXT, command TEXT,
                    success INTEGER, output TEXT, exec_time REAL
                )
            ''')
            conn.commit()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _worker(self):
        while not self._stop_event.is_set():
            with self._condition:
                while not self._queue and not self._stop_event.is_set():
                    self._condition.wait(timeout=1)
                if self._stop_event.is_set():
                    break
                batch = self._queue[:self.batch_size]
                self._queue = self._queue[self.batch_size:]
            if batch:
                self._flush_batch(batch)

    def _flush_batch(self, batch: List[tuple]):
        for func, args, kwargs in batch:
            conn = None
            for attempt in range(2):
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5.0)
                    func(conn, *args, **kwargs)
                    conn.commit()
                    break
                except Exception as e:
                    logger.error(f"数据库写入失败（尝试 {attempt+1}/2）: {e}")
                    if attempt == 0:
                        time.sleep(0.2)
                finally:
                    if conn:
                        conn.close()

    def _enqueue(self, func, *args, **kwargs):
        with self._condition:
            self._queue.append((func, args, kwargs))
            self._condition.notify()

    def _upsert_target(self, conn, target_data: Dict[str, Any]):
        conn.execute('''
            INSERT OR REPLACE INTO targets 
            (ip, port, status, open_time, username, password, version, os_type,
             is_xp_cmdshell, env_checked, last_error, attempts,
             honeypot_score, honeypot_reasons, cve_list, service_banner, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            target_data['ip'], target_data.get('port', 1433), target_data.get('status', 'pending'),
            target_data.get('open_time'), target_data.get('username'), target_data.get('password'),
            target_data.get('version'), target_data.get('os_type'),
            1 if target_data.get('is_xp_cmdshell') else 0,
            1 if target_data.get('env_checked') else 0,
            target_data.get('last_error'), target_data.get('attempts', 0),
            target_data.get('honeypot_score', 0.0),
            json.dumps(target_data.get('honeypot_reasons', [])),
            json.dumps(target_data.get('cve_list', [])),
            target_data.get('service_banner', ''),
            time.time()
        ))

    def upsert_target(self, target_data: Dict[str, Any]):
        self._enqueue(self._upsert_target, target_data)

    def log_attempt(self, username: str, password: str, target_ip: str, success: bool, error_msg: str = ''):
        def _log(conn):
            conn.execute('''
                INSERT INTO attempts (username, password, target_ip, success, attempt_time, error_msg)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password, target_ip, 1 if success else 0, time.time(), error_msg))
        self._enqueue(_log)

    def log_exploit(self, target_ip: str, action: str, command: str, success: bool, output: str = ''):
        def _log(conn):
            conn.execute('''
                INSERT INTO exploits (target_ip, action, command, success, output, exec_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (target_ip, action, command, 1 if success else 0, output[:500], time.time()))
        self._enqueue(_log)

    def get_target(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute('SELECT * FROM targets WHERE ip = ?', (ip,)).fetchone()
            if row:
                return dict(row)
        return None

    def get_targets_by_status(self, status: str) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute('SELECT * FROM targets WHERE status = ?', (status,)).fetchall()
            return [dict(r) for r in rows]

    def shutdown(self):
        self._stop_event.set()
        with self._condition:
            self._condition.notify()
        self._worker_thread.join(timeout=3)

db = DBWriter()