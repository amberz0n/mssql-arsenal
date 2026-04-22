import socket, threading, json, time, sqlite3, queue
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from core.logger import logger
from core.signals import is_shutdown_requested
from core.database import db

TASK_TIMEOUT = 300
WORKER_TIMEOUT = 60

@dataclass
class WorkerInfo:
    worker_id: str; address: str
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    busy: bool = False; current_task_id: Optional[int] = None

class DistributedMaster:
    def __init__(self, host='0.0.0.0', port=9999, db_path='arsenal.db'):
        self.host, self.port, self.db_path = host, port, db_path
        self.server_socket = None
        self.workers: Dict[str, WorkerInfo] = {}
        self.lock = threading.RLock()
        self.running = False
        self.task_queue = queue.Queue()
        self._init_db(); self._preload_tasks()
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._reaper_thread = threading.Thread(target=self._reaper_loop, daemon=True)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS distributed_tasks
                (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER DEFAULT 1433,
                status TEXT DEFAULT 'pending', worker_id TEXT, assigned_time REAL,
                completed_time REAL, result TEXT, retries INTEGER DEFAULT 0)''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_status ON distributed_tasks (status)')
            conn.commit()

    def _preload_tasks(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT id, ip, port FROM distributed_tasks WHERE status='pending'").fetchall()
            for row in rows:
                self.task_queue.put({'id': row['id'], 'ip': row['ip'], 'port': row['port']})

    def add_tasks(self, ip_list: List[str], port=1433):
        with sqlite3.connect(self.db_path) as conn:
            for ip in ip_list:
                cur = conn.execute("INSERT INTO distributed_tasks (ip,port) VALUES (?,?)", (ip,port))
                self.task_queue.put({'id': cur.lastrowid, 'ip': ip, 'port': port})
            conn.commit()

    def _get_next_task(self):
        try:
            task = self.task_queue.get_nowait()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("UPDATE distributed_tasks SET status='assigned', assigned_time=? WHERE id=?", (time.time(), task['id']))
            return task
        except queue.Empty:
            return None

    def _submit_result(self, task_id, result, worker_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE distributed_tasks SET status=?, completed_time=?, result=?, worker_id=? WHERE id=?",
                         (result.get('status','completed'), time.time(), json.dumps(result), worker_id, task_id))
        if ip := result.get('ip'):
            target = db.get_target(ip) or {}
            target.update(result)
            db.upsert_target(target)

    def _heartbeat_loop(self):
        while self.running and not is_shutdown_requested():
            time.sleep(15)
            with self.lock:
                now = time.time()
                offline = [wid for wid, w in self.workers.items() if now - w.last_seen > WORKER_TIMEOUT]
                for wid in offline:
                    del self.workers[wid]

    def _reaper_loop(self):
        while self.running and not is_shutdown_requested():
            time.sleep(30)
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT id, ip, port, worker_id FROM distributed_tasks WHERE status='assigned' AND assigned_time < ?",
                                    (time.time() - TASK_TIMEOUT,)).fetchall()
                for row in rows:
                    if row['worker_id'] not in self.workers:
                        conn.execute("UPDATE distributed_tasks SET status='pending', worker_id=NULL WHERE id=?", (row['id'],))
                        self.task_queue.put({'id': row['id'], 'ip': row['ip'], 'port': row['port']})
                conn.commit()

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.running = True
        self._heartbeat_thread.start()
        self._reaper_thread.start()
        logger.info(f"主节点启动 {self.host}:{self.port}")
        while self.running and not is_shutdown_requested():
            try:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_worker, args=(client, addr), daemon=True).start()
            except:
                pass

    def _handle_worker(self, client, addr):
        wid = f"{addr[0]}:{addr[1]}"
        with self.lock: self.workers[wid] = WorkerInfo(wid, addr[0])
        try:
            client.settimeout(5)
            while self.running:
                data = client.recv(4096).decode().strip()
                if not data: break
                if data == 'GET_TASK':
                    task = self._get_next_task()
                    if task:
                        client.send(json.dumps(task).encode()+b'\n')
                        with self.lock:
                            if wid in self.workers:
                                self.workers[wid].busy = True
                                self.workers[wid].current_task_id = task['id']
                    else:
                        client.send(b'WAIT\n')
                elif data.startswith('RESULT:'):
                    payload = json.loads(data[7:])
                    self._submit_result(payload['task_id'], payload['result'], wid)
                    client.send(b'ACK\n')
                    with self.lock:
                        if wid in self.workers:
                            self.workers[wid].busy = False
                elif data == 'PONG':
                    with self.lock:
                        if wid in self.workers:
                            self.workers[wid].last_seen = time.time()
        except: pass
        finally:
            client.close()
            with self.lock: self.workers.pop(wid, None)

    def stop(self):
        self.running = False
        if self.server_socket: self.server_socket.close()