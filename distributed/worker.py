import socket, json, time, threading, asyncio
from typing import Optional, List
from core.logger import logger
from core.signals import is_shutdown_requested
from scanner.port_scanner import AsyncPortScanner
from scanner.banner import TDSBannerGrabber
from bruter.bruter import MSSQLBruter
from cve.checker import CVEChecker
from honeypot.detector import HoneypotDetector

class DistributedWorker:
    def __init__(self, master_host: str, master_port=9999, users=None, passwords=None):
        self.master_host, self.master_port = master_host, master_port
        self.users = users or ['sa']
        self.passwords = passwords or ['']
        self.running = False
        self.loop = None
        self.scanner = AsyncPortScanner(concurrency=200)
        self.banner_grabber = TDSBannerGrabber()
        self.bruter = MSSQLBruter()
        self.cve_checker = CVEChecker()
        self.honeypot = HoneypotDetector()

    def _scan_single(self, task: dict) -> dict:
        ip, port = task['ip'], task.get('port', 1433)
        res = {'ip': ip, 'port': port, 'status': 'closed'}
        open_ports = self.scanner.scan_sync([ip], [port])
        if not open_ports: return res
        res['status'] = 'open'
        banner = self.banner_grabber.grab_sync(ip, port)
        res['version'] = banner.version
        cracked = self.bruter.brute([ip], [port], self.users, self.passwords)
        if cracked:
            cred = cracked[0]
            res.update({'status': 'cracked', 'username': cred.username, 'password': cred.password})
            score, reasons = self.honeypot.detect(ip, port, cred.version, cred.latency, cred.error)
            res['honeypot_score'] = score
            if self.honeypot.is_honeypot(score): res['status'] = 'honeypot'
            cves = self.cve_checker.check_single(ip, port, (cred.username, cred.password), cred.version)
            res['cve_list'] = [c['id'] for c in cves]
        return res

    def start(self):
        self.running = True
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._worker_main())

    async def _worker_main(self):
        while self.running and not is_shutdown_requested():
            try:
                sock = socket.socket(); sock.connect((self.master_host, self.master_port)); sock.settimeout(10)
                await self._work_loop(sock)
            except Exception as e:
                logger.error(f"连接主节点失败: {e}")
                await asyncio.sleep(5)

    async def _work_loop(self, sock):
        loop = asyncio.get_running_loop()
        while self.running:
            await loop.sock_sendall(sock, b'GET_TASK\n')
            data = await loop.sock_recv(sock, 4096)
            msg = data.decode().strip()
            if msg == 'WAIT': await asyncio.sleep(2); continue
            task = json.loads(msg)
            result = await loop.run_in_executor(None, self._scan_single, task)
            payload = json.dumps({'task_id': task['id'], 'result': result})
            await loop.sock_sendall(sock, f"RESULT:{payload}\n".encode())
            await loop.sock_recv(sock, 1024)

    def stop(self):
        self.running = False
        if self.loop: self.loop.call_soon_threadsafe(self.loop.stop)