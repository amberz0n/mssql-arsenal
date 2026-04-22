import ipaddress
import socket
import struct
import random
import time
import threading
from typing import List

MAX_IP_RANGE = 100000

class IPUtils:
    @staticmethod
    def parse_target(target: str) -> List[str]:
        if target.startswith('file://'):
            path = target[7:]
            with open(path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if '-' in target:
            parts = target.split('-')
            if len(parts) == 2:
                start = parts[0].strip()
                end = parts[1].strip()
                if '.' in end and end.count('.') == 3:
                    ips = IPUtils._range_to_ips(start, end)
                else:
                    base = '.'.join(start.split('.')[:-1])
                    end_num = int(end)
                    start_num = int(start.split('.')[-1])
                    ips = [f"{base}.{i}" for i in range(start_num, end_num + 1)]
                if len(ips) > MAX_IP_RANGE:
                    raise ValueError(f"IP范围过大，生成 {len(ips)} 个IP，超过上限 {MAX_IP_RANGE}")
                return ips
        if '/' in target:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > MAX_IP_RANGE:
                raise ValueError(f"CIDR范围过大，包含 {net.num_addresses} 个地址，超过上限 {MAX_IP_RANGE}")
            return [str(ip) for ip in net.hosts()]
        # 域名解析
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(5.0)
            ips = set()
            for res in socket.getaddrinfo(target, None, socket.AF_INET):
                ips.add(res[4][0])
            socket.setdefaulttimeout(old_timeout)
            if ips:
                return list(ips)
        except socket.gaierror:
            pass
        # 单 IP
        try:
            socket.inet_aton(target)
            return [target]
        except socket.error:
            raise ValueError(f"无法解析目标: {target}")

    @staticmethod
    def _range_to_ips(start: str, end: str) -> List[str]:
        start_int = struct.unpack('!I', socket.inet_aton(start))[0]
        end_int = struct.unpack('!I', socket.inet_aton(end))[0]
        if start_int > end_int:
            start_int, end_int = end_int, start_int
        count = end_int - start_int + 1
        if count > MAX_IP_RANGE:
            raise ValueError(f"IP范围过大，共 {count} 个IP，超过上限 {MAX_IP_RANGE}")
        return [socket.inet_ntoa(struct.pack('!I', i)) for i in range(start_int, end_int + 1)]

class RateLimiter:
    def __init__(self, max_per_second: float):
        self.max_per_second = max_per_second
        self.tokens = max_per_second if max_per_second > 0 else float('inf')
        self.lock = threading.Lock()
        self.last_refill = time.monotonic()

    def acquire(self):
        if self.max_per_second <= 0:
            return
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.max_per_second, self.tokens + elapsed * self.max_per_second)
            self.last_refill = now
            if self.tokens >= 1:
                self.tokens -= 1
            else:
                sleep_time = (1 - self.tokens) / self.max_per_second
                time.sleep(sleep_time)
                self.tokens = 0
                self.last_refill = time.monotonic()

    def acquire_with_jitter(self, jitter: float = 0.2):
        self.acquire()
        if jitter > 0:
            time.sleep(random.uniform(0, jitter))