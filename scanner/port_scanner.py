import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Callable

from core.logger import logger
from core.signals import is_shutdown_requested, register_task

@dataclass
class PortScanResult:
    ip: str
    port: int
    is_open: bool
    latency: Optional[float] = None
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

class AsyncPortScanner:
    def __init__(
        self,
        concurrency: int = 500,
        timeout: float = 2.0,
        enable_ipv6: bool = False
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.enable_ipv6 = enable_ipv6
        self._results: List[PortScanResult] = []
        self._progress_callback: Optional[Callable[[int, int, str], None]] = None
        self._completed = 0
        self._total = 0

    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        self._progress_callback = callback

    async def _connect_one(self, ip: str, port: int) -> PortScanResult:
        start = time.monotonic()
        try:
            family = socket.AF_INET6 if (self.enable_ipv6 and ':' in ip) else socket.AF_INET
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=family),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            latency = time.monotonic() - start
            return PortScanResult(ip=ip, port=port, is_open=True, latency=latency)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            latency = time.monotonic() - start
            return PortScanResult(ip=ip, port=port, is_open=False, latency=latency, error=str(e))
        except Exception as e:
            latency = time.monotonic() - start
            return PortScanResult(ip=ip, port=port, is_open=False, latency=latency, error=str(e))

    async def _scan_batch(self, targets: List[tuple]):
        semaphore = asyncio.Semaphore(self.concurrency)

        async def limited_scan(ip, port):
            async with semaphore:
                if is_shutdown_requested():
                    raise asyncio.CancelledError()
                return await self._connect_one(ip, port)

        tasks = [asyncio.create_task(limited_scan(ip, port)) for ip, port in targets]
        for task in tasks:
            register_task(task)

        try:
            for coro in asyncio.as_completed(tasks):
                if is_shutdown_requested():
                    for t in tasks:
                        t.cancel()
                    break
                try:
                    result = await coro
                    self._results.append(result)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug(f"扫描任务异常: {e}")
                finally:
                    self._completed += 1
                    if self._progress_callback:
                        self._progress_callback(self._completed, self._total,
                                                f"端口扫描 {self._completed}/{self._total}")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def scan(self, ip_list: List[str], ports: List[int]) -> List[PortScanResult]:
        if not ip_list or not ports:
            return []
        logger.info(f"开始异步端口扫描: {len(ip_list)} IPs × {len(ports)} 端口, 并发={self.concurrency}")
        self._results = []
        self._completed = 0
        self._total = len(ip_list) * len(ports)
        targets = [(ip, port) for ip in ip_list for port in ports]
        await self._scan_batch(targets)
        open_results = [r for r in self._results if r.is_open]
        logger.info(f"端口扫描完成: 发现 {len(open_results)} 个开放端口")
        return open_results

    def scan_sync(self, ip_list: List[str], ports: List[int]) -> List[PortScanResult]:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.scan(ip_list, ports))
        else:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, self.scan(ip_list, ports))
                return future.result()