from typing import List, Optional, Dict, Any, Callable
import time
from core.logger import logger
from core.database import db
from .strategies import BruterCore, Strategy, BruteResult
from .dictionary import SmartDictionary

class MSSQLBruter:
    def __init__(
        self,
        strategy: str = "ip_first",
        timeout: float = 5.0,
        retries: int = 2,
        rate_limit: int = 0,
        use_tls: bool = False,
        use_windows_auth: bool = False,
        use_kerberos: bool = False,
        domain: str = "",
        enable_smart_dict: bool = True,
        random_delay: bool = False,
        delay_jitter: float = 0.2,
        max_workers: int = 50
    ):
        self.strategy = Strategy.IP_FIRST if strategy == "ip_first" else Strategy.CRED_FIRST
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self.use_tls = use_tls
        self.use_windows_auth = use_windows_auth
        self.use_kerberos = use_kerberos
        self.domain = domain
        self.enable_smart_dict = enable_smart_dict
        self.random_delay = random_delay
        self.delay_jitter = delay_jitter
        self.max_workers = max_workers
        self.smart_dict = SmartDictionary()
        self._progress_callback: Optional[Callable[[int, int, str], None]] = None

    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        self._progress_callback = callback

    def brute(
        self,
        ips: List[str],
        ports: List[int],
        users: List[str],
        passwords: List[str],
        target_info: Optional[Dict[str, Any]] = None
    ) -> List[BruteResult]:
        if not ips or not ports:
            return []
        uncracked_ips = []
        for ip in ips:
            target = db.get_target(ip)
            if target and target.get('status') in ('cracked', 'exploited'):
                continue
            uncracked_ips.append(ip)
        if not uncracked_ips:
            logger.info("所有IP均已破解，跳过爆破")
            return []

        final_passwords = passwords.copy()
        if self.enable_smart_dict:
            extra = self.smart_dict.generate(users, passwords, target_info)
            final_passwords = list(set(passwords + extra))

        logger.info(f"开始爆破: {len(uncracked_ips)} IPs, {len(users)} 用户, {len(final_passwords)} 密码")

        core = BruterCore(
            strategy=self.strategy,
            timeout=self.timeout,
            retries=self.retries,
            rate_limit=self.rate_limit,
            use_tls=self.use_tls,
            use_windows_auth=self.use_windows_auth,
            use_kerberos=self.use_kerberos,
            domain=self.domain,
            random_delay=self.random_delay,
            delay_jitter=self.delay_jitter
        )
        core.set_progress_callback(self._progress_callback)
        results = core.run(uncracked_ips, ports, users, final_passwords, self.max_workers)

        for res in results:
            target_data = {
                'ip': res.ip,
                'port': res.port,
                'status': 'cracked',
                'username': res.username,
                'password': res.password,
                'version': res.version,
                'os_type': res.os_type,
                'attempts': self.retries + 1,
                'updated_at': time.time()
            }
            db.upsert_target(target_data)
        return results