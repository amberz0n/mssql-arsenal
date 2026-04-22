import socket
import time
from typing import Tuple, List, Dict, Any, Optional
from core.logger import logger


class HoneypotDetector:
    SUSPICIOUS_VERSIONS = {
        'WOW64': 0.3, 'Evaluation': 0.2, 'Express': 0.1, 'Developer': 0.1,
        'Microsoft SQL Server 2005': 0.3, 'Microsoft SQL Server 2008': 0.2,
        'Linux': 0.4, 'Unix': 0.4
    }
    HONEYPOT_ERRORS = ['Cannot open database', 'SSL Security error', 'The server principal']

    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold

    def detect(
        self, ip: str, port: int = 1433, version: Optional[str] = None,
        login_latency: Optional[float] = None, error_msg: Optional[str] = None,
        banner: Optional[str] = None, extra_info: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []

        if version:
            for sus, weight in self.SUSPICIOUS_VERSIONS.items():
                if sus in version:
                    score += weight
                    reasons.append(f"可疑版本: {sus}")
                    break
        else:
            score += 0.05
            reasons.append("无版本信息")

        if login_latency is not None:
            if login_latency < 0.05:
                score += 0.15
                reasons.append(f"响应极快 ({login_latency*1000:.2f}ms)")
            elif login_latency > 5.0:
                score += 0.1
                reasons.append(f"响应缓慢 ({login_latency:.2f}s)")

        if error_msg:
            for err in self.HONEYPOT_ERRORS:
                if err in error_msg:
                    score += 0.2
                    reasons.append(f"蜜罐错误: {err[:30]}")
                    break

        bait_score, bait_reason = self._active_bait(ip, port)
        score += bait_score
        if bait_reason:
            reasons.append(bait_reason)

        if extra_info:
            sandbox_score, sandbox_reason = self._sandbox_check(extra_info)
            score += sandbox_score
            if sandbox_reason:
                reasons.append(sandbox_reason)

        if ip.startswith('10.') or ip.startswith('192.168.'):
            score += 0.01
            reasons.append("私有IP")

        return min(score, 1.0), reasons

    def _active_bait(self, ip: str, port: int) -> Tuple[float, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b'\x0F\x01\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00')
            response = sock.recv(1024)
            sock.close()
            if b'error' in response.lower() or b'exception' in response.lower():
                return 0.2, "畸形包异常响应"
            if len(response) == 0:
                return 0.1, "畸形包直接断开"
        except:
            pass
        return 0.0, ""

    def _sandbox_check(self, extra_info: Dict) -> Tuple[float, str]:
        cpu = extra_info.get('cpu_cores', 0)
        mem_kb = extra_info.get('memory_kb', 0)
        if cpu == 1 and 0 < mem_kb < 2 * 1024 * 1024:
            return 0.25, f"沙箱特征: 单核/{mem_kb//1024}MB"
        return 0.0, ""

    def is_honeypot(self, score: float) -> bool:
        return score >= self.threshold