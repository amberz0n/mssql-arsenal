from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

class ExploitMode(Enum):
    RDP = "rdp"
    FILELESS = "fileless"
    CLR = "clr"
    OLE = "ole"
    PLUGIN = "plugin"
    NONE = "none"

class AlertPlatform(Enum):
    TELEGRAM = "telegram"
    DISCORD = "discord"

@dataclass
class AlertConfig:
    enabled: bool = False
    platform: AlertPlatform = AlertPlatform.TELEGRAM
    webhook_url: Optional[str] = None
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None

@dataclass
class ScanConfig:
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=lambda: [1433])
    timeout: float = 3.0
    max_concurrency: int = 500
    enable_ipv6: bool = False
    users: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    user_file: Optional[str] = None
    pass_file: Optional[str] = None
    shuffle_creds: bool = False
    credential_strategy: str = "ip_first"
    max_retries: int = 3
    rate_limit: int = 0
    use_tls: bool = False
    use_windows_auth: bool = False
    use_kerberos: bool = False
    domain: str = ""
    exploit_mode: ExploitMode = ExploitMode.NONE
    exploit_config: Dict[str, Any] = field(default_factory=dict)
    enable_honeypot: bool = True
    honeypot_threshold: float = 0.6
    enable_cve_check: bool = True
    enable_unauth_check: bool = True
    random_delay: bool = False
    delay_jitter: float = 0.2
    proxy: Optional[str] = None
    output_format: str = "json"
    output_file: Optional[str] = None
    hide_passwords: bool = False
    encrypt_results: bool = False
    master_mode: bool = False
    worker_mode: bool = False
    master_host: str = "0.0.0.0"
    master_port: int = 9999
    worker_id: Optional[str] = None
    alert: AlertConfig = field(default_factory=AlertConfig)

    def validate(self) -> bool:
        if not self.targets and not self.master_mode and not self.worker_mode:
            raise ValueError("必须指定扫描目标或启用分布式模式")
        if not self.ports:
            raise ValueError("端口列表不能为空")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency 必须大于0")
        if self.rate_limit < 0:
            raise ValueError("rate_limit 不能为负数")
        if self.exploit_mode == ExploitMode.FILELESS and 'lhost' not in self.exploit_config:
            raise ValueError("fileless模式必须指定 lhost")
        if self.exploit_mode == ExploitMode.PLUGIN and 'plugin_name' not in self.exploit_config:
            raise ValueError("plugin模式必须指定 plugin_name")
        return True