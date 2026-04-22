import pymssql
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from core.logger import logger

@dataclass
class ConnectionResult:
    success: bool
    error_msg: str = ""
    latency: float = 0.0
    version: Optional[str] = None
    server_name: Optional[str] = None
    is_encrypted: bool = False
    os_type: str = "Unknown"
    extra_info: Dict[str, Any] = field(default_factory=dict)

class MSSQLConnection:
    def __init__(
        self,
        host: str,
        port: int = 1433,
        username: str = "",
        password: str = "",
        database: str = "",
        timeout: float = 5.0,
        use_tls: bool = False,
        use_windows_auth: bool = False,
        use_kerberos: bool = False,
        domain: str = ""
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.timeout = timeout
        self.use_tls = use_tls
        self.use_windows_auth = use_windows_auth
        self.use_kerberos = use_kerberos
        self.domain = domain

    def connect(self) -> ConnectionResult:
        start = time.monotonic()
        result = ConnectionResult(success=False)
        conn = None
        try:
            kwargs = {
                'server': self.host,
                'port': str(self.port),
                'user': self.username,
                'password': self.password,
                'database': self.database,
                'login_timeout': self.timeout,
                'timeout': self.timeout,
                'as_dict': True
            }
            if self.use_tls or self.use_kerberos:
                kwargs['tds_version'] = '7.4'
                kwargs['encrypt'] = True
                kwargs['trust_server_certificate'] = True
            if self.use_kerberos:
                kwargs['windows_auth'] = True
                kwargs['user'] = ''
                kwargs['password'] = ''
            elif self.use_windows_auth:
                if self.domain:
                    kwargs['user'] = f"{self.domain}\\{self.username}"
                kwargs['windows_auth'] = True

            conn = pymssql.connect(**kwargs)
            cursor = conn.cursor()

            cursor.execute("SELECT @@VERSION")
            row = cursor.fetchone()
            if row:
                result.version = list(row.values())[0] if isinstance(row, dict) else row[0]

            ver = result.version or ""
            if "Windows" in ver:
                result.os_type = "Windows"
            elif "Linux" in ver:
                result.os_type = "Linux"

            cursor.execute("SELECT @@SERVERNAME")
            row = cursor.fetchone()
            if row:
                result.server_name = list(row.values())[0] if isinstance(row, dict) else row[0]

            try:
                cursor.execute("SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID")
                row = cursor.fetchone()
                if row:
                    val = list(row.values())[0] if isinstance(row, dict) else row[0]
                    result.is_encrypted = (val == 'TRUE')
            except:
                pass

            try:
                cursor.execute("SELECT cpu_count FROM sys.dm_os_sys_info")
                row = cursor.fetchone()
                if row:
                    result.extra_info['cpu_cores'] = list(row.values())[0] if isinstance(row, dict) else row[0]
                cursor.execute("SELECT total_physical_memory_kb FROM sys.dm_os_sys_memory")
                row = cursor.fetchone()
                if row:
                    result.extra_info['memory_kb'] = list(row.values())[0] if isinstance(row, dict) else row[0]
            except:
                pass

            cursor.close()
            result.success = True
        except pymssql.OperationalError as e:
            result.error_msg = str(e)
            if "Login failed" in str(e):
                result.error_msg = "Login failed"
        except Exception as e:
            result.error_msg = str(e)
        finally:
            if conn:
                conn.close()
            result.latency = time.monotonic() - start
        return result