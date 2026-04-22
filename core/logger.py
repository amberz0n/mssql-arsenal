import logging
import re
from typing import List, Callable

class SensitiveFilter(logging.Filter):
    def __init__(self, hide_secrets: bool = False):
        super().__init__()
        self.hide_secrets = hide_secrets

    def filter(self, record):
        if self.hide_secrets:
            msg = record.getMessage()
            msg = re.sub(r'(爆破成功: \S+ \S+:)\S+', r'\1***', msg)
            msg = re.sub(r'(账户 \S+:)\S+', r'\1***', msg)
            msg = re.sub(r'(password=)[^&\s]+', r'\1***', msg)
            record.msg = msg
            record.args = ()
        return True

class LogManager:
    _instance = None
    _initialized = False
    _lock = __import__('threading').Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.logger = logging.getLogger('MSSQLArsenal')
        self.logger.setLevel(logging.DEBUG)
        self._callbacks: List[Callable[[str], None]] = []
        self._callback_lock = __import__('threading').Lock()
        self._setup_handlers()

    def _setup_handlers(self):
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', '%H:%M:%S'))
        self.logger.addHandler(ch)
        fh = logging.FileHandler('mssql_arsenal.log', encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        self.logger.addHandler(fh)

    def add_callback(self, callback: Callable[[str], None]):
        with self._callback_lock:
            self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[str], None]):
        with self._callback_lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def _emit_to_callbacks(self, message: str):
        with self._callback_lock:
            callbacks = self._callbacks.copy()
        for cb in callbacks:
            try:
                cb(message)
            except Exception:
                pass

    def info(self, msg: str, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)
        self._emit_to_callbacks(msg % args if args else msg)

    def debug(self, msg: str, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)
        self._emit_to_callbacks(f"[警告] {msg % args if args else msg}")

    def error(self, msg: str, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)
        self._emit_to_callbacks(f"[错误] {msg % args if args else msg}")

    def set_hide_secrets(self, hide: bool):
        for handler in self.logger.handlers:
            handler.addFilter(SensitiveFilter(hide))

logger = LogManager()

def setup_logging(hide_secrets: bool = False):
    logger.set_hide_secrets(hide_secrets)