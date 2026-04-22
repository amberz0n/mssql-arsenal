import json
from datetime import datetime
from core.database import db
from core.logger import logger

class ReportGenerator:
    @staticmethod
    def generate_json(out='scan_report.json', hide=False):
        targets = []
        for status in ['open', 'cracked', 'exploited', 'honeypot']:
            for t in db.get_targets_by_status(status):
                targets.append({
                    'ip': t['ip'], 'port': t.get('port'), 'status': t['status'],
                    'username': t.get('username'), 'password': '***' if hide else t.get('password'),
                    'version': t.get('version'), 'honeypot_score': t.get('honeypot_score'),
                    'cve_list': t.get('cve_list')
                })
        with open(out, 'w') as f: json.dump({'generated': datetime.now().isoformat(), 'targets': targets}, f, indent=2)
        logger.info(f"报告已生成: {out}")

    @staticmethod
    def generate_html(out='scan_report.html', hide=False):
        rows = []
        for status in ['cracked', 'exploited', 'honeypot']:
            for t in db.get_targets_by_status(status):
                rows.append(f"<tr><td>{t['ip']}</td><td>{t.get('port')}</td><td>{t['status']}</td><td>{t.get('username','')}</td><td>{'***' if hide else t.get('password','')}</td><td>{t.get('version','')[:50]}</td><td>{t.get('honeypot_score',0):.2f}</td><td>{','.join(t.get('cve_list',[]))}</td></tr>")
        html = f"<html><head><title>MSSQL Arsenal Report</title><style>body{{background:#1e1e1e;color:#ddd}} table{{border-collapse:collapse}} th,td{{border:1px solid #444;padding:5px}}</style></head><body><h1>扫描报告 {datetime.now()}</h1><table><tr><th>IP</th><th>端口</th><th>状态</th><th>用户</th><th>密码</th><th>版本</th><th>蜜罐</th><th>CVE</th></tr>{''.join(rows)}</table></body></html>"
        with open(out, 'w') as f: f.write(html)
        logger.info(f"报告已生成: {out}")