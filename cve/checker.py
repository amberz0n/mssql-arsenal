import json
import os
import pymssql
from typing import List, Dict, Any, Optional, Tuple
from urllib.request import Request, urlopen

from core.logger import logger
from core.database import db


class CVEChecker:
    def __init__(self, rules_file: str = None):
        if rules_file is None:
            rules_file = os.path.join(os.path.dirname(__file__), 'definitions.json')
        self.rules = self._load_rules(rules_file)

    def _load_rules(self, path: str) -> List[Dict]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('cves', [])
        except Exception as e:
            logger.error(f"加载CVE规则失败: {e}")
            return []

    def check_single(
        self,
        ip: str,
        port: int = 1433,
        credentials: Optional[Tuple[str, str]] = None,
        version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        found = []
        for rule in self.rules:
            detection = rule.get('detection', {})
            det_type = detection.get('type')
            try:
                if det_type == 'http':
                    if self._check_http(ip, detection):
                        found.append(rule)
                elif det_type == 'sql':
                    if credentials:
                        if self._check_sql(ip, port, credentials[0], credentials[1], detection):
                            found.append(rule)
                elif det_type == 'version':
                    if version and self._check_version(version, detection):
                        found.append(rule)
            except Exception as e:
                logger.debug(f"CVE检测异常 {rule.get('id')}: {e}")

        if found:
            target = db.get_target(ip) or {}
            cve_list = target.get('cve_list', [])
            cve_list.extend([c['id'] for c in found])
            target['cve_list'] = list(set(cve_list))
            db.upsert_target(target)
            logger.info(f"{ip} 发现 {len(found)} 个CVE: {[c['id'] for c in found]}")
        return found

    def _check_http(self, ip: str, detection: Dict) -> bool:
        path = detection.get('path', '/')
        pattern = detection.get('pattern', '')
        url = f"http://{ip}:80{path}"
        try:
            req = Request(url, method='GET')
            resp = urlopen(req, timeout=5)
            content = resp.read().decode(errors='ignore')
            return pattern in content
        except:
            return False

    def _check_sql(self, ip: str, port: int, user: str, pwd: str, detection: Dict) -> bool:
        query = detection.get('query')
        expect = detection.get('expect')
        pattern = detection.get('pattern')
        try:
            conn = pymssql.connect(server=ip, port=str(port), user=user, password=pwd, login_timeout=5)
            cursor = conn.cursor()
            cursor.execute(query)
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            if expect == 'non-null':
                return row is not None
            elif expect == '1':
                return row and (row[0] == 1 or row[0] == '1')
            elif pattern:
                return pattern in str(row)
            return False
        except:
            return False

    def _check_version(self, version: str, detection: Dict) -> bool:
        ver_range = detection.get('range', [])
        for v in ver_range:
            if v in version:
                return True
        return False