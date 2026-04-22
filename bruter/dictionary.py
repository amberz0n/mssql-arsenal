from typing import List, Set, Optional
from datetime import datetime
from core.logger import logger

class SmartDictionary:
    BASE_PASSWORDS = [
        '', 'sa', '123456', 'password', 'admin', 'admin123',
        'sa123', 'sql', 'mssql', 'pass123', 'P@ssw0rd',
        'Password123', 'Admin@123', 'sa@123'
    ]
    USERNAME_VARIANTS = ['', '123', '1234', '12345', '123456', '@123', '!@#', '2023', '2024', '2025', '2026']

    def generate(self, base_users: List[str], base_passwords: List[str], target_info: Optional[dict] = None) -> List[str]:
        passwords: Set[str] = set(base_passwords)
        passwords.update(self.BASE_PASSWORDS)
        if target_info:
            company = target_info.get('company', '')
            domain = target_info.get('domain', '')
            ip = target_info.get('ip', '')
            if company:
                cl = company.lower()
                passwords.update([company, cl, f"{company}123", f"{company}@123", f"{cl}sa", f"{company}2024", f"{company}2025"])
            if domain:
                parts = domain.split('.')
                if len(parts) >= 2:
                    main = parts[-2]
                    passwords.update([main, f"{main}123", f"{main}@123"])
            if ip:
                parts = ip.split('.')
                if len(parts) == 4:
                    passwords.update([f"P@{ip}", f"{parts[-1]}{parts[-2]}", f"sql{parts[-1]}", f"sa{parts[-1]}"])
        current_year = datetime.now().year
        for year in range(current_year - 2, current_year + 2):
            passwords.update([f"admin@{year}", f"Pass@{year}", f"sa@{year}", f"sql@{year}"])
        for user in base_users:
            if user and user not in ('sa', 'admin', 'sql'):
                passwords.add(user)
                for suffix in self.USERNAME_VARIANTS:
                    passwords.add(f"{user}{suffix}")
        patterns = ['admin', 'sa', 'sql', 'user', 'test', 'root', 'backup', 'support', 'web', 'app']
        for p in patterns:
            passwords.update([p, p.capitalize(), p.upper(), f"{p}123", f"{p}1234", f"{p}@123", f"{p}@2024"])
        passwords.discard('')
        valid = [p for p in passwords if len(p) <= 32]
        logger.debug(f"智能字典生成: {len(valid)} 个密码")
        return valid