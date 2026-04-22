"""SOCKS5 代理支持（通过 PySocks 猴子补丁）"""
import socket
import socks

def setup_proxy(proxy_url: str) -> None:
    """
    设置 SOCKS5 代理，格式：socks5://127.0.0.1:1080
    或 socks5://user:pass@host:port
    """
    if not proxy_url:
        return
    if not proxy_url.startswith('socks5://'):
        raise ValueError("仅支持 socks5:// 格式的代理")
    url = proxy_url[9:]
    auth = None
    if '@' in url:
        auth_part, host_part = url.split('@')
        user, passwd = auth_part.split(':')
        host, port = host_part.split(':')
        socks.set_default_proxy(socks.SOCKS5, host, int(port), username=user, password=passwd)
    else:
        host, port = url.split(':')
        socks.set_default_proxy(socks.SOCKS5, host, int(port))
    socket.socket = socks.socksocket