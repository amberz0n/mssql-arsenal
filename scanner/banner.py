import socket
import ssl
import time
import struct
import random
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple

from core.logger import logger


@dataclass
class TDSBannerInfo:
    ip: str
    port: int
    raw_banner: bytes = b''
    version: Optional[str] = None
    tds_version: Optional[str] = None
    server_name: Optional[str] = None
    instance_name: Optional[str] = None
    is_encrypted: bool = False
    ssl_supported: bool = False
    error: Optional[str] = None
    latency: float = 0.0
    timestamp: float = field(default_factory=time.time)


class TDSBannerGrabber:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    @staticmethod
    def _create_prelogin_packet() -> bytes:
        options: List[Tuple[int, bytes]] = [
            (0x00, b'\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00'),
            (0x01, b'\x00'),
        ]
        random.shuffle(options)

        data_buffer = bytearray()
        for _, data in options:
            data_buffer.extend(data)

        token_array = bytearray()
        current_offset = 0
        for token, data in options:
            token_array.append(token)
            token_array.extend(struct.pack('<H', current_offset))
            token_array.extend(struct.pack('<H', len(data)))
            current_offset += len(data)

        header = bytearray(b'\x12\x01\x00\x00\x00\x00\x00\x00\x00\x00')
        total_length = len(header) + len(token_array) + len(data_buffer)
        struct.pack_into('>H', header, 2, total_length)

        return bytes(header) + bytes(token_array) + bytes(data_buffer)

    def _recv_tds_message(self, sock: socket.socket) -> bytes:
        data = sock.recv(8)
        if len(data) < 8:
            return data
        total_len = struct.unpack('>H', data[2:4])[0]
        received = bytearray(data)
        while len(received) < total_len:
            chunk = sock.recv(total_len - len(received))
            if not chunk:
                break
            received.extend(chunk)
        return bytes(received)

    def _parse_prelogin_response(self, data: bytes) -> Dict[str, Any]:
        info: Dict[str, Any] = {'encryption_supported': False}
        if len(data) < 4 or data[0] != 0x04:
            return info

        if len(data) < 10:
            return info
        token_offset = struct.unpack('<H', data[8:10])[0]
        if token_offset + 1 > len(data):
            return info
        token_count = data[token_offset]
        pos = token_offset + 1

        for _ in range(token_count):
            if pos + 5 > len(data):
                break
            token_type = data[pos]
            offset = struct.unpack('<H', data[pos+1:pos+3])[0]
            length = struct.unpack('<H', data[pos+3:pos+5])[0]
            pos += 5
            if offset + length > len(data):
                continue

            if token_type == 0x01:
                info['encryption_supported'] = (data[offset] == 0x01)
            elif token_type == 0x00:
                if length >= 4:
                    ver_bytes = data[offset+4:offset+length]
                    try:
                        ver_str = ver_bytes.decode('utf-16-le', errors='ignore').strip('\x00')
                        if ver_str:
                            info['version'] = ver_str
                    except:
                        pass
        return info

    def _grab_banner_raw(self, ip: str, port: int) -> Tuple[bytes, float]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        start = time.monotonic()
        try:
            sock.connect((ip, port))
            sock.send(self._create_prelogin_packet())
            data = self._recv_tds_message(sock)
            latency = time.monotonic() - start
            return data, latency
        finally:
            sock.close()

    def _try_tls_handshake(self, ip: str, port: int) -> Tuple[bool, Optional[bytes]]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((ip, port))
            sock.send(self._create_prelogin_packet())
            resp1 = self._recv_tds_message(sock)
            parsed = self._parse_prelogin_response(resp1)
            if not parsed.get('encryption_supported', False):
                return False, None

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_3

            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.send(self._create_prelogin_packet())
                data = self._recv_tds_message(ssock)
                return True, data
        except Exception as e:
            logger.debug(f"TLS握手失败 {ip}:{port} - {e}")
            return False, None
        finally:
            sock.close()

    def grab(self, ip: str, port: int = 1433) -> TDSBannerInfo:
        result = TDSBannerInfo(ip=ip, port=port)
        try:
            raw_data, latency = self._grab_banner_raw(ip, port)
            result.raw_banner = raw_data
            result.latency = latency
            parsed = self._parse_prelogin_response(raw_data)
            result.version = parsed.get('version')
            result.ssl_supported = parsed.get('encryption_supported', False)
        except Exception as e:
            result.error = f"预登录失败: {e}"
            return result

        if result.ssl_supported:
            try:
                tls_ok, tls_data = self._try_tls_handshake(ip, port)
                if tls_ok and tls_data:
                    result.is_encrypted = True
                    tls_parsed = self._parse_prelogin_response(tls_data)
                    if tls_parsed.get('version'):
                        result.version = tls_parsed['version']
            except Exception as e:
                logger.debug(f"TLS探测异常 {ip}:{port} - {e}")

        if result.version:
            if '2019' in result.version:
                result.tds_version = '7.5'
            elif '2017' in result.version:
                result.tds_version = '7.4'
            elif '2016' in result.version:
                result.tds_version = '7.3'
            elif '2014' in result.version:
                result.tds_version = '7.2'
            elif '2012' in result.version:
                result.tds_version = '7.2'
            elif '2008' in result.version:
                result.tds_version = '7.1'
            else:
                result.tds_version = '7.0+'
        return result

    def grab_sync(self, ip: str, port: int = 1433) -> TDSBannerInfo:
        return self.grab(ip, port)