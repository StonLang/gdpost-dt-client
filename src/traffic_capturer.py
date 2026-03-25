"""
流量捕获模块 - 使用 WinDivert 捕获网络流量
"""
import logging
import socket
import struct
import threading
from typing import Callable, Optional

try:
    import pydivert
except ImportError:
    pydivert = None
    logging.warning("pydivert not installed, traffic capture unavailable")

from .config import ClientConfig

logger = logging.getLogger(__name__)


class TrafficCapturer:
    """
    WinDivert 流量捕获器
    捕获 HTTP/HTTPS 流量并交给处理器
    """
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self._running = False
        self._handle: Optional[pydivert.WinDivert] = None
        self._capture_thread: Optional[threading.Thread] = None
        self._packet_callback: Optional[Callable] = None
        
        if pydivert is None:
            raise ImportError("pydivert is required for traffic capture")
    
    def set_packet_callback(self, callback: Callable):
        """设置数据包处理回调函数"""
        self._packet_callback = callback
    
    def start(self):
        """启动流量捕获"""
        if self._running:
            return
        
        try:
            # 创建 WinDivert 句柄
            self._handle = pydivert.WinDivert(
                self.config.divert_filter,
                priority=self.config.divert_priority
            )
            
            self._running = True
            self._capture_thread = threading.Thread(
                target=self._capture_loop,
                name="TrafficCaptureThread",
                daemon=True
            )
            self._capture_thread.start()
            
            logger.info(f"Traffic capture started")
            logger.info(f"Filter: {self.config.divert_filter}")
            logger.info(f"Priority: {self.config.divert_priority}")
            logger.info("Waiting for TCP packets...")
            
        except Exception as e:
            logger.error(f"Failed to start traffic capture: {e}")
            raise
    
    def stop(self):
        """停止流量捕获"""
        self._running = False
        
        if self._handle:
            try:
                self._handle.close()
            except:
                pass
            self._handle = None
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2)
        
        logger.info("Traffic capture stopped")
    
    def _capture_loop(self):
        """捕获循环 - 捕获并重新注入数据包，确保网络连通"""
        # packet_count = 0
        # http_count = 0
        
        try:
            with self._handle:
                logger.info(f"[DEBUG] Capture loop started on filter: {self.config.divert_filter}")
                logger.info(f"[DEBUG] Waiting for packets... All captured packets will be reinjected.")
                
                for packet in self._handle:
                    if not self._running:
                        break
                    
                    # packet_count += 1
                    
                    # # 每收到一个包打印一个点（进度指示）
                    # if packet_count % 10 == 0:
                    #     print(".", end="", flush=True)
                    
                    # # 每100个数据包打印一次统计
                    # if packet_count % 100 == 0:
                    #     print()  # 换行
                    #     logger.info(f"[DEBUG] Total packets: {packet_count}, HTTP: {http_count}")
                    
                    # !!! 关键：优先重新注入数据包，避免处理逻辑阻塞网络 !!!
                    try:
                        self._handle.send(packet)
                    except Exception as e:
                        logger.debug(f"Failed to reinject packet: {e}")
                        # 注入失败时跳过后续处理，防止异常放大
                        continue

                    try:
                        # # 仅在前若干个包打印详细调试信息（不区分端口）
                        # if packet_count <= 10:
                        #     src = f"{packet.src_addr}:{packet.src_port}"
                        #     dst = f"{packet.dst_addr}:{packet.dst_port}"
                        #     payload_len = len(packet.payload) if packet.payload else 0
                        #     preview = packet.payload[:50] if packet.payload else b""
                        #     print(f"\n[PACKET #{packet_count}] {src} -> {dst}, payload: {payload_len} bytes")
                        #     print(f"[PREVIEW] {preview}")
                        
                        # 在不影响传输的前提下进行解析和日志
                        is_http = self._process_packet(packet)
                        # if is_http:
                        #     http_count += 1
                    except Exception as e:
                        print(f"[ERROR] Processing packet: {e}")
                        logger.debug(f"Error processing packet: {e}")
                        
        except Exception as e:
            if self._running:
                logger.error(f"Capture loop error: {e}")
    
    def _process_packet(self, packet):
        """处理单个数据包，返回是否成功识别为 HTTP"""
        if not packet.payload:
            return False
        
        # 尝试解析 HTTP 请求
        payload = packet.payload
        
        # 检查是否是 HTTP 请求（简单检查）
        http_methods = (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"OPTI", b"PATC")
        is_http = any(payload.startswith(method) for method in http_methods)
        is_http_response = payload.startswith(b"HTTP/")
        
        if not is_http and not is_http_response:
            # 尝试解析 HTTPS/TLS ClientHello 的 SNI（域名）
            tls_sni = self._parse_tls_sni(payload)
            if tls_sni:
                src_addr = packet.src_addr
                src_port = packet.src_port
                dst_addr = packet.dst_addr
                dst_port = packet.dst_port
                path = "/"
                protocol = "https"
                method = "CONNECT"
                if self._packet_callback:
                    self._packet_callback(
                        src_addr=src_addr,
                        src_port=src_port,
                        dst_addr=dst_addr,
                        dst_port=dst_port,
                        payload=payload,
                        http_info={
                            "method": method,
                            "protocol": protocol,
                            "host": tls_sni,
                            "path": path,
                            "version": "TLS",
                            "headers": "",
                            "message_type": "request",
                        },
                        packet=packet
                    )
                return True

            # 不是 HTTP/HTTPS 请求，打印到 DEBUG 避免刷屏
            if len(payload) > 0:
                preview = payload[:100]
                logger.debug(f"[NON-HTTP] {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
                logger.debug(f"[NON-HTTP] First 100 bytes: {preview}")

            # 非 HTTP/HTTPS 请求，直接放行
            return False
        
        # 提取源和目标信息
        src_addr = packet.src_addr
        src_port = packet.src_port
        dst_addr = packet.dst_addr
        dst_port = packet.dst_port
        
        # 解析 HTTP 请求基本信息
        try:
            http_info = self._parse_http_request(payload)
            if http_info:
                if self._packet_callback:
                    self._packet_callback(
                        src_addr=src_addr,
                        src_port=src_port,
                        dst_addr=dst_addr,
                        dst_port=dst_port,
                        payload=payload,
                        http_info=http_info,
                        packet=packet
                    )
                return True
        except Exception as e:
            logger.debug(f"Failed to parse HTTP request: {e}")

        # 尝试解析 HTTP 响应
        if is_http_response:
            try:
                response_info = self._parse_http_response(payload)
                if response_info:
                    if self._packet_callback:
                        self._packet_callback(
                            src_addr=src_addr,
                            src_port=src_port,
                            dst_addr=dst_addr,
                            dst_port=dst_port,
                            payload=payload,
                            http_info=response_info,
                            packet=packet
                        )
                    return True
            except Exception as e:
                logger.debug(f"Failed to parse HTTP response: {e}")
        
        return False
    
    def _parse_http_request(self, payload: bytes) -> Optional[dict]:
        """
        简单解析 HTTP 请求
        
        Returns:
            dict with method, path, host, protocol or None
        """
        try:
            # 找到 HTTP 头的结束位置
            header_end = payload.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = len(payload)
            else:
                header_end += 4
            
            # 解码头部
            headers_data = payload[:header_end].decode('utf-8', errors='ignore')
            lines = headers_data.split('\r\n')
            
            if not lines:
                return None
            
            # 解析请求行
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
            
            method = parts[0]
            path = parts[1]
            version = parts[2]
            
            # 解析 Host 头
            host = None
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line[5:].strip()
                    break
            
            # 判断协议（根据端口或 HTTPS 标记）
            protocol = "https" if b"HTTPS" in payload or b":443" in payload else "http"
            
            return {
                'method': method,
                'path': path,
                'host': host,
                'protocol': protocol,
                'version': version,
                'headers': headers_data,
                'message_type': 'request',
            }
            
        except Exception as e:
            logger.debug(f"HTTP parse error: {e}")
            return None

    def _parse_http_response(self, payload: bytes) -> Optional[dict]:
        """简单解析 HTTP 响应"""
        try:
            header_end = payload.find(b"\r\n\r\n")
            if header_end == -1:
                return None

            headers_bytes = payload[:header_end]
            body = payload[header_end + 4:]
            headers_data = headers_bytes.decode("utf-8", errors="ignore")
            lines = headers_data.split("\r\n")
            if not lines:
                return None

            status_line = lines[0]
            parts = status_line.split(" ", 2)
            if len(parts) < 2:
                return None

            version = parts[0]
            status_code = int(parts[1]) if parts[1].isdigit() else 0
            reason = parts[2] if len(parts) > 2 else ""

            return {
                "version": version,
                "status_code": status_code,
                "reason": reason,
                "headers": headers_data,
                "body": body,
                "message_type": "response",
            }
        except Exception as e:
            logger.debug(f"HTTP response parse error: {e}")
            return None

    def _parse_tls_sni(self, payload: bytes) -> Optional[str]:
        """
        解析 TLS ClientHello 中的 SNI 主机名。
        只处理典型的 TLS 握手首包，不完整或非握手数据返回 None。
        """
        try:
            # TLS record header: type(1) + version(2) + length(2)
            if len(payload) < 5 or payload[0] != 0x16:
                return None

            record_len = int.from_bytes(payload[3:5], byteorder="big")
            if len(payload) < 5 + record_len:
                # 可能是分片，保守处理
                return None

            # Handshake message starts at offset 5
            hs_offset = 5
            if len(payload) < hs_offset + 4:
                return None

            handshake_type = payload[hs_offset]
            if handshake_type != 0x01:  # client_hello
                return None

            hs_len = int.from_bytes(payload[hs_offset + 1:hs_offset + 4], byteorder="big")
            hs_end = hs_offset + 4 + hs_len
            if len(payload) < hs_end:
                return None

            i = hs_offset + 4
            # client_version(2) + random(32)
            i += 2 + 32
            if i >= hs_end:
                return None

            # session_id
            sid_len = payload[i]
            i += 1 + sid_len
            if i + 2 > hs_end:
                return None

            # cipher_suites
            cs_len = int.from_bytes(payload[i:i + 2], byteorder="big")
            i += 2 + cs_len
            if i >= hs_end:
                return None

            # compression_methods
            comp_len = payload[i]
            i += 1 + comp_len
            if i + 2 > hs_end:
                return None

            # extensions
            ext_total_len = int.from_bytes(payload[i:i + 2], byteorder="big")
            i += 2
            ext_end = min(i + ext_total_len, hs_end)

            while i + 4 <= ext_end:
                ext_type = int.from_bytes(payload[i:i + 2], byteorder="big")
                ext_len = int.from_bytes(payload[i + 2:i + 4], byteorder="big")
                i += 4
                if i + ext_len > ext_end:
                    return None

                # server_name extension
                if ext_type == 0x0000 and ext_len >= 5:
                    # list_len(2) + name_type(1) + name_len(2) + name
                    list_len = int.from_bytes(payload[i:i + 2], byteorder="big")
                    j = i + 2
                    list_end = min(j + list_len, i + ext_len)

                    while j + 3 <= list_end:
                        name_type = payload[j]
                        name_len = int.from_bytes(payload[j + 1:j + 3], byteorder="big")
                        j += 3
                        if j + name_len > list_end:
                            break
                        if name_type == 0:
                            return payload[j:j + name_len].decode("utf-8", errors="ignore")
                        j += name_len

                i += ext_len

        except Exception as e:
            logger.debug(f"TLS SNI parse error: {e}")

        return None
    
    @property
    def is_running(self) -> bool:
        """是否正在运行"""
        return self._running
