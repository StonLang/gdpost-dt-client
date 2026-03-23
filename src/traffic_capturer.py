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
            
            logger.info(f"Traffic capture started on filter: {self.config.divert_filter}")
            
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
        """捕获循环"""
        try:
            with self._handle:
                for packet in self._handle:
                    if not self._running:
                        break
                    
                    try:
                        self._process_packet(packet)
                    except Exception as e:
                        logger.debug(f"Error processing packet: {e}")
                        
        except Exception as e:
            if self._running:
                logger.error(f"Capture loop error: {e}")
    
    def _process_packet(self, packet):
        """处理单个数据包"""
        if not packet.payload:
            return
        
        # 尝试解析 HTTP 请求
        payload = packet.payload
        
        # 检查是否是 HTTP 请求（简单检查）
        http_methods = (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"OPTI", b"PATC")
        if not any(payload.startswith(method) for method in http_methods):
            # 不是 HTTP 请求，直接放行
            return
        
        # 提取源和目标信息
        src_addr = packet.src_addr
        src_port = packet.src_port
        dst_addr = packet.dst_addr
        dst_port = packet.dst_port
        
        # 解析 HTTP 请求基本信息
        try:
            http_info = self._parse_http_request(payload)
            if http_info and self._packet_callback:
                self._packet_callback(
                    src_addr=src_addr,
                    src_port=src_port,
                    dst_addr=dst_addr,
                    dst_port=dst_port,
                    payload=payload,
                    http_info=http_info,
                    packet=packet
                )
        except Exception as e:
            logger.debug(f"Failed to parse HTTP request: {e}")
    
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
                'headers': headers_data
            }
            
        except Exception as e:
            logger.debug(f"HTTP parse error: {e}")
            return None
    
    @property
    def is_running(self) -> bool:
        """是否正在运行"""
        return self._running
