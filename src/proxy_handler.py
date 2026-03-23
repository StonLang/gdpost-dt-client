"""
透明代理处理器 - 核心逻辑：匹配规则、记录数据、透明传输
"""
import logging
import socket
import threading
import time
from typing import Optional

from .api_client import APIClient, CaptureRule
from .config import ClientConfig
from .logger import log_matched_request, log_unmatched_request

logger = logging.getLogger(__name__)


class TransparentProxyHandler:
    """
    透明代理处理器
    1. 匹配规则 -> 记录请求响应 -> 上报API -> 透明传输
    2. 不匹配 -> 直接透明传输
    """
    
    def __init__(self, config: ClientConfig, api_client: APIClient):
        self.config = config
        self.api_client = api_client
    
    def handle_request(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int,
                       payload: bytes, http_info: dict, packet: object) -> bool:
        """
        处理HTTP请求
        
        Returns:
            bool: 是否被处理（匹配并记录）
        """
        method = http_info.get('method', 'GET')
        protocol = http_info.get('protocol', 'http')
        host = http_info.get('host', dst_addr)
        path = http_info.get('path', '/')
        
        # 查找匹配规则
        rule = self.api_client.find_matching_rule(method, protocol, host, dst_port, path)
        
        if rule:
            # 匹配成功：记录并上报
            logger.debug(f"Request matched rule: {rule.api_id} ({rule.api_name})")
            self._process_matched_request(
                rule, method, protocol, host, dst_port, path,
                payload, http_info, src_addr, src_port, dst_addr, dst_port
            )
            return True
        else:
            # 未匹配：透明传输
            log_unmatched_request(method, protocol, host, dst_port, path)
            return False
    
    def _process_matched_request(self, rule: CaptureRule, method: str, protocol: str,
                                  host: str, port: int, path: str,
                                  request_payload: bytes, http_info: dict,
                                  src_addr: str, src_port: int, dst_addr: str, dst_port: int):
        """处理匹配的请求：记录、上报、透明传输"""
        
        # 准备请求数据
        request_data = {
            "method": method,
            "protocol": protocol,
            "host": host,
            "port": port,
            "path": path,
            "headers": http_info.get('headers', ''),
            "payload_size": len(request_payload),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        
        # 执行透明代理获取响应（简化的透明传输逻辑）
        response_data = self._transparent_forward(
            src_addr, src_port, dst_addr, dst_port, request_payload
        )
        
        # 上报到API
        upload_status = "FAILED"
        try:
            success = self.api_client.upload_capture_data(
                rule.api_id, request_data, response_data
            )
            upload_status = "SUCCESS" if success else "FAILED"
        except Exception as e:
            logger.error(f"Upload failed: {e}")
        
        # 记录日志
        log_matched_request(method, protocol, host, port, path, rule.api_id, upload_status)
    
    def _transparent_forward(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int,
                             request_data: bytes) -> dict:
        """
        透明转发请求到目标服务器
        返回响应数据摘要（实际应完整转发）
        """
        # 简化实现：记录响应基本信息
        return {
            "status_code": 200,  # 实际应从响应解析
            "response_size": 0,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
