"""
API客户端模块 - 负责与服务端通信
"""
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
import urllib3

from .config import ClientConfig

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


@dataclass
class CaptureRule:
    """捕获规则"""
    api_id: int
    api_code: str
    api_name: str
    api_tag: str
    api_type: str
    req_url: str
    req_method: str
    req_protocol: str
    req_host: str
    req_port: str
    req_path: str
    status: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaptureRule":
        """从字典创建规则对象"""
        return cls(
            api_id=data.get("api_id", 0),
            api_code=data.get("api_code", ""),
            api_name=data.get("api_name", ""),
            api_tag=data.get("api_tag", ""),
            api_type=data.get("api_type", ""),
            req_url=data.get("req_url", ""),
            req_method=data.get("req_method", "GET"),
            req_protocol=data.get("req_protocol", "HTTP"),
            req_host=data.get("req_host", ""),
            req_port=str(data.get("req_port", "80")),
            req_path=data.get("req_path", "/"),
            status=data.get("status", "1"),
        )
    
    def matches(self, method: str, protocol: str, host: str, port: int, path: str) -> bool:
        """
        检查请求是否匹配此规则
        
        Args:
            method: HTTP方法 (GET, POST等)
            protocol: 协议 (http, https)
            host: 主机地址
            port: 端口号
            path: 请求路径
            
        Returns:
            bool: 是否匹配
        """
        # 方法匹配（不区分大小写）
        if self.req_method.upper() != method.upper():
            return False
        
        # 协议匹配（不区分大小写）
        if self.req_protocol.upper() != protocol.upper():
            return False
        
        # 主机匹配（区分大小写，与规则字段一致；调用方传入已规范化的主机名）
        if self.req_host != host:
            return False
        
        # 端口匹配：规则中端口为 0 表示任意端口
        rule_port = int(self.req_port)
        if rule_port != 0 and rule_port != port:
            return False
        
        # 路径匹配：规则以 * 结尾时为前缀匹配，否则为路径完全匹配（不含查询串）
        path_only = path.split("?", 1)[0]
        req_path = self.req_path
        if req_path.endswith("*"):
            prefix = req_path[:-1]
            if not path_only.startswith(prefix):
                return False
        else:
            a = path_only.rstrip("/") or "/"
            b = req_path.rstrip("/") or "/"
            if a != b:
                return False
        
        return True


class APIClient:
    """API客户端"""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self.session = requests.Session()
        self.session.timeout = (config.connect_timeout, config.read_timeout)
        self.session.verify = False
        self._rules: List[CaptureRule] = []
        self._last_refresh: float = 0
    
    def fetch_capture_rules(self) -> bool:
        """
        从API接口1获取捕获规则列表
        
        Returns:
            bool: 是否成功获取
        """
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            
            # 添加认证信息
            if self.config.api_key:
                headers["X-API-Key"] = self.config.api_key
            if self.config.client_id:
                headers["X-Client-ID"] = self.config.client_id
            
            logger.info(f"Fetching capture rules from: {self.config.api_configs_url}")
            
            response = self.session.get(
                self.config.api_configs_url,
                headers=headers,
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("success") and "data" in data:
                    rules_data = data["data"]
                    self._rules = [CaptureRule.from_dict(r) for r in rules_data]
                    self._last_refresh = time.time()
                    logger.info(f"Successfully fetched {len(self._rules)} capture rules")
                    return True
                else:
                    logger.warning(f"API returned unsuccessful response: {data.get('message')}")
                    return False
            else:
                logger.error(f"Failed to fetch rules: HTTP {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error fetching capture rules: {e}")
            return False
    
    def upload_capture_data(self, api_id: int, request_data: Dict, response_data: Dict, capture_data: Optional[Dict] = None) -> bool:
        """
        将捕获的数据上报到API接口2
        
        Args:
            api_id: 匹配的API ID
            request_data: 请求数据
            response_data: 响应数据
            
        Returns:
            bool: 是否成功上报
        """
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            
            if self.config.api_key:
                headers["X-API-Key"] = self.config.api_key
            if self.config.client_id:
                headers["X-Client-ID"] = self.config.client_id
            
            payload = {
                "api_id": api_id,
                "client_id": self.config.client_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "request": request_data,
                "response": response_data,
            }
            if capture_data is not None:
                payload["capture_data"] = capture_data
            
            response = self.session.post(
                self.config.api_upload_url,
                headers=headers,
                json=payload,
            )
            
            if response.status_code == 200:
                logger.debug(f"Successfully uploaded capture data for api_id={api_id}")
                return True
            else:
                logger.warning(f"Failed to upload data: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error uploading capture data: {e}")
            return False
    
    def find_matching_rule(self, method: str, protocol: str, host: str, port: int, path: str) -> Optional[CaptureRule]:
        """
        查找匹配的捕获规则
        
        Returns:
            匹配的规则或None
        """
        for rule in self._rules:
            if rule.status == "1" and rule.matches(method, protocol, host, port, path):
                return rule
        return None
    
    @property
    def rules(self) -> List[CaptureRule]:
        """获取当前规则列表"""
        return self._rules.copy()
    
    @property
    def is_config_expired(self) -> bool:
        """检查配置是否过期"""
        return (time.time() - self._last_refresh) > self.config.poll_interval
