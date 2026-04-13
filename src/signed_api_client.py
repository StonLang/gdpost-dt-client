"""
带签名的API客户端 - 包装类，不修改原有APIClient
自动为请求添加RSA签名
"""
import time
from typing import Optional

from .api_client import APIClient
from .auth_client import RequestSigner


class SignedAPIClient:
    """
    带请求签名的API客户端包装类
    包装原有的APIClient，自动添加RSA签名头
    """
    
    def __init__(
        self,
        config,
        private_key_path: str,
        base_api_client: Optional[APIClient] = None
    ):
        """
        初始化带签名的API客户端
        
        Args:
            config: 客户端配置对象
            private_key_path: 私钥文件路径
            base_api_client: 可选，已有的APIClient实例
        """
        self.config = config
        self.client_id = config.client_id
        self.signer = RequestSigner(private_key_path)
        
        # 复用或创建基础APIClient
        self.api_client = base_api_client or APIClient(config)
    
    def _add_auth_headers(self, headers: dict, method: str, path: str, data: Optional[dict] = None) -> dict:
        """
        为请求添加签名认证头
        
        Args:
            headers: 原始请求头
            method: HTTP方法
            path: 请求路径
            data: 请求体数据（可选）
            
        Returns:
            添加了认证头的请求头字典
        """
        import json
        
        # 准备请求体字节
        body = None
        if data is not None:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        
        # 获取签名头
        auth_headers = self.signer.get_auth_headers(
            client_id=self.client_id,
            method=method,
            path=path,
            body=body
        )
        
        # 合并请求头
        result = headers.copy() if headers else {}
        result.update(auth_headers)
        
        return result
    
    def get(self, endpoint: str, params: Optional[dict] = None, headers: Optional[dict] = None):
        """发送带签名的GET请求"""
        signed_headers = self._add_auth_headers(headers or {}, "GET", endpoint)
        return self.api_client.get(endpoint, params=params, headers=signed_headers)
    
    def post(self, endpoint: str, data: Optional[dict] = None, headers: Optional[dict] = None):
        """发送带签名的POST请求"""
        import json
        signed_headers = self._add_auth_headers(headers or {}, "POST", endpoint, data)
        return self.api_client.post(endpoint, data=data, headers=signed_headers)
    
    def put(self, endpoint: str, data: Optional[dict] = None, headers: Optional[dict] = None):
        """发送带签名的PUT请求"""
        signed_headers = self._add_auth_headers(headers or {}, "PUT", endpoint, data)
        return self.api_client.put(endpoint, data=data, headers=signed_headers)
    
    def delete(self, endpoint: str, headers: Optional[dict] = None):
        """发送带签名的DELETE请求"""
        signed_headers = self._add_auth_headers(headers or {}, "DELETE", endpoint)
        return self.api_client.delete(endpoint, headers=signed_headers)
    
    # 保留原有APIClient的方法代理
    def fetch_capture_rules(self) -> bool:
        """获取捕获规则（复用原有APIClient的方法）"""
        return self.api_client.fetch_capture_rules()
    
    @property
    def rules(self):
        """访问规则列表"""
        return self.api_client.rules
    
    @property
    def api_base_url(self):
        """访问API基础URL"""
        return self.api_client.api_base_url
    
    def upload_capture(self, data: dict) -> bool:
        """上报捕获数据（使用签名）"""
        endpoint = self.config.api_upload_endpoint
        try:
            signed_headers = self._add_auth_headers({}, "POST", endpoint, data)
            response = self.api_client.post(endpoint, data=data, headers=signed_headers)
            return response is not None
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Upload failed: {e}")
            return False
