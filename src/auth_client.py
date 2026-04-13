"""
RSA签名认证客户端 - 独立模块，不修改原有代码
用于客户端请求签名
"""
import base64
import hashlib
import os
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class RequestSigner:
    """请求签名工具类"""
    
    def __init__(self, private_key_path: str):
        """
        初始化签名工具
        
        Args:
            private_key_path: 私钥文件路径（PEM格式）
        """
        self.private_key_path = private_key_path
        self.private_key = self._load_private_key()
    
    def _load_private_key(self):
        """从文件加载私钥"""
        with open(self.private_key_path, 'rb') as f:
            key_data = f.read()
        return serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
    
    @staticmethod
    def generate_key_pair() -> tuple:
        """
        生成RSA密钥对
        
        Returns:
            (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    @staticmethod
    def save_key(key_pem: str, path: str):
        """保存密钥到文件"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(key_pem)
    
    def sign_request(
        self,
        method: str,
        path: str,
        timestamp: str,
        body: Optional[bytes] = None
    ) -> str:
        """
        签名HTTP请求
        
        Args:
            method: HTTP方法 (GET, POST, etc.)
            path: 请求路径 (/api/v1/...)
            timestamp: Unix时间戳字符串
            body: 请求体字节（可选）
            
        Returns:
            Base64编码的签名
        """
        # 构建签名内容: METHOD|PATH|TIMESTAMP|BODY_SHA256
        body_hash = hashlib.sha256(body or b'').hexdigest()
        sign_content = f"{method.upper()}|{path}|{timestamp}|{body_hash}"
        
        # 签名
        signature = self.private_key.sign(
            sign_content.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def get_auth_headers(
        self,
        client_id: str,
        method: str,
        path: str,
        body: Optional[bytes] = None
    ) -> dict:
        """
        获取完整的认证请求头
        
        Args:
            client_id: 客户端标识
            method: HTTP方法
            path: 请求路径
            body: 请求体（可选）
            
        Returns:
            包含认证头的字典
        """
        import time
        timestamp = str(int(time.time()))
        signature = self.sign_request(method, path, timestamp, body)
        
        return {
            "X-Client-ID": client_id,
            "X-Timestamp": timestamp,
            "X-Signature": signature
        }
