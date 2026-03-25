"""
gdpost-dt-client 配置模块
"""
import os
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()


@dataclass
class ClientConfig:
    """客户端配置"""
    
    # 服务端API接口1配置（获取捕获规则）
    api_base_url: str = field(default="http://localhost:8000")
    api_configs_endpoint: str = field(default="/api/v1/api-configs/login")
    
    # 服务端API接口2配置（上报捕获数据）
    api_upload_endpoint: str = field(default="/api/v1/capture/upload")
    
    # 认证信息
    api_key: Optional[str] = field(default=None)
    client_id: Optional[str] = field(default="client-001")
    
    # 轮询间隔（秒），默认5分钟
    poll_interval: int = field(default=300)
    
    # 日志配置
    log_dir: str = field(default="logs")
    log_level: str = field(default="INFO")
    log_retention_days: int = field(default=30)
    
    # WinDivert：默认捕获全部 TCP（任意源/目的 IP、任意端口、入站+出站），便于关联请求与响应
    divert_filter: str = field(default="tcp")
    divert_priority: int = field(default=0)
    
    # 代理配置（本地透明代理端口）
    proxy_host: str = field(default="127.0.0.1")
    proxy_port: int = field(default=0)  # 0表示自动选择
    
    # HTTP连接配置
    connect_timeout: int = field(default=10)
    read_timeout: int = field(default=30)
    
    @classmethod
    def from_env(cls) -> "ClientConfig":
        """从环境变量加载配置"""
        return cls(
            api_base_url=os.getenv("API_BASE_URL", "http://localhost:8000"),
            api_configs_endpoint=os.getenv("API_CONFIGS_ENDPOINT", "/api/v1/api-configs/login"),
            api_upload_endpoint=os.getenv("API_UPLOAD_ENDPOINT", "/api/v1/capture/upload"),
            api_key=os.getenv("API_KEY"),
            client_id=os.getenv("CLIENT_ID", "client-001"),
            poll_interval=int(os.getenv("POLL_INTERVAL", "300")),
            log_dir=os.getenv("LOG_DIR", "logs"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_retention_days=int(os.getenv("LOG_RETENTION_DAYS", "30")),
            divert_filter=os.getenv("DIVERT_FILTER", "tcp"),
            divert_priority=int(os.getenv("DIVERT_PRIORITY", "0")),
            proxy_host=os.getenv("PROXY_HOST", "127.0.0.1"),
            proxy_port=int(os.getenv("PROXY_PORT", "0")),
            connect_timeout=int(os.getenv("CONNECT_TIMEOUT", "10")),
            read_timeout=int(os.getenv("READ_TIMEOUT", "30")),
        )
    
    @property
    def api_configs_url(self) -> str:
        """获取API配置接口完整URL"""
        return f"{self.api_base_url}{self.api_configs_endpoint}"
    
    @property
    def api_upload_url(self) -> str:
        """获取数据上报接口完整URL"""
        return f"{self.api_base_url}{self.api_upload_endpoint}"
