"""
日志模块 - 按天归档，自动清理30天前的日志
"""
import logging
import os
import sys
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Optional


class DailyRotatingFileHandler(TimedRotatingFileHandler):
    """
    按天归档的日志处理器
    每天创建一个日志文件，自动清理N天前的旧日志
    """
    
    def __init__(self, log_dir: str, retention_days: int = 30):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # 生成日志文件名: logs/gdpost-dt-client-2026-03-23.log
        self.log_prefix = "gdpost-dt-client"
        
        super().__init__(
            filename=self.log_dir / f"{self.log_prefix}.log",
            when="midnight",
            interval=1,
            backupCount=retention_days,
            encoding="utf-8",
        )
        
        self.retention_days = retention_days
        self.suffix = "%Y-%m-%d"
        
    def doRollover(self):
        """执行日志轮转时同时清理旧文件"""
        super().doRollover()
        self._cleanup_old_logs()
    
    def _cleanup_old_logs(self):
        """清理超过 retention_days 天的日志文件"""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        try:
            for log_file in self.log_dir.glob(f"{self.log_prefix}-*.log"):
                # 从文件名提取日期
                try:
                    # 格式: gdpost-dt-client-2026-03-23.log
                    date_str = log_file.stem.replace(f"{self.log_prefix}-", "")
                    file_date = datetime.strptime(date_str, "%Y-%m-%d")
                    
                    if file_date < cutoff_date:
                        log_file.unlink()
                        logging.info(f"Deleted old log file: {log_file.name}")
                except ValueError:
                    # 文件名格式不符合，跳过
                    pass
        except Exception as e:
            logging.warning(f"Error during log cleanup: {e}")


def setup_logging(log_dir: str, log_level: str, retention_days: int = 30) -> logging.Logger:
    """
    配置日志系统
    
    Args:
        log_dir: 日志目录
        log_level: 日志级别 (DEBUG, INFO, WARNING, ERROR)
        retention_days: 日志保留天数
        
    Returns:
        根日志记录器
    """
    # 创建日志目录
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # 获取根记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # 清除现有处理器
    root_logger.handlers.clear()
    
    # 日志格式
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # 1. 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # 2. 文件处理器（按天归档）
    file_handler = DailyRotatingFileHandler(log_dir, retention_days)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # 3. 匹配请求专用日志（单独文件）
    matched_handler = logging.FileHandler(
        Path(log_dir) / "matched_requests.log",
        encoding="utf-8",
        mode="a"
    )
    matched_handler.setLevel(logging.INFO)
    matched_formatter = logging.Formatter(
        "%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    matched_handler.setFormatter(matched_formatter)
    
    # 创建专用记录器
    matched_logger = logging.getLogger("matched_requests")
    matched_logger.setLevel(logging.INFO)
    matched_logger.addHandler(matched_handler)
    matched_logger.propagate = False  # 不向父记录器传播
    
    return root_logger


def log_matched_request(method: str, protocol: str, host: str, port: int, path: str, 
                        api_id: int, upload_status: str):
    """
    记录匹配的请求
    
    Args:
        method: HTTP方法
        protocol: 协议
        host: 主机
        port: 端口
        path: 路径
        api_id: 匹配的API ID
        upload_status: 上传状态
    """
    logger = logging.getLogger("matched_requests")
    logger.info(f"[MATCHED] {method} {protocol}://{host}:{port}{path} -> API_ID:{api_id}, Upload:{upload_status}")


def log_unmatched_request(method: str, protocol: str, host: str, port: int, path: str):
    """
    记录未匹配的请求（透明传输）
    
    Args:
        method: HTTP方法
        protocol: 协议
        host: 主机
        port: 端口
        path: 路径
    """
    logger = logging.getLogger("matched_requests")
    logger.info(f"[PASSTHROUGH] {method} {protocol}://{host}:{port}{path}")
