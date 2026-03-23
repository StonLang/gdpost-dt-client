"""
gdpost-dt-client 主程序入口
"""
import signal
import sys
import threading
import time

from .api_client import APIClient
from .config import ClientConfig
from .logger import setup_logging
from .proxy_handler import TransparentProxyHandler
from .traffic_capturer import TrafficCapturer


def main():
    """主入口函数"""
    # 加载配置
    config = ClientConfig.from_env()
    
    # 设置日志
    setup_logging(config.log_dir, config.log_level, config.log_retention_days)
    
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("gdpost-dt-client Starting...")
    logger.info("=" * 60)
    
    # 创建API客户端
    api_client = APIClient(config)
    
    # 初始获取规则
    logger.info("Fetching capture rules from API...")
    if not api_client.fetch_capture_rules():
        logger.error("Failed to fetch initial rules, starting with empty rules")
    else:
        logger.info(f"Loaded {len(api_client.rules)} capture rules")
    
    # 创建代理处理器
    proxy_handler = TransparentProxyHandler(config, api_client)
    
    # 创建流量捕获器
    try:
        capturer = TrafficCapturer(config)
        capturer.set_packet_callback(
            lambda **kwargs: proxy_handler.handle_request(**kwargs)
        )
        capturer.start()
        logger.info("Traffic capture started (requires admin privileges)")
    except ImportError as e:
        logger.error(f"Traffic capture unavailable: {e}")
        logger.info("Running in API polling mode only")
        capturer = None
    except Exception as e:
        logger.error(f"Failed to start traffic capture: {e}")
        capturer = None
    
    # 启动规则刷新线程
    stop_event = threading.Event()
    
    def refresh_loop():
        while not stop_event.is_set():
            time.sleep(config.poll_interval)
            if stop_event.is_set():
                break
            logger.info("Refreshing capture rules...")
            if api_client.fetch_capture_rules():
                logger.info(f"Rules refreshed: {len(api_client.rules)} rules loaded")
    
    refresh_thread = threading.Thread(target=refresh_loop, name="RuleRefreshThread", daemon=True)
    refresh_thread.start()
    
    logger.info("=" * 60)
    logger.info("gdpost-dt-client Started Successfully!")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 60)
    
    # 信号处理
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, stopping...")
        stop_event.set()
        if capturer:
            capturer.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 主循环
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping client...")
        stop_event.set()
        if capturer:
            capturer.stop()
        logger.info("Client stopped")


if __name__ == "__main__":
    main()
