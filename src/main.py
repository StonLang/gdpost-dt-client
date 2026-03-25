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
    logger.info("gdpost-dt-client 正在启动...")
    logger.info("=" * 60)
    
    # 创建API客户端
    api_client = APIClient(config)
    
    # 启动时从接口拉取一次捕获规则
    logger.info("正在从 API 获取捕获规则...")
    if not api_client.fetch_capture_rules():
        logger.error("获取初始规则失败，将以空规则启动")
    else:
        logger.info(f"已加载 {len(api_client.rules)} 条捕获规则")
    
    # 创建代理处理器
    proxy_handler = TransparentProxyHandler(config, api_client)
    
    # 创建并启动流量捕获（需管理员权限以加载 WinDivert）
    try:
        capturer = TrafficCapturer(config)
        # 每个捕获到的数据包交给透明代理处理器解析、匹配与上报
        capturer.set_packet_callback(
            lambda **kwargs: proxy_handler.handle_request(**kwargs)
        )
        capturer.start()
        logger.info("流量捕获已启动（需要管理员权限）")
    except ImportError as e:
        logger.error(f"无法启用流量捕获: {e}")
        logger.info("当前仅以轮询 API 模式运行（不抓包）")
        capturer = None
    except Exception as e:
        logger.error(f"启动流量捕获失败: {e}")
        capturer = None
    
    # 后台线程：按间隔定时刷新捕获规则
    stop_event = threading.Event()
    
    def refresh_loop():
        while not stop_event.is_set():
            time.sleep(config.poll_interval)
            if stop_event.is_set():
                break
            logger.info("正在刷新捕获规则...")
            if api_client.fetch_capture_rules():
                logger.info(f"规则已刷新，当前共 {len(api_client.rules)} 条")
    
    refresh_thread = threading.Thread(target=refresh_loop, name="RuleRefreshThread", daemon=True)
    refresh_thread.start()
    
    logger.info("=" * 60)
    logger.info("gdpost-dt-client 启动成功")
    logger.info("按 Ctrl+C 可停止运行")
    logger.info("=" * 60)
    
    # 注册退出信号（Ctrl+C / 终止）
    def signal_handler(sig, frame):
        logger.info(f"收到信号 {sig}，正在停止...")
        stop_event.set()
        if capturer:
            capturer.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 主线程阻塞等待（由信号或键盘中断结束）
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("正在停止客户端...")
        stop_event.set()
        if capturer:
            capturer.stop()
        logger.info("客户端已停止")


if __name__ == "__main__":
    # 直接运行本模块时执行入口
    main()
