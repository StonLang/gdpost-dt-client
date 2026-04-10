"""
打包入口脚本 - 支持命令行参数控制服务
用法:
    main_cli.exe install    - 安装并启动服务
    main_cli.exe uninstall  - 停止并卸载服务
    main_cli.exe run        - 前台运行（调试用）
    main_cli.exe (无参数)   - 作为服务启动
"""
import sys
import os
import win32serviceutil
import win32service
import win32event
import servicemanager
import logging
import threading
import time

# 确保路径正确
if getattr(sys, 'frozen', False):
    # 打包后的路径
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # 开发路径
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, 'src'))

from src.main import main as client_main
from src.config import ClientConfig

# 服务配置
SERVICE_NAME = "GdpostClient"
SERVICE_DISPLAY_NAME = "GDPost DT Client"
SERVICE_DESCRIPTION = "GDPost 数据捕获与上报客户端服务"


class GdpostClientService(win32serviceutil.ServiceFramework):
    """GDPost DT Client Windows Service"""
    
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = False
        self.logger = self._setup_logging()
    
    def _setup_logging(self):
        """设置服务日志"""
        log_dir = os.path.join(BASE_DIR, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'service.log'), encoding='utf-8'),
            ]
        )
        return logging.getLogger(__name__)
    
    def SvcStop(self):
        """服务停止"""
        self.logger.info("收到服务停止请求")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False
    
    def SvcDoRun(self):
        """服务运行"""
        self.logger.info("服务启动中...")
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        
        try:
            # 在新线程中运行客户端，避免阻塞服务
            client_thread = threading.Thread(
                target=self._run_client, 
                name="ClientMain", 
                daemon=True
            )
            client_thread.start()
            
            # 等待停止事件
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            
        except Exception as e:
            self.logger.error(f"服务运行错误: {e}")
            self.SvcStop()
    
    def _run_client(self):
        """运行客户端"""
        try:
            self.logger.info("启动客户端主程序...")
            client_main()
        except Exception as e:
            self.logger.error(f"客户端异常: {e}")


def install_service():
    """安装并启动服务"""
    try:
        # 获取当前 exe 路径
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = sys.executable
            script_path = os.path.abspath(__file__)
        
        self_logger = logging.getLogger(__name__)
        self_logger.info(f"安装服务，程序路径: {exe_path}")
        
        # 安装服务
        win32serviceutil.InstallService(
            GdpostClientService,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            startType=win32service.SERVICE_AUTO_START,
            exeName=exe_path
        )
        
        print(f"✓ 服务 '{SERVICE_DISPLAY_NAME}' 安装成功")
        print(f"✓ 服务设置为开机自动启动")
        
        # 启动服务
        try:
            win32serviceutil.StartService(SERVICE_NAME)
            print(f"✓ 服务已启动")
        except Exception as e:
            print(f"⚠ 服务启动失败（可能需要手动启动）: {e}")
        
        print(f"\n管理命令:")
        print(f"  启动: net start {SERVICE_NAME}")
        print(f"  停止: net stop {SERVICE_NAME}")
        print(f"  卸载: {os.path.basename(exe_path)} uninstall")
        
    except Exception as e:
        print(f"✗ 安装失败: {e}")
        return 1
    return 0


def uninstall_service():
    """停止并卸载服务"""
    try:
        # 先停止服务
        try:
            win32serviceutil.StopService(SERVICE_NAME)
            print(f"✓ 服务已停止")
            time.sleep(1)  # 等待服务完全停止
        except:
            pass
        
        # 卸载服务
        win32serviceutil.RemoveService(SERVICE_NAME)
        print(f"✓ 服务 '{SERVICE_DISPLAY_NAME}' 已卸载")
        
    except Exception as e:
        print(f"✗ 卸载失败: {e}")
        return 1
    return 0


def run_foreground():
    """前台运行（调试用）"""
    print("前台运行模式（按 Ctrl+C 停止）...")
    try:
        client_main()
    except KeyboardInterrupt:
        print("\n程序已停止")
    return 0


def main():
    """主入口"""
    # 设置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # 解析命令行参数
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        
        if cmd in ('install', 'i', '--install'):
            return install_service()
        
        elif cmd in ('uninstall', 'remove', 'u', '--uninstall', '--remove'):
            return uninstall_service()
        
        elif cmd in ('run', 'r', '--run', 'console'):
            return run_foreground()
        
        elif cmd in ('help', 'h', '--help', '-?'):
            print(f"GDPost DT Client - 命令行工具")
            print(f"")
            print(f"用法: {os.path.basename(sys.argv[0])} [命令]")
            print(f"")
            print(f"命令:")
            print(f"  install     安装为 Windows 服务并启动（开机自动启动）")
            print(f"  uninstall   停止并卸载 Windows 服务")
            print(f"  run         前台运行（调试用，按 Ctrl+C 停止）")
            print(f"  help        显示帮助信息")
            print(f"")
            print(f"注意: 无参数运行时作为服务启动（由 Windows 服务管理器调用）")
            return 0
        else:
            print(f"未知命令: {cmd}")
            print(f"使用 '{os.path.basename(sys.argv[0])} help' 查看帮助")
            return 1
    
    # 无参数：尝试作为服务启动，如果不是 SCM 启动则自动安装
    if getattr(sys, 'frozen', False):
        # 打包后，尝试作为服务启动
        # 由 SCM 启动时会成功，否则失败并执行安装
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(GdpostClientService)
            servicemanager.StartServiceCtrlDispatcher()
            # 如果成功，程序会阻塞在这里直到服务停止
            return 0
        except Exception as e:
            # 启动失败（错误 1063 = 不是由 SCM 启动）
            error_str = str(e)
            if '1063' in error_str or 'StartServiceCtrlDispatcher' in error_str or 'failed' in error_str.lower():
                # 用户直接运行，执行安装
                print(f"GDPost DT Client 安装程序")
                print(f"=" * 50)
                print(f"检测到直接运行，正在安装为 Windows 服务...")
                print(f"")
                return install_service()
            else:
                print(f"服务启动失败: {e}")
                return 1
    else:
        # 开发模式，默认前台运行
        return run_foreground()


if __name__ == '__main__':
    sys.exit(main())
