# gdpost-dt-client

Windows 平台网络流量自动采集客户端。基于 WinDivert 底层驱动捕获浏览器与服务端的 HTTP/HTTPS 通信，智能匹配服务端下发的业务接口规则，自动解析请求/响应数据并上报服务端进行后续处理。

## 项目概述

**核心目标**：在用户无感知的情况下，透明抓取指定业务接口的网络流量，提取完整的请求/响应数据并实时上报服务端。

**业务场景**：
- 透明抓包：基于 WinDivert 驱动捕获底层 TCP 网络包，不影响浏览器正常使用
- 智能匹配：根据服务端下发的规则自动识别目标业务接口
- 请求/响应配对：通过五元组关联同一 HTTP 事务的请求和响应
- 自动上报：匹配成功的完整请求/响应数据通过线程池异步上报服务端
- RSA 签名认证：防止非法客户端伪造数据上报，请求可追溯、防重放

## 核心功能模块

### 1. WinDivert 流量捕获（底层驱动）
- **驱动调用**：基于 `pydivert`（WinDivert）捕获底层网络包，需管理员权限
- **过滤器配置**：仅捕获 TCP 流量，排除本地回环（`ip.DstAddr != 127.0.0.1`）
- **立即重新注入**：抓包后立即 `packet.send()` 放回网络，保证浏览器通信畅通
- **管理员权限检测**：启动时自动检测，无权限则降级为仅轮询模式

### 2. 双线程高性能架构
- **捕获线程**（`TrafficCaptureThread`）：专用线程高速捕获网络包，只做 `send+enqueue`
- **解析工作线程**（`TrafficParseWorker`）：从队列取出数据包，解析 HTTP、匹配规则、触发上报
- **线程安全**：队列、字典等共享资源加锁保护
- **大容量队列**：10000 容量，非阻塞入队（满时丢弃新包，零阻塞网络）
- **丢包统计**：每分钟记录丢包数量，可观测

### 3. HTTP 响应重组
- **响应流缓冲**：缓存多包响应数据，按 flow_key 累积
- **流超时清理**：30 秒无新数据自动清理缓存
- **缓冲区限制**：单个响应最大 256KB，防内存溢出
- **重复日志防护**：防止同一错误重复记录

### 4. 透明代理处理与规则匹配
- **规则匹配检查**：检查请求是否命中捕获规则（方法、协议、主机、端口、路径）
- **未匹配透传**：不匹配的规则直接放行，不做任何处理
- **会话创建**：为匹配请求创建唯一 `tracking_id`
- **请求数据组装**：提取方法、URL、Header、Body、Query 参数
- **数据截断**：超过 200KB 的请求体截断后上传
- **响应配对**：根据源/目标地址（flow_key）找到对应请求
- **异步上传**：5 个工作线程的线程池异步上报，不阻塞抓包

### 5. 规则引擎（与服务端联动）
- **初始规则获取**：启动时从服务端拉取接口捕获规则（`GET /api/v1/api-configs/login`）
- **后台规则刷新**：定时（默认 5 分钟）从服务端更新捕获规则
- **失败重试机制**：规则获取失败时 30 秒后重试，成功恢复 5 分钟间隔
- **分段等待设计**：1 秒步长等待，支持及时响应停止信号
- **匹配维度**：HTTP 方法、协议、主机、端口（0 表示任意）、路径（`*` 结尾为前缀匹配）

### 6. API 通信与 RSA 签名认证
- **规则获取接口**：调用服务端获取捕获规则（含重试、指数退避）
- **数据上报接口**：`POST /api/v1/capture/upload` 上报捕获数据
- **RSA 签名**：`METHOD|PATH|TIMESTAMP|BODY_SHA256` 签名，Base64 编码
- **认证头**：`X-Client-ID`、`X-Timestamp`、`X-Signature`
- **防重放攻击**：时间戳机制

### 7. 配置管理
- **.env 文件加载**：从环境变量文件读取所有配置
- **环境变量覆盖**：系统环境变量优先
- **关键配置项**：
  - `API_BASE_URL` — 服务端地址
  - `CLIENT_ID` / `PRIVATE_KEY_PATH` — 客户端标识与 RSA 私钥
  - `POLL_INTERVAL` — 规则刷新间隔（秒）
  - `DIVERT_FILTER` — WinDivert 抓包过滤规则
  - `LOG_LEVEL` / `LOG_RETENTION_DAYS` — 日志级别与保留天数

### 8. 日志系统
- **控制台输出**：实时显示运行日志
- **文件日志**：按天生成日志文件（`logs/gdpost-dt-client-YYYY-MM-DD.log`）
- **自动清理**：自动删除超期日志（可配置保留天数）
- **匹配请求日志**：单独记录匹配成功的请求（方法、URL、API ID、上传状态）

### 9. 部署与运行模式
- **开发模式**：`python -m src.main` 直接运行，或 `run.bat` 一键启动
- **Windows 服务**：`main_cli.py` 封装为 Windows Service（install / run / uninstall）
- **打包发布**：PyInstaller 单文件 exe + Inno Setup 安装程序

## 项目结构

```
gdpost-dt-client/
├── src/                      # 源代码目录
│   ├── main.py               # 程序入口（启动捕获、代理、规则刷新循环）
│   ├── config.py             # 配置管理（.env 驱动，dataclass）
│   ├── api_client.py         # API 客户端（规则获取、数据上报、规则匹配）
│   ├── traffic_capturer.py   # WinDivert 流量捕获器（双线程 + 队列）
│   ├── proxy_handler.py      # 透明代理处理器（配对、匹配、异步上报）
│   ├── auth_client.py        # RSA 签名工具（RequestSigner）
│   ├── signed_api_client.py  # 带签名的 API 客户端包装类
│   └── logger.py             # 日志配置（控制台 + 按天归档）
├── keys/                     # RSA 密钥存放目录
├── logs/                     # 日志目录（运行时创建）
├── venv/                     # Python 虚拟环境
├── .env.example              # 环境变量示例
├── .env                      # 本地环境变量（.gitignore）
├── requirements.txt          # Python 依赖
├── entry.py                  # PyInstaller 打包入口
├── main_cli.py               # Windows 服务封装（pywin32）
├── run.bat                   # Windows 一键启动脚本（检查权限、环境、依赖）
├── build.spec                # PyInstaller 打包配置
├── installer.iss             # Inno Setup 安装程序配置
├── BUILD.md                  # 打包与发布详细指南
└── README.md                 # 项目说明
```

## 快速开始

### 1. 环境准备

**前置要求**：
- Windows 系统（WinDivert 仅支持 Windows）
- Python 3.11+
- 管理员权限（WinDivert 驱动需要）

```bash
# 克隆项目
cd gdpost-dt-client

# 创建虚拟环境
python -m venv venv

# 激活（Windows）
venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
# 复制示例配置
cp .env.example .env

# 编辑 .env 文件，配置服务端地址、客户端ID、私钥路径等
```

### 3. 启动服务

**方式一：一键启动脚本（推荐）**

右键以管理员身份运行：
```bash
run.bat
```

脚本会自动：
1. 检查管理员权限
2. 创建/激活虚拟环境
3. 安装缺失依赖
4. 启动客户端

**方式二：命令行启动**

```bash
# 管理员权限 CMD
python -m src.main
```

### 4. 停止服务

按 `Ctrl+C` 或发送终止信号，客户端会：
1. 广播停止事件
2. 关闭 WinDivert 驱动
3. 等待线程池任务完成
4. 释放资源

## 配置说明

```env
# 服务端 API
API_BASE_URL=http://localhost:9909
API_CONFIGS_ENDPOINT=/api/v1/api-configs/login
API_UPLOAD_ENDPOINT=/api/v1/capture/upload

# 认证
CLIENT_ID=client-windows-01
PRIVATE_KEY_PATH=./keys/client_private_key.pem

# 轮询间隔（秒），默认 5 分钟
POLL_INTERVAL=300

# 日志
LOG_DIR=logs
LOG_LEVEL=INFO
LOG_RETENTION_DAYS=30

# WinDivert 过滤器
capture and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1
DIVERT_PRIORITY=0

# HTTP 超时
CONNECT_TIMEOUT=10
READ_TIMEOUT=30
```

## 打包与发布

### 生成 RSA 密钥对（首次部署）

```bash
python -c "from src.auth_client import RequestSigner; pk, pub = RequestSigner.generate_key_pair(); RequestSigner.save_key(pk, './keys/client_private_key.pem'); RequestSigner.save_key(pub, './keys/client_public_key.pem')"
```

### 打包为单文件 exe

```bash
# 安装打包工具
pip install pyinstaller pywin32

# 执行打包
pyinstaller build.spec

# 或直接命令行打包
pyinstaller --onefile --console --name GdpostClient --hidden-import win32service --hidden-import win32serviceutil --hidden-import win32event --hidden-import servicemanager main_cli.py
```

打包产物：`dist/GdpostClient.exe`

### 创建安装程序（可选）

1. 安装 [Inno Setup](https://jrsoftware.org/isinfo.php)
2. 打开 `installer.iss`
3. 点击 **Build** -> **Compile**
4. 输出：`installer_output/GDPost_DT_Client_Setup_v1.0.0.exe`

### 部署为 Windows 服务

```cmd
# 安装并启动服务（管理员权限）
GdpostClient.exe install

# 查看服务状态
sc query GdpostClient

# 停止服务
net stop GdpostClient

# 卸载服务
GdpostClient.exe uninstall
```

更多打包细节参考 [BUILD.md](BUILD.md)。

## 运行模式

### 模式一：完整抓包模式（推荐）

**前提**：管理员权限 + WinDivert 驱动可用

**功能**：
- 实时网络抓包
- 智能规则匹配
- 请求/响应自动关联
- 数据实时上报

### 模式二：仅轮询模式（降级）

**前提**：无管理员权限或驱动不可用

**功能**：
- 定时获取规则
- 无抓包功能
- 基础日志记录

## 技术栈

| 层级 | 技术选型 |
|------|----------|
| 开发语言 | Python 3.11 |
| 抓包驱动 | WinDivert（pydivert） |
| HTTP 客户端 | http.client + urllib3 |
| 加密算法 | cryptography（RSA） |
| 配置管理 | python-dotenv |
| 打包工具 | PyInstaller |
| 安装程序 | Inno Setup |
| 操作系统 | Windows（需管理员权限） |

## 业务价值

1. **透明采集**：用户无感知，不影响浏览器正常使用
2. **实时上报**：数据捕获后立即上报服务端处理
3. **智能匹配**：只采集配置的接口，过滤无关流量
4. **安全可靠**：RSA 签名认证，防止伪造和抵赖
5. **高可用**：支持降级模式，保证核心功能可用
6. **易于部署**：提供安装程序，一键安装运行

## 依赖服务端功能

| 客户端功能 | 依赖服务端接口 | 说明 |
|-----------|----------------|------|
| 规则获取 | `GET /api/v1/api-configs/login` | 获取接口捕获规则 |
| 数据上报 | `POST /api/v1/capture/upload` | 上报捕获的请求/响应数据 |
| 身份认证 | RSA 签名验证 | 服务端验证客户端身份 |

## 风险与注意事项

1. **管理员权限**：WinDivert 驱动需要管理员权限才能加载
2. **驱动兼容性**：需测试不同 Windows 版本的兼容性
3. **网络性能**：高并发场景可能丢包，需监控丢包率
4. **安全合规**：抓包涉及用户隐私，需合规审查

## 许可证

MIT License
