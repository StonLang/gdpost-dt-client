# gdpost-dt-client

基于 WinDivert 的 Windows 透明代理客户端。

## 项目概述

`gdpost-dt-client` 是一个 Windows 平台的透明代理客户端，通过 WinDivert 驱动在内核层捕获网络流量，根据配置的规则智能分流 HTTP/HTTPS 请求。

## 核心特性

- **内核层流量捕获**：使用 WinDivert 在 Windows 内核层透明捕获网络流量
- **智能流量分流**：根据规则配置，自动判断请求是否走代理
- **HTTP/HTTPS 完整支持**：支持 HTTP 明文代理和 HTTPS CONNECT 隧道
- **动态规则同步**：每 5 分钟自动从配置服务器刷新代理规则
- **请求标记追踪**：代理请求自动添加 `x-api-id` 头部，便于追踪和统计
- **零配置感知**：对浏览器和其他应用程序完全透明，无需修改代理设置

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        gdpost-dt-client                          │
│                     (Windows 透明代理客户端)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐ │
│  │ Traffic Capturer │  │   Server Client  │  │ Proxy Handler   │ │
│  │  (WinDivert)     │  │   (API Client)   │  │  (HTTP Proxy)   │ │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬────────┘ │
│           │                   │                    │             │
│           │ Capture           │ Get Config         │ Forward     │
│           │                   │                    │             │
│  ┌────────▼─────────┐         │              ┌─────▼──────┐      │
│  │   Packet Parser  │         │              │  Upstream  │      │
│  │  (HTTP Parser)   │         │              │   Proxy    │      │
│  └────────┬─────────┘         │              └────────────┘      │
│           │                   │                                  │
│           └───────────────────┼──────────────────────────────────┘
│                               │
│  ┌────────────────────────────▼────────────────────────────┐     │
│  │              Rule Matcher (Config Refresh)                │   │
│  └───────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────── ┘
           │
           │ WinDivert Driver (Kernel Layer)
           │
┌──────────▼───────────────────────────────────────────────────┐
│                   Network Stack (Windows Kernel)             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ Browser  │  │   App    │  │   App    │  │   App    │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
└──────────────────────────────────────────────────────────────┘
```

## 模块说明

### 1. Traffic Capturer (`src/traffic_capturer.py`)

使用 WinDivert 捕获网络流量的核心模块。

**功能**：
- 在内核层拦截 HTTP/HTTPS 出入站流量
- 解析 TCP 数据包，提取 HTTP 请求/响应信息
- 回调机制通知代理处理器

**关键类**：
- `TrafficCapturer`: 流量捕获主类

### 2. Server Client (`src/api_client.py`)

与配置服务器通信的客户端模块。

**功能**：
- 从配置服务器获取代理规则配置
- 每 5 分钟自动刷新配置
- 规则匹配算法

**关键类**：
- `ServerClient`: API 客户端主类
- `ApiConfig`: 代理规则配置项

### 3. Proxy Handler (`src/proxy_handler.py`)

HTTP 代理请求处理模块。

**功能**：
- 本地 HTTP 代理服务器
- 请求匹配和转发逻辑
- 添加 `x-api-id` 代理头部
- HTTPS CONNECT 隧道支持

**关键类**：
- `ProxyHandler`: HTTP 请求处理器
- `ProxyServer`: 代理服务器
- `TransparentProxyHandler`: 透明代理处理器

### 4. Configuration (`src/config.py`)

配置管理模块。

**功能**：
- 环境变量加载
- 默认配置管理
- 配置验证

### 5. Main Entry (`src/main.py`)

程序入口和生命周期管理。

**功能**：
- 初始化各模块
- 启动流量捕获和代理服务
- 信号处理和优雅退出

## 工作流程

```
1. 启动阶段
   └─> 从配置服务器获取代理规则
   └─> 启动本地代理服务器
   └─> 启动 WinDivert 流量捕获

2. 请求处理流程
   
   浏览器 ──HTTP──> WinDivert (内核)
                      │
                      ▼
               Packet Capturer
                      │
                      ▼
               HTTP Parser ──> 提取 (Method, Host, Port, Path)
                      │
                      ▼
               Rule Matcher ──> 对比代理规则
                      │
              ┌────────┴────────┐
              │                 │
           Match            No Match
              │                 │
              ▼                 ▼
       Add x-api-id          Direct
       Forward to            Connect
       Proxy Server          Target
              │                 │
              └────────┬────────┘
                       ▼
                  Return Response
                       │
                       ▼
                    Browser

3. 配置刷新
   └─> 每 5 分钟调用配置服务器接口
   └─> 更新本地代理规则缓存
```

## 项目结构

```
gdpost-dt-client/
├── src/                          # 源代码目录
│   ├── __init__.py              # 包初始化
│   ├── config.py                # 配置管理模块
│   ├── api_client.py            # 配置服务器 API 客户端
│   ├── traffic_capturer.py      # WinDivert 流量捕获
│   ├── proxy_handler.py         # 代理转发逻辑
│   └── main.py                  # 主程序入口
├── venv/                         # 虚拟环境（本地创建）
├── .env.example                  # 环境变量示例配置
├── .env                          # 实际环境变量配置（不提交）
├── requirements.txt              # Python 依赖列表
├── run.bat                       # Windows 启动脚本
└── README.md                     # 项目文档
```

## 安装指南

### 系统要求

- **操作系统**: Windows 10/11 (64位)
- **Python**: 3.8+
- **权限**: 需要管理员权限（WinDivert 驱动要求）
- **网络**: 需要访问配置服务器的网络连接

### 安装步骤

1. **进入项目目录**

```bash
cd G:\vscode-workspace\gdpost-dt-client
```

2. **创建虚拟环境**

```bash
cd gdpost-dt-client
python -m venv venv
venv\Scripts\activate
```

3. **安装依赖**

```bash
pip install -r requirements.txt
```

**注意**: WinDivert 驱动会在首次运行时自动安装，需要管理员权限。

## 配置说明

### 环境变量配置

复制示例配置文件并修改：

```bash
copy .env.example .env
notepad .env
```

### 配置项说明

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `SERVER_HOST` | localhost | 配置服务器主机地址 |
| `SERVER_PORT` | 8000 | 配置服务器端口 |
| `SERVER_API_BASE` | /api/v1 | API 基础路径 |
| `API_KEY` | - | API 认证密钥 |
| `CLIENT_ID` | - | 客户端标识 |
| `DIVERT_FILTER` | tcp | WinDivert 过滤规则（默认全部 TCP，不限制 IP/端口） |
| `PROXY_HOST` | 127.0.0.1 | 上级代理主机 |
| `PROXY_PORT` | 1080 | 上级代理端口 |
| `CONFIG_REFRESH_INTERVAL` | 300 | 配置刷新间隔（秒） |
| `API_ID_HEADER` | x-api-id | API ID 头部名称 |
| `LOG_LEVEL` | INFO | 日志级别 |
| `CONNECT_TIMEOUT` | 30 | 连接超时（秒） |

`DIVERT_FILTER` 使用 `tcp` 时，会捕获本机**全部 TCP**（不限制源/目的 IP 与端口，含入站与出站），便于关联请求与响应。若只希望抓取出站、降低开销，可改为 `tcp and outbound`。

### 示例配置

```ini
# 配置服务器
SERVER_HOST=192.168.1.100
SERVER_PORT=8000
API_KEY=your-secret-api-key
CLIENT_ID=client-windows-01

# 上级代理服务器（暂用本地，后续更换）
PROXY_HOST=127.0.0.1
PROXY_PORT=1080

# 日志级别
LOG_LEVEL=INFO
```

## 使用说明

### 方法一：使用启动脚本（推荐）

双击运行 `run.bat`，脚本会自动：
1. 检查并请求管理员权限
2. 激活虚拟环境
3. 检查并安装依赖
4. 启动客户端

```bash
run.bat
```

### 方法二：命令行手动启动

**需要以管理员身份运行 PowerShell**

```powershell
# 以管理员身份运行 PowerShell
# 然后执行:
cd G:\vscode-workspace\gdpost-dt-client
venv\Scripts\activate
python -m src.main
```

### 方法三：创建快捷方式

创建带管理员权限的快捷方式：

1. 右键 `run.bat` -> 发送到桌面快捷方式
2. 右键快捷方式 -> 属性 -> 高级 -> 勾选"以管理员身份运行"

### 停止客户端

- 在运行窗口按 `Ctrl + C`
- 或关闭 PowerShell 窗口

## 规则匹配逻辑

### 匹配字段

| 字段 | 类型 | 匹配方式 | 示例 |
|------|------|---------|------|
| `request_method` | string | 精确匹配或 `*` 通配符 | `GET`, `POST`, `*`, `PUT` |
| `request_protocol` | string | 精确匹配或 `*` | `http`, `https`, `*` |
| `request_host` | string | 精确匹配或子域名通配 | `example.com`, `*.example.com`, `*` |
| `request_port` | int | 精确匹配或 `0`（任意） | `80`, `443`, `0` |
| `request_path` | string | 前缀匹配或通配符 | `/api/*`, `/v1/*`, `*` |

### 匹配示例

**规则**: 
```json
{
  "api_id": "api-001",
  "request_method": "GET",
  "request_protocol": "http",
  "request_host": "api.example.com",
  "request_port": 80,
  "request_path": "/api/*"
}
```

**匹配情况**:
- ✅ `GET http://api.example.com/api/users` - 匹配
- ✅ `GET http://api.example.com/api/items/1` - 匹配
- ❌ `POST http://api.example.com/api/users` - 方法不匹配
- ❌ `GET http://other.com/api/users` - 主机不匹配
- ❌ `GET http://api.example.com:8080/api/users` - 端口不匹配

**子域名匹配**:
```json
{
  "request_host": "*.example.com"
}
```
匹配: `api.example.com`, `www.example.com`, `sub.example.com`

## 代理转发机制

### HTTP 请求

1. 捕获请求 `GET http://target.com/path`
2. 匹配规则 `api_id=xxx`
3. 添加头部 `x-api-id: xxx`
4. 转发到代理服务器
5. 代理服务器转发到目标
6. 返回响应

### HTTPS 请求 (CONNECT 隧道)

1. 捕获 `CONNECT target.com:443`
2. 匹配规则
3. 与代理服务器建立 CONNECT 隧道，携带 `x-api-id`
4. 隧道建立后，双向转发加密数据

## 日志说明

### 日志级别

- `DEBUG`: 详细的数据包信息和匹配过程
- `INFO`: 启动/停止信息、配置刷新、代理转发记录
- `WARNING`: 配置刷新失败、连接警告
- `ERROR`: 错误和异常

### 查看日志

```powershell
# 在 PowerShell 中运行，日志直接输出到控制台
python -m src.main

# 保存日志到文件
python -m src.main 2>&1 | Tee-Object -FilePath client.log
```

## 故障排查

### 问题：无法安装 pydivert

**解决**: 确保以管理员权限运行 pip，且已安装 Visual C++ Redistributable

### 问题：WinDivert 启动失败

**可能原因**: 
- 未以管理员权限运行
- 驱动签名验证失败（测试模式未开启）

**解决**:
```powershell
# 以管理员运行
# 启用测试模式（开发环境）
bcdedit /set testsigning on
# 重启电脑
```

### 问题：无法连接到配置服务器

**检查**:
1. 配置服务器是否启动
2. 防火墙是否放行端口
3. `.env` 中 `SERVER_HOST` 和 `SERVER_PORT` 是否正确

### 问题：流量未被代理

**检查**:
1. 检查配置服务器返回的规则是否正确
2. 检查日志中的匹配过程
3. 确认 `is_active` 为 `true`

## 安全注意事项

1. **权限控制**: 客户端需要管理员权限运行，请确保在安全环境中部署
2. **API 密钥**: 妥善保管 `API_KEY`，不要硬编码在代码中
3. **代理循环**: 确保代理服务器地址不在代理规则中，避免无限循环
4. **驱动安全**: WinDivert 是内核驱动，仅从可信来源安装

## 开发计划

- [ ] 支持 SOCKS5 代理协议
- [ ] 添加流量统计和上报功能
- [ ] 支持 WebSocket 代理
- [ ] GUI 管理界面
- [ ] 支持 Windows 服务方式运行
- [ ] 配置文件热重载

## License

MIT License

Copyright (c) 2024 StonLang
