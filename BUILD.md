# GDPost DT Client - 打包与发布指南

## 一、前置要求

1. **Python 3.12**（与开发环境一致）
2. **pip 包管理工具**
3. **PyInstaller** - 用于打包成 .exe
4. **Inno Setup** - 用于创建安装程序（可选但推荐）

## 二、打包步骤

### 步骤 1：安装打包依赖

```bash
cd g:\vscode-workspace\gdpost-dt-client

# 安装 pyinstaller 和 pywin32
pip install pyinstaller pywin32
```

### 步骤 2：执行打包

```bash
# 使用 spec 文件打包
pyinstaller build.spec

# 或者直接打包（简化版）
pyinstaller --onefile --console --name GdpostClient --hidden-import win32service --hidden-import win32serviceutil --hidden-import win32event --hidden-import servicemanager main_cli.py
```

打包完成后，可执行文件位于 `dist/GdpostClient.exe`

### 步骤 3：测试可执行文件

```bash
# 测试帮助信息
dist\GdpostClient.exe help

# 测试前台运行
dist\GdpostClient.exe run

# 安装为服务（管理员权限）
dist\GdpostClient.exe install

# 检查服务状态
sc query GdpostClient

# 卸载服务
dist\GdpostClient.exe uninstall
```

## 三、创建安装程序（可选）

### 安装 Inno Setup

下载地址：https://jrsoftware.org/isinfo.php

### 编译安装程序

1. 打开 Inno Setup Compiler
2. 打开 `installer.iss` 文件
3. 点击 **Build** → **Compile**
4. 输出文件：`installer_output/GDPost_DT_Client_Setup_v1.0.0.exe`

## 四、最终用户安装流程

### 方法 1：使用安装程序（推荐）

1. 双击运行 `GDPost_DT_Client_Setup_v1.0.0.exe`
2. 以管理员身份运行安装程序
3. 勾选"安装为 Windows 服务"
4. 安装完成后编辑 `.env` 文件配置服务器地址
5. 重启服务应用配置

### 方法 2：手动部署

1. 复制 `GdpostClient.exe` 到目标目录
2. 创建 `.env` 文件配置服务器地址：
   ```
   API_BASE_URL=http://100.194.2.74:9909
   API_KEY=your-api-key
   ```
3. 管理员 CMD 执行：
   ```cmd
   GdpostClient.exe install
   ```

## 五、管理服务

### 命令行管理

```cmd
# 启动服务
net start GdpostClient

# 停止服务
net stop GdpostClient

# 查看状态
sc query GdpostClient

# 使用 GUI 管理（Windows 服务管理器）
services.msc
```

### 日志查看

日志文件位于安装目录的 `logs/` 子目录：
- `service.log` - 服务框架日志
- `app.log` - 应用程序日志

## 六、常见问题

### 1. 服务无法启动

**原因**：WinDivert 驱动需要管理员权限
**解决**：确保以服务方式运行（自动具有系统权限）

### 2. 无法连接服务器

**原因**：`.env` 文件配置错误或服务器未启动
**解决**：检查 `.env` 中的 `API_BASE_URL`，确保服务器可访问

### 3. 打包后找不到模块

**原因**：PyInstaller 未包含隐式导入
**解决**：在 `build.spec` 的 `hiddenimports` 中添加模块

### 4. 服务安装失败

**原因**：非管理员权限运行
**解决**：右键点击选择"以管理员身份运行"

## 七、目录结构

```
gdpost-dt-client/
├── main_cli.py          # 打包入口（服务支持）
├── build.spec           # PyInstaller 配置
├── installer.iss        # Inno Setup 安装脚本
├── BUILD.md             # 本文件
├── dist/                # 打包输出目录
│   └── GdpostClient.exe # 可执行文件
├── installer_output/    # 安装程序输出
│   └── GDPost_DT_Client_Setup_v1.0.0.exe
└── src/                 # 源代码
    ├── main.py
    ├── config.py
    └── ...
```

## 八、一键打包脚本

创建 `build.bat`：

```batch
@echo off
echo ======================================
echo  GDPost DT Client 打包脚本
echo ======================================
echo.

:: 清理旧文件
rmdir /s /q build dist 2>nul

:: 打包
echo [1/3] 正在打包...
pyinstaller build.spec
if errorlevel 1 goto error

:: 测试可执行文件
echo [2/3] 测试可执行文件...
dist\GdpostClient.exe help
if errorlevel 1 goto error

:: 创建安装程序（如果安装了 Inno Setup）
echo [3/3] 创建安装程序...
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
    echo 安装程序创建成功！
) else (
    echo 未找到 Inno Setup，跳过安装程序创建
    echo 可执行文件已生成：dist\GdpostClient.exe
)

echo.
echo ======================================
echo  打包完成！
echo ======================================
goto end

:error
echo.
echo 打包失败！
exit /b 1

:end
pause
```

运行 `build.bat` 即可完成完整打包流程。
