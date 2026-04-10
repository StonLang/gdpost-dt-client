# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 打包配置 - GDPost DT Client
生成独立 .exe，包含 Windows 服务支持
"""

import os
import sys

# 项目根目录（spec 文件所在目录）
BASE_DIR = os.path.abspath(os.getcwd())

# 添加虚拟环境路径（如果有）
venv_path = os.path.join(BASE_DIR, 'venv', 'Lib', 'site-packages')
if os.path.exists(venv_path):
    sys.path.insert(0, venv_path)

block_cipher = None

# 分析入口文件
a = Analysis(
    ['main_cli.py'],
    pathex=[
        BASE_DIR,
        os.path.join(BASE_DIR, 'src'),
    ],
    binaries=[
        # 包含 WinDivert 驱动（如果有的话）
        # ('WinDivert.dll', '.'),
        # ('WinDivert64.sys', '.'),
    ],
    datas=[
        # 包含 .env 作为默认配置
        ('.env', '.'),
        # 包含 README
        ('README.md', '.'),
        # 包含 src 目录（作为数据文件）
        ('src', 'src'),
    ],
    hiddenimports=[
        # 隐式导入
        'win32service',
        'win32serviceutil',
        'win32event',
        'servicemanager',
        'win32timezone',
        'pywintypes',
        # 客户端依赖
        'requests',
        'urllib3',
        'dotenv',
        'pydivert',
        # 子模块
        'src.api_client',
        'src.config',
        'src.logger',
        'src.proxy_handler',
        'src.traffic_capturer',
        'src.main',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # 排除不需要的模块（减小体积）
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'PyQt5',
        'PyQt6',
        'tkinter',
        'test',
        'unittest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# 处理二进制文件
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# 创建可执行文件
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='GdpostClient',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # 使用 UPX 压缩
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # 显示控制台（服务需要）
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,  # 如果有图标
)

# 构建信息
print(f"打包配置完成")
print(f"输出文件: {os.path.join('dist', 'GdpostClient.exe')}")
