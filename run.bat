@echo off
chcp 65001 >nul
title gdpost-dt-client
echo ==========================================
echo    gdpost-dt-client - Windows Transparent Proxy Client
echo ==========================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges required!
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: Change to script directory
cd /d "%~dp0"

:: Check if virtual environment exists
if not exist "venv\Scripts\activate.bat" (
    echo [INFO] Virtual environment not found, creating...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
)

:: Activate virtual environment
call venv\Scripts\activate.bat

:: Check if dependencies are installed
pip show pydivert >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [INFO] Starting gdpost-dt-client...
echo.

:: Run the client
python -m src.main

:: Pause on error
if errorlevel 1 (
    echo.
    echo [ERROR] Client exited with error
    pause
)

deactivate
