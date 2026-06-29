@echo off
setlocal EnableExtensions
chcp 65001 >nul
title Argus Investigator

set "PROJECT_DIR=%~dp0"
set "URL=http://127.0.0.1:8000"
set "PYTHONIOENCODING=utf-8"
cd /d "%PROJECT_DIR%"

echo.
echo ========================================
echo   Argus Investigator launcher
echo ========================================
echo Project: %PROJECT_DIR%
echo URL:     %URL%
echo.

if not exist ".env" (
    echo [WARN] .env not found. Creating from .env.example...
    if exist ".env.example" copy ".env.example" ".env" >nul
    echo [WARN] Open .env and add GEMINI_API_KEYS before AI search.
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue; if($p){exit 0}else{exit 1}" >nul 2>nul
if not errorlevel 1 (
    echo [OK] Argus is already running. Opening browser...
    start "" "%URL%"
    exit /b 0
)

set "PYTHON_EXE=%PROJECT_DIR%.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [SETUP] Virtual environment not found. Creating .venv...
    if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
        "%LocalAppData%\Programs\Python\Python312\python.exe" -m venv .venv
    ) else (
        python -m venv .venv
    )
)

set "PYTHON_EXE=%PROJECT_DIR%.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [ERROR] Python virtual environment was not created.
    echo Install Python 3.12 and run this file again.
    pause
    exit /b 1
)

if not exist ".venv\.deps-installed" (
    echo [SETUP] Installing Python dependencies...
    "%PYTHON_EXE%" -m pip install --upgrade pip
    if errorlevel 1 goto install_failed
    "%PYTHON_EXE%" -m pip install -r requirements.txt
    if errorlevel 1 goto install_failed
    type nul > ".venv\.deps-installed"
)

if not exist ".venv\.playwright-installed" (
    echo [SETUP] Installing Playwright Chromium...
    "%PYTHON_EXE%" -m playwright install chromium
    if errorlevel 1 goto install_failed
    type nul > ".venv\.playwright-installed"
)

echo [OK] Opening browser in a few seconds...
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 4; Start-Process '%URL%'"

echo [OK] Starting Argus. Keep this window open.
echo Press CTRL+C to stop.
echo.
"%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000

echo.
echo Argus stopped.
pause
exit /b 0

:install_failed
echo.
echo [ERROR] Setup failed. Check internet connection and Python installation.
pause
exit /b 1