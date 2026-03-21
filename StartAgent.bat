@echo off
title SecureKit Local Agent Setup
color 0A

echo.
echo  =====================================================
echo   SecureKit Local Agent - Windows Auto Setup
echo  =====================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed.
    echo.
    echo  Please install Python 3.9+ from https://python.org
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

echo  [OK] Python found
echo.

:: Install required packages
echo  Installing required packages...
echo.
python -m pip install fastapi uvicorn scapy pydantic --quiet
if errorlevel 1 (
    echo  [ERROR] Failed to install packages.
    echo  Try running this script as Administrator.
    pause
    exit /b 1
)
echo  [OK] Packages installed
echo.

:: Check if ngrok is installed
ngrok --version >nul 2>&1
if errorlevel 1 (
    echo  [INFO] ngrok not found. Installing via winget...
    winget install ngrok.ngrok --silent
    if errorlevel 1 (
        echo  [WARN] Could not auto-install ngrok.
        echo  Download it manually from https://ngrok.com/download
        echo  Then run: ngrok http 8765
        echo.
    ) else (
        echo  [OK] ngrok installed
    )
) else (
    echo  [OK] ngrok found
)
echo.

:: Start the local agent in a new window
echo  Starting local agent on http://127.0.0.1:8765 ...
start "SecureKit Agent" cmd /k "python local_agent.py"
timeout /t 2 /nobreak >nul

:: Start ngrok in a new window
echo  Starting ngrok tunnel...
start "SecureKit ngrok" cmd /k "ngrok http 8765"
echo.

echo  =====================================================
echo   Setup complete!
echo  =====================================================
echo.
echo  Two windows have opened:
echo.
echo   1. SecureKit Agent  - Keep this running
echo   2. SecureKit ngrok  - Copy the https:// URL shown
echo.
echo  Then on the SecureKit website:
echo   - Paste the ngrok https:// URL into the Agent URL field
echo   - Click Connect, then Enable Local Scanning
echo.
echo  This window can be closed.
echo.
pause