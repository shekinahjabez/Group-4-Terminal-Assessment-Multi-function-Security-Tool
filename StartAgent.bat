@echo off
:: StartAgent.bat — SecureKit Local Agent setup script (Windows)
:: Architecture: direct localhost (http://127.0.0.1:8765) — no ngrok required.
:: ngrok is OPTIONAL: only needed if you want to access the agent from another device.
::
:: For live packet capture (Traffic Analyzer), right-click this file and
:: choose "Run as Administrator". For port scanning only, double-click is fine.

title SecureKit Local Agent Setup

echo.
echo  =====================================================
echo   SecureKit Local Agent - Windows Setup
echo  =====================================================
echo.

:: ── Resolve script directory ──────────────────────────────────────────────────
:: %~dp0 gives the directory containing this .bat file, with trailing backslash
set "SCRIPT_DIR=%~dp0"
echo  [INFO] Script directory: %SCRIPT_DIR%
echo.

:: ── Check Python ──────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo.
    echo  Install Python 3.11 or newer from https://python.org
    echo  Check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VER=%%i
echo  [OK] Python found: %PYTHON_VER%
echo.

:: ── Create or reuse virtualenv ────────────────────────────────────────────────
set "VENV_DIR=%SCRIPT_DIR%.venv"
if exist "%VENV_DIR%\Scripts\python.exe" (
    echo  [OK] Existing virtualenv found at .venv — reusing it.
) else (
    echo  [INFO] Creating virtualenv at .venv ...
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtualenv.
        pause
        exit /b 1
    )
    echo  [OK] Virtualenv created.
)
echo.

:: ── Install packages into venv ────────────────────────────────────────────────
echo  [INFO] Installing required packages into virtualenv...
"%VENV_DIR%\Scripts\pip.exe" install --quiet --upgrade pip
"%VENV_DIR%\Scripts\pip.exe" install --quiet fastapi "uvicorn[standard]" scapy pydantic bcrypt zxcvbn
if errorlevel 1 (
    echo  [ERROR] Package installation failed. Check your internet connection.
    pause
    exit /b 1
)
echo  [OK] Packages installed.
echo.

:: ── Verify local_agent.py exists ─────────────────────────────────────────────
if not exist "%SCRIPT_DIR%local_agent.py" (
    echo  [ERROR] local_agent.py not found in %SCRIPT_DIR%
    echo  Make sure you downloaded local_agent.py into the same folder as this script.
    echo.
    pause
    exit /b 1
)

:: ── Start local agent in a new window ────────────────────────────────────────
echo  [INFO] Starting local agent on http://127.0.0.1:8765 ...
echo         (For live packet capture, this window must be run as Administrator)
echo.
start "SecureKit Agent" cmd /k "cd /d "%SCRIPT_DIR%" && "%VENV_DIR%\Scripts\python.exe" local_agent.py"

:: ── ngrok — OPTIONAL: only needed for multi-device access ─────────────────────
::
::   ngrok is NOT required for normal use. Chrome and Edge connect to the agent
::   at http://127.0.0.1:8765 directly — no URL to copy or paste.
::
::   Only use ngrok if you need to access the agent from another device
::   (e.g. a phone or a remote teammate). In that case:
::     1. Download ngrok from https://ngrok.com/download
::     2. Register a free account and run: ngrok config add-authtoken YOUR_TOKEN
::     3. Run in a separate window: ngrok http 8765
::     4. Paste the https:// forwarding URL into the Agent URL field on the site
::
:: Do NOT auto-start ngrok — it is optional and requires a registered authtoken.

:: ── Summary ───────────────────────────────────────────────────────────────────
echo.
echo  =====================================================
echo   Setup complete!
echo  =====================================================
echo.
echo  A new window has opened with the SecureKit agent.
echo  Leave that window running while you use the site.
echo.
echo  What to do next:
echo.
echo    1. Open Chrome or Edge (required — Firefox blocks localhost from HTTPS)
echo    2. Go to https://securekit-whk3.onrender.com
echo    3. Open Port Scanner or Traffic Analyzer
echo    4. Click "Enable Local Scanning" — the site connects automatically
echo       to http://127.0.0.1:8765 (no URL to copy or paste)
echo.
echo  To stop the agent: close the SecureKit Agent window or press Ctrl+C in it.
echo.
pause
