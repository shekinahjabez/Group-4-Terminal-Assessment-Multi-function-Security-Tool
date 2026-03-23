#!/bin/bash
# StartAgent.sh — SecureKit Local Agent setup script (Mac/Linux)
# Architecture: direct localhost (http://127.0.0.1:8765) — no ngrok required.
# ngrok is OPTIONAL: only needed if you want to access the agent from another device.

echo ""
echo " ====================================================="
echo "  SecureKit Local Agent - Mac/Linux Setup"
echo " ====================================================="
echo ""

# ── Resolve script directory ───────────────────────────────────────────────────
# Works whether the user runs: ./StartAgent.sh, bash StartAgent.sh, or /abs/path/StartAgent.sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo " [INFO] Script directory: $SCRIPT_DIR"
echo ""

# ── Check Python ───────────────────────────────────────────────────────────────
if ! command -v python3 &> /dev/null; then
    echo " [ERROR] Python 3 is not installed."
    echo "         Install from https://python.org or via your package manager."
    echo "         macOS: brew install python3"
    echo "         Ubuntu/Debian: sudo apt install python3 python3-venv"
    exit 1
fi
PYTHON_VERSION="$(python3 --version 2>&1)"
echo " [OK] Python found: $PYTHON_VERSION"
echo ""

# ── Create or reuse virtualenv ─────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"
if [ -d "$VENV_DIR" ]; then
    echo " [OK] Existing virtualenv found at .venv — reusing it."
else
    echo " [INFO] Creating virtualenv at .venv ..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo " [ERROR] Failed to create virtualenv."
        echo "         On Ubuntu/Debian you may need: sudo apt install python3-venv"
        exit 1
    fi
    echo " [OK] Virtualenv created."
fi
echo ""

# ── Install packages into venv ─────────────────────────────────────────────────
VENV_PIP="$VENV_DIR/bin/pip"
VENV_PYTHON="$VENV_DIR/bin/python"

echo " [INFO] Installing required packages into virtualenv..."
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet fastapi "uvicorn[standard]" scapy pydantic bcrypt zxcvbn
if [ $? -ne 0 ]; then
    echo " [ERROR] Package installation failed. Check your internet connection."
    exit 1
fi
echo " [OK] Packages installed."
echo ""

# ── Verify local_agent.py exists ──────────────────────────────────────────────
if [ ! -f "$SCRIPT_DIR/local_agent.py" ]; then
    echo " [ERROR] local_agent.py not found in $SCRIPT_DIR"
    echo "         Make sure you downloaded local_agent.py into the same folder as this script."
    exit 1
fi

# ── Verify src/ package tree exists ───────────────────────────────────────────
if [ ! -d "$SCRIPT_DIR/src" ]; then
    echo " [ERROR] src/ directory not found in $SCRIPT_DIR"
    echo "         The local agent requires the full repository, not just the agent scripts."
    echo "         Clone or download the complete repo, then run this script from the repo root."
    exit 1
fi

# ── Track whether windows were opened ─────────────────────────────────────────
AGENT_WINDOW_OPENED=false
NGROK_WINDOW_OPENED=false

# ── Start local agent ─────────────────────────────────────────────────────────
echo " [INFO] Starting local agent..."
echo "        (Live packet capture requires sudo — enter your password if prompted)"
echo ""

if command -v osascript &> /dev/null; then
    # macOS — open in a new Terminal window
    osascript -e "tell application \"Terminal\" to do script \"echo 'SecureKit Local Agent'; cd '$SCRIPT_DIR' && sudo '$VENV_PYTHON' local_agent.py\"" 2>/dev/null
    if [ $? -eq 0 ]; then
        AGENT_WINDOW_OPENED=true
        echo " [OK] Agent window opened (Terminal.app)"
    fi
elif command -v gnome-terminal &> /dev/null; then
    # Linux — GNOME Terminal
    gnome-terminal -- bash -c "echo 'SecureKit Local Agent'; cd '$SCRIPT_DIR' && sudo '$VENV_PYTHON' local_agent.py; exec bash" 2>/dev/null
    if [ $? -eq 0 ]; then
        AGENT_WINDOW_OPENED=true
        echo " [OK] Agent window opened (gnome-terminal)"
    fi
elif command -v xterm &> /dev/null; then
    # Fallback — xterm
    xterm -title "SecureKit Agent" -e "cd '$SCRIPT_DIR' && sudo '$VENV_PYTHON' local_agent.py" &
    if [ $? -eq 0 ]; then
        AGENT_WINDOW_OPENED=true
        echo " [OK] Agent window opened (xterm)"
    fi
fi

if [ "$AGENT_WINDOW_OPENED" = false ]; then
    echo " [INFO] Could not open a new terminal window."
    echo "        Run this command manually in a new terminal:"
    echo ""
    echo "          cd '$SCRIPT_DIR'"
    echo "          sudo '$VENV_PYTHON' local_agent.py"
    echo ""
fi

# ── ngrok — OPTIONAL: only needed for multi-device access ─────────────────────
echo ""
echo " ── ngrok (OPTIONAL) ──────────────────────────────────────────────────────"
echo " ngrok is NOT required for normal use. The SecureKit website (Chrome/Edge)"
echo " connects to the agent at http://127.0.0.1:8765 directly."
echo ""
echo " Only install ngrok if you need to access the agent from another device"
echo " (e.g. phone, remote teammate). Skip this section otherwise."
echo " ──────────────────────────────────────────────────────────────────────────"
echo ""

if command -v ngrok &> /dev/null; then
    echo " [OK] ngrok found: $(ngrok --version)"
    echo " [INFO] To start ngrok (only if you need multi-device access):"
    echo "        ngrok http 8765"
    echo ""
    # Do NOT auto-start ngrok — it is optional.
    # Uncomment the lines below if you want to auto-start the ngrok window:
    # if command -v osascript &> /dev/null; then
    #     osascript -e 'tell application "Terminal" to do script "ngrok http 8765"' 2>/dev/null
    #     NGROK_WINDOW_OPENED=true
    # elif command -v gnome-terminal &> /dev/null; then
    #     gnome-terminal -- bash -c "ngrok http 8765; exec bash" 2>/dev/null
    #     NGROK_WINDOW_OPENED=true
    # fi
else
    echo " [INFO] ngrok is not installed. That is fine for normal use."
    echo "        If you want ngrok for multi-device access:"
    echo "          macOS:  brew install ngrok/ngrok/ngrok"
    echo "          Linux:  https://ngrok.com/download"
    echo "          Then:   ngrok config add-authtoken YOUR_TOKEN"
    echo "                  ngrok http 8765"
    echo ""
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo " ====================================================="
echo "  Setup complete!"
echo " ====================================================="
echo ""

if [ "$AGENT_WINDOW_OPENED" = true ]; then
    echo " A new terminal window has opened with the SecureKit agent."
    echo " Enter your sudo password if prompted (required for live capture)."
    echo ""
fi

echo " What to do next:"
echo ""
echo "  1. Open Chrome or Edge (required — Firefox blocks localhost from HTTPS)"
echo "  2. Go to https://securekit-whk3.onrender.com"
echo "  3. Open Port Scanner or Traffic Analyzer"
echo "  4. Click 'Enable Local Scanning' — the site will connect automatically"
echo "     to http://127.0.0.1:8765 (no URL to copy or paste)"
echo ""

if [ "$AGENT_WINDOW_OPENED" = false ]; then
    echo " IMPORTANT: The agent window could not be opened automatically."
    echo " You must start it manually before using the site:"
    echo ""
    echo "   cd '$SCRIPT_DIR'"
    echo "   sudo '$VENV_PYTHON' local_agent.py"
    echo ""
fi

echo " To stop the agent: press Ctrl+C in the agent terminal window."
echo ""
