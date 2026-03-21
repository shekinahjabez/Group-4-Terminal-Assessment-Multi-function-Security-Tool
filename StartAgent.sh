#!/bin/bash

echo ""
echo " ====================================================="
echo "  SecureKit Local Agent - Mac/Linux Auto Setup"
echo " ====================================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo " [ERROR] Python 3 is not installed."
    echo " Install it from https://python.org or via brew: brew install python3"
    exit 1
fi
echo " [OK] Python3 found: $(python3 --version)"
echo ""

# Install packages
echo " Installing required packages..."
python3 -m pip install fastapi uvicorn scapy pydantic --quiet
echo " [OK] Packages installed"
echo ""

# Check ngrok
if ! command -v ngrok &> /dev/null; then
    echo " [INFO] ngrok not found."
    if command -v brew &> /dev/null; then
        echo " Installing ngrok via Homebrew..."
        brew install ngrok/ngrok/ngrok
    else
        echo " Please download ngrok from https://ngrok.com/download"
        echo " Then run: ngrok http 8765"
    fi
else
    echo " [OK] ngrok found: $(ngrok --version)"
fi
echo ""

# Start local agent in background
echo " Starting local agent..."
osascript -e 'tell application "Terminal" to do script "cd '"$(pwd)"' && sudo python3 local_agent.py"' 2>/dev/null || \
    gnome-terminal -- bash -c "cd $(pwd) && sudo python3 local_agent.py; exec bash" 2>/dev/null || \
    (sudo python3 local_agent.py &)

sleep 2

# Start ngrok
echo " Starting ngrok tunnel..."
osascript -e 'tell application "Terminal" to do script "ngrok http 8765"' 2>/dev/null || \
    gnome-terminal -- bash -c "ngrok http 8765; exec bash" 2>/dev/null || \
    (ngrok http 8765 &)

echo ""
echo " ====================================================="
echo "  Setup complete!"
echo " ====================================================="
echo ""
echo " Two terminal windows have opened:"
echo ""
echo "  1. SecureKit Agent  - Keep this running (needs sudo)"
echo "  2. SecureKit ngrok  - Copy the https:// URL shown"
echo ""
echo " Then on the SecureKit website:"
echo "  - Paste the ngrok https:// URL into the Agent URL field"
echo "  - Click Connect, then Enable Local Scanning"
echo ""