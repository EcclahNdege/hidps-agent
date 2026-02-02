#!/bin/bash

# Configuration
INSTALL_DIR="/opt/hidps-agent"
SERVICE_NAME="hidps-agent"
DEFAULT_BACKEND="ws://localhost:3000"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
  exit 1
fi

# Parse arguments
AGENT_ID=""
BACKEND_URL="$DEFAULT_BACKEND"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --agent-id) AGENT_ID="$2"; shift ;;
        --backend-url) BACKEND_URL="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$AGENT_ID" ]; then
    echo -e "${RED}Error: --agent-id is required.${NC}"
    echo "Usage: sudo ./install.sh --agent-id <your-uuid> [--backend-url <url>]"
    exit 1
fi

echo -e "${GREEN}Starting installation for Agent: $AGENT_ID${NC}"

# 1. Install System Dependencies
echo "Installing system packages..."
apt-get update -qq
apt-get install -y python3-pip python3-venv ufw build-essential python3-dev

# Ensure UFW is installed but don't enable it yet (agent will manage it)
if ! command -v ufw &> /dev/null; then
    echo "Installing UFW..."
    apt-get install -y ufw
fi

# 2. Setup Directory and Files
echo "Setting up installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp agent.py "$INSTALL_DIR/main.py"

# 3. Setup Python Environment
echo "Creating virtual environment..."
if [ -d "$INSTALL_DIR/venv" ]; then
    rm -rf "$INSTALL_DIR/venv"
fi
python3 -m venv "$INSTALL_DIR/venv"

echo "Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install psutil watchdog websockets asyncio

# 4. Create Systemd Service
echo "Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=HIDPS Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="AGENT_ID=$AGENT_ID"
Environment="BACKEND_URL=$BACKEND_URL"
# Force stdout to be unbuffered
Environment="PYTHONUNBUFFERED=1"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 5. Enable and Start Service
echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo -e "${GREEN}Installation Complete!${NC}"
echo "-----------------------------------"
echo "Status: systemctl status $SERVICE_NAME"
echo "Logs:   journalctl -u $SERVICE_NAME -f"
echo "Agent ID: $AGENT_ID"
echo "Backend:  $BACKEND_URL"