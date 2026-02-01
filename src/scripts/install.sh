#!/bin/bash

# This script must be run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Variables
AGENT_USER="hidps-agent"
AGENT_GROUP="hidps-agent"
AGENT_HOME="/usr/local/hidps-agent"
VENV_PATH="$AGENT_HOME/venv"
AGENT_SCRIPT="agent.py"
SUDOERS_FILE="/etc/sudoers.d/hidps-agent"

# Create user and group
echo "Creating user and group '$AGENT_USER'..."
groupadd --system "$AGENT_GROUP"
useradd --system --no-create-home --gid "$AGENT_GROUP" "$AGENT_USER"

# Install dependencies (Debian/Ubuntu)
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 python3-pip python3-venv auditd

# Create agent directory
echo "Creating agent directory at $AGENT_HOME..."
mkdir -p "$AGENT_HOME"

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "$VENV_PATH"

# Install Python packages
echo "Installing Python packages..."
"$VENV_PATH/bin/pip" install psutil websockets

# Copy agent files
echo "Copying agent files..."
# This assumes the script is run from the root of the project
cp src/agent.py "$AGENT_HOME/$AGENT_SCRIPT"
chown -R "$AGENT_USER:$AGENT_GROUP" "$AGENT_HOME"
chmod -R 750 "$AGENT_HOME"

# Create sudoers file
echo "Creating sudoers file..."
cat > "$SUDOERS_FILE" << EOF
# Sudo permissions for the HIDPS Agent
$AGENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw status, /usr/bin/journalctl *, /sbin/auditctl *
EOF
chmod 440 "$SUDOERS_FILE"

# Create systemd service file
echo "Creating systemd service file..."
cat > /etc/systemd/system/hidps-agent.service << EOF
[Unit]
Description=HIDPS Agent
After=network.target

[Service]
User=$AGENT_USER
Group=$AGENT_GROUP
WorkingDirectory=$AGENT_HOME
ExecStart=$VENV_PATH/bin/python3 $AGENT_HOME/$AGENT_SCRIPT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
echo "Enabling and starting the HIDPS Agent service..."
systemctl daemon-reload
systemctl enable hidps-agent.service
systemctl start hidps-agent.service

echo "Installation complete."
