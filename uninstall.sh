#!/bin/bash

INSTALL_DIR="/opt/hidps-agent"
SERVICE_NAME="hidps-agent"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root.${NC}"
  exit 1
fi

echo "Stopping service..."
systemctl stop $SERVICE_NAME

echo "Disabling service..."
systemctl disable $SERVICE_NAME

echo "Removing service file..."
rm /etc/systemd/system/$SERVICE_NAME.service
systemctl daemon-reload

echo "Removing installation files..."
rm -rf "$INSTALL_DIR"

echo -e "${GREEN}Agent uninstalled successfully.${NC}"
echo "Note: Dependencies (ufw, python3) were NOT removed to avoid breaking other system tools."