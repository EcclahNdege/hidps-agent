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
SUDOERS_FILE="/etc/sudoers.d/hidps-agent"
SERVICE_FILE="/etc/systemd/system/hidps-agent.service"

echo "Stopping and disabling the HIDPS Agent service..."
systemctl stop hidps-agent.service
systemctl disable hidps-agent.service

echo "Removing systemd service file..."
rm -f "$SERVICE_FILE"
systemctl daemon-reload

echo "Removing sudoers file..."
rm -f "$SUDOERS_FILE"

echo "Removing agent directory..."
rm -rf "$AGENT_HOME"

echo "Removing user and group '$AGENT_USER'..."
userdel "$AGENT_USER"
groupdel "$AGENT_GROUP"

echo "Uninstallation complete."
