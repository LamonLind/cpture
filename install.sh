#!/bin/bash
# One-click install script for Cpture

set -e

echo "============================================"
echo "  Cpture Installation Script"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "[1/6] Creating directories..."
mkdir -p /var/lib/cpture
mkdir -p /usr/local/bin

echo "[2/6] Installing capture.py..."
cp capture.py /usr/local/bin/capture.py
chmod +x /usr/local/bin/capture.py

echo "[3/6] Installing capture command..."
cp capture /usr/local/bin/capture
chmod +x /usr/local/bin/capture

echo "[4/6] Installing systemd service..."
cp capture.service /etc/systemd/system/capture.service
systemctl daemon-reload

echo "[5/6] Enabling service to start on boot..."
systemctl enable capture.service

echo "[6/6] Starting capture service..."
systemctl start capture.service

echo ""
echo "============================================"
echo "  Installation Complete!"
echo "============================================"
echo ""
echo "Service Status:"
systemctl status capture.service --no-pager -l || true
echo ""
echo "Useful Commands:"
echo "  - View captured hosts:     capture"
echo "  - Check service status:    sudo systemctl status capture"
echo "  - View service logs:       sudo journalctl -u capture -f"
echo "  - Stop service:            sudo systemctl stop capture"
echo "  - Start service:           sudo systemctl start capture"
echo "  - Restart service:         sudo systemctl restart capture"
echo "  - Disable auto-start:      sudo systemctl disable capture"
echo ""
echo "The service will automatically start on system reboot."
echo "Captured hosts are stored in: /var/lib/cpture/captured_hosts.txt"
echo ""
