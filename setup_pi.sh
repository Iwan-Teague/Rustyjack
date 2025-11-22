#!/bin/bash
# Run this script on your Raspberry Pi after copying the binaries
# Usage: ssh root@192.168.0.48 'bash -s' < setup_pi.sh

echo "============================================"
echo "Rustyjack Setup on Raspberry Pi"
echo "============================================"
echo ""

# Make binaries executable
echo "[STEP 1/5] Setting executable permissions..."
chmod +x /usr/local/bin/rustyjack-core
chmod +x /usr/local/bin/rustyjack-ui
echo "[OK] Permissions set"

# Verify binaries work
echo ""
echo "[STEP 2/5] Verifying binaries..."
if /usr/local/bin/rustyjack-core --version 2>/dev/null; then
    echo "[OK] rustyjack-core is working"
else
    echo "[WARN] rustyjack-core version check failed (may be normal)"
fi

# Create necessary directories
echo ""
echo "[STEP 3/5] Creating directories..."
mkdir -p /root/Rustyjack/loot/{Nmap,Responder,DNSSpoof,MITM}
mkdir -p /root/Rustyjack/wifi/profiles
echo "[OK] Directories created"

# Set up systemd service
echo ""
echo "[STEP 4/5] Setting up systemd service..."
cd /root/Rustyjack
systemctl daemon-reload
systemctl enable rustyjack.service
echo "[OK] Service enabled"

# Start service
echo ""
echo "[STEP 5/5] Starting Rustyjack service..."
systemctl start rustyjack.service
sleep 2

# Check status
echo ""
echo "Service Status:"
systemctl status rustyjack.service --no-pager

echo ""
echo "============================================"
echo "[SUCCESS] Rustyjack setup complete!"
echo "============================================"
echo ""
echo "The LCD should now display the Rustyjack menu."
echo ""
echo "Useful commands:"
echo "  systemctl status rustyjack    - Check service status"
echo "  systemctl restart rustyjack   - Restart service"
echo "  journalctl -u rustyjack -f    - View logs"
echo ""
