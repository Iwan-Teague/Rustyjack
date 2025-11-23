#!/bin/bash
# Automated setup script for Rustyjack on Pi Zero W 2
# Run this after git pull: sudo ./setup_after_pull.sh

set -e  # Exit on error

echo "=== Rustyjack Setup Script ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root: sudo $0"
    exit 1
fi

cd /root/Rustyjack

echo "[1/5] Cleaning previous builds..."
cargo clean
rm -f */Cargo.lock
rm -f rustyjack-ui/src/display.rs.backup
echo "✓ Clean complete"
echo ""

echo "[2/5] Fixing display.rs for embedded-graphics 0.7..."
if [ -f "fix_display_final.py" ]; then
    python3 fix_display_final.py
    if [ $? -eq 0 ]; then
        echo "✓ display.rs fixed"
    else
        echo "✗ display.rs fix failed"
        exit 1
    fi
else
    echo "⚠ fix_display_final.py not found, skipping..."
fi
echo ""

echo "[3/5] Running install script..."
chmod +x install_rustyjack.sh
./install_rustyjack.sh
if [ $? -eq 0 ]; then
    echo "✓ Installation complete"
else
    echo "✗ Installation failed"
    exit 1
fi
echo ""

echo "[4/5] Checking service status..."
systemctl status rustyjack --no-pager || true
echo ""

echo "[5/5] Setup complete!"
echo ""
echo "Next steps:"
echo "  - View logs: journalctl -u rustyjack -f"
echo "  - Restart service: systemctl restart rustyjack"
echo "  - Check LCD display for Rustyjack menu"
echo ""
