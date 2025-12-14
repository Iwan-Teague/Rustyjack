#!/bin/bash
# Quick hotspot fix deployment script

echo "=========================================="
echo "Deploying Hotspot RF-kill & AP Detection Fix"
echo "=========================================="
echo

# 1. Stop service
echo "1. Stopping rustyjack service..."
sudo systemctl stop rustyjack

# 2. Kill any remaining processes
echo "2. Cleaning up processes..."
sudo pkill -f rustyjack-ui
sudo pkill -f hostapd
sudo pkill -f dnsmasq

# 3. Ensure RF-kill is unblocked
echo "3. Unblocking RF-kill..."
sudo rfkill unblock all

# 4. Reset interfaces
echo "4. Resetting wireless interfaces..."
for iface in wlan0 wlan1; do
    if [ -d "/sys/class/net/$iface" ]; then
        echo "  Resetting $iface..."
        sudo ip addr flush dev $iface 2>/dev/null
        sudo ip link set $iface down 2>/dev/null
        # Leave unmanaged - this is the fix!
        sudo nmcli device set $iface managed no 2>/dev/null || echo "    (nmcli not available)"
    fi
done

# 5. Unblock RF-kill again
echo "5. Final RF-kill unblock..."
sudo rfkill unblock all
sleep 1

# 6. Check RF-kill status
echo "6. Checking RF-kill status..."
sudo rfkill list

# 7. Pull updates
echo
echo "7. Pulling latest code..."
cd ~/Rustyjack
git pull

# 8. Rebuild
echo
echo "8. Rebuilding..."
echo "Choose build type:"
echo "  [1] Debug build (fast compile, ~8 minutes)"
echo "  [2] Release build (slow compile, ~20 minutes)"
read -p "Select [1/2] (default: 1): " choice
choice=${choice:-1}

if [ "$choice" = "2" ]; then
    echo "Building release..."
    cargo build --release
    sudo cp target/release/rustyjack-ui /usr/local/bin/
else
    echo "Building debug..."
    cargo build
    sudo cp target/debug/rustyjack-ui /usr/local/bin/
fi

# 9. Start service
echo
echo "9. Starting rustyjack service..."
sudo systemctl start rustyjack

sleep 3

# 10. Check status
echo
echo "10. Checking service status..."
if sudo systemctl is-active --quiet rustyjack; then
    echo "  ✓ Service is running!"
else
    echo "  ✗ Service failed to start"
    sudo systemctl status rustyjack
    exit 1
fi

echo
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo
echo "Watch logs with:"
echo "  journalctl -u rustyjack -f"
echo
echo "Test the hotspot:"
echo "  1. Try wlan0 → Should show clear error (no AP support)"
echo "  2. Try wlan1 → Should work (USB WiFi adapter)"
echo "  3. Start hotspot"
echo "  4. Stop hotspot"
echo "  5. Start hotspot again ← Should now work!"
echo
echo "NOTES:"
echo "  - Wireless interfaces are now left UNMANAGED"
echo "    to prevent NetworkManager from blocking RF-kill"
echo "  - wlan0 (Pi Zero 2 W built-in) does NOT support AP mode"
echo "  - You need a USB WiFi adapter (wlan1) for hotspot"
echo

