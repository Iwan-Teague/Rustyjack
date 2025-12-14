#!/bin/bash
# Emergency Rustyjack Service Recovery Script

echo "=========================================="
echo "Rustyjack Service Emergency Recovery"
echo "=========================================="
echo

# 1. Stop the service
echo "1. Stopping rustyjack service..."
sudo systemctl stop rustyjack
sleep 2

# 2. Kill any remaining processes
echo "2. Killing any remaining Rustyjack processes..."
sudo pkill -f rustyjack-ui || echo "  No rustyjack-ui processes found"
sudo pkill -f hostapd || echo "  No hostapd processes found"
sudo pkill -f dnsmasq || echo "  No dnsmasq processes found"
sleep 1

# 3. Reset failed state
echo "3. Resetting failed service state..."
sudo systemctl reset-failed rustyjack

# 4. Check filesystem
echo "4. Checking filesystem mount status..."
if mount | grep -E "on / type" | grep -q "ro,"; then
    echo "  WARNING: Root filesystem is READ-ONLY!"
    echo "  Remounting as read-write..."
    sudo mount -o remount,rw /
    if [ $? -eq 0 ]; then
        echo "  Successfully remounted as read-write"
    else
        echo "  ERROR: Failed to remount. SD card may be failing."
        exit 1
    fi
else
    echo "  Root filesystem is read-write (OK)"
fi

# 5. Check if binary exists and is accessible
echo "5. Checking Rustyjack binary..."
BINARY="/root/Rustyjack/target/release/rustyjack-ui"
if [ ! -f "$BINARY" ]; then
    echo "  ERROR: Binary not found at $BINARY"
    echo "  You need to rebuild: cd ~/Rustyjack && cargo build --release"
    exit 1
fi

if [ ! -x "$BINARY" ]; then
    echo "  Binary is not executable, fixing..."
    sudo chmod +x "$BINARY"
fi

echo "  Binary is OK: $(ls -lh $BINARY | awk '{print $5}')"

# 6. Clean up temporary files
echo "6. Cleaning up temporary files..."
sudo rm -rf /tmp/rustyjack_hotspot
sudo rm -f /tmp/rustyjack_*
echo "  Cleaned up temporary files"

# 7. Reset network interfaces
echo "7. Resetting network interfaces..."
for iface in wlan0 wlan1; do
    if [ -d "/sys/class/net/$iface" ]; then
        echo "  Resetting $iface..."
        sudo ip addr flush dev $iface 2>/dev/null
        sudo ip link set $iface down 2>/dev/null
        sleep 1
        sudo rfkill unblock all
        sleep 1
        sudo nmcli device set $iface managed yes 2>/dev/null || echo "    (nmcli not available or failed)"
    fi
done

# 8. Check for I/O errors
echo "8. Checking for recent I/O errors..."
if dmesg | tail -50 | grep -qi "i/o error\|blk_update_request"; then
    echo "  WARNING: I/O errors detected in kernel log!"
    echo "  Your SD card may be failing."
    echo "  Check: sudo dmesg | grep -i error"
fi

if journalctl -n 50 --no-pager | grep -qi "input/output error"; then
    echo "  WARNING: I/O errors in systemd journal!"
    echo "  SD card health check recommended."
fi

# 9. Start the service
echo "9. Starting rustyjack service..."
sudo systemctl start rustyjack

sleep 3

# 10. Check status
echo "10. Checking service status..."
if sudo systemctl is-active --quiet rustyjack; then
    echo "  SUCCESS! Service is running"
    echo
    echo "  View logs with: journalctl -u rustyjack -f"
else
    echo "  ERROR: Service failed to start"
    echo
    echo "  Checking status:"
    sudo systemctl status rustyjack
    echo
    echo "  Recent logs:"
    journalctl -u rustyjack -n 20 --no-pager
    echo
    echo "  Try running manually to see error:"
    echo "    sudo $BINARY"
fi

echo
echo "=========================================="
echo "Recovery Complete"
echo "=========================================="
