#!/bin/bash
# SD Card Health Check and Recovery Script

echo "=========================================="
echo "Rustyjack SD Card Health Check"
echo "=========================================="
echo

# 1. Check filesystem errors
echo "1. Checking filesystem for errors..."
dmesg | tail -50 | grep -i "error\|corruption\|i/o" || echo "No recent filesystem errors in dmesg"
echo

# 2. Check SD card health
echo "2. Checking SD card status..."
if [ -b /dev/mmcblk0 ]; then
    echo "SD card device: /dev/mmcblk0"
    sudo smartctl -a /dev/mmcblk0 2>/dev/null || echo "smartctl not available (normal for SD cards)"
else
    echo "SD card device not found"
fi
echo

# 3. Check filesystem mount status
echo "3. Current filesystem mounts:"
mount | grep -E "mmcblk|/$"
echo

# 4. Check if root is mounted read-only
echo "4. Checking if root filesystem is read-only..."
if mount | grep -E "on / type" | grep -q "ro,"; then
    echo "WARNING: Root filesystem is mounted READ-ONLY!"
    echo "This can cause write failures."
    echo
    echo "To remount as read-write:"
    echo "  sudo mount -o remount,rw /"
else
    echo "Root filesystem is mounted read-write (OK)"
fi
echo

# 5. Check disk space
echo "5. Disk space usage:"
df -h / /tmp
echo

# 6. Check for bad blocks
echo "6. Checking system logs for I/O errors..."
journalctl -n 100 --no-pager | grep -i "i/o error" | tail -10 || echo "No recent I/O errors in journal"
echo

# 7. Check if rustyjack binary is accessible
echo "7. Checking Rustyjack binary:"
BINARY="/root/Rustyjack/target/release/rustyjack-ui"
if [ -f "$BINARY" ]; then
    ls -lh "$BINARY"
    echo "Binary is accessible"
else
    echo "ERROR: Binary not found at $BINARY"
fi
echo

# 8. Test writing to filesystem
echo "8. Testing filesystem write capability..."
TEST_FILE="/tmp/rustyjack_write_test_$$"
if echo "test" > "$TEST_FILE" 2>&1; then
    echo "Write test successful"
    rm -f "$TEST_FILE"
else
    echo "ERROR: Cannot write to /tmp!"
fi
echo

echo "=========================================="
echo "Recommended Actions:"
echo "=========================================="

# Check if there were I/O errors
if dmesg | grep -qi "i/o error\|blk_update_request"; then
    echo "WARNING: I/O errors detected!"
    echo
    echo "Your SD card may be failing. Recommended actions:"
    echo "1. Backup your data immediately"
    echo "2. Run filesystem check (requires reboot):"
    echo "   sudo touch /forcefsck"
    echo "   sudo reboot"
    echo "3. Consider replacing the SD card"
    echo
fi

# Check if filesystem needs repair
if journalctl -n 100 | grep -qi "input/output error"; then
    echo "CRITICAL: Recent I/O errors in journal!"
    echo
    echo "Immediate actions:"
    echo "1. Stop Rustyjack service:"
    echo "   sudo systemctl stop rustyjack"
    echo
    echo "2. Check filesystem (will take several minutes):"
    echo "   sudo e2fsck -f /dev/mmcblk0p2"
    echo
    echo "3. If errors persist, the SD card may be failing"
    echo
fi

echo "To fix Rustyjack service after filesystem issues:"
echo "  sudo systemctl stop rustyjack"
echo "  sudo systemctl reset-failed rustyjack"
echo "  sudo systemctl start rustyjack"
echo
