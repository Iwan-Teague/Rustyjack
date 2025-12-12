#!/bin/bash
# USB Detection Diagnostic Script
# Run this on the Raspberry Pi to diagnose USB detection issues

echo "=== USB Detection Diagnostic ==="
echo ""

echo "1. Listing all block devices with lsblk:"
lsblk -nrpo NAME,RM,SIZE,MODEL,TRAN
echo ""

echo "2. Checking /sys/block/ for devices:"
for dev in /sys/block/sd* /sys/block/nvme* 2>/dev/null; do
    if [ -e "$dev" ]; then
        name=$(basename "$dev")
        echo "Device: $name"
        
        # Check removable
        if [ -f "$dev/removable" ]; then
            removable=$(cat "$dev/removable")
            echo "  removable: $removable"
        fi
        
        # Check size
        if [ -f "$dev/size" ]; then
            size=$(cat "$dev/size")
            echo "  size: $size blocks"
        fi
        
        # Check device symlink
        if [ -L "$dev/device" ]; then
            device_link=$(readlink "$dev/device")
            echo "  device link: $device_link"
        fi
        
        # Check uevent
        if [ -f "$dev/device/uevent" ]; then
            echo "  uevent content:"
            grep -E "DRIVER|usb" "$dev/device/uevent" || echo "    (no USB-related entries)"
        fi
        
        echo ""
    fi
done

echo "3. Checking /proc/mounts for mounted devices:"
grep "^/dev/" /proc/mounts | grep -v "mmcblk"
echo ""

echo "4. Checking common mount points:"
for dir in /media /mnt /run/media; do
    if [ -d "$dir" ]; then
        echo "$dir:"
        find "$dir" -mindepth 1 -maxdepth 2 -type d 2>/dev/null || echo "  (empty)"
    fi
done
echo ""

echo "5. Checking dmesg for recent USB insertions (last 50 lines):"
dmesg | grep -i "usb\|storage" | tail -50
echo ""

echo "6. USB devices from lsusb:"
lsusb
echo ""

echo "=== End of diagnostic ==="
