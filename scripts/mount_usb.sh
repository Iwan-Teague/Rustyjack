#!/bin/bash
# Helper script to manually mount USB devices
# Run this if your USB is detected but not auto-mounted

set -e

echo "=== USB Mount Helper ==="
echo ""

# Find unmounted USB devices
echo "Looking for unmounted USB devices..."
DEVICES=$(lsblk -nrpo NAME,RM,TRAN,MOUNTPOINT | grep -E '(usb|1)' | awk '$4=="" {print $1}')

if [ -z "$DEVICES" ]; then
    echo "No unmounted USB devices found."
    echo ""
    echo "Currently mounted USB devices:"
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -E 'sd[a-z]'
    exit 0
fi

echo "Unmounted USB devices found:"
echo "$DEVICES"
echo ""

# Get the first device
DEVICE=$(echo "$DEVICES" | head -1)
echo "Selecting device: $DEVICE"

# Check for partitions
PARTITIONS=$(lsblk -nrpo NAME "$DEVICE" | tail -n +2)

if [ -n "$PARTITIONS" ]; then
    MOUNT_DEV=$(echo "$PARTITIONS" | head -1)
    echo "Found partition: $MOUNT_DEV"
else
    MOUNT_DEV="$DEVICE"
    echo "No partitions found, using device directly: $MOUNT_DEV"
fi

# Create mount point if needed
MOUNT_POINT="/mnt/usb_rustyjack"
echo "Creating mount point: $MOUNT_POINT"
sudo mkdir -p "$MOUNT_POINT"

# Try to mount
echo "Mounting $MOUNT_DEV to $MOUNT_POINT..."
if sudo mount "$MOUNT_DEV" "$MOUNT_POINT"; then
    echo "SUCCESS! USB mounted at $MOUNT_POINT"
    echo ""
    echo "Contents:"
    ls -lh "$MOUNT_POINT"
    echo ""
    echo "Rustyjack should now detect the USB drive."
else
    echo "FAILED to mount. Checking filesystem..."
    sudo blkid "$MOUNT_DEV" || echo "No filesystem detected"
    echo ""
    echo "You may need to format the USB drive first."
    echo "To format as FAT32: sudo mkfs.vfat -F 32 $MOUNT_DEV"
    echo "To format as ext4: sudo mkfs.ext4 $MOUNT_DEV"
    exit 1
fi
