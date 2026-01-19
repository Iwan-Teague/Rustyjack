# USB Detection Fix Summary
Created: 2026-01-07

## Problem Identified

The USB detection logic in Rustyjack had several issues preventing reliable USB device detection:

1. **Overly restrictive detection**: Required **both** `removable=1` AND `TRAN=usb` from `lsblk`, but some USB devices don't report both flags correctly on Raspberry Pi.

2. **Case-sensitive checks**: Some USB-related paths were checked with case-sensitive string matching, missing devices with uppercase "USB" in their paths.

3. **Missing subsystem check**: The code didn't check the `/sys/block/*/device/subsystem` symlink, which is a reliable way to identify USB devices.

4. **No auto-mounting**: If a USB was detected but not already mounted by the system, Rustyjack would fail rather than attempting to mount it.

## Changes Made

### 1. Improved `list_usb_devices()` (line ~2532)
- Changed from requiring **both** removable AND USB transport to accepting **either** condition
- Added explicit filtering of system devices (mmcblk, loop, ram)
- More permissive detection while still filtering out boot drives

### 2. Enhanced `find_usb_block_devices()` (line ~3568)
- Added case-insensitive string matching (`.to_lowercase()`)
- Added check for USB subsystem symlink at `/sys/block/*/device/subsystem`
- More comprehensive USB detection using multiple methods:
  - Removable flag
  - Device symlink path contains "usb"
  - Uevent file contains USB references
  - Subsystem symlink points to USB

### 3. Added Auto-mount Capability
- New `try_auto_mount_usb()` function that:
  - Detects partitions on USB devices
  - Attempts to mount to `/mnt/rustyjack_usb`
  - Verifies the mount is writable
  - Falls back gracefully if mounting fails

### 4. Better Error Messages
- Now distinguishes between:
  - No USB device detected at all
  - USB detected but not mounted (with device names)
  - USB detected and mount attempted but failed

## Testing

### Step 1: Run Diagnostic Script
Copy and run the diagnostic script on your Pi:

```bash
cd /opt/rustyjack
chmod +x scripts/diagnose_usb.sh
sudo ./scripts/diagnose_usb.sh
```

This will show:
- All block devices detected by `lsblk`
- Detailed `/sys/block/` information for each device
- Current mount points
- Recent USB events in dmesg
- USB devices from `lsusb`

### Step 2: Manual Mount (if needed)
If the diagnostic shows your USB is detected but not mounted:

```bash
chmod +x scripts/mount_usb.sh
sudo ./scripts/mount_usb.sh
```

This will automatically find and mount your USB drive.

### Step 3: Rebuild and Test Rustyjack
After making the code changes:

```bash
cd /opt/rustyjack
cargo build --release
sudo systemctl restart rustyjack
```

Now test in the UI:
- Navigate to **Encryption → Generate Key on USB** (should detect and mount USB)
- Navigate to **Encryption → Load Key from USB** (should show USB browser)
- Navigate to **Loot → Transfer to USB** (should find USB mount)

## Common USB Issues on Raspberry Pi

### Issue: USB not detected at all
**Cause**: USB device not recognized by kernel  
**Check**: `dmesg | grep -i usb` after inserting USB  
**Solution**: Try different USB port or check USB device compatibility

### Issue: USB detected but not mounted
**Cause**: No auto-mount service running  
**Check**: `systemctl status udisks2` or check for automount services  
**Solution**: Use the `mount_usb.sh` script or mount manually

### Issue: USB mounted but not writable
**Cause**: Filesystem corruption or read-only mount  
**Check**: `mount | grep usb` to see mount options  
**Solution**: 
```bash
sudo fsck /dev/sda1  # Check filesystem
sudo mount -o remount,rw /dev/sda1  # Remount read-write
```

### Issue: "removable" flag shows 0
**Cause**: Some USB adapters report as non-removable  
**Solution**: The updated code now checks USB subsystem, not just removable flag

## Verification Checklist

After deploying the fix, verify:

- [ ] USB insertion is logged in `dmesg` (kernel recognizes device)
- [ ] `/sys/block/sda` (or similar) exists for USB device
- [ ] `/proc/mounts` shows USB mount point (or auto-mount works)
- [ ] Rustyjack Encryption menu can generate keys on USB
- [ ] Rustyjack Encryption menu can load keys from USB
- [ ] Rustyjack Loot menu can transfer files to USB
- [ ] USB files are readable/writable from shell

## Technical Details

### USB Detection Flow
1. Scan `/sys/block/` for block devices
2. Filter out known system devices (mmcblk, loop, ram)
3. Check multiple USB indicators:
   - `/sys/block/*/removable` = "1"
   - `/sys/block/*/device` symlink contains "usb"
   - `/sys/block/*/device/uevent` contains USB references
   - `/sys/block/*/device/subsystem` links to USB subsystem
4. Verify device has non-zero size
5. Cross-reference with `/proc/mounts` to find mount point
6. Verify mount point is writable
7. If not mounted, attempt auto-mount to `/mnt/rustyjack_usb`

### Filesystem Support
The code looks for these common USB filesystems:
- FAT32/FAT16 (vfat)
- exFAT
- NTFS (ntfs, ntfs3)
- ext2/ext3/ext4
- FUSE-based (fuseblk)

## Rollback Instructions

If the changes cause issues, revert by:

```bash
cd /opt/rustyjack
git diff rustyjack-ui/src/app.rs  # Review changes
git checkout rustyjack-ui/src/app.rs  # Revert file
cargo build --release
sudo systemctl restart rustyjack
```

## Files Modified

- `rustyjack-ui/src/app.rs`:
  - `list_usb_devices()` - More permissive detection
  - `find_usb_block_devices()` - Case-insensitive + subsystem check
  - `find_usb_mount()` - Added auto-mount capability
  - `try_auto_mount_usb()` - New function for automatic mounting

## Files Added

- `scripts/diagnose_usb.sh` - Diagnostic script for troubleshooting
- `scripts/mount_usb.sh` - Helper script for manual mounting
- `USB_DETECTION_FIX.md` - This documentation file
