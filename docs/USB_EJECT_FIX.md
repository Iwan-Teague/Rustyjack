# USB Ejection Logic - Comprehensive Analysis & Fixes

## Issues Found & Fixed

### PowerShell Scripts (build_arm32.ps1, build_arm64.ps1)

#### Issue 1: Invalid WMI Filter Syntax ❌
**Problem:**
```powershell
$driveObj = Get-WmiObject Win32_Volume -Filter "DriveLetter = '$($script:UsbExportDrive)'"
```
When `$script:UsbExportDrive` is `"E:"`, this expands to:
```powershell
-Filter "DriveLetter = '$E:'"
```
The nested single quotes break the WMI query syntax.

**Fix:** ✅
```powershell
$driveLetter = $script:UsbExportDrive
$driveObj = Get-WmiObject Win32_Volume -Filter "DriveLetter = '$driveLetter'"
```
Store the drive letter in a variable first to avoid quote expansion issues.

#### Issue 2: No Buffer Flush Before Dismount ❌
**Problem:**
Windows file system buffers may still have pending writes when `Dismount()` is called. This can cause:
- Dismount failure with error code 5 (Access Denied)
- Data corruption
- "Drive still in use" errors

**Fix:** ✅
```powershell
Write-Volume -DriveLetter $($script:UsbExportDrive.TrimEnd(':')) -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Milliseconds 500
```
- `Write-Volume` flushes all pending writes to the specified drive
- 500ms sleep ensures flush completes before dismount attempt

#### Issue 3: No Helpful Error Messages ❌
**Problem:**
When dismount fails, user gets generic message with no guidance.

**Fix:** ✅
```powershell
if ($result.ReturnValue -eq 0) {
    Write-Host "USB drive ejected successfully. Safe to remove." -ForegroundColor Green
} else {
    Write-Host "Failed to eject USB drive (error code: $($result.ReturnValue)). Please eject manually." -ForegroundColor Yellow
    Write-Host "You may need to close any programs accessing the drive." -ForegroundColor Gray
}
```
Added helpful hint about closing programs that may be locking the drive.

---

### Bash Scripts (build_arm32.sh, build_arm64.sh)

#### Issue 1: Wrong df Column for Mount Point ❌
**Problem:**
```bash
mount_point=$(df "$USB_EXPORT_DEST" 2>/dev/null | awk 'NR==2 {print $1}')
```
`$1` in `df` output is the **device** (e.g., `/dev/sdb1`), not the **mount point** (e.g., `/media/usb`).

**df output columns:**
```
Filesystem     1K-blocks      Used Available Use% Mounted on
/dev/sdb1       30832636  10485760  20346876  34% /media/usb
$1             $2         $3        $4        $5   $6
```

**Original code:**
- `$1` = `/dev/sdb1` (device)
- `umount /dev/sdb1` works BUT...
- If USB has multiple partitions, this only unmounts one partition
- Better to unmount by mount point

**Fix:** ✅
```bash
mount_point=$(df "$USB_EXPORT_DEST" 2>/dev/null | awk 'NR==2 {print $6}')

if [ -z "$mount_point" ]; then
    # Fallback: try to find the mount point by walking up the directory tree
    mount_point=$(df "$USB_EXPORT_DEST" 2>/dev/null | tail -1 | awk '{print $NF}')
fi
```
- `$6` is the mount point column
- `$NF` (last field) is a fallback for systems where mount point is the last column
- Now unmounting by mount point, which is more reliable

#### Issue 2: No sync Before umount ❌
**Problem:**
Linux filesystem buffers (page cache) may have pending writes. Calling `umount` immediately after file operations can:
- Delay unmount while buffers flush (appears to "hang")
- Fail with "device busy" error
- Risk data loss if interrupted

**Fix:** ✅
```bash
sync
sleep 1
```
- `sync` flushes all filesystem buffers to disk
- 1-second sleep ensures sync completes (sync may return before I/O is fully committed on some systems)

#### Issue 3: No sudo Fallback ❌
**Problem:**
On many Linux systems, `umount` requires root privileges. Non-root users get "permission denied".

**Fix:** ✅
```bash
if umount "$mount_point" 2>/dev/null; then
    echo "USB drive ejected successfully. Safe to remove."
elif command -v sudo >/dev/null 2>&1 && sudo umount "$mount_point" 2>/dev/null; then
    echo "USB drive ejected successfully (required sudo). Safe to remove."
else
    echo "Failed to eject USB drive. Please eject manually with: sudo umount $mount_point"
fi
```
- Try `umount` without sudo first (works if user is in `disk` group or using FUSE mount)
- If that fails, try with `sudo` (user will be prompted for password if needed)
- If both fail, provide exact command user can run manually

---

## Common Dismount/Umount Error Codes

### Windows (WMI ReturnValue)
- `0` - Success
- `2` - Access Denied (another process has the drive open)
- `5` - The parameter is incorrect (invalid drive letter format)
- `15` - The device is not ready (drive already ejected or removed)
- `21` - The device is not ready (drive in use)

### Linux (umount exit codes)
- `0` - Success
- `1` - Permission denied (need sudo)
- `16` - Device busy (files open, process has cwd in mount, etc.)
- `32` - Mount point does not exist

---

## Testing Validation

### PowerShell Test Cases
```powershell
# Test 1: Normal eject
./build_arm64.ps1
# Choose USB drive, select Y for auto-eject
# Expected: "USB drive ejected successfully. Safe to remove."

# Test 2: Drive in use
# Open Explorer to USB drive
./build_arm64.ps1
# Choose USB drive, select Y for auto-eject
# Expected: "Failed to eject USB drive (error code: 2). Please eject manually."
#           "You may need to close any programs accessing the drive."

# Test 3: No eject
./build_arm64.ps1
# Choose USB drive, select N for auto-eject
# Expected: "Remember to eject the USB drive before removing it."
```

### Bash Test Cases
```bash
# Test 1: Normal eject (with permissions)
./build_arm64.sh
# Choose USB drive, select Y for auto-eject
# Expected: "USB drive ejected successfully. Safe to remove."

# Test 2: Need sudo
./build_arm64.sh
# Choose USB drive, select Y for auto-eject
# Expected: Sudo password prompt, then "USB drive ejected successfully (required sudo)."

# Test 3: Drive busy
# Terminal: cd /media/usb
./build_arm64.sh
# Choose USB drive, select Y for auto-eject
# Expected: "Failed to eject USB drive. Please eject manually with: sudo umount /media/usb"
```

---

## Platform-Specific Notes

### Windows
- `Write-Volume` requires PowerShell 3.0+ (Windows 8+)
- On Windows 7, flush is best-effort (may silently fail)
- NTFS and FAT32 both supported
- Dismount does NOT physically eject the drive (just unmounts the filesystem)

### Linux
- `sync` is POSIX-compliant, available on all Linux/macOS
- `df` column positions are standardized by POSIX
- `umount` requires `CAP_SYS_ADMIN` capability or membership in `disk` group
- Some desktop environments (GNOME, KDE) use `udisksctl` for user-space unmount

### macOS
- Bash script works on macOS (uses same `df`/`umount` commands)
- `diskutil unmount /Volumes/USB` is the native macOS way
- `diskutil eject /dev/disk2` physically ejects the drive

---

## Summary of Changes

| File | Lines Changed | Key Fixes |
|------|--------------|-----------|
| `build_arm32.ps1` | 675-700 | WMI filter escaping, buffer flush, helpful error messages |
| `build_arm64.ps1` | 182-202 | WMI filter escaping, buffer flush, helpful error messages |
| `build_arm32.sh` | 608-632 | Correct df column, sync before umount, sudo fallback |
| `build_arm64.sh` | 608-632 | Correct df column, sync before umount, sudo fallback |

**All fixes applied and ready for testing.**
