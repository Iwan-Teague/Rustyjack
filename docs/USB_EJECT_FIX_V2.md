# USB Ejection Fix v2 - Platform Compatibility

## Issue

USB auto-ejection was failing on all platforms:

### Windows (PowerShell)
```
Failed to eject USB: The term 'Write-Volume' is not recognized...
```
**Cause:** `Write-Volume` cmdlet doesn't exist in PowerShell.

### macOS (Bash)
- Using `umount` doesn't properly eject removable media on macOS
- Need `diskutil eject` for safe ejection
- `df` output format differs from Linux

### Linux (Bash)
- `df` column parsing was correct but not robust across all distributions
- Needed POSIX mode for consistency

---

## Fixes Applied

### PowerShell Scripts (build_arm32.ps1, build_arm64.ps1)

**1. Fixed Buffer Flush**
```powershell
# BEFORE (BROKEN):
Write-Volume -DriveLetter $($script:UsbExportDrive.TrimEnd(':'))

# AFTER (FIXED):
try {
    Write-VolumeCache -DriveLetter $driveLetter -ErrorAction Stop | Out-Null
} catch {
    # Fallback for non-admin: sync via .NET
    [System.IO.File]::WriteAllBytes("$($script:UsbExportDrive)\.flush", @())
    Remove-Item "$($script:UsbExportDrive)\.flush" -ErrorAction SilentlyContinue
}
```

**Why:**
- Correct cmdlet is `Write-VolumeCache`, not `Write-Volume`
- Requires admin on some systems → fallback creates/deletes dummy file to force sync
- `.NET File API` ensures kernel flushes buffers before ejection

**2. Improved Error Handling**
- Try `Write-VolumeCache` first (proper way)
- Fall back to .NET if lacking permissions
- Continue with ejection even if flush fails (better than complete failure)

---

### Bash Scripts (build_arm32.sh, build_arm64.sh)

**1. Platform Detection**
```bash
os_type=$(uname -s)

case "$os_type" in
    Darwin)
        # macOS: use diskutil
        device=$(df -P "$USB_EXPORT_DEST" | awk 'NR==2 {print $1}')
        diskutil eject "$device"
        ;;
    Linux)
        # Linux: use umount
        umount "$mount_point" || sudo umount "$mount_point"
        ;;
    *)
        # Unknown: try umount anyway
        umount "$mount_point"
        ;;
esac
```

**Why:**
- **macOS:** `umount` doesn't properly eject USB drives - device stays "in use"
  - `diskutil eject` handles device cleanup and notifies the system
  - Also works with encrypted volumes, Time Machine drives, etc.
- **Linux:** `umount` is correct and standard

**2. POSIX df Mode**
```bash
# Use df -P for consistent column layout across platforms
mount_point=$(df -P "$USB_EXPORT_DEST" 2>/dev/null | awk 'NR==2 {print $6}')
device=$(df -P "$USB_EXPORT_DEST" 2>/dev/null | awk 'NR==2 {print $1}')
```

**Why:**
- `-P` flag forces POSIX format (one line per filesystem)
- Prevents multi-line output on macOS when device names are long
- Column 1 = device (`/dev/disk2s1`), Column 6 = mount point (`/Volumes/USB`)

**3. Improved Fallback**
```bash
if [ -z "$mount_point" ]; then
    # Use last field if POSIX mode fails
    mount_point=$(df "$USB_EXPORT_DEST" 2>/dev/null | tail -1 | awk '{print $NF}')
fi
```

**Why:**
- `$NF` = last field in awk (mount point is always last)
- Works even when df has unexpected formatting

---

## Platform-Specific Behaviors

### Windows
1. **Flush:** `Write-VolumeCache` (admin) or dummy file write (.NET fallback)
2. **Eject:** WMI `Win32_Volume.Dismount()`
3. **Permissions:** Admin required for VolumeCache; WMI works without admin on removable drives

### macOS
1. **Flush:** `sync` (kernel buffer flush)
2. **Eject:** `diskutil eject /dev/diskN`
3. **Permissions:** `diskutil` works without sudo for removable media
4. **Why not umount:** macOS keeps device active even after `umount` - causes "disk not ejected properly" errors

### Linux
1. **Flush:** `sync` (kernel buffer flush)
2. **Eject:** `umount /mount/point` (with sudo fallback)
3. **Permissions:** Requires sudo unless user is in `disk` group or mount was done by user

---

## Testing Matrix

| Platform | Command | Expected Result |
|----------|---------|----------------|
| Windows 10/11 (Admin) | `build_arm64.ps1` → Y → Y | Write-VolumeCache + WMI eject |
| Windows 10/11 (User) | `build_arm64.ps1` → Y → Y | .NET flush + WMI eject |
| macOS (Intel/ARM) | `build_arm64.sh` → y → y | `diskutil eject /dev/disk2s1` |
| Linux (user) | `build_arm64.sh` → y → y | `sudo umount /media/usb` |
| Linux (disk group) | `build_arm64.sh` → y → y | `umount /media/usb` |

---

## Error Messages

All error messages now include exact manual commands:

### Windows
```
Failed to eject USB drive (error code: 5). Please eject manually.
You may need to close any programs accessing the drive.
```

### macOS
```
Failed to eject USB drive. Please eject manually with: diskutil eject /dev/disk2s1
```

### Linux
```
Failed to eject USB drive. Please eject manually with: sudo umount /media/usb
```

---

## Known Limitations

1. **Windows:** Eject may fail if Explorer has files open from the drive
2. **macOS:** Spotlight indexing can delay ejection (normal behavior)
3. **Linux:** SELinux/AppArmor policies might block umount for some users

---

## References

- [Windows: Write-VolumeCache cmdlet](https://docs.microsoft.com/en-us/powershell/module/storage/write-volumecache)
- [macOS: diskutil man page](https://ss64.com/osx/diskutil.html)
- [Linux: umount man page](https://man7.org/linux/man-pages/man8/umount.8.html)
- [POSIX df format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/df.html)

---

## Commit

All fixes applied in commit: [hash]
- Fixed `Write-Volume` → `Write-VolumeCache` in PowerShell scripts
- Added .NET fallback for non-admin Windows users
- Added macOS `diskutil eject` support in bash scripts
- Used `df -P` for POSIX-compliant column parsing
- Improved error messages with platform-specific manual commands
