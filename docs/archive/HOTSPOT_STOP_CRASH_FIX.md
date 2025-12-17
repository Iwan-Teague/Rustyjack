# Hotspot Stop Crash - Recovery and Fix

## Problem
The hotspot started successfully and you connected to it, but when stopping the hotspot:
1. **Application crashed with SIGBUS (signal 7)** - indicates memory corruption or I/O error
2. **SD card I/O errors** - "Input/output error" and "Failed to find catalog entry"
3. **Service won't restart** - systemd cannot spawn the process due to I/O errors

## Root Causes

### Primary: SD Card Corruption/Failure
The "Input/output error" messages indicate:
- SD card is failing or corrupted
- Filesystem corruption
- Bad sectors on the SD card

### Secondary: App Crash on Stop
The app crashed with SIGBUS when calling `nmcli` to restore NetworkManager management.

## Immediate Recovery Steps

### Step 1: Check SD Card Health (CRITICAL)
```bash
cd ~/Rustyjack/scripts
chmod +x check_sd_health.sh
sudo ./check_sd_health.sh
```

### Step 2: Fix the Service
```bash
# Stop the service
sudo systemctl stop rustyjack

# Reset failed state
sudo systemctl reset-failed rustyjack

# Check if filesystem is read-only
mount | grep "on / type"

# If read-only, remount as read-write
sudo mount -o remount,rw /

# Rebuild Rustyjack
cd ~/Rustyjack
cargo build --release

# Start the service
sudo systemctl start rustyjack

# Watch logs
journalctl -u rustyjack -f
```

### Step 3: If Service Still Won't Start
```bash
# Check for filesystem errors
sudo dmesg | tail -50

# Check if binary is accessible
ls -lh ~/Rustyjack/target/release/rustyjack-ui

# Try running manually to see exact error
sudo ~/Rustyjack/target/release/rustyjack-ui
```

## Code Changes Made

### Fixed `stop_hotspot()` in `rustyjack-wireless/src/hotspot.rs`

**Changes:**
1. **Added comprehensive logging** throughout the stop process
2. **Added delays** between killing processes to allow cleanup
3. **Added timeout to nmcli** - prevents hanging if NetworkManager is stuck
4. **Made NetworkManager restore non-critical** - failure won't crash the app
5. **Better error handling** - all operations are best-effort with fallbacks

**Key improvement:**
```rust
// Use timeout to prevent hanging
let nmcli_result = std::process::Command::new("timeout")
    .args(["5", "nmcli", "device", "set", &s.ap_interface, "managed", "yes"])
    .status();

match nmcli_result {
    Ok(status) if status.success() => {
        eprintln!("[HOTSPOT] NetworkManager management restored");
    }
    Ok(_) => {
        eprintln!("[HOTSPOT] WARNING: Failed to restore NetworkManager management (non-critical)");
    }
    Err(e) => {
        eprintln!("[HOTSPOT] WARNING: nmcli command failed: {} (non-critical)", e);
    }
}
```

Now the stop process:
- Won't crash if `nmcli` fails
- Won't hang waiting for `nmcli`
- Provides detailed logging at each step
- Always cleans up properly

## Testing After Fix

### 1. Deploy the fix
```bash
cd ~/Rustyjack
git pull
cargo build --release
sudo systemctl restart rustyjack
```

### 2. Test hotspot lifecycle
```bash
# Watch logs in real-time
journalctl -u rustyjack -f

# From the UI:
# 1. Start hotspot
# 2. Connect from your phone
# 3. Stop hotspot
# 4. Start hotspot again
# 5. Stop hotspot again
```

### Expected logs when stopping:
```
[HOTSPOT] ========== HOTSPOT STOP ATTEMPT ==========
[HOTSPOT] Stopping hotspot processes...
[HOTSPOT] Killing hostapd PID 1209...
[HOTSPOT] Killing dnsmasq PID 1238...
[HOTSPOT] Restoring NetworkManager management of wlan0...
[HOTSPOT] NetworkManager management restored
[HOTSPOT] Removing state file...
[HOTSPOT] Hotspot stopped successfully
```

## SD Card Health

### Signs of SD Card Failure
- "Input/output error" messages
- "Failed to find catalog entry" messages  
- Service won't start after reboot
- Random crashes
- Files disappearing or corrupting

### If SD Card is Failing

**BACKUP IMMEDIATELY:**
```bash
# From another computer, backup the SD card
sudo dd if=/dev/sdX of=rustyjack_backup.img bs=4M status=progress

# Or backup just important data
scp -r root@rustyjack:/root/Rustyjack ~/rustyjack_backup
scp -r root@rustyjack:/root/loot ~/loot_backup
```

**Replace SD Card:**
1. Get a high-quality SD card (SanDisk Extreme, Samsung EVO+)
2. Flash fresh Raspberry Pi OS
3. Restore Rustyjack from backup
4. Run installer script

### Prevent SD Card Wear

Add to `/boot/firmware/config.txt` or `/boot/config.txt`:
```
# Reduce SD card writes
vm.dirty_ratio=20
vm.dirty_background_ratio=10
```

Consider adding tmpfs mounts in `/etc/fstab`:
```
tmpfs /tmp tmpfs defaults,noatime,nosuid,size=100M 0 0
tmpfs /var/log tmpfs defaults,noatime,nosuid,mode=0755,size=50M 0 0
```

## Manual Hotspot Control (Emergency)

If the UI is crashing, you can control hotspot manually:

### Start hotspot manually:
```bash
cd ~/Rustyjack/scripts
chmod +x test_hotspot_manual.sh
sudo ./test_hotspot_manual.sh wlan0 rustyjack-test 6
```

### Stop hotspot manually:
```bash
# Kill processes
sudo pkill -f hostapd
sudo pkill -f dnsmasq

# Restore NetworkManager (optional)
sudo nmcli device set wlan0 managed yes

# Clean up IP
sudo ip addr flush dev wlan0
```

## Files Modified
- `rustyjack-wireless/src/hotspot.rs` - Made stop_hotspot crash-resistant

## Files Created
- `scripts/check_sd_health.sh` - SD card health check script
- `HOTSPOT_STOP_CRASH_FIX.md` - This documentation

## Summary

The crash was caused by:
1. **SD card I/O errors** (primary issue - hardware)
2. **Unhandled nmcli failure** (secondary issue - fixed in code)

The fix makes the stop process:
- More robust with timeouts
- Better logging
- Non-fatal if NetworkManager restore fails
- Proper cleanup even if steps fail

**IMPORTANT:** Check your SD card health! The "Input/output error" messages suggest hardware failure.
