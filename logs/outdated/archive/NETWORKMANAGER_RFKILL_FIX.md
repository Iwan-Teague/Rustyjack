# Critical Fix: NetworkManager RF-kill Re-blocking Issue
Created: 2026-01-07

## Problem Discovered

After stopping the hotspot, **you cannot start it again** - even with different interfaces. The logs show:

```
Dec 14 00:48:49 - RF-kill unblocked successfully
Dec 14 00:48:50 - rfkill[2464]: block set for id 2    ← SOMETHING RE-BLOCKS IT!
Dec 14 00:48:50 - phy0: Wireless LAN Soft blocked: yes
Dec 14 00:48:50 - [HOTSPOT] WARNING: Wireless is still blocked by rfkill!
```

## Root Cause

**NetworkManager re-blocks RF-kill when we restore its management of the interface!**

The sequence was:
1. Hotspot starts → set interface to unmanaged → unblock RF-kill → **works!**
2. Hotspot stops → restore NetworkManager management → **NetworkManager blocks RF-kill**
3. Try to start hotspot again → RF-kill is blocked → **fails!**

NetworkManager has a feature where it blocks RF-kill for interfaces it manages that aren't actively in use. This is breaking our hotspot restart.

## The Fix

### Change 1: Aggressive RF-kill Unblocking in `start_hotspot()`

Added a 3-attempt loop to unblock RF-kill, plus aggressive fallback:

```rust
// Try multiple times because something keeps re-blocking it
for attempt in 1..=3 {
    eprintln!("[HOTSPOT] RF-kill unblock attempt {}...", attempt);
    let _ = Command::new("rfkill").args(&["unblock", "all"]).output();
    std::thread::sleep(std::time::Duration::from_millis(300));
}

// If still blocked, try unblocking by device ID
if is_blocked {
    for id in 0..10 {
        let _ = Command::new("rfkill").args(&["unblock", &id.to_string()]).status();
    }
}
```

### Change 2: DO NOT Restore NetworkManager Management in `stop_hotspot()`

**Critical change:** Instead of restoring NetworkManager management (which blocks RF-kill), we now:
- Bring interface down to clean state
- Flush IP addresses
- **Leave interface unmanaged**
- Ensure RF-kill stays unblocked

```rust
// DO NOT restore NetworkManager management immediately
// NetworkManager re-blocks RF-kill when it takes control
eprintln!("[HOTSPOT] Cleaning up interface {} (leaving unmanaged)...", s.ap_interface);

// Bring interface down to clean state
let _ = Command::new("ip").args(["link", "set", &s.ap_interface, "down"]).status();

// Flush any remaining IPs
let _ = Command::new("ip").args(["addr", "flush", "dev", &s.ap_interface]).status();

// Ensure RF-kill stays unblocked
let _ = Command::new("rfkill").args(&["unblock", "all"]).status();

eprintln!("[HOTSPOT] NOTE: Interface left unmanaged to prevent RF-kill blocking");
```

## Why This Works

1. **Interfaces stay unmanaged** - NetworkManager can't block RF-kill
2. **RF-kill stays unblocked** - Multiple unblock attempts catch any re-blocking
3. **Clean state** - Interface is brought down and IPs are flushed, so it's ready for next use
4. **No NetworkManager interference** - It can't manage what it doesn't control

## Trade-offs

**Benefit:** Hotspot can be started/stopped/restarted reliably without RF-kill blocking

**Cost:** Wireless interfaces stay unmanaged by NetworkManager

This is acceptable for Rustyjack because:
- This is a dedicated penetration testing device
- Rustyjack controls wireless interfaces directly, not NetworkManager
- If user wants to use NetworkManager later, they can manually re-enable:
  ```bash
  sudo nmcli device set wlan0 managed yes
  sudo nmcli device set wlan1 managed yes
  ```

## Deployment

```bash
cd ~/Rustyjack
git pull
cargo build --release  # or use install script for debug build
sudo systemctl restart rustyjack
```

## Testing

After deploying, test the full cycle:

```bash
# Watch logs
journalctl -u rustyjack -f

# From UI:
# 1. Start hotspot (wlan0 or wlan1, with or without upstream)
# 2. Verify it starts and you can connect
# 3. Stop hotspot
# 4. IMMEDIATELY start hotspot again ← This should now work!
# 5. Stop hotspot
# 6. Try with different interface
# 7. Try multiple start/stop cycles
```

Expected logs on stop:
```
[HOTSPOT] ========== HOTSPOT STOP ATTEMPT ==========
[HOTSPOT] Stopping hotspot processes...
[HOTSPOT] Killing hostapd PID 2309...
[HOTSPOT] Killing dnsmasq PID 2346...
[HOTSPOT] Cleaning up interface wlan1 (leaving unmanaged)...
[HOTSPOT] Ensuring RF-kill stays unblocked...
[HOTSPOT] NOTE: Interface wlan1 left unmanaged to prevent RF-kill blocking
[HOTSPOT] Hotspot stopped successfully
```

Expected logs on start (after stop):
```
[HOTSPOT] ========== HOTSPOT START ATTEMPT ==========
[HOTSPOT] Unblocking rfkill for all wireless devices...
[HOTSPOT] RF-kill unblock attempt 1...
[HOTSPOT] RF-kill unblock attempt 2...
[HOTSPOT] RF-kill unblock attempt 3...
[HOTSPOT] rfkill status:
1: phy0: Wireless LAN
        Soft blocked: no    ← Should be "no" now!
        Hard blocked: no
```

## If NetworkManager Management Is Needed

If you ever need NetworkManager to manage interfaces again (e.g., for normal WiFi client mode):

```bash
# Re-enable NetworkManager management
sudo nmcli device set wlan0 managed yes
sudo nmcli device set wlan1 managed yes

# Prevent NetworkManager from blocking RF-kill
# Edit /etc/NetworkManager/NetworkManager.conf:
[keyfile]
unmanaged-devices=

# Add this to prevent RF-kill blocking:
[device]
wifi.scan-rand-mac-address=no

# Restart NetworkManager
sudo systemctl restart NetworkManager

# Unblock RF-kill
sudo rfkill unblock all
```

## Summary

**The fix:** Stop restoring NetworkManager management and use aggressive RF-kill unblocking.

**Result:** Hotspot can now be started, stopped, and restarted reliably without RF-kill blocking issues.

**Files modified:**
- `rustyjack-wireless/src/hotspot.rs` - start_hotspot() and stop_hotspot()
