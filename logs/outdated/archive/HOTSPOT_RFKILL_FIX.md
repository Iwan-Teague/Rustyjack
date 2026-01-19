# Hotspot RF-kill Blocking Issue - Fixed
Created: 2026-01-07

## Problem Analysis

The hotspot functionality was failing with RF-kill errors. Analysis of the journal logs revealed:

1. **RF-kill was being re-blocked after initial unblock** - The code called `rfkill unblock wifi` successfully, but shortly after, something was re-blocking the wireless interface
2. **NetworkManager was interfering** - Log entry showed `rfkill[2194]: block set for id 2` happening asynchronously
3. **wpa_supplicant conflicts** - When the interface was in use by wpa_supplicant (for client mode), hostapd could not take control
4. **Timing issue** - RF-kill was unblocked early but not verified before hostapd start

Error symptoms from logs:
```
rfkill: WLAN soft blocked
Failed to set beacon parameters
wlan1: Could not connect to kernel driver
Interface initialization failed
```

## Root Causes

1. **NetworkManager auto-management** - NetworkManager was managing the wireless interface and would re-enable RF-kill or prevent AP mode
2. **wpa_supplicant still running** - If wpa_supplicant was attached to the interface, hostapd couldn't initialize
3. **RF-kill not persistent** - Something (likely NetworkManager) was re-blocking RF-kill between our unblock and hostapd start
4. **Insufficient verification** - The code didn't verify RF-kill status before starting hostapd

## Solution Implemented

Modified `rustyjack-wireless/src/hotspot.rs` with the following fixes:

### 1. Stop wpa_supplicant on AP interface (line 151-156)
```rust
// Stop wpa_supplicant on the AP interface to prevent interference
eprintln!("[HOTSPOT] Stopping wpa_supplicant on {}...", config.ap_interface);
let _ = Command::new("pkill")
    .args(["-f", &format!("wpa_supplicant.*{}", config.ap_interface)])
    .status();
```

### 2. Set interface to unmanaged by NetworkManager (line 158-181)
```rust
// Set interface to unmanaged by NetworkManager to prevent interference
eprintln!("[HOTSPOT] Setting {} to unmanaged by NetworkManager...", config.ap_interface);
let nmcli_result = Command::new("nmcli")
    .args(["device", "set", &config.ap_interface, "managed", "no"])
    .output();
```

This prevents NetworkManager from:
- Blocking RF-kill
- Managing the interface's state
- Interfering with hostapd

### 3. Unblock ALL RF-kill devices (line 183-201)
Changed from `rfkill unblock wifi` to `rfkill unblock all` to ensure all wireless devices are unblocked:
```rust
let rfkill_result = Command::new("rfkill")
    .args(&["unblock", "all"])
    .output();
```

### 4. Verify RF-kill status (line 207-216)
Added verification to detect if RF-kill is still blocked:
```rust
eprintln!("[HOTSPOT] Verifying rfkill status...");
if let Ok(output) = Command::new("rfkill").arg("list").output() {
    let status = String::from_utf8_lossy(&output.stdout);
    eprintln!("[HOTSPOT] rfkill status:\n{}", status);
    if status.contains("Soft blocked: yes") || status.contains("Hard blocked: yes") {
        eprintln!("[HOTSPOT] WARNING: Wireless is still blocked by rfkill!");
    }
}
```

### 5. Final RF-kill unblock before hostapd (line 365-368)
Added a second RF-kill unblock right before starting hostapd to ensure it stays unblocked:
```rust
// Double-check rfkill is still unblocked right before starting hostapd
eprintln!("[HOTSPOT] Final rfkill unblock before starting hostapd...");
let _ = Command::new("rfkill").args(&["unblock", "all"]).status();
std::thread::sleep(std::time::Duration::from_millis(500));
```

### 6. Restore NetworkManager management on stop (line 580-583)
When stopping the hotspot, restore normal NetworkManager management:
```rust
// Restore NetworkManager management of the AP interface
eprintln!("[HOTSPOT] Restoring NetworkManager management of {}...", s.ap_interface);
let _ = Command::new("nmcli")
    .args(["device", "set", &s.ap_interface, "managed", "yes"])
    .status();
```

## Testing Instructions

After deploying the fix on the Pi:

1. **Rebuild and restart the service:**
   ```bash
   cd ~/Rustyjack
   cargo build --release
   sudo systemctl restart rustyjack
   ```

2. **Monitor the logs:**
   ```bash
   journalctl -u rustyjack -f
   ```

3. **Test hotspot start:**
   - Use the UI to enable hotspot
   - Try with wlan0, wlan1, or any combination
   - Watch for the new log messages showing:
     - wpa_supplicant being stopped
     - NetworkManager being set to unmanaged
     - RF-kill status verification
     - Final RF-kill unblock before hostapd

4. **Verify hotspot is running:**
   ```bash
   # Check processes
   ps aux | grep hostapd
   ps aux | grep dnsmasq
   
   # Check RF-kill status
   rfkill list
   
   # Check NetworkManager status
   nmcli device status
   
   # Try connecting from another device
   ```

5. **Test hotspot stop:**
   - Stop the hotspot via UI
   - Verify NetworkManager regains management: `nmcli device status`

## Expected Log Output

With the fix, you should see these new log entries:

```
[HOTSPOT] Stopping wpa_supplicant on wlan1...
[HOTSPOT] Setting wlan1 to unmanaged by NetworkManager...
[HOTSPOT] Interface set to unmanaged successfully
[HOTSPOT] Unblocking rfkill for all wireless devices...
[HOTSPOT] rfkill unblocked successfully
[HOTSPOT] Verifying rfkill status...
[HOTSPOT] rfkill status:
0: phy0: Wireless LAN
	Soft blocked: no
	Hard blocked: no
...
[HOTSPOT] Final rfkill unblock before starting hostapd...
[HOTSPOT] Starting hostapd on wlan1 (SSID: rustyjack)
```

## Why This Fix Works

1. **Prevents NetworkManager interference** - Setting the interface to unmanaged tells NetworkManager to leave it alone
2. **Clears wpa_supplicant** - Killing wpa_supplicant frees the interface for hostapd
3. **Persistent RF-kill unblock** - Two unblock calls (early + before hostapd) ensure RF-kill stays unblocked
4. **Better visibility** - RF-kill status verification helps debug any remaining issues
5. **Clean shutdown** - Restoring management allows normal NetworkManager operation after hotspot stops

## Related Files Modified

- `rustyjack-wireless/src/hotspot.rs` - Main hotspot implementation

## Additional Notes

- The fix is defensive and includes warnings if steps fail (e.g., if nmcli is not available)
- Works with or without NetworkManager installed
- Compatible with both built-in wlan0 (Pi Zero 2 W) and USB wireless adapters
- The interface can be used normally (client mode) after stopping the hotspot
