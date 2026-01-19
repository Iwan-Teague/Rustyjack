# Hardware Detection Feature
Created: 2026-01-07

## Overview
Added a comprehensive hardware detection feature that scans and categorizes all network interfaces on your Raspberry Pi, allowing you to see exactly what hardware is available before launching attacks.

## What It Does

### Automatic Categorization
The hardware scanner automatically identifies and categorizes:

1. **Ethernet Ports** - Physical wired connections (eth*, en*)
2. **WiFi Modules** - Wireless adapters (wlan*)
3. **Other Interfaces** - USB adapters, virtual interfaces, etc.

### Information Displayed
For each detected interface:
- **Name** - Interface identifier (e.g., eth0, wlan0, wlan1)
- **Status** - Operational state (up, down, unknown)
- **IP Address** - Current IPv4 address or "no ip"

## How to Use

### From Main Menu
1. Select **"Hardware Detect"** (2nd option in Main Menu)
2. Wait for scan (~1 second)
3. View categorized results showing:
   - Count of each type
   - Detailed list with status and IPs
4. Press **SELECT** or **BACK** to exit

### Example Output
```
┌─────────────────────────┐
│ Hardware Detected       │
│ Ethernet: 1             │
│ WiFi: 2                 │
│ Other: 0                │
│                         │
│ Ethernet Ports:         │
│   eth0: up 192.168.1.10 │
│                         │
│ WiFi Modules:           │
│   wlan0: up 10.0.0.5    │
│   wlan1: down no ip     │
└─────────────────────────┘
```

## Use Cases

### 1. **Pre-Attack Planning**
- Verify hardware before configuring attacks
- Identify which interfaces are operational
- Check IP assignments

### 2. **Troubleshooting**
- Diagnose why an interface isn't working
- Verify USB adapters are recognized
- Check interface states after configuration

### 3. **Multi-Interface Attacks**
- See all available WiFi modules for dual-band attacks
- Identify backup interfaces
- Plan bridge configurations

### 4. **Quick Status Check**
- Fast overview without navigating WiFi menus
- See all interfaces at once
- Verify system after reboot

## Technical Details

### Core Implementation
**File:** `rustyjack-core/src/operations.rs`

The `handle_hardware_detect()` function:
1. Calls `list_interface_summaries()` to scan `/sys/class/net/`
2. Filters out loopback interface
3. Categorizes by interface type (wireless vs wired)
4. Further filters Ethernet by name pattern (eth*/en*)
5. Returns JSON with categorized results

**Data Structure:**
```json
{
  "ethernet_count": 1,
  "wifi_count": 2,
  "other_count": 0,
  "ethernet_ports": [
    {"name": "eth0", "kind": "wired", "oper_state": "up", "ip": "192.168.1.10"}
  ],
  "wifi_modules": [
    {"name": "wlan0", "kind": "wireless", "oper_state": "up", "ip": "10.0.0.5"},
    {"name": "wlan1", "kind": "wireless", "oper_state": "down", "ip": null}
  ],
  "other_interfaces": [],
  "total_interfaces": 3
}
```

### UI Implementation
**File:** `rustyjack-ui/src/app.rs`

The `show_hardware_detect()` function:
1. Shows progress indicator
2. Dispatches `HardwareCommand::Detect` to core
3. Parses JSON response
4. Formats categorized view with counts and details
5. Displays in scrollable dialog

### CLI Command
**File:** `rustyjack-core/src/cli.rs`

Added `HardwareCommand` enum:
```rust
pub enum HardwareCommand {
    Detect,
}
```

Can also be invoked from command line:
```bash
rustyjack hardware detect
```

## Interface Classification Logic

### Ethernet Ports
- Type: "wired" in `/sys/class/net/<iface>/wireless`
- Name pattern: Starts with "eth" or "en"
- Examples: eth0, eth1, enp0s3

### WiFi Modules
- Type: "wireless" (has `/sys/class/net/<iface>/wireless` directory)
- Name pattern: Typically wlan*
- Examples: wlan0, wlan1, wlx00c0ca123456

### Other Interfaces
- USB network adapters with non-standard names
- Virtual interfaces (veth*, br*, docker*)
- PPP connections
- Excluded: loopback (lo)

## Integration with Existing Features

### WiFi Manager
After hardware detection, navigate to:
- **WiFi Manager** → Use detected WiFi modules
- **Switch Interface** → Select from detected list

### Bridge Mode
Hardware detection helps plan bridge configurations:
- Requires 2+ interfaces
- See which are available before starting

### Attack Configuration
Know your hardware before launching:
- **MITM** - Verify active interface
- **DNS Spoof** - Check target interface

## Troubleshooting

### "No interfaces detected"
- System issue - check `ip link` manually
- Should never happen on a working Pi

### Interface shows "down"
```bash
# Bring interface up
sudo ip link set <interface> up
```

### Interface shows "no ip"
```bash
# Assign IP via DHCP
sudo dhclient <interface>

# Or static IP
sudo ip addr add 192.168.1.100/24 dev <interface>
```

### WiFi module not detected
1. Check USB connection (if external adapter)
2. Verify driver loaded: `lsusb` and `lsmod | grep wifi`
3. Check dmesg for errors: `dmesg | grep -i wireless`

## Performance

- **Scan Time**: ~500ms - 1 second
- **Memory Usage**: Minimal (~1KB for result data)
- **System Impact**: Read-only operations, no configuration changes

## Future Enhancements

### Possible Additions
1. **MAC Addresses** - Show hardware addresses
2. **Driver Info** - Display loaded kernel modules
3. **Capabilities** - List supported features (monitor mode, injection)
4. **Speed/Link Info** - Show connection speed for active interfaces
5. **Quick Actions** - Bring up/down directly from detection screen
6. **Historical View** - Track interface states over time

### CLI Extensions
```bash
# Possible future commands
rustyjack hardware detect --json      # Machine-readable output
rustyjack hardware test <interface>   # Test interface capabilities
rustyjack hardware configure <iface>  # Quick configuration wizard
```

## Example Scenarios

### Scenario 1: Dual WiFi Attack
```
Hardware Detect shows:
  WiFi: 2 (wlan0, wlan1)

Plan:
  - wlan0 → Connect to target network
  - wlan1 → Create evil twin AP
```

### Scenario 2: Wired + Wireless Bridge
```
Hardware Detect shows:
  Ethernet: 1 (eth0: up)
  WiFi: 1 (wlan0: up)

Plan:
  - Bridge eth0 ↔ wlan0
  - Capture traffic between networks
```

### Scenario 3: USB Adapter Verification
```
Just plugged in USB WiFi adapter

Hardware Detect shows:
  WiFi: 2 (wlan0, wlan1)
  
Verified: New adapter detected as wlan1
```

## Development Notes

### Adding New Interface Types
To add new categories (e.g., Bluetooth, LTE modems):

1. **Core:** Modify `handle_hardware_detect()` in operations.rs
2. **UI:** Update display formatting in `show_hardware_detect()`
3. **Menu:** Add sub-options if needed

### Testing
```bash
# Simulate interfaces for testing
sudo ip link add dummy0 type dummy
sudo ip link add wlan2 type dummy

# Run detection
rustyjack hardware detect

# Cleanup
sudo ip link delete dummy0
sudo ip link delete wlan2
```

---

**Navigation:** Main Menu → Hardware Detect
**Command:** `rustyjack hardware detect`
**Files Modified:** 
- `rustyjack-core/src/cli.rs`
- `rustyjack-core/src/operations.rs`
- `rustyjack-ui/src/menu.rs`
- `rustyjack-ui/src/app.rs`
