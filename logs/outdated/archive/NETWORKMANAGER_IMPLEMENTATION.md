# NetworkManager D-Bus Implementation
Created: 2026-01-07

## Overview

Replaced `nmcli` command-line tool calls with native Rust D-Bus communication using the `zbus` crate. This provides:
- Better error handling with detailed context
- No subprocess overhead
- Type-safe D-Bus interface
- Direct NetworkManager integration

## What Was Replaced

### Before (nmcli subprocess calls)
```rust
Command::new("nmcli")
    .args(["device", "set", interface, "managed", "no"])
    .output()

Command::new("nmcli")
    .args(["device", "disconnect", interface])
    .output()

Command::new("nmcli")
    .args(["device", "reconnect", interface])
    .status()

Command::new("nmcli")
    .args(["--terse", "--wait", "20", "device", "wifi", "connect", ssid])
    .args(["ifname", interface])
    .args(["password", password])
    .output()
```

### After (D-Bus API)
```rust
use rustyjack_netlink::networkmanager::*;

// Set device managed/unmanaged
set_device_managed(interface, false).await?;

// Disconnect device
disconnect_device(interface).await?;

// Reconnect device
reconnect_device(interface).await?;

// Connect to WiFi network
connect_wifi(interface, ssid, Some(password), 20).await?;
```

## New Module: `rustyjack-netlink::networkmanager`

### Core API

#### `NetworkManagerClient`
Main client for NetworkManager D-Bus communication.

```rust
pub struct NetworkManagerClient {
    connection: Connection,
}

impl NetworkManagerClient {
    pub async fn new() -> Result<Self>
    pub async fn is_available(&self) -> bool
    pub async fn version(&self) -> Result<String>
    pub async fn set_device_managed(&self, interface: &str, managed: bool) -> Result<()>
    pub async fn get_device_state(&self, interface: &str) -> Result<NmDeviceState>
    pub async fn disconnect_device(&self, interface: &str) -> Result<()>
    pub async fn reconnect_device(&self, interface: &str) -> Result<()>
    pub async fn connect_wifi(&self, interface: &str, ssid: &str, password: Option<&str>, timeout_secs: u32) -> Result<()>
    pub async fn list_wifi_networks(&self, interface: &str) -> Result<Vec<AccessPoint>>
}
```

#### Convenience Functions
```rust
pub async fn set_device_managed(interface: &str, managed: bool) -> Result<()>
pub async fn get_device_state(interface: &str) -> Result<NmDeviceState>
pub async fn disconnect_device(interface: &str) -> Result<()>
pub async fn reconnect_device(interface: &str) -> Result<()>
pub async fn connect_wifi(interface: &str, ssid: &str, password: Option<&str>, timeout_secs: u32) -> Result<()>
pub async fn list_wifi_networks(interface: &str) -> Result<Vec<AccessPoint>>
```

#### Types

**`NmDeviceState`** - Device connection states:
- `Unknown`, `Unmanaged`, `Unavailable`, `Disconnected`
- `Prepare`, `Config`, `NeedAuth`, `IpConfig`, `IpCheck`
- `Secondaries`, `Activated`, `Deactivating`, `Failed`

**`AccessPoint`** - WiFi network information:
```rust
pub struct AccessPoint {
    pub ssid: String,
    pub bssid: String,
    pub signal_strength: u8,
    pub frequency: u32,
    pub max_bitrate: u32,
    pub security_flags: Vec<String>,
}
```

## Refactored Code Locations

### `rustyjack-core/src/system.rs`

**`connect_wifi_interface()`** - Now uses D-Bus:
```rust
// Connect via NetworkManager D-Bus
let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
if let Err(e) = rt.block_on(async {
    rustyjack_netlink::networkmanager::connect_wifi(
        interface,
        ssid,
        password,
        20, // 20 second timeout
    )
    .await
}) {
    bail!("Failed to connect to {ssid} on {interface}: {e}");
}
```

**`disconnect_wifi_interface()`** - Now uses D-Bus:
```rust
let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
if let Err(e) = rt.block_on(async {
    rustyjack_netlink::networkmanager::disconnect_device(&iface).await
}) {
    bail!("Failed to disconnect {iface}: {e}");
}
```

### `rustyjack-ui/src/util.rs`

**`trigger_mac_reconnect()`** - Fallback to NetworkManager:
```rust
let nm_success = if !wpa_success {
    let rt = tokio::runtime::Runtime::new().ok();
    if let Some(rt) = rt {
        rt.block_on(async {
            rustyjack_netlink::networkmanager::reconnect_device(interface)
                .await
                .is_ok()
        })
    } else {
        false
    }
} else {
    false
};
```

### `rustyjack-wireless/src/hotspot.rs`

**`start_hotspot()`** - Set interface unmanaged:
```rust
let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
let nm_result = rt.block_on(async {
    rustyjack_netlink::networkmanager::set_device_managed(&config.ap_interface, false).await
});

match nm_result {
    Ok(()) => {
        log::info!("Set {} to unmanaged by NetworkManager", config.ap_interface);
    }
    Err(e) => {
        log::warn!("Could not set {} unmanaged: may not have NetworkManager or D-Bus unavailable", config.ap_interface);
    }
}
```

## Error Handling

All NetworkManager functions provide detailed, actionable error messages:

```rust
// Example error messages:
"Failed to connect to system D-Bus - is D-Bus running?"
"Failed to get device path for interface 'wlan0' - interface may not exist or may not be managed by NetworkManager"
"Failed to set interface 'wlan0' to unmanaged by NetworkManager - permission denied or device in invalid state"
"Access point with SSID 'MyNetwork' not found - network may be out of range or hidden"
"Timeout waiting for connection to 'MyNetwork' on interface 'wlan0' after 20 seconds - check signal strength and authentication"
"Connection to 'MyNetwork' on interface 'wlan0' requires authentication - check password"
```

## Dependencies

Added to `rustyjack-netlink/Cargo.toml`:
```toml
zbus = "4.0"
uuid = { version = "1.0", features = ["v4"] }
```

## Benefits

1. **No External Binary Dependency**: Removes requirement for `network-manager` package's `nmcli` tool
2. **Better Performance**: Direct D-Bus calls eliminate subprocess overhead
3. **Improved Error Context**: Detailed, actionable error messages at every step
4. **Type Safety**: Compile-time checks for D-Bus method calls and property access
5. **Async Support**: Native async/await integration with tokio runtime
6. **State Monitoring**: Can query device state and wait for connection completion
7. **Network Scanning**: Can list available WiFi networks with signal strength and security info

## Installation Script Impact

The `install_rustyjack.sh` and `install_rustyjack_dev.sh` scripts still install `network-manager` because:
1. NetworkManager daemon must be running for D-Bus API to work
2. Provides WiFi management and connection persistence
3. Other system tools may depend on it

However, the `nmcli` CLI tool is no longer used by Rustyjack code.

## Testing

To test on target (Raspberry Pi):
```bash
# Verify NetworkManager is running
systemctl status NetworkManager

# Verify D-Bus is available
dbus-send --system --print-reply --dest=org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.DBus.Properties.Get string:org.freedesktop.NetworkManager string:Version

# Test with Rustyjack
sudo systemctl restart rustyjack
journalctl -u rustyjack -f
```

## Platform Support

- **Linux with D-Bus**: Full support (Raspberry Pi OS, Debian, Ubuntu, Fedora, etc.)
- **Linux without D-Bus**: Falls back gracefully (errors indicate D-Bus unavailable)
- **Windows/macOS**: Code is `cfg(target_os = "linux")` gated and won't compile

## Future Enhancements

Potential additions to the NetworkManager module:
- VPN connection management
- Connection profile creation/deletion
- Hotspot creation via NetworkManager (alternative to hostapd)
- Network device monitoring (signal strength, throughput)
- Ethernet connection management
- IPv6 configuration
