# Hardware Isolation Implementation
Created: 2026-01-07

## Overview

The hardware isolation feature ensures that only the intended network interface is active at any given time, preventing accidental data leakage through secondary interfaces. This is critical for maintaining operational security during penetration testing operations.

## Features Implemented

### 1. Startup Enforcement
The daemon now enforces interface isolation on startup by calling `select_active_uplink()` during the reconciliation phase. This ensures the preferred interface is active immediately after system boot or daemon restart.

### 2. Centralized API
A new high-level `set_active_interface()` function provides a single entry point for:
- Validating the requested interface exists
- Writing the interface preference
- Establishing routes
- Enforcing isolation

This is exposed via the `SetActiveInterface` RPC endpoint for use by the UI and other clients.

### 3. Netlink Watcher
A background task monitors network interface state changes using rtnetlink and automatically re-enforces isolation when:
- Interfaces are brought up/down
- IP addresses are added/removed
- Link state changes occur

The watcher uses a 250ms debounce to avoid excessive enforcement during rapid state changes.

### 4. Hotplug Notifications
The `HotplugNotify` RPC endpoint allows external scripts (installer, udev rules) to notify the daemon when new hardware is detected or driver installation completes. The daemon waits 500ms for the system to stabilize, then re-enforces isolation.

### 5. Refactored Implementation
- `NetOps` trait abstracts system operations for testability
- `apply_interface_isolation_with_ops()` returns structured `IsolationOutcome`
- Mock implementations enable comprehensive unit testing
- Uplink lock prevents concurrent isolation enforcement

## API

### RPC Endpoints

#### SetActiveInterface
```json
{
  "type": "SetActiveInterface",
  "data": {
    "interface": "wlan0"
  }
}
```

Response:
```json
{
  "type": "SetActiveInterface",
  "data": {
    "interface": "wlan0",
    "allowed": ["wlan0"],
    "blocked": ["eth0", "wlan1"],
    "errors": []
  }
}
```

#### HotplugNotify
```json
{
  "type": "HotplugNotify"
}
```

Response:
```json
{
  "type": "HotplugNotify",
  "data": {
    "acknowledged": true
  }
}
```

## Usage

### From CLI (via dispatcher)
```rust
use rustyjack_core::operations::set_active_interface;

let outcome = set_active_interface(&root, "wlan0")?;
println!("Allowed: {:?}", outcome.allowed);
println!("Blocked: {:?}", outcome.blocked);
```

### From External Scripts
```bash
# Notify daemon after driver installation
rustyjack-client hotplug-notify
```

## Configuration

The feature uses the existing `system_preferred` preference file at `<root>/preferences/system_preferred`.

### Environment Variables

- `RUSTYJACKD_NM_INTEGRATION` - Enable NetworkManager integration (default: `false`)
  - Set to `1` or `true` to enable
  - When enabled, blocked interfaces are marked as "unmanaged" in NetworkManager
  - Allowed interfaces are marked as "managed"

Example:
```bash
# Enable NetworkManager integration
export RUSTYJACKD_NM_INTEGRATION=true
sudo systemctl restart rustyjackd
```

### NetworkManager Integration

When `RUSTYJACKD_NM_INTEGRATION=true`, the system will:
- Mark blocked interfaces as "unmanaged" to prevent NetworkManager from auto-connecting
- Mark allowed interfaces as "managed" to allow NetworkManager control
- Use D-Bus API (pure Rust, no `nmcli` binary dependency)
- Gracefully degrade if NetworkManager is not available

This is optional and disabled by default for maximum compatibility.

## Testing

### Unit Tests
Run unit tests with the mock NetOps implementation:
```bash
cd tests/hardware_select
cargo test --test integration_boot_reconcile
```

### Integration Tests
Integration tests verify:
- Startup reconciliation with preferred interface
- Isolation allows multiple interfaces (hotspot scenario)
- Empty allow list is rejected
- Non-existent interfaces are rejected
- Wireless interfaces use rfkill blocking

## Security Considerations

- **Authorization**: `SetActiveInterface` RPC is accessible to all authenticated users. Consider adding admin-level authorization if needed.
- **Race Conditions**: The uplink lock prevents concurrent isolation enforcement
- **Hotplug Trust**: `HotplugNotify` currently accepts requests from any authenticated client. For production, restrict to root UID using SO_PEERCRED.

## Future Enhancements

See `HARDWARE_ISOLATION_SPEC.md` for:
- NetworkManager integration (optional, opt-in)
- Enhanced telemetry and metrics
- E2E tests with network namespaces
- Recovery bypass mechanism

## Troubleshooting

### Isolation not enforced at startup
Check daemon logs for errors during `reconcile_on_startup()`. The enforcement is non-fatal to prevent systemd start failures.

### Netlink watcher not triggering
Ensure the daemon has `CAP_NET_ADMIN` capability and rtnetlink messages are not filtered by the kernel.

### Interfaces remain active after blocking
Verify rfkill is functional for wireless interfaces:
```bash
rfkill list
```

For wired interfaces, check that the interface was successfully brought down:
```bash
ip link show <interface>
```
