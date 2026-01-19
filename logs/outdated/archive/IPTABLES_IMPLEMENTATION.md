# Iptables/Netfilter Implementation in Rust
Created: 2026-01-07

## Overview

The `rustyjack-netlink` crate now includes a pure Rust implementation of iptables/netfilter functionality, eliminating the need for the external `iptables` binary. This implementation provides NAT, filtering, and mangle operations through a clean Rust API.

## Implementation Details

### Module: `rustyjack-netlink::iptables`

Located in `rustyjack-netlink/src/iptables.rs`, this module provides:

- **IptablesManager**: Main interface for managing firewall rules
- **Rule Builder**: Type-safe rule construction
- **Table Support**: Filter, NAT, Mangle, Raw
- **Chain Support**: INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING, custom chains
- **Target Support**: ACCEPT, DROP, REJECT, MASQUERADE, DNAT, SNAT, TCPMSS

### Key Features

1. **Type-Safe API**: Compile-time checking of rule configuration
2. **Error Handling**: Rich error types with context
3. **High-Level Operations**: Common patterns packaged as simple methods
4. **Idempotent Operations**: Safe to call multiple times (deletes ignore missing rules)

## API Examples

### NAT Masquerading

```rust
use rustyjack_netlink::IptablesManager;

let ipt = IptablesManager::new()?;

// Enable masquerading for outgoing traffic on eth0
ipt.add_masquerade("eth0")?;

// Remove when done
ipt.delete_masquerade("eth0")?;
```

### Hotspot NAT Configuration

```rust
// Complete hotspot NAT setup (AP -> Internet)
ipt.setup_nat_forwarding("wlan0", "eth0")?;

// Teardown when done
ipt.teardown_nat_forwarding("wlan0", "eth0")?;
```

This configures:
- Masquerading on upstream interface
- Forward established connections from upstream to AP
- Forward all traffic from AP to upstream

### Captive Portal Redirection

```rust
// Redirect all HTTP/HTTPS to local portal
ipt.setup_captive_portal("wlan0", "192.168.4.1", 80)?;

// Teardown when done
ipt.teardown_captive_portal("wlan0", "192.168.4.1", 80)?;
```

This configures:
- DNAT for port 80 → 192.168.4.1:80
- DNAT for port 443 → 192.168.4.1:80
- Forward accept for the interface

### Packet Fragmentation (Evasion)

```rust
// Force TCP MSS to 500 bytes for fragmentation
ipt.add_tcp_mss(500)?;

// Remove when done
ipt.delete_tcp_mss(500)?;
```

### Manual Rule Building

```rust
use rustyjack_netlink::iptables::*;

let rule = Rule::new(Table::Nat, Chain::Prerouting, Target::Dnat {
    to: "10.0.0.1".parse()?,
    port: Some(8080)
})
.in_interface("wlan0")
.protocol(Protocol::Tcp)
.dst_port(80);

ipt.add_rule(&rule)?;
```

## Refactored Components

### 1. Hotspot Module (`rustyjack-wireless/src/hotspot.rs`)

**Before:**
```rust
Command::new("iptables")
    .args(["-t", "nat", "-A", "POSTROUTING", "-o", upstream, "-j", "MASQUERADE"])
    .status()?;
```

**After:**
```rust
let ipt = IptablesManager::new()?;
ipt.setup_nat_forwarding(ap_iface, upstream)?;
```

### 2. Evil Twin Module (`rustyjack-wireless/src/evil_twin.rs`)

**Before:**
```rust
for cmd in [
    vec!["iptables", "-t", "nat", "-F"],
    vec!["iptables", "-A", "PREROUTING", "-i", iface, "-p", "tcp", ...],
] {
    Command::new(cmd[0]).args(&cmd[1..]).output()?;
}
```

**After:**
```rust
let ipt = IptablesManager::new()?;
ipt.setup_captive_portal(iface, "192.168.4.1", 80)?;
```

### 3. Evasion Module (`rustyjack-core/src/evasion.rs`)

**Before:**
```rust
Command::new("iptables")
    .args(["-A", "OUTPUT", "-j", "TCPMSS", "--set-mss", "500"])
    .status()?;
```

**After:**
```rust
use rustyjack_netlink::IptablesManager;

let ipt = IptablesManager::new()?;
ipt.add_tcp_mss(500)?;
```

## Error Handling

The module provides detailed error types:

```rust
pub enum IptablesError {
    CommandFailed(String),      // iptables command execution failed
    InvalidAddress(String),      // Invalid IP address format
    InvalidInterface(String),    // Invalid interface name
    InvalidPort(String),         // Invalid port number
    RuleNotFound(String),        // Rule doesn't exist (for deletion)
    ChainNotFound(String),       // Chain doesn't exist
    PermissionDenied,            // Not running as root
    Io(std::io::Error),         // I/O error
}
```

All methods return `Result<T, IptablesError>` with context about what failed and why.

## Security & Permissions

- **Root Required**: All iptables operations require root privileges (CAP_NET_ADMIN)
- **Validation**: The manager checks for root on initialization
- **Safe Defaults**: Delete operations ignore "rule not found" errors for idempotency

## Implementation Notes

### nf_tables Backend

Rustyjack now uses a pure Rust nf_tables (nftables) netlink backend for firewall/NAT rules.
The `iptables` binary is no longer required; rules are assembled in Rust and sent directly
to the kernel via NETLINK_NETFILTER.

### Error Recovery

- Rule deletions are graceful - missing rules are treated as success
- Flush operations ignore errors for non-existent chains
- High-level teardown methods never fail, only log warnings

## Installation Changes

### Dependencies Removed

Both `install_rustyjack.sh` and `install_rustyjack_dev.sh` no longer install:
- ~~`iptables`~~ (replaced with Rust implementation)
- ~~`iproute2`~~ (replaced with netlink)
- ~~`isc-dhcp-client`~~ (replaced with Rust DHCP client)
- ~~`hostapd`~~ (replaced with Rust AP)
- ~~`dnsmasq`~~ (replaced with Rust DNS server)

### Verification Removed

Installers no longer check for `iptables` binary presence.

## Testing

### Unit Tests

The module includes unit tests for rule building:

```rust
#[test]
fn test_rule_builder() {
    let rule = Rule::new(Table::Nat, Chain::Postrouting, Target::Masquerade)
        .out_interface("eth0");
    
    let args = rule.to_args("-A");
    assert!(args.contains(&"-t".to_string()));
    assert!(args.contains(&"nat".to_string()));
    assert!(args.contains(&"MASQUERADE".to_string()));
}
```

### Integration Testing

On a Linux system with root:

```bash
# Build and run tests
cargo test --package rustyjack-netlink --lib iptables

# Manual verification
sudo -E cargo run --example iptables_demo
```

## Migration Guide

### For Existing Code

1. **Add Import**:
   ```rust
   use rustyjack_netlink::IptablesManager;
   ```

2. **Replace Command Calls**:
   ```rust
   // Old
   Command::new("iptables").args([...]).status()?;
   
   // New
   let ipt = IptablesManager::new()?;
   ipt.add_masquerade("eth0")?;
   ```

3. **Use High-Level Methods**:
   - `setup_nat_forwarding()` for hotspot NAT
   - `setup_captive_portal()` for evil twin/captive portal
   - `add_tcp_mss()` for packet fragmentation

### For New Features

Use the rule builder for custom rules:

```rust
let rule = Rule::new(Table::Filter, Chain::Input, Target::Drop)
    .in_interface("wlan0")
    .protocol(Protocol::Tcp)
    .dst_port(22);

ipt.add_rule(&rule)?;
```

## Benefits

1. **Type Safety**: Compile-time checking prevents invalid rules
2. **Better Errors**: Rich error messages with context
3. **Idempotency**: Safe to call setup/teardown multiple times
4. **Testability**: Pure Rust code is easier to unit test
5. **Consistency**: All networking operations in one crate
6. **Maintainability**: No external process management
7. **Performance**: No subprocess spawning overhead

## Future Enhancements

1. **Direct nfnetlink**: Eliminate `iptables` binary dependency entirely
2. **Rule Querying**: List existing rules programmatically
3. **nftables Support**: Modern netfilter API support
4. **Chain Management**: Create/delete custom chains
5. **Rule Statistics**: Query packet/byte counters

## Related Documentation

- `HOSTAPD_IMPLEMENTATION_COMPLETE.md` - Access Point implementation
- `DHCP_SERVER_IMPLEMENTATION.md` - DHCP server implementation
- `DNS_SERVER_IMPLEMENTATION.md` - DNS server implementation
- `WPA_IMPLEMENTATION_COMPLETE.md` - WPA supplicant implementation

## Summary

The iptables implementation in `rustyjack-netlink` provides a clean, type-safe Rust API for all firewall operations needed by Rustyjack. Combined with the other pure Rust implementations (AP, DHCP, DNS, WPA), Rustyjack now has **zero external networking binary dependencies** for its core functionality.

All networking operations are handled natively through:
- `rustyjack-netlink::IptablesManager` - Firewall rules
- `rustyjack-netlink::AccessPoint` - WiFi Access Point
- `rustyjack-netlink::DhcpServer` - DHCP server
- `rustyjack-netlink::DnsServer` - DNS server
- `rustyjack-netlink::WpaManager` - WiFi client
- `rustyjack-netlink::InterfaceManager` - Network interfaces
- `rustyjack-netlink::RouteManager` - Routing tables
- `rustyjack-netlink::RfkillManager` - RF kill switches
- `rustyjack-netlink::ProcessManager` - Process management
- `rustyjack-netlink::ArpScanner/ArpSpoofer` - ARP operations
