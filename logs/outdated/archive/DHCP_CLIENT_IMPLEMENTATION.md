# DHCP Client Implementation
Created: 2026-01-07

## Overview

Implemented a complete, native Rust DHCP client in `rustyjack-netlink` to replace all `dhclient` binary dependencies. The implementation follows RFC 2131 (DHCP protocol) with robust error handling and detailed logging.

## Architecture

### Core Components

**`rustyjack-netlink::DhcpClient`**
- Full DHCP state machine (DISCOVER → OFFER → REQUEST → ACK)
- Automatic retry logic with configurable attempts
- Network configuration via netlink (IP address, routes, DNS)
- Lease management (acquire, renew, release)

**Key Features:**
- **Raw UDP socket binding** - Binds to 0.0.0.0:68 with SO_BINDTODEVICE for interface isolation
- **Broadcast support** - Sends DISCOVER/REQUEST to 255.255.255.255:67
- **Transaction ID tracking** - Generates unique XIDs and validates responses
- **DHCP option parsing** - Subnet mask, router, DNS servers, lease time
- **Hostname support** - Optional hostname in DHCP packets (Option 12)
- **Automatic configuration** - Sets IP, gateway, and DNS after lease acquisition

### Error Handling

Comprehensive error types in `DhcpClientError`:
- **`BindFailed`** - Socket binding errors with interface context
- **`SendFailed`** - Packet transmission failures with packet type
- **`ReceiveFailed`** - Reception errors with interface context
- **`Timeout`** - No response after timeout with packet type and duration
- **`InvalidPacket`** - Malformed responses with detailed reason
- **`ServerNak`** - Server rejected request
- **`AddressConfigFailed`** - Failed to configure IP address via netlink
- **`GatewayConfigFailed`** - Failed to add default route
- **`MacAddressFailed`** - Cannot retrieve interface MAC address
- **`NoOffer`** - No DHCP offer after all retry attempts

All errors include full context (interface name, IP addresses, error sources).

## API

### Public Functions

```rust
// Library functions
pub async fn dhcp_release(interface: &str) -> Result<()>
pub async fn dhcp_acquire(interface: &str, hostname: Option<&str>) -> Result<DhcpLease>
pub async fn dhcp_renew(interface: &str, hostname: Option<&str>) -> Result<DhcpLease>

// DhcpClient methods
impl DhcpClient {
    pub fn new() -> Result<Self>
    pub async fn release(&self, interface: &str) -> Result<()>
    pub async fn acquire(&self, interface: &str, hostname: Option<&str>) -> Result<DhcpLease>
    pub async fn renew(&self, interface: &str, hostname: Option<&str>) -> Result<DhcpLease>
}
```

### Data Structures

```rust
pub struct DhcpLease {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time: Duration,
}
```

## Refactored Code

### rustyjack-core/system.rs

**Before:**
```rust
let _ = Command::new("dhclient").args(["-r", interface]).status();
let dhcp_result = Command::new("dhclient").arg(interface).output();
```

**After:**
```rust
let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
if let Err(e) = rt.block_on(async {
    rustyjack_netlink::dhcp_release(interface).await
}) {
    log::warn!("Failed to release DHCP lease for {}: {}", interface, e);
}

let dhcp_result = rt.block_on(async {
    rustyjack_netlink::dhcp_acquire(interface, None).await
});
```

### rustyjack-ui/util.rs

**Before:**
```rust
let _dhcp_release = Command::new("dhclient").args(["-r", interface]).status();
let dhcp_renew = Command::new("dhclient").arg(interface).status();
```

**After:**
```rust
let dhcp_success = rt.block_on(async {
    if let Err(e) = rustyjack_netlink::dhcp_renew(interface, None).await {
        log::warn!("DHCP renew failed for {}: {}", interface, e);
        false
    } else {
        log::info!("DHCP lease renewed for {}", interface);
        true
    }
});
```

## Protocol Implementation

### DHCP Packet Structure

Standard 300-byte BOOTREQUEST/BOOTREPLY format:
- **Fixed header** (236 bytes): op, htype, hlen, hops, xid, secs, flags, addresses, MAC
- **Magic cookie** (4 bytes): 0x63 0x82 0x53 0x63
- **Options** (variable): Message type, requested IP, server ID, hostname, parameter request list

### State Machine

1. **DISCOVER** - Broadcast request for DHCP servers
   - Includes hostname (if provided)
   - Parameter request list: subnet mask, router, DNS, lease time
   - Retries up to 3 times with 1-second delays

2. **OFFER** - Wait for server response
   - Validates transaction ID
   - Extracts offered IP, server ID, network parameters
   - 5-second timeout per attempt

3. **REQUEST** - Accept offer from server
   - Includes requested IP and server ID options
   - Broadcast to 255.255.255.255

4. **ACK/NAK** - Final confirmation
   - ACK: Configure interface with lease parameters
   - NAK: Return error and abort

### Network Configuration

After receiving ACK:
1. **Add IP address** - `InterfaceManager::add_address()`
2. **Add default route** - `RouteManager::add_default_route()`
3. **Configure DNS** - Write `/etc/resolv.conf`

## Testing Considerations

- **Requires root privileges** - Socket binding to port 68, SO_BINDTODEVICE
- **Network dependency** - Needs real DHCP server on network
- **Timing sensitive** - 5-second timeouts, retries with delays
- **State mutation** - Modifies interface IP, routes, DNS

## Future Enhancements

1. **Lease renewal daemon** - Background thread to renew before expiration
2. **Lease persistence** - Save/restore leases across reboots
3. **DHCPv6 support** - IPv6 address configuration
4. **DHCP INFORM** - Query for additional parameters without address assignment
5. **Vendor-specific options** - Parse and handle vendor extensions

## Benefits

- **Zero external dependencies** - No `dhclient` binary required
- **Better error handling** - Structured errors with full context
- **Consistent logging** - All operations logged with interface and addresses
- **Type safety** - Strong typing for all network parameters
- **Performance** - No process spawning overhead
- **Integration** - Direct access to lease data structures

## Dependencies Eliminated

- ✅ `dhclient` - DHCP client
- ✅ `isc-dhcp-client` - Package providing dhclient

## Remaining Binary Dependencies

- `nmcli` - NetworkManager CLI (WiFi connection management)
- `wpa_cli` - WPA supplicant control (WiFi authentication)
- `hostapd` - Access point daemon (AP mode)
