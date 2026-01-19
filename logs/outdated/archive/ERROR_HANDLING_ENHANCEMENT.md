# Error Handling Enhancement Summary
**Operations Updated**:
**Operations Updated**:
**Previous Errors Consolidated**:

## Overview
Enhanced error handling across the `rustyjack-netlink` crate to provide detailed, actionable error messages with full context about operations, interfaces, and failure reasons.

## Changes Made

### 1. Unified Error Type (`error.rs`)
Created a comprehensive `NetlinkError` enum that consolidates all error types:

#### Error Categories
- **Interface Errors**: `InterfaceNotFound`, `InterfaceIndexError`, `SetStateError`, `MacAddressError`
- **Address Management**: `AddAddressError`, `DeleteAddressError`, `ListAddressesError`
- **Routing**: `AddRouteError`, `DeleteRouteError`, `ListRoutesError`
- **Wireless**: `WirelessModeError`, `ChannelSetError`, `TxPowerError`, `WirelessInfoError`
- **Rfkill**: `RfkillError`, `RfkillDeviceError`
- **Process Management**: `ProcessNotFound`, `ProcessSignalError`, `ProcReadError`
- **ARP**: `ArpError`, `ArpSocketError`
- **DHCP**: `DhcpError`, `DhcpTimeout`
- **DNS**: `DnsServerError`, `DnsParseError`
- **Generic**: `InvalidArgument`, `PermissionDenied`, `Timeout`, `Io`, `ParseError`, `NetlinkProtocol`, `Runtime`

#### Key Features
- **Structured Error Data**: Each error variant includes relevant context fields (interface name, operation, reason, etc.)
- **Detailed Messages**: Clear, actionable error messages with troubleshooting hints
- **Helper Methods**: Convenience constructors like `io_error()`, `netlink_error()`, `runtime()`
- **Permission Detection**: Automatically converts `PermissionDenied` IO errors to explicit permission errors

### 2. Interface Management (`interface.rs`)
Updated all error handling to use new structured errors:

```rust
// Before
Err(NetlinkError::SetStateError(format!("Failed to set {} up: {}", name, e)))

// After  
Err(NetlinkError::SetStateError {
    interface: name.to_string(),
    desired_state: "UP".to_string(),
    reason: e.to_string(),
})
```

- `get_interface_index()` - Validates non-empty interface names
- `set_interface_up()` / `set_interface_down()` - Clear state change errors
- `add_address()` / `delete_address()` - Validates prefix lengths for IPv4/IPv6
- `flush_addresses()` - Detailed address enumeration errors
- `list_interfaces()` - Runtime errors with operation context

### 3. Route Management (`route.rs`)
Enhanced routing error messages with full context:

```rust
// Before
Err(NetlinkError::AddRouteError(format!("Failed to add default route via {}: {}", gateway, e)))

// After
Err(NetlinkError::AddRouteError {
    destination: "default".to_string(),
    gateway: gateway.to_string(),
    interface: interface.to_string(),
    reason: e.to_string(),
})
```

- `add_default_route()` - Gateway, interface, and destination context
- `delete_default_route()` - Identifies which route failed to delete
- `list_routes()` - Enumeration error details

### 4. DHCP Client (`dhcp.rs`)
Removed separate `DhcpClientError` enum - all DHCP errors now use `NetlinkError::DhcpError` and `NetlinkError::DhcpTimeout`:

- `BindFailed` → `DhcpError { operation: "bind socket", ... }`
- `SendFailed` → `DhcpError { operation: "send DISCOVER", ... }`
- `Timeout` → `DhcpTimeout { packet_type, interface, timeout_secs }`
- `InvalidPacket` → `DhcpError { operation: "packet parsing", ... }`
- `ServerNak` → `DhcpError { operation: "REQUEST", reason: "Server sent NAK" }`
- `NoOffer` → `DhcpError { operation: "DISCOVER", reason: "No offer after N attempts" }`

## Benefits

### 1. **Consistency**
- All errors follow same structured pattern
- Uniform field names across error types
- Predictable error messages

### 2. **Debuggability**
- Always includes interface/device name in context
- Shows what operation was attempted
- Includes underlying error reason
- Provides actionable hints (e.g., "Try running with sudo", "Verify interface exists with 'ip link show'")

### 3. **Programmatic Handling**
- Structured fields allow pattern matching on specific error conditions
- Can extract interface names, operations, reasons for logging/UI
- Easy to convert to different error formats (JSON, structured logs, etc.)

### 4. **User Experience**
- Clear error messages help users diagnose issues quickly
- No cryptic "operation failed" messages
- Suggests next steps when appropriate

## Example Error Messages

### Before
```
Failed to set interface state: error occurred
```

### After
```
Failed to set interface 'wlan0' state to UP: Operation not permitted (os error 1)
```

### Before
```
Failed to add address: invalid prefix
```

### After
```
Failed to add address 192.168.1.100/33 to interface 'eth0': Invalid IPv4 prefix length: 33 (must be 0-32)
```

### Before
```
DHCP client error: timeout
```

### After
```
DHCP timeout waiting for OFFER on 'wlan0' after 10s
```

## Testing
- ✅ `rustyjack-netlink` crate compiles successfully
- ✅ All error types properly structured
- ✅ Helper methods work correctly
- ✅ No breaking changes to public API (Result type unchanged)

## Future Enhancements

### Potential Improvements
1. Add error codes for programmatic error type identification
2. Include stack traces in debug builds
3. Add more specific recovery suggestions
4. Implement `From<std::io::Error>` with automatic categorization
5. Add context chaining for nested errors
6. Implement Display with different verbosity levels

### Logging Integration
Consider adding structured logging fields:
```rust
log::error!(
    interface = %error.interface,
    operation = %error.operation,
    "Network operation failed: {}",
    error
);
```

## Conclusion
The enhanced error handling provides a solid foundation for debugging and user experience. All errors now include full context about what operation failed, which interface/device was involved, and why it failed, with actionable guidance where appropriate.
