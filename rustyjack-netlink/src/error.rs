use thiserror::Error;

/// Unified error type for all rustyjack-netlink operations.
///
/// Provides detailed, actionable error messages with context about what operation
/// failed, which interface/device was involved, and the underlying cause.
#[derive(Error, Debug)]
pub enum NetlinkError {
    // Interface errors
    #[error("Interface '{name}' not found. Verify interface exists with 'ip link show'.")]
    InterfaceNotFound { name: String },

    #[error("Failed to get interface index for '{interface}': {reason}")]
    InterfaceIndexError { interface: String, reason: String },

    #[error("Failed to set interface '{interface}' state to {desired_state}: {reason}")]
    SetStateError {
        interface: String,
        desired_state: String,
        reason: String,
    },

    #[error("Failed to get MAC address for interface '{interface}': {reason}")]
    MacAddressError { interface: String, reason: String },

    // Address management errors
    #[error("Failed to add address {address}/{prefix} to interface '{interface}': {reason}")]
    AddAddressError {
        address: String,
        prefix: u8,
        interface: String,
        reason: String,
    },

    #[error("Failed to delete address {address} from interface '{interface}': {reason}")]
    DeleteAddressError {
        address: String,
        interface: String,
        reason: String,
    },

    #[error("Failed to list addresses for interface '{interface}': {reason}")]
    ListAddressesError { interface: String, reason: String },

    // Routing errors
    #[error("Failed to add route to {destination} via {gateway} on '{interface}': {reason}")]
    AddRouteError {
        destination: String,
        gateway: String,
        interface: String,
        reason: String,
    },

    #[error("Failed to delete route to {destination} on '{interface}': {reason}")]
    DeleteRouteError {
        destination: String,
        interface: String,
        reason: String,
    },

    #[error("Failed to list routes: {reason}")]
    ListRoutesError { reason: String },

    // Wireless errors
    #[error("Failed to set wireless interface '{interface}' to {mode} mode: {reason}")]
    WirelessModeError {
        interface: String,
        mode: String,
        reason: String,
    },

    #[error("Failed to set channel {channel} on '{interface}': {reason}")]
    ChannelSetError {
        interface: String,
        channel: u32,
        reason: String,
    },

    #[error("Failed to set TX power to {power_mbm} mBm on '{interface}': {reason}")]
    TxPowerError {
        interface: String,
        power_mbm: u32,
        reason: String,
    },

    #[error("Failed to query wireless info for '{interface}': {reason}")]
    WirelessInfoError { interface: String, reason: String },

    // Rfkill errors
    #[error("Failed to {operation} rfkill device {device_id} ({device_type}): {reason}")]
    RfkillError {
        operation: String,
        device_id: u32,
        device_type: String,
        reason: String,
    },

    #[error("Failed to open /dev/rfkill: {reason}. Ensure device exists and you have permissions.")]
    RfkillDeviceError { reason: String },

    // Process errors
    #[error("Failed to find process '{pattern}': {reason}")]
    ProcessNotFound { pattern: String, reason: String },

    #[error("Failed to signal process {pid} ({name}) with {signal}: {reason}")]
    ProcessSignalError {
        pid: i32,
        name: String,
        signal: String,
        reason: String,
    },

    #[error("Failed to read /proc filesystem: {reason}")]
    ProcReadError { reason: String },

    // ARP errors
    #[error("ARP operation failed on '{interface}': {reason}")]
    ArpError { interface: String, reason: String },

    #[error("Failed to create raw socket for ARP on '{interface}': {reason}. Root privileges required.")]
    ArpSocketError { interface: String, reason: String },

    // DHCP errors
    #[error("DHCP {operation} failed on '{interface}': {reason}")]
    DhcpError {
        operation: String,
        interface: String,
        reason: String,
    },

    #[error("DHCP timeout waiting for {packet_type} on '{interface}' after {timeout_secs}s")]
    DhcpTimeout {
        packet_type: String,
        interface: String,
        timeout_secs: u64,
    },

    #[error("DHCP client error: {0}")]
    DhcpClient(#[from] crate::dhcp::DhcpClientError),

    // DNS errors
    #[error("DNS server error on {bind_addr}: {reason}")]
    DnsServerError { bind_addr: String, reason: String },

    #[error("Failed to parse DNS query from {client}: {reason}")]
    DnsParseError { client: String, reason: String },

    // WPA errors
    #[error("WPA supplicant error: {0}")]
    Wpa(String),

    // Generic errors
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid argument: {parameter} = '{value}': {reason}")]
    InvalidArgument {
        parameter: String,
        value: String,
        reason: String,
    },

    #[error("Operation failed: {0}")]
    OperationFailed(String),

    #[error("Operation not supported: {0}")]
    OperationNotSupported(String),

    #[error("System error: {0}")]
    System(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Permission denied: {operation}. Root privileges required.")]
    PermissionDenied { operation: String },

    #[error("Operation timed out after {timeout_secs}s: {operation}")]
    Timeout {
        operation: String,
        timeout_secs: u64,
    },

    #[error("IO error during {operation}: {source}")]
    Io {
        operation: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse {what}: {reason}")]
    ParseError { what: String, reason: String },

    #[error("Netlink protocol error during {operation}: {reason}")]
    NetlinkProtocol { operation: String, reason: String },

    #[error("Runtime error: {context}: {reason}")]
    Runtime { context: String, reason: String },

    #[error("ARP error: {0}")]
    Arp(#[from] crate::arp::ArpError),
}

pub type Result<T> = std::result::Result<T, NetlinkError>;

// Helper methods for common error construction patterns
impl NetlinkError {
    /// Create an IO error with context
    pub fn io_error(operation: impl Into<String>, source: std::io::Error) -> Self {
        // Check for permission denied
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            return Self::PermissionDenied {
                operation: operation.into(),
            };
        }
        Self::Io {
            operation: operation.into(),
            source,
        }
    }

    /// Create a netlink protocol error with context
    pub fn netlink_error(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::NetlinkProtocol {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// Create a runtime error with context
    pub fn runtime(context: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Runtime {
            context: context.into(),
            reason: reason.into(),
        }
    }
}
