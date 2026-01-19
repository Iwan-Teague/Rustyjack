use std::io;
use std::net::Ipv4Addr;
use thiserror::Error;

// Re-export sub-modules
pub use crate::arp_scanner::ArpScanner;
pub use crate::arp_spoofer::{ArpSpoofConfig, ArpSpoofer};

#[derive(Error, Debug)]
pub enum ArpError {
    #[error("Failed to create raw socket for ARP on {interface}: {source}")]
    SocketCreate {
        interface: String,
        source: io::Error,
    },

    #[error("Failed to bind socket to interface {interface}: {source}")]
    SocketBind {
        interface: String,
        source: io::Error,
    },

    #[error("Failed to send ARP request to {target_ip} on {interface}: {source}")]
    SendRequest {
        target_ip: Ipv4Addr,
        interface: String,
        source: io::Error,
    },

    #[error("Failed to receive ARP reply on {interface}: {source}")]
    ReceiveReply {
        interface: String,
        source: io::Error,
    },

    #[error("Interface {interface} not found or not available")]
    InterfaceNotFound { interface: String },

    #[error("Failed to get MAC address for interface {interface}: {reason}")]
    MacAddressError { interface: String, reason: String },

    #[error("Failed to parse IP address '{address}': {source}")]
    InvalidIpAddress {
        address: String,
        source: std::net::AddrParseError,
    },

    #[error("Invalid MAC address format: {address}. Expected format: AA:BB:CC:DD:EE:FF")]
    InvalidMacAddress { address: String },

    #[error("Timeout waiting for ARP reply from {target_ip} after {timeout_ms}ms")]
    Timeout {
        target_ip: Ipv4Addr,
        timeout_ms: u64,
    },

    #[error("ARP operation requires root privileges. Try running with sudo.")]
    PermissionDenied,

    #[error("Invalid subnet mask: {mask}")]
    InvalidSubnetMask { mask: String },

    #[error(
        "Subnet {subnet} is too large. Maximum {max_hosts} hosts, requested {requested_hosts}."
    )]
    SubnetTooLarge {
        subnet: String,
        max_hosts: u32,
        requested_hosts: u32,
    },

    #[error("ARP spoof operation failed on {interface}: {reason}")]
    SpoofError { interface: String, reason: String },

    #[error("IO error during ARP operation on {interface}: {source}")]
    Io {
        interface: String,
        #[source]
        source: io::Error,
    },
}

pub type Result<T> = std::result::Result<T, ArpError>;

/// ARP packet structure (28 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket {
    pub hw_type: u16,        // Hardware type (1 = Ethernet)
    pub proto_type: u16,     // Protocol type (0x0800 = IPv4)
    pub hw_size: u8,         // Hardware address size (6 for MAC)
    pub proto_size: u8,      // Protocol address size (4 for IPv4)
    pub opcode: u16,         // Operation (1 = request, 2 = reply)
    pub sender_mac: [u8; 6], // Sender MAC address
    pub sender_ip: [u8; 4],  // Sender IP address
    pub target_mac: [u8; 6], // Target MAC address
    pub target_ip: [u8; 4],  // Target IP address
}

impl ArpPacket {
    /// Create a new ARP request packet
    pub fn new_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpPacket {
            hw_type: 1u16.to_be(),
            proto_type: 0x0800u16.to_be(),
            hw_size: 6,
            proto_size: 4,
            opcode: 1u16.to_be(), // Request
            sender_mac,
            sender_ip: sender_ip.octets(),
            target_mac: [0; 6], // Unknown (what we're asking for)
            target_ip: target_ip.octets(),
        }
    }

    /// Create a new ARP reply packet (for spoofing)
    pub fn new_reply(
        sender_mac: [u8; 6],
        sender_ip: Ipv4Addr,
        target_mac: [u8; 6],
        target_ip: Ipv4Addr,
    ) -> Self {
        ArpPacket {
            hw_type: 1u16.to_be(),
            proto_type: 0x0800u16.to_be(),
            hw_size: 6,
            proto_size: 4,
            opcode: 2u16.to_be(), // Reply
            sender_mac,
            sender_ip: sender_ip.octets(),
            target_mac,
            target_ip: target_ip.octets(),
        }
    }

    /// Get opcode as native u16
    pub fn get_opcode(&self) -> u16 {
        u16::from_be(self.opcode)
    }

    /// Get sender IP as Ipv4Addr
    pub fn get_sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.sender_ip[0],
            self.sender_ip[1],
            self.sender_ip[2],
            self.sender_ip[3],
        )
    }

    /// Get target IP as Ipv4Addr
    pub fn get_target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.target_ip[0],
            self.target_ip[1],
            self.target_ip[2],
            self.target_ip[3],
        )
    }

    /// Convert to bytes for transmission
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<ArpPacket>(),
            )
        }
    }

    /// Parse from received bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<ArpPacket>() {
            return None;
        }

        unsafe { Some(std::ptr::read_unaligned(bytes.as_ptr() as *const ArpPacket)) }
    }
}

/// Result of an ARP scan
#[derive(Debug, Clone)]
pub struct ArpScanResult {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub vendor: Option<String>,
    pub response_time_ms: u64,
}

impl ArpScanResult {
    /// Format MAC address as string
    pub fn mac_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }

    /// Get OUI (Organizationally Unique Identifier) - first 3 bytes of MAC
    pub fn oui(&self) -> [u8; 3] {
        [self.mac[0], self.mac[1], self.mac[2]]
    }
}

/// ARP scanner configuration
#[derive(Debug, Clone)]
pub struct ArpScanConfig {
    /// Timeout for each host response (milliseconds)
    pub timeout_ms: u64,
    /// Number of retries per host
    pub retries: u8,
    /// Delay between retries (milliseconds)
    pub retry_delay_ms: u64,
    /// Maximum concurrent scans
    pub max_concurrent: usize,
}

impl Default for ArpScanConfig {
    fn default() -> Self {
        ArpScanConfig {
            timeout_ms: 1000,
            retries: 2,
            retry_delay_ms: 100,
            max_concurrent: 100,
        }
    }
}

/// Parse MAC address from string
pub fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();

    if parts.len() != 6 {
        return Err(ArpError::InvalidMacAddress {
            address: mac_str.to_string(),
        });
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| ArpError::InvalidMacAddress {
            address: mac_str.to_string(),
        })?;
    }

    Ok(mac)
}

/// Format MAC address as string
pub fn format_mac_address(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse subnet CIDR notation (e.g., "192.168.1.0/24")
pub fn parse_subnet(subnet: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = subnet.split('/').collect();

    if parts.len() != 2 {
        return Err(ArpError::InvalidSubnetMask {
            mask: subnet.to_string(),
        });
    }

    let ip = parts[0]
        .parse::<Ipv4Addr>()
        .map_err(|e| ArpError::InvalidIpAddress {
            address: parts[0].to_string(),
            source: e,
        })?;

    let prefix_len = parts[1]
        .parse::<u8>()
        .map_err(|_| ArpError::InvalidSubnetMask {
            mask: subnet.to_string(),
        })?;

    if prefix_len > 32 {
        return Err(ArpError::InvalidSubnetMask {
            mask: subnet.to_string(),
        });
    }

    Ok((ip, prefix_len))
}

/// Generate list of IPs in a subnet
pub fn subnet_to_ips(subnet: &str) -> Result<Vec<Ipv4Addr>> {
    let (network_ip, prefix_len) = parse_subnet(subnet)?;

    if prefix_len < 8 {
        return Err(ArpError::SubnetTooLarge {
            subnet: subnet.to_string(),
            max_hosts: 1 << (32 - 8),
            requested_hosts: 1 << (32 - prefix_len),
        });
    }

    let network_u32 = u32::from(network_ip);
    let host_bits = 32 - prefix_len;
    let num_hosts = (1u32 << host_bits) - 2; // Exclude network and broadcast

    let mut ips = Vec::new();
    for i in 1..=num_hosts {
        let ip_u32 = network_u32 + i;
        ips.push(Ipv4Addr::from(ip_u32));
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address() {
        let mac = parse_mac_address("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac_address("AA:BB:CC:DD:EE").is_err());
        assert!(parse_mac_address("ZZ:BB:CC:DD:EE:FF").is_err());
    }

    #[test]
    fn test_format_mac_address() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac_address(&mac), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_parse_subnet() {
        let (ip, prefix) = parse_subnet("192.168.1.0/24").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_subnet_to_ips() {
        let ips = subnet_to_ips("192.168.1.0/30").unwrap();
        assert_eq!(ips.len(), 2); // .1 and .2 (exclude .0 network and .3 broadcast)
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[1], Ipv4Addr::new(192, 168, 1, 2));
    }

    #[test]
    fn test_arp_packet_creation() {
        let sender_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = Ipv4Addr::new(192, 168, 1, 100);
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);

        let packet = ArpPacket::new_request(sender_mac, sender_ip, target_ip);

        assert_eq!(packet.hw_size, 6);
        assert_eq!(packet.proto_size, 4);
        assert_eq!(packet.get_opcode(), 1); // Request
        assert_eq!(packet.sender_mac, sender_mac);
        assert_eq!(packet.get_sender_ip(), sender_ip);
        assert_eq!(packet.get_target_ip(), target_ip);
    }
}
