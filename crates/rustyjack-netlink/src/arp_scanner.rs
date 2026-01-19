use libc::{sockaddr_ll, socket, AF_PACKET, SOCK_RAW};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::{ArpError, ArpPacket, ArpScanConfig, ArpScanResult};
use crate::arp::{parse_mac_address, subnet_to_ips};
use crate::error::{NetlinkError, Result};
use crate::interface::InterfaceManager;

/// ARP Scanner for discovering hosts on local network
pub struct ArpScanner {
    config: ArpScanConfig,
}

impl ArpScanner {
    /// Create a new ARP scanner with default configuration
    pub fn new() -> Self {
        ArpScanner {
            config: ArpScanConfig::default(),
        }
    }

    /// Create a new ARP scanner with custom configuration
    pub fn with_config(config: ArpScanConfig) -> Self {
        ArpScanner { config }
    }

    /// Scan a single IP address
    pub fn scan_ip(&self, target_ip: Ipv4Addr, interface: &str) -> Result<Option<ArpScanResult>> {
        let start_time = Instant::now();

        // Get interface index and MAC address
        let if_index = self.get_interface_index(interface)?;
        let local_mac = self.get_interface_mac(interface)?;
        let local_ip = self.get_interface_ip(interface)?;

        // Create raw socket
        let sock_fd = self.create_raw_socket(interface)?;

        // Bind to interface
        self.bind_to_interface(sock_fd, if_index, interface)?;

        // Set timeout
        self.set_socket_timeout(sock_fd, self.config.timeout_ms, interface)?;

        // Try with retries
        for attempt in 0..=self.config.retries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(self.config.retry_delay_ms));
            }

            // Send ARP request
            let packet = ArpPacket::new_request(local_mac, local_ip, target_ip);
            self.send_arp_packet(sock_fd, &packet, if_index, interface, target_ip)?;

            // Try to receive reply
            match self.receive_arp_reply(sock_fd, target_ip, interface) {
                Ok(Some(reply_mac)) => {
                    let response_time = start_time.elapsed().as_millis() as u64;
                    unsafe {
                        libc::close(sock_fd);
                    }

                    return Ok(Some(ArpScanResult {
                        ip: target_ip,
                        mac: reply_mac,
                        vendor: None, // Could be populated from OUI database
                        response_time_ms: response_time,
                    }));
                }
                Ok(None) => continue, // Timeout, try again
                Err(e) => {
                    unsafe {
                        libc::close(sock_fd);
                    }
                    return Err(e);
                }
            }
        }

        // No response after retries
        unsafe {
            libc::close(sock_fd);
        }
        Ok(None)
    }

    /// Scan multiple IP addresses
    pub fn scan_ips(&self, targets: &[Ipv4Addr], interface: &str) -> Result<Vec<ArpScanResult>> {
        let mut results = Vec::new();

        for target in targets {
            if let Some(result) = self.scan_ip(*target, interface)? {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Scan entire subnet
    pub fn scan_subnet(&self, subnet: &str, interface: &str) -> Result<Vec<ArpScanResult>> {
        let ips = subnet_to_ips(subnet)?;

        tracing::info!(
            "Scanning {} hosts in subnet {} on {}",
            ips.len(),
            subnet,
            interface
        );

        self.scan_ips(&ips, interface)
    }

    /// Quick check if host is alive (single attempt, shorter timeout)
    pub fn is_alive(&self, target_ip: Ipv4Addr, interface: &str) -> Result<bool> {
        let mut quick_config = self.config.clone();
        quick_config.timeout_ms = 500;
        quick_config.retries = 0;

        let scanner = ArpScanner::with_config(quick_config);
        Ok(scanner.scan_ip(target_ip, interface)?.is_some())
    }

    /// Get MAC address for an IP (ARP lookup)
    pub fn get_mac(&self, target_ip: Ipv4Addr, interface: &str) -> Result<Option<[u8; 6]>> {
        Ok(self.scan_ip(target_ip, interface)?.map(|r| r.mac))
    }

    // Private helper methods

    fn create_raw_socket(&self, interface: &str) -> Result<i32> {
        let sock_fd =
            unsafe { socket(AF_PACKET, SOCK_RAW, (libc::ETH_P_ARP as u16).to_be() as i32) };

        if sock_fd < 0 {
            let err = std::io::Error::last_os_error();
            return if err.raw_os_error() == Some(libc::EPERM) {
                Err(NetlinkError::Arp(ArpError::PermissionDenied))
            } else {
                Err(NetlinkError::Arp(ArpError::SocketCreate {
                    interface: interface.to_string(),
                    source: err,
                }))
            };
        }

        Ok(sock_fd)
    }

    fn bind_to_interface(&self, sock_fd: i32, if_index: u32, interface: &str) -> Result<()> {
        let mut sll: sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        sll.sll_ifindex = if_index as i32;

        let result = unsafe {
            libc::bind(
                sock_fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if result < 0 {
            return Err(NetlinkError::Arp(ArpError::SocketBind {
                interface: interface.to_string(),
                source: std::io::Error::last_os_error(),
            }));
        }

        Ok(())
    }

    fn set_socket_timeout(&self, sock_fd: i32, timeout_ms: u64, interface: &str) -> Result<()> {
        let timeout = libc::timeval {
            tv_sec: (timeout_ms / 1000) as libc::time_t,
            tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
        };

        let result = unsafe {
            libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };

        if result < 0 {
            return Err(NetlinkError::Arp(ArpError::Io {
                interface: interface.to_string(),
                source: std::io::Error::last_os_error(),
            }));
        }

        Ok(())
    }

    fn send_arp_packet(
        &self,
        sock_fd: i32,
        packet: &ArpPacket,
        if_index: u32,
        interface: &str,
        target_ip: Ipv4Addr,
    ) -> Result<()> {
        // Ethernet frame: dest MAC (broadcast) + source MAC + EtherType (ARP) + ARP packet
        let local_mac = self.get_interface_mac(interface)?;

        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xFF; 6]); // Broadcast MAC
        frame.extend_from_slice(&local_mac); // Source MAC
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
        frame.extend_from_slice(packet.as_bytes()); // ARP packet

        let mut sll: sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        sll.sll_ifindex = if_index as i32;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&[0xFF; 6]);

        let result = unsafe {
            libc::sendto(
                sock_fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if result < 0 {
            return Err(NetlinkError::Arp(ArpError::SendRequest {
                target_ip,
                interface: interface.to_string(),
                source: std::io::Error::last_os_error(),
            }));
        }

        Ok(())
    }

    fn receive_arp_reply(
        &self,
        sock_fd: i32,
        target_ip: Ipv4Addr,
        interface: &str,
    ) -> Result<Option<[u8; 6]>> {
        let mut buffer = [0u8; 2048];

        loop {
            let result = unsafe {
                libc::recvfrom(
                    sock_fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut
                {
                    return Ok(None); // Timeout
                }
                return Err(NetlinkError::Arp(ArpError::ReceiveReply {
                    interface: interface.to_string(),
                    source: err,
                }));
            }

            // Skip Ethernet header (14 bytes: 6 dest + 6 src + 2 ethertype)
            if result < 14 {
                continue;
            }

            let arp_data = &buffer[14..result as usize];
            if let Some(arp_packet) = ArpPacket::from_bytes(arp_data) {
                // Check if this is a reply (opcode 2) and matches our target IP
                if arp_packet.get_opcode() == 2 && arp_packet.get_sender_ip() == target_ip {
                    return Ok(Some(arp_packet.sender_mac));
                }
            }
        }
    }

    fn get_interface_index(&self, interface: &str) -> Result<u32> {
        let mgr = InterfaceManager::new()?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { mgr.get_index(interface).await })
        })
    }

    fn get_interface_mac(&self, interface: &str) -> Result<[u8; 6]> {
        use std::fs;

        let path = format!("/sys/class/net/{}/address", interface);
        let mac_str = fs::read_to_string(&path).map_err(|e| {
            NetlinkError::Arp(ArpError::MacAddressError {
                interface: interface.to_string(),
                reason: format!("Failed to read {}: {}", path, e),
            })
        })?;

        parse_mac_address(mac_str.trim()).map_err(|e| NetlinkError::Arp(e))
    }

    fn get_interface_ip(&self, interface: &str) -> Result<Ipv4Addr> {
        let mgr = InterfaceManager::new()?;

        let addrs = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { mgr.get_addresses(interface).await })
        })?;

        // Find first IPv4 address
        for addr_info in addrs {
            if let std::net::IpAddr::V4(ipv4) = addr_info.address {
                return Ok(ipv4);
            }
        }

        Err(NetlinkError::Arp(ArpError::MacAddressError {
            interface: interface.to_string(),
            reason: "No IPv4 address configured on interface".to_string(),
        }))
    }
}

impl Default for ArpScanner {
    fn default() -> Self {
        Self::new()
    }
}
