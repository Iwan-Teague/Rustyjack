//! Packet capture functionality
//!
//! Capture and parse 802.11 frames from a monitor mode interface.

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use nix::libc::{self, c_int, c_void, sockaddr_ll, AF_PACKET, SOCK_RAW};

use crate::error::{WirelessError, Result};
use crate::frames::{Ieee80211Frame, FrameType, FrameSubtype, MacAddress};
use crate::radiotap::{RadiotapHeader, RadiotapInfo};
use crate::interface::WirelessInterface;
use crate::nl80211::get_ifindex;

/// Maximum capture buffer size
const CAPTURE_BUFFER_SIZE: usize = 65536;

/// Packet capture socket
pub struct PacketCapture {
    fd: RawFd,
    #[allow(dead_code)]
    ifindex: i32,
    buffer: Vec<u8>,
    filter: CaptureFilter,
    stats: CaptureStats,
}

impl PacketCapture {
    /// Create new capture on interface
    pub fn new(interface: &str) -> Result<Self> {
        if !crate::check_privileges() {
            return Err(WirelessError::Permission(
                "Root privileges required for packet capture".into()
            ));
        }
        
        let ifindex = get_ifindex(interface)?;
        
        // Create raw socket
        let fd = unsafe {
            libc::socket(
                AF_PACKET,
                SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as c_int,
            )
        };
        
        if fd < 0 {
            return Err(WirelessError::Socket(
                format!("Failed to create capture socket: {}", io::Error::last_os_error())
            ));
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
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };
        
        if bind_result < 0 {
            unsafe { libc::close(fd) };
            return Err(WirelessError::Socket(
                format!("Failed to bind capture socket: {}", io::Error::last_os_error())
            ));
        }
        
        // Set receive timeout
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const c_void,
                mem::size_of::<libc::timeval>() as u32,
            );
        }
        
        log::debug!("Created capture socket on interface index {}", ifindex);
        
        Ok(Self {
            fd,
            ifindex,
            buffer: vec![0u8; CAPTURE_BUFFER_SIZE],
            filter: CaptureFilter::default(),
            stats: CaptureStats::default(),
        })
    }
    
    /// Create from WirelessInterface
    pub fn from_interface(iface: &WirelessInterface) -> Result<Self> {
        Self::new(iface.name())
    }
    
    /// Set capture filter
    pub fn set_filter(&mut self, filter: CaptureFilter) {
        self.filter = filter;
    }
    
    /// Read next packet (blocking with timeout)
    pub fn next_packet(&mut self) -> Result<Option<CapturedPacket>> {
        let received = unsafe {
            libc::recv(
                self.fd,
                self.buffer.as_mut_ptr() as *mut c_void,
                self.buffer.len(),
                0,
            )
        };
        
        if received < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                return Ok(None);
            }
            return Err(WirelessError::Capture(format!("Receive failed: {}", err)));
        }
        
        if received == 0 {
            return Ok(None);
        }
        
        let data = &self.buffer[..received as usize];
        self.stats.packets_received += 1;
        self.stats.bytes_received += received as u64;
        
        // Parse radiotap header
        let (radiotap, rt_len) = match RadiotapHeader::parse(data) {
            Ok(r) => r,
            Err(e) => {
                log::trace!("Failed to parse radiotap: {}", e);
                return Ok(None);
            }
        };
        
        // Parse 802.11 frame
        let frame_data = &data[rt_len..];
        if frame_data.len() < 24 {
            return Ok(None);
        }
        
        let frame = match Ieee80211Frame::parse(frame_data) {
            Ok(f) => f,
            Err(e) => {
                log::trace!("Failed to parse frame: {}", e);
                return Ok(None);
            }
        };
        
        // Apply filter
        if !self.filter.matches(&frame) {
            return Ok(None);
        }
        
        self.stats.packets_passed_filter += 1;
        
        let packet = CapturedPacket {
            timestamp: Instant::now(),
            radiotap_info: RadiotapInfo::parse(&radiotap),
            frame,
            raw_data: data.to_vec(),
        };
        
        Ok(Some(packet))
    }
    
    /// Capture packets for a duration
    pub fn capture_for(&mut self, duration: Duration) -> Result<Vec<CapturedPacket>> {
        let mut packets = Vec::new();
        let start = Instant::now();
        
        while start.elapsed() < duration {
            if let Some(packet) = self.next_packet()? {
                packets.push(packet);
            }
        }
        
        Ok(packets)
    }
    
    /// Capture until a condition is met
    pub fn capture_until<F>(&mut self, mut condition: F, timeout: Duration) -> Result<Vec<CapturedPacket>>
    where
        F: FnMut(&CapturedPacket) -> bool,
    {
        let mut packets = Vec::new();
        let start = Instant::now();
        
        while start.elapsed() < timeout {
            if let Some(packet) = self.next_packet()? {
                let should_stop = condition(&packet);
                packets.push(packet);
                if should_stop {
                    break;
                }
            }
        }
        
        Ok(packets)
    }
    
    /// Get capture statistics
    pub fn stats(&self) -> &CaptureStats {
        &self.stats
    }
    
    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = CaptureStats::default();
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for PacketCapture {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Capture filter configuration
#[derive(Debug, Clone, Default)]
pub struct CaptureFilter {
    /// Only capture specific BSSID
    pub bssid: Option<MacAddress>,
    /// Only capture specific source MAC
    pub source: Option<MacAddress>,
    /// Only capture specific destination MAC
    pub destination: Option<MacAddress>,
    /// Only capture specific frame types
    pub frame_types: Option<Vec<FrameType>>,
    /// Only capture specific subtypes
    pub subtypes: Option<Vec<FrameSubtype>>,
    /// Only capture EAPOL frames (for handshake)
    pub eapol_only: bool,
}

impl CaptureFilter {
    /// Create filter that only captures EAPOL frames
    pub fn eapol_only() -> Self {
        Self {
            eapol_only: true,
            ..Default::default()
        }
    }
    
    /// Create filter for specific BSSID
    pub fn for_bssid(bssid: MacAddress) -> Self {
        Self {
            bssid: Some(bssid),
            ..Default::default()
        }
    }
    
    /// Create filter for management frames only
    pub fn management_only() -> Self {
        Self {
            frame_types: Some(vec![FrameType::Management]),
            ..Default::default()
        }
    }
    
    /// Create filter for deauth frames
    pub fn deauth_only() -> Self {
        Self {
            frame_types: Some(vec![FrameType::Management]),
            subtypes: Some(vec![FrameSubtype::Deauthentication]),
            ..Default::default()
        }
    }
    
    /// Add BSSID filter
    pub fn with_bssid(mut self, bssid: MacAddress) -> Self {
        self.bssid = Some(bssid);
        self
    }
    
    /// Check if frame matches filter
    pub fn matches(&self, frame: &Ieee80211Frame) -> bool {
        // EAPOL check
        if self.eapol_only && !frame.is_eapol() {
            return false;
        }
        
        // BSSID check
        if let Some(ref filter_bssid) = self.bssid {
            if let Some(frame_bssid) = frame.bssid() {
                if &frame_bssid != filter_bssid {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        // Source check
        if let Some(ref filter_src) = self.source {
            if let Some(frame_src) = frame.source() {
                if &frame_src != filter_src {
                    return false;
                }
            }
        }
        
        // Destination check
        if let Some(ref filter_dst) = self.destination {
            if let Some(frame_dst) = frame.destination() {
                if &frame_dst != filter_dst {
                    return false;
                }
            }
        }
        
        // Frame type check
        if let Some(ref types) = self.frame_types {
            if !types.contains(&frame.frame_type()) {
                return false;
            }
        }
        
        // Subtype check
        if let Some(ref subtypes) = self.subtypes {
            if !subtypes.contains(&frame.subtype()) {
                return false;
            }
        }
        
        true
    }
}

/// A captured packet with metadata
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Capture timestamp
    pub timestamp: Instant,
    /// Radiotap info (signal, channel, etc.)
    pub radiotap_info: RadiotapInfo,
    /// Parsed 802.11 frame
    pub frame: Ieee80211Frame,
    /// Raw packet data (including radiotap)
    pub raw_data: Vec<u8>,
}

impl CapturedPacket {
    /// Get signal strength
    pub fn signal_dbm(&self) -> Option<i8> {
        self.radiotap_info.signal_dbm
    }
    
    /// Get channel
    pub fn channel(&self) -> Option<u8> {
        self.radiotap_info.channel
    }
    
    /// Check if this is an EAPOL frame (handshake)
    pub fn is_eapol(&self) -> bool {
        self.frame.is_eapol()
    }
    
    /// Check if this is a deauth frame
    pub fn is_deauth(&self) -> bool {
        self.frame.is_deauth()
    }
    
    /// Get source MAC
    pub fn source(&self) -> Option<MacAddress> {
        self.frame.source()
    }
    
    /// Get destination MAC
    pub fn destination(&self) -> Option<MacAddress> {
        self.frame.destination()
    }
    
    /// Get BSSID
    pub fn bssid(&self) -> Option<MacAddress> {
        self.frame.bssid()
    }
}

/// Capture statistics
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    /// Total packets received
    pub packets_received: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Packets that passed filter
    pub packets_passed_filter: u64,
    /// EAPOL frames captured
    pub eapol_frames: u64,
    /// Deauth frames captured
    pub deauth_frames: u64,
}

impl CaptureStats {
    /// Filter pass rate
    pub fn filter_pass_rate(&self) -> f32 {
        if self.packets_received == 0 {
            0.0
        } else {
            (self.packets_passed_filter as f32 / self.packets_received as f32) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capture_filter() {
        let filter = CaptureFilter::eapol_only();
        assert!(filter.eapol_only);
        
        let filter = CaptureFilter::for_bssid("AA:BB:CC:DD:EE:FF".parse().unwrap());
        assert!(filter.bssid.is_some());
    }
}
