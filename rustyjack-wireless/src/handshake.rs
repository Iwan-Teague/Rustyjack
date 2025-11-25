//! WPA/WPA2 4-way handshake detection and capture
//!
//! This module provides functionality to detect and capture
//! WPA handshakes from EAPOL frames.

use std::time::{Duration, Instant};

use crate::frames::MacAddress;
use crate::capture::CapturedPacket;
use byteorder::{BigEndian, ByteOrder};

/// EAPOL Ethertype (0x888E)
#[allow(dead_code)]
const EAPOL_ETHER_TYPE: u16 = 0x888E;

/// EAPOL packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EapolType {
    /// EAP Packet
    Packet = 0,
    /// EAPOL Start
    Start = 1,
    /// EAPOL Logoff
    Logoff = 2,
    /// EAPOL Key
    Key = 3,
    /// EAPOL Encapsulated ASF Alert
    EncapsulatedAsf = 4,
}

/// WPA Key Information flags
#[derive(Debug, Clone, Copy)]
pub struct KeyInfo {
    raw: u16,
}

impl KeyInfo {
    /// Parse from raw u16
    pub fn new(raw: u16) -> Self {
        Self { raw }
    }
    
    /// Key descriptor version (1=WPA, 2=WPA2)
    pub fn descriptor_version(&self) -> u8 {
        (self.raw & 0x0007) as u8
    }
    
    /// Pairwise key (true) or Group key (false)
    pub fn is_pairwise(&self) -> bool {
        (self.raw & 0x0008) != 0
    }
    
    /// Install flag
    pub fn install(&self) -> bool {
        (self.raw & 0x0040) != 0
    }
    
    /// ACK flag (set by AP in messages 1 and 3)
    pub fn ack(&self) -> bool {
        (self.raw & 0x0080) != 0
    }
    
    /// MIC flag (set when MIC is present)
    pub fn mic(&self) -> bool {
        (self.raw & 0x0100) != 0
    }
    
    /// Secure flag
    pub fn secure(&self) -> bool {
        (self.raw & 0x0200) != 0
    }
    
    /// Error flag
    pub fn error(&self) -> bool {
        (self.raw & 0x0400) != 0
    }
    
    /// Request flag
    pub fn request(&self) -> bool {
        (self.raw & 0x0800) != 0
    }
    
    /// Encrypted Key Data flag
    pub fn encrypted_key_data(&self) -> bool {
        (self.raw & 0x1000) != 0
    }
    
    /// Determine handshake message number
    pub fn message_number(&self) -> u8 {
        match (self.ack(), self.mic(), self.install(), self.secure()) {
            (true, false, false, false) => 1,  // AP->STA: ACK, no MIC
            (false, true, false, false) => 2,  // STA->AP: MIC, no ACK
            (true, true, true, true) => 3,     // AP->STA: ACK, MIC, Install, Secure
            (false, true, false, true) => 4,   // STA->AP: MIC, Secure, no ACK
            _ => 0, // Unknown
        }
    }
}

/// Single handshake message
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    /// Message number (1-4)
    pub message_num: u8,
    /// Timestamp
    pub timestamp: Instant,
    /// Access Point MAC
    pub ap_mac: MacAddress,
    /// Client/Station MAC
    pub client_mac: MacAddress,
    /// ANonce (from AP in message 1)
    pub anonce: Option<[u8; 32]>,
    /// SNonce (from client in message 2)
    pub snonce: Option<[u8; 32]>,
    /// MIC value
    pub mic: Option<[u8; 16]>,
    /// Key Info
    pub key_info: KeyInfo,
    /// Replay counter
    pub replay_counter: u64,
    /// Raw EAPOL data
    pub raw_eapol: Vec<u8>,
}

impl HandshakeMessage {
    /// Parse from EAPOL frame data
    pub fn parse(eapol_data: &[u8], ap_mac: MacAddress, client_mac: MacAddress) -> Option<Self> {
        // Minimum EAPOL-Key size: 99 bytes (4 + 95)
        if eapol_data.len() < 99 {
            return None;
        }
        
        // Check EAPOL type (offset 1 in EAPOL header)
        if eapol_data[1] != EapolType::Key as u8 {
            return None;
        }
        
        // EAPOL-Key starts at offset 4
        let key_data = &eapol_data[4..];
        
        // Key descriptor type (1 = RC4, 2 = RSN/WPA2)
        let _key_type = key_data[0];
        
        // Key Information (2 bytes, big endian)
        let key_info = KeyInfo::new(BigEndian::read_u16(&key_data[1..3]));
        
        // Key Length (2 bytes)
        let _key_length = BigEndian::read_u16(&key_data[3..5]);
        
        // Replay Counter (8 bytes)
        let replay_counter = BigEndian::read_u64(&key_data[5..13]);
        
        // Key Nonce (32 bytes at offset 13)
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&key_data[13..45]);
        
        // Key IV (16 bytes at offset 45) - skip
        
        // Key RSC (8 bytes at offset 61) - skip
        
        // Key ID (8 bytes at offset 69) - skip
        
        // Key MIC (16 bytes at offset 77)
        let mut mic = [0u8; 16];
        mic.copy_from_slice(&key_data[77..93]);
        
        let msg_num = key_info.message_number();
        
        // Determine which nonce this is
        let (anonce, snonce) = match msg_num {
            1 | 3 => (Some(nonce), None),  // AP sends ANonce
            2 | 4 => (None, Some(nonce)),  // Client sends SNonce (only in msg 2)
            _ => (None, None),
        };
        
        // Check if MIC is all zeros (only present in msg 2, 3, 4)
        let has_mic = key_info.mic() && mic.iter().any(|&b| b != 0);
        
        Some(Self {
            message_num: msg_num,
            timestamp: Instant::now(),
            ap_mac,
            client_mac,
            anonce,
            snonce,
            mic: if has_mic { Some(mic) } else { None },
            key_info,
            replay_counter,
            raw_eapol: eapol_data.to_vec(),
        })
    }
}

/// Handshake capture state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// No messages captured
    Empty,
    /// Message 1 captured
    GotMessage1,
    /// Messages 1 and 2 captured (can crack!)
    GotMessage1And2,
    /// Messages 1, 2, and 3 captured
    GotMessage1To3,
    /// All 4 messages captured (complete)
    Complete,
    /// Messages 2 and 3 captured (alternative crack method)
    GotMessage2And3,
}

impl HandshakeState {
    /// Check if handshake is crackable
    pub fn is_crackable(&self) -> bool {
        matches!(
            self,
            Self::GotMessage1And2 | Self::GotMessage2And3 | 
            Self::GotMessage1To3 | Self::Complete
        )
    }
}

/// Handshake capture session
#[derive(Debug)]
pub struct HandshakeCapture {
    /// Target BSSID
    bssid: MacAddress,
    /// Target client (optional)
    target_client: Option<MacAddress>,
    /// Captured messages
    messages: Vec<HandshakeMessage>,
    /// Current state
    state: HandshakeState,
    /// Start time
    started: Instant,
}

impl HandshakeCapture {
    /// Create new capture session
    pub fn new(bssid: MacAddress, target_client: Option<MacAddress>) -> Self {
        Self {
            bssid,
            target_client,
            messages: Vec::with_capacity(4),
            state: HandshakeState::Empty,
            started: Instant::now(),
        }
    }
    
    /// Process a captured packet
    pub fn process_packet(&mut self, packet: &CapturedPacket) {
        if !packet.is_eapol() {
            return;
        }
        
        // Get EAPOL data from frame
        let eapol_data = self.extract_eapol_data(packet);
        if eapol_data.is_none() {
            return;
        }
        let eapol_data = eapol_data.unwrap();
        
        // Get source and destination
        let src = packet.source().unwrap_or(MacAddress::ZERO);
        let dst = packet.destination().unwrap_or(MacAddress::ZERO);
        
        // Determine AP and client
        let (ap_mac, client_mac) = if src == self.bssid {
            (src, dst)
        } else if dst == self.bssid {
            (dst, src)
        } else {
            return; // Not related to our target
        };
        
        // Filter by target client if specified
        if let Some(ref target) = self.target_client {
            if &client_mac != target {
                return;
            }
        }
        
        // Parse handshake message
        if let Some(msg) = HandshakeMessage::parse(&eapol_data, ap_mac, client_mac) {
            log::info!(
                "Captured handshake message {} (AP: {}, Client: {})",
                msg.message_num, ap_mac, client_mac
            );
            
            self.add_message(msg);
        }
    }
    
    /// Add a handshake message
    fn add_message(&mut self, msg: HandshakeMessage) {
        // Check if we already have this message
        let msg_num = msg.message_num;
        
        // Remove old message of same type if present
        self.messages.retain(|m| m.message_num != msg_num);
        self.messages.push(msg);
        
        // Update state
        self.update_state();
    }
    
    /// Update state based on captured messages
    fn update_state(&mut self) {
        let has_msg = |n: u8| self.messages.iter().any(|m| m.message_num == n);
        
        self.state = if has_msg(1) && has_msg(2) && has_msg(3) && has_msg(4) {
            HandshakeState::Complete
        } else if has_msg(1) && has_msg(2) && has_msg(3) {
            HandshakeState::GotMessage1To3
        } else if has_msg(1) && has_msg(2) {
            HandshakeState::GotMessage1And2
        } else if has_msg(2) && has_msg(3) {
            HandshakeState::GotMessage2And3
        } else if has_msg(1) {
            HandshakeState::GotMessage1
        } else {
            HandshakeState::Empty
        };
    }
    
    /// Extract EAPOL data from packet
    fn extract_eapol_data(&self, packet: &CapturedPacket) -> Option<Vec<u8>> {
        let raw = packet.frame.raw();
        
        // Find LLC/SNAP header with EAPOL ethertype
        // Typically at offset 24 or 26 (with QoS)
        for offset in [24, 26, 28, 30] {
            if raw.len() < offset + 8 {
                continue;
            }
            
            // Check for LLC/SNAP with EAPOL
            if raw[offset..offset + 6] == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]
                && raw[offset + 6..offset + 8] == [0x88, 0x8E]
            {
                return Some(raw[offset + 8..].to_vec());
            }
        }
        
        None
    }
    
    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }
    
    /// Check if capture is complete (all 4 messages)
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }
    
    /// Check if handshake is crackable (have enough messages)
    pub fn is_crackable(&self) -> bool {
        self.state.is_crackable()
    }
    
    /// Get captured messages
    pub fn messages(&self) -> &[HandshakeMessage] {
        &self.messages
    }
    
    /// Get message by number
    pub fn get_message(&self, num: u8) -> Option<&HandshakeMessage> {
        self.messages.iter().find(|m| m.message_num == num)
    }
    
    /// Get ANonce (from message 1 or 3)
    pub fn anonce(&self) -> Option<[u8; 32]> {
        self.get_message(1)
            .or_else(|| self.get_message(3))
            .and_then(|m| m.anonce)
    }
    
    /// Get SNonce (from message 2)
    pub fn snonce(&self) -> Option<[u8; 32]> {
        self.get_message(2).and_then(|m| m.snonce)
    }
    
    /// Export handshake data for cracking tools
    pub fn export_for_cracking(&self) -> Option<HandshakeExport> {
        if !self.is_crackable() {
            return None;
        }
        
        let anonce = self.anonce()?;
        let snonce = self.snonce()?;
        let msg2 = self.get_message(2)?;
        
        Some(HandshakeExport {
            bssid: self.bssid,
            client_mac: msg2.client_mac,
            anonce,
            snonce,
            mic: msg2.mic?,
            eapol_data: msg2.raw_eapol.clone(),
        })
    }
    
    /// Clear captured messages
    pub fn reset(&mut self) {
        self.messages.clear();
        self.state = HandshakeState::Empty;
        self.started = Instant::now();
    }
    
    /// Get capture duration
    pub fn duration(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Exported handshake data for cracking
#[derive(Debug, Clone)]
pub struct HandshakeExport {
    /// Access Point BSSID
    pub bssid: MacAddress,
    /// Client MAC address
    pub client_mac: MacAddress,
    /// ANonce from AP
    pub anonce: [u8; 32],
    /// SNonce from client
    pub snonce: [u8; 32],
    /// MIC from message 2
    pub mic: [u8; 16],
    /// Raw EAPOL data from message 2
    pub eapol_data: Vec<u8>,
}

impl HandshakeExport {
    /// Convert to hashcat format (22000)
    pub fn to_hashcat_22000(&self) -> String {
        // WPA*02*MIC*BSSID*CLIENT*ESSID*ANONCE*EAPOL*MSGPAIR
        let mic_hex: String = self.mic.iter().map(|b| format!("{:02x}", b)).collect();
        let bssid_hex: String = self.bssid.0.iter().map(|b| format!("{:02x}", b)).collect();
        let client_hex: String = self.client_mac.0.iter().map(|b| format!("{:02x}", b)).collect();
        let anonce_hex: String = self.anonce.iter().map(|b| format!("{:02x}", b)).collect();
        let eapol_hex: String = self.eapol_data.iter().map(|b| format!("{:02x}", b)).collect();
        
        format!(
            "WPA*02*{}*{}*{}**{}*{}*02",
            mic_hex, bssid_hex, client_hex, anonce_hex, eapol_hex
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_info() {
        // Message 1 flags: Pairwise, ACK
        let ki = KeyInfo::new(0x008A);
        assert!(ki.ack());
        assert!(!ki.mic());
        assert!(!ki.install());
        assert_eq!(ki.message_number(), 1);
    }
    
    #[test]
    fn test_handshake_state() {
        assert!(HandshakeState::GotMessage1And2.is_crackable());
        assert!(HandshakeState::Complete.is_crackable());
        assert!(!HandshakeState::GotMessage1.is_crackable());
    }
}
