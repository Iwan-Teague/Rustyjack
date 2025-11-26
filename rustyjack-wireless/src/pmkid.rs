//! PMKID capture and extraction
//!
//! PMKID attacks allow cracking WPA2 passwords without capturing a full handshake.
//! The PMKID is sent in the first EAPOL message from the AP, so no deauth is needed.
//!
//! ## How it works
//! 1. Send association request to target AP
//! 2. AP responds with EAPOL Message 1 containing PMKID in RSN IE
//! 3. Extract PMKID and crack offline with hashcat mode 22000
//!
//! ## Advantages over handshake capture
//! - No need to wait for client
//! - No deauth attack needed (stealthier)
//! - Works on networks with no active clients
//! - Faster acquisition (seconds vs minutes)

use std::time::{Duration, Instant};

use crate::error::{WirelessError, Result};
use crate::frames::MacAddress;
use crate::capture::{PacketCapture, CaptureFilter, CapturedPacket};
use crate::interface::WirelessInterface;

/// PMKID data extracted from EAPOL Message 1
#[derive(Debug, Clone)]
pub struct PmkidCapture {
    /// Target BSSID (Access Point MAC)
    pub bssid: MacAddress,
    /// Client MAC that received the PMKID
    pub client_mac: MacAddress,
    /// The PMKID value (16 bytes)
    pub pmkid: [u8; 16],
    /// SSID of the network (if known)
    pub ssid: Option<String>,
    /// Timestamp of capture
    pub timestamp: Instant,
}

impl PmkidCapture {
    /// Convert to hashcat 22000 format
    /// Format: WPA*01*PMKID*BSSID*CLIENT*ESSID_HEX
    pub fn to_hashcat_22000(&self) -> String {
        let pmkid_hex: String = self.pmkid.iter().map(|b| format!("{:02x}", b)).collect();
        let bssid_hex: String = self.bssid.0.iter().map(|b| format!("{:02x}", b)).collect();
        let client_hex: String = self.client_mac.0.iter().map(|b| format!("{:02x}", b)).collect();
        let ssid_hex: String = self.ssid
            .as_ref()
            .map(|s| s.bytes().map(|b| format!("{:02x}", b)).collect())
            .unwrap_or_default();
        
        format!(
            "WPA*01*{}*{}*{}*{}",
            pmkid_hex, bssid_hex, client_hex, ssid_hex
        )
    }
    
    /// Convert to hcxpcapngtool compatible format
    pub fn to_hcx_format(&self) -> String {
        self.to_hashcat_22000()
    }
}

/// PMKID capturer
pub struct PmkidCapturer {
    interface_name: String,
    captures: Vec<PmkidCapture>,
}

impl PmkidCapturer {
    /// Create new PMKID capturer
    pub fn new(interface: &WirelessInterface) -> Result<Self> {
        if !interface.is_monitor_mode()? {
            return Err(WirelessError::MonitorMode(
                "Interface must be in monitor mode for PMKID capture".into()
            ));
        }
        
        Ok(Self {
            interface_name: interface.name().to_string(),
            captures: Vec::new(),
        })
    }
    
    /// Create from interface name
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(Self {
            interface_name: name.to_string(),
            captures: Vec::new(),
        })
    }
    
    /// Passive PMKID capture - listen for PMKIDs from any network
    /// This captures PMKIDs from existing authentication attempts
    pub fn passive_capture(&mut self, duration: Duration) -> Result<Vec<PmkidCapture>> {
        log::info!("Starting passive PMKID capture for {:?}", duration);
        
        let mut capture = PacketCapture::new(&self.interface_name)?;
        capture.set_filter(CaptureFilter::eapol_only());
        
        let start = Instant::now();
        let mut found = Vec::new();
        
        while start.elapsed() < duration {
            if let Some(packet) = capture.next_packet()? {
                if let Some(pmkid) = self.extract_pmkid(&packet) {
                    log::info!("Found PMKID for BSSID: {}", pmkid.bssid);
                    found.push(pmkid.clone());
                    self.captures.push(pmkid);
                }
            }
        }
        
        log::info!("Passive capture complete: {} PMKIDs found", found.len());
        Ok(found)
    }
    
    /// Targeted PMKID capture - actively try to get PMKID from specific AP
    /// Sends association request to trigger EAPOL Message 1
    pub fn active_capture(
        &mut self,
        bssid: MacAddress,
        ssid: Option<&str>,
        timeout: Duration,
    ) -> Result<Option<PmkidCapture>> {
        log::info!("Starting active PMKID capture for BSSID: {}", bssid);
        
        // Start packet capture
        let mut capture = PacketCapture::new(&self.interface_name)?;
        capture.set_filter(CaptureFilter::for_bssid(bssid));
        
        let start = Instant::now();
        
        // Send authentication and association frames
        // Note: This requires sending management frames which needs implementation
        // For now, we'll do passive capture on the target BSSID
        
        while start.elapsed() < timeout {
            if let Some(packet) = capture.next_packet()? {
                if let Some(mut pmkid) = self.extract_pmkid(&packet) {
                    if pmkid.bssid == bssid {
                        pmkid.ssid = ssid.map(|s| s.to_string());
                        log::info!("Captured PMKID for target BSSID: {}", bssid);
                        self.captures.push(pmkid.clone());
                        return Ok(Some(pmkid));
                    }
                }
            }
        }
        
        log::warn!("PMKID capture timeout for BSSID: {}", bssid);
        Ok(None)
    }
    
    /// Extract PMKID from captured EAPOL packet
    fn extract_pmkid(&self, packet: &CapturedPacket) -> Option<PmkidCapture> {
        if !packet.is_eapol() {
            return None;
        }
        
        let raw = packet.frame.raw();
        
        // Find EAPOL data in the frame
        // Look for LLC/SNAP header with EAPOL ethertype (88 8E)
        let eapol_offset = self.find_eapol_offset(raw)?;
        let eapol_data = &raw[eapol_offset..];
        
        // Check EAPOL type (offset 1) - must be Key (3)
        if eapol_data.len() < 100 || eapol_data[1] != 3 {
            return None;
        }
        
        // EAPOL-Key starts at offset 4
        let key_data = &eapol_data[4..];
        
        // Key Information (2 bytes at offset 1)
        let key_info = u16::from_be_bytes([key_data[1], key_data[2]]);
        
        // Check if this is Message 1 (ACK set, MIC not set)
        let is_ack = (key_info & 0x0080) != 0;
        let is_mic = (key_info & 0x0100) != 0;
        
        if !is_ack || is_mic {
            return None; // Not Message 1
        }
        
        // Key Data Length (2 bytes at offset 93)
        if key_data.len() < 95 {
            return None;
        }
        let key_data_len = u16::from_be_bytes([key_data[93], key_data[94]]) as usize;
        
        if key_data.len() < 95 + key_data_len {
            return None;
        }
        
        // Search for PMKID in RSN IE
        let key_data_content = &key_data[95..95 + key_data_len];
        let pmkid = self.find_pmkid_in_rsn(key_data_content)?;
        
        // Get MAC addresses
        let bssid = packet.bssid()?;
        let client_mac = packet.destination()?;
        
        Some(PmkidCapture {
            bssid,
            client_mac,
            pmkid,
            ssid: None,
            timestamp: Instant::now(),
        })
    }
    
    /// Find EAPOL data offset in raw frame
    fn find_eapol_offset(&self, raw: &[u8]) -> Option<usize> {
        // Look for LLC/SNAP header: AA AA 03 00 00 00 88 8E
        for offset in [24, 26, 28, 30, 32] {
            if raw.len() < offset + 8 {
                continue;
            }
            
            if raw[offset..offset + 6] == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]
                && raw[offset + 6..offset + 8] == [0x88, 0x8E]
            {
                return Some(offset + 8);
            }
        }
        None
    }
    
    /// Find PMKID in RSN IE
    fn find_pmkid_in_rsn(&self, data: &[u8]) -> Option<[u8; 16]> {
        let mut pos = 0;
        
        while pos + 2 <= data.len() {
            let tag_type = data[pos];
            let tag_len = data[pos + 1] as usize;
            
            if pos + 2 + tag_len > data.len() {
                break;
            }
            
            // RSN IE (tag 0x30) or Vendor Specific (tag 0xDD with WPA OUI)
            if tag_type == 0x30 {
                // RSN IE - search for PMKID List
                let rsn_data = &data[pos + 2..pos + 2 + tag_len];
                if let Some(pmkid) = self.extract_pmkid_from_rsn_ie(rsn_data) {
                    return Some(pmkid);
                }
            }
            
            pos += 2 + tag_len;
        }
        
        None
    }
    
    /// Extract PMKID from RSN IE content
    fn extract_pmkid_from_rsn_ie(&self, rsn: &[u8]) -> Option<[u8; 16]> {
        // RSN IE structure:
        // Version (2) + Group Cipher (4) + Pairwise Count (2) + Pairwise Suites (n*4)
        // + AKM Count (2) + AKM Suites (n*4) + RSN Capabilities (2)
        // + [PMKID Count (2) + PMKIDs (n*16)]
        
        if rsn.len() < 8 {
            return None;
        }
        
        let mut pos = 2; // Skip version
        
        // Skip Group Cipher Suite (4 bytes)
        pos += 4;
        if pos + 2 > rsn.len() {
            return None;
        }
        
        // Pairwise Cipher Suite Count
        let pairwise_count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
        pos += 2 + pairwise_count * 4;
        
        if pos + 2 > rsn.len() {
            return None;
        }
        
        // AKM Suite Count
        let akm_count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
        pos += 2 + akm_count * 4;
        
        if pos + 2 > rsn.len() {
            return None;
        }
        
        // RSN Capabilities (2 bytes)
        pos += 2;
        
        if pos + 2 > rsn.len() {
            return None;
        }
        
        // PMKID Count
        let pmkid_count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
        pos += 2;
        
        if pmkid_count == 0 || pos + 16 > rsn.len() {
            return None;
        }
        
        // Extract first PMKID (16 bytes)
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&rsn[pos..pos + 16]);
        
        // Verify PMKID is not all zeros
        if pmkid.iter().all(|&b| b == 0) {
            return None;
        }
        
        Some(pmkid)
    }
    
    /// Get all captured PMKIDs
    pub fn captures(&self) -> &[PmkidCapture] {
        &self.captures
    }
    
    /// Export all captures to hashcat format
    pub fn export_hashcat(&self) -> Vec<String> {
        self.captures.iter().map(|c| c.to_hashcat_22000()).collect()
    }
    
    /// Clear captured PMKIDs
    pub fn clear(&mut self) {
        self.captures.clear();
    }
}

/// Quick PMKID capture function
pub fn quick_pmkid_capture(
    interface: &str,
    bssid: Option<&str>,
    ssid: Option<&str>,
    channel: u8,
    timeout_secs: u64,
) -> Result<Vec<PmkidCapture>> {
    // Setup interface
    let mut iface = WirelessInterface::new(interface)?;
    iface.set_monitor_mode()?;
    iface.set_channel(channel)?;
    
    let mut capturer = PmkidCapturer::new(&iface)?;
    
    let result = if let Some(bssid_str) = bssid {
        let target: MacAddress = bssid_str.parse()
            .map_err(|e| WirelessError::InvalidMac(format!("{}", e)))?;
        
        match capturer.active_capture(target, ssid, Duration::from_secs(timeout_secs))? {
            Some(pmkid) => vec![pmkid],
            None => Vec::new(),
        }
    } else {
        capturer.passive_capture(Duration::from_secs(timeout_secs))?
    };
    
    // Cleanup
    iface.set_managed_mode()?;
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pmkid_to_hashcat() {
        let pmkid = PmkidCapture {
            bssid: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
            client_mac: "11:22:33:44:55:66".parse().unwrap(),
            pmkid: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            ssid: Some("TestNetwork".to_string()),
            timestamp: Instant::now(),
        };
        
        let hashcat = pmkid.to_hashcat_22000();
        assert!(hashcat.starts_with("WPA*01*"));
        assert!(hashcat.contains("aabbccddeeff")); // BSSID
        assert!(hashcat.contains("112233445566")); // Client MAC
    }
}
