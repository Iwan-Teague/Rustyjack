//! Stealth and Evasion Module
//! 
//! Provides MAC randomization, passive mode, and TX power control
//! for conducting wireless operations without detection.

use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::path::PathBuf;

/// Saved MAC address state for restoration
#[derive(Debug, Clone)]
pub struct MacState {
    pub interface: String,
    pub original_mac: String,
    pub current_mac: String,
    pub is_randomized: bool,
}

/// TX Power levels for different operation modes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TxPowerLevel {
    /// Minimum power - very short range, maximum stealth
    Stealth,      // ~1 dBm
    /// Low power - short range operations
    Low,          // ~5 dBm  
    /// Medium power - balanced range/stealth
    Medium,       // ~12 dBm
    /// High power - normal operations
    High,         // ~18 dBm
    /// Maximum power - maximum range
    Maximum,      // ~20+ dBm (adapter dependent)
    /// Custom power level in dBm
    Custom(i32),
}

impl TxPowerLevel {
    pub fn to_dbm(&self) -> i32 {
        match self {
            TxPowerLevel::Stealth => 1,
            TxPowerLevel::Low => 5,
            TxPowerLevel::Medium => 12,
            TxPowerLevel::High => 18,
            TxPowerLevel::Maximum => 30, // Will be capped by adapter
            TxPowerLevel::Custom(dbm) => *dbm,
        }
    }
    
    pub fn to_mw(&self) -> u32 {
        // Convert dBm to mW: mW = 10^(dBm/10)
        let dbm = self.to_dbm() as f64;
        (10f64.powf(dbm / 10.0)) as u32
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "stealth" | "min" | "minimum" => Some(TxPowerLevel::Stealth),
            "low" => Some(TxPowerLevel::Low),
            "medium" | "med" => Some(TxPowerLevel::Medium),
            "high" => Some(TxPowerLevel::High),
            "max" | "maximum" => Some(TxPowerLevel::Maximum),
            _ => s.parse::<i32>().ok().map(TxPowerLevel::Custom),
        }
    }
}

/// Passive mode configuration
#[derive(Debug, Clone)]
pub struct PassiveModeConfig {
    /// Interface to use
    pub interface: String,
    /// Channel to monitor (0 = hop all channels)
    pub channel: u8,
    /// Duration in seconds (0 = indefinite)
    pub duration: u32,
    /// Capture probe requests
    pub capture_probes: bool,
    /// Capture beacons
    pub capture_beacons: bool,
    /// Capture data frames (for handshakes)
    pub capture_data: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
}

/// Result of passive monitoring
#[derive(Debug, Clone, Default)]
pub struct PassiveResult {
    pub networks_discovered: Vec<DiscoveredNetwork>,
    pub clients_discovered: Vec<DiscoveredClient>,
    pub probe_requests: Vec<ProbeRequest>,
    pub duration_secs: u32,
    pub packets_captured: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveredNetwork {
    pub ssid: String,
    pub bssid: String,
    pub channel: u8,
    pub signal_dbm: i32,
    pub encryption: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub beacon_count: u32,
}

#[derive(Debug, Clone)]
pub struct DiscoveredClient {
    pub mac: String,
    pub associated_bssid: Option<String>,
    pub signal_dbm: i32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub packet_count: u32,
}

#[derive(Debug, Clone)]
pub struct ProbeRequest {
    pub client_mac: String,
    pub ssid_probed: String,
    pub signal_dbm: i32,
    pub timestamp: u64,
}

/// Stealth operations manager
pub struct StealthManager {
    saved_macs: Vec<MacState>,
    saved_tx_powers: Vec<(String, i32)>,
}

impl StealthManager {
    pub fn new() -> Self {
        Self {
            saved_macs: Vec::new(),
            saved_tx_powers: Vec::new(),
        }
    }
    
    /// Get the current MAC address of an interface
    pub fn get_mac(&self, interface: &str) -> io::Result<String> {
        // Read from /sys/class/net/<iface>/address
        let path = format!("/sys/class/net/{}/address", interface);
        fs::read_to_string(&path)
            .map(|s| s.trim().to_uppercase())
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, 
                format!("Cannot read MAC for {}: {}", interface, e)))
    }
    
    /// Generate a random MAC address
    /// Preserves locally administered bit and unicast bit
    pub fn generate_random_mac(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        // Simple PRNG
        let mut state = seed;
        let mut bytes = [0u8; 6];
        for i in 0..6 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes[i] = (state >> 33) as u8;
        }
        
        // Set locally administered bit (bit 1 of first byte)
        // Clear multicast bit (bit 0 of first byte)
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }
    
    /// Generate a MAC that looks like a specific vendor
    pub fn generate_vendor_mac(&self, vendor: &str) -> String {
        // Common vendor OUIs
        let oui = match vendor.to_lowercase().as_str() {
            "apple" | "iphone" | "macbook" => "F4:0F:24",
            "samsung" => "00:1A:8A",
            "google" | "pixel" => "F8:8F:CA",
            "intel" => "00:1E:67",
            "realtek" => "00:E0:4C",
            "tp-link" => "50:C7:BF",
            "netgear" => "00:14:6C",
            "cisco" => "00:1B:D5",
            "huawei" => "48:46:FB",
            _ => "02:00:00", // Locally administered
        };
        
        // Generate random last 3 bytes
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        let mut state = seed;
        let mut bytes = [0u8; 3];
        for i in 0..3 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes[i] = (state >> 33) as u8;
        }
        
        format!("{}:{:02X}:{:02X}:{:02X}", oui, bytes[0], bytes[1], bytes[2])
    }
    
    /// Randomize MAC address on interface
    pub fn randomize_mac(&mut self, interface: &str) -> io::Result<MacState> {
        // Save original MAC
        let original_mac = self.get_mac(interface)?;
        
        // Generate new MAC
        let new_mac = self.generate_random_mac();
        
        // Apply new MAC
        self.set_mac(interface, &new_mac)?;
        
        let state = MacState {
            interface: interface.to_string(),
            original_mac: original_mac.clone(),
            current_mac: new_mac,
            is_randomized: true,
        };
        
        self.saved_macs.push(state.clone());
        Ok(state)
    }
    
    /// Set a specific MAC address
    pub fn set_mac(&self, interface: &str, mac: &str) -> io::Result<()> {
        // Bring interface down
        let down = Command::new("ip")
            .args(["link", "set", interface, "down"])
            .output()?;
        
        if !down.status.success() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "Failed to bring interface down - need root?"));
        }
        
        // Set new MAC
        let set_mac = Command::new("ip")
            .args(["link", "set", interface, "address", mac])
            .output()?;
        
        if !set_mac.status.success() {
            // Try to bring interface back up before returning error
            let _ = Command::new("ip")
                .args(["link", "set", interface, "up"])
                .output();
            
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Failed to set MAC: {}", 
                    String::from_utf8_lossy(&set_mac.stderr))));
        }
        
        // Bring interface back up
        let up = Command::new("ip")
            .args(["link", "set", interface, "up"])
            .output()?;
        
        if !up.status.success() {
            return Err(io::Error::new(io::ErrorKind::Other,
                "Failed to bring interface back up"));
        }
        
        Ok(())
    }
    
    /// Restore original MAC address
    pub fn restore_mac(&mut self, interface: &str) -> io::Result<()> {
        if let Some(pos) = self.saved_macs.iter().position(|s| s.interface == interface) {
            let state = self.saved_macs.remove(pos);
            self.set_mac(interface, &state.original_mac)?;
        }
        Ok(())
    }
    
    /// Restore all original MAC addresses
    pub fn restore_all_macs(&mut self) -> io::Result<()> {
        let states: Vec<_> = self.saved_macs.drain(..).collect();
        for state in states {
            if let Err(e) = self.set_mac(&state.interface, &state.original_mac) {
                eprintln!("Warning: Failed to restore MAC on {}: {}", state.interface, e);
            }
        }
        Ok(())
    }
    
    /// Get current TX power
    pub fn get_tx_power(&self, interface: &str) -> io::Result<i32> {
        let output = Command::new("iw")
            .args(["dev", interface, "get", "power_save"])
            .output()?;
        
        // Try iwconfig as fallback
        let output = Command::new("iwconfig")
            .arg(interface)
            .output()?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse "Tx-Power=XX dBm"
        for line in stdout.lines() {
            if let Some(pos) = line.find("Tx-Power=") {
                let start = pos + 9;
                if let Some(end) = line[start..].find(" ") {
                    if let Ok(power) = line[start..start+end].parse::<i32>() {
                        return Ok(power);
                    }
                }
            }
        }
        
        // Default if we can't read
        Ok(20)
    }
    
    /// Set TX power level
    pub fn set_tx_power(&mut self, interface: &str, level: TxPowerLevel) -> io::Result<()> {
        // Save original power
        if let Ok(original) = self.get_tx_power(interface) {
            if !self.saved_tx_powers.iter().any(|(i, _)| i == interface) {
                self.saved_tx_powers.push((interface.to_string(), original));
            }
        }
        
        let dbm = level.to_dbm();
        
        // Try iw first (modern)
        let result = Command::new("iw")
            .args(["dev", interface, "set", "txpower", "fixed", &format!("{}00", dbm)]) // iw uses mBm
            .output();
        
        if let Ok(output) = result {
            if output.status.success() {
                return Ok(());
            }
        }
        
        // Fall back to iwconfig
        let result = Command::new("iwconfig")
            .args([interface, "txpower", &format!("{}", dbm)])
            .output()?;
        
        if !result.status.success() {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Failed to set TX power: {}",
                    String::from_utf8_lossy(&result.stderr))));
        }
        
        Ok(())
    }
    
    /// Restore original TX power
    pub fn restore_tx_power(&mut self, interface: &str) -> io::Result<()> {
        if let Some(pos) = self.saved_tx_powers.iter().position(|(i, _)| i == interface) {
            let (_, power) = self.saved_tx_powers.remove(pos);
            self.set_tx_power(interface, TxPowerLevel::Custom(power))?;
        }
        Ok(())
    }
    
    /// Enable passive monitoring mode
    /// This puts the interface in monitor mode but NEVER transmits
    pub fn enable_passive_mode(&self, interface: &str) -> io::Result<String> {
        // Create monitor interface with no TX
        let mon_name = format!("{}mon", interface);
        
        // Delete if exists
        let _ = Command::new("iw")
            .args(["dev", &mon_name, "del"])
            .output();
        
        // Add monitor interface with no active flag
        let add = Command::new("iw")
            .args(["dev", interface, "interface", "add", &mon_name, "type", "monitor"])
            .output()?;
        
        if !add.status.success() {
            // Try airmon-ng style
            let airmon = Command::new("airmon-ng")
                .args(["start", interface])
                .output();
            
            if let Ok(out) = airmon {
                if out.status.success() {
                    // airmon-ng might create wlan0mon or similar
                    return Ok(format!("{}mon", interface));
                }
            }
            
            return Err(io::Error::new(io::ErrorKind::Other,
                "Failed to create monitor interface"));
        }
        
        // Bring up
        let _ = Command::new("ip")
            .args(["link", "set", &mon_name, "up"])
            .output();
        
        // Set TX power to minimum for passive
        let _ = self.set_tx_power_direct(&mon_name, 0);
        
        Ok(mon_name)
    }
    
    fn set_tx_power_direct(&self, interface: &str, dbm: i32) -> io::Result<()> {
        let _ = Command::new("iw")
            .args(["dev", interface, "set", "txpower", "fixed", &format!("{}00", dbm)])
            .output();
        Ok(())
    }
    
    /// Start passive monitoring (no transmission)
    pub fn start_passive_capture(&self, config: &PassiveModeConfig) -> io::Result<PassiveResult> {
        // This would integrate with packet capture
        // For now, return empty result
        Ok(PassiveResult::default())
    }
}

impl Default for StealthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StealthManager {
    fn drop(&mut self) {
        // Restore everything on drop
        let _ = self.restore_all_macs();
    }
}

/// Quick function to randomize MAC before an attack
pub fn randomize_for_attack(interface: &str) -> io::Result<MacState> {
    let mut manager = StealthManager::new();
    manager.randomize_mac(interface)
}

/// Quick function to set stealth TX power
pub fn set_stealth_power(interface: &str) -> io::Result<()> {
    let mut manager = StealthManager::new();
    manager.set_tx_power(interface, TxPowerLevel::Stealth)
}

/// Quick function for maximum range
pub fn set_max_power(interface: &str) -> io::Result<()> {
    let mut manager = StealthManager::new();
    manager.set_tx_power(interface, TxPowerLevel::Maximum)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_mac_format() {
        let manager = StealthManager::new();
        let mac = manager.generate_random_mac();
        
        // Check format XX:XX:XX:XX:XX:XX
        assert_eq!(mac.len(), 17);
        assert_eq!(mac.matches(':').count(), 5);
        
        // Check locally administered bit is set
        let first_byte = u8::from_str_radix(&mac[0..2], 16).unwrap();
        assert!(first_byte & 0x02 != 0, "Locally administered bit not set");
        assert!(first_byte & 0x01 == 0, "Multicast bit should be clear");
    }
    
    #[test]
    fn test_vendor_mac() {
        let manager = StealthManager::new();
        
        let apple_mac = manager.generate_vendor_mac("apple");
        assert!(apple_mac.starts_with("F4:0F:24:"));
        
        let samsung_mac = manager.generate_vendor_mac("samsung");
        assert!(samsung_mac.starts_with("00:1A:8A:"));
    }
    
    #[test]
    fn test_tx_power_conversion() {
        assert_eq!(TxPowerLevel::Stealth.to_dbm(), 1);
        assert_eq!(TxPowerLevel::Maximum.to_dbm(), 30);
        assert_eq!(TxPowerLevel::Custom(15).to_dbm(), 15);
    }
}
