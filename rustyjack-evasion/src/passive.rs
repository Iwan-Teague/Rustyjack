//! Passive monitoring mode
//!
//! This module provides support for passive-only wireless monitoring
//! where no packets are transmitted.
//!
//! ## Passive Mode Features
//!
//! - Creates monitor interface
//! - Sets TX power to absolute minimum
//! - Captures beacons, probes, and data frames
//! - No deauth, no injection, no active scanning
//!
//! ## Use Cases
//!
//! - Reconnaissance without detection
//! - Compliance monitoring
//! - Wireless surveys
//! - Handshake capture (waiting for natural reconnections)

use crate::error::{EvasionError, Result};
use crate::txpower::{TxPowerLevel, TxPowerManager};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for passive monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveConfig {
    /// Base interface name
    pub interface: String,

    /// Channel to monitor (0 = channel hop)
    pub channel: u8,

    /// Duration in seconds (0 = indefinite)
    pub duration: u32,

    /// Capture probe requests
    pub capture_probes: bool,

    /// Capture beacon frames
    pub capture_beacons: bool,

    /// Capture data frames (for handshakes)
    pub capture_data: bool,

    /// Set minimum TX power
    pub stealth_power: bool,

    /// Log file for captured data
    pub log_file: Option<PathBuf>,
}

impl Default for PassiveConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            channel: 0,
            duration: 0,
            capture_probes: true,
            capture_beacons: true,
            capture_data: true,
            stealth_power: true,
            log_file: None,
        }
    }
}

impl PassiveConfig {
    /// Create a new passive config for an interface
    #[must_use]
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            ..Default::default()
        }
    }

    /// Set the channel to monitor
    #[must_use]
    pub fn channel(mut self, channel: u8) -> Self {
        self.channel = channel;
        self
    }

    /// Set the duration
    #[must_use]
    pub fn duration(mut self, seconds: u32) -> Self {
        self.duration = seconds;
        self
    }

    /// Set log file
    #[must_use]
    pub fn log_to(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_file = Some(path.into());
        self
    }
}

/// Results from passive monitoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PassiveResult {
    /// Networks discovered
    pub networks: Vec<DiscoveredNetwork>,

    /// Clients discovered
    pub clients: Vec<DiscoveredClient>,

    /// Probe requests captured
    pub probes: Vec<CapturedProbe>,

    /// Total packets captured
    pub packet_count: u64,

    /// Duration in seconds
    pub duration_secs: u32,

    /// Monitor interface name
    pub monitor_interface: String,
}

/// A network discovered during passive monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredNetwork {
    /// SSID (may be empty for hidden networks)
    pub ssid: String,

    /// BSSID (AP MAC address)
    pub bssid: String,

    /// Channel
    pub channel: u8,

    /// Signal strength in dBm
    pub signal_dbm: i32,

    /// Encryption type (WPA2, WPA3, Open, etc.)
    pub encryption: String,

    /// First seen timestamp (Unix epoch)
    pub first_seen: i64,

    /// Last seen timestamp
    pub last_seen: i64,

    /// Number of beacons received
    pub beacon_count: u32,
}

/// A client discovered during passive monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredClient {
    /// Client MAC address
    pub mac: String,

    /// Associated AP BSSID (None if not associated)
    pub associated_bssid: Option<String>,

    /// Signal strength
    pub signal_dbm: i32,

    /// First seen timestamp
    pub first_seen: i64,

    /// Last seen timestamp
    pub last_seen: i64,

    /// Packet count
    pub packet_count: u32,
}

/// A probe request captured
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedProbe {
    /// Client MAC that sent the probe
    pub client_mac: String,

    /// SSID being probed for
    pub ssid: String,

    /// Signal strength
    pub signal_dbm: i32,

    /// Timestamp
    pub timestamp: i64,
}

/// Manager for passive monitoring operations
pub struct PassiveManager {
    tx_manager: TxPowerManager,
    active_monitors: Vec<String>,
}

impl PassiveManager {
    /// Create a new passive manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx_manager: TxPowerManager::new(),
            active_monitors: Vec::new(),
        }
    }

    /// Enable passive monitor mode on an interface
    ///
    /// This creates a monitor interface and sets TX power to minimum.
    ///
    /// # Arguments
    ///
    /// * `interface` - Base wireless interface
    ///
    /// # Returns
    ///
    /// Name of the created monitor interface (e.g., "wlan0mon")
    ///
    /// # Errors
    ///
    /// Returns an error if monitor mode cannot be enabled
    pub fn enable(&mut self, interface: &str) -> Result<String> {
        if !crate::is_wireless(interface) {
            return Err(EvasionError::NotWireless(interface.into()));
        }

        let mon_name = format!("{}mon", interface);

        // Delete existing monitor if present
        if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
            let _ = mgr.delete_interface(&mon_name);
        }

        // Create monitor interface using netlink
        if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
            if mgr.create_interface(interface, &mon_name, rustyjack_netlink::InterfaceMode::Monitor).is_ok() {
                // Bring it up
                if let Ok(link_mgr) = rustyjack_netlink::LinkManager::new() {
                    let _ = link_mgr.set_link_up(&mon_name);
                }

                self.active_monitors.push(mon_name.clone());

                log::info!("Created monitor interface: {}", mon_name);
                return Ok(mon_name);
            }
        }

        // Fall back to airmon-ng if netlink fails
        let airmon = std::process::Command::new("airmon-ng")
            .args(["start", interface])
            .output();

        if let Ok(output) = airmon {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(EvasionError::InterfaceError(format!(
                    "Failed to create monitor interface: {}",
                    stderr
                )));
            }
        } else {
            return Err(EvasionError::InterfaceError(
                "Failed to create monitor interface with airmon-ng".to_string()
            ));
        }

        // Bring up the monitor interface
        if let Ok(link_mgr) = rustyjack_netlink::LinkManager::new() {
            let _ = link_mgr.set_link_up(&mon_name);
        }

        // Set TX power to minimum for passive mode
        if let Err(e) = self.tx_manager.set_power(&mon_name, TxPowerLevel::Stealth) {
            log::warn!("Could not set stealth TX power: {}", e);
            // Not fatal - continue without stealth power
        }

        self.active_monitors.push(mon_name.clone());

        log::info!(
            "Enabled passive monitor mode on {} -> {}",
            interface,
            mon_name
        );
        Ok(mon_name)
    }

    /// Disable passive mode and cleanup
    ///
    /// # Arguments
    ///
    /// * `monitor_interface` - The monitor interface to disable
    pub fn disable(&mut self, monitor_interface: &str) -> Result<()> {
        // Bring down and delete interface
        if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
            if mgr.delete_interface(monitor_interface).is_err() {
                // Try airmon-ng stop as fallback
                let _ = std::process::Command::new("airmon-ng")
                    .args(["stop", monitor_interface])
                    .output();
            }
        }

        // Remove from active list
        self.active_monitors.retain(|m| m != monitor_interface);

        log::info!("Disabled monitor mode on {}", monitor_interface);
        Ok(())
    }

    /// Set channel on monitor interface
    ///
    /// # Arguments
    ///
    /// * `interface` - Monitor interface
    /// * `channel` - WiFi channel (1-14 for 2.4GHz, higher for 5GHz)
    pub fn set_channel(&self, interface: &str, channel: u8) -> Result<()> {
        let output = std::process::Command::new("iw")
            .args(["dev", interface, "set", "channel", &channel.to_string()])
            .output()
            .map_err(|e| EvasionError::System(format!("Failed to set channel: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EvasionError::InterfaceError(format!(
                "Failed to set channel {}: {}",
                channel, stderr
            )));
        }

        Ok(())
    }

    /// Start passive capture with configuration
    ///
    /// Note: This is a placeholder - actual capture would integrate with
    /// packet capture libraries like libpcap or raw sockets.
    ///
    /// # Arguments
    ///
    /// * `config` - Passive monitoring configuration
    pub fn start_capture(&mut self, config: &PassiveConfig) -> Result<PassiveResult> {
        let mon_iface = self.enable(&config.interface)?;

        if config.channel > 0 {
            self.set_channel(&mon_iface, config.channel)?;
        }

        // Placeholder result - actual implementation would capture packets
        Ok(PassiveResult {
            monitor_interface: mon_iface,
            duration_secs: config.duration,
            ..Default::default()
        })
    }

    /// Get list of active monitor interfaces
    #[must_use]
    pub fn active_monitors(&self) -> &[String] {
        &self.active_monitors
    }

    /// Cleanup all active monitors
    pub fn cleanup_all(&mut self) -> Result<()> {
        let monitors: Vec<_> = self.active_monitors.drain(..).collect();
        let mut first_error = None;

        for mon in monitors {
            if let Err(e) = self.disable(&mon) {
                log::warn!("Failed to disable {}: {}", mon, e);
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

impl Default for PassiveManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PassiveManager {
    fn drop(&mut self) {
        if !self.active_monitors.is_empty() {
            if let Err(e) = self.cleanup_all() {
                log::error!("Failed to cleanup monitors on drop: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_config_builder() {
        let config = PassiveConfig::new("wlan0")
            .channel(6)
            .duration(300)
            .log_to("/tmp/passive.log");

        assert_eq!(config.interface, "wlan0");
        assert_eq!(config.channel, 6);
        assert_eq!(config.duration, 300);
        assert!(config.log_file.is_some());
    }

    #[test]
    fn test_default_config() {
        let config = PassiveConfig::default();

        assert!(config.capture_probes);
        assert!(config.capture_beacons);
        assert!(config.capture_data);
        assert!(config.stealth_power);
    }
}
