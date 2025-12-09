//! # rustyjack-wireless
//!
//! Native Rust wireless security toolkit for Raspberry Pi.
//! Provides monitor mode management, packet injection, deauthentication attacks,
//! and handshake capture without external dependencies.
//!
//! ## Features
//!
//! - Monitor mode via nl80211
//! - Raw 802.11 frame injection
//! - Deauthentication attacks
//! - WPA handshake capture and detection
//! - Channel management
//!
//! ## Example
//!
//! ```no_run
//! use rustyjack_wireless::{WirelessInterface, DeauthAttacker, DeauthConfig};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Setup interface
//! let mut iface = WirelessInterface::new("wlan1")?;
//! iface.set_monitor_mode()?;
//! iface.set_channel(6)?;
//!
//! // Run deauth attack
//! let attacker = DeauthAttacker::new(&iface)?;
//! let config = DeauthConfig {
//!     packets_per_burst: 64,
//!     duration: Duration::from_secs(120),
//!     ..Default::default()
//! };
//!
//! let stats = attacker.attack(
//!     "AA:BB:CC:DD:EE:FF".parse()?,
//!     None,
//!     config,
//! )?;
//!
//! // Cleanup
//! iface.set_managed_mode()?;
//! # Ok(())
//! # }
//! ```

#![cfg(target_os = "linux")]
#![allow(missing_docs)]
#![warn(clippy::all)]

// Module declarations
pub mod capture;
pub mod channel;
pub mod crack;
pub mod deauth;
pub mod error;
pub mod evil_twin;
pub mod frames;
pub mod handshake;
pub mod hotspot;
pub mod inject;
pub mod interface;
pub mod karma;
pub mod nl80211;
pub mod pipeline;
pub mod pmkid;
pub mod probe;
pub mod radiotap;
pub mod recon;

// Re-export evasion crate for convenience (stealth functionality now in separate crate)
pub use hotspot::{
    random_password, random_ssid, start_hotspot, status_hotspot, stop_hotspot, HotspotConfig,
    HotspotState,
};
pub use rustyjack_evasion as evasion;
pub use rustyjack_evasion::{
    EvasionConfig, EvasionSettings, MacAddress as EvasionMacAddress, MacGenerationStrategy,
    MacManager, MacState, PassiveConfig, PassiveManager, PassiveResult, TxPowerLevel,
    TxPowerManager,
};

// Legacy stealth module re-export for backwards compatibility
pub mod stealth {
    //! Stealth and evasion functionality
    //!
    //! This module is now provided by the `rustyjack-evasion` crate.
    //! It is re-exported here for backwards compatibility.

    pub use rustyjack_evasion::{
        MacManager as StealthManager, MacState, PassiveConfig as PassiveModeConfig, PassiveResult,
        TxPowerLevel,
    };
}

// Re-exports for convenience
pub use capture::{CaptureFilter, CapturedPacket, PacketCapture};
pub use channel::ChannelInfo;
pub use crack::{CrackResult, CrackerConfig, WpaCracker};
pub use deauth::{DeauthAttacker, DeauthConfig, DeauthStats};
pub use error::{Result, WirelessError};
pub use evil_twin::{execute_evil_twin, EvilTwin, EvilTwinConfig, EvilTwinResult, EvilTwinStats};
pub use frames::{DeauthFrame, DeauthReason, FrameSubtype, FrameType, Ieee80211Frame, MacAddress};
pub use handshake::{HandshakeCapture, HandshakeExport, HandshakeMessage, HandshakeState};
pub use interface::WirelessInterface;
pub use karma::{
    execute_karma, execute_karma_with_ap, CapturedProbe, KarmaAttack, KarmaConfig,
    KarmaExecutionResult, KarmaResult, KarmaStats, KarmaVictim,
};
pub use pipeline::{
    AttackPipeline, AttackTechnique, PipelineConfig, PipelineObjective, PipelineResult,
    PipelineStage,
};
pub use pmkid::{
    execute_pmkid_capture, PmkidCapture, PmkidCaptureResult, PmkidCapturer, PmkidConfig,
};
pub use probe::{
    execute_probe_sniff, ClientStats, ProbeRequest, ProbeSniffConfig, ProbeSniffResult,
    ProbeSniffer, ProbedNetwork,
};
pub use recon::{
    arp_scan, calculate_bandwidth, discover_gateway, discover_mdns_devices, get_traffic_stats,
    parse_dns_query, scan_network_services, start_dns_capture, ArpDevice, BandwidthSample,
    DeviceServices, DnsQuery, GatewayInfo, MdnsDevice, ServiceInfo, TrafficStats,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if running with sufficient privileges for raw socket operations
pub fn check_privileges() -> bool {
    // Check if we're root or have CAP_NET_RAW
    unsafe { libc::geteuid() == 0 }
}

/// Global logging toggle driven by the UI.
/// When disabled, components should avoid writing log files.
pub fn logs_disabled() -> bool {
    match std::env::var("RUSTYJACK_LOGS_DISABLED") {
        Ok(val) => {
            let normalized = val.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

pub fn logs_enabled() -> bool {
    !logs_disabled()
}

/// Check if an interface exists and is wireless
pub fn is_wireless_interface(name: &str) -> bool {
    let path = format!("/sys/class/net/{}/wireless", name);
    std::path::Path::new(&path).exists()
}

/// List all wireless interfaces on the system
pub fn list_wireless_interfaces() -> Result<Vec<String>> {
    let mut interfaces = Vec::new();

    let net_dir = std::fs::read_dir("/sys/class/net")
        .map_err(|e| WirelessError::System(format!("Failed to read /sys/class/net: {}", e)))?;

    for entry in net_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if is_wireless_interface(&name) {
            interfaces.push(name);
        }
    }

    Ok(interfaces)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_interfaces() {
        // This will work on any Linux system
        let result = list_wireless_interfaces();
        assert!(result.is_ok());
    }

    #[test]
    fn test_privilege_check() {
        // Just ensure it doesn't panic
        let _ = check_privileges();
    }
}
