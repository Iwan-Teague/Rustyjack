#![deny(unsafe_op_in_unsafe_fn)]
//! # rustyjack-wireless
//!
//! Native Rust wireless security toolkit for Raspberry Pi.
//! Provides monitor mode management, packet injection, deauthentication attacks,
//! and handshake capture. Requires root privileges for raw sockets.
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
pub mod deauth;
pub mod error;
pub mod evil_twin;
pub mod frames;
pub mod handshake;
pub mod hotspot;
pub mod inject;
pub mod interface;
pub mod karma;
mod netlink_helpers;
pub mod nl80211;
pub mod nl80211_queries;
pub mod pmkid;
pub mod pcap;
pub mod probe;
mod process_helpers;
pub mod radiotap;
pub mod recon;
mod rfkill_helpers;

// Re-export evasion crate for convenience (stealth functionality now in separate crate)
pub use hotspot::{
    hotspot_disconnect_client, hotspot_leases, hotspot_set_blacklist, random_password, random_ssid,
    read_regdom_info, start_hotspot, status_hotspot, stop_hotspot, take_last_hotspot_warning,
    HotspotConfig, HotspotState, RegdomInfo,
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
pub use deauth::{DeauthAttacker, DeauthConfig, DeauthStats};
pub use nl80211_queries::{InterfaceCapabilities, query_interface_capabilities};
pub use error::{Result, WirelessError};
pub use evil_twin::{
    execute_evil_twin, execute_evil_twin_cancellable, EvilTwin, EvilTwinConfig, EvilTwinResult,
    EvilTwinStats,
};
pub use frames::{DeauthFrame, DeauthReason, FrameSubtype, FrameType, Ieee80211Frame, MacAddress};
pub use handshake::{HandshakeCapture, HandshakeMessage, HandshakeState};
pub use interface::WirelessInterface;
pub use pcap::PcapWriter;
pub use rustyjack_wpa::crack;
pub use rustyjack_wpa::{CrackResult, CrackerConfig, HandshakeExport, WpaCracker};
pub use karma::{
    execute_karma, execute_karma_cancellable, execute_karma_with_ap,
    execute_karma_with_ap_cancellable, CapturedProbe, KarmaAttack, KarmaConfig,
    KarmaExecutionResult, KarmaResult, KarmaStats, KarmaVictim,
};
pub use pmkid::{
    execute_pmkid_capture, execute_pmkid_capture_cancellable, PmkidCapture, PmkidCaptureResult,
    PmkidCapturer, PmkidConfig,
};
pub use probe::{
    execute_probe_sniff, execute_probe_sniff_cancellable, ClientStats, ProbeRequest,
    ProbeSniffConfig, ProbeSniffResult, ProbeSniffer, ProbedNetwork,
};
pub use recon::{
    arp_scan, arp_scan_cancellable, calculate_bandwidth, discover_gateway, discover_mdns_devices,
    discover_mdns_devices_cancellable, get_traffic_stats, capture_dns_queries,
    capture_dns_queries_cancellable, scan_network_services, scan_network_services_cancellable,
    ArpDevice, BandwidthSample, DeviceServices, DnsQuery, GatewayInfo, MdnsDevice, ServiceInfo,
    TrafficStats,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if running with sufficient privileges for raw socket operations
pub fn check_privileges() -> bool {
    // Check if we're root or have CAP_NET_RAW
    unsafe { libc::geteuid() == 0 }
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
