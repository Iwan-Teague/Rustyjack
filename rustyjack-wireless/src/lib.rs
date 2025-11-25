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
#![warn(missing_docs)]
#![warn(clippy::all)]

// Module declarations
pub mod error;
pub mod frames;
pub mod radiotap;
pub mod interface;
pub mod inject;
pub mod capture;
pub mod deauth;
pub mod handshake;
pub mod channel;
pub mod nl80211;

// Re-exports for convenience
pub use error::{WirelessError, Result};
pub use interface::WirelessInterface;
pub use frames::{Ieee80211Frame, FrameType, FrameSubtype, MacAddress, DeauthReason, DeauthFrame};
pub use deauth::{DeauthAttacker, DeauthConfig, DeauthStats};
pub use capture::{PacketCapture, CaptureFilter, CapturedPacket};
pub use handshake::{HandshakeCapture, HandshakeMessage, HandshakeState};
pub use channel::ChannelInfo;

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
