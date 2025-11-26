//! # rustyjack-evasion
//!
//! A reusable Rust library for network evasion and obfuscation techniques.
//! Designed for security tools, penetration testing, and privacy applications.
//!
//! ## Features
//!
//! - **MAC Address Randomization**: Generate random or vendor-specific MAC addresses
//! - **TX Power Control**: Adjust wireless transmission power for stealth operations
//! - **Passive Mode**: Monitor-only mode with no transmissions
//! - **State Management**: Save and restore original network interface state
//!
//! ## Example
//!
//! ```no_run
//! use rustyjack_evasion::{MacManager, TxPowerLevel, EvasionConfig};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create evasion manager
//!     let mut manager = MacManager::new()?;
//!     
//!     // Randomize MAC address
//!     let state = manager.randomize("wlan0")?;
//!     println!("New MAC: {}", state.current_mac);
//!     
//!     // Do your operations...
//!     
//!     // Restore original MAC
//!     manager.restore("wlan0")?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Platform Support
//!
//! This library is designed for Linux systems with standard network tools
//! (`ip`, `iw`, `iwconfig`). Root privileges are required for most operations.
//!
//! ## Security Considerations
//!
//! - Uses cryptographically secure random number generation (`getrandom`)
//! - Properly sets locally administered bit on generated MACs
//! - Saves original state for restoration
//! - Implements Drop trait for automatic cleanup

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

// Core modules
pub mod error;
pub mod mac;
pub mod txpower;
pub mod passive;
pub mod config;
pub mod state;
pub mod vendor;

// Re-exports for convenience
pub use error::{EvasionError, Result};
pub use mac::{MacManager, MacAddress, MacState, MacGenerationStrategy};
pub use txpower::{TxPowerManager, TxPowerLevel};
pub use passive::{PassiveManager, PassiveConfig, PassiveResult};
pub use config::{EvasionConfig, EvasionSettings};
pub use state::{StateManager, InterfaceState};
pub use vendor::{VendorOui, VENDOR_DATABASE};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if running with sufficient privileges
/// 
/// Most evasion operations require root or `CAP_NET_ADMIN` capability.
/// 
/// # Returns
/// 
/// `true` if running as root (euid == 0)
#[must_use]
pub fn check_privileges() -> bool {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::geteuid() == 0
    }
    
    #[cfg(not(target_os = "linux"))]
    false
}

/// Check if an interface exists
/// 
/// # Arguments
/// 
/// * `interface` - Network interface name (e.g., "wlan0")
/// 
/// # Returns
/// 
/// `true` if the interface exists in `/sys/class/net/`
#[must_use]
pub fn interface_exists(interface: &str) -> bool {
    if interface.is_empty() || interface.contains('/') || interface.contains('\0') {
        return false;
    }
    
    let path = format!("/sys/class/net/{}", interface);
    std::path::Path::new(&path).exists()
}

/// Check if an interface is wireless
/// 
/// # Arguments
/// 
/// * `interface` - Network interface name
/// 
/// # Returns
/// 
/// `true` if the interface has wireless capabilities
#[must_use]
pub fn is_wireless(interface: &str) -> bool {
    if !interface_exists(interface) {
        return false;
    }
    
    let wireless_path = format!("/sys/class/net/{}/wireless", interface);
    let phy_path = format!("/sys/class/net/{}/phy80211", interface);
    
    std::path::Path::new(&wireless_path).exists() || 
    std::path::Path::new(&phy_path).exists()
}

/// List all network interfaces
/// 
/// # Errors
/// 
/// Returns an error if `/sys/class/net` cannot be read
pub fn list_interfaces() -> Result<Vec<String>> {
    let net_dir = std::fs::read_dir("/sys/class/net")
        .map_err(|e| EvasionError::System(format!("Failed to read /sys/class/net: {}", e)))?;
    
    let interfaces: Vec<String> = net_dir
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    
    Ok(interfaces)
}

/// List all wireless interfaces
/// 
/// # Errors
/// 
/// Returns an error if interface enumeration fails
pub fn list_wireless_interfaces() -> Result<Vec<String>> {
    let all = list_interfaces()?;
    Ok(all.into_iter().filter(|i| is_wireless(i)).collect())
}

/// Convenience function to quickly randomize a MAC address
/// 
/// This is a stateless operation - the original MAC is not saved.
/// For operations requiring restoration, use [`MacManager`] instead.
/// 
/// # Arguments
/// 
/// * `interface` - Network interface name
/// 
/// # Errors
/// 
/// Returns an error if MAC randomization fails
/// 
/// # Example
/// 
/// ```no_run
/// use rustyjack_evasion::quick_randomize_mac;
/// 
/// if let Ok(new_mac) = quick_randomize_mac("wlan0") {
///     println!("New MAC: {}", new_mac);
/// }
/// ```
pub fn quick_randomize_mac(interface: &str) -> Result<String> {
    let mut manager = MacManager::new()?;
    let state = manager.randomize(interface)?;
    Ok(state.current_mac.to_string())
}

/// Convenience function to set TX power to stealth level
/// 
/// # Arguments
/// 
/// * `interface` - Wireless interface name
/// 
/// # Errors
/// 
/// Returns an error if TX power cannot be set
pub fn set_stealth_power(interface: &str) -> Result<()> {
    let mut manager = TxPowerManager::new();
    manager.set_power(interface, TxPowerLevel::Stealth)
}

/// Convenience function to set TX power to maximum
/// 
/// # Arguments
/// 
/// * `interface` - Wireless interface name
/// 
/// # Errors
/// 
/// Returns an error if TX power cannot be set
pub fn set_max_power(interface: &str) -> Result<()> {
    let mut manager = TxPowerManager::new();
    manager.set_power(interface, TxPowerLevel::Maximum)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_interface_exists_validation() {
        // Invalid interface names should return false
        assert!(!interface_exists(""));
        assert!(!interface_exists("../etc/passwd"));
        assert!(!interface_exists("wlan0\0"));
        assert!(!interface_exists("a/b"));
    }
    
    #[test]
    fn test_list_interfaces() {
        // Should not panic on any system
        let result = list_interfaces();
        // On non-Linux, this might fail, but shouldn't panic
        if cfg!(target_os = "linux") {
            assert!(result.is_ok());
        }
    }
    
    #[test]
    fn test_privilege_check() {
        // Should not panic
        let _ = check_privileges();
    }
}
