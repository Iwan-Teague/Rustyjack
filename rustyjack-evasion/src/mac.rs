//! MAC Address management and randomization
//!
//! This module provides comprehensive MAC address manipulation capabilities
//! including:
//! - Cryptographically secure random MAC generation
//! - Vendor-specific MAC generation (for blending in)
//! - MAC address validation
//! - State tracking for restoration
//!
//! ## Security Notes
//!
//! - Uses `getrandom` crate for cryptographically secure randomness
//! - Always sets the locally administered bit (IEEE requirement for random MACs)
//! - Clears the multicast bit (ensures unicast address)
//!
//! ## Example
//!
//! ```no_run
//! use rustyjack_evasion::mac::{MacManager, MacGenerationStrategy};
//!
//! let mut manager = MacManager::new().unwrap();
//!
//! // Random MAC
//! let state = manager.randomize("wlan0").unwrap();
//!
//! // Vendor-specific MAC (looks like an iPhone)
//! let state = manager.set_with_strategy("wlan0", MacGenerationStrategy::Vendor("apple")).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use crate::error::{EvasionError, Result};
use crate::vendor::VendorOui;

/// A validated MAC address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress {
    bytes: [u8; 6],
}

impl MacAddress {
    /// Create a new MAC address from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 6-byte array representing the MAC address
    #[must_use]
    pub fn new(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }

    /// Parse a MAC address from string
    ///
    /// Accepts formats:
    /// - `AA:BB:CC:DD:EE:FF`
    /// - `AA-BB-CC-DD-EE-FF`
    /// - `AABBCCDDEEFF`
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid MAC address
    pub fn parse(s: &str) -> Result<Self> {
        s.parse()
    }

    /// Get the raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.bytes
    }

    /// Check if this is a locally administered address
    ///
    /// Locally administered addresses have bit 1 of the first byte set.
    /// All randomly generated MACs should be locally administered.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.bytes[0] & 0x02 != 0
    }

    /// Check if this is a unicast address
    ///
    /// Unicast addresses have bit 0 of the first byte clear.
    #[must_use]
    pub fn is_unicast(&self) -> bool {
        self.bytes[0] & 0x01 == 0
    }

    /// Check if this is a multicast address
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        !self.is_unicast()
    }

    /// Get the OUI (Organizationally Unique Identifier) portion
    ///
    /// Returns the first 3 bytes which identify the vendor
    #[must_use]
    pub fn oui(&self) -> [u8; 3] {
        [self.bytes[0], self.bytes[1], self.bytes[2]]
    }

    /// Get the NIC-specific portion
    ///
    /// Returns the last 3 bytes which are device-specific
    #[must_use]
    pub fn nic(&self) -> [u8; 3] {
        [self.bytes[3], self.bytes[4], self.bytes[5]]
    }

    /// Create a random MAC address
    ///
    /// - Sets locally administered bit
    /// - Clears multicast bit
    /// - Uses cryptographically secure random bytes
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 6];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| EvasionError::RngError(format!("Failed to get random bytes: {}", e)))?;

        // Set locally administered bit, clear multicast bit
        bytes[0] = (bytes[0] | 0x02) & 0xFE;

        Ok(Self { bytes })
    }

    /// Create a random MAC with a specific vendor OUI
    ///
    /// # Arguments
    ///
    /// * `oui` - 3-byte vendor OUI
    pub fn random_with_oui(oui: [u8; 3]) -> Result<Self> {
        let mut bytes = [0u8; 6];

        getrandom::getrandom(&mut bytes[3..6])
            .map_err(|e| EvasionError::RngError(format!("Failed to get random bytes: {}", e)))?;

        bytes[0] = (oui[0] | 0x02) & 0xFE;
        bytes[1] = oui[1];
        bytes[2] = oui[2];

        Ok(Self { bytes })
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = EvasionError;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim().to_uppercase();

        // Try colon-separated
        if s.contains(':') {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() != 6 {
                return Err(EvasionError::InvalidMac(format!(
                    "Expected 6 octets, got {}",
                    parts.len()
                )));
            }

            let mut bytes = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                bytes[i] = u8::from_str_radix(part, 16).map_err(|_| {
                    EvasionError::InvalidMac(format!("Invalid hex octet: {}", part))
                })?;
            }

            return Ok(Self { bytes });
        }

        // Try dash-separated
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 6 {
                return Err(EvasionError::InvalidMac(format!(
                    "Expected 6 octets, got {}",
                    parts.len()
                )));
            }

            let mut bytes = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                bytes[i] = u8::from_str_radix(part, 16).map_err(|_| {
                    EvasionError::InvalidMac(format!("Invalid hex octet: {}", part))
                })?;
            }

            return Ok(Self { bytes });
        }

        // Try continuous hex
        if s.len() == 12 {
            let mut bytes = [0u8; 6];
            for i in 0..6 {
                bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| {
                    EvasionError::InvalidMac(format!("Invalid hex at position {}", i * 2))
                })?;
            }

            return Ok(Self { bytes });
        }

        Err(EvasionError::InvalidMac(format!(
            "Unrecognized MAC format: {}",
            s
        )))
    }
}

/// Strategy for generating MAC addresses
#[derive(Debug, Clone)]
pub enum MacGenerationStrategy<'a> {
    /// Completely random (locally administered)
    Random,
    /// Use a specific vendor's OUI
    Vendor(&'a str),
    /// Use a custom OUI
    CustomOui([u8; 3]),
    /// Use a specific MAC address
    Specific(MacAddress),
}

/// State of a MAC address change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacState {
    /// Interface name
    pub interface: String,
    /// Original MAC address before modification
    pub original_mac: MacAddress,
    /// Current MAC address
    pub current_mac: MacAddress,
    /// Whether the MAC has been randomized
    pub is_randomized: bool,
    /// Timestamp of the change (Unix epoch)
    pub changed_at: i64,
}

impl MacState {
    /// Check if MAC needs to be restored
    #[must_use]
    pub fn needs_restore(&self) -> bool {
        self.is_randomized && self.original_mac != self.current_mac
    }
}

/// Manager for MAC address operations
///
/// Tracks state changes and provides restoration capability.
/// Implements Drop to automatically restore MACs on cleanup.
pub struct MacManager {
    states: HashMap<String, MacState>,
    auto_restore: bool,
}

impl MacManager {
    /// Create a new MAC manager
    ///
    /// # Errors
    ///
    /// Returns an error if the system doesn't support MAC operations
    pub fn new() -> Result<Self> {
        Ok(Self {
            states: HashMap::new(),
            auto_restore: true,
        })
    }

    /// Set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, auto: bool) {
        self.auto_restore = auto;
    }

    /// Get the current MAC address of an interface
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name
    ///
    /// # Errors
    ///
    /// Returns an error if the interface doesn't exist or MAC can't be read
    pub fn get_mac(&self, interface: &str) -> Result<MacAddress> {
        self.validate_interface(interface)?;

        let path = format!("/sys/class/net/{}/address", interface);
        let mac_str = std::fs::read_to_string(&path).map_err(|e| {
            EvasionError::InterfaceError(format!("Failed to read MAC from {}: {}", path, e))
        })?;

        mac_str.trim().parse()
    }

    /// Set the MAC address of an interface
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name
    /// * `mac` - New MAC address
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Interface doesn't exist
    /// - Permission denied (need root)
    /// - Driver doesn't support MAC changes
    pub fn set_mac(&mut self, interface: &str, mac: &MacAddress) -> Result<MacState> {
        self.validate_interface(interface)?;

        let current_mac = self.get_mac(interface)?;

        if current_mac == *mac {
            return Ok(MacState {
                interface: interface.to_string(),
                original_mac: current_mac.clone(),
                current_mac: current_mac,
                is_randomized: false,
                changed_at: chrono::Utc::now().timestamp(),
            });
        }

        self.states
            .entry(interface.to_string())
            .or_insert_with(|| MacState {
                interface: interface.to_string(),
                original_mac: current_mac.clone(),
                current_mac: current_mac.clone(),
                is_randomized: false,
                changed_at: chrono::Utc::now().timestamp(),
            });

        self.interface_down(interface)?;
        let result = self.set_mac_raw(interface, mac);
        let up_result = self.interface_up(interface);
        result?;
        up_result?;

        let state = self.states.get_mut(interface).unwrap();
        state.current_mac = mac.clone();
        state.is_randomized = true;
        state.changed_at = chrono::Utc::now().timestamp();

        Ok(state.clone())
    }

    /// Randomize the MAC address
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name
    ///
    /// # Errors
    ///
    /// Returns an error if randomization fails
    pub fn randomize(&mut self, interface: &str) -> Result<MacState> {
        let new_mac = MacAddress::random()?;
        self.set_mac(interface, &new_mac)
    }

    /// Set MAC using a specific strategy
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name
    /// * `strategy` - Generation strategy
    ///
    /// # Errors
    ///
    /// Returns an error if MAC setting fails
    pub fn set_with_strategy(
        &mut self,
        interface: &str,
        strategy: MacGenerationStrategy<'_>,
    ) -> Result<MacState> {
        let new_mac = match strategy {
            MacGenerationStrategy::Random => MacAddress::random()?,
            MacGenerationStrategy::Vendor(vendor) => {
                let oui = VendorOui::from_name(vendor)
                    .ok_or_else(|| EvasionError::Config(format!("Unknown vendor: {}", vendor)))?;
                MacAddress::random_with_oui(oui.oui)?
            }
            MacGenerationStrategy::CustomOui(oui) => MacAddress::random_with_oui(oui)?,
            MacGenerationStrategy::Specific(mac) => mac,
        };

        self.set_mac(interface, &new_mac)
    }

    /// Restore the original MAC address
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails
    pub fn restore(&mut self, interface: &str) -> Result<()> {
        if let Some(state) = self.states.remove(interface) {
            // Bring down, set original, bring up
            self.interface_down(interface)?;
            let result = self.set_mac_raw(interface, &state.original_mac);
            let _ = self.interface_up(interface);

            result?;
        }

        Ok(())
    }

    /// Restore all modified interfaces
    ///
    /// # Errors
    ///
    /// Returns the first error encountered, but attempts all restorations
    pub fn restore_all(&mut self) -> Result<()> {
        let states: Vec<_> = self.states.values().cloned().collect();
        let mut first_error: Option<EvasionError> = None;

        for state in states {
            if state.needs_restore() {
                if let Err(e) = self.restore_state(&state) {
                    log::warn!("Failed to restore MAC on {}: {}", state.interface, e);
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        self.states.clear();

        first_error.map_or(Ok(()), Err)
    }

    /// Get the saved state for an interface
    #[must_use]
    pub fn get_state(&self, interface: &str) -> Option<&MacState> {
        self.states.get(interface)
    }

    /// Get all saved states
    #[must_use]
    pub fn all_states(&self) -> Vec<&MacState> {
        self.states.values().collect()
    }

    // Private helper methods

    fn validate_interface(&self, interface: &str) -> Result<()> {
        if interface.is_empty() {
            return Err(EvasionError::InterfaceNotFound(
                "empty interface name".into(),
            ));
        }

        if interface.contains('/') || interface.contains('\0') {
            return Err(EvasionError::InterfaceError(
                "invalid characters in interface name".into(),
            ));
        }

        if !crate::interface_exists(interface) {
            return Err(EvasionError::InterfaceNotFound(interface.into()));
        }

        Ok(())
    }

    fn interface_down(&self, interface: &str) -> Result<()> {
        let mgr = rustyjack_netlink::InterfaceManager::new()
            .map_err(|e| EvasionError::System(format!("Failed to initialize netlink: {}", e)))?;
        
        tokio::runtime::Handle::current().block_on(async {
            mgr.set_link_down(interface).await
                .map_err(|e| {
                    if e.to_string().contains("Operation not permitted") || e.to_string().contains("Permission denied") {
                        EvasionError::PermissionDenied("bringing interface down".into())
                    } else {
                        EvasionError::InterfaceError(format!("Failed to bring {} down: {}", interface, e))
                    }
                })
        })
    }

    fn interface_up(&self, interface: &str) -> Result<()> {
        let mgr = rustyjack_netlink::InterfaceManager::new()
            .map_err(|e| EvasionError::System(format!("Failed to initialize netlink: {}", e)))?;
        
        tokio::runtime::Handle::current().block_on(async {
            mgr.set_link_up(interface).await
                .map_err(|e| EvasionError::InterfaceError(format!("Failed to bring {} up: {}", interface, e)))
        })
    }

    fn set_mac_raw(&self, interface: &str, mac: &MacAddress) -> Result<()> {
        let mac_str = mac.to_string();
        let mgr = rustyjack_netlink::InterfaceManager::new()
            .map_err(|e| EvasionError::System(format!("Failed to initialize netlink: {}", e)))?;
        
        tokio::runtime::Handle::current().block_on(async {
            mgr.set_mac_address(interface, &mac_str).await
                .map_err(|e| {
                    if e.to_string().contains("Operation not permitted") || e.to_string().contains("Permission denied") {
                        EvasionError::PermissionDenied("setting MAC address".into())
                    } else {
                        EvasionError::InterfaceError(format!("Failed to set MAC on {}: {}", interface, e))
                    }
                })
        })
    }

    fn restore_state(&self, state: &MacState) -> Result<()> {
        self.interface_down(&state.interface)?;
        let result = self.set_mac_raw(&state.interface, &state.original_mac);
        let _ = self.interface_up(&state.interface);
        result
    }
}

impl Drop for MacManager {
    fn drop(&mut self) {
        if self.auto_restore && !self.states.is_empty() {
            if let Err(e) = self.restore_all() {
                log::error!("Failed to restore MAC addresses on drop: {}", e);
            }
        }
    }
}

impl Default for MacManager {
    fn default() -> Self {
        Self {
            states: HashMap::new(),
            auto_restore: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_parse_colon() {
        let mac: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(mac.bytes, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_parse_dash() {
        let mac: MacAddress = "AA-BB-CC-DD-EE-FF".parse().unwrap();
        assert_eq!(mac.bytes, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_parse_continuous() {
        let mac: MacAddress = "AABBCCDDEEFF".parse().unwrap();
        assert_eq!(mac.bytes, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_parse_lowercase() {
        let mac: MacAddress = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(mac.bytes, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_display() {
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(mac.to_string(), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_random_mac_properties() {
        let mac = MacAddress::random().unwrap();

        // Must be locally administered
        assert!(mac.is_local(), "Random MAC should be locally administered");

        // Must be unicast
        assert!(mac.is_unicast(), "Random MAC should be unicast");
    }

    #[test]
    fn test_mac_oui() {
        let mac = MacAddress::new([0xF4, 0x0F, 0x24, 0xAA, 0xBB, 0xCC]);
        assert_eq!(mac.oui(), [0xF4, 0x0F, 0x24]);
        assert_eq!(mac.nic(), [0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_invalid_mac() {
        assert!("not a mac".parse::<MacAddress>().is_err());
        assert!("AA:BB".parse::<MacAddress>().is_err());
        assert!("AA:BB:CC:DD:EE:GG".parse::<MacAddress>().is_err());
    }
}
