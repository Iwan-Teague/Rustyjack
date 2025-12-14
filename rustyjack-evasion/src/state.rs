//! Interface state management
//!
//! This module provides centralized state tracking for network interfaces
//! to ensure proper cleanup and restoration.

use crate::error::{EvasionError, Result};
use crate::mac::MacAddress;
use crate::txpower::TxPowerLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete state of a network interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceState {
    /// Interface name
    pub interface: String,

    /// Original MAC address
    pub original_mac: Option<String>,

    /// Current MAC address
    pub current_mac: Option<String>,

    /// Original TX power in dBm
    pub original_tx_power: Option<i32>,

    /// Current TX power level
    pub current_tx_power: Option<TxPowerLevel>,

    /// Whether interface was up before we modified it
    pub was_up: bool,

    /// Whether we created a monitor interface
    pub monitor_created: Option<String>,

    /// Timestamp of first modification (Unix epoch)
    pub first_modified: i64,

    /// Timestamp of last modification
    pub last_modified: i64,
}

impl InterfaceState {
    /// Create a new state for an interface
    #[must_use]
    pub fn new(interface: impl Into<String>) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            interface: interface.into(),
            original_mac: None,
            current_mac: None,
            original_tx_power: None,
            current_tx_power: None,
            was_up: true,
            monitor_created: None,
            first_modified: now,
            last_modified: now,
        }
    }

    /// Check if any modifications were made
    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.original_mac.is_some()
            || self.original_tx_power.is_some()
            || self.monitor_created.is_some()
    }

    /// Check if MAC was changed
    #[must_use]
    pub fn mac_changed(&self) -> bool {
        self.original_mac.is_some() && self.current_mac.is_some()
    }

    /// Check if TX power was changed
    #[must_use]
    pub fn tx_power_changed(&self) -> bool {
        self.original_tx_power.is_some() && self.current_tx_power.is_some()
    }

    /// Update the last modified timestamp
    pub fn touch(&mut self) {
        self.last_modified = chrono::Utc::now().timestamp();
    }
}

/// Manager for tracking and restoring interface states
pub struct StateManager {
    states: HashMap<String, InterfaceState>,
    auto_restore: bool,
}

impl StateManager {
    /// Create a new state manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            auto_restore: true,
        }
    }

    /// Set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, auto: bool) {
        self.auto_restore = auto;
    }

    /// Get or create state for an interface
    pub fn get_or_create(&mut self, interface: &str) -> &mut InterfaceState {
        self.states
            .entry(interface.to_string())
            .or_insert_with(|| InterfaceState::new(interface))
    }

    /// Get state for an interface (if exists)
    #[must_use]
    pub fn get(&self, interface: &str) -> Option<&InterfaceState> {
        self.states.get(interface)
    }

    /// Record MAC change
    pub fn record_mac_change(&mut self, interface: &str, original: &MacAddress, new: &MacAddress) {
        let state = self.get_or_create(interface);
        if state.original_mac.is_none() {
            state.original_mac = Some(original.to_string());
        }
        state.current_mac = Some(new.to_string());
        state.touch();
    }

    /// Record TX power change
    pub fn record_tx_power_change(&mut self, interface: &str, original: i32, new: TxPowerLevel) {
        let state = self.get_or_create(interface);
        if state.original_tx_power.is_none() {
            state.original_tx_power = Some(original);
        }
        state.current_tx_power = Some(new);
        state.touch();
    }

    /// Record monitor interface creation
    pub fn record_monitor_created(&mut self, base_interface: &str, monitor_name: &str) {
        let state = self.get_or_create(base_interface);
        state.monitor_created = Some(monitor_name.to_string());
        state.touch();
    }

    /// Remove state for an interface (after restoration)
    pub fn remove(&mut self, interface: &str) -> Option<InterfaceState> {
        self.states.remove(interface)
    }

    /// Get all modified interfaces
    #[must_use]
    pub fn modified_interfaces(&self) -> Vec<&str> {
        self.states
            .iter()
            .filter(|(_, s)| s.is_modified())
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Restore a specific interface
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails
    pub fn restore(&mut self, interface: &str) -> Result<()> {
        let state = match self.states.get(interface) {
            Some(s) => s.clone(),
            None => return Ok(()),
        };

        let mut errors = Vec::new();

        // Restore monitor interface
        if let Some(ref mon) = state.monitor_created {
            if let Err(e) = self.delete_monitor(mon) {
                errors.push(format!("Failed to delete monitor {}: {}", mon, e));
            }
        }

        // Restore MAC
        if let Some(ref original_mac) = state.original_mac {
            if let Err(e) = self.restore_mac(interface, original_mac) {
                errors.push(format!("Failed to restore MAC: {}", e));
            }
        }

        // Restore TX power
        if let Some(original_power) = state.original_tx_power {
            if let Err(e) = self.restore_tx_power(interface, original_power) {
                errors.push(format!("Failed to restore TX power: {}", e));
            }
        }

        // Remove state
        self.states.remove(interface);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(EvasionError::RestoreError(errors.join("; ")))
        }
    }

    /// Restore all interfaces
    ///
    /// # Errors
    ///
    /// Returns the first error encountered
    pub fn restore_all(&mut self) -> Result<()> {
        let interfaces: Vec<String> = self.states.keys().cloned().collect();
        let mut first_error = None;

        for interface in interfaces {
            if let Err(e) = self.restore(&interface) {
                log::warn!("Failed to restore {}: {}", interface, e);
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Save states to a JSON file for persistence
    ///
    /// # Errors
    ///
    /// Returns an error if saving fails
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let states: Vec<_> = self.states.values().collect();
        let json = serde_json::to_string_pretty(&states)
            .map_err(|e| EvasionError::Config(format!("Failed to serialize: {}", e)))?;

        std::fs::write(path.as_ref(), json)
            .map_err(|e| EvasionError::Config(format!("Failed to write: {}", e)))
    }

    /// Load states from a JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails
    pub fn load_from_file(&mut self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let json = std::fs::read_to_string(path.as_ref())
            .map_err(|e| EvasionError::Config(format!("Failed to read: {}", e)))?;

        let states: Vec<InterfaceState> = serde_json::from_str(&json)
            .map_err(|e| EvasionError::Config(format!("Failed to parse: {}", e)))?;

        for state in states {
            self.states.insert(state.interface.clone(), state);
        }

        Ok(())
    }

    // Helper methods for restoration

    fn delete_monitor(&self, monitor: &str) -> Result<()> {
        // Try netlink first
        if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
            if mgr.delete_interface(monitor).is_ok() {
                return Ok(());
            }
        }

        // Fall back to airmon-ng
        let _ = std::process::Command::new("airmon-ng")
            .args(["stop", monitor])
            .output();

        Ok(())
    }

    fn restore_mac(&self, interface: &str, mac: &str) -> Result<()> {
        let mgr = rustyjack_netlink::LinkManager::new()
            .map_err(|e| EvasionError::System(format!("Failed to initialize netlink: {}", e)))?;
        
        // Bring down
        let _ = mgr.set_link_down(interface);

        // Set MAC
        let result = mgr.set_mac_address(interface, mac)
            .map_err(|e| EvasionError::RestoreError(format!("Failed to set MAC: {}", e)));

        // Bring up
        let _ = mgr.set_link_up(interface);

        result
    }

    fn restore_tx_power(&self, interface: &str, dbm: i32) -> Result<()> {
        let mbm = dbm * 100;

        // Try netlink first
        if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
            let power_setting = rustyjack_netlink::TxPowerSetting::Fixed(mbm as u32);
            if mgr.set_tx_power(interface, power_setting).is_ok() {
                return Ok(());
            }
        }

        // Fall back to iwconfig
        let _ = std::process::Command::new("iwconfig")
            .args([interface, "txpower", &dbm.to_string()])
            .output();

        Ok(())
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StateManager {
    fn drop(&mut self) {
        if self.auto_restore && !self.states.is_empty() {
            if let Err(e) = self.restore_all() {
                log::error!("Failed to restore interface states on drop: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_state_new() {
        let state = InterfaceState::new("wlan0");
        assert_eq!(state.interface, "wlan0");
        assert!(!state.is_modified());
    }

    #[test]
    fn test_state_manager() {
        let mut manager = StateManager::new();
        manager.set_auto_restore(false); // Prevent actual restoration in tests

        let state = manager.get_or_create("wlan0");
        state.original_mac = Some("AA:BB:CC:DD:EE:FF".to_string());

        assert!(manager.get("wlan0").is_some());
        assert!(manager.get("wlan1").is_none());
    }

    #[test]
    fn test_modified_interfaces() {
        let mut manager = StateManager::new();
        manager.set_auto_restore(false);

        {
            let state = manager.get_or_create("wlan0");
            state.original_mac = Some("AA:BB:CC:DD:EE:FF".to_string());
        }

        let _ = manager.get_or_create("wlan1"); // Not modified

        let modified = manager.modified_interfaces();
        assert_eq!(modified.len(), 1);
        assert!(modified.contains(&"wlan0"));
    }
}
