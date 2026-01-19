//! Evasion configuration and settings
//!
//! This module provides configuration management for evasion operations,
//! including serialization for persistence.

use crate::error::{EvasionError, Result};
use crate::txpower::TxPowerLevel;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Complete evasion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// MAC randomization settings
    pub mac: MacConfig,

    /// TX power settings
    pub tx_power: TxPowerConfig,

    /// Passive mode settings
    pub passive: PassiveSettings,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            mac: MacConfig::default(),
            tx_power: TxPowerConfig::default(),
            passive: PassiveSettings::default(),
        }
    }
}

impl EvasionConfig {
    /// Create a new default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from a JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| EvasionError::Config(format!("Failed to read config: {}", e)))?;

        serde_json::from_str(&content)
            .map_err(|e| EvasionError::Config(format!("Failed to parse config: {}", e)))
    }

    /// Save configuration to a JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| EvasionError::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path.as_ref(), content)
            .map_err(|e| EvasionError::Config(format!("Failed to write config: {}", e)))
    }
}

/// MAC randomization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacConfig {
    /// Enable automatic MAC randomization before operations
    pub auto_randomize: bool,

    /// Restore original MAC after operations
    pub auto_restore: bool,

    /// Use vendor-specific OUI instead of random
    pub use_vendor_oui: bool,

    /// Preferred vendor for OUI (if use_vendor_oui is true)
    pub preferred_vendor: Option<String>,

    /// Original MAC (saved for restoration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_mac: Option<String>,

    /// Current MAC (if randomized)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_mac: Option<String>,
}

impl Default for MacConfig {
    fn default() -> Self {
        Self {
            auto_randomize: false,
            auto_restore: true,
            use_vendor_oui: false,
            preferred_vendor: None,
            original_mac: None,
            current_mac: None,
        }
    }
}

/// TX power configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPowerConfig {
    /// Default power level
    pub default_level: String,

    /// Auto-set stealth power during recon
    pub stealth_during_recon: bool,

    /// Restore original power after operations
    pub auto_restore: bool,
}

impl Default for TxPowerConfig {
    fn default() -> Self {
        Self {
            default_level: "high".to_string(),
            stealth_during_recon: true,
            auto_restore: true,
        }
    }
}

impl TxPowerConfig {
    /// Get the default TX power level
    #[must_use]
    pub fn default_power(&self) -> TxPowerLevel {
        TxPowerLevel::from_str(&self.default_level).unwrap_or(TxPowerLevel::High)
    }
}

/// Passive mode settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveSettings {
    /// Enable passive mode by default
    pub enabled: bool,

    /// Default channel (0 = hop)
    pub default_channel: u8,

    /// Default duration in seconds
    pub default_duration: u32,

    /// Capture probe requests
    pub capture_probes: bool,

    /// Capture beacons
    pub capture_beacons: bool,
}

impl Default for PassiveSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            default_channel: 0,
            default_duration: 60,
            capture_probes: true,
            capture_beacons: true,
        }
    }
}

/// Runtime evasion settings (non-persistent)
#[derive(Debug, Clone)]
pub struct EvasionSettings {
    /// Active interface
    pub interface: String,

    /// MAC randomization enabled for this session
    pub mac_randomize_enabled: bool,

    /// Passive mode enabled for this session
    pub passive_mode_enabled: bool,

    /// Current TX power level
    pub tx_power: TxPowerLevel,

    /// Original MAC (if changed)
    pub original_mac: Option<String>,

    /// Current MAC (if randomized)
    pub current_mac: Option<String>,
}

impl Default for EvasionSettings {
    fn default() -> Self {
        Self {
            interface: String::new(),
            mac_randomize_enabled: false,
            passive_mode_enabled: false,
            tx_power: TxPowerLevel::High,
            original_mac: None,
            current_mac: None,
        }
    }
}

impl EvasionSettings {
    /// Create settings for a specific interface
    #[must_use]
    pub fn for_interface(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            ..Default::default()
        }
    }

    /// Check if MAC has been changed
    #[must_use]
    pub fn mac_is_changed(&self) -> bool {
        self.current_mac.is_some() && self.original_mac.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EvasionConfig::default();
        assert!(!config.mac.auto_randomize);
        assert!(config.mac.auto_restore);
    }

    #[test]
    fn test_config_serialize() {
        let config = EvasionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("auto_randomize"));
    }

    #[test]
    fn test_config_roundtrip() {
        let original = EvasionConfig {
            mac: MacConfig {
                auto_randomize: true,
                preferred_vendor: Some("apple".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let json = serde_json::to_string(&original).unwrap();
        let restored: EvasionConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.mac.auto_randomize, original.mac.auto_randomize);
        assert_eq!(restored.mac.preferred_vendor, original.mac.preferred_vendor);
    }

    #[test]
    fn test_tx_power_config() {
        let config = TxPowerConfig::default();
        assert_eq!(config.default_power(), TxPowerLevel::High);

        let config = TxPowerConfig {
            default_level: "stealth".to_string(),
            ..Default::default()
        };
        assert_eq!(config.default_power(), TxPowerLevel::Stealth);
    }

    #[test]
    fn test_settings_interface() {
        let settings = EvasionSettings::for_interface("wlan0");
        assert_eq!(settings.interface, "wlan0");
        assert!(!settings.mac_is_changed());
    }
}
