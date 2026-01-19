//! TX Power control for wireless interfaces
//!
//! This module provides control over wireless transmission power levels
//! for stealth operations or maximum range scenarios.
//!
//! ## Power Levels
//!
//! | Level    | dBm | Use Case |
//! |----------|-----|----------|
//! | Stealth  | 1   | Minimum detection range |
//! | Low      | 5   | Short-range operations |
//! | Medium   | 12  | Balanced |
//! | High     | 18  | Normal operations |
//! | Maximum  | 30  | Maximum range |
//!
//! ## Notes
//!
//! - TX power is hardware and driver dependent
//! - Some adapters may not support all power levels
//! - Regulatory limits apply in most countries
//! - Uses nl80211 via `rustyjack-netlink`

use crate::error::{EvasionError, Result};
use serde::{Deserialize, Serialize};

/// TX Power levels for wireless operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxPowerLevel {
    /// Stealth mode - minimum power (~1 dBm)
    ///
    /// Use for close-range operations where detection is a concern.
    Stealth,

    /// Low power (~5 dBm)
    ///
    /// Short range, reduced detection footprint.
    Low,

    /// Medium power (~12 dBm)
    ///
    /// Balanced range and stealth.
    Medium,

    /// High power (~18 dBm)
    ///
    /// Normal operation range.
    High,

    /// Maximum power (~30 dBm, adapter dependent)
    ///
    /// Maximum range, may be limited by hardware.
    Maximum,

    /// Custom power level in dBm
    Custom(i32),
}

impl TxPowerLevel {
    /// Convert to dBm value
    #[must_use]
    pub const fn to_dbm(self) -> i32 {
        match self {
            Self::Stealth => 1,
            Self::Low => 5,
            Self::Medium => 12,
            Self::High => 18,
            Self::Maximum => 30,
            Self::Custom(dbm) => dbm,
        }
    }

    /// Convert to milliWatts
    #[must_use]
    pub fn to_mw(self) -> u32 {
        let dbm = self.to_dbm() as f64;
        (10f64.powf(dbm / 10.0)) as u32
    }

    /// Convert to mBm (milli-dBm) for nl80211
    #[must_use]
    pub const fn to_mbm(self) -> i32 {
        self.to_dbm() * 100
    }

    /// Parse from string
    ///
    /// Accepts:
    /// - Named levels: "stealth", "low", "medium", "high", "max"
    /// - Numeric dBm values: "15", "-5"
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "stealth" | "min" | "minimum" | "1" => Some(Self::Stealth),
            "low" | "5" => Some(Self::Low),
            "medium" | "med" | "12" => Some(Self::Medium),
            "high" | "18" => Some(Self::High),
            "max" | "maximum" | "30" => Some(Self::Maximum),
            other => other.parse::<i32>().ok().map(Self::Custom),
        }
    }

    /// Get a human-readable label
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stealth => "Stealth (1 dBm)",
            Self::Low => "Low (5 dBm)",
            Self::Medium => "Medium (12 dBm)",
            Self::High => "High (18 dBm)",
            Self::Maximum => "Maximum",
            Self::Custom(_) => "Custom",
        }
    }

    /// Get description for this power level
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Stealth => "Minimal range - stealth mode",
            Self::Low => "Short range operations",
            Self::Medium => "Balanced range/stealth",
            Self::High => "Normal operation range",
            Self::Maximum => "Maximum range",
            Self::Custom(_) => "Custom power level",
        }
    }
}

impl Default for TxPowerLevel {
    fn default() -> Self {
        Self::High
    }
}

impl std::fmt::Display for TxPowerLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Saved TX power state for restoration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPowerState {
    /// Interface name
    pub interface: String,
    /// Original power level in dBm
    pub original_dbm: i32,
    /// Current power level
    pub current: TxPowerLevel,
}

/// Manager for TX power operations
pub struct TxPowerManager {
    states: Vec<TxPowerState>,
    auto_restore: bool,
}

impl TxPowerManager {
    /// Create a new TX power manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
            auto_restore: true,
        }
    }

    /// Set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, auto: bool) {
        self.auto_restore = auto;
    }

    /// Get current TX power for an interface
    ///
    /// # Arguments
    ///
    /// * `interface` - Wireless interface name
    ///
    /// # Returns
    ///
    /// Current power in dBm, or default (20) if unreadable
    pub fn get_power(&self, interface: &str) -> Result<i32> {
        // Try netlink via rustyjack-netlink
        #[cfg(target_os = "linux")]
        {
            if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
                if let Ok(info) = mgr.get_interface_info(interface) {
                    if let Some(txpower_mbm) = info.txpower_mbm {
                        return Ok(txpower_mbm / 100);
                    }
                }
            }
        }

        // Default if we can't read
        Ok(20)
    }

    /// Set TX power level
    ///
    /// # Arguments
    ///
    /// * `interface` - Wireless interface name
    /// * `level` - Desired power level
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Interface doesn't exist
    /// - Permission denied
    /// - Driver doesn't support TX power control
    pub fn set_power(&mut self, interface: &str, level: TxPowerLevel) -> Result<()> {
        self.validate_interface(interface)?;

        // Save original power
        let original = self.get_power(interface).unwrap_or(20);

        if !self.states.iter().any(|s| s.interface == interface) {
            self.states.push(TxPowerState {
                interface: interface.to_string(),
                original_dbm: original,
                current: level,
            });
        }

        // Use netlink
        #[cfg(target_os = "linux")]
        {
            let mbm = level.to_mbm();
            if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
                let power_setting = rustyjack_netlink::TxPowerSetting::Fixed(mbm as u32);
                mgr.set_tx_power(interface, power_setting)
                    .map_err(|e| EvasionError::TxPowerError(format!("{}", e)))?;
                tracing::debug!("Set TX power on {} to {} dBm using netlink", interface, level.to_dbm());
                return Ok(());
            }
        }

        Err(EvasionError::TxPowerError(format!(
            "Failed to set TX power on {}: netlink unavailable",
            interface
        )))
    }

    /// Set stealth power (minimum)
    ///
    /// Convenience method for `set_power(interface, TxPowerLevel::Stealth)`
    pub fn set_stealth(&mut self, interface: &str) -> Result<()> {
        self.set_power(interface, TxPowerLevel::Stealth)
    }

    /// Set maximum power
    ///
    /// Convenience method for `set_power(interface, TxPowerLevel::Maximum)`
    pub fn set_maximum(&mut self, interface: &str) -> Result<()> {
        self.set_power(interface, TxPowerLevel::Maximum)
    }

    /// Restore original TX power
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface to restore
    pub fn restore(&mut self, interface: &str) -> Result<()> {
        if let Some(pos) = self.states.iter().position(|s| s.interface == interface) {
            let state = self.states.remove(pos);
            self.set_power(interface, TxPowerLevel::Custom(state.original_dbm))?;
        }
        Ok(())
    }

    /// Restore all interfaces
    pub fn restore_all(&mut self) -> Result<()> {
        let states: Vec<_> = self.states.drain(..).collect();
        let mut first_error = None;

        for state in states {
            if let Err(e) =
                self.set_power(&state.interface, TxPowerLevel::Custom(state.original_dbm))
            {
                tracing::warn!("Failed to restore TX power on {}: {}", state.interface, e);
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    fn validate_interface(&self, interface: &str) -> Result<()> {
        if !crate::is_wireless(interface) {
            return Err(EvasionError::NotWireless(interface.into()));
        }
        Ok(())
    }
}

impl Default for TxPowerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TxPowerManager {
    fn drop(&mut self) {
        if self.auto_restore && !self.states.is_empty() {
            if let Err(e) = self.restore_all() {
                tracing::error!("Failed to restore TX power on drop: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_levels() {
        assert_eq!(TxPowerLevel::Stealth.to_dbm(), 1);
        assert_eq!(TxPowerLevel::Low.to_dbm(), 5);
        assert_eq!(TxPowerLevel::Medium.to_dbm(), 12);
        assert_eq!(TxPowerLevel::High.to_dbm(), 18);
        assert_eq!(TxPowerLevel::Maximum.to_dbm(), 30);
        assert_eq!(TxPowerLevel::Custom(15).to_dbm(), 15);
    }

    #[test]
    fn test_mbm_conversion() {
        assert_eq!(TxPowerLevel::Stealth.to_mbm(), 100);
        assert_eq!(TxPowerLevel::Maximum.to_mbm(), 3000);
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            TxPowerLevel::from_str("stealth"),
            Some(TxPowerLevel::Stealth)
        );
        assert_eq!(TxPowerLevel::from_str("LOW"), Some(TxPowerLevel::Low));
        assert_eq!(TxPowerLevel::from_str("max"), Some(TxPowerLevel::Maximum));
        assert_eq!(TxPowerLevel::from_str("15"), Some(TxPowerLevel::Custom(15)));
    }

    #[test]
    fn test_mw_conversion() {
        // 0 dBm = 1 mW
        // 10 dBm = 10 mW
        // 20 dBm = 100 mW
        let level = TxPowerLevel::Custom(10);
        assert_eq!(level.to_mw(), 10);

        let level = TxPowerLevel::Custom(20);
        assert_eq!(level.to_mw(), 100);
    }
}
