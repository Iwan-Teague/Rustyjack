//! Wireless interface management
//!
//! High-level interface for managing wireless adapters, including
//! monitor mode, channel setting, and state management.

use std::fmt;
use std::thread;
use std::time::Duration;

use crate::error::{Result, WirelessError};
use crate::frames::MacAddress;
use crate::nl80211::{
    self, get_channel, get_ifindex, get_interface_state, get_mac_address, is_monitor_mode,
    kill_interfering_processes, set_channel_iw, set_interface_state, set_interface_type_iw,
    InterfaceState, Nl80211IfType,
};

/// Wireless interface wrapper
#[derive(Debug)]
pub struct WirelessInterface {
    /// Interface name (e.g., "wlan0")
    name: String,
    /// Interface index
    ifindex: i32,
    /// Original MAC address (for restoration)
    #[allow(dead_code)]
    original_mac: [u8; 6],
    /// Original interface type
    #[allow(dead_code)]
    original_type: Option<Nl80211IfType>,
    /// Whether we put it in monitor mode
    we_enabled_monitor: bool,
}

impl WirelessInterface {
    /// Create interface wrapper
    pub fn new(name: &str) -> Result<Self> {
        // Verify interface exists and is wireless
        if !crate::is_wireless_interface(name) {
            return Err(WirelessError::Interface(format!(
                "'{}' is not a wireless interface",
                name
            )));
        }

        let ifindex = get_ifindex(name)?;
        let original_mac = get_mac_address(name)?;

        Ok(Self {
            name: name.to_string(),
            ifindex,
            original_mac,
            original_type: None,
            we_enabled_monitor: false,
        })
    }

    /// Get interface name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get interface index
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Get MAC address
    pub fn mac_address(&self) -> Result<MacAddress> {
        let mac = get_mac_address(&self.name)?;
        Ok(MacAddress::new(mac))
    }

    /// Check if interface is currently in monitor mode
    pub fn is_monitor_mode(&self) -> Result<bool> {
        is_monitor_mode(&self.name)
    }

    /// Get interface state (up/down)
    pub fn state(&self) -> Result<InterfaceState> {
        get_interface_state(&self.name)
    }

    /// Check if interface is up
    pub fn is_up(&self) -> Result<bool> {
        Ok(self.state()? == InterfaceState::Up)
    }

    /// Bring interface up
    pub fn up(&self) -> Result<()> {
        set_interface_state(&self.name, true)
    }

    /// Bring interface down
    pub fn down(&self) -> Result<()> {
        set_interface_state(&self.name, false)
    }

    /// Enable monitor mode
    ///
    /// This will:
    /// 1. Kill interfering processes (optional)
    /// 2. Bring interface down
    /// 3. Set interface type to monitor
    /// 4. Bring interface up
    pub fn set_monitor_mode(&mut self) -> Result<()> {
        self.set_monitor_mode_opts(MonitorModeOptions::default())
    }

    /// Enable monitor mode with options
    pub fn set_monitor_mode_opts(&mut self, opts: MonitorModeOptions) -> Result<()> {
        tracing::info!("Enabling monitor mode on {}", self.name);

        // Check if already in monitor mode
        if self.is_monitor_mode()? {
            tracing::info!("{} already in monitor mode", self.name);
            return Ok(());
        }

        // Kill interfering processes
        if opts.kill_processes {
            tracing::debug!("Killing interfering processes");
            kill_interfering_processes()?;
            thread::sleep(Duration::from_millis(500));
        }

        // Set to monitor mode
        set_interface_type_iw(&self.name, Nl80211IfType::Monitor)?;

        // Verify
        thread::sleep(Duration::from_millis(100));
        if !self.is_monitor_mode()? {
            return Err(WirelessError::MonitorMode(
                "Failed to verify monitor mode".into(),
            ));
        }

        self.we_enabled_monitor = true;
        tracing::info!("{} is now in monitor mode", self.name);

        Ok(())
    }

    /// Disable monitor mode and return to managed mode
    pub fn set_managed_mode(&mut self) -> Result<()> {
        tracing::info!("Disabling monitor mode on {}", self.name);

        if !self.is_monitor_mode()? {
            tracing::info!("{} not in monitor mode", self.name);
            return Ok(());
        }

        set_interface_type_iw(&self.name, Nl80211IfType::Managed)?;

        // Restart network services
        self.restart_network_services()?;

        self.we_enabled_monitor = false;
        tracing::info!("{} is now in managed mode", self.name);

        Ok(())
    }

    /// Set channel
    pub fn set_channel(&self, channel: u8) -> Result<()> {
        tracing::debug!("Setting {} to channel {}", self.name, channel);
        set_channel_iw(&self.name, channel)
    }

    /// Get current channel
    pub fn get_channel(&self) -> Result<Option<u8>> {
        get_channel(&self.name)
    }

    /// Set channel with retry
    pub fn set_channel_retry(&self, channel: u8, retries: u32) -> Result<()> {
        for attempt in 0..retries {
            match self.set_channel(channel) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if attempt < retries - 1 {
                        tracing::warn!("Channel set attempt {} failed: {}", attempt + 1, e);
                        thread::sleep(Duration::from_millis(100));
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err(WirelessError::Channel(format!(
            "Failed to set channel after {} attempts",
            retries
        )))
    }

    /// Restart network services (NetworkManager, etc.)
    fn restart_network_services(&self) -> Result<()> {
        tracing::info!(
            "Skipping network service restarts for {} (Rustyjack manages the interface state)",
            self.name
        );
        Ok(())
    }

    /// Get monitor interface name
    /// Some drivers create a separate monitor interface (wlan0mon)
    pub fn monitor_interface_name(&self) -> String {
        if self.name.ends_with("mon") {
            self.name.clone()
        } else if is_monitor_mode(&format!("{}mon", self.name)).unwrap_or(false) {
            format!("{}mon", self.name)
        } else {
            self.name.clone()
        }
    }
}

impl Drop for WirelessInterface {
    fn drop(&mut self) {
        // Optionally restore managed mode when dropped
        if self.we_enabled_monitor {
            if let Err(e) = self.set_managed_mode() {
                tracing::warn!("Failed to restore managed mode on {}: {}", self.name, e);
            }
        }
    }
}

impl fmt::Display for WirelessInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (index: {})", self.name, self.ifindex)
    }
}

/// Options for enabling monitor mode
#[derive(Debug, Clone)]
pub struct MonitorModeOptions {
    /// Kill interfering processes (NetworkManager, wpa_supplicant, etc.)
    pub kill_processes: bool,
    /// Create a separate monitor interface instead of converting
    pub create_new_interface: bool,
    /// New interface name (if creating new)
    pub new_interface_name: Option<String>,
}

impl Default for MonitorModeOptions {
    fn default() -> Self {
        Self {
            kill_processes: true,
            create_new_interface: false,
            new_interface_name: None,
        }
    }
}

impl MonitorModeOptions {
    /// Create with process killing enabled
    pub fn with_kill_processes(mut self) -> Self {
        self.kill_processes = true;
        self
    }

    /// Create without process killing
    pub fn without_kill_processes(mut self) -> Self {
        self.kill_processes = false;
        self
    }
}

/// Interface capability information
#[derive(Debug, Clone)]
pub struct InterfaceCapabilities {
    /// Supports monitor mode
    pub monitor_mode: bool,
    /// Supports packet injection
    pub injection: bool,
    /// Supported channels (2.4GHz)
    pub channels_2g: Vec<u8>,
    /// Supported channels (5GHz)
    pub channels_5g: Vec<u8>,
}

impl InterfaceCapabilities {
    /// Query capabilities for an interface
    pub fn query(name: &str) -> Result<Self> {
        let monitor_mode = nl80211::supports_monitor_mode(name).unwrap_or(false);
        let injection = nl80211::supports_injection(name).unwrap_or(false);

        // Default channels - actual detection would require nl80211 phy parsing
        let channels_2g = (1..=14).collect();
        let channels_5g = vec![
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
            144, 149, 153, 157, 161, 165,
        ];

        Ok(Self {
            monitor_mode,
            injection,
            channels_2g,
            channels_5g,
        })
    }

    /// Check if interface is suitable for attacks
    pub fn suitable_for_attacks(&self) -> bool {
        self.monitor_mode && self.injection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_mode_options() {
        let opts = MonitorModeOptions::default();
        assert!(opts.kill_processes);
        assert!(!opts.create_new_interface);
    }
}
