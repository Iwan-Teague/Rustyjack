//! RF kill device management via `/dev/rfkill`.
//!
//! Pure Rust implementation of rfkill functionality for blocking/unblocking wireless devices.
//! Directly interfaces with `/dev/rfkill` kernel device without calling external `rfkill` command.
//!
//! Supports all rfkill device types (WLAN, Bluetooth, GPS, NFC, etc.) and provides both
//! individual device control and type-based bulk operations.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RfkillError {
    #[error("Failed to open /dev/rfkill: {0}")]
    DeviceOpen(#[from] std::io::Error),

    #[error("Failed to read rfkill event: {0}")]
    ReadEvent(String),

    #[error("Failed to write rfkill event: {0}")]
    WriteEvent(String),

    #[error("Invalid rfkill type: {0}")]
    InvalidType(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(u32),

    #[error("Invalid state")]
    InvalidState,
}

pub type Result<T> = std::result::Result<T, RfkillError>;

/// rfkill device types from linux/rfkill.h.
///
/// Represents different categories of RF devices that can be blocked/unblocked.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfkillType {
    All = 0,
    Wlan = 1,
    Bluetooth = 2,
    Uwb = 3,
    Wimax = 4,
    Wwan = 5,
    Gps = 6,
    Fm = 7,
    Nfc = 8,
}

impl RfkillType {
    /// Convert u8 value to RfkillType enum.
    ///
    /// Returns None for unknown type values.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RfkillType::All),
            1 => Some(RfkillType::Wlan),
            2 => Some(RfkillType::Bluetooth),
            3 => Some(RfkillType::Uwb),
            4 => Some(RfkillType::Wimax),
            5 => Some(RfkillType::Wwan),
            6 => Some(RfkillType::Gps),
            7 => Some(RfkillType::Fm),
            8 => Some(RfkillType::Nfc),
            _ => None,
        }
    }

    /// Get human-readable name for device type.
    pub fn name(&self) -> &'static str {
        match self {
            RfkillType::All => "all",
            RfkillType::Wlan => "wlan",
            RfkillType::Bluetooth => "bluetooth",
            RfkillType::Uwb => "uwb",
            RfkillType::Wimax => "wimax",
            RfkillType::Wwan => "wwan",
            RfkillType::Gps => "gps",
            RfkillType::Fm => "fm",
            RfkillType::Nfc => "nfc",
        }
    }
}

/// rfkill operations from linux/rfkill.h
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfkillOp {
    Add = 0,
    Del = 1,
    Change = 2,
    ChangeAll = 3,
}

impl RfkillOp {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RfkillOp::Add),
            1 => Some(RfkillOp::Del),
            2 => Some(RfkillOp::Change),
            3 => Some(RfkillOp::ChangeAll),
            _ => None,
        }
    }
}

/// rfkill event structure from linux/rfkill.h
/// Must be packed to match kernel ABI
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RfkillEvent {
    pub idx: u32,
    pub type_: u8,
    pub op: u8,
    pub soft: u8,
    pub hard: u8,
}

impl RfkillEvent {
    const SIZE: usize = 8;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(RfkillError::ReadEvent(format!(
                "Invalid event size: {} < {}",
                bytes.len(),
                Self::SIZE
            )));
        }

        Ok(RfkillEvent {
            idx: u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            type_: bytes[4],
            op: bytes[5],
            soft: bytes[6],
            hard: bytes[7],
        })
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let idx_bytes = self.idx.to_ne_bytes();
        [
            idx_bytes[0],
            idx_bytes[1],
            idx_bytes[2],
            idx_bytes[3],
            self.type_,
            self.op,
            self.soft,
            self.hard,
        ]
    }

    pub fn get_type(&self) -> Option<RfkillType> {
        RfkillType::from_u8(self.type_)
    }

    pub fn get_op(&self) -> Option<RfkillOp> {
        RfkillOp::from_u8(self.op)
    }

    pub fn is_soft_blocked(&self) -> bool {
        self.soft != 0
    }

    pub fn is_hard_blocked(&self) -> bool {
        self.hard != 0
    }

    pub fn is_blocked(&self) -> bool {
        self.is_soft_blocked() || self.is_hard_blocked()
    }
}

/// rfkill device state information.
///
/// Contains current blocking status (soft/hard) and device metadata.
#[derive(Debug, Clone)]
pub struct RfkillDevice {
    /// Device index (matches /sys/class/rfkill/rfkill{idx})
    pub idx: u32,
    /// Device type (WLAN, Bluetooth, etc.)
    pub type_: RfkillType,
    /// Software block status (can be changed by user)
    pub soft_blocked: bool,
    /// Hardware block status (hardware switch, cannot be changed by software)
    pub hard_blocked: bool,
    /// Device name from sysfs, if available
    pub name: Option<String>,
}

impl RfkillDevice {
    /// Check if device is blocked (soft or hard).
    pub fn is_blocked(&self) -> bool {
        self.soft_blocked || self.hard_blocked
    }

    /// Get human-readable state string.
    ///
    /// Returns "hard blocked", "soft blocked", or "unblocked".
    pub fn state_string(&self) -> &'static str {
        if self.hard_blocked {
            "hard blocked"
        } else if self.soft_blocked {
            "soft blocked"
        } else {
            "unblocked"
        }
    }
}

/// Main rfkill manager.
///
/// Provides high-level interface for blocking/unblocking RF devices.
/// Uses `/dev/rfkill` for control and `/sys/class/rfkill` for device information.
///
/// # Examples
///
/// ```no_run
/// # use rustyjack_netlink::*;
/// # fn example() -> Result<(), RfkillError> {
/// let rfkill = RfkillManager::new();
///
/// // List all devices
/// for dev in rfkill.list()? {
///     println!("rfkill{}: {} - {}", dev.idx, dev.type_.name(), dev.state_string());
/// }
///
/// // Unblock all WLAN devices
/// rfkill.unblock_type(RfkillType::Wlan)?;
///
/// // Block specific device
/// rfkill.block(0)?;
/// # Ok(())
/// # }
/// ```
pub struct RfkillManager {
    dev_path: &'static str,
}

impl RfkillManager {
    const DEV_RFKILL: &'static str = "/dev/rfkill";
    const SYS_RFKILL: &'static str = "/sys/class/rfkill";

    /// Create a new rfkill manager.
    pub fn new() -> Self {
        RfkillManager {
            dev_path: Self::DEV_RFKILL,
        }
    }

    /// List all rfkill devices with their current state.
    ///
    /// Reads from `/dev/rfkill` to enumerate all devices and their blocking status.
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot open /dev/rfkill (insufficient permissions)
    /// * `ReadEvent` - Failed to read rfkill events
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # fn example() -> Result<(), RfkillError> {
    /// let rfkill = RfkillManager::new();
    /// for dev in rfkill.list()? {
    ///     println!("Device {}: {} ({})", dev.idx,
    ///         dev.name.as_deref().unwrap_or("unknown"),
    ///         dev.state_string());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list(&self) -> Result<Vec<RfkillDevice>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(self.dev_path)?;

        let mut devices = Vec::new();
        let mut buffer = [0u8; RfkillEvent::SIZE];

        loop {
            match file.read(&mut buffer) {
                Ok(n) if n >= RfkillEvent::SIZE => {
                    let event = RfkillEvent::from_bytes(&buffer)?;

                    if let Some(op) = event.get_op() {
                        if op == RfkillOp::Add {
                            if let Some(type_) = event.get_type() {
                                let name = self.get_device_name(event.idx);
                                devices.push(RfkillDevice {
                                    idx: event.idx,
                                    type_,
                                    soft_blocked: event.is_soft_blocked(),
                                    hard_blocked: event.is_hard_blocked(),
                                    name,
                                });
                            }
                        }
                    }
                }
                Ok(_) => break,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(RfkillError::ReadEvent(e.to_string())),
            }
        }

        Ok(devices)
    }

    /// Get device name from sysfs.
    ///
    /// Reads `/sys/class/rfkill/rfkill{idx}/name`.
    fn get_device_name(&self, idx: u32) -> Option<String> {
        let path = format!("{}/rfkill{}/name", Self::SYS_RFKILL, idx);
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Soft-block a device (disable RF transmission).
    ///
    /// # Arguments
    ///
    /// * `idx` - Device index (from `list()` or `/sys/class/rfkill`)
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot open /dev/rfkill
    /// * `WriteEvent` - Failed to write block command
    pub fn block(&self, idx: u32) -> Result<()> {
        self.set_state(idx, true)
    }

    /// Unblock a device (enable RF transmission).
    ///
    /// Removes software block. Cannot remove hardware blocks (physical switch).
    ///
    /// # Arguments
    ///
    /// * `idx` - Device index
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot open /dev/rfkill
    /// * `WriteEvent` - Failed to write unblock command
    pub fn unblock(&self, idx: u32) -> Result<()> {
        self.set_state(idx, false)
    }

    /// Block all devices of a specific type.
    ///
    /// # Arguments
    ///
    /// * `type_` - Device type (e.g., `RfkillType::Wlan` for all wireless)
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot open /dev/rfkill
    /// * `WriteEvent` - Failed to write block command
    pub fn block_type(&self, type_: RfkillType) -> Result<()> {
        self.set_state_all(type_, true)
    }

    /// Unblock all devices of a specific type.
    ///
    /// # Arguments
    ///
    /// * `type_` - Device type (e.g., `RfkillType::Wlan`)
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot open /dev/rfkill
    /// * `WriteEvent` - Failed to write unblock command
    pub fn unblock_type(&self, type_: RfkillType) -> Result<()> {
        self.set_state_all(type_, false)
    }

    /// Block all rfkill devices of all types.
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot open /dev/rfkill
    /// * `WriteEvent` - Failed to write block command
    pub fn block_all(&self) -> Result<()> {
        self.set_state_all(RfkillType::All, true)
    }

    /// Unblock all rfkill devices of all types.
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot open /dev/rfkill
    /// * `WriteEvent` - Failed to write unblock command
    pub fn unblock_all(&self) -> Result<()> {
        self.set_state_all(RfkillType::All, false)
    }

    /// Set state for a specific device by index
    #[tracing::instrument(target = "wifi", skip(self))]
    fn set_state(&self, idx: u32, block: bool) -> Result<()> {
        let mut file = OpenOptions::new().write(true).open(self.dev_path)?;

        let event = RfkillEvent {
            idx,
            type_: 0, // Not used for single device changes
            op: RfkillOp::Change as u8,
            soft: if block { 1 } else { 0 },
            hard: 0,
        };

        file.write_all(&event.to_bytes())
            .map_err(|e| RfkillError::WriteEvent(e.to_string()))?;

        tracing::info!(
            target: "wifi",
            idx = idx,
            state = if block { "blocked" } else { "unblocked" },
            "rfkill_device_state"
        );

        Ok(())
    }

    /// Set state for all devices of a type
    #[tracing::instrument(target = "wifi", skip(self))]
    fn set_state_all(&self, type_: RfkillType, block: bool) -> Result<()> {
        let mut file = OpenOptions::new().write(true).open(self.dev_path)?;

        let event = RfkillEvent {
            idx: 0, // Not used for type-based changes
            type_: type_ as u8,
            op: RfkillOp::ChangeAll as u8,
            soft: if block { 1 } else { 0 },
            hard: 0,
        };

        file.write_all(&event.to_bytes())
            .map_err(|e| RfkillError::WriteEvent(e.to_string()))?;

        tracing::info!(
            target: "wifi",
            rf_type = type_.name(),
            state = if block { "blocked" } else { "unblocked" },
            "rfkill_type_state"
        );

        Ok(())
    }

    /// Get state of a specific device by index.
    ///
    /// # Arguments
    ///
    /// * `idx` - Device index
    ///
    /// # Errors
    ///
    /// * `DeviceNotFound` - Device index does not exist
    /// * `DeviceOpen` - Cannot open /dev/rfkill
    /// * `ReadEvent` - Failed to read rfkill events
    pub fn get_state(&self, idx: u32) -> Result<RfkillDevice> {
        let devices = self.list()?;
        devices
            .into_iter()
            .find(|d| d.idx == idx)
            .ok_or(RfkillError::DeviceNotFound(idx))
    }

    /// Find rfkill device index by network interface name.
    ///
    /// Searches `/sys/class/rfkill` to map network interface (e.g., "wlan0") to rfkill index.
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name (e.g., "wlan0", "hci0")
    ///
    /// # Returns
    ///
    /// * `Some(idx)` - Found rfkill index for interface
    /// * `None` - Interface not found or has no associated rfkill device
    ///
    /// # Errors
    ///
    /// * `DeviceOpen` - Cannot read /sys/class/rfkill
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # fn example() -> Result<(), RfkillError> {
    /// let rfkill = RfkillManager::new();
    /// if let Some(idx) = rfkill.find_index_by_interface("wlan0")? {
    ///     rfkill.unblock(idx)?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn find_index_by_interface(&self, interface: &str) -> Result<Option<u32>> {
        let rfkill_path = Path::new(Self::SYS_RFKILL);
        if !rfkill_path.exists() {
            return Ok(None);
        }

        let iface_path = Path::new("/sys/class/net").join(interface).join("device");
        let iface_dev = match fs::canonicalize(&iface_path) {
            Ok(path) => path,
            Err(_) => return Ok(None),
        };
        let entries = match fs::read_dir(rfkill_path) {
            Ok(entries) => entries,
            Err(_) => return Ok(None),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name_str) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(idx_str) = name_str.strip_prefix("rfkill") else {
                continue;
            };
            let Ok(idx) = idx_str.parse::<u32>() else {
                continue;
            };

            let rfkill_dev = match fs::canonicalize(path.join("device")) {
                Ok(path) => path,
                Err(_) => continue,
            };
            if iface_dev.starts_with(&rfkill_dev) || rfkill_dev.starts_with(&iface_dev) {
                return Ok(Some(idx));
            }
        }

        Ok(None)
    }
}

impl Default for RfkillManager {
    fn default() -> Self {
        Self::new()
    }
}
