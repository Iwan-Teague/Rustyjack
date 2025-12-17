//! nl80211 interface for wireless configuration
//!
//! This module provides low-level access to the Linux wireless subsystem
//! via the nl80211 netlink interface.

use std::fs;
use std::process::Command;

use crate::error::{Result, WirelessError};
use crate::process_helpers::pkill_pattern_force;
use rustyjack_netlink::{InterfaceMode, WirelessManager};

/// nl80211 command types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Nl80211Cmd {
    /// Get interface info
    GetInterface = 5,
    /// Set interface type (managed/monitor)
    SetInterface = 6,
    /// Get wiphy (physical device) info
    GetWiphy = 1,
    /// Set wiphy parameters
    SetWiphy = 2,
    /// Set channel
    SetChannel = 65,
    /// Trigger scan
    TriggerScan = 33,
    /// Get scan results
    GetScan = 32,
}

/// nl80211 interface types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nl80211IfType {
    /// Unspecified
    Unspecified = 0,
    /// Ad-hoc (IBSS)
    Adhoc = 1,
    /// Managed (client/station)
    Managed = 2,
    /// Access Point
    Ap = 3,
    /// AP VLAN
    ApVlan = 4,
    /// WDS (Wireless Distribution System)
    Wds = 5,
    /// Monitor mode
    Monitor = 6,
    /// Mesh point
    MeshPoint = 7,
    /// P2P Client
    P2pClient = 8,
    /// P2P GO
    P2pGo = 9,
    /// P2P Device
    P2pDevice = 10,
    /// OCB (Outside Context of BSS)
    Ocb = 11,
    /// NAN (Neighbor Awareness Networking)
    Nan = 12,
}

/// nl80211 attribute types
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Nl80211Attr {
    /// Unspecified
    Unspec = 0,
    /// Wiphy index
    Wiphy = 1,
    /// Wiphy name
    WiphyName = 2,
    /// Interface index
    Ifindex = 3,
    /// Interface name
    Ifname = 4,
    /// Interface type
    Iftype = 5,
    /// MAC address
    Mac = 6,
    /// Key data
    KeyData = 7,
    /// Frequency
    WiphyFreq = 38,
    /// Channel width
    ChannelWidth = 159,
    /// Center frequency 1
    CenterFreq1 = 160,
    /// SSID
    Ssid = 52,
    /// BSS info
    Bss = 47,
}

/// Netlink message header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgHdr {
    /// Message length including header
    pub len: u32,
    /// Message type
    pub msg_type: u16,
    /// Message flags
    pub flags: u16,
    /// Sequence number
    pub seq: u32,
    /// Process ID
    pub pid: u32,
}

impl NlMsgHdr {
    /// Size of the header in bytes
    pub const SIZE: usize = 16;

    /// Create a new netlink message header
    pub fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        Self {
            len: Self::SIZE as u32,
            msg_type,
            flags,
            seq,
            pid: std::process::id(),
        }
    }
}

/// Generic netlink message header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GenlMsgHdr {
    /// Command
    pub cmd: u8,
    /// Version
    pub version: u8,
    /// Reserved (padding)
    pub reserved: u16,
}

impl GenlMsgHdr {
    /// Size of the header in bytes
    pub const SIZE: usize = 4;
}

/// Netlink attribute header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlAttrHdr {
    /// Attribute length including header
    pub len: u16,
    /// Attribute type
    pub attr_type: u16,
}

impl NlAttrHdr {
    /// Size of the header in bytes
    pub const SIZE: usize = 4;
}

/// Get interface index from name
pub fn get_ifindex(name: &str) -> Result<i32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = fs::read_to_string(&path)
        .map_err(|e| WirelessError::Interface(format!("Failed to read ifindex: {}", e)))?;

    content
        .trim()
        .parse()
        .map_err(|e| WirelessError::Interface(format!("Invalid ifindex: {}", e)))
}

/// Get wiphy index for an interface
pub fn get_wiphy_index(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/phy80211/index", name);
    let content = fs::read_to_string(&path)
        .map_err(|e| WirelessError::Interface(format!("Failed to read wiphy index: {}", e)))?;

    content
        .trim()
        .parse()
        .map_err(|e| WirelessError::Interface(format!("Invalid wiphy index: {}", e)))
}

/// Check if interface is in monitor mode
pub fn is_monitor_mode(name: &str) -> Result<bool> {
    let path = format!("/sys/class/net/{}/type", name);
    let content = fs::read_to_string(&path)
        .map_err(|e| WirelessError::Interface(format!("Failed to read interface type: {}", e)))?;

    // Type 803 is ARPHRD_IEEE80211_RADIOTAP (monitor mode with radiotap)
    // Type 801 is ARPHRD_IEEE80211 (raw 802.11)
    let iface_type: u32 = content.trim().parse().unwrap_or(0);
    Ok(iface_type == 803 || iface_type == 801)
}

/// Get current interface type
pub fn get_interface_type(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/type", name);
    let content = fs::read_to_string(&path)
        .map_err(|e| WirelessError::Interface(format!("Failed to read interface type: {}", e)))?;

    content
        .trim()
        .parse()
        .map_err(|e| WirelessError::Interface(format!("Invalid interface type: {}", e)))
}

/// Interface state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    /// Interface is up
    Up,
    /// Interface is down
    Down,
    /// Unknown state
    Unknown,
}

/// Get interface state (up/down)
pub fn get_interface_state(name: &str) -> Result<InterfaceState> {
    let path = format!("/sys/class/net/{}/operstate", name);
    let content = fs::read_to_string(&path)
        .map_err(|e| WirelessError::Interface(format!("Failed to read operstate: {}", e)))?;

    Ok(match content.trim() {
        "up" => InterfaceState::Up,
        "down" => InterfaceState::Down,
        _ => InterfaceState::Unknown,
    })
}

/// Set interface up or down using ioctl
pub fn set_interface_state(name: &str, up: bool) -> Result<()> {
    let state = if up { "up" } else { "down" };
    let status = Command::new("ip")
        .args(["link", "set", name, state])
        .status()
        .map_err(|e| WirelessError::Interface(format!("Failed to run ip command: {}", e)))?;

    if !status.success() {
        return Err(WirelessError::Interface(format!(
            "Failed to set interface {} {}",
            name, state
        )));
    }

    Ok(())
}

/// Set interface type using iw command
/// This is a fallback when netlink doesn't work
pub fn set_interface_type_iw(name: &str, mode: Nl80211IfType) -> Result<()> {
    use std::process::Command;

    let mode_str = match mode {
        Nl80211IfType::Monitor => "monitor",
        Nl80211IfType::Managed => "managed",
        Nl80211IfType::Adhoc => "ibss",
        Nl80211IfType::Ap => "ap",
        Nl80211IfType::MeshPoint => "mesh",
        _ => {
            return Err(WirelessError::Unsupported(format!(
                "Interface type {:?} not supported via iw",
                mode
            )))
        }
    };

    // First bring interface down
    set_interface_state(name, false)?;

    // Set the type
    let status = Command::new("iw")
        .args(["dev", name, "set", "type", mode_str])
        .status()
        .map_err(|e| WirelessError::Interface(format!("Failed to run iw command: {}", e)))?;

    if !status.success() {
        return Err(WirelessError::MonitorMode(format!(
            "Failed to set {} to {} mode",
            name, mode_str
        )));
    }

    // Bring interface back up
    set_interface_state(name, true)?;

    Ok(())
}

/// Set interface type using the Rustyjack netlink backend (preferred over `iw`)
pub fn set_interface_type_netlink(name: &str, mode: Nl80211IfType) -> Result<()> {
    let netlink_mode = match mode {
        Nl80211IfType::Monitor => InterfaceMode::Monitor,
        Nl80211IfType::Managed => InterfaceMode::Station,
        Nl80211IfType::Adhoc => InterfaceMode::Adhoc,
        Nl80211IfType::Ap => InterfaceMode::AccessPoint,
        Nl80211IfType::MeshPoint => InterfaceMode::MeshPoint,
        Nl80211IfType::P2pClient => InterfaceMode::P2PClient,
        Nl80211IfType::P2pGo => InterfaceMode::P2PGo,
        _ => {
            return Err(WirelessError::Unsupported(format!(
                "Interface type {:?} not supported via nl80211",
                mode
            )))
        }
    };

    let mut mgr = WirelessManager::new()
        .map_err(|e| WirelessError::System(format!("Failed to open nl80211 socket: {}", e)))?;

    mgr.set_mode(name, netlink_mode).map_err(|e| {
        WirelessError::System(format!("Failed to set {} to {:?} mode: {}", name, mode, e))
    })
}

/// Set channel using netlink
pub fn set_channel_iw(name: &str, channel: u8) -> Result<()> {
    let mut mgr = rustyjack_netlink::WirelessManager::new()
        .map_err(|e| WirelessError::Channel(format!("Failed to create wireless manager: {}", e)))?;

    mgr.set_channel(name, channel).map_err(|e| {
        WirelessError::Channel(format!(
            "Failed to set channel {} on {}: {}",
            channel, name, e
        ))
    })
}

/// Set frequency using netlink
pub fn set_frequency_iw(name: &str, freq_mhz: u32) -> Result<()> {
    let mut mgr = rustyjack_netlink::WirelessManager::new()
        .map_err(|e| WirelessError::Channel(format!("Failed to create wireless manager: {}", e)))?;

    mgr.set_frequency(name, freq_mhz, rustyjack_netlink::ChannelWidth::NoHT)
        .map_err(|e| {
            WirelessError::Channel(format!(
                "Failed to set frequency {} MHz on {}: {}",
                freq_mhz, name, e
            ))
        })
}

/// Get current channel
pub fn get_channel(name: &str) -> Result<Option<u8>> {
    let mut mgr = rustyjack_netlink::WirelessManager::new()
        .map_err(|e| WirelessError::Channel(format!("Failed to create wireless manager: {}", e)))?;

    let info = mgr.get_interface_info(name).map_err(|e| {
        WirelessError::Channel(format!("Failed to get interface info for {}: {}", name, e))
    })?;

    Ok(info.channel)
}

/// Kill processes that might interfere with monitor mode
pub fn kill_interfering_processes() -> Result<()> {
    // Common interfering processes
    let processes = [
        "wpa_supplicant",
        "NetworkManager",
        "dhclient",
        "avahi-daemon",
    ];

    for proc in processes {
        let _ = pkill_pattern_force(proc);
    }

    Ok(())
}

/// Get MAC address of interface
pub fn get_mac_address(name: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", name);
    let content = fs::read_to_string(&path)
        .map_err(|e| WirelessError::Interface(format!("Failed to read MAC: {}", e)))?;

    let mac_str = content.trim();
    let parts: Vec<&str> = mac_str.split(':').collect();

    if parts.len() != 6 {
        return Err(WirelessError::Interface(format!(
            "Invalid MAC format: {}",
            mac_str
        )));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| WirelessError::Interface(format!("Invalid MAC octet: {}", part)))?;
    }

    Ok(mac)
}

/// Set MAC address
pub fn set_mac_address(name: &str, mac: &[u8; 6]) -> Result<()> {
    use std::process::Command;

    let mac_str = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // Interface must be down to change MAC
    set_interface_state(name, false)?;

    let status = Command::new("ip")
        .args(["link", "set", name, "address", &mac_str])
        .status()
        .map_err(|e| WirelessError::Interface(format!("Failed to set MAC: {}", e)))?;

    set_interface_state(name, true)?;

    if !status.success() {
        return Err(WirelessError::Interface(format!(
            "Failed to set MAC address to {}",
            mac_str
        )));
    }

    Ok(())
}

/// Check if interface supports monitor mode
pub fn supports_monitor_mode(_name: &str) -> Result<bool> {
    // Query iw for phy capabilities
    // Note: _name is reserved for future per-interface checks
    let output = Command::new("iw")
        .args(["phy"])
        .output()
        .map_err(|e| WirelessError::Interface(format!("Failed to run iw phy: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the phy for this interface and check supported modes
    // This is a simplified check
    Ok(stdout.contains("monitor"))
}

/// Check if interface supports packet injection
pub fn supports_injection(name: &str) -> Result<bool> {
    // This would require actually attempting injection
    // For now, assume if monitor mode is supported, injection might work
    supports_monitor_mode(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ifindex() {
        // This test will work on any Linux system with loopback
        let result = get_ifindex("lo");
        assert!(result.is_ok());
    }
}
