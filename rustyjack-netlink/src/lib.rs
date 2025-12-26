//! # rustyjack-netlink
//!
//! Pure Rust networking library that replaces system binaries (`ip`, `dhclient`, `dnsmasq`, `rfkill`, `pgrep/pkill`)
//! with native implementations using Linux kernel APIs (netlink, rfkill, /proc).
//!
//! ## Features
//!
//! - **Network Interface Management**: Configure interfaces (up/down, addresses, MAC)
//! - **Routing**: Manage routing tables and default gateways
//! - **DHCP Client & Server**: Full RFC 2131 compliant implementations
//! - **DNS Server**: RFC 1035 compliant with wildcard spoofing for captive portals
//! - **RF Kill**: Block/unblock wireless devices
//! - **Process Management**: Find and signal processes without external tools
//! - **ARP Suite**: Scanning, spoofing, and host detection
//! - **Wireless**: nl80211-based wireless configuration and monitoring
//!
//! ## Platform Support
//!
//! Linux-only. Code is gated with `#[cfg(target_os = "linux")]` and compiles on other platforms
//! but functions are unavailable.
//!
//! ## Usage
//!
//! ```no_run
//! use rustyjack_netlink::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Bring interface up
//!     set_interface_up("eth0").await?;
//!     
//!     // Configure IP address
//!     let addr = "192.168.1.100".parse()?;
//!     add_address("eth0", addr, 24).await?;
//!     
//!     // Add default route
//!     let gateway = "192.168.1.1".parse()?;
//!     add_default_route(gateway, "eth0").await?;
//!     
//!     Ok(())
//! }
//! ```

#[cfg(target_os = "linux")]
pub mod arp;
#[cfg(target_os = "linux")]
mod arp_scanner;
#[cfg(target_os = "linux")]
mod arp_spoofer;
#[cfg(target_os = "linux")]
pub mod dhcp;
#[cfg(target_os = "linux")]
pub mod dhcp_server;
#[cfg(target_os = "linux")]
pub mod dns_server;
#[cfg(target_os = "linux")]
pub mod hostapd;
#[cfg(target_os = "linux")]
pub mod interface;
#[cfg(target_os = "linux")]
pub mod iptables;
pub mod logging;
#[cfg(target_os = "linux")]
pub mod networkmanager;
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(target_os = "linux")]
pub mod rfkill;
#[cfg(target_os = "linux")]
pub mod route;
#[cfg(target_os = "linux")]
pub mod supplicant;
#[cfg(target_os = "linux")]
pub mod wireless;
#[cfg(target_os = "linux")]
pub mod wpa;

pub mod error;

pub use error::{NetlinkError, Result};
#[cfg(target_os = "linux")]
pub use hostapd::take_last_ap_error;

#[cfg(target_os = "linux")]
pub use arp::{ArpError, ArpPacket, ArpScanConfig, ArpScanResult};
#[cfg(target_os = "linux")]
pub use arp_scanner::ArpScanner;
#[cfg(target_os = "linux")]
pub use arp_spoofer::{ArpSpoofConfig, ArpSpoofer};
#[cfg(target_os = "linux")]
pub use dhcp::{DhcpClient, DhcpLease};
#[cfg(target_os = "linux")]
pub use dhcp_server::{DhcpConfig, DhcpError, DhcpLease as DhcpServerLease, DhcpServer};
#[cfg(target_os = "linux")]
pub use dns_server::{DnsConfig, DnsError, DnsRule, DnsServer};
#[cfg(target_os = "linux")]
pub use hostapd::{
    generate_pmk, AccessPoint, ApClient, ApConfig, ApSecurity, ApStats, HardwareMode, WpaState,
};
#[cfg(target_os = "linux")]
pub use interface::{AddressInfo, InterfaceInfo, InterfaceManager};
#[cfg(target_os = "linux")]
pub use iptables::{Chain, IptablesError, IptablesManager, Protocol, Rule, Table, Target};
pub use logging::init_journald_logger;
#[cfg(target_os = "linux")]
pub use networkmanager::{AccessPoint as NmAccessPoint, NetworkManagerClient, NmDeviceState};
#[cfg(target_os = "linux")]
pub use process::{ProcessError, ProcessInfo, ProcessManager};
#[cfg(target_os = "linux")]
pub use rfkill::{RfkillDevice, RfkillError, RfkillManager, RfkillType};
#[cfg(target_os = "linux")]
pub use route::{RouteInfo, RouteManager};
#[cfg(target_os = "linux")]
pub use supplicant::{StationConfig, StationManager, StationOutcome, StationState};
#[cfg(target_os = "linux")]
pub use wireless::{
    ChannelWidth, InterfaceMode, PhyCapabilities, TxPowerSetting, WirelessInfo, WirelessManager,
};
#[cfg(target_os = "linux")]
pub use wpa::{
    is_wpa_running, start_wpa_supplicant, stop_wpa_supplicant, WpaManager, WpaNetworkConfig,
    WpaState as WpaSupplicantState, WpaStatus,
};

#[cfg(target_os = "linux")]
use std::net::IpAddr;

#[cfg(target_os = "linux")]
pub async fn set_interface_up(interface: &str) -> Result<()> {
    let mgr = InterfaceManager::new()?;
    mgr.set_interface_up(interface).await
}

#[cfg(target_os = "linux")]
pub async fn set_interface_down(interface: &str) -> Result<()> {
    let mgr = InterfaceManager::new()?;
    mgr.set_interface_down(interface).await
}

#[cfg(target_os = "linux")]
pub async fn add_address(interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
    let mgr = InterfaceManager::new()?;
    mgr.add_address(interface, addr, prefix_len).await
}

#[cfg(target_os = "linux")]
pub async fn delete_address(interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
    let mgr = InterfaceManager::new()?;
    mgr.delete_address(interface, addr, prefix_len).await
}

#[cfg(target_os = "linux")]
pub async fn flush_addresses(interface: &str) -> Result<()> {
    let mgr = InterfaceManager::new()?;
    mgr.flush_addresses(interface).await
}

#[cfg(target_os = "linux")]
pub async fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let mgr = InterfaceManager::new()?;
    mgr.list_interfaces().await
}

#[cfg(target_os = "linux")]
pub async fn add_default_route(gateway: IpAddr, interface: &str) -> Result<()> {
    let mgr = RouteManager::new()?;
    mgr.add_default_route(gateway, interface).await
}

#[cfg(target_os = "linux")]
pub async fn add_default_route_with_metric(
    gateway: IpAddr,
    interface: &str,
    metric: Option<u32>,
) -> Result<()> {
    let mgr = RouteManager::new()?;
    mgr.add_default_route_with_metric(gateway, interface, metric)
        .await
}

#[cfg(target_os = "linux")]
pub async fn delete_default_route() -> Result<()> {
    let mgr = RouteManager::new()?;
    mgr.delete_default_route().await
}

#[cfg(target_os = "linux")]
pub async fn list_routes() -> Result<Vec<RouteInfo>> {
    let mgr = RouteManager::new()?;
    mgr.list_routes().await
}

#[cfg(target_os = "linux")]
pub async fn dhcp_release(interface: &str) -> Result<()> {
    let client = DhcpClient::new()?;
    client.release(interface).await
}

#[cfg(target_os = "linux")]
pub async fn dhcp_acquire(interface: &str, hostname: Option<&str>) -> Result<DhcpLease> {
    let client = DhcpClient::new()?;
    client.acquire(interface, hostname).await
}

#[cfg(target_os = "linux")]
pub async fn dhcp_renew(interface: &str, hostname: Option<&str>) -> Result<DhcpLease> {
    let client = DhcpClient::new()?;
    client.renew(interface, hostname).await
}
