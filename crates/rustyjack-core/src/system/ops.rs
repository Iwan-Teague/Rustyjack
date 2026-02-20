use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSummary {
    pub name: String,
    pub kind: String,
    pub oper_state: String,
    pub ip: Option<String>,
    pub is_wireless: bool,
    pub admin_up: bool,
    pub carrier: Option<bool>,
    pub capabilities: Option<InterfaceCapabilities>,
}

/// TX-in-monitor capability verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxInMonitorCapability {
    Supported,
    NotSupported,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceCapabilities {
    pub name: String,
    pub is_wireless: bool,
    pub is_physical: bool,
    pub supports_monitor: bool,
    pub supports_ap: bool,
    /// Legacy field - derived from tx_in_monitor for backward compatibility
    pub supports_injection: bool,
    pub supports_5ghz: bool,
    pub supports_2ghz: bool,
    pub mac_address: Option<String>,
    pub driver: Option<String>,
    pub chipset: Option<String>,
    /// TX-in-monitor capability with accurate driver-based detection
    #[serde(default)]
    pub tx_in_monitor: TxInMonitorCapability,
    /// Human-readable reason for tx_in_monitor verdict
    #[serde(default)]
    pub tx_in_monitor_reason: String,
}

impl Default for TxInMonitorCapability {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone)]
pub struct IsolationOutcome {
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub errors: Vec<ErrorEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEntry {
    pub interface: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct RouteOutcome {
    pub interface: String,
    pub gateway: Ipv4Addr,
    pub metric: u32,
    pub dns_servers: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub interface: String,
    pub gateway: Ipv4Addr,
    pub metric: u32,
    pub destination: Option<ipnet::Ipv4Net>,
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
}

pub trait NetOps: Send + Sync {
    fn list_interfaces(&self) -> Result<Vec<InterfaceSummary>>;
    fn bring_up(&self, interface: &str) -> Result<()>;
    fn bring_down(&self, interface: &str) -> Result<()>;
    fn set_rfkill_block(&self, interface: &str, blocked: bool) -> Result<()>;
    fn is_wireless(&self, interface: &str) -> bool;
    fn interface_exists(&self, interface: &str) -> bool;

    fn add_default_route(&self, iface: &str, gateway: Ipv4Addr, metric: u32) -> Result<()>;
    fn delete_default_route(&self, iface: &str) -> Result<()>;
    fn list_routes(&self) -> Result<Vec<RouteEntry>>;

    fn acquire_dhcp(&self, iface: &str, timeout: Duration) -> Result<DhcpLease>;
    fn release_dhcp(&self, iface: &str) -> Result<()>;
    fn flush_addresses(&self, interface: &str) -> Result<()>;

    fn get_ipv4_address(&self, iface: &str) -> Result<Option<Ipv4Addr>>;
    fn get_interface_capabilities(&self, iface: &str) -> Result<InterfaceCapabilities>;
    fn admin_is_up(&self, interface: &str) -> Result<bool>;
    fn has_carrier(&self, interface: &str) -> Result<Option<bool>>;

    /// Check if rfkill is blocking this interface (soft or hard blocked)
    fn is_rfkill_blocked(&self, interface: &str) -> Result<bool>;

    /// Check if rfkill is HARD blocked (physical switch - cannot be unblocked via software)
    fn is_rfkill_hard_blocked(&self, interface: &str) -> Result<bool>;
}

pub struct RealNetOps;

static INTERFACE_INDEX_CACHE: OnceLock<StdMutex<HashMap<u32, String>>> = OnceLock::new();

impl RealNetOps {
    fn refresh_interface_cache(&self) -> Result<()> {
        let cache = INTERFACE_INDEX_CACHE.get_or_init(|| StdMutex::new(HashMap::new()));
        let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        guard.clear();

        use std::fs;
        let entries = fs::read_dir("/sys/class/net")?;

        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name == "lo" {
                    continue;
                }

                let ifindex_path = entry.path().join("ifindex");
                if let Ok(content) = fs::read_to_string(&ifindex_path) {
                    if let Ok(idx) = content.trim().parse::<u32>() {
                        guard.insert(idx, name);
                    }
                }
            }
        }

        Ok(())
    }

    fn interface_name_from_index(&self, index: u32) -> Option<String> {
        let cache = INTERFACE_INDEX_CACHE.get_or_init(|| StdMutex::new(HashMap::new()));

        // Try cache first
        {
            let guard = cache.lock().ok()?;
            if let Some(name) = guard.get(&index) {
                return Some(name.clone());
            }
        }

        // Cache miss - refresh and try again
        self.refresh_interface_cache().ok()?;

        let guard = cache.lock().ok()?;
        guard.get(&index).cloned()
    }
}

impl NetOps for RealNetOps {
    fn list_interfaces(&self) -> Result<Vec<InterfaceSummary>> {
        use anyhow::Context;
        use std::fs;

        let entries = fs::read_dir("/sys/class/net").context("reading /sys/class/net")?;
        let mut interfaces = Vec::new();

        for entry in entries {
            let entry = entry.context("iterating interfaces")?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }

            let is_wireless = self.is_wireless(&name);
            let kind = if is_wireless { "wireless" } else { "wired" };

            let oper_state_path = entry.path().join("operstate");
            let oper_state = fs::read_to_string(&oper_state_path)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string();

            let flags_hex = fs::read_to_string(entry.path().join("flags")).unwrap_or_default();
            let flags = u32::from_str_radix(flags_hex.trim().trim_start_matches("0x"), 16)
                .or_else(|_| flags_hex.trim().parse::<u32>())
                .unwrap_or(0);
            let admin_up = (flags & 0x1) != 0;

            let carrier = fs::read_to_string(entry.path().join("carrier"))
                .ok()
                .and_then(|val| match val.trim() {
                    "0" => Some(false),
                    "1" => Some(true),
                    _ => None,
                });

            // Query capabilities (ignore errors)
            let capabilities = self.get_interface_capabilities(&name).ok();

            interfaces.push(InterfaceSummary {
                name,
                kind: kind.to_string(),
                oper_state,
                ip: None,
                is_wireless,
                admin_up,
                carrier,
                capabilities,
            });
        }

        Ok(interfaces)
    }

    fn bring_up(&self, interface: &str) -> Result<()> {
        crate::netlink_helpers::netlink_set_interface_up(interface)
    }

    fn bring_down(&self, interface: &str) -> Result<()> {
        crate::netlink_helpers::netlink_set_interface_down(interface)
    }

    fn set_rfkill_block(&self, interface: &str, blocked: bool) -> Result<()> {
        use crate::netlink_helpers::{rfkill_block, rfkill_find_index, rfkill_unblock};

        match rfkill_find_index(interface)? {
            Some(idx) => {
                if blocked {
                    rfkill_block(idx)?;
                } else {
                    rfkill_unblock(idx)?;
                }
                Ok(())
            }
            None => Err(anyhow!(
                "rfkill device not found for interface {}",
                interface
            )),
        }
    }

    fn is_wireless(&self, interface: &str) -> bool {
        use std::path::Path;
        Path::new("/sys/class/net")
            .join(interface)
            .join("wireless")
            .exists()
    }

    fn interface_exists(&self, interface: &str) -> bool {
        use std::path::Path;
        Path::new("/sys/class/net").join(interface).exists()
    }

    fn add_default_route(&self, iface: &str, gateway: Ipv4Addr, metric: u32) -> Result<()> {
        use std::net::IpAddr;
        crate::netlink_helpers::netlink_add_default_route(IpAddr::V4(gateway), iface, Some(metric))
    }

    fn delete_default_route(&self, iface: &str) -> Result<()> {
        crate::netlink_helpers::netlink_delete_default_routes_on_interface(iface)
    }

    fn list_routes(&self) -> Result<Vec<RouteEntry>> {
        use crate::netlink_helpers::netlink_list_routes;

        // Refresh interface cache before querying routes
        self.refresh_interface_cache().ok();

        let routes = netlink_list_routes()?;

        Ok(routes
            .into_iter()
            .filter_map(|r| {
                // Only process IPv4 routes with gateways
                let gw = match r.gateway {
                    Some(std::net::IpAddr::V4(v4)) => v4,
                    _ => return None,
                };

                // Resolve interface name from index
                let iface_name = r
                    .interface_index
                    .and_then(|idx| self.interface_name_from_index(idx))
                    .unwrap_or_else(|| format!("if{}", r.interface_index.unwrap_or(0)));

                // Build destination if present
                let dest = match r.destination {
                    Some(std::net::IpAddr::V4(ip)) => ipnet::Ipv4Net::new(ip, r.prefix_len).ok(),
                    _ => None,
                };

                Some(RouteEntry {
                    interface: iface_name,
                    gateway: gw,
                    metric: r.metric.unwrap_or(0),
                    destination: dest,
                })
            })
            .collect())
    }

    fn acquire_dhcp(&self, iface: &str, timeout: Duration) -> Result<DhcpLease> {
        use anyhow::Context;
        use rustyjack_netlink::DhcpClient;

        let client = DhcpClient::new()?;
        let rt = tokio::runtime::Runtime::new()?;
        let report = rt
            .block_on(client.acquire_report_timeout(iface, None, timeout))
            .with_context(|| format!("DHCP failed for {} after {:?}", iface, timeout))?;
        let netlink_lease = report.lease.ok_or_else(|| {
            anyhow::anyhow!(
                "DHCP failed for {}: {}",
                iface,
                report.error.unwrap_or_else(|| "unknown error".to_string())
            )
        })?;

        Ok(DhcpLease {
            ip: netlink_lease.address,
            prefix_len: netlink_lease.prefix_len,
            gateway: netlink_lease.gateway,
            dns_servers: netlink_lease.dns_servers,
        })
    }

    fn release_dhcp(&self, iface: &str) -> Result<()> {
        use rustyjack_netlink::DhcpClient;

        let client = DhcpClient::new()?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(client.release(iface))
            .map_err(|e| anyhow::anyhow!("Failed to release DHCP: {}", e))
    }

    fn flush_addresses(&self, interface: &str) -> Result<()> {
        crate::netlink_helpers::netlink_flush_addresses(interface)
    }

    fn get_ipv4_address(&self, iface: &str) -> Result<Option<Ipv4Addr>> {
        use crate::netlink_helpers::netlink_get_ipv4_addresses;

        let addrs = netlink_get_ipv4_addresses(iface)?;
        Ok(addrs.first().and_then(|addr| {
            if let std::net::IpAddr::V4(ipv4) = addr.address {
                Some(ipv4)
            } else {
                None
            }
        }))
    }

    fn get_interface_capabilities(&self, iface: &str) -> Result<InterfaceCapabilities> {
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;

            if self.is_wireless(iface) {
                // Query wireless capabilities from rustyjack_wireless and convert
                let wireless_caps = rustyjack_wireless::query_interface_capabilities(iface)
                    .context(format!("Failed to query capabilities for {}", iface))?;

                // Convert tx_in_monitor capability
                let tx_cap = match wireless_caps.tx_in_monitor {
                    rustyjack_wireless::nl80211_queries::TxInMonitorCapability::Supported => {
                        TxInMonitorCapability::Supported
                    }
                    rustyjack_wireless::nl80211_queries::TxInMonitorCapability::NotSupported => {
                        TxInMonitorCapability::NotSupported
                    }
                    rustyjack_wireless::nl80211_queries::TxInMonitorCapability::Unknown => {
                        TxInMonitorCapability::Unknown
                    }
                };

                Ok(InterfaceCapabilities {
                    name: wireless_caps.name,
                    is_wireless: wireless_caps.is_wireless,
                    is_physical: wireless_caps.is_physical,
                    supports_monitor: wireless_caps.supports_monitor,
                    supports_ap: wireless_caps.supports_ap,
                    supports_injection: wireless_caps.supports_injection,
                    supports_5ghz: wireless_caps.supports_5ghz,
                    supports_2ghz: wireless_caps.supports_2ghz,
                    mac_address: wireless_caps.mac_address,
                    driver: wireless_caps.driver,
                    chipset: wireless_caps.chipset,
                    tx_in_monitor: tx_cap,
                    tx_in_monitor_reason: wireless_caps.tx_in_monitor_reason,
                })
            } else {
                // For wired interfaces, return basic capabilities
                use std::fs;
                let mut caps = InterfaceCapabilities {
                    name: iface.to_string(),
                    is_wireless: false,
                    is_physical: true,
                    supports_monitor: false,
                    supports_ap: false,
                    supports_injection: false,
                    supports_5ghz: false,
                    supports_2ghz: false,
                    mac_address: None,
                    driver: None,
                    chipset: None,
                    tx_in_monitor: TxInMonitorCapability::NotSupported,
                    tx_in_monitor_reason: "Wired interface - TX-in-monitor not applicable"
                        .to_string(),
                };

                // Get MAC address
                let mac_path = format!("/sys/class/net/{}/address", iface);
                if let Ok(mac_str) = fs::read_to_string(&mac_path) {
                    caps.mac_address = Some(mac_str.trim().to_string());
                }

                // Check if physical
                let device_path = format!("/sys/class/net/{}/device", iface);
                caps.is_physical = std::path::Path::new(&device_path).exists();

                // Read driver
                let uevent_path = format!("/sys/class/net/{}/device/uevent", iface);
                if let Ok(contents) = fs::read_to_string(&uevent_path) {
                    for line in contents.lines() {
                        if let Some(driver_line) = line.strip_prefix("DRIVER=") {
                            caps.driver = Some(driver_line.to_string());
                        }
                    }
                }

                Ok(caps)
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("Interface capabilities only supported on Linux")
        }
    }

    fn admin_is_up(&self, interface: &str) -> Result<bool> {
        use std::fs;
        let flags_path = format!("/sys/class/net/{}/flags", interface);
        let raw = fs::read_to_string(&flags_path)
            .map_err(|e| anyhow::anyhow!("Failed to read flags for {}: {}", interface, e))?;
        let trimmed = raw.trim().trim_start_matches("0x");
        let flags = u32::from_str_radix(trimmed, 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse flags for {}: {}", interface, e))?;
        Ok((flags & libc::IFF_UP as u32) != 0)
    }

    fn has_carrier(&self, interface: &str) -> Result<Option<bool>> {
        use std::fs;
        let carrier_path = format!("/sys/class/net/{}/carrier", interface);
        match fs::read_to_string(&carrier_path) {
            Ok(contents) => {
                let val = contents.trim();
                match val {
                    "1" => Ok(Some(true)),
                    "0" => Ok(Some(false)),
                    _ => Ok(None),
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to read carrier for {}: {}",
                        interface,
                        e
                    ))
                }
            }
        }
    }

    fn is_rfkill_blocked(&self, interface: &str) -> Result<bool> {
        use crate::netlink_helpers::{rfkill_find_index, rfkill_is_blocked};

        match rfkill_find_index(interface)? {
            Some(idx) => rfkill_is_blocked(idx),
            None => Err(anyhow!(
                "rfkill device not found for interface {}",
                interface
            )),
        }
    }

    fn is_rfkill_hard_blocked(&self, interface: &str) -> Result<bool> {
        use crate::netlink_helpers::{rfkill_find_index, rfkill_is_hard_blocked};

        match rfkill_find_index(interface)? {
            Some(idx) => rfkill_is_hard_blocked(idx),
            None => Err(anyhow!(
                "rfkill device not found for interface {}",
                interface
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    pub struct MockNetOps {
        interfaces: Arc<Mutex<Vec<InterfaceSummary>>>,
        routes: Arc<Mutex<Vec<RouteEntry>>>,
        up_interfaces: Arc<Mutex<Vec<String>>>,
        down_interfaces: Arc<Mutex<Vec<String>>>,
        dhcp_results: Arc<Mutex<HashMap<String, Result<DhcpLease>>>>,
        admin_state: Arc<Mutex<HashMap<String, bool>>>,
        carrier_state: Arc<Mutex<HashMap<String, bool>>>,
        flushed: Arc<Mutex<Vec<String>>>,
    }

    impl MockNetOps {
        pub fn new() -> Self {
            Self {
                interfaces: Arc::new(Mutex::new(Vec::new())),
                routes: Arc::new(Mutex::new(Vec::new())),
                up_interfaces: Arc::new(Mutex::new(Vec::new())),
                down_interfaces: Arc::new(Mutex::new(Vec::new())),
                dhcp_results: Arc::new(Mutex::new(HashMap::new())),
                admin_state: Arc::new(Mutex::new(HashMap::new())),
                carrier_state: Arc::new(Mutex::new(HashMap::new())),
                flushed: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn add_interface(&self, name: &str, is_wireless: bool, oper_state: &str) {
            let mut interfaces = self.interfaces.lock().unwrap();
            interfaces.push(InterfaceSummary {
                name: name.to_string(),
                kind: if is_wireless { "wireless" } else { "wired" }.to_string(),
                oper_state: oper_state.to_string(),
                ip: None,
                is_wireless,
                admin_up: oper_state == "up",
                carrier: None,
                capabilities: None,
            });
            self.admin_state
                .lock()
                .unwrap()
                .insert(name.to_string(), oper_state == "up");
            // Default carrier true for wired, false for wireless to allow explicit control
            self.carrier_state
                .lock()
                .unwrap()
                .insert(name.to_string(), !is_wireless);
        }

        pub fn set_dhcp_result(&self, iface: &str, result: Result<DhcpLease>) {
            let mut results = self.dhcp_results.lock().unwrap();
            results.insert(iface.to_string(), result);
        }

        pub fn set_carrier_state(&self, iface: &str, carrier: bool) {
            self.carrier_state
                .lock()
                .unwrap()
                .insert(iface.to_string(), carrier);
        }

        pub fn was_brought_up(&self, iface: &str) -> bool {
            self.up_interfaces
                .lock()
                .unwrap()
                .contains(&iface.to_string())
        }

        pub fn was_brought_down(&self, iface: &str) -> bool {
            self.down_interfaces
                .lock()
                .unwrap()
                .contains(&iface.to_string())
        }

        pub fn get_routes(&self) -> Vec<RouteEntry> {
            self.routes.lock().unwrap().clone()
        }

        pub fn flushed_interfaces(&self) -> Vec<String> {
            self.flushed.lock().unwrap().clone()
        }
    }

    impl NetOps for MockNetOps {
        fn list_interfaces(&self) -> Result<Vec<InterfaceSummary>> {
            Ok(self.interfaces.lock().unwrap().clone())
        }

        fn bring_up(&self, interface: &str) -> Result<()> {
            self.up_interfaces
                .lock()
                .unwrap()
                .push(interface.to_string());
            self.admin_state
                .lock()
                .unwrap()
                .insert(interface.to_string(), true);
            Ok(())
        }

        fn bring_down(&self, interface: &str) -> Result<()> {
            self.down_interfaces
                .lock()
                .unwrap()
                .push(interface.to_string());
            self.admin_state
                .lock()
                .unwrap()
                .insert(interface.to_string(), false);
            Ok(())
        }

        fn set_rfkill_block(&self, _interface: &str, _blocked: bool) -> Result<()> {
            Ok(())
        }

        fn is_wireless(&self, interface: &str) -> bool {
            self.interfaces
                .lock()
                .unwrap()
                .iter()
                .find(|i| i.name == interface)
                .map(|i| i.is_wireless)
                .unwrap_or(false)
        }

        fn interface_exists(&self, interface: &str) -> bool {
            self.interfaces
                .lock()
                .unwrap()
                .iter()
                .any(|i| i.name == interface)
        }

        fn add_default_route(&self, iface: &str, gateway: Ipv4Addr, metric: u32) -> Result<()> {
            let mut routes = self.routes.lock().unwrap();
            routes.push(RouteEntry {
                interface: iface.to_string(),
                gateway,
                metric,
                destination: None,
            });
            Ok(())
        }

        fn delete_default_route(&self, iface: &str) -> Result<()> {
            let mut routes = self.routes.lock().unwrap();
            routes.retain(|r| r.interface != iface || r.destination.is_some());
            Ok(())
        }

        fn list_routes(&self) -> Result<Vec<RouteEntry>> {
            Ok(self.routes.lock().unwrap().clone())
        }

        fn acquire_dhcp(&self, iface: &str, _timeout: Duration) -> Result<DhcpLease> {
            let results = self.dhcp_results.lock().unwrap();
            results.get(iface).cloned().unwrap_or_else(|| {
                Ok(DhcpLease {
                    ip: Ipv4Addr::new(192, 168, 1, 100),
                    prefix_len: 24,
                    gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                    dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                })
            })
        }

        fn release_dhcp(&self, _iface: &str) -> Result<()> {
            Ok(())
        }

        fn get_ipv4_address(&self, _iface: &str) -> Result<Option<Ipv4Addr>> {
            Ok(Some(Ipv4Addr::new(192, 168, 1, 100)))
        }

        fn get_interface_capabilities(&self, iface: &str) -> Result<InterfaceCapabilities> {
            Ok(InterfaceCapabilities {
                name: iface.to_string(),
                is_wireless: self.is_wireless(iface),
                is_physical: true,
                supports_monitor: false,
                supports_ap: false,
                supports_injection: false,
                supports_5ghz: false,
                supports_2ghz: false,
                mac_address: Some("00:11:22:33:44:55".to_string()),
                driver: Some("mock_driver".to_string()),
                chipset: Some("Mock Chipset".to_string()),
                tx_in_monitor: TxInMonitorCapability::Unknown,
                tx_in_monitor_reason: "Mock interface".to_string(),
            })
        }

        fn flush_addresses(&self, interface: &str) -> Result<()> {
            self.flushed.lock().unwrap().push(interface.to_string());
            Ok(())
        }

        fn admin_is_up(&self, interface: &str) -> Result<bool> {
            Ok(*self
                .admin_state
                .lock()
                .unwrap()
                .get(interface)
                .unwrap_or(&false))
        }

        fn has_carrier(&self, interface: &str) -> Result<Option<bool>> {
            Ok(self.carrier_state.lock().unwrap().get(interface).copied())
        }

        fn is_rfkill_blocked(&self, _interface: &str) -> Result<bool> {
            Ok(false) // Mock: never blocked
        }

        fn is_rfkill_hard_blocked(&self, _interface: &str) -> Result<bool> {
            Ok(false) // Mock: never hard blocked
        }
    }

    #[test]
    fn test_mock_netops_basic() {
        let mock = MockNetOps::new();
        mock.add_interface("eth0", false, "up");

        let interfaces = mock.list_interfaces().unwrap();
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "eth0");
        assert!(!interfaces[0].is_wireless);
    }

    #[test]
    fn test_mock_netops_bring_up() {
        let mock = MockNetOps::new();
        mock.add_interface("eth0", false, "up");

        mock.bring_up("eth0").unwrap();
        assert!(mock.was_brought_up("eth0"));
    }

    #[test]
    fn test_mock_netops_routes() {
        let mock = MockNetOps::new();

        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        mock.add_default_route("eth0", gateway, 100).unwrap();

        let routes = mock.list_routes().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].interface, "eth0");
        assert_eq!(routes[0].gateway, gateway);
        assert_eq!(routes[0].metric, 100);
    }

    #[test]
    fn test_mock_netops_dhcp() {
        let mock = MockNetOps::new();

        let lease = mock.acquire_dhcp("eth0", Duration::from_secs(1)).unwrap();
        assert_eq!(lease.ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(lease.prefix_len, 24);
        assert_eq!(lease.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }
}
