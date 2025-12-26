//! Post-connection network reconnaissance
//!
//! This module provides network discovery and monitoring features that require
//! an active network connection (WiFi or Ethernet).

use crate::error::{Result, WirelessError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub default_gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub dhcp_server: Option<Ipv4Addr>,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpDevice {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceServices {
    pub ip: Ipv4Addr,
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsDevice {
    pub name: String,
    pub ip: Ipv4Addr,
    pub services: Vec<String>,
    pub txt_records: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct TrafficStats {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct BandwidthSample {
    pub timestamp: Instant,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub timestamp: Instant,
    pub domain: String,
    pub query_type: String,
    pub source_ip: Ipv4Addr,
}

/// Discover network gateway, DNS servers, and DHCP server
pub fn discover_gateway(interface: &str) -> Result<GatewayInfo> {
    let default_gateway = get_default_gateway(interface)?;
    let dns_servers = get_dns_servers()?;
    let dhcp_server = get_dhcp_server(interface)?;

    Ok(GatewayInfo {
        default_gateway,
        dns_servers,
        dhcp_server,
        interface: interface.to_string(),
    })
}

fn netlink_routes() -> Result<Vec<rustyjack_netlink::RouteInfo>> {
    use tokio::runtime::Handle;

    let fetch = |handle: &Handle| {
        handle.block_on(async {
            rustyjack_netlink::list_routes()
                .await
                .map_err(|e| WirelessError::System(format!("Failed to list routes: {}", e)))
        })
    };

    match Handle::try_current() {
        Ok(handle) => fetch(&handle),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
            .block_on(async {
                rustyjack_netlink::list_routes()
                    .await
                    .map_err(|e| WirelessError::System(format!("Failed to list routes: {}", e)))
            }),
    }
}

fn netlink_ifindex(interface: &str) -> Result<u32> {
    use tokio::runtime::Handle;

    let fetch = |handle: &Handle| {
        handle.block_on(async {
            let mgr = rustyjack_netlink::InterfaceManager::new()
                .map_err(|e| WirelessError::System(format!("Failed to open netlink: {}", e)))?;
            mgr.get_interface_index(interface)
                .await
                .map_err(|e| {
                    WirelessError::System(format!("Failed to get ifindex for {}: {}", interface, e))
                })
        })
    };

    match Handle::try_current() {
        Ok(handle) => fetch(&handle),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
            .block_on(async {
                let mgr = rustyjack_netlink::InterfaceManager::new()
                    .map_err(|e| WirelessError::System(format!("Failed to open netlink: {}", e)))?;
                mgr.get_interface_index(interface)
                    .await
                    .map_err(|e| {
                        WirelessError::System(format!(
                            "Failed to get ifindex for {}: {}",
                            interface, e
                        ))
                    })
            }),
    }
}

fn netlink_ipv4_addrs(interface: &str) -> Result<Vec<rustyjack_netlink::AddressInfo>> {
    use tokio::runtime::Handle;

    let fetch = |handle: &Handle| {
        handle.block_on(async {
            let mgr = rustyjack_netlink::InterfaceManager::new()
                .map_err(|e| WirelessError::System(format!("Failed to open netlink: {}", e)))?;
            mgr.get_ipv4_addresses(interface)
                .await
                .map_err(|e| {
                    WirelessError::System(format!(
                        "Failed to read IPv4 addresses for {}: {}",
                        interface, e
                    ))
                })
        })
    };

    match Handle::try_current() {
        Ok(handle) => fetch(&handle),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
            .block_on(async {
                let mgr = rustyjack_netlink::InterfaceManager::new()
                    .map_err(|e| WirelessError::System(format!("Failed to open netlink: {}", e)))?;
                mgr.get_ipv4_addresses(interface)
                    .await
                    .map_err(|e| {
                        WirelessError::System(format!(
                            "Failed to read IPv4 addresses for {}: {}",
                            interface, e
                        ))
                    })
            }),
    }
}

fn get_default_gateway(interface: &str) -> Result<Option<Ipv4Addr>> {
    let ifindex = netlink_ifindex(interface)?;
    let routes = netlink_routes()?;

    let is_default = |route: &rustyjack_netlink::RouteInfo| {
        if route.prefix_len != 0 {
            return false;
        }
        match route.destination {
            None => true,
            Some(IpAddr::V4(v4)) => v4.octets() == [0, 0, 0, 0],
            _ => false,
        }
    };

    let gw = routes
        .iter()
        .find(|route| route.interface_index == Some(ifindex) && is_default(route))
        .and_then(|route| route.gateway)
        .and_then(|gw| match gw {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        });

    Ok(gw)
}

fn get_dns_servers() -> Result<Vec<IpAddr>> {
    let mut dns_servers = Vec::new();

    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            if line.trim().starts_with("nameserver") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[1].parse::<IpAddr>() {
                        dns_servers.push(ip);
                    }
                }
            }
        }
    }

    Ok(dns_servers)
}

fn get_dhcp_server(interface: &str) -> Result<Option<Ipv4Addr>> {
    let lease_paths = vec![
        format!("/var/lib/dhcp/dhclient.{}.leases", interface),
        format!("/var/lib/dhclient/dhclient-{}.leases", interface),
        format!("/var/lib/NetworkManager/dhclient-{}.lease", interface),
    ];

    for path in lease_paths {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            for line in contents.lines() {
                if line.trim().starts_with("option dhcp-server-identifier") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(ip_str) = parts.last() {
                        let ip_clean = ip_str.trim_end_matches(';');
                        if let Ok(ip) = ip_clean.parse::<Ipv4Addr>() {
                            return Ok(Some(ip));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Perform ARP scan of local subnet to discover devices
pub fn arp_scan(interface: &str) -> Result<Vec<ArpDevice>> {
    let subnet = get_interface_subnet(interface)?;
    let mut devices = Vec::new();

    if let Ok(contents) = std::fs::read_to_string("/proc/net/arp") {
        for (idx, line) in contents.lines().enumerate() {
            if idx == 0 {
                continue;
            }
            if let Some(device) = parse_arp_line(line, Some(interface)) {
                devices.push(device);
            }
        }
    }

    if devices.is_empty() {
        perform_active_arp_scan(&subnet, interface)?;
        std::thread::sleep(Duration::from_millis(500));

        if let Ok(contents) = std::fs::read_to_string("/proc/net/arp") {
            for (idx, line) in contents.lines().enumerate() {
                if idx == 0 {
                    continue;
                }
                if let Some(device) = parse_arp_line(line, Some(interface)) {
                    devices.push(device);
                }
            }
        }
    }

    Ok(devices)
}

fn get_interface_subnet(interface: &str) -> Result<String> {
    let addrs = netlink_ipv4_addrs(interface)?;
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.address {
            return Ok(format!("{}/{}", v4, addr.prefix_len));
        }
    }
    Err(WirelessError::System(format!(
        "No IPv4 subnet found on {}",
        interface
    )))
}

fn parse_arp_line(line: &str, interface: Option<&str>) -> Option<ArpDevice> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    if let Some(expected) = interface {
        if parts[5] != expected {
            return None;
        }
    }
    let ip = parts[0].parse::<Ipv4Addr>().ok()?;
    let mac = parts[3].to_string();
    if mac == "00:00:00:00:00:00" {
        return None;
    }

    let vendor = lookup_mac_vendor(&mac);

    Some(ArpDevice {
        ip,
        mac,
        hostname: resolve_hostname(ip),
        vendor,
    })
}

fn perform_active_arp_scan(subnet: &str, interface: &str) -> Result<()> {
    let _ = Command::new("arping")
        .args(["-c", "1", "-w", "1", "-I", interface, "-b", subnet])
        .output();

    let base = subnet.split('/').next().unwrap_or("192.168.1.0");
    let octets: Vec<&str> = base.split('.').collect();
    if octets.len() == 4 {
        let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
        for i in 1..255 {
            let target = format!("{}.{}", prefix, i);
            let _ = Command::new("ping")
                .args(["-c", "1", "-W", "1", &target])
                .output();
        }
    }

    Ok(())
}

fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    let output = Command::new("host").arg(ip.to_string()).output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("domain name pointer") {
        let parts: Vec<&str> = stdout.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|&p| p == "pointer") {
            return parts
                .get(idx + 1)
                .map(|s| s.trim_end_matches('.').to_string());
        }
    }

    None
}

fn lookup_mac_vendor(mac: &str) -> Option<String> {
    let oui = mac.split(':').take(3).collect::<Vec<_>>().join(":");
    let oui_upper = oui.to_uppercase();

    let vendor_map: HashMap<&str, &str> = [
        ("00:00:0C", "Cisco Systems"),
        ("00:0A:95", "Apple, Inc."),
        ("00:0C:29", "VMware, Inc."),
        ("00:0D:B9", "Netgear"),
        ("00:15:5D", "Microsoft Corporation"),
        ("00:16:CB", "Apple, Inc."),
        ("00:1C:B3", "Apple, Inc."),
        ("00:50:56", "VMware, Inc."),
        ("0C:D2:92", "Raspberry Pi Foundation"),
        ("20:C9:D0", "Amazon Technologies Inc."),
        ("28:CF:E9", "Apple, Inc."),
        ("3C:22:FB", "Apple, Inc."),
        ("50:DE:06", "Tp-Link Technologies Co."),
        ("54:26:96", "Apple, Inc."),
        ("68:05:CA", "Tp-Link Technologies Co."),
        ("78:11:DC", "Ubiquiti Networks Inc."),
        ("88:63:DF", "Amazon Technologies Inc."),
        ("A0:20:A6", "Netgear"),
        ("AC:BC:32", "Apple, Inc."),
        ("B8:27:EB", "Raspberry Pi Foundation"),
        ("C8:60:00", "Tp-Link Technologies Co."),
        ("DC:A6:32", "Raspberry Pi Foundation"),
        ("E0:B9:A5", "Tp-Link Technologies Co."),
        ("F0:18:98", "Apple, Inc."),
    ]
    .iter()
    .copied()
    .collect();

    vendor_map.get(oui_upper.as_str()).map(|v| v.to_string())
}

/// Scan common network services on discovered devices
pub fn scan_network_services(devices: &[ArpDevice]) -> Result<Vec<DeviceServices>> {
    let common_ports = vec![
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (3389, "RDP"),
        (8080, "HTTP-Alt"),
    ];

    let mut results = Vec::new();

    for device in devices {
        let mut services = Vec::new();

        for (port, service_name) in &common_ports {
            if is_port_open(device.ip, *port) {
                services.push(ServiceInfo {
                    port: *port,
                    service: service_name.to_string(),
                    state: "open".to_string(),
                });
            }
        }

        if !services.is_empty() {
            results.push(DeviceServices {
                ip: device.ip,
                services,
            });
        }
    }

    Ok(results)
}

fn is_port_open(ip: Ipv4Addr, port: u16) -> bool {
    use std::net::{SocketAddr, TcpStream};

    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

/// Discover mDNS/Bonjour devices on the network
pub fn discover_mdns_devices(_duration_secs: u64) -> Result<Vec<MdnsDevice>> {
    let mut devices = Vec::new();
    let mut seen_devices = HashSet::new();

    let output = Command::new("avahi-browse")
        .args(["-a", "-t", "-r", "-p"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Some(device) = parse_mdns_line(line) {
                let key = format!("{}:{}", device.name, device.ip);
                if !seen_devices.contains(&key) {
                    seen_devices.insert(key);
                    devices.push(device);
                }
            }
        }
    } else {
        return Err(WirelessError::System(
            "avahi-browse not found. Install with: apt install avahi-utils".to_string(),
        ));
    }

    Ok(devices)
}

fn parse_mdns_line(line: &str) -> Option<MdnsDevice> {
    let parts: Vec<&str> = line.split(';').collect();
    if parts.len() >= 9 && parts[0] == "=" {
        let name = parts[3].to_string();
        let service = parts[4].to_string();
        let ip_str = parts[7];

        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            return Some(MdnsDevice {
                name,
                ip,
                services: vec![service],
                txt_records: HashMap::new(),
            });
        }
    }

    None
}

/// Monitor bandwidth usage on an interface
pub fn get_traffic_stats(interface: &str) -> Result<TrafficStats> {
    let rx_bytes = read_sys_net_stat(interface, "rx_bytes")?;
    let tx_bytes = read_sys_net_stat(interface, "tx_bytes")?;
    let rx_packets = read_sys_net_stat(interface, "rx_packets")?;
    let tx_packets = read_sys_net_stat(interface, "tx_packets")?;

    Ok(TrafficStats {
        interface: interface.to_string(),
        rx_bytes,
        tx_bytes,
        rx_packets,
        tx_packets,
        timestamp: Instant::now(),
    })
}

fn read_sys_net_stat(interface: &str, stat: &str) -> Result<u64> {
    let path = format!("/sys/class/net/{}/statistics/{}", interface, stat);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| WirelessError::System(format!("Failed to read {}: {}", path, e)))?;

    contents
        .trim()
        .parse::<u64>()
        .map_err(|e| WirelessError::System(format!("Failed to parse stat: {}", e)))
}

/// Calculate bandwidth from two traffic samples
pub fn calculate_bandwidth(before: &TrafficStats, after: &TrafficStats) -> BandwidthSample {
    let elapsed = after
        .timestamp
        .duration_since(before.timestamp)
        .as_secs_f64();

    let rx_bytes_delta = after.rx_bytes.saturating_sub(before.rx_bytes);
    let tx_bytes_delta = after.tx_bytes.saturating_sub(before.tx_bytes);

    let rx_bps = (rx_bytes_delta as f64 * 8.0) / elapsed;
    let tx_bps = (tx_bytes_delta as f64 * 8.0) / elapsed;

    BandwidthSample {
        timestamp: after.timestamp,
        rx_bps,
        tx_bps,
    }
}

/// Capture DNS queries using tcpdump
pub fn start_dns_capture(interface: &str) -> Result<std::process::Child> {
    Command::new("tcpdump")
        .args(["-i", interface, "-n", "-l", "udp port 53"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| WirelessError::System(format!("Failed to start tcpdump: {}", e)))
}

/// Parse DNS query from tcpdump output line
pub fn parse_dns_query(line: &str) -> Option<DnsQuery> {
    if line.contains("A?") || line.contains("AAAA?") {
        let parts: Vec<&str> = line.split_whitespace().collect();

        let source_ip = parts
            .iter()
            .find(|p| p.contains('.') && !p.contains('>'))
            .and_then(|s| s.split('.').next())
            .and_then(|s| s.parse::<Ipv4Addr>().ok())?;

        let domain = parts
            .iter()
            .position(|&p| p == "A?" || p == "AAAA?")
            .and_then(|idx| parts.get(idx + 1))
            .map(|s| s.trim_end_matches('?').to_string())?;

        let query_type = if line.contains("A?") { "A" } else { "AAAA" };

        return Some(DnsQuery {
            timestamp: Instant::now(),
            domain,
            query_type: query_type.to_string(),
            source_ip,
        });
    }

    None
}
