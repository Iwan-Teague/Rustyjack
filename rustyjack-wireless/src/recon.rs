//! Post-connection network reconnaissance
//!
//! This module provides network discovery and monitoring features that require
//! an active network connection (WiFi or Ethernet).

use crate::error::{Result, WirelessError};
use crate::nl80211::get_ifindex;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::unix::io::RawFd;
use std::ptr;
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

const MDNS_MULTICAST: &str = "224.0.0.251:5353";

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
    let network: Ipv4Net = subnet.parse().map_err(|e| {
        WirelessError::System(format!("Invalid subnet {}: {}", subnet, e))
    })?;

    let timeout = Duration::from_secs(1);
    if let Err(err) = rustyjack_ethernet::discover_hosts(network, timeout) {
        tracing::warn!("ICMP sweep failed on {}: {}", subnet, err);
    }

    if let Err(err) = run_arp_discovery(interface, network, timeout) {
        tracing::warn!("ARP sweep failed on {} ({}): {}", interface, subnet, err);
    }

    Ok(())
}

fn run_arp_discovery(
    interface: &str,
    network: Ipv4Net,
    timeout: Duration,
) -> Result<()> {
    use tokio::runtime::Handle;

    let run = |handle: &Handle| {
        handle.block_on(async {
            rustyjack_ethernet::discover_hosts_arp(interface, network, None, timeout)
                .await
                .map_err(|e| WirelessError::System(format!("ARP discovery failed: {}", e)))
        })
        .map(|_| ())
    };

    match Handle::try_current() {
        Ok(handle) => run(&handle),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
            .block_on(async {
                rustyjack_ethernet::discover_hosts_arp(interface, network, None, timeout)
                    .await
                    .map_err(|e| WirelessError::System(format!("ARP discovery failed: {}", e)))
            })
            .map(|_| ()),
    }
}

fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    let sockaddr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    };

    let mut host = [0u8; libc::NI_MAXHOST as usize];
    let res = unsafe {
        libc::getnameinfo(
            &sockaddr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
            host.as_mut_ptr() as *mut i8,
            host.len() as u32,
            ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };

    if res != 0 {
        return None;
    }

    let name = unsafe { CStr::from_ptr(host.as_ptr() as *const libc::c_char) }
        .to_str()
        .ok()?;
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
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
pub fn discover_mdns_devices(duration_secs: u64) -> Result<Vec<MdnsDevice>> {
    let mut devices = Vec::new();
    let mut seen_devices = HashSet::new();
    let timeout = Duration::from_secs(duration_secs.max(1));

    let mut results = query_mdns(timeout)?;
    results.retain(|_, names| !names.is_empty());

    for (ip, names) in results {
        let name = names.first().cloned().unwrap_or_else(|| ip.to_string());
        let key = format!("{}:{}", name, ip);
        if seen_devices.insert(key) {
            devices.push(MdnsDevice {
                name,
                ip,
                services: names,
                txt_records: HashMap::new(),
            });
        }
    }

    Ok(devices)
}

fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    let id: u16 = rand::random();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // flags
    packet.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT

    for label in name.split('.') {
        let bytes = label.as_bytes();
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.push(0); // terminator
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&0x0001u16.to_be_bytes()); // class IN
    packet
}

fn decode_dns_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut pos = *offset;
    let mut depth = 0;

    loop {
        if depth > 10 || pos >= data.len() {
            return None;
        }
        let len = data.get(pos).copied()? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as u16) << 8) | data[pos + 1] as u16;
            pos += 2;
            if !jumped {
                *offset = pos;
            }
            pos = ptr as usize;
            jumped = true;
            depth += 1;
            continue;
        }
        let start = pos + 1;
        let end = start + len;
        if end > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[start..end]).ok()?.to_string();
        labels.push(label);
        pos = end;
    }
    if !jumped {
        *offset = pos;
    }
    Some(labels.join("."))
}

fn parse_dns_records(data: &[u8]) -> Vec<String> {
    if data.len() < 12 {
        return Vec::new();
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let mut offset = 12usize;

    for _ in 0..qdcount {
        if decode_dns_name(data, &mut offset).is_none() {
            return Vec::new();
        }
        if offset + 4 > data.len() {
            return Vec::new();
        }
        offset += 4;
    }

    let mut names = Vec::new();
    for _ in 0..ancount {
        let _ = decode_dns_name(data, &mut offset);
        if offset + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlen = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > data.len() {
            break;
        }
        match rtype {
            1 => {
                if rdlen == 4 {
                    let ip = Ipv4Addr::new(
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    );
                    names.push(ip.to_string());
                }
            }
            5 | 12 | 33 => {
                let mut rptr = offset;
                if let Some(name) = decode_dns_name(data, &mut rptr) {
                    names.push(name);
                }
            }
            16 => {
                if let Ok(txt) = std::str::from_utf8(&data[offset..offset + rdlen]) {
                    names.push(txt.to_string());
                }
            }
            _ => {}
        }
        offset += rdlen;
    }
    names
}

fn query_multicast_dns(
    multicast: &str,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<HashMap<Ipv4Addr, Vec<String>>> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| WirelessError::System(format!("binding UDP socket: {}", e)))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| WirelessError::System(format!("setting read timeout: {}", e)))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|e| WirelessError::System(format!("setting write timeout: {}", e)))?;
    socket
        .set_multicast_loop_v4(true)
        .map_err(|e| WirelessError::System(format!("enabling multicast loop: {}", e)))?;

    let packet = build_dns_query(name, qtype);
    let _ = socket
        .send_to(&packet, multicast)
        .map_err(|e| WirelessError::System(format!("sending mDNS query: {}", e)))?;

    let start = Instant::now();
    let mut results: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let mut buf = [0u8; 1500];
    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if n == 0 {
                    continue;
                }
                let names = parse_dns_records(&buf[..n]);
                if names.is_empty() {
                    continue;
                }
                if let Ok(src) = addr.ip().to_string().parse::<Ipv4Addr>() {
                    results.entry(src).or_default().extend(names);
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => {
                return Err(WirelessError::System(format!(
                    "reading mDNS response: {}",
                    e
                )))
            }
        }
    }
    Ok(results)
}

fn query_mdns(timeout: Duration) -> Result<HashMap<Ipv4Addr, Vec<String>>> {
    let mut results =
        query_multicast_dns(MDNS_MULTICAST, "_services._dns-sd._udp.local", 12, timeout)?;
    let extra = query_multicast_dns(MDNS_MULTICAST, "local", 255, timeout)?;
    for (k, v) in extra {
        results.entry(k).or_default().extend(v);
    }
    Ok(results)
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

/// Capture DNS queries using a raw socket on the interface.
pub fn capture_dns_queries(interface: &str, duration: Duration) -> Result<Vec<DnsQuery>> {
    if !crate::check_privileges() {
        return Err(WirelessError::Permission(
            "Root privileges required for DNS capture".to_string(),
        ));
    }

    let fd = open_dns_capture_socket(interface)?;
    let start = Instant::now();
    let mut buf = vec![0u8; 2048];
    let mut queries = Vec::new();

    while start.elapsed() < duration {
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                continue;
            }
            unsafe {
                libc::close(fd);
            }
            return Err(WirelessError::Socket(format!(
                "DNS capture recv failed: {}",
                err
            )));
        }

        let packet = &buf[..n as usize];
        if let Some(query) = parse_dns_packet(packet) {
            queries.push(query);
        }
    }

    unsafe {
        libc::close(fd);
    }

    Ok(queries)
}

fn open_dns_capture_socket(interface: &str) -> Result<RawFd> {
    let ifindex = get_ifindex(interface)?;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if fd < 0 {
        return Err(WirelessError::Socket(format!(
            "Failed to create capture socket: {}",
            io::Error::last_os_error()
        )));
    }

    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = ifindex;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();

    let bind_result = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };

    if bind_result < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(WirelessError::Socket(format!(
            "Failed to bind capture socket: {}",
            io::Error::last_os_error()
        )));
    }

    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as u32,
        );
    }

    Ok(fd)
}

fn parse_dns_packet(packet: &[u8]) -> Option<DnsQuery> {
    let (ethertype, mut offset) = parse_ethertype(packet)?;
    if ethertype != 0x0800 {
        return None;
    }

    if packet.len() < offset + 20 {
        return None;
    }

    let version_ihl = packet[offset];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if packet.len() < offset + ihl + 8 {
        return None;
    }

    let protocol = packet[offset + 9];
    if protocol != 17 {
        return None;
    }

    let source_ip = Ipv4Addr::new(
        packet[offset + 12],
        packet[offset + 13],
        packet[offset + 14],
        packet[offset + 15],
    );

    offset += ihl;
    let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    if dst_port != 53 {
        return None;
    }

    let dns_offset = offset + 8;
    if packet.len() < dns_offset + 12 {
        return None;
    }

    let flags = u16::from_be_bytes([packet[dns_offset + 2], packet[dns_offset + 3]]);
    if (flags & 0x8000) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[dns_offset + 4], packet[dns_offset + 5]]);
    if qdcount == 0 {
        return None;
    }

    let mut qname_offset = dns_offset + 12;
    let domain = decode_dns_name(packet, &mut qname_offset)?;
    if qname_offset + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[qname_offset], packet[qname_offset + 1]]);
    let query_type = match qtype {
        1 => "A".to_string(),
        28 => "AAAA".to_string(),
        12 => "PTR".to_string(),
        other => format!("TYPE{}", other),
    };

    Some(DnsQuery {
        timestamp: Instant::now(),
        domain,
        query_type,
        source_ip,
    })
}

fn parse_ethertype(packet: &[u8]) -> Option<(u16, usize)> {
    if packet.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    let mut offset = 14;

    if ethertype == 0x8100 {
        if packet.len() < 18 {
            return None;
        }
        ethertype = u16::from_be_bytes([packet[16], packet[17]]);
        offset = 18;
    }

    Some((ethertype, offset))
}
