use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd};

use anyhow::{anyhow, Context, Result};
use ipnet::Ipv4Net;
use socket2::{Domain, Protocol, Socket, Type};

const DEFAULT_ARP_PPS: u32 = 50;
const DEFAULT_BANNER_READ: Duration = Duration::from_millis(750);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const MDNS_MULTICAST: &str = "224.0.0.251:5353";
const LLMNR_MULTICAST: &str = "224.0.0.252:5355";
const WSD_MULTICAST: &str = "239.255.255.250:3702";

/// Discovery transport used for a host hit.
#[derive(Debug, Clone, Copy)]
pub enum DiscoveryMethod {
    Icmp,
    Arp,
}

/// Host hit with optional metadata.
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub ttl: Option<u8>,
    pub method: DiscoveryMethod,
}

/// Result of a LAN discovery sweep.
#[derive(Debug, Clone)]
pub struct LanDiscoveryResult {
    pub network: Ipv4Net,
    pub hosts: Vec<Ipv4Addr>,
    pub details: Vec<DiscoveredHost>,
}

/// Result of a TCP port scan.
#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub target: Ipv4Addr,
    pub open_ports: Vec<u16>,
    pub banners: Vec<PortBanner>,
}

/// Service banner result.
#[derive(Debug, Clone)]
pub struct PortBanner {
    pub port: u16,
    pub probe: String,
    pub banner: String,
}

/// Service/hostname information learned via multicast discovery.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub protocol: String,
    pub detail: String,
}

/// Device summary combining discovery, banners, and passive service data.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub services: Vec<ServiceInfo>,
    pub os_hint: Option<String>,
    pub ttl: Option<u8>,
    pub open_ports: Vec<u16>,
    pub banners: Vec<PortBanner>,
}

/// Crude OS guess from an observed TTL value.
#[must_use]
pub fn guess_os_from_ttl(ttl: Option<u8>) -> Option<&'static str> {
    match ttl {
        Some(t) if t >= 240 => Some("network appliance/router"),
        Some(t) if t >= 128 => Some("windows"),
        Some(t) if t >= 64 => Some("linux/unix"),
        Some(t) if t >= 32 => Some("embedded/older stack"),
        _ => None,
    }
}

fn guess_os_from_ports(ttl_guess: Option<&str>, ports: &[u16]) -> Option<String> {
    if ports.contains(&445) || ports.contains(&3389) || ports.contains(&139) {
        return Some("windows (smb/rdp)".to_string());
    }
    if ports.contains(&22) && (ports.contains(&80) || ports.contains(&443)) {
        return Some("linux/unix (ssh+web)".to_string());
    }
    if let Some(ttl) = ttl_guess {
        return Some(ttl.to_string());
    }
    None
}

/// Perform a simple ICMP echo sweep across the given CIDR.
/// Requires root (RAW socket).
pub fn discover_hosts(network: Ipv4Net, timeout: Duration) -> Result<LanDiscoveryResult> {
    let timeout = timeout.max(Duration::from_millis(10));
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .context("creating ICMP socket (requires root/CAP_NET_RAW)")?;
    socket
        .set_nonblocking(true)
        .context("setting ICMP socket nonblocking")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("setting write timeout")?;

    // Track probes so we only report replies we originated.
    let mut inflight: HashMap<u16, Ipv4Addr> = HashMap::new();
    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    let mut hosts = Vec::new();
    let mut details = Vec::new();
    let mut seq: u16 = 1;
    let ident: u16 = 0xBEEF;

    for ip in network.hosts() {
        // Skip network/broadcast are excluded by hosts()
        let packet = build_icmp_echo(ident, seq);
        let addr = SocketAddr::new(ip.into(), 0);
        let sock_addr = socket2::SockAddr::from(addr);
        if let Err(err) = socket.send_to(&packet, &sock_addr) {
            // Permission errors after socket creation are fatal; other per-host errors are skipped.
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(err).context("sending ICMP probe (permission denied)");
            }
            continue;
        }
        inflight.insert(seq, ip);
        seq = seq.wrapping_add(1);
    }

    if inflight.is_empty() {
        return Ok(LanDiscoveryResult {
            network,
            hosts: Vec::new(),
            details: Vec::new(),
        });
    }

    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if n < 28 {
                    continue;
                }
                // Safety: recv_from initialized the first `n` bytes.
                let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                let ttl = bytes.get(8).copied();
                let icmp = &bytes[20..];
                // Only accept echo replies that match our identifier.
                if icmp[0] != 0 || icmp[1] != 0 {
                    continue;
                }
                let reply_ident = u16::from_be_bytes([icmp[4], icmp[5]]);
                if reply_ident != ident {
                    continue;
                }
                let reply_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                if let Some(sock) = from.as_socket() {
                    if let SocketAddr::V4(from_v4) = sock {
                        if let Some(expected_ip) = inflight.get(&reply_seq) {
                            if from_v4.ip() == expected_ip && seen.insert(*expected_ip) {
                                hosts.push(*expected_ip);
                                details.push(DiscoveredHost {
                                    ip: *expected_ip,
                                    ttl,
                                    method: DiscoveryMethod::Icmp,
                                });
                            }
                        }
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err).context("receiving ICMP replies"),
        }
    }

    Ok(LanDiscoveryResult {
        network,
        hosts,
        details,
    })
}

/// Perform a TCP SYN-like check using connect (no external binaries).
/// This uses TCP connect with a timeout; it is slower than raw SYN but is dependency-free.
pub fn quick_port_scan(
    target: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
) -> Result<PortScanResult> {
    let mut open = Vec::new();
    let mut banners = Vec::new();
    for port in ports {
        let addr = SocketAddr::new(target.into(), *port);
        if let Ok(stream) = TcpStream::connect_timeout(&addr, timeout) {
            stream.set_read_timeout(Some(DEFAULT_BANNER_READ)).ok();
            stream.set_write_timeout(Some(DEFAULT_CONNECT_TIMEOUT)).ok();
            open.push(*port);
            if let Some(info) = grab_banner(stream, *port) {
                banners.push(info);
            }
        }
    }

    Ok(PortScanResult {
        target,
        open_ports: open,
        banners,
    })
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let v = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(v);
    }
    if let Some(&b) = chunks.remainder().get(0) {
        sum = sum.wrapping_add((b as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_icmp_echo(ident: u16, seq: u16) -> [u8; 8] {
    let mut packet = [0u8; 8];
    packet[0] = 8; // type: echo request
    packet[1] = 0; // code
    packet[4..6].copy_from_slice(&ident.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    let csum = checksum(&packet);
    packet[2..4].copy_from_slice(&csum.to_be_bytes());
    packet
}

/// Convenience to parse CIDR and run discovery.
pub fn discover_cidr(cidr: &str, timeout: Duration) -> Result<LanDiscoveryResult> {
    let net: Ipv4Net = cidr.parse().context("parsing CIDR")?;
    discover_hosts(net, timeout)
}

/// Perform an ARP sweep across a CIDR on a specific interface.
/// This complements ICMP by finding hosts even when ICMP is blocked.
#[cfg(target_os = "linux")]
pub async fn discover_hosts_arp(
    interface: &str,
    network: Ipv4Net,
    rate_limit_pps: Option<u32>,
    timeout: Duration,
) -> Result<LanDiscoveryResult> {
    let local_mac = read_iface_mac(interface)?;
    let local_ip = read_iface_ipv4(interface).await?;
    let ifindex = unsafe { libc::if_nametoindex(CString::new(interface)?.as_ptr()) };
    if ifindex == 0 {
        return Err(anyhow!("failed to resolve ifindex for {}", interface));
    }

    let sock = unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("creating ARP raw socket");
        }
        Socket::from_raw_fd(fd)
    };

    // Bind to interface
    let mut sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ARP as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0; 8],
    };
    sll.sll_addr[..6].copy_from_slice(&local_mac);
    let bind_res = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bind_res != 0 {
        return Err(io::Error::last_os_error()).context("binding ARP socket to interface");
    }

    let delay =
        Duration::from_micros(1_000_000 / rate_limit_pps.unwrap_or(DEFAULT_ARP_PPS).max(1) as u64);
    let targets: Vec<Ipv4Addr> = network.hosts().filter(|ip| *ip != local_ip).collect();
    let mut inflight: HashSet<Ipv4Addr> = HashSet::new();

    for ip in &targets {
        let frame = build_arp_request(&local_mac, &local_ip, ip);
        let sent = unsafe {
            libc::send(
                sock.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        if sent < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(err).context("sending ARP probe (permission denied)");
            }
        } else {
            inflight.insert(*ip);
        }
        std::thread::sleep(delay);
    }

    let mut details = Vec::new();
    if inflight.is_empty() {
        return Ok(LanDiscoveryResult {
            network,
            hosts: Vec::new(),
            details,
        });
    }

    sock.set_read_timeout(Some(timeout))?;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) => {
                if n < 42 {
                    continue;
                }
                // Safety: recv initialized the first `n` bytes.
                let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                if bytes[12] != 0x08 || bytes[13] != 0x06 {
                    continue;
                }
                // ARP reply opcode 2 at bytes 20-21 of Ethernet payload
                let payload = &bytes[14..];
                if payload[6] != 0x00 || payload[7] != 0x02 {
                    continue;
                }
                let sender_ip = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);
                if inflight.contains(&sender_ip) {
                    details.push(DiscoveredHost {
                        ip: sender_ip,
                        ttl: None,
                        method: DiscoveryMethod::Arp,
                    });
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => return Err(err).context("receiving ARP replies"),
        }
    }

    let mut unique = HashSet::new();
    let hosts: Vec<Ipv4Addr> = details
        .iter()
        .filter_map(|d| {
            if unique.insert(d.ip) {
                Some(d.ip)
            } else {
                None
            }
        })
        .collect();

    Ok(LanDiscoveryResult {
        network,
        hosts,
        details,
    })
}

/// Non-Linux stub for ARP discovery.
#[cfg(not(target_os = "linux"))]
pub fn discover_hosts_arp(
    _interface: &str,
    network: Ipv4Net,
    _rate_limit_pps: Option<u32>,
    _timeout: Duration,
) -> Result<LanDiscoveryResult> {
    Err(anyhow!(
        "ARP discovery is only supported on Linux; target network {} not scanned",
        network
    ))
}

#[cfg(target_os = "linux")]
fn build_arp_request(src_mac: &[u8; 6], src_ip: &Ipv4Addr, target_ip: &Ipv4Addr) -> Vec<u8> {
    let mut frame = vec![0u8; 42];
    // Ethernet header
    frame[0..6].fill(0xFF); // dest broadcast
    frame[6..12].copy_from_slice(src_mac);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP
                                                             // ARP payload
    frame[14..16].copy_from_slice(&0x0001u16.to_be_bytes()); // HTYPE Ethernet
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // PTYPE IPv4
    frame[18] = 6; // HLEN
    frame[19] = 4; // PLEN
    frame[20..22].copy_from_slice(&0x0001u16.to_be_bytes()); // OPCODE request
    frame[22..28].copy_from_slice(src_mac); // Sender MAC
    frame[28..32].copy_from_slice(&src_ip.octets()); // Sender IP
    frame[32..38].fill(0); // Target MAC unknown
    frame[38..42].copy_from_slice(&target_ip.octets()); // Target IP
    frame
}

#[cfg(target_os = "linux")]
fn read_iface_mac(interface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", interface);
    let content = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path))?;
    let parts: Vec<&str> = content.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!("invalid MAC address format in {}", path));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] =
            u8::from_str_radix(part, 16).with_context(|| format!("parsing MAC octet {}", part))?;
    }
    Ok(mac)
}

#[cfg(target_os = "linux")]
async fn read_iface_ipv4(interface: &str) -> Result<Ipv4Addr> {
    let mgr = rustyjack_netlink::InterfaceManager::new()
        .with_context(|| format!("initializing netlink for {}", interface))?;
    
    let addrs = mgr.get_ipv4_addresses(interface).await
        .with_context(|| format!("reading IPv4 addresses for {}", interface))?;
    
    if let Some(addr) = addrs.first() {
        match addr.address {
            std::net::IpAddr::V4(v4) => Ok(v4),
            _ => Err(anyhow!("No IPv4 address found on {}", interface))
        }
    } else {
        Err(anyhow!("No IPv4 address found on {}", interface))
    }
}

fn grab_banner(mut stream: TcpStream, port: u16) -> Option<PortBanner> {
    let mut probe = String::new();
    let mut banner = String::new();

    match port {
        80 | 8080 | 8000 | 8443 | 443 => {
            probe = "http-head".to_string();
            let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n");
        }
        _ => {}
    }

    let mut buf = [0u8; 512];
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            banner = String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
        }
    }

    if banner.is_empty() {
        return None;
    }

    Some(PortBanner {
        port,
        probe,
        banner,
    })
}

// --- Service discovery helpers ---

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
        // compression pointer
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

    // Skip questions
    for _ in 0..qdcount {
        if decode_dns_name(data, &mut offset).is_none() {
            return Vec::new();
        }
        if offset + 4 > data.len() {
            return Vec::new();
        }
        offset += 4; // type + class
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
    let socket = UdpSocket::bind("0.0.0.0:0").context("binding UDP socket for multicast DNS")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("setting read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("setting write timeout")?;
    socket
        .set_multicast_loop_v4(true)
        .context("enabling multicast loop")?;

    let packet = build_dns_query(name, qtype);
    let _ = socket.send_to(&packet, multicast)?;

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
                if let Some(src) = addr.ip().to_string().parse::<Ipv4Addr>().ok() {
                    results.entry(src).or_default().extend(names);
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => break,
        }
    }
    Ok(results)
}

fn query_mdns(timeout: Duration) -> Result<HashMap<Ipv4Addr, Vec<String>>> {
    // Ask for the list of services and general local names
    let mut results =
        query_multicast_dns(MDNS_MULTICAST, "_services._dns-sd._udp.local", 12, timeout)?;
    let extra = query_multicast_dns(MDNS_MULTICAST, "local", 255, timeout)?;
    for (k, v) in extra {
        results.entry(k).or_default().extend(v);
    }
    Ok(results)
}

fn query_llmnr(timeout: Duration) -> Result<HashMap<Ipv4Addr, Vec<String>>> {
    // Query for WORKGROUP to elicit LLMNR responses
    query_multicast_dns(LLMNR_MULTICAST, "WORKGROUP", 1, timeout)
}

fn encode_netbios_name(name: &str) -> Vec<u8> {
    let mut padded = name.to_uppercase();
    if padded.len() > 15 {
        padded.truncate(15);
    }
    while padded.len() < 15 {
        padded.push(' ');
    }
    padded.push('\0');
    let mut encoded = Vec::with_capacity(32);
    for b in padded.bytes() {
        let high = ((b >> 4) & 0x0F) + b'A';
        let low = (b & 0x0F) + b'A';
        encoded.push(high);
        encoded.push(low);
    }
    encoded
}

fn query_netbios(timeout: Duration) -> Result<HashMap<Ipv4Addr, Vec<String>>> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("binding UDP socket for NetBIOS")?;
    socket.set_broadcast(true).ok();
    socket.set_read_timeout(Some(timeout)).ok();

    let mut packet = Vec::new();
    let id: u16 = rand::random();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0010u16.to_be_bytes()); // flags: recursion desired
    packet.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT

    let encoded = encode_netbios_name("*");
    packet.push(32); // label length
    packet.extend_from_slice(&encoded);
    packet.push(0); // terminator
    packet.extend_from_slice(&0x0020u16.to_be_bytes()); // NB
    packet.extend_from_slice(&0x0001u16.to_be_bytes()); // IN

    let _ = socket.send_to(&packet, "255.255.255.255:137")?;

    let start = Instant::now();
    let mut results: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let mut buf = [0u8; 1500];
    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if n < 12 {
                    continue;
                }
                // Look for NBSTAT RDATA name table
                if let Some(src) = addr.ip().to_string().parse::<Ipv4Addr>().ok() {
                    if let Some(names) = parse_netbios_names(&buf[..n]) {
                        results.entry(src).or_default().extend(names);
                    }
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => break,
        }
    }
    Ok(results)
}

fn parse_netbios_names(data: &[u8]) -> Option<Vec<String>> {
    // Find NBSTAT answer (type 0x0021)
    let mut offset = 12usize;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    for _ in 0..qdcount {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset += 1 + 4; // null + type/class
    }

    for _ in 0..ancount {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset += 1;
        if offset + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlen = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > data.len() {
            return None;
        }
        if rtype == 0x0021 && rdlen > 0 {
            let count = data[offset] as usize;
            let mut names = Vec::new();
            let mut pos = offset + 1;
            for _ in 0..count {
                if pos + 18 > offset + rdlen {
                    break;
                }
                let raw = &data[pos..pos + 15];
                if let Ok(s) = std::str::from_utf8(raw) {
                    names.push(s.trim().to_string());
                }
                pos += 18;
            }
            return Some(names);
        }
        offset += rdlen;
    }
    None
}

fn query_ws_discovery(timeout: Duration) -> Result<HashMap<Ipv4Addr, Vec<String>>> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("binding UDP socket for WS-Discovery")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("setting WS-Discovery timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("setting WS-Discovery write timeout")?;
    socket
        .set_multicast_loop_v4(true)
        .context("enabling multicast loop")?;

    let uuid = format!("{}", uuid::Uuid::new_v4());
    let probe = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <e:Header>
    <w:MessageID>uuid:{uuid}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"#
    );

    let _ = socket.send_to(probe.as_bytes(), WSD_MULTICAST)?;

    let start = Instant::now();
    let mut results: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let mut buf = [0u8; 4096];
    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let payload = String::from_utf8_lossy(&buf[..n]);
                let mut types = Vec::new();
                for line in payload.lines() {
                    if line.contains("<d:Types") || line.contains("<Types") {
                        let clean = line
                            .replace("<d:Types>", "")
                            .replace("</d:Types>", "")
                            .replace("<Types>", "")
                            .replace("</Types>", "")
                            .trim()
                            .to_string();
                        if !clean.is_empty() {
                            types.push(clean);
                        }
                    }
                }
                if let Some(src) = addr.ip().to_string().parse::<Ipv4Addr>().ok() {
                    if !types.is_empty() {
                        results.entry(src).or_default().extend(types);
                    }
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => break,
        }
    }
    Ok(results)
}

/// Build device inventory from discovery + port scans + multicast service probes.
pub fn build_device_inventory(
    discovery: &LanDiscoveryResult,
    ports: &[u16],
    timeout: Duration,
) -> Result<Vec<DeviceInfo>> {
    let mdns = query_mdns(timeout).unwrap_or_default();
    let llmnr = query_llmnr(timeout).unwrap_or_default();
    let netbios = query_netbios(timeout).unwrap_or_default();
    let wsd = query_ws_discovery(timeout).unwrap_or_default();

    let mut devices = Vec::new();
    for host in &discovery.hosts {
        let scan = quick_port_scan(*host, ports, timeout).unwrap_or_else(|_| PortScanResult {
            target: *host,
            open_ports: Vec::new(),
            banners: Vec::new(),
        });

        let ttl_raw = discovery
            .details
            .iter()
            .find(|d| d.ip == *host)
            .and_then(|d| d.ttl);
        let ttl_guess = ttl_raw.and_then(|t| guess_os_from_ttl(Some(t)));
        let os_hint = guess_os_from_ports(ttl_guess, &scan.open_ports);

        let mut services = Vec::new();
        if let Some(names) = mdns.get(host) {
            for n in names {
                services.push(ServiceInfo {
                    protocol: "mDNS".to_string(),
                    detail: n.clone(),
                });
            }
        }
        if let Some(names) = llmnr.get(host) {
            for n in names {
                services.push(ServiceInfo {
                    protocol: "LLMNR".to_string(),
                    detail: n.clone(),
                });
            }
        }
        if let Some(names) = netbios.get(host) {
            for n in names {
                services.push(ServiceInfo {
                    protocol: "NetBIOS".to_string(),
                    detail: n.clone(),
                });
            }
        }
        if let Some(types) = wsd.get(host) {
            for t in types {
                services.push(ServiceInfo {
                    protocol: "WS-Discovery".to_string(),
                    detail: t.clone(),
                });
            }
        }

        let hostname = services
            .iter()
            .find_map(|s| {
                if s.detail.contains(".local") {
                    Some(s.detail.clone())
                } else {
                    None
                }
            })
            .or_else(|| services.get(0).map(|s| s.detail.clone()));

        devices.push(DeviceInfo {
            ip: *host,
            hostname,
            services,
            os_hint,
            ttl: ttl_raw,
            open_ports: scan.open_ports.clone(),
            banners: scan.banners.clone(),
        });
    }

    Ok(devices)
}
