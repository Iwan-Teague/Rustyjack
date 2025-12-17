#[allow(dead_code)]
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

const BOOTREPLY: u8 = 2;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPDECLINE: u8 = 4;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const DHCPRELEASE: u8 = 7;
const DHCPINFORM: u8 = 8;

const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS_SERVER: u8 = 6;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_ID: u8 = 54;
const OPTION_RENEWAL_TIME: u8 = 58;
const OPTION_REBINDING_TIME: u8 = 59;
const OPTION_END: u8 = 255;

#[derive(Error, Debug)]
pub enum DhcpError {
    #[error("Failed to bind DHCP server on interface {interface}: {source}")]
    BindFailed {
        interface: String,
        source: std::io::Error,
    },

    #[error("Failed to set SO_BINDTODEVICE on {interface}: {source}")]
    BindToDeviceFailed {
        interface: String,
        source: std::io::Error,
    },

    #[error("Failed to set SO_BROADCAST on socket: {0}")]
    BroadcastFailed(std::io::Error),

    #[error("Failed to receive DHCP packet: {0}")]
    ReceiveFailed(std::io::Error),

    #[error("Failed to send DHCP packet: {0}")]
    SendFailed(std::io::Error),

    #[error("Invalid DHCP packet: {reason}")]
    InvalidPacket { reason: String },

    #[error("DHCP address pool exhausted for range {start} - {end}")]
    PoolExhausted { start: Ipv4Addr, end: Ipv4Addr },

    #[error("Invalid IP address configuration: {0}")]
    InvalidConfig(String),

    #[error("Server not running on interface {0}")]
    NotRunning(String),
}

pub type Result<T> = std::result::Result<T, DhcpError>;

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub lease_start: u64,
    pub lease_duration: u32,
}

impl DhcpLease {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.lease_start + self.lease_duration as u64
    }

    pub fn remaining_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires = self.lease_start + self.lease_duration as u64;
        expires.saturating_sub(now)
    }
}

#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time_secs: u32,
    pub log_packets: bool,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            server_ip: Ipv4Addr::new(10, 20, 30, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            range_start: Ipv4Addr::new(10, 20, 30, 10),
            range_end: Ipv4Addr::new(10, 20, 30, 200),
            router: Some(Ipv4Addr::new(10, 20, 30, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            lease_time_secs: 43200, // 12 hours
            log_packets: false,
        }
    }
}

#[derive(Debug)]
struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    options: Vec<DhcpOption>,
}

#[derive(Debug, Clone)]
enum DhcpOption {
    MessageType(u8),
    ServerIdentifier(Ipv4Addr),
    RequestedIpAddress(Ipv4Addr),
    LeaseTime(u32),
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DnsServer(Vec<Ipv4Addr>),
    RenewalTime(u32),
    RebindingTime(u32),
    Hostname(String),
    Unknown(u8, Vec<u8>),
}

pub struct DhcpServer {
    config: DhcpConfig,
    socket: Option<UdpSocket>,
    leases: Arc<Mutex<HashMap<[u8; 6], DhcpLease>>>,
    running: Arc<Mutex<bool>>,
}

impl DhcpServer {
    pub fn new(config: DhcpConfig) -> Result<Self> {
        if config.interface.is_empty() {
            return Err(DhcpError::InvalidConfig(
                "Interface name cannot be empty".to_string(),
            ));
        }

        if config.range_start >= config.range_end {
            return Err(DhcpError::InvalidConfig(format!(
                "Invalid IP range: {} >= {}",
                config.range_start, config.range_end
            )));
        }

        Ok(Self {
            config,
            socket: None,
            leases: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(false)),
        })
    }

    pub fn start(&mut self) -> Result<()> {
        // Bind to all addresses but pin to the target interface to ensure we only
        // serve requests arriving on that link.
        let bind_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DHCP_SERVER_PORT);

        let socket = UdpSocket::bind(bind_addr).map_err(|e| DhcpError::BindFailed {
            interface: self.config.interface.clone(),
            source: e,
        })?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            let iface_bytes = self.config.interface.as_bytes();

            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_bytes.as_ptr() as *const libc::c_void,
                    iface_bytes.len() as libc::socklen_t,
                );

                if ret < 0 {
                    return Err(DhcpError::BindToDeviceFailed {
                        interface: self.config.interface.clone(),
                        source: std::io::Error::last_os_error(),
                    });
                }

                let broadcast: libc::c_int = 1;
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BROADCAST,
                    &broadcast as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );

                if ret < 0 {
                    return Err(DhcpError::BroadcastFailed(std::io::Error::last_os_error()));
                }
            }
        }

        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|e| DhcpError::BindFailed {
                interface: self.config.interface.clone(),
                source: e,
            })?;

        self.socket = Some(socket);
        *self.running.lock().unwrap() = true;

        Ok(())
    }

    /// Expose a handle to the running flag so callers can stop the background loop.
    pub fn running_handle(&self) -> Arc<Mutex<bool>> {
        Arc::clone(&self.running)
    }

    /// Request server shutdown.
    pub fn stop(&mut self) {
        *self.running.lock().unwrap() = false;
        self.socket = None;
    }

    pub fn serve(&mut self) -> Result<()> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| DhcpError::NotRunning(self.config.interface.clone()))?;

        let mut buf = vec![0u8; 1500];

        while *self.running.lock().unwrap() {
            match socket.recv_from(&mut buf) {
                Ok((size, src)) => {
                    if let Err(e) = self.handle_packet(&buf[..size], src) {
                        if self.config.log_packets {
                            eprintln!("[DHCP] Error handling packet: {}", e);
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(DhcpError::ReceiveFailed(e));
                }
            }
        }

        Ok(())
    }

    pub fn get_leases(&self) -> Vec<DhcpLease> {
        let leases = self.leases.lock().unwrap();
        leases
            .values()
            .filter(|l| !l.is_expired())
            .cloned()
            .collect()
    }

    pub fn release_lease(&self, mac: &[u8; 6]) {
        let mut leases = self.leases.lock().unwrap();
        leases.remove(mac);
    }

    fn handle_packet(&self, data: &[u8], _src: SocketAddr) -> Result<()> {
        let packet = Self::parse_packet(data)?;

        let msg_type = packet
            .options
            .iter()
            .find_map(|opt| {
                if let DhcpOption::MessageType(t) = opt {
                    Some(*t)
                } else {
                    None
                }
            })
            .ok_or_else(|| DhcpError::InvalidPacket {
                reason: "Missing message type option".to_string(),
            })?;

        if self.config.log_packets {
            let mac = &packet.chaddr[..6];
            eprintln!(
                "[DHCP] Received {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                Self::message_type_name(msg_type),
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
        }

        match msg_type {
            DHCPDISCOVER => self.handle_discover(&packet),
            DHCPREQUEST => self.handle_request(&packet),
            DHCPRELEASE => self.handle_release(&packet),
            DHCPDECLINE => self.handle_decline(&packet),
            DHCPINFORM => Ok(()),
            _ => Ok(()),
        }
    }

    fn handle_discover(&self, packet: &DhcpPacket) -> Result<()> {
        let client_mac: [u8; 6] = packet.chaddr[..6].try_into().unwrap();

        let offered_ip = self.get_or_allocate_ip(&client_mac)?;

        let response = self.build_offer(packet, offered_ip);
        self.send_packet(&response)?;

        if self.config.log_packets {
            eprintln!(
                "[DHCP] Sent OFFER: {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                offered_ip,
                client_mac[0],
                client_mac[1],
                client_mac[2],
                client_mac[3],
                client_mac[4],
                client_mac[5]
            );
        }

        Ok(())
    }

    fn handle_request(&self, packet: &DhcpPacket) -> Result<()> {
        let client_mac: [u8; 6] = packet.chaddr[..6].try_into().unwrap();

        let requested_ip = packet.options.iter().find_map(|opt| {
            if let DhcpOption::RequestedIpAddress(ip) = opt {
                Some(*ip)
            } else {
                None
            }
        });

        let hostname = packet.options.iter().find_map(|opt| {
            if let DhcpOption::Hostname(name) = opt {
                Some(name.clone())
            } else {
                None
            }
        });

        let ip_to_ack = if let Some(req_ip) = requested_ip {
            if self.is_ip_available(&client_mac, req_ip) {
                req_ip
            } else {
                return self.send_nak(packet);
            }
        } else {
            self.get_or_allocate_ip(&client_mac)?
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let lease = DhcpLease {
            mac: client_mac,
            ip: ip_to_ack,
            hostname,
            lease_start: now,
            lease_duration: self.config.lease_time_secs,
        };

        self.leases.lock().unwrap().insert(client_mac, lease);

        let response = self.build_ack(packet, ip_to_ack);
        self.send_packet(&response)?;

        if self.config.log_packets {
            eprintln!(
                "[DHCP] Sent ACK: {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                ip_to_ack,
                client_mac[0],
                client_mac[1],
                client_mac[2],
                client_mac[3],
                client_mac[4],
                client_mac[5]
            );
        }

        Ok(())
    }

    fn handle_release(&self, packet: &DhcpPacket) -> Result<()> {
        let client_mac: [u8; 6] = packet.chaddr[..6].try_into().unwrap();
        self.release_lease(&client_mac);

        if self.config.log_packets {
            eprintln!(
                "[DHCP] Released lease for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                client_mac[0],
                client_mac[1],
                client_mac[2],
                client_mac[3],
                client_mac[4],
                client_mac[5]
            );
        }

        Ok(())
    }

    fn handle_decline(&self, packet: &DhcpPacket) -> Result<()> {
        let client_mac: [u8; 6] = packet.chaddr[..6].try_into().unwrap();
        self.release_lease(&client_mac);

        if self.config.log_packets {
            eprintln!(
                "[DHCP] Client declined IP: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                client_mac[0],
                client_mac[1],
                client_mac[2],
                client_mac[3],
                client_mac[4],
                client_mac[5]
            );
        }

        Ok(())
    }

    fn get_or_allocate_ip(&self, mac: &[u8; 6]) -> Result<Ipv4Addr> {
        let leases = self.leases.lock().unwrap();

        if let Some(lease) = leases.get(mac) {
            if !lease.is_expired() {
                return Ok(lease.ip);
            }
        }

        let start = u32::from(self.config.range_start);
        let end = u32::from(self.config.range_end);

        let allocated_ips: std::collections::HashSet<_> = leases
            .values()
            .filter(|l| !l.is_expired())
            .map(|l| l.ip)
            .collect();

        for ip_int in start..=end {
            let ip = Ipv4Addr::from(ip_int);
            if allocated_ips.contains(&ip) {
                continue;
            }
            if ip == self.config.server_ip {
                continue;
            }
            if self.config.router == Some(ip) {
                continue;
            }
            return Ok(ip);
        }

        Err(DhcpError::PoolExhausted {
            start: self.config.range_start,
            end: self.config.range_end,
        })
    }

    fn is_ip_available(&self, requesting_mac: &[u8; 6], ip: Ipv4Addr) -> bool {
        if ip < self.config.range_start || ip > self.config.range_end {
            return false;
        }

        if ip == self.config.server_ip {
            return false;
        }

        if let Some(router) = self.config.router {
            if ip == router {
                return false;
            }
        }

        let leases = self.leases.lock().unwrap();

        if let Some(lease) = leases.values().find(|l| l.ip == ip && !l.is_expired()) {
            lease.mac == *requesting_mac
        } else {
            true
        }
    }

    fn build_offer(&self, request: &DhcpPacket, offered_ip: Ipv4Addr) -> DhcpPacket {
        let mut options = vec![
            DhcpOption::MessageType(DHCPOFFER),
            DhcpOption::ServerIdentifier(self.config.server_ip),
            DhcpOption::LeaseTime(self.config.lease_time_secs),
            DhcpOption::SubnetMask(self.config.subnet_mask),
        ];

        if let Some(router) = self.config.router {
            options.push(DhcpOption::Router(vec![router]));
        }

        if !self.config.dns_servers.is_empty() {
            options.push(DhcpOption::DnsServer(self.config.dns_servers.clone()));
        }

        let renewal_time = self.config.lease_time_secs / 2;
        let rebinding_time = (self.config.lease_time_secs * 7) / 8;
        options.push(DhcpOption::RenewalTime(renewal_time));
        options.push(DhcpOption::RebindingTime(rebinding_time));

        DhcpPacket {
            op: BOOTREPLY,
            htype: request.htype,
            hlen: request.hlen,
            hops: 0,
            xid: request.xid,
            secs: 0,
            flags: request.flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: offered_ip,
            siaddr: self.config.server_ip,
            giaddr: request.giaddr,
            chaddr: request.chaddr,
            sname: [0; 64],
            file: [0; 128],
            options,
        }
    }

    fn build_ack(&self, request: &DhcpPacket, acked_ip: Ipv4Addr) -> DhcpPacket {
        let mut response = self.build_offer(request, acked_ip);
        response.options[0] = DhcpOption::MessageType(DHCPACK);
        response
    }

    fn send_nak(&self, request: &DhcpPacket) -> Result<()> {
        let response = DhcpPacket {
            op: BOOTREPLY,
            htype: request.htype,
            hlen: request.hlen,
            hops: 0,
            xid: request.xid,
            secs: 0,
            flags: request.flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: self.config.server_ip,
            giaddr: request.giaddr,
            chaddr: request.chaddr,
            sname: [0; 64],
            file: [0; 128],
            options: vec![
                DhcpOption::MessageType(DHCPNAK),
                DhcpOption::ServerIdentifier(self.config.server_ip),
            ],
        };

        self.send_packet(&response)?;

        if self.config.log_packets {
            let mac = &request.chaddr[..6];
            eprintln!(
                "[DHCP] Sent NAK to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
        }

        Ok(())
    }

    fn send_packet(&self, packet: &DhcpPacket) -> Result<()> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| DhcpError::NotRunning(self.config.interface.clone()))?;

        let data = Self::serialize_packet(packet);

        let dest_addr = if packet.flags & 0x8000 != 0 || packet.giaddr != Ipv4Addr::UNSPECIFIED {
            SocketAddr::new(Ipv4Addr::BROADCAST.into(), DHCP_CLIENT_PORT)
        } else if packet.ciaddr != Ipv4Addr::UNSPECIFIED {
            SocketAddr::new(packet.ciaddr.into(), DHCP_CLIENT_PORT)
        } else {
            SocketAddr::new(Ipv4Addr::BROADCAST.into(), DHCP_CLIENT_PORT)
        };

        socket
            .send_to(&data, dest_addr)
            .map_err(DhcpError::SendFailed)?;

        Ok(())
    }

    fn parse_packet(data: &[u8]) -> Result<DhcpPacket> {
        if data.len() < 240 {
            return Err(DhcpError::InvalidPacket {
                reason: format!("Packet too short: {} bytes", data.len()),
            });
        }

        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);
        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&data[28..44]);

        let mut sname = [0u8; 64];
        sname.copy_from_slice(&data[44..108]);

        let mut file = [0u8; 128];
        file.copy_from_slice(&data[108..236]);

        if data.len() < 240 || &data[236..240] != DHCP_MAGIC_COOKIE {
            return Err(DhcpError::InvalidPacket {
                reason: "Invalid magic cookie".to_string(),
            });
        }

        let options = Self::parse_options(&data[240..])?;

        Ok(DhcpPacket {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }

    fn parse_options(data: &[u8]) -> Result<Vec<DhcpOption>> {
        let mut options = Vec::new();
        let mut i = 0;

        while i < data.len() {
            let code = data[i];

            if code == OPTION_END {
                break;
            }

            if code == 0 {
                i += 1;
                continue;
            }

            if i + 1 >= data.len() {
                break;
            }

            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }

            let opt_data = &data[i + 2..i + 2 + len];

            let option = match code {
                OPTION_MESSAGE_TYPE if len == 1 => DhcpOption::MessageType(opt_data[0]),
                OPTION_SERVER_ID if len == 4 => DhcpOption::ServerIdentifier(Ipv4Addr::new(
                    opt_data[0],
                    opt_data[1],
                    opt_data[2],
                    opt_data[3],
                )),
                OPTION_REQUESTED_IP if len == 4 => DhcpOption::RequestedIpAddress(Ipv4Addr::new(
                    opt_data[0],
                    opt_data[1],
                    opt_data[2],
                    opt_data[3],
                )),
                OPTION_LEASE_TIME if len == 4 => DhcpOption::LeaseTime(u32::from_be_bytes([
                    opt_data[0],
                    opt_data[1],
                    opt_data[2],
                    opt_data[3],
                ])),
                OPTION_SUBNET_MASK if len == 4 => DhcpOption::SubnetMask(Ipv4Addr::new(
                    opt_data[0],
                    opt_data[1],
                    opt_data[2],
                    opt_data[3],
                )),
                OPTION_ROUTER => {
                    let mut routers = Vec::new();
                    for chunk in opt_data.chunks_exact(4) {
                        routers.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                    }
                    DhcpOption::Router(routers)
                }
                OPTION_DNS_SERVER => {
                    let mut dns = Vec::new();
                    for chunk in opt_data.chunks_exact(4) {
                        dns.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                    }
                    DhcpOption::DnsServer(dns)
                }
                OPTION_RENEWAL_TIME if len == 4 => DhcpOption::RenewalTime(u32::from_be_bytes([
                    opt_data[0],
                    opt_data[1],
                    opt_data[2],
                    opt_data[3],
                ])),
                OPTION_REBINDING_TIME if len == 4 => {
                    DhcpOption::RebindingTime(u32::from_be_bytes([
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ]))
                }
                12 => {
                    if let Ok(hostname) = String::from_utf8(opt_data.to_vec()) {
                        DhcpOption::Hostname(hostname)
                    } else {
                        DhcpOption::Unknown(code, opt_data.to_vec())
                    }
                }
                _ => DhcpOption::Unknown(code, opt_data.to_vec()),
            };

            options.push(option);
            i += 2 + len;
        }

        Ok(options)
    }

    fn serialize_packet(packet: &DhcpPacket) -> Vec<u8> {
        let mut data = Vec::with_capacity(576);

        data.push(packet.op);
        data.push(packet.htype);
        data.push(packet.hlen);
        data.push(packet.hops);
        data.extend_from_slice(&packet.xid.to_be_bytes());
        data.extend_from_slice(&packet.secs.to_be_bytes());
        data.extend_from_slice(&packet.flags.to_be_bytes());
        data.extend_from_slice(&packet.ciaddr.octets());
        data.extend_from_slice(&packet.yiaddr.octets());
        data.extend_from_slice(&packet.siaddr.octets());
        data.extend_from_slice(&packet.giaddr.octets());
        data.extend_from_slice(&packet.chaddr);
        data.extend_from_slice(&packet.sname);
        data.extend_from_slice(&packet.file);
        data.extend_from_slice(&DHCP_MAGIC_COOKIE);

        for option in &packet.options {
            Self::serialize_option(&mut data, option);
        }

        data.push(OPTION_END);

        while data.len() < 300 {
            data.push(0);
        }

        data
    }

    fn serialize_option(data: &mut Vec<u8>, option: &DhcpOption) {
        match option {
            DhcpOption::MessageType(t) => {
                data.push(OPTION_MESSAGE_TYPE);
                data.push(1);
                data.push(*t);
            }
            DhcpOption::ServerIdentifier(ip) => {
                data.push(OPTION_SERVER_ID);
                data.push(4);
                data.extend_from_slice(&ip.octets());
            }
            DhcpOption::RequestedIpAddress(ip) => {
                data.push(OPTION_REQUESTED_IP);
                data.push(4);
                data.extend_from_slice(&ip.octets());
            }
            DhcpOption::LeaseTime(time) => {
                data.push(OPTION_LEASE_TIME);
                data.push(4);
                data.extend_from_slice(&time.to_be_bytes());
            }
            DhcpOption::SubnetMask(mask) => {
                data.push(OPTION_SUBNET_MASK);
                data.push(4);
                data.extend_from_slice(&mask.octets());
            }
            DhcpOption::Router(routers) => {
                data.push(OPTION_ROUTER);
                data.push((routers.len() * 4) as u8);
                for router in routers {
                    data.extend_from_slice(&router.octets());
                }
            }
            DhcpOption::DnsServer(servers) => {
                data.push(OPTION_DNS_SERVER);
                data.push((servers.len() * 4) as u8);
                for server in servers {
                    data.extend_from_slice(&server.octets());
                }
            }
            DhcpOption::RenewalTime(time) => {
                data.push(OPTION_RENEWAL_TIME);
                data.push(4);
                data.extend_from_slice(&time.to_be_bytes());
            }
            DhcpOption::RebindingTime(time) => {
                data.push(OPTION_REBINDING_TIME);
                data.push(4);
                data.extend_from_slice(&time.to_be_bytes());
            }
            DhcpOption::Hostname(name) => {
                data.push(12);
                data.push(name.len() as u8);
                data.extend_from_slice(name.as_bytes());
            }
            DhcpOption::Unknown(code, bytes) => {
                data.push(*code);
                data.push(bytes.len() as u8);
                data.extend_from_slice(bytes);
            }
        }
    }

    fn message_type_name(msg_type: u8) -> &'static str {
        match msg_type {
            DHCPDISCOVER => "DISCOVER",
            DHCPOFFER => "OFFER",
            DHCPREQUEST => "REQUEST",
            DHCPDECLINE => "DECLINE",
            DHCPACK => "ACK",
            DHCPNAK => "NAK",
            DHCPRELEASE => "RELEASE",
            DHCPINFORM => "INFORM",
            _ => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_config_default() {
        let config = DhcpConfig::default();
        assert_eq!(config.server_ip, Ipv4Addr::new(10, 20, 30, 1));
        assert_eq!(config.lease_time_secs, 43200);
    }

    #[test]
    fn test_lease_expiration() {
        let lease = DhcpLease {
            mac: [0; 6],
            ip: Ipv4Addr::new(10, 20, 30, 10),
            hostname: None,
            lease_start: 0,
            lease_duration: 1,
        };
        assert!(lease.is_expired());
    }

    #[test]
    fn test_invalid_range() {
        let config = DhcpConfig {
            interface: "eth0".to_string(),
            range_start: Ipv4Addr::new(10, 20, 30, 200),
            range_end: Ipv4Addr::new(10, 20, 30, 10),
            ..Default::default()
        };
        assert!(DhcpServer::new(config).is_err());
    }

    #[test]
    fn test_empty_interface() {
        let config = DhcpConfig {
            interface: String::new(),
            ..Default::default()
        };
        assert!(DhcpServer::new(config).is_err());
    }
}
