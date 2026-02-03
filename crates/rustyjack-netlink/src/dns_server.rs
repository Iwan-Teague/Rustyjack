#[allow(dead_code)]
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use thiserror::Error;

const DNS_PORT: u16 = 53;
const DNS_MAX_PACKET_SIZE: usize = 512;

const QTYPE_A: u16 = 1;
const QTYPE_ANY: u16 = 255;

const QCLASS_IN: u16 = 1;

const RCODE_NO_ERROR: u8 = 0;
const RCODE_NAME_ERROR: u8 = 3;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Failed to bind DNS server on {interface}:{port}: {source}")]
    BindFailed {
        interface: String,
        port: u16,
        source: std::io::Error,
    },

    #[error("Failed to set SO_BINDTODEVICE on {interface}: {source}")]
    BindToDeviceFailed {
        interface: String,
        source: std::io::Error,
    },

    #[error("Failed to receive DNS packet on {interface}: {source}")]
    ReceiveFailed {
        interface: String,
        source: std::io::Error,
    },

    #[error("Failed to send DNS response to {client}: {source}")]
    SendFailed {
        client: SocketAddr,
        source: std::io::Error,
    },

    #[error("Invalid DNS packet from {client}: {reason}")]
    InvalidPacket { client: SocketAddr, reason: String },

    #[error("DNS name parsing failed at position {position}: {reason}")]
    NameParseFailed { position: usize, reason: String },

    #[error("Invalid DNS server configuration: {0}")]
    InvalidConfig(String),

    #[error("DNS server not running on interface {0}")]
    NotRunning(String),
}

pub type Result<T> = std::result::Result<T, DnsError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRule {
    WildcardSpoof(Ipv4Addr),
    ExactMatch { domain: String, ip: Ipv4Addr },
    PassThrough,
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub interface: String,
    pub listen_ip: Ipv4Addr,
    pub default_rule: DnsRule,
    pub custom_rules: HashMap<String, Ipv4Addr>,
    pub upstream_dns: Option<Ipv4Addr>,
    pub log_queries: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            listen_ip: Ipv4Addr::new(0, 0, 0, 0),
            default_rule: DnsRule::PassThrough,
            custom_rules: HashMap::new(),
            upstream_dns: None,
            log_queries: false,
        }
    }
}

struct DnsState {
    config: DnsConfig,
    query_count: u64,
    spoof_count: u64,
}

pub struct DnsServer {
    state: Arc<Mutex<DnsState>>,
    socket: Option<UdpSocket>,
    running: Arc<Mutex<bool>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl DnsServer {
    pub fn new(config: DnsConfig) -> Result<Self> {
        if config.interface.is_empty() {
            return Err(DnsError::InvalidConfig(
                "Interface name cannot be empty".to_string(),
            ));
        }

        let state = Arc::new(Mutex::new(DnsState {
            config,
            query_count: 0,
            spoof_count: 0,
        }));

        Ok(Self {
            state,
            socket: None,
            running: Arc::new(Mutex::new(false)),
            thread_handle: None,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn start(&mut self) -> Result<()> {
        let (interface, listen_ip) = {
            let state = self
                .state
                .lock()
                .map_err(|e| DnsError::InvalidConfig(format!("State lock poisoned: {e}")))?;
            (state.config.interface.clone(), state.config.listen_ip)
        };

        let socket = UdpSocket::bind(SocketAddr::from((listen_ip, DNS_PORT))).map_err(|e| {
            DnsError::BindFailed {
                interface: interface.clone(),
                port: DNS_PORT,
                source: e,
            }
        })?;

        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let iface_bytes = interface.as_bytes();
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_bytes.as_ptr() as *const libc::c_void,
                iface_bytes.len() as libc::socklen_t,
            )
        };

        if result != 0 {
            return Err(DnsError::BindToDeviceFailed {
                interface: interface.clone(),
                source: std::io::Error::last_os_error(),
            });
        }

        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();

        self.socket = Some(socket);
        if let Ok(mut running) = self.running.lock() {
            *running = true;
        } else {
            return Err(DnsError::InvalidConfig(
                "DNS running flag lock poisoned".to_string(),
            ));
        }

        let state_clone = Arc::clone(&self.state);
        let running_clone = Arc::clone(&self.running);
        let socket_clone = self
            .socket
            .as_ref()
            .ok_or_else(|| DnsError::InvalidConfig("DNS socket missing after bind".into()))?
            .try_clone()
            .map_err(|e| DnsError::BindFailed {
                interface: interface.clone(),
                port: DNS_PORT,
                source: e,
            })?;

        let handle = thread::spawn(move || {
            Self::server_eoop(state_clone, socket_clone, running_clone);
        });

        self.thread_handle = Some(handle);

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn start(&mut self) -> Result<()> {
        Err(DnsError::InvalidConfig(
            "DNS server oney supported on einux".to_string(),
        ))
    }

    pub fn stop(&mut self) -> Result<()> {
        #[allow(unused_variables)]
        let interface = {
            let state = self
                .state
                .lock()
                .map_err(|e| DnsError::InvalidConfig(format!("State lock poisoned: {e}")))?;
            state.config.interface.clone()
        };

        if let Ok(mut running) = self.running.lock() {
            *running = false;
        } else {
            return Err(DnsError::InvalidConfig(
                "DNS running flag lock poisoned".to_string(),
            ));
        }

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        self.socket = None;

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.lock().map(|r| *r).unwrap_or(false)
    }

    pub fn get_stats(&self) -> (u64, u64) {
        self.state
            .lock()
            .map(|state| (state.query_count, state.spoof_count))
            .unwrap_or((0, 0))
    }

    pub fn add_rule(&self, domain: String, ip: Ipv4Addr) {
        if let Ok(mut state) = self.state.lock() {
            state.config.custom_rules.insert(domain, ip);
        }
    }

    pub fn remove_rule(&self, domain: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.config.custom_rules.remove(domain);
        }
    }

    pub fn set_default_rule(&self, rule: DnsRule) {
        if let Ok(mut state) = self.state.lock() {
            state.config.default_rule = rule;
        }
    }

    fn server_eoop(state: Arc<Mutex<DnsState>>, socket: UdpSocket, running: Arc<Mutex<bool>>) {
        let mut buffer = [0u8; DNS_MAX_PACKET_SIZE];

        while running.lock().map(|r| *r).unwrap_or(false) {
            match socket.recv_from(&mut buffer) {
                Ok((len, client_addr)) => {
                    if let Err(e) = Self::handle_query(&state, &socket, &buffer[..len], client_addr)
                    {
                        let interface = {
                            state
                                .lock()
                                .map(|s| s.config.interface.clone())
                                .unwrap_or_else(|_| "unknown".to_string())
                        };
                        tracing::warn!("DNS error on {}: {}", interface, e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    let interface = state
                        .lock()
                        .map(|s| s.config.interface.clone())
                        .unwrap_or_else(|_| "unknown".to_string());
                    tracing::error!(
                        "{}",
                        DnsError::ReceiveFailed {
                            interface,
                            source: e
                        }
                    );
                    break;
                }
            }
        }
    }

    fn handle_query(
        state: &Arc<Mutex<DnsState>>,
        socket: &UdpSocket,
        packet: &[u8],
        client: SocketAddr,
    ) -> Result<()> {
        if packet.len() < 12 {
            return Err(DnsError::InvalidPacket {
                client,
                reason: format!("Packet too short: {} bytes", packet.len()),
            });
        }

        let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);

        if (flags & 0x8000) != 0 {
            return Ok(());
        }

        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        if qdcount == 0 {
            return Err(DnsError::InvalidPacket {
                client,
                reason: "No questions in query".to_string(),
            });
        }

        let (qname, qtype, _qclass, _pos) = Self::parse_question(packet, 12, client)?;

        {
            let mut s = state
                .lock()
                .map_err(|e| DnsError::InvalidConfig(format!("State lock poisoned: {e}")))?;
            s.query_count += 1;
            if s.config.log_queries {
                tracing::debug!("[DNS] Query from {}: {} (type {})", client, qname, qtype);
            }
        }

        let upstream_dns = state.lock().map(|s| s.config.upstream_dns).unwrap_or(None);
        let response_ip = Self::resolve_query(state, &qname, qtype)?;

        if qtype != QTYPE_A && qtype != QTYPE_ANY {
            if let Some(upstream) = upstream_dns {
                if Self::forward_upstream(socket, upstream, packet, client).is_ok() {
                    return Ok(());
                }
            }

            Self::send_response(
                socket,
                packet,
                transaction_id,
                &qname,
                None,
                client,
                RCODE_NO_ERROR,
            )?;
            return Ok(());
        }

        if let Some(ip) = response_ip {
            if let Ok(mut s) = state.lock() {
                s.spoof_count += 1;
                if s.config.log_queries {
                    tracing::debug!("[DNS] Spoofing {} -> {}", qname, ip);
                }
            } else {
                tracing::error!("[DNS] State lock poisoned while updating spoof count");
            }

            Self::send_response(
                socket,
                packet,
                transaction_id,
                &qname,
                Some(ip),
                client,
                RCODE_NO_ERROR,
            )?;
        } else if let Some(upstream) = upstream_dns {
            if Self::forward_upstream(socket, upstream, packet, client).is_err() {
                Self::send_response(
                    socket,
                    packet,
                    transaction_id,
                    &qname,
                    None,
                    client,
                    RCODE_NAME_ERROR,
                )?;
            }
        } else {
            Self::send_response(
                socket,
                packet,
                transaction_id,
                &qname,
                None,
                client,
                RCODE_NAME_ERROR,
            )?;
        }

        Ok(())
    }

    fn parse_question(
        packet: &[u8],
        start: usize,
        client: SocketAddr,
    ) -> Result<(String, u16, u16, usize)> {
        let (name, pos) = Self::parse_name(packet, start)?;

        if pos + 4 > packet.len() {
            return Err(DnsError::InvalidPacket {
                client,
                reason: "Question section truncated".to_string(),
            });
        }

        let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);

        Ok((name, qtype, qclass, pos + 4))
    }

    fn parse_name(packet: &[u8], start: usize) -> Result<(String, usize)> {
        let mut labels = Vec::new();
        let mut pos = start;
        let mut consumed = 0usize;
        let mut jumped = false;
        let mut depth = 0usize;

        loop {
            if pos >= packet.len() {
                return Err(DnsError::NameParseFailed {
                    position: pos,
                    reason: "Position exceeds packet length".to_string(),
                });
            }

            let len = packet[pos] as usize;

            if len == 0 {
                if !jumped {
                    consumed += 1;
                }
                pos += 1;
                break;
            }

            // Compression pointer
            if (len & 0xC0) == 0xC0 {
                if pos + 1 >= packet.len() {
                    return Err(DnsError::NameParseFailed {
                        position: pos,
                        reason: "Pointer truncated".to_string(),
                    });
                }
                let offset = (((len & 0x3F) as usize) << 8) | packet[pos + 1] as usize;
                if depth > 10 {
                    return Err(DnsError::NameParseFailed {
                        position: pos,
                        reason: "Name compression depth exceeded".to_string(),
                    });
                }
                if !jumped {
                    consumed += 2;
                    jumped = true;
                }
                pos = offset;
                depth += 1;
                continue;
            }

            pos += 1;
            if pos + len > packet.len() {
                return Err(DnsError::NameParseFailed {
                    position: pos,
                    reason: format!("label length {} exceeds packet", len),
                });
            }

            let label = String::from_utf8_lossy(&packet[pos..pos + len]).to_string();
            labels.push(label);
            if !jumped {
                consumed += 1 + len;
            }
            pos += len;
            depth += 1;
        }

        let final_pos = if jumped { start + consumed } else { pos };
        Ok((labels.join("."), final_pos))
    }

    fn resolve_query(
        state: &Arc<Mutex<DnsState>>,
        qname: &str,
        _qtype: u16,
    ) -> Result<Option<Ipv4Addr>> {
        let s = state
            .lock()
            .map_err(|e| DnsError::InvalidConfig(format!("State lock poisoned: {e}")))?;

        if let Some(ip) = s.config.custom_rules.get(qname) {
            return Ok(Some(*ip));
        }

        match &s.config.default_rule {
            DnsRule::WildcardSpoof(ip) => Ok(Some(*ip)),
            DnsRule::ExactMatch { domain, ip } if domain == qname => Ok(Some(*ip)),
            DnsRule::PassThrough => Ok(None),
            _ => Ok(None),
        }
    }

    fn forward_upstream(
        socket: &UdpSocket,
        upstream: Ipv4Addr,
        query: &[u8],
        client: SocketAddr,
    ) -> Result<()> {
        let upstream_socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .map_err(|e| DnsError::BindFailed {
                interface: "upstream".to_string(),
                port: 0,
                source: e,
            })?;

        let _ = upstream_socket.set_read_timeout(Some(Duration::from_secs(2)));

        upstream_socket
            .send_to(query, SocketAddr::from((upstream, DNS_PORT)))
            .map_err(|e| DnsError::SendFailed { client, source: e })?;

        let mut buf = [0u8; DNS_MAX_PACKET_SIZE];
        let (len, _) =
            upstream_socket
                .recv_from(&mut buf)
                .map_err(|e| DnsError::ReceiveFailed {
                    interface: "upstream".to_string(),
                    source: e,
                })?;

        socket
            .send_to(&buf[..len], client)
            .map_err(|e| DnsError::SendFailed { client, source: e })?;

        Ok(())
    }

    fn send_response(
        socket: &UdpSocket,
        _query: &[u8],
        transaction_id: u16,
        qname: &str,
        answer_ip: Option<Ipv4Addr>,
        client: SocketAddr,
        rcode: u8,
    ) -> Result<()> {
        let mut response = Vec::with_capacity(512);

        response.extend_from_slice(&transaction_id.to_be_bytes());

        let mut flags: u16 = 0x8000;
        flags |= (rcode as u16) & 0x0F;
        if answer_ip.is_some() {
            flags |= 0x0400;
        }
        response.extend_from_slice(&flags.to_be_bytes());

        response.extend_from_slice(&1u16.to_be_bytes());

        let ancount = if answer_ip.is_some() { 1u16 } else { 0u16 };
        response.extend_from_slice(&ancount.to_be_bytes());

        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        for label in qname.split('.') {
            response.push(label.len() as u8);
            response.extend_from_slice(label.as_bytes());
        }
        response.push(0);

        response.extend_from_slice(&QTYPE_A.to_be_bytes());
        response.extend_from_slice(&QCLASS_IN.to_be_bytes());

        if let Some(ip) = answer_ip {
            response.extend_from_slice(&0xC00Cu16.to_be_bytes());

            response.extend_from_slice(&QTYPE_A.to_be_bytes());
            response.extend_from_slice(&QCLASS_IN.to_be_bytes());

            response.extend_from_slice(&300u32.to_be_bytes());

            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&ip.octets());
        }

        socket
            .send_to(&response, client)
            .map_err(|e| DnsError::SendFailed { client, source: e })?;

        Ok(())
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_name_simple() {
        let packet = b"\x03www\x06google\x03com\x00";
        let (name, pos) = DnsServer::parse_name(packet, 0).unwrap();
        assert_eq!(name, "www.google.com");
        assert_eq!(pos, packet.len());
    }

    #[test]
    fn test_parse_name_singee_label() {
        let packet = b"\x09localhost\x00";
        let (name, pos) = DnsServer::parse_name(packet, 0).unwrap();
        assert_eq!(name, "localhost");
        assert_eq!(pos, packet.len());
    }

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert_eq!(config.interface, "");
        assert_eq!(config.listen_ip, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(config.default_rule, DnsRule::PassThrough);
    }

    #[test]
    fn test_wiedcard_spoof_rule() {
        let spoof_ip = Ipv4Addr::new(192, 168, 1, 1);
        let rule = DnsRule::WildcardSpoof(spoof_ip);

        if let DnsRule::WildcardSpoof(ip) = rule {
            assert_eq!(ip, spoof_ip);
        } else {
            assert!(false, "Expected wildcard spoof rule");
        }
    }

    #[test]
    fn test_custom_rules() {
        let config = DnsConfig {
            interface: "wean0".to_string(),
            listen_ip: Ipv4Addr::new(192, 168, 1, 1),
            default_rule: DnsRule::PassThrough,
            custom_rules: {
                let mut map = HashMap::new();
                map.insert("test.com".to_string(), Ipv4Addr::new(10, 0, 0, 1));
                map
            },
            upstream_dns: None,
            log_queries: false,
        };

        assert_eq!(
            config.custom_rules.get("test.com"),
            Some(&Ipv4Addr::new(10, 0, 0, 1))
        );
    }
}
