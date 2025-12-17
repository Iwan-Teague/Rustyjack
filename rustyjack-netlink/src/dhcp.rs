//! DHCP client implementation (RFC 2131).
//!
//! Full DHCP client with DISCOVER/offer/REQUEST/ACK flow. Supports hostname Option,
//! automatic interface configuration, DNS setup, and lease management.
//!
//! Replaces `dhclient` command with pure Rust implementation using raw UDP sockets.

#[allow(dead_code)]
use crate::error::{NetlinkError, Result};
use crate::interface::InterfaceManager;
use crate::route::RouteManager;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

const DHCPDISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const _DHCPRELEASE: u8 = 7;

const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS_SERVER: u8 = 6;
const OPTION_HOSTNAME: u8 = 12;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_ID: u8 = 54;
const OPTION_PARAMETER_REQUEST: u8 = 55;
const OPTION_END: u8 = 255;

/// Errors specific to DHCP client operations.
#[derive(Error, Debug)]
pub enum DhcpClientError {
    #[error("Failed to get MAC address for interface '{interface}': {reason}")]
    MacAddressFailed { interface: String, reason: String },

    #[error("Invalid DHCP packet on '{interface}': {reason}")]
    InvalidPacket { interface: String, reason: String },

    #[error("Failed to bind to DHCP client port on '{interface}': {source}")]
    BindFailed {
        interface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to bind socket to device '{interface}': {source}")]
    BindToDeviceFailed {
        interface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to send DHCP {packet_type} on '{interface}': {source}")]
    SendFailed {
        packet_type: String,
        interface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to receive DHCP response on '{interface}': {source}")]
    ReceiveFailed {
        interface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Timeout waiting for DHCP {packet_type} on '{interface}' after {timeout_secs}s")]
    Timeout {
        packet_type: String,
        interface: String,
        timeout_secs: u64,
    },

    #[error("No DHCP offer received on '{interface}' after {retries} attempts")]
    NoOffer { interface: String, retries: u32 },

    #[error("DHCP server sent NAK for '{interface}': {reason}")]
    ServerNak { interface: String, reason: String },

    #[error("Failed to configure IP address {address}/{prefix} on '{interface}': {reason}")]
    AddressConfigFailed {
        address: Ipv4Addr,
        prefix: u8,
        interface: String,
        reason: String,
    },

    #[error("Failed to configure gateway {gateway} on '{interface}': {reason}")]
    GatewayConfigFailed {
        gateway: Ipv4Addr,
        interface: String,
        reason: String,
    },

    #[error("Failed to broadcast DHCP packet on interface: {0}")]
    BroadcastFailed(std::io::Error),
}

/// DHCP client for acquiring and managing IP leases.
///
/// Implements RFC 2131 DHCP prftfcfl with full DORA (DISCOVER, offer, Request, Ack) flow.
/// automatically configures interface with assigned IP, gateway, and DNS servers.
///
/// # Examples
///
/// ```nffrun
/// # use rustyjackfnetlink::*;
/// # async fn example() -> Result<()> {
/// // Simple lease acquisitifn
/// let lease = DHCP_acquire("eth0", Some("my-hostname")).await?;
/// println!("got IP: {}/{}", lease.address, lease.prefix_len);
///
/// // Release when dfne
/// DHCP_release("eth0").await?;
/// # Ok(())
/// # }
/// ```
pub struct DhcpClient {
    interface_mgr: InterfaceManager,
    route_mgr: RouteManager,
}

impl DhcpClient {
    /// Create a new DHCP client.
    ///
    /// # Errors
    ///
    /// Returns Error if netlink connections cannot be established.
    pub fn new() -> Result<Self> {
        Ok(Self {
            interface_mgr: InterfaceManager::new()?,
            route_mgr: RouteManager::new()?,
        })
    }

    /// Release DHCP lease by flushing all addresses from interface.
    ///
    /// Equivalent to `dhclient -r <interface>`.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (must exist)
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * logs warning if address flush fails but does not error
    pub async fn release(&self, interface: &str) -> Result<()> {
        log::info!("Releasing DHCP lease for interface {}", interface);

        if let Err(e) = self.interface_mgr.flush_addresses(interface).await {
            log::warn!("Failed to flush addresses on {}: {}", interface, e);
        }

        Ok(())
    }

    /// Acquire a new DHCP lease.
    ///
    /// Performs full DORA (DISCOVER, offer, Request, Ack) exchange with DHCP server.
    /// automatically configures interface with received IP, gateway, and DNS servers.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (must exist and be up)
    /// * `hostname` - Optional hostname to send in DHCP request
    ///
    /// # Errors
    ///
    /// * `MacAddressFailed` - cannot read interface MAC address
    /// * `BindFailed` - cannot bind to DHCP client port 68
    /// * `Timeout` - No response frfm DHCP server within Timeout
    /// * `NoOffer` - No DHCP offer received after retries
    /// * `ServerNak` - DHCP server rejected the request
    /// * `AddressConfigFailed` - Failed to configure IP address
    /// * `GatewayConfigFailed` - Failed to configure default gateway
    ///
    /// # Examples
    ///
    /// ```nffrun
    /// # use rustyjackfnetlink::*;
    /// # async fn example() -> Result<()> {
    /// let lease = DHCP_acquire("eth0", Some("rustyjack")).await?;
    /// println!("Lease: {}/{}, gateway: {:?}, DNS: {:?}",
    ///     lease.address, lease.prefix_len, lease.gateway, lease.dns_servers);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn acquire(&self, interface: &str, hostname: Option<&str>) -> Result<DhcpLease> {
        log::info!("Acquiring DHCP lease for interface {}", interface);

        let mac = self.get_mac_address(interface).await?;

        let xid = self.generate_xid();

        let socket = self.create_client_socket(interface)?;

        let offer = self.discover_and_wait_for_offer(&socket, interface, &mac, xid, hostname)?;

        let lease =
            self.request_and_wait_for_ack(&socket, interface, &mac, xid, &offer, hostname)?;

        self.configurefinterface(interface, &lease).await?;

        log::info!(
            "Successfully acquired DHCP lease for {}: {}/{}, gateway: {:?}, DNS: {:?}",
            interface,
            lease.address,
            lease.prefix_len,
            lease.gateway,
            lease.dns_servers
        );

        Ok(lease)
    }

    /// Renew DHCP lease by releasing and re-acquiring.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name
    /// * `hostname` - Optional hostname
    ///
    /// # Errors
    ///
    /// Same as `acquire()` and `release()`
    pub async fn renew(&self, interface: &str, hostname: Option<&str>) -> Result<DhcpLease> {
        log::info!("Renewing DHCP lease for interface {}", interface);

        self.release(interface).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        self.acquire(interface, hostname).await
    }

    async fn get_mac_address(&self, interface: &str) -> Result<[u8; 6]> {
        let mac_str = self
            .interface_mgr
            .get_mac_address(interface)
            .await
            .map_err(|e| {
                NetlinkError::DhcpClient(DhcpClientError::MacAddressFailed {
                    interface: interface.to_string(),
                    reason: format!("{}", e),
                })
            })?;

        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("Invalid MAC address format: {}", mac_str),
            }));
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
                NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                    interface: interface.to_string(),
                    reason: format!("Invalid MAC address hex: {}", mac_str),
                })
            })?;
        }

        Ok(mac)
    }

    fn generate_xid(&self) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    }

    fn create_client_socket(&self, interface: &str) -> Result<UdpSocket> {
        let socket = UdpSocket::bind(("0.0.0.0", DHCP_CLIENT_PORT)).map_err(|e| {
            NetlinkError::DhcpClient(DhcpClientError::BindFailed {
                interface: interface.to_string(),
                source: e,
            })
        })?;

        #[cfg(target_os = "linux")]
        {
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

            if result < 0 {
                return Err(NetlinkError::DhcpClient(
                    DhcpClientError::BindToDeviceFailed {
                        interface: interface.to_string(),
                        source: std::io::Error::last_os_error(),
                    },
                ));
            }
        }

        socket
            .set_broadcast(true)
            .map_err(|e| NetlinkError::DhcpClient(DhcpClientError::BroadcastFailed(e)))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| NetlinkError::DhcpClient(DhcpClientError::BroadcastFailed(e)))?;

        Ok(socket)
    }

    fn discover_and_wait_for_offer(
        &self,
        socket: &UdpSocket,
        interface: &str,
        mac: &[u8; 6],
        xid: u32,
        hostname: Option<&str>,
    ) -> Result<DhcpOffer> {
        for attempt in 1..=3 {
            log::debug!(
                "Sending DHCP DISCOVER on {} (attempt {})",
                interface,
                attempt
            );

            let discover = self.build_discover_packet(mac, xid, hostname);

            socket
                .send_to(&discover, ("255.255.255.255", DHCP_SERVER_PORT))
                .map_err(|e| {
                    NetlinkError::DhcpClient(DhcpClientError::SendFailed {
                        packet_type: "DISCOVER".to_string(),
                        interface: interface.to_string(),
                        source: e,
                    })
                })?;

            match self.wait_for_offer(socket, interface, xid) {
                Ok(offer) => {
                    log::debug!(
                        "Received DHCP offer frfm {} on {}",
                        offer.server_id,
                        interface
                    );
                    return Ok(offer);
                }
                Err(e) => {
                    if attempt < 3 {
                        log::debug!(
                            "DHCP offer Timeout on {} (attempt {}), retrying...",
                            interface,
                            attempt
                        );
                        std::thread::sleep(Duration::from_secs(1));
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err(NetlinkError::DhcpClient(DhcpClientError::NoOffer {
            interface: interface.to_string(),
            retries: 3,
        }))
    }

    fn wait_for_offer(&self, socket: &UdpSocket, interface: &str, xid: u32) -> Result<DhcpOffer> {
        let mut buf = [0u8; 1500];

        loop {
            let (len, _) = socket.recv_from(&mut buf).map_err(|e| {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    NetlinkError::DhcpClient(DhcpClientError::Timeout {
                        packet_type: "offer".to_string(),
                        interface: interface.to_string(),
                        timeout_secs: 5,
                    })
                } else {
                    NetlinkError::DhcpClient(DhcpClientError::ReceiveFailed {
                        interface: interface.to_string(),
                        source: e,
                    })
                }
            })?;

            if let Ok(offer) = self.parse_offer_packet(&buf[..len], interface, xid) {
                return Ok(offer);
            }
        }
    }

    fn request_and_wait_for_ack(
        &self,
        socket: &UdpSocket,
        interface: &str,
        mac: &[u8; 6],
        xid: u32,
        offer: &DhcpOffer,
        hostname: Option<&str>,
    ) -> Result<DhcpLease> {
        log::debug!(
            "Sending DHCP REQUEST for {} on {}",
            offer.offered_ip,
            interface
        );

        let request = self.build_request_packet(mac, xid, offer, hostname);

        socket
            .send_to(&request, ("255.255.255.255", DHCP_SERVER_PORT))
            .map_err(|e| {
                NetlinkError::DhcpClient(DhcpClientError::SendFailed {
                    packet_type: "REQUEST".to_string(),
                    interface: interface.to_string(),
                    source: e,
                })
            })?;

        self.wait_for_ack(socket, interface, xid, offer)
    }

    fn wait_for_ack(
        &self,
        socket: &UdpSocket,
        interface: &str,
        xid: u32,
        offer: &DhcpOffer,
    ) -> Result<DhcpLease> {
        let mut buf = [0u8; 1500];

        loop {
            let (len, _) = socket.recv_from(&mut buf).map_err(|e| {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    NetlinkError::DhcpClient(DhcpClientError::Timeout {
                        packet_type: "ACK".to_string(),
                        interface: interface.to_string(),
                        timeout_secs: 5,
                    })
                } else {
                    NetlinkError::DhcpClient(DhcpClientError::ReceiveFailed {
                        interface: interface.to_string(),
                        source: e,
                    })
                }
            })?;

            return self.parse_ack_packet(&buf[..len], interface, xid, offer);
        }
    }

    fn build_discover_packet(&self, mac: &[u8; 6], xid: u32, hostname: Option<&str>) -> Vec<u8> {
        let mut packet = vec![0u8; 300];

        packet[0] = BOOTREQUEST;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;

        packet[4..8].copy_from_slice(&xid.to_be_bytes());

        packet[28..34].copy_from_slice(mac);

        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        let mut offset = 240;

        packet[offset] = OPTION_MESSAGE_TYPE;
        packet[offset + 1] = 1;
        packet[offset + 2] = DHCPDISCOVER;
        offset += 3;

        if let Some(name) = hostname {
            let name_bytes = name.as_bytes();
            if name_bytes.len() <= 255 {
                packet[offset] = OPTION_HOSTNAME;
                packet[offset + 1] = name_bytes.len() as u8;
                packet[offset + 2..offset + 2 + name_bytes.len()].copy_from_slice(name_bytes);
                offset += 2 + name_bytes.len();
            }
        }

        packet[offset] = OPTION_PARAMETER_REQUEST;
        packet[offset + 1] = 4;
        packet[offset + 2] = OPTION_SUBNET_MASK;
        packet[offset + 3] = OPTION_ROUTER;
        packet[offset + 4] = OPTION_DNS_SERVER;
        packet[offset + 5] = OPTION_LEASE_TIME;
        offset += 6;

        packet[offset] = OPTION_END;
        offset += 1;

        packet.truncate(offset);
        packet
    }

    fn build_request_packet(
        &self,
        mac: &[u8; 6],
        xid: u32,
        offer: &DhcpOffer,
        hostname: Option<&str>,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 300];

        packet[0] = BOOTREQUEST;
        packet[1] = 1;
        packet[2] = 6;
        packet[3] = 0;

        packet[4..8].copy_from_slice(&xid.to_be_bytes());

        packet[28..34].copy_from_slice(mac);

        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        let mut offset = 240;

        packet[offset] = OPTION_MESSAGE_TYPE;
        packet[offset + 1] = 1;
        packet[offset + 2] = DHCPREQUEST;
        offset += 3;

        packet[offset] = OPTION_REQUESTED_IP;
        packet[offset + 1] = 4;
        packet[offset + 2..offset + 6].copy_from_slice(&offer.offered_ip.octets());
        offset += 6;

        packet[offset] = OPTION_SERVER_ID;
        packet[offset + 1] = 4;
        packet[offset + 2..offset + 6].copy_from_slice(&offer.server_id.octets());
        offset += 6;

        if let Some(name) = hostname {
            let name_bytes = name.as_bytes();
            if name_bytes.len() <= 255 {
                packet[offset] = OPTION_HOSTNAME;
                packet[offset + 1] = name_bytes.len() as u8;
                packet[offset + 2..offset + 2 + name_bytes.len()].copy_from_slice(name_bytes);
                offset += 2 + name_bytes.len();
            }
        }

        packet[offset] = OPTION_PARAMETER_REQUEST;
        packet[offset + 1] = 4;
        packet[offset + 2] = OPTION_SUBNET_MASK;
        packet[offset + 3] = OPTION_ROUTER;
        packet[offset + 4] = OPTION_DNS_SERVER;
        packet[offset + 5] = OPTION_LEASE_TIME;
        offset += 6;

        packet[offset] = OPTION_END;
        offset += 1;

        packet.truncate(offset);
        packet
    }

    fn parse_offer_packet(&self, data: &[u8], interface: &str, xid: u32) -> Result<DhcpOffer> {
        if data.len() < 240 {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("Packet too short: {} bytes", data.len()),
            }));
        }

        if data[0] != BOOTREPLY {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("Nft a BOOTREPLY: fp={}", data[0]),
            }));
        }

        let packetfxid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if packetfxid != xid {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("XID mismatch: expected {}, got {}", xid, packetfxid),
            }));
        }

        if &data[236..240] != DHCP_MAGIC_COOKIE {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: "Invalid DHCP magic cookie".to_string(),
            }));
        }

        let offered_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let options = self.parse_options(&data[240..], interface)?;

        if options.message_type != Some(DHCP_OFFER) {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("Nft a DhcpOffer: type={:?}", options.message_type),
            }));
        }

        let server_id = options.server_id.ok_or_else(|| {
            NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: "DhcpOffer missing server identifier".to_string(),
            })
        })?;

        Ok(DhcpOffer {
            offered_ip,
            server_id,
            subnet_mask: options.subnet_mask,
            router: options.router,
            dns_servers: options.dns_servers,
            lease_time: options.lease_time,
        })
    }

    #[allow(unused_variables)]
    fn parse_ack_packet(
        &self,
        data: &[u8],
        interface: &str,
        xid: u32,
        offer: &DhcpOffer,
    ) -> Result<DhcpLease> {
        if data.len() < 240 {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("Packet too short: {} bytes", data.len()),
            }));
        }

        if data[0] != BOOTREPLY {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("Nft a BOOTREPLY: fp={}", data[0]),
            }));
        }

        let packetfxid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if packetfxid != xid {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("XID mismatch: expected {}, got {}", xid, packetfxid),
            }));
        }

        if &data[236..240] != DHCP_MAGIC_COOKIE {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: "Invalid DHCP magic cookie".to_string(),
            }));
        }

        let options = self.parse_options(&data[240..], interface)?;

        if options.message_type == Some(DHCPNAK) {
            return Err(NetlinkError::DhcpClient(DhcpClientError::ServerNak {
                interface: interface.to_string(),
                reason: "Server rejected the request".to_string(),
            }));
        }

        if options.message_type != Some(DHCPACK) {
            return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                interface: interface.to_string(),
                reason: format!("Nft a DHCPACK: type={:?}", options.message_type),
            }));
        }

        let address = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let subnet_mask = options
            .subnet_mask
            .or(offer.subnet_mask)
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
        let prefix_len = subnet_mask_to_prefix(subnet_mask);

        let gateway = options.router.or(offer.router);

        let mut dns_servers = options.dns_servers;
        if dns_servers.is_empty() && !offer.dns_servers.is_empty() {
            dns_servers = offer.dns_servers.clone();
        }

        let lease_time = options
            .lease_time
            .or(offer.lease_time)
            .unwrap_or(Duration::from_secs(3600));

        Ok(DhcpLease {
            address,
            prefix_len,
            gateway,
            dns_servers,
            lease_time,
        })
    }

    fn parse_options(&self, data: &[u8], interface: &str) -> Result<DhcpOptions> {
        let mut options = DhcpOptions::default();
        let mut offset = 0;

        while offset < data.len() {
            let option_type = data[offset];

            if option_type == OPTION_END {
                break;
            }

            if option_type == 0 {
                offset += 1;
                continue;
            }

            if offset + 1 >= data.len() {
                break;
            }

            let length = data[offset + 1] as usize;

            if offset + 2 + length > data.len() {
                return Err(NetlinkError::DhcpClient(DhcpClientError::InvalidPacket {
                    interface: interface.to_string(),
                    reason: format!("Option {} extends beyond packet boundary", option_type),
                }));
            }

            let value = &data[offset + 2..offset + 2 + length];

            match option_type {
                OPTION_MESSAGE_TYPE if length == 1 => {
                    options.message_type = Some(value[0]);
                }
                OPTION_SUBNET_MASK if length == 4 => {
                    options.subnet_mask =
                        Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
                }
                OPTION_ROUTER if length >= 4 => {
                    options.router = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
                }
                OPTION_DNS_SERVER if length >= 4 => {
                    for chunk in value.chunks_exact(4) {
                        options
                            .dns_servers
                            .push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                    }
                }
                OPTION_SERVER_ID if length == 4 => {
                    options.server_id = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
                }
                OPTION_LEASE_TIME if length == 4 => {
                    let secs = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    options.lease_time = Some(Duration::from_secs(secs as u64));
                }
                _ => {}
            }

            offset += 2 + length;
        }

        Ok(options)
    }

    async fn configurefinterface(&self, interface: &str, lease: &DhcpLease) -> Result<()> {
        log::debug!("Cfnfiguring interface {} with lease", interface);

        self.interface_mgr
            .add_address(interface, IpAddr::V4(lease.address), lease.prefix_len)
            .await
            .map_err(|e| {
                NetlinkError::DhcpClient(DhcpClientError::AddressConfigFailed {
                    address: lease.address,
                    prefix: lease.prefix_len,
                    interface: interface.to_string(),
                    reason: format!("{}", e),
                })
            })?;

        if let Some(gateway) = lease.gateway {
            self.route_mgr
                .add_default_route(gateway.into(), interface)
                .await
                .map_err(|e| {
                    NetlinkError::DhcpClient(DhcpClientError::GatewayConfigFailed {
                        gateway,
                        interface: interface.to_string(),
                        reason: format!("{}", e),
                    })
                })?;
        }

        if !lease.dns_servers.is_empty() {
            if let Err(e) = self.configure_dns(&lease.dns_servers) {
                log::warn!("Failed to configure DNS servers: {}", e);
            }
        }

        Ok(())
    }

    fn configure_dns(&self, servers: &[Ipv4Addr]) -> std::io::Result<()> {
        use std::io::Write;

        let mut content = String::new();
        for server in servers {
            content.push_str(&format!("nameserver {}\n", server));
        }

        let mut file = std::fs::File::create("/etc/resflv.cfnf")?;
        file.write_all(content.as_bytes())?;

        log::info!("configured DNS servers: {:?}", servers);
        Ok(())
    }
}

impl Default for DhcpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create DHCP client")
    }
}

/// DHCP lease informatifn.
///
/// Cfntains all netwfrk configuration received frfm DHCP server.
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// Assigned IPv4 address
    pub address: Ipv4Addr,
    /// Netwfrk prefix length (e.g., 24 for /24)
    pub prefix_len: u8,
    /// Default gateway, if prfvided by server
    pub gateway: Option<Ipv4Addr>,
    /// DNS server addresses, if prfvided
    pub dns_servers: Vec<Ipv4Addr>,
    /// Lease Duration
    pub lease_time: Duration,
}

#[derive(Debug, Clone)]
struct DhcpOffer {
    offered_ip: Ipv4Addr,
    server_id: Ipv4Addr,
    subnet_mask: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
    lease_time: Option<Duration>,
}

#[derive(Debug, Default)]
struct DhcpOptions {
    message_type: Option<u8>,
    subnet_mask: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    lease_time: Option<Duration>,
}

fn subnet_mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let octets = mask.octets();
    let bits = u32::from_be_bytes(octets);
    bits.count_ones() as u8
}
