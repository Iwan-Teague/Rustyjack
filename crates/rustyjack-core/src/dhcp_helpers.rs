use anyhow::Result;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
pub use rustyjack_netlink::{DhcpConfig, DhcpServer, DhcpServerLease as DhcpLease};

#[cfg(target_os = "linux")]
pub fn create_dhcp_server(
    interface: &str,
    server_ip: Ipv4Addr,
    range_start: Ipv4Addr,
    range_end: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
    lease_time_secs: u32,
    log_packets: bool,
) -> Result<DhcpServer> {
    let config = DhcpConfig {
        interface: interface.to_string(),
        server_ip,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        range_start,
        range_end,
        router: gateway,
        dns_servers,
        lease_time_secs,
        log_packets,
    };

    DhcpServer::new(config).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create DHCP server on interface {}: {}",
            interface,
            e
        )
    })
}

#[cfg(target_os = "linux")]
pub fn start_dhcp_server(server: &mut DhcpServer) -> Result<()> {
    server
        .start()
        .map_err(|e| anyhow::anyhow!("Failed to start DHCP server: {}", e))
}

#[cfg(target_os = "linux")]
pub fn stop_dhcp_server(server: &mut DhcpServer) {
    server.stop();
}

#[cfg(target_os = "linux")]
pub fn get_dhcp_leases(server: &DhcpServer) -> Vec<DhcpLease> {
    server.get_leases()
}

#[cfg(not(target_os = "linux"))]
pub fn create_dhcp_server(
    _interface: &str,
    _server_ip: Ipv4Addr,
    _range_start: Ipv4Addr,
    _range_end: Ipv4Addr,
    _gateway: Option<Ipv4Addr>,
    _dns_servers: Vec<Ipv4Addr>,
    _lease_time_secs: u32,
    _log_packets: bool,
) -> Result<()> {
    anyhow::bail!("DHCP server only supported on Linux")
}
