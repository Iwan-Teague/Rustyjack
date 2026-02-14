use rustyjack_netlink::{DnsConfig, DnsRule, DnsServer};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Start DNS server for hotspot/AP mode with wildcard spoofing to gateway
pub fn start_hotspot_dns(interface: &str, gateway_ip: Ipv4Addr) -> Result<DnsServer, String> {
    let config = DnsConfig {
        interface: interface.to_string(),
        listen_ip: gateway_ip,
        default_rule: DnsRule::WildcardSpoof(gateway_ip),
        custom_rules: HashMap::new(),
        upstream_dns: Some(Ipv4Addr::new(8, 8, 8, 8)),
        log_queries: false,
    };

    let mut server = DnsServer::new(config)
        .map_err(|e| format!("Failed to create DNS server on {}: {}", interface, e))?;

    server
        .start()
        .map_err(|e| format!("Failed to start DNS server on {}: {}", interface, e))?;

    Ok(server)
}

/// Start DNS server for captive portal with wildcard spoofing
pub fn start_captive_portal_dns(
    interface: &str,
    listen_ip: Ipv4Addr,
    portal_ip: Ipv4Addr,
) -> Result<DnsServer, String> {
    let config = DnsConfig {
        interface: interface.to_string(),
        listen_ip,
        default_rule: DnsRule::WildcardSpoof(portal_ip),
        custom_rules: HashMap::new(),
        upstream_dns: None,
        log_queries: false,
    };

    let mut server = DnsServer::new(config).map_err(|e| {
        format!(
            "Failed to create DNS server on {} for captive portal: {}",
            interface, e
        )
    })?;

    server.start().map_err(|e| {
        format!(
            "Failed to start DNS server on {} for captive portal: {}",
            interface, e
        )
    })?;

    Ok(server)
}

/// Start DNS server for Evil Twin with custom domain spoofing
pub fn start_evil_twin_dns(
    interface: &str,
    listen_ip: Ipv4Addr,
    spoof_ip: Ipv4Addr,
    custom_domains: HashMap<String, Ipv4Addr>,
) -> Result<DnsServer, String> {
    let config = DnsConfig {
        interface: interface.to_string(),
        listen_ip,
        default_rule: DnsRule::WildcardSpoof(spoof_ip),
        custom_rules: custom_domains,
        upstream_dns: Some(Ipv4Addr::new(8, 8, 8, 8)),
        log_queries: false,
    };

    let mut server = DnsServer::new(config).map_err(|e| {
        format!(
            "Failed to create DNS server on {} for evil twin: {}",
            interface, e
        )
    })?;

    server.start().map_err(|e| {
        format!(
            "Failed to start DNS server on {} for evil twin: {}",
            interface, e
        )
    })?;

    Ok(server)
}

/// Start pass-through DNS server (forwards all queries upstream)
pub fn start_passthrough_dns(
    interface: &str,
    listen_ip: Ipv4Addr,
    upstream_dns: Ipv4Addr,
) -> Result<DnsServer, String> {
    let config = DnsConfig {
        interface: interface.to_string(),
        listen_ip,
        default_rule: DnsRule::PassThrough,
        custom_rules: HashMap::new(),
        upstream_dns: Some(upstream_dns),
        log_queries: false,
    };

    let mut server = DnsServer::new(config).map_err(|e| {
        format!(
            "Failed to create pass-through DNS server on {}: {}",
            interface, e
        )
    })?;

    server.start().map_err(|e| {
        format!(
            "Failed to start pass-through DNS server on {}: {}",
            interface, e
        )
    })?;

    Ok(server)
}
