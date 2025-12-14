use anyhow::Result;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
pub fn arp_scan_subnet(subnet: &str, interface: &str) -> Result<Vec<rustyjack_netlink::ArpScanResult>> {
    use rustyjack_netlink::ArpScanner;
    let scanner = ArpScanner::new();
    scanner.scan_subnet(subnet, interface)
        .map_err(|e| anyhow::anyhow!("ARP scan failed on {}: {}", interface, e))
}

#[cfg(target_os = "linux")]
pub fn arp_get_mac(ip: Ipv4Addr, interface: &str) -> Result<Option<[u8; 6]>> {
    use rustyjack_netlink::ArpScanner;
    let scanner = ArpScanner::new();
    scanner.get_mac(ip, interface)
        .map_err(|e| anyhow::anyhow!("Failed to get MAC for {} on {}: {}", ip, interface, e))
}

#[cfg(target_os = "linux")]
pub fn arp_is_alive(ip: Ipv4Addr, interface: &str) -> Result<bool> {
    use rustyjack_netlink::ArpScanner;
    let scanner = ArpScanner::new();
    scanner.is_alive(ip, interface)
        .map_err(|e| anyhow::anyhow!("Failed to check if {} is alive on {}: {}", ip, interface, e))
}

#[cfg(target_os = "linux")]
pub fn arp_spoof_single(
    target_ip: Ipv4Addr,
    target_mac: [u8; 6],
    spoof_ip: Ipv4Addr,
    attacker_mac: [u8; 6],
    interface: &str,
) -> Result<()> {
    use rustyjack_netlink::ArpSpoofer;
    ArpSpoofer::send_spoof(target_ip, target_mac, spoof_ip, attacker_mac, interface)
        .map_err(|e| anyhow::anyhow!("ARP spoof failed on {}: {}", interface, e))
}

#[cfg(not(target_os = "linux"))]
pub fn arp_scan_subnet(_subnet: &str, _interface: &str) -> Result<Vec<()>> {
    anyhow::bail!("ARP operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn arp_get_mac(_ip: Ipv4Addr, _interface: &str) -> Result<Option<[u8; 6]>> {
    anyhow::bail!("ARP operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn arp_is_alive(_ip: Ipv4Addr, _interface: &str) -> Result<bool> {
    anyhow::bail!("ARP operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn arp_spoof_single(
    _target_ip: Ipv4Addr,
    _target_mac: [u8; 6],
    _spoof_ip: Ipv4Addr,
    _attacker_mac: [u8; 6],
    _interface: &str,
) -> Result<()> {
    anyhow::bail!("ARP operations only supported on Linux")
}
