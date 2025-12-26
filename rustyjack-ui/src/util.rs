//! Utility functions for the UI
//!
//! This module contains standalone helper functions that don't
//! require access to the App state.

use anyhow::{Context, Result};
use chrono::Local;
use log::info;
use rustyjack_evasion::logs_disabled;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

/// Count the number of lines in a file
pub fn count_lines(path: &Path) -> std::io::Result<usize> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count())
}

/// Check if an interface has an IPv4 address assigned
pub fn interface_has_ip(interface: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        use tokio::runtime::Handle;

        let fetch = |handle: &Handle| {
            handle.block_on(async {
                let mgr = rustyjack_netlink::InterfaceManager::new()?;
                mgr.get_ipv4_addresses(interface).await
            })
        };

        let addrs = match Handle::try_current() {
            Ok(handle) => fetch(&handle).ok(),
            Err(_) => tokio::runtime::Runtime::new()
                .ok()
                .and_then(|rt| fetch(rt.handle()).ok()),
        };

        addrs
            .unwrap_or_default()
            .iter()
            .any(|addr| matches!(addr.address, std::net::IpAddr::V4(_)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        false
    }
}

/// Check if a directory exists and contains at least one file
pub fn dir_has_files(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    fs::read_dir(dir)
        .ok()
        .and_then(|mut it| it.next())
        .is_some()
}

/// Shorten a string for display by truncating the middle with "..."
pub fn shorten_for_display(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    if max_len <= 3 {
        return value[..max_len.min(value.len())].to_string();
    }
    let keep = max_len - 3;
    let prefix = keep / 2;
    let suffix = keep - prefix;
    let start = &value[..prefix.min(value.len())];
    let end = &value[value.len().saturating_sub(suffix)..];
    format!("{start}...{end}")
}

fn sanitize_component(input: &str) -> String {
    if input.trim().is_empty() {
        return "unknown".to_string();
    }
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

/// Write a scoped log under loot/<scope>/<target>/<action>/logs/.
/// Respects RUSTYJACK_LOGS_DISABLED and returns the written path if successful.
pub fn write_scoped_log(
    root: &Path,
    scope: &str,
    target: &str,
    action: &str,
    name: &str,
    lines: &[String],
) -> Option<PathBuf> {
    if logs_disabled() || lines.is_empty() {
        return None;
    }
    let dir = root
        .join("loot")
        .join(scope)
        .join(sanitize_component(target))
        .join(sanitize_component(action))
        .join("logs");
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let fname = format!(
        "{}_{}.log",
        sanitize_component(name),
        Local::now().format("%Y%m%d_%H%M%S")
    );
    let path = dir.join(fname);
    if let Ok(mut file) = fs::File::create(&path) {
        for line in lines {
            let _ = writeln!(file, "{line}");
        }
        Some(path)
    } else {
        None
    }
}

/// Get a human-readable description of a port's typical service
pub fn port_role(port: u16) -> &'static str {
    match port {
        21 => "(ftp)",
        22 => "(ssh)",
        23 => "(telnet)",
        25 => "(smtp)",
        53 => "(dns)",
        80 => "(http)",
        110 => "(pop3)",
        139 => "(netbios)",
        143 => "(imap)",
        389 => "(ldap)",
        443 => "(https)",
        445 => "(smb)",
        465 => "(smtps)",
        587 => "(submission)",
        993 => "(imaps)",
        995 => "(pop3s)",
        1433 => "(mssql)",
        1521 => "(oracle)",
        1723 => "(pptp)",
        3306 => "(mysql)",
        3389 => "(rdp)",
        5432 => "(postgres)",
        5900 => "(vnc)",
        6379 => "(redis)",
        8080 => "(http-alt)",
        8443 => "(https-alt)",
        62078 => "(iphone-sync)",
        _ => "",
    }
}

/// Get a description of common vulnerabilities or weaknesses for a port
#[allow(dead_code)]
pub fn port_weakness(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("FTP (cleartext creds)"),
        23 => Some("Telnet (cleartext, legacy)"),
        25 => Some("SMTP (check open relay/unauth)"),
        110 | 143 => Some("Mail (POP/IMAP cleartext)"),
        139 | 445 => Some("SMB (lateral movement/hash relay)"),
        3389 => Some("RDP (remote access exposure)"),
        5900 => Some("VNC (weak/no auth common)"),
        3306 => Some("MySQL (DB exposure)"),
        5432 => Some("Postgres (DB exposure)"),
        6379 => Some("Redis (no auth by default)"),
        1521 => Some("Oracle DB (sensitive)"),
        1723 => Some("PPTP (weak VPN)"),
        62078 => Some("iTunes sync (device trust risk)"),
        _ => None,
    }
}

// ==================== Linux-specific Network Helpers ====================

#[cfg(target_os = "linux")]
pub fn renew_dhcp_and_reconnect(interface: &str) -> bool {
    use tokio::runtime::Handle;

    let dhcp_success = match Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| {
            handle.block_on(async {
                if let Err(e) = rustyjack_netlink::dhcp_renew(interface, None).await {
                    log::warn!("DHCP renew failed for {}: {}", interface, e);
                    false
                } else {
                    log::info!("DHCP lease renewed for {}", interface);
                    true
                }
            })
        }),
        Err(_) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Err(e) = rustyjack_netlink::dhcp_renew(interface, None).await {
                    log::warn!("DHCP renew failed for {}: {}", interface, e);
                    false
                } else {
                    log::info!("DHCP lease renewed for {}", interface);
                    true
                }
            })
        }
    };

    // Try WPA reconnect via rustyjack-netlink
    let wpa_success = match rustyjack_netlink::WpaManager::new(interface) {
        Ok(mgr) => match mgr.reconnect() {
            Ok(_) => {
                log::info!("WPA reconnect triggered for {}", interface);
                true
            }
            Err(e) => {
                log::debug!(
                    "WPA reconnect failed (may not be using wpa_supplicant): {}",
                    e
                );
                false
            }
        },
        Err(e) => {
            log::debug!("WPA manager creation failed: {}", e);
            false
        }
    };

    // Fallback to NetworkManager if needed
    let nm_success = if !wpa_success {
        let rt = tokio::runtime::Runtime::new().ok();
        if let Some(rt) = rt {
            rt.block_on(async {
                rustyjack_netlink::networkmanager::reconnect_device(interface)
                    .await
                    .is_ok()
            })
        } else {
            false
        }
    } else {
        false
    };

    dhcp_success || wpa_success || nm_success
}

#[cfg(target_os = "linux")]
pub fn generate_vendor_aware_mac(interface: &str) -> Result<(rustyjack_evasion::MacAddress, bool)> {
    use rustyjack_evasion::{MacAddress, VendorOui};

    let current = std::fs::read_to_string(format!("/sys/class/net/{}/address", interface))
        .ok()
        .and_then(|s| MacAddress::parse(s.trim()).ok());

    if let Some(mac) = current {
        if let Some(vendor) = VendorOui::from_oui(mac.oui()) {
            let mut candidate = MacAddress::random_with_oui(vendor.oui)?;
            let mut bytes = *candidate.as_bytes();
            // Preserve vendor flavor but force locally administered + unicast bits
            bytes[0] = (bytes[0] | 0x02) & 0xFE;
            candidate = MacAddress::new(bytes);
            return Ok((candidate, true));
        }
    }

    Ok((MacAddress::random()?, false))
}

#[cfg(target_os = "linux")]
pub fn randomize_mac_with_reconnect(
    interface: &str,
) -> Result<(rustyjack_evasion::MacState, bool, bool)> {
    use rustyjack_evasion::MacManager;

    let mut manager = MacManager::new().context("creating MacManager")?;
    manager.set_auto_restore(false);

    let (new_mac, vendor_reused) = generate_vendor_aware_mac(interface)?;
    let state = manager
        .set_mac(interface, &new_mac)
        .context("setting randomized MAC")?;

    let reconnect_ok = renew_dhcp_and_reconnect(interface);
    info!(
        "[MAC] randomized interface {}: {} -> {} (vendor_reused={}, reconnect_ok={})",
        interface,
        state.original_mac,
        state.current_mac,
        vendor_reused,
        reconnect_ok
    );
    Ok((state, reconnect_ok, vendor_reused))
}

/// Auto-randomize MAC before attack if enabled in settings
/// Returns true if MAC was randomized (so caller knows to restore later)
#[allow(dead_code)]
pub fn auto_randomize_mac_if_enabled(
    interface: &str,
    settings: &crate::config::SettingsConfig,
) -> bool {
    if !settings.mac_randomization_enabled {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        randomize_mac_with_reconnect(interface).is_ok()
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Restore original MAC from saved settings
#[allow(dead_code)]
pub fn restore_original_mac(interface: &str, original_mac: &str) -> bool {
    if original_mac.is_empty() {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        use rustyjack_evasion::{MacAddress, MacManager};
        let mut manager = match MacManager::new() {
            Ok(mgr) => mgr,
            Err(_) => return false,
        };
        manager.set_auto_restore(false);
        let mac = match MacAddress::parse(original_mac) {
            Ok(mac) => mac,
            Err(_) => return false,
        };
        manager.set_mac(interface, &mac).is_ok()
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        let _ = original_mac;
        false
    }
}

#[cfg(target_os = "linux")]
pub fn interface_wiphy(interface: &str) -> Option<String> {
    let mut mgr = rustyjack_netlink::WirelessManager::new().ok()?;
    let info = mgr.get_interface_info(interface).ok()?;
    Some(info.wiphy.to_string())
}

#[cfg(target_os = "linux")]
pub fn check_monitor_mode_support(interface: &str) -> bool {
    let mut mgr = match rustyjack_netlink::WirelessManager::new() {
        Ok(mgr) => mgr,
        Err(_) => return false,
    };
    mgr.get_phy_capabilities(interface)
        .map(|caps| caps.supports_monitor)
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
pub fn check_monitor_mode_support(_interface: &str) -> bool {
    true
}
