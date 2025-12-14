//! Utility functions for the UI
//!
//! This module contains standalone helper functions that don't
//! require access to the App state.

use anyhow::{Context, Result};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
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
        let output = Command::new("ip")
            .args(["-4", "addr", "show", "dev", interface])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            return stdout.contains("inet ");
        }
        false
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
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    if let Err(e) = rustyjack_netlink::dhcp_renew(interface, None).await {
                        log::warn!("DHCP renew failed for {}: {}", interface, e);
                        false
                    } else {
                        log::info!("DHCP lease renewed for {}", interface);
                        true
                    }
                })
            })
        }
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
                log::debug!("WPA reconnect failed (may not be using wpa_supplicant): {}", e);
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
pub fn generate_vendor_aware_mac(interface: &str) -> Result<rustyjack_evasion::MacAddress> {
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
            return Ok(candidate);
        }
    }

    Ok(MacAddress::random()?)
}

#[cfg(target_os = "linux")]
pub fn randomize_mac_with_reconnect(
    interface: &str,
) -> Result<(rustyjack_evasion::MacState, bool)> {
    use rustyjack_evasion::MacManager;

    let mut manager = MacManager::new().context("creating MacManager")?;
    manager.set_auto_restore(false);

    let new_mac = generate_vendor_aware_mac(interface)?;
    let state = manager
        .set_mac(interface, &new_mac)
        .context("setting randomized MAC")?;

    let reconnect_ok = renew_dhcp_and_reconnect(interface);
    Ok((state, reconnect_ok))
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

    let _ = Command::new("ip")
        .args(["link", "set", interface, "down"])
        .output();

    let result = Command::new("ip")
        .args(["link", "set", interface, "address", original_mac])
        .output();

    let _ = Command::new("ip")
        .args(["link", "set", interface, "up"])
        .output();

    result.map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub fn interface_wiphy(interface: &str) -> Option<String> {
    let output = Command::new("iw")
        .args(["dev", interface, "info"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("wiphy ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn check_monitor_mode_support(interface: &str) -> bool {
    if let Some(phy) = interface_wiphy(interface) {
        return Command::new("iw")
            .args(["phy", &format!("phy{}", phy), "info"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("monitor"))
            .unwrap_or(false);
    }
    // Fallback
    Command::new("iw")
        .arg("list")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("monitor"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
pub fn check_monitor_mode_support(_interface: &str) -> bool {
    true
}
