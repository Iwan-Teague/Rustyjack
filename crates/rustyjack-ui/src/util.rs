//! Utility functions for the UI
//!
//! This module contains standalone helper functions that don't
//! require access to the App state.

use anyhow::{Context, Result};
use chrono::Local;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use rustyjack_client::DaemonClient;
use rustyjack_evasion::logs_disabled;
use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

/// Count the number of lines in a file
pub fn count_lines(path: &Path) -> std::io::Result<usize> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count())
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

pub fn random_hotspot_ssid() -> String {
    let rand: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    format!("RJ-{}", rand)
}

pub fn random_hotspot_password() -> String {
    OsRng
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

pub fn fetch_gpio_diagnostics() -> Result<String> {
    block_on(async {
        let socket_path = daemon_socket_path();
        let mut client =
            DaemonClient::connect(&socket_path, "rustyjack-ui", env!("CARGO_PKG_VERSION")).await?;
        let response = client.gpio_diagnostics().await?;
        Ok(response.content)
    })
}

fn daemon_socket_path() -> PathBuf {
    env::var("RUSTYJACKD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/rustyjack/rustyjackd.sock"))
}

fn block_on<F, T>(fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(fut),
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building tokio runtime for daemon client")?;
            rt.block_on(fut)
        }
    }
}
