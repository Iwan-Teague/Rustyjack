//! Probe request sniffing and analysis
//!
//! Capture and analyze probe requests to discover:
//! - What networks nearby devices are looking for
//! - Client MAC addresses and device patterns
//! - Potential targets for evil twin attacks
//!
//! ## How probe requests work
//! When a device's WiFi is on, it broadcasts probe requests asking
//! "Is network X here?" for all saved/known networks. This reveals:
//! - Network names the device has connected to before
//! - Device MAC address (unless randomized)
//! - Device vendor from OUI
//!
//! ## Uses
//! - Reconnaissance: discover networks in the area
//! - Target selection: find common networks to impersonate
//! - Tracking: monitor device presence (privacy research)

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Local;

use crate::capture::{CaptureFilter, CapturedPacket, PacketCapture};
use crate::error::{Result, WirelessError};
use crate::frames::{FrameSubtype, FrameType, MacAddress};
use crate::interface::WirelessInterface;

/// A probe request from a client device
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// Client MAC address (may be randomized)
    pub client_mac: MacAddress,
    /// SSID being probed for (empty = broadcast probe)
    pub ssid: Option<String>,
    /// Signal strength at capture
    pub signal_dbm: Option<i8>,
    /// Timestamp of capture
    pub timestamp: Instant,
    /// Whether MAC appears randomized (local bit set)
    pub mac_randomized: bool,
}

impl ProbeRequest {
    /// Check if this is a broadcast probe (no specific SSID)
    pub fn is_broadcast(&self) -> bool {
        self.ssid.is_none() || self.ssid.as_ref().map(|s| s.is_empty()).unwrap_or(true)
    }
}

/// Statistics about a probed network
#[derive(Debug, Clone)]
pub struct ProbedNetwork {
    /// Network SSID
    pub ssid: String,
    /// Clients that probed for this network
    pub clients: HashSet<MacAddress>,
    /// Number of probe requests seen
    pub probe_count: u32,
    /// First seen timestamp
    pub first_seen: Instant,
    /// Last seen timestamp
    pub last_seen: Instant,
}

impl ProbedNetwork {
    fn new(ssid: String) -> Self {
        let now = Instant::now();
        Self {
            ssid,
            clients: HashSet::new(),
            probe_count: 0,
            first_seen: now,
            last_seen: now,
        }
    }

    fn add_probe(&mut self, client: MacAddress) {
        self.clients.insert(client);
        self.probe_count += 1;
        self.last_seen = Instant::now();
    }
}

/// Statistics about a client device
#[derive(Debug, Clone)]
pub struct ClientStats {
    /// Client MAC address
    pub mac: MacAddress,
    /// Networks this client is looking for
    pub probed_networks: HashSet<String>,
    /// Number of probes sent
    pub probe_count: u32,
    /// First seen
    pub first_seen: Instant,
    /// Last seen
    pub last_seen: Instant,
    /// Strongest signal seen
    pub best_signal: Option<i8>,
    /// Whether MAC appears randomized
    pub mac_randomized: bool,
}

impl ClientStats {
    fn new(mac: MacAddress) -> Self {
        let randomized = mac.is_locally_administered();
        let now = Instant::now();
        Self {
            mac,
            probed_networks: HashSet::new(),
            probe_count: 0,
            first_seen: now,
            last_seen: now,
            best_signal: None,
            mac_randomized: randomized,
        }
    }

    fn add_probe(&mut self, ssid: Option<&str>, signal: Option<i8>) {
        if let Some(ssid) = ssid {
            if !ssid.is_empty() {
                self.probed_networks.insert(ssid.to_string());
            }
        }
        self.probe_count += 1;
        self.last_seen = Instant::now();

        if let Some(sig) = signal {
            match self.best_signal {
                Some(best) if sig > best => self.best_signal = Some(sig),
                None => self.best_signal = Some(sig),
                _ => {}
            }
        }
    }
}

/// Probe request sniffer
pub struct ProbeSniffer {
    interface_name: String,
    /// All captured probe requests
    probes: Vec<ProbeRequest>,
    /// Network statistics
    networks: HashMap<String, ProbedNetwork>,
    /// Client statistics
    clients: HashMap<MacAddress, ClientStats>,
}

impl ProbeSniffer {
    /// Create new probe sniffer
    pub fn new(interface: &WirelessInterface) -> Result<Self> {
        Ok(Self {
            interface_name: interface.name().to_string(),
            probes: Vec::new(),
            networks: HashMap::new(),
            clients: HashMap::new(),
        })
    }

    /// Create from interface name
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(Self {
            interface_name: name.to_string(),
            probes: Vec::new(),
            networks: HashMap::new(),
            clients: HashMap::new(),
        })
    }

    /// Sniff probe requests for a duration
    pub fn sniff(&mut self, duration: Duration) -> Result<SniffResult> {
        log::info!("Starting probe sniffing for {:?}", duration);

        let mut capture = PacketCapture::new(&self.interface_name)?;

        // Filter for probe requests (management frames, subtype 4)
        let filter = CaptureFilter {
            frame_types: Some(vec![FrameType::Management]),
            subtypes: Some(vec![FrameSubtype::ProbeRequest]),
            ..Default::default()
        };
        capture.set_filter(filter);

        let start = Instant::now();
        let mut total_probes = 0u32;

        while start.elapsed() < duration {
            if let Some(packet) = capture.next_packet()? {
                if let Some(probe) = self.parse_probe_request(&packet) {
                    self.process_probe(&probe);
                    self.probes.push(probe);
                    total_probes += 1;
                }
            }
        }

        let result = SniffResult {
            duration: start.elapsed(),
            total_probes,
            unique_clients: self.clients.len() as u32,
            unique_networks: self.networks.len() as u32,
            top_networks: self.top_networks(10).into_iter().cloned().collect(),
            active_clients: self.active_clients(10).into_iter().cloned().collect(),
        };

        log::info!(
            "Probe sniffing complete: {} probes, {} clients, {} networks",
            total_probes,
            self.clients.len(),
            self.networks.len()
        );

        Ok(result)
    }

    /// Channel hopping sniff (requires channel control)
    pub fn sniff_with_hopping(
        &mut self,
        iface: &mut WirelessInterface,
        channels: &[u8],
        duration: Duration,
        hop_interval: Duration,
    ) -> Result<SniffResult> {
        log::info!(
            "Starting probe sniffing with channel hopping ({} channels)",
            channels.len()
        );

        let mut capture = PacketCapture::new(&self.interface_name)?;
        let filter = CaptureFilter {
            frame_types: Some(vec![FrameType::Management]),
            subtypes: Some(vec![FrameSubtype::ProbeRequest]),
            ..Default::default()
        };
        capture.set_filter(filter);

        let start = Instant::now();
        let mut channel_idx = 0;
        let mut last_hop = Instant::now();
        let mut total_probes = 0u32;

        while start.elapsed() < duration {
            // Hop channel if needed
            if last_hop.elapsed() >= hop_interval {
                let channel = channels[channel_idx % channels.len()];
                if let Err(e) = iface.set_channel(channel) {
                    log::warn!("Failed to set channel {}: {}", channel, e);
                }
                channel_idx += 1;
                last_hop = Instant::now();
            }

            if let Some(packet) = capture.next_packet()? {
                if let Some(probe) = self.parse_probe_request(&packet) {
                    self.process_probe(&probe);
                    self.probes.push(probe);
                    total_probes += 1;
                }
            }
        }

        Ok(SniffResult {
            duration: start.elapsed(),
            total_probes,
            unique_clients: self.clients.len() as u32,
            unique_networks: self.networks.len() as u32,
            top_networks: self.top_networks(10).into_iter().cloned().collect(),
            active_clients: self.active_clients(10).into_iter().cloned().collect(),
        })
    }

    /// Parse probe request from captured packet
    pub fn parse_probe_request(&self, packet: &CapturedPacket) -> Option<ProbeRequest> {
        let frame = &packet.frame;

        // Verify it's a probe request
        if frame.frame_type() != FrameType::Management
            || frame.subtype() != FrameSubtype::ProbeRequest
        {
            return None;
        }

        let client_mac = frame.source()?;
        let ssid = self.extract_ssid(frame.raw());

        Some(ProbeRequest {
            client_mac,
            ssid,
            signal_dbm: packet.signal_dbm(),
            timestamp: Instant::now(),
            mac_randomized: client_mac.is_locally_administered(),
        })
    }

    /// Extract SSID from probe request frame
    fn extract_ssid(&self, raw: &[u8]) -> Option<String> {
        // Skip 802.11 header (24 bytes for management frame)
        if raw.len() < 26 {
            return None;
        }

        let body = &raw[24..];

        // First tagged parameter should be SSID (tag 0)
        if body.len() < 2 || body[0] != 0 {
            return None;
        }

        let ssid_len = body[1] as usize;
        if ssid_len == 0 || body.len() < 2 + ssid_len {
            return None; // Broadcast probe or truncated
        }

        let ssid_bytes = &body[2..2 + ssid_len];
        String::from_utf8(ssid_bytes.to_vec()).ok()
    }

    /// Process a probe request and update statistics
    pub fn process_probe(&mut self, probe: &ProbeRequest) {
        // Update client stats
        let client = self
            .clients
            .entry(probe.client_mac)
            .or_insert_with(|| ClientStats::new(probe.client_mac));
        client.add_probe(probe.ssid.as_deref(), probe.signal_dbm);

        // Update network stats
        if let Some(ref ssid) = probe.ssid {
            if !ssid.is_empty() {
                let network = self
                    .networks
                    .entry(ssid.clone())
                    .or_insert_with(|| ProbedNetwork::new(ssid.clone()));
                network.add_probe(probe.client_mac);
            }
        }
    }

    /// Get top N networks by probe count
    pub fn top_networks(&self, n: usize) -> Vec<&ProbedNetwork> {
        let mut networks: Vec<_> = self.networks.values().collect();
        networks.sort_by(|a, b| b.probe_count.cmp(&a.probe_count));
        networks.into_iter().take(n).collect()
    }

    /// Get most active clients
    pub fn active_clients(&self, n: usize) -> Vec<&ClientStats> {
        let mut clients: Vec<_> = self.clients.values().collect();
        clients.sort_by(|a, b| b.probe_count.cmp(&a.probe_count));
        clients.into_iter().take(n).collect()
    }

    /// Get all captured probes
    pub fn probes(&self) -> &[ProbeRequest] {
        &self.probes
    }

    /// Get all networks
    pub fn networks(&self) -> &HashMap<String, ProbedNetwork> {
        &self.networks
    }

    /// Get all clients
    pub fn clients(&self) -> &HashMap<MacAddress, ClientStats> {
        &self.clients
    }

    /// Find clients probing for a specific network
    pub fn clients_for_network(&self, ssid: &str) -> Vec<MacAddress> {
        self.networks
            .get(ssid)
            .map(|n| n.clients.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Find networks a specific client is probing for
    pub fn networks_for_client(&self, mac: MacAddress) -> Vec<String> {
        self.clients
            .get(&mac)
            .map(|c| c.probed_networks.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Clear all data
    pub fn clear(&mut self) {
        self.probes.clear();
        self.networks.clear();
        self.clients.clear();
    }
}

/// Result of a probe sniffing session
#[derive(Debug)]
pub struct SniffResult {
    /// Total duration
    pub duration: Duration,
    /// Total probe requests captured
    pub total_probes: u32,
    /// Number of unique client MACs
    pub unique_clients: u32,
    /// Number of unique networks probed
    pub unique_networks: u32,
    /// Top probed networks
    pub top_networks: Vec<ProbedNetwork>,
    /// Most active clients
    pub active_clients: Vec<ClientStats>,
}

impl SniffResult {
    /// Get probe rate per second
    pub fn probes_per_second(&self) -> f32 {
        if self.duration.as_secs_f32() == 0.0 {
            0.0
        } else {
            self.total_probes as f32 / self.duration.as_secs_f32()
        }
    }
}

// Extend MacAddress with locally administered check
impl MacAddress {
    /// Check if MAC is locally administered (randomized)
    /// The second-least-significant bit of the first octet is 1
    pub fn is_locally_administered(&self) -> bool {
        (self.0[0] & 0x02) != 0
    }

    /// Get OUI (first 3 bytes) for vendor lookup
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }
}

/// Quick probe sniff function
pub fn quick_probe_sniff(interface: &str, channel: u8, duration_secs: u64) -> Result<SniffResult> {
    let mut iface = WirelessInterface::new(interface)?;
    iface.set_monitor_mode()?;
    iface.set_channel(channel)?;

    let mut sniffer = ProbeSniffer::new(&iface)?;
    let result = sniffer.sniff(Duration::from_secs(duration_secs))?;

    iface.set_managed_mode()?;

    Ok(result)
}

/// Configuration for probe sniffing
#[derive(Debug, Clone)]
pub struct ProbeSniffConfig {
    /// Interface to use
    pub interface: String,
    /// Duration in seconds
    pub duration: u32,
    /// Channel to sniff on (0 = hop through common channels)
    pub channel: u8,
}

/// Result of probe sniffing with loot paths
#[derive(Debug, Clone)]
pub struct ProbeSniffResult {
    /// Total probes captured
    pub total_probes: u32,
    /// Unique client MACs seen
    pub unique_clients: u32,
    /// Unique networks probed for
    pub unique_networks: u32,
    /// Duration of capture
    pub duration: Duration,
    /// Top networks (SSID, probe count)
    pub top_networks: Vec<(String, u32)>,
    /// Top clients (MAC, probe count)
    pub top_clients: Vec<(String, u32)>,
    /// Global log file path
    pub global_log: PathBuf,
    /// Per-network log directory
    pub network_logs_dir: PathBuf,
}

/// Execute probe sniffing with full loot output
///
/// Captures probe requests and writes:
/// - Global log with all probes and statistics
/// - Per-network logs for each SSID discovered
pub fn execute_probe_sniff<F>(
    loot_dir: &Path,
    config: &ProbeSniffConfig,
    on_progress: F,
) -> Result<ProbeSniffResult>
where
    F: Fn(f32, &str),
{
    log::info!("Starting probe sniff on interface {}", config.interface);
    on_progress(0.05, "Initializing interface...");

    // Validate interface
    if !crate::is_wireless_interface(&config.interface) {
        return Err(WirelessError::Interface(format!(
            "{} is not a wireless interface",
            config.interface
        )));
    }

    // Create loot directory and set up optional logging paths
    fs::create_dir_all(loot_dir)
        .map_err(|e| WirelessError::System(format!("Failed to create loot dir: {}", e)))?;
    let logging_enabled = rustyjack_core::system::logs_enabled();

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let (network_logs_dir, global_log) = if logging_enabled {
        let network_logs_dir = loot_dir.join("networks");
        fs::create_dir_all(&network_logs_dir)
            .map_err(|e| WirelessError::System(format!("Failed to create networks dir: {}", e)))?;

        let logs_dir = loot_dir.join("logs");
        fs::create_dir_all(&logs_dir)
            .map_err(|e| WirelessError::System(format!("Failed to create logs dir: {}", e)))?;

        let global_log = logs_dir.join(format!("probe_sniff_{}.txt", timestamp));
        (network_logs_dir, global_log)
    } else {
        (PathBuf::new(), PathBuf::new())
    };

    on_progress(0.10, "Enabling monitor mode...");

    // Setup interface
    let mut iface = WirelessInterface::new(&config.interface)?;
    iface.set_monitor_mode()?;

    // Channel hopping setup
    let channels: Vec<u8> = if config.channel == 0 {
        vec![1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10]
    } else {
        vec![config.channel]
    };

    on_progress(0.15, "Starting capture...");

    let mut sniffer = ProbeSniffer::from_name(&config.interface)?;
    let start = Instant::now();
    let duration = Duration::from_secs(config.duration as u64);
    let mut channel_idx = 0;
    let mut last_channel_hop = Instant::now();
    let channel_hop_interval = Duration::from_millis(500); // Fast hopping for probes

    // Create packet capture with probe request filter
    let mut capture = PacketCapture::new(&config.interface)?;
    let filter = CaptureFilter {
        frame_types: Some(vec![FrameType::Management]),
        subtypes: Some(vec![FrameSubtype::ProbeRequest]),
        ..Default::default()
    };
    capture.set_filter(filter);

    while start.elapsed() < duration {
        // Channel hopping
        if channels.len() > 1 && last_channel_hop.elapsed() > channel_hop_interval {
            let ch = channels[channel_idx % channels.len()];
            if iface.set_channel(ch).is_ok() {
                log::trace!("Hopped to channel {}", ch);
            }
            channel_idx += 1;
            last_channel_hop = Instant::now();
        }

        // Capture packets
        if let Ok(Some(packet)) = capture.next_packet() {
            if let Some(probe) = sniffer.parse_probe_request(&packet) {
                sniffer.process_probe(&probe);
                sniffer.probes.push(probe);
            }
        }

        // Progress update
        let elapsed_pct = start.elapsed().as_secs_f32() / duration.as_secs_f32();
        if (elapsed_pct * 20.0) as u32 != ((elapsed_pct - 0.05) * 20.0).max(0.0) as u32 {
            on_progress(
                0.15 + elapsed_pct.min(0.8) * 0.7,
                &format!(
                    "{} probes, {} clients, {} networks",
                    sniffer.probes.len(),
                    sniffer.clients.len(),
                    sniffer.networks.len()
                ),
            );
        }
    }

    let finish_msg = if logging_enabled {
        "Saving logs..."
    } else {
        "Finalizing..."
    };
    on_progress(0.90, finish_msg);

    // Restore managed mode
    if let Err(e) = iface.set_managed_mode() {
        log::warn!("Failed to restore managed mode: {}", e);
    }

    // Build results
    let top_networks: Vec<(String, u32)> = sniffer
        .top_networks(10)
        .iter()
        .map(|n| (n.ssid.clone(), n.probe_count))
        .collect();

    let top_clients: Vec<(String, u32)> = sniffer
        .active_clients(10)
        .iter()
        .map(|c| (c.mac.to_string(), c.probe_count))
        .collect();

    // Write per-network logs
    if logging_enabled {
        for (ssid, network) in sniffer.networks() {
            if ssid.is_empty() {
                continue;
            }

            let safe_ssid =
                ssid.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_");
            let network_file = network_logs_dir.join(format!("{}.txt", safe_ssid));

            let mut content = String::new();
            content.push_str(&format!("SSID: {}\n", ssid));
            content.push_str(&format!("Probe count: {}\n", network.probe_count));
            content.push_str(&format!("Unique clients: {}\n", network.clients.len()));
            content.push_str("\nClients probing for this network:\n");
            for mac in &network.clients {
                let randomized = if mac.is_locally_administered() {
                    " (randomized)"
                } else {
                    ""
                };
                content.push_str(&format!("  - {}{}\n", mac, randomized));
            }

            let _ = fs::write(&network_file, &content);
        }
    }

    // Write global log
    if logging_enabled {
        let mut log_content = String::new();
        log_content.push_str("====================================================\n");
        log_content.push_str("    RUSTYJACK PROBE SNIFF LOG                       \n");
        log_content.push_str("====================================================\n\n");
        log_content.push_str(&format!(
            "Timestamp: {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
        log_content.push_str(&format!("Interface: {}\n", config.interface));
        log_content.push_str(&format!("Duration: {} seconds\n", config.duration));
        log_content.push_str(&format!("Channels: {:?}\n", channels));

        log_content.push_str("\n--- SUMMARY ---------------------------------------\n");
        log_content.push_str(&format!(
            "Total probes captured: {}\n",
            sniffer.probes.len()
        ));
        log_content.push_str(&format!("Unique clients: {}\n", sniffer.clients.len()));
        log_content.push_str(&format!("Unique networks: {}\n", sniffer.networks.len()));

        if !top_networks.is_empty() {
            log_content.push_str("\n--- TOP NETWORKS (by probe count) -----------------\n");
            for (i, (ssid, count)) in top_networks.iter().enumerate() {
                log_content.push_str(&format!("  {}. {} ({} probes)\n", i + 1, ssid, count));
            }
        }

        if !top_clients.is_empty() {
            log_content.push_str("\n--- TOP CLIENTS (by activity) ---------------------\n");
            for (i, (mac, count)) in top_clients.iter().enumerate() {
                let mac_parsed: std::result::Result<MacAddress, _> = mac.parse();
                let randomized = mac_parsed
                    .map(|m| m.is_locally_administered())
                    .unwrap_or(false);
                let marker = if randomized { " (randomized)" } else { "" };
                log_content.push_str(&format!(
                    "  {}. {}{} ({} probes)\n",
                    i + 1,
                    mac,
                    marker,
                    count
                ));
            }
        }

        log_content.push_str("\n--- ALL PROBED NETWORKS ---------------------------\n");
        let mut all_networks: Vec<_> = sniffer.networks().values().collect();
        all_networks.sort_by(|a, b| b.probe_count.cmp(&a.probe_count));
        for net in all_networks {
            log_content.push_str(&format!(
                "  {} - {} probes, {} clients\n",
                net.ssid,
                net.probe_count,
                net.clients.len()
            ));
        }

        log_content.push_str("\n====================================================\n");
        log_content.push_str("Use this data to identify targets for Evil Twin attacks\n");
        log_content.push_str("====================================================\n");

        fs::write(&global_log, &log_content)
            .map_err(|e| WirelessError::System(format!("Failed to write log: {}", e)))?;
    }

    on_progress(1.0, "Complete");

    Ok(ProbeSniffResult {
        total_probes: sniffer.probes.len() as u32,
        unique_clients: sniffer.clients.len() as u32,
        unique_networks: sniffer.networks.len() as u32,
        duration: start.elapsed(),
        top_networks,
        top_clients,
        global_log,
        network_logs_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_randomized() {
        // Randomized MAC (local bit set)
        let random: MacAddress = "02:00:00:00:00:00".parse().unwrap();
        assert!(random.is_locally_administered());

        // Real MAC (local bit not set)
        let real: MacAddress = "00:11:22:33:44:55".parse().unwrap();
        assert!(!real.is_locally_administered());
    }

    #[test]
    fn test_probe_request() {
        let probe = ProbeRequest {
            client_mac: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
            ssid: Some("TestNetwork".to_string()),
            signal_dbm: Some(-50),
            timestamp: Instant::now(),
            mac_randomized: false,
        };

        assert!(!probe.is_broadcast());

        let broadcast = ProbeRequest {
            ssid: None,
            ..probe.clone()
        };
        assert!(broadcast.is_broadcast());
    }
}
