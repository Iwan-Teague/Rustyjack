//! WPA supplicant functionality
//!
//! Pure Rust implementation of WPA supplicant operations using nl80211 and control sockets.
//! Replaces `wpa_supplicant` and `wpa_cli` binaries for wireless authentication.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{NetlinkError, Result};
use log::info;

/// WPA supplicant manager
pub struct WpaManager {
    interface: String,
    control_path: PathBuf,
}

/// WPA supplicant status
#[derive(Debug, Clone, PartialEq)]
pub struct WpaStatus {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub freq: Option<u32>,
    pub mode: Option<String>,
    pub pairwise_cipher: Option<String>,
    pub group_cipher: Option<String>,
    pub key_mgmt: Option<String>,
    pub wpa_state: WpaState,
    pub ip_address: Option<String>,
    pub address: Option<String>,
}

/// WPA connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpaState {
    /// Not connected
    Disconnected,
    /// Scanning for networks
    Scanning,
    /// Authenticating
    Authenticating,
    /// Associating
    Associating,
    /// Associated but not yet authenticated
    Associated,
    /// 4-way handshake in progress
    FourWayHandshake,
    /// Group handshake in progress
    GroupHandshake,
    /// Fully connected
    Completed,
    /// Unknown state
    Unknown,
}

impl std::fmt::Display for WpaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WpaState::Disconnected => write!(f, "DISCONNECTED"),
            WpaState::Scanning => write!(f, "SCANNING"),
            WpaState::Authenticating => write!(f, "AUTHENTICATING"),
            WpaState::Associating => write!(f, "ASSOCIATING"),
            WpaState::Associated => write!(f, "ASSOCIATED"),
            WpaState::FourWayHandshake => write!(f, "4WAY_HANDSHAKE"),
            WpaState::GroupHandshake => write!(f, "GROUP_HANDSHAKE"),
            WpaState::Completed => write!(f, "COMPLETED"),
            WpaState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl WpaState {
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DISCONNECTED" | "INACTIVE" => WpaState::Disconnected,
            "SCANNING" => WpaState::Scanning,
            "AUTHENTICATING" => WpaState::Authenticating,
            "ASSOCIATING" => WpaState::Associating,
            "ASSOCIATED" => WpaState::Associated,
            "4WAY_HANDSHAKE" => WpaState::FourWayHandshake,
            "GROUP_HANDSHAKE" => WpaState::GroupHandshake,
            "COMPLETED" => WpaState::Completed,
            _ => WpaState::Unknown,
        }
    }
}

/// Network configuration for WPA
#[derive(Debug, Clone)]
pub struct WpaNetworkConfig {
    pub ssid: String,
    pub psk: Option<String>,
    pub key_mgmt: String,
    pub scan_ssid: bool,
    pub priority: i32,
    pub bssid: Option<String>,
    pub proto: Option<String>,
    pub pairwise: Option<String>,
    pub group: Option<String>,
}

impl Default for WpaNetworkConfig {
    fn default() -> Self {
        Self {
            ssid: String::new(),
            psk: None,
            key_mgmt: "WPA-PSK".to_string(),
            scan_ssid: false,
            priority: 0,
            bssid: None,
            proto: None,
            pairwise: None,
            group: None,
        }
    }
}

/// BSS details from wpa_supplicant
#[derive(Debug, Clone)]
pub struct BssInfo {
    pub bssid: Option<String>,
    pub freq: Option<u32>,
    pub level: Option<i32>,
    pub flags: Option<String>,
    pub ssid: Option<String>,
    pub ie: Option<Vec<u8>>,
    pub beacon_ie: Option<Vec<u8>>,
}

impl WpaManager {
    /// Create a new WPA manager for the given interface
    ///
    /// # Arguments
    /// * `interface` - Network interface name (e.g., "wlan0")
    ///
    /// # Errors
    /// Returns error if the interface does not exist or is not wireless
    pub fn new(interface: &str) -> Result<Self> {
        if interface.is_empty() {
            return Err(NetlinkError::Wpa(
                "Interface name cannot be empty".to_string(),
            ));
        }

        // Check if interface exists
        let sys_path = format!("/sys/class/net/{}", interface);
        if !Path::new(&sys_path).exists() {
            return Err(NetlinkError::Wpa(format!(
                "Interface '{}' does not exist",
                interface
            )));
        }

        // Check if it's a wireless interface
        let wireless_path = format!("{}/wireless", sys_path);
        if !Path::new(&wireless_path).exists()
            && !Path::new(&format!("{}/phy80211", sys_path)).exists()
        {
            return Err(NetlinkError::Wpa(format!(
                "Interface '{}' is not a wireless interface",
                interface
            )));
        }

        // Default control socket paths (most common locations)
        let control_path = PathBuf::from(format!("/var/run/wpa_supplicant/{}", interface));

        Ok(Self {
            interface: interface.to_string(),
            control_path,
        })
    }

    /// Set custom control socket path
    pub fn with_control_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.control_path = path.as_ref().to_path_buf();
        self
    }

    /// Send command to wpa_supplicant via control socket
    fn send_command(&self, command: &str) -> Result<String> {
        if !self.control_path.exists() {
            return Err(NetlinkError::Wpa(format!(
                "WPA supplicant control socket not found at {:?}. Is wpa_supplicant running on {}?",
                self.control_path, self.interface
            )));
        }

        let mut stream = UnixStream::connect(&self.control_path).map_err(|e| {
            NetlinkError::Wpa(format!(
                "Failed to connect to wpa_supplicant control socket at {:?}: {}",
                self.control_path, e
            ))
        })?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| NetlinkError::Wpa(format!("Failed to set socket timeout: {}", e)))?;

        stream.write_all(command.as_bytes()).map_err(|e| {
            NetlinkError::Wpa(format!("Failed to send command to wpa_supplicant: {}", e))
        })?;

        let mut response = String::new();
        stream.read_to_string(&mut response).map_err(|e| {
            NetlinkError::Wpa(format!(
                "Failed to read response from wpa_supplicant: {}",
                e
            ))
        })?;

        // Check for error responses
        if response.starts_with("FAIL") {
            return Err(NetlinkError::Wpa(format!(
                "WPA command '{}' failed: {}",
                command, response
            )));
        }

        Ok(response.trim().to_string())
    }

    /// Get current status from wpa_supplicant
    ///
    /// # Errors
    /// Returns error if wpa_supplicant is not running or communication fails
    pub fn status(&self) -> Result<WpaStatus> {
        let response = self.send_command("STATUS")?;

        let mut status = WpaStatus {
            ssid: None,
            bssid: None,
            freq: None,
            mode: None,
            pairwise_cipher: None,
            group_cipher: None,
            key_mgmt: None,
            wpa_state: WpaState::Disconnected,
            ip_address: None,
            address: None,
        };

        for line in response.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "ssid" => status.ssid = Some(value.to_string()),
                    "bssid" => status.bssid = Some(value.to_string()),
                    "freq" => status.freq = value.parse().ok(),
                    "mode" => status.mode = Some(value.to_string()),
                    "pairwise_cipher" => status.pairwise_cipher = Some(value.to_string()),
                    "group_cipher" => status.group_cipher = Some(value.to_string()),
                    "key_mgmt" => status.key_mgmt = Some(value.to_string()),
                    "wpa_state" => status.wpa_state = WpaState::from_str(value),
                    "ip_address" => status.ip_address = Some(value.to_string()),
                    "address" => status.address = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        Ok(status)
    }

    /// Trigger a reconnect attempt
    ///
    /// Forces wpa_supplicant to disconnect and reconnect to the current network
    ///
    /// # Errors
    /// Returns error if the reconnect command fails
    pub fn reconnect(&self) -> Result<()> {
        self.send_command("RECONNECT")?;
        Ok(())
    }

    /// Disconnect from current network
    ///
    /// # Errors
    /// Returns error if the disconnect command fails
    pub fn disconnect(&self) -> Result<()> {
        self.send_command("DISCONNECT")?;
        Ok(())
    }

    /// Reassociate with the current AP
    ///
    /// Similar to reconnect but doesn't perform a full disconnect
    ///
    /// # Errors
    /// Returns error if the reassociate command fails
    pub fn reassociate(&self) -> Result<()> {
        self.send_command("REASSOCIATE")?;
        Ok(())
    }

    /// Trigger a network scan
    ///
    /// # Errors
    /// Returns error if the scan command fails
    pub fn scan(&self) -> Result<()> {
        self.send_command("SCAN")?;
        Ok(())
    }

    /// Get scan results
    ///
    /// Returns a list of available networks from the last scan
    ///
    /// # Errors
    /// Returns error if unable to retrieve scan results
    pub fn scan_results(&self) -> Result<Vec<HashMap<String, String>>> {
        let response = self.send_command("SCAN_RESULTS")?;

        let mut results = Vec::new();
        let mut lines = response.lines();

        // Skip header line
        lines.next();

        for line in lines {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 5 {
                let mut network = HashMap::new();
                network.insert("bssid".to_string(), fields[0].to_string());
                network.insert("frequency".to_string(), fields[1].to_string());
                network.insert("signal".to_string(), fields[2].to_string());
                network.insert("flags".to_string(), fields[3].to_string());
                network.insert("ssid".to_string(), fields[4].to_string());
                results.push(network);
            }
        }

        Ok(results)
    }

    /// Query detailed BSS info for a given BSSID
    ///
    /// # Errors
    /// Returns error if unable to retrieve or parse BSS details
    pub fn bss(&self, bssid: &str) -> Result<BssInfo> {
        if bssid.trim().is_empty() {
            return Err(NetlinkError::Wpa("BSSID cannot be empty".to_string()));
        }

        let response = self.send_command(&format!("BSS {}", bssid))?;
        let mut info = BssInfo {
            bssid: None,
            freq: None,
            level: None,
            flags: None,
            ssid: None,
            ie: None,
            beacon_ie: None,
        };

        for line in response.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "bssid" => info.bssid = Some(value.to_string()),
                    "freq" => info.freq = value.parse().ok(),
                    "level" => info.level = value.parse().ok(),
                    "flags" => info.flags = Some(value.to_string()),
                    "ssid" => info.ssid = Some(value.to_string()),
                    "ie" => {
                        if let Ok(bytes) = parse_hex_bytes(value) {
                            if !bytes.is_empty() {
                                info.ie = Some(bytes);
                            }
                        }
                    }
                    "beacon_ie" => {
                        if let Ok(bytes) = parse_hex_bytes(value) {
                            if !bytes.is_empty() {
                                info.beacon_ie = Some(bytes);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(info)
    }

    /// Add a new network configuration
    ///
    /// Returns the network ID for the added network
    ///
    /// # Errors
    /// Returns error if unable to add the network
    pub fn add_network(&self) -> Result<u32> {
        let response = self.send_command("ADD_NETWORK")?;
        response
            .parse()
            .map_err(|e| NetlinkError::Wpa(format!("Failed to parse network ID: {}", e)))
    }

    /// Remove a network configuration
    ///
    /// # Arguments
    /// * `network_id` - ID of the network to remove
    ///
    /// # Errors
    /// Returns error if unable to remove the network
    pub fn remove_network(&self, network_id: u32) -> Result<()> {
        self.send_command(&format!("REMOVE_NETWORK {}", network_id))?;
        Ok(())
    }

    /// Set a network parameter
    ///
    /// # Arguments
    /// * `network_id` - ID of the network
    /// * `variable` - Parameter name (e.g., "ssid", "psk")
    /// * `value` - Parameter value
    ///
    /// # Errors
    /// Returns error if unable to set the parameter
    pub fn set_network(&self, network_id: u32, variable: &str, value: &str) -> Result<()> {
        self.send_command(&format!(
            "SET_NETWORK {} {} {}",
            network_id, variable, value
        ))?;
        Ok(())
    }

    /// Enable a network
    ///
    /// # Arguments
    /// * `network_id` - ID of the network to enable
    ///
    /// # Errors
    /// Returns error if unable to enable the network
    pub fn enable_network(&self, network_id: u32) -> Result<()> {
        self.send_command(&format!("ENABLE_NETWORK {}", network_id))?;
        Ok(())
    }

    /// Disable a network
    ///
    /// # Arguments
    /// * `network_id` - ID of the network to disable
    ///
    /// # Errors
    /// Returns error if unable to disable the network
    pub fn disable_network(&self, network_id: u32) -> Result<()> {
        self.send_command(&format!("DISABLE_NETWORK {}", network_id))?;
        Ok(())
    }

    /// Select a specific network (disable all others)
    ///
    /// # Arguments
    /// * `network_id` - ID of the network to select
    ///
    /// # Errors
    /// Returns error if unable to select the network
    pub fn select_network(&self, network_id: u32) -> Result<()> {
        self.send_command(&format!("SELECT_NETWORK {}", network_id))?;
        Ok(())
    }

    /// List all configured networks
    ///
    /// # Errors
    /// Returns error if unable to list networks
    pub fn list_networks(&self) -> Result<Vec<HashMap<String, String>>> {
        let response = self.send_command("LIST_NETWORKS")?;

        let mut networks = Vec::new();
        let mut lines = response.lines();

        // Skip header line
        lines.next();

        for line in lines {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 4 {
                let mut network = HashMap::new();
                network.insert("network_id".to_string(), fields[0].to_string());
                network.insert("ssid".to_string(), fields[1].to_string());
                network.insert("bssid".to_string(), fields[2].to_string());
                network.insert("flags".to_string(), fields[3].to_string());
                networks.push(network);
            }
        }

        Ok(networks)
    }

    /// Save the current configuration to persistent storage
    ///
    /// # Errors
    /// Returns error if unable to save configuration
    pub fn save_config(&self) -> Result<()> {
        self.send_command("SAVE_CONFIG")?;
        Ok(())
    }

    /// Reconfigure wpa_supplicant (reload configuration)
    ///
    /// # Errors
    /// Returns error if unable to reconfigure
    pub fn reconfigure(&self) -> Result<()> {
        self.send_command("RECONFIGURE")?;
        Ok(())
    }

    /// Configure and connect to a network in one step
    ///
    /// This is a high-level helper that adds a network, configures it, and connects
    ///
    /// # Arguments
    /// * `config` - Network configuration
    ///
    /// # Returns
    /// Returns the network ID of the created network
    ///
    /// # Errors
    /// Returns error if any step fails
    pub fn connect_network(&self, config: &WpaNetworkConfig) -> Result<u32> {
        info!(
            "[WIFI] WPA: configuring network ssid={} scan_ssid={} priority={}",
            config.ssid, config.scan_ssid, config.priority
        );
        // Add network
        let network_id = self.add_network()?;

        // Configure SSID (quoted)
        self.set_network(network_id, "ssid", &format!("\"{}\"", config.ssid))
            .map_err(|e| {
                let _ = self.remove_network(network_id);
                e
            })?;

        // Configure PSK if provided
        if let Some(ref psk) = config.psk {
            if psk.len() == 64 && psk.chars().all(|c| c.is_ascii_hexdigit()) {
                // Raw PSK (64 hex chars, no quotes)
                self.set_network(network_id, "psk", psk).map_err(|e| {
                    let _ = self.remove_network(network_id);
                    e
                })?;
            } else {
                // Passphrase (quoted)
                self.set_network(network_id, "psk", &format!("\"{}\"", psk))
                    .map_err(|e| {
                        let _ = self.remove_network(network_id);
                        e
                    })?;
            }
            if !config.key_mgmt.is_empty() {
                self.set_network(network_id, "key_mgmt", &config.key_mgmt)
                    .map_err(|e| {
                        let _ = self.remove_network(network_id);
                        e
                    })?;
            }
        } else {
            // Open network
            let key_mgmt = if config.key_mgmt.is_empty() {
                "NONE"
            } else {
                config.key_mgmt.as_str()
            };
            self.set_network(network_id, "key_mgmt", key_mgmt)
                .map_err(|e| {
                    let _ = self.remove_network(network_id);
                    e
                })?;
        }

        // Set scan_ssid for hidden networks
        if config.scan_ssid {
            self.set_network(network_id, "scan_ssid", "1")
                .map_err(|e| {
                    let _ = self.remove_network(network_id);
                    e
                })?;
        }

        // Set priority
        if config.priority != 0 {
            self.set_network(network_id, "priority", &config.priority.to_string())
                .map_err(|e| {
                    let _ = self.remove_network(network_id);
                    e
                })?;
        }

        if let Some(ref bssid) = config.bssid {
            self.set_network(network_id, "bssid", bssid).map_err(|e| {
                let _ = self.remove_network(network_id);
                e
            })?;
        }

        if let Some(ref proto) = config.proto {
            self.set_network(network_id, "proto", proto).map_err(|e| {
                let _ = self.remove_network(network_id);
                e
            })?;
        }

        if let Some(ref pairwise) = config.pairwise {
            self.set_network(network_id, "pairwise", pairwise)
                .map_err(|e| {
                    let _ = self.remove_network(network_id);
                    e
                })?;
        }

        if let Some(ref group) = config.group {
            self.set_network(network_id, "group", group).map_err(|e| {
                let _ = self.remove_network(network_id);
                e
            })?;
        }

        // Select and enable the network
        self.select_network(network_id).map_err(|e| {
            let _ = self.remove_network(network_id);
            e
        })?;

        Ok(network_id)
    }

    /// Wait for connection to complete
    ///
    /// Polls the connection state until it reaches COMPLETED or times out
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait
    ///
    /// # Errors
    /// Returns error if connection fails or times out
    pub fn wait_for_connection(&self, timeout: Duration) -> Result<WpaStatus> {
        let start = Instant::now();

        loop {
            if start.elapsed() >= timeout {
                return Err(NetlinkError::Wpa(format!(
                    "Connection timeout after {:?}",
                    timeout
                )));
            }

            let status = self.status()?;

            match status.wpa_state {
                WpaState::Completed => return Ok(status),
                WpaState::Disconnected => {
                    return Err(NetlinkError::Wpa(
                        "Connection failed (disconnected)".to_string(),
                    ))
                }
                WpaState::Unknown => {
                    return Err(NetlinkError::Wpa(format!(
                        "Connection failed (unknown state {:?})",
                        status
                    )))
                }
                _ => {
                    log::debug!(
                        "WPA state {:?} ssid={:?} bssid={:?} elapsed={:?}",
                        status.wpa_state,
                        status.ssid,
                        status.bssid,
                        start.elapsed()
                    );
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }

    /// Ping wpa_supplicant to check if it's responsive
    ///
    /// # Errors
    /// Returns error if wpa_supplicant is not running or not responsive
    pub fn ping(&self) -> Result<()> {
        let response = self.send_command("PING")?;
        if response == "PONG" {
            Ok(())
        } else {
            Err(NetlinkError::Wpa(format!(
                "Unexpected ping response: {}",
                response
            )))
        }
    }

    /// Get signal strength information
    ///
    /// # Errors
    /// Returns error if unable to retrieve signal information
    pub fn signal_poll(&self) -> Result<HashMap<String, String>> {
        let response = self.send_command("SIGNAL_POLL")?;

        let mut info = HashMap::new();
        for line in response.lines() {
            if let Some((key, value)) = line.split_once('=') {
                info.insert(key.to_string(), value.to_string());
            }
        }

        Ok(info)
    }
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut hi: Option<u8> = None;
    let mut saw_hex = false;

    for ch in input.chars() {
        if let Some(val) = ch.to_digit(16) {
            saw_hex = true;
            let val = val as u8;
            if let Some(high) = hi.take() {
                bytes.push((high << 4) | val);
            } else {
                hi = Some(val);
            }
        }
    }

    if !saw_hex {
        return Ok(Vec::new());
    }

    if hi.is_some() {
        return Err(NetlinkError::ParseError {
            what: "BSS IE hex".to_string(),
            reason: "odd-length hex string".to_string(),
        });
    }

    Ok(bytes)
}

/// Check if wpa_supplicant is running for an interface
///
/// # Arguments
/// * `interface` - Network interface name
///
/// # Errors
/// Returns error if unable to check wpa_supplicant status
pub fn is_wpa_running(interface: &str) -> Result<bool> {
    let control_path = format!("/var/run/wpa_supplicant/{}", interface);
    Ok(Path::new(&control_path).exists())
}

/// Start wpa_supplicant for an interface
///
/// This is a helper function that generates a minimal wpa_supplicant.conf
/// and starts the daemon.
///
/// # Arguments
/// * `interface` - Network interface name
/// * `config_path` - Optional path to custom configuration file
///
/// # Errors
/// Returns error if unable to start wpa_supplicant
pub fn start_wpa_supplicant(interface: &str, config_path: Option<&str>) -> Result<()> {
    use std::process::Command;

    if is_wpa_running(interface)? {
        return Ok(());
    }

    let conf_path = if let Some(path) = config_path {
        path.to_string()
    } else {
        // Generate minimal config
        let default_conf = format!("/tmp/wpa_supplicant_{}.conf", interface);
        fs::write(
            &default_conf,
            "ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\n",
        )
        .map_err(|e| NetlinkError::Wpa(format!("Failed to create wpa_supplicant config: {}", e)))?;
        default_conf
    };

    let output = Command::new("wpa_supplicant")
        .args(["-B", "-i", interface, "-c", &conf_path])
        .output()
        .map_err(|e| NetlinkError::Wpa(format!("Failed to start wpa_supplicant: {}", e)))?;

    if !output.status.success() {
        return Err(NetlinkError::Wpa(format!(
            "wpa_supplicant failed to start: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Wait for control socket to appear
    let control_path = format!("/var/run/wpa_supplicant/{}", interface);
    let start = Instant::now();
    while !Path::new(&control_path).exists() {
        if start.elapsed() > Duration::from_secs(5) {
            return Err(NetlinkError::Wpa(
                "wpa_supplicant control socket did not appear".to_string(),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

/// Stop wpa_supplicant for an interface
///
/// # Arguments
/// * `interface` - Network interface name
///
/// # Errors
/// Returns error if unable to stop wpa_supplicant
pub fn stop_wpa_supplicant(interface: &str) -> Result<()> {
    if !is_wpa_running(interface)? {
        return Ok(());
    }

    let mgr = WpaManager::new(interface)?;
    let _ = mgr.send_command("TERMINATE");

    // Wait for socket to disappear
    let control_path = format!("/var/run/wpa_supplicant/{}", interface);
    let start = Instant::now();
    while Path::new(&control_path).exists() {
        if start.elapsed() > Duration::from_secs(5) {
            // Force kill if terminate didn't work
            use crate::process::ProcessManager;
            let pm = ProcessManager::new();
            let _ = pm.kill_pattern(&format!("wpa_supplicant.*{}", interface));
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpa_state_parsing() {
        assert_eq!(WpaState::from_str("COMPLETED"), WpaState::Completed);
        assert_eq!(WpaState::from_str("DISCONNECTED"), WpaState::Disconnected);
        assert_eq!(WpaState::from_str("SCANNING"), WpaState::Scanning);
        assert_eq!(WpaState::from_str("invalid"), WpaState::Unknown);
    }

    #[test]
    fn test_wpa_state_display() {
        assert_eq!(WpaState::Completed.to_string(), "COMPLETED");
        assert_eq!(WpaState::Disconnected.to_string(), "DISCONNECTED");
    }
}
