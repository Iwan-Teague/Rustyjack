//! Pure Rust Access Point (AP) bring-up using nl80211 `START_AP`/`STOP_AP`.
//!
//! This is a minimal in-process AP implementation built on nl80211. WPA2-PSK
//! support is experimental and currently limited to a CCMP-only handshake path
//! (RSN IE + 4-way); WPA3 is not implemented. The goal is to avoid external
//! hostapd/wpa binaries while still providing a working AP for captive-portal /
//! testing flows on constrained devices.
//!
//! ## Features
//! - Create WPA2-PSK or Open access points
//! - Full 802.11 management frame handling
//! - WPA2 4-way handshake implementation
//! - Client association tracking
//! - Multiple SSID support
//!
//! ## Example
//! ```no_run
//! use rustyjack_netlink::hostapd::{AccessPoint, ApConfig, ApSecurity};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ApConfig {
//!         interface: "wlan0".to_string(),
//!         ssid: "MyAP".to_string(),
//!         channel: 6,
//!         security: ApSecurity::Wpa2Psk {
//!             passphrase: "SecurePassword123".to_string(),
//!         },
//!         ..Default::default()
//!     };
//!     
//!     let mut ap = AccessPoint::new(config)?;
//!     ap.start().await?;
//!     
//!     // AP runs in background
//!     tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
//!     
//!     ap.stop().await?;
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::fs;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use neli::consts::nl::{NlmF, NlmFFlags};
use neli::genl::Genlmsghdr;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::GenlBuffer;

use hmac::{Hmac, Mac};
use std::collections::HashMap as StdHashMap;
use std::sync::Mutex as StdMutex;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::error::{NetlinkError, Result};
use crate::wireless::{InterfaceMode, PhyCapabilities, WirelessManager};

use once_cell::sync::Lazy;

// Minimal nl80211 constants needed for START_AP/STOP_AP
const NL80211_GENL_NAME: &str = "nl80211";
const NL80211_GENL_VERSION: u8 = 1;
const NL80211_CMD_START_AP: u8 = 95;
const NL80211_CMD_STOP_AP: u8 = 96;
const NL80211_CMD_NEW_KEY: u8 = 26;
const NL80211_CMD_SET_STATION: u8 = 19;
const NL80211_CMD_DEL_STATION: u8 = 20;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_BEACON_HEAD: u16 = 54;
const NL80211_ATTR_BEACON_TAIL: u16 = 55;
const NL80211_ATTR_PROBE_RESP: u16 = 56;
const NL80211_ATTR_BEACON_INTERVAL: u16 = 74;
const NL80211_ATTR_DTIM_PERIOD: u16 = 75;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_BSS_BASIC_RATES: u16 = 36;
const NL80211_ATTR_PRIVACY: u16 = 14;
const NL80211_ATTR_WPA_VERSIONS: u16 = 48;
const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 15;
const NL80211_ATTR_CIPHER_SUITES_PAIRWISE: u16 = 16;
const NL80211_ATTR_AKM_SUITES: u16 = 17;
const NL80211_ATTR_HIDDEN_SSID: u16 = 103;
const NL80211_HIDDEN_SSID_NOT_IN_USE: u32 = 0;
const NL80211_HIDDEN_SSID_ZERO_LEN: u32 = 1;
#[allow(dead_code)]
const NL80211_HIDDEN_SSID_ZERO_CONTENTS: u32 = 2;
const NL80211_ATTR_KEY_DATA: u16 = 13;
const NL80211_ATTR_KEY_IDX: u16 = 10;
const NL80211_ATTR_KEY_CIPHER: u16 = 12;
const NL80211_ATTR_KEY_TYPE: u16 = 33;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_STA_FLAGS2: u16 = 58;

// EAPOL constants
const ETHERTYPE_EAPOL: u16 = 0x888e;
const EAPOL_TYPE_KEY: u8 = 3;
const WPA2_KEY_DESCRIPTOR: u8 = 2; // RSN
const WPA2_KEY_INFO_KEY_MIC: u16 = 1 << 8;
const WPA2_KEY_INFO_KEY_ACK: u16 = 1 << 7;
const WPA2_KEY_INFO_INSTALL: u16 = 1 << 6;
const WPA2_KEY_INFO_PAIRWISE: u16 = 1 << 3;
const WPA2_KEY_INFO_SECURE: u16 = 1 << 9;
const NL80211_KEYTYPE_GROUP: u8 = 0;
const NL80211_KEYTYPE_PAIRWISE: u8 = 1;
const NL80211_STA_FLAG_AUTHORIZED: u32 = 1 << 0;
const CIPHER_SUITE_CCMP: u32 = 0x000f_ac_04;
const AKM_SUITE_PSK: u32 = 0x000f_ac_02;
const WPA_VERSION_2: u32 = 2;
const NL80211_CHAN_WIDTH_20_NOHT: u32 = 0;
const NL80211_CHAN_WIDTH_20: u32 = 1;
const NL80211_CHAN_NO_HT: u32 = 0;
const NL80211_CHAN_HT20: u32 = 1;
const NL80211_DFS_AVAILABLE: u8 = 2;
type HmacSha1 = Hmac<sha1::Sha1>;

/// Access Point security mode
#[derive(Debug, Clone)]
pub enum ApSecurity {
    /// Open network (no encryption)
    Open,
    /// WPA2-PSK with passphrase
    Wpa2Psk { passphrase: String },
}

impl ApSecurity {
    /// Validate security configuration
    pub fn validate(&self) -> Result<()> {
        match self {
            ApSecurity::Open => Ok(()),
            ApSecurity::Wpa2Psk { passphrase } => {
                if passphrase.len() < 8 || passphrase.len() > 63 {
                    return Err(NetlinkError::InvalidInput(
                        "WPA2 passphrase must be 8-63 characters".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Access Point configuration
#[derive(Debug, Clone)]
pub struct ApConfig {
    /// Network interface name (must support AP mode)
    pub interface: String,
    /// SSID to broadcast
    pub ssid: String,
    /// WiFi channel (1-13 for 2.4GHz, 36-165 for 5GHz)
    pub channel: u8,
    /// Security configuration
    pub security: ApSecurity,
    /// Hide SSID (don't broadcast in beacons)
    pub hidden: bool,
    /// Beacon interval in ms (default: 100ms)
    pub beacon_interval: u16,
    /// Maximum number of clients (0 = unlimited)
    pub max_clients: u32,
    /// DTIM period (delivery traffic indication message)
    pub dtim_period: u8,
    /// Hardware mode (g = 2.4GHz 802.11g, a = 5GHz 802.11a)
    pub hw_mode: HardwareMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareMode {
    /// 802.11g (2.4 GHz)
    G,
    /// 802.11a (5 GHz)
    A,
    /// 802.11n (2.4 or 5 GHz)
    N,
}

impl Default for ApConfig {
    fn default() -> Self {
        Self {
            interface: "wlan0".to_string(),
            ssid: "rustyjack".to_string(),
            channel: 6,
            security: ApSecurity::Open,
            hidden: false,
            beacon_interval: 100,
            max_clients: 0,
            dtim_period: 2,
            hw_mode: HardwareMode::G,
        }
    }
}

impl ApConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.ssid.is_empty() || self.ssid.len() > 32 {
            return Err(NetlinkError::InvalidInput(
                "SSID must be 1-32 characters".to_string(),
            ));
        }

        // Validate channel ranges
        match self.hw_mode {
            HardwareMode::G | HardwareMode::N if self.channel <= 14 => {
                if self.channel == 0 || self.channel > 14 {
                    return Err(NetlinkError::InvalidInput(
                        "2.4 GHz channel must be 1-14".to_string(),
                    ));
                }
            }
            HardwareMode::A | HardwareMode::N if self.channel > 14 => {
                // 5 GHz channels (simplified validation)
                if ![
                    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132,
                    136, 140, 144, 149, 153, 157, 161, 165,
                ]
                .contains(&self.channel)
                {
                    return Err(NetlinkError::InvalidInput(
                        "Invalid 5 GHz channel".to_string(),
                    ));
                }
            }
            _ => {
                return Err(NetlinkError::InvalidInput(
                    "Invalid channel/mode combination".to_string(),
                ));
            }
        }

        self.security.validate()?;
        Ok(())
    }
}

/// Connected client information
#[derive(Debug, Clone)]
pub struct ApClient {
    /// Client MAC address
    pub mac_address: [u8; 6],
    /// Association ID
    pub aid: u16,
    /// Time of association
    pub associated_at: Instant,
    /// Client capabilities
    pub capabilities: u16,
    /// Supported rates
    pub rates: Vec<u8>,
    /// WPA2 handshake state
    pub wpa_state: WpaState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpaState {
    /// No WPA (open network)
    None,
    /// Waiting for 4-way handshake
    NotAuthenticated,
    /// PTK derived, waiting for confirmation
    Authenticating,
    /// Fully authenticated
    Authenticated,
}

/// Access Point statistics
#[derive(Debug, Clone, Default)]
pub struct ApStats {
    /// Number of clients currently connected
    pub clients_connected: u32,
    /// Total number of association attempts
    pub association_attempts: u64,
    /// Successful associations
    pub associations_success: u64,
    /// Failed associations
    pub associations_failed: u64,
    /// Beacons sent
    pub beacons_sent: u64,
    /// Authentication requests received
    pub auth_requests: u64,
    /// Deauthentication frames sent
    pub deauth_sent: u64,
    /// Data frames transmitted
    pub data_tx: u64,
    /// Data frames received
    pub data_rx: u64,
    /// Uptime
    pub uptime: Duration,
}

/// Access Point implementation
pub struct AccessPoint {
    config: ApConfig,
    clients: Arc<RwLock<HashMap<[u8; 6], ApClient>>>,
    stats: Arc<Mutex<ApStats>>,
    running: Arc<Mutex<bool>>,
    wireless_mgr: WirelessManager,
    start_time: Option<Instant>,
    eapol_fd: Option<RawFd>,
    eapol_task: Option<JoinHandle<()>>,
    pmk: Option<[u8; 32]>,
    ifindex: Option<u32>,
}

#[derive(Debug, Clone)]
struct StaHandshake {
    anonce: [u8; 32],
    ptk: Option<[u8; 64]>,
    last_replay: u64,
    authorized: bool,
}

static LAST_AP_ERROR: Lazy<std::sync::Mutex<Option<String>>> =
    Lazy::new(|| std::sync::Mutex::new(None));

fn record_ap_error(msg: impl Into<String>) {
    let mut guard = LAST_AP_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(msg.into());
}

/// Retrieve and clear the last AP error recorded by the WPA/EAPOL handler.
pub fn take_last_ap_error() -> Option<String> {
    let mut guard = LAST_AP_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    guard.take()
}

impl AccessPoint {
    /// Create a new Access Point with the given configuration
    ///
    /// # Errors
    /// - `InvalidInput`: Configuration validation failed
    /// - `DeviceNotFound`: Interface doesn't exist
    /// - `OperationNotSupported`: Interface doesn't support AP mode
    pub fn new(config: ApConfig) -> Result<Self> {
        config.validate()?;

        let wireless_mgr = WirelessManager::new()?;

        Ok(Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Mutex::new(ApStats::default())),
            running: Arc::new(Mutex::new(false)),
            wireless_mgr,
            start_time: None,
            eapol_fd: None,
            eapol_task: None,
            pmk: None,
            ifindex: None,
        })
    }

    /// Start the Access Point
    ///
    /// This will:
    /// 1. Verify interface supports AP mode
    /// 2. Set interface to AP mode
    /// 3. Configure channel
    /// 4. Start beacon transmission
    /// 5. Start management frame handler
    ///
    /// # Errors
    /// - `OperationNotSupported`: Interface doesn't support AP mode
    /// - `DeviceNotFound`: Interface doesn't exist
    /// - `PermissionDenied`: Need CAP_NET_ADMIN
    pub async fn start(&mut self) -> Result<()> {
        log::info!(
            "Starting Access Point: SSID={}, channel={}, beacon={} TU, dtim={}",
            self.config.ssid,
            self.config.channel,
            self.config.beacon_interval,
            self.config.dtim_period
        );

        // Check if interface supports AP mode
        let phy_caps = self
            .wireless_mgr
            .get_phy_capabilities(&self.config.interface)?;
        let ap_supported = phy_caps.supports_ap
            || phy_caps
                .supported_modes
                .iter()
                .any(|m| *m == InterfaceMode::AccessPoint);
        log::info!(
            "Phy {} (wiphy {}) caps: supports_ap={} modes={:?}",
            phy_caps.name,
            phy_caps.wiphy,
            phy_caps.supports_ap,
            phy_caps.supported_modes
        );

        if !ap_supported {
            return Err(NetlinkError::OperationNotSupported(format!(
                "Interface {} does not support AP mode. Supported modes: {:?}",
                self.config.interface, phy_caps.supported_modes
            )));
        }

        // Force interface into AP mode via nl80211
        let iface_info = self
            .wireless_mgr
            .get_interface_info(&self.config.interface)?;
        if iface_info.mode != Some(InterfaceMode::AccessPoint) {
            self.wireless_mgr
                .set_mode(&self.config.interface, InterfaceMode::AccessPoint)
                .map_err(|e| NetlinkError::OperationFailed(format!(
                    "Failed to set {} to AP mode via nl80211: {}. Ensure the interface is down and unmanaged before starting the AP.",
                    self.config.interface, e
                )))?;
        } else {
            log::debug!(
                "Interface {} already in AP mode; skipping mode change",
                self.config.interface
            );
        }

        // Set channel using nl80211 (best effort; START_AP also carries frequency)
        if let Err(e) = self
            .wireless_mgr
            .set_channel(&self.config.interface, self.config.channel)
        {
            log::warn!(
                "set_channel {} on {} via nl80211 failed (continuing, START_AP will set freq): {}",
                self.config.channel,
                self.config.interface,
                e
            );
        }

        let ifindex = read_ifindex(&self.config.interface)?;
        let bssid = read_interface_mac(&self.config.interface)?;
        log::info!(
            "AP context: iface={} ifindex={} bssid={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} chan={} beacon_int={} dtim={} security={:?}",
            self.config.interface,
            ifindex,
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
            self.config.channel,
            self.config.beacon_interval,
            self.config.dtim_period,
            self.config.security
        );

        // Build candidate channels using wiphy/regdom constraints
        let candidate_channels = build_candidate_channels(&self.config, &phy_caps);

        // Attempt set_channel for each candidate (best-effort), but do not filter
        let mut attempt_channels = Vec::new();
        for ch in candidate_channels {
            match self
                .wireless_mgr
                .set_channel(&self.config.interface, ch)
            {
                Ok(_) => {
                    log::info!(
                        "Channel {} (freq {:?}) accepted by driver (NoHT assumed)",
                        ch,
                        channel_to_frequency(ch)
                    );
                }
                Err(e) => {
                    log::warn!(
                        "Channel {} set_channel failed (continuing with START_AP chandef): {}",
                        ch,
                        e
                    );
                }
            }
            attempt_channels.push(ch);
        }

        if attempt_channels.is_empty() {
            let regdom = read_regdom_alpha2()
                .map(|code| String::from_utf8_lossy(&code).to_string());
            let msg = if let Some(code) = regdom {
                format!(
                    "No valid channels available for interface {} (regdom={} check regdom/driver)",
                    self.config.interface, code
                )
            } else {
                format!(
                    "No valid channels available for interface {} (check regdom/driver)",
                    self.config.interface
                )
            };
            log::error!("{}", msg);
            record_ap_error(&msg);
            return Err(NetlinkError::OperationFailed(msg));
        }

        // Attempt START_AP over validated channels
        let mut chosen_channel = self.config.channel;
        let mut last_err: Option<String> = None;
        let dtim_period = if self.config.dtim_period == 0 {
            1
        } else {
            self.config.dtim_period
        };
        for ch in attempt_channels.iter() {
            let frames = build_ap_frame_bundle(&self.config, bssid, *ch, Some(&phy_caps))?;
            log::debug!(
                "Beacon built for channel {}: head_len={} tail_len={} ssid_len={} basic_rates={} hidden={}",
                ch,
                frames.beacon_head.len(),
                frames.beacon_tail.len(),
                frames.ssid_bytes.len(),
                frames.basic_rates.len(),
                self.config.hidden
            );
            log::info!(
                "Attempting START_AP on validated channel {} (freq {:?}, width={})",
                ch,
                channel_to_frequency(*ch),
                if frames.ht_enabled { "HT20" } else { "NOHT" }
            );
            eprintln!(
                "[HOSTAPD] Trying START_AP on channel {} ({}MHz)",
                ch,
                channel_to_frequency(*ch).unwrap_or(0)
            );
            let wpa_enabled = matches!(self.config.security, ApSecurity::Wpa2Psk { .. });
            let hidden_ssid = if self.config.hidden {
                NL80211_HIDDEN_SSID_ZERO_LEN
            } else {
                NL80211_HIDDEN_SSID_NOT_IN_USE
            };
            match send_start_ap(
                ifindex,
                *ch,
                self.config.beacon_interval,
                dtim_period,
                self.config.ssid.as_bytes(),
                &frames.beacon_head,
                &frames.beacon_tail,
                &frames.probe_resp,
                hidden_ssid,
                wpa_enabled,
                &frames.basic_rates,
                frames.ht_enabled,
            ) {
                Ok(_) => {
                    chosen_channel = *ch;
                    last_err = None;
                    eprintln!("[HOSTAPD] START_AP succeeded on channel {}", ch);
                    break;
                }
                Err(e) => {
                    let msg = format!("START_AP failed on channel {}: {}", ch, e);
                    log::warn!("{}", msg);
                    eprintln!("[HOSTAPD] START_AP failed on channel {}: {}", ch, e);
                    last_err = Some(msg);
                }
            }
        }

        if let Some(err) = last_err {
            record_ap_error(&err);
            return Err(NetlinkError::OperationFailed(err));
        }

        self.config.channel = chosen_channel;
        log::info!(
            "START_AP succeeded on channel {} (width={})",
            chosen_channel,
            if self.config.hw_mode == HardwareMode::N {
                "HT20"
            } else {
                "NOHT"
            }
        );

        *self.running.lock().await = true;
        self.start_time = Some(Instant::now());
        self.ifindex = Some(ifindex);

        // Start EAPOL listener for WPA2-PSK to capture handshake frames
        if matches!(self.config.security, ApSecurity::Wpa2Psk { .. }) {
            // Derive PMK from passphrase/SSID
            if let ApSecurity::Wpa2Psk { passphrase } = &self.config.security {
                self.pmk = Some(generate_pmk(passphrase, &self.config.ssid)?);
            }
            match open_eapol_socket(ifindex) {
                Ok(fd) => {
                    let running = Arc::clone(&self.running);
                    let stats = Arc::clone(&self.stats);
                    let clients = Arc::clone(&self.clients);
                    let iface = self.config.interface.clone();
                    let pmk = self.pmk;
                    let bssid = bssid;
                    self.eapol_task = Some(spawn_eapol_task(
                        fd, running, stats, clients, iface, pmk, bssid, ifindex,
                    ));
                    self.eapol_fd = Some(fd);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to open EAPOL socket on {}: {} (WPA handshake will not proceed)",
                        self.config.interface,
                        e
                    );
                }
            }
        }

        log::info!(
            "Access Point started successfully on {} ({})",
            self.config.interface,
            match self.config.security {
                ApSecurity::Open => "open",
                ApSecurity::Wpa2Psk { .. } => "WPA2-PSK (handshake pending)",
            }
        );
        Ok(())
    }

    /// Stop the Access Point
    pub async fn stop(&mut self) -> Result<()> {
        log::info!("Stopping Access Point");

        *self.running.lock().await = false;

        // Best-effort deauth before stopping AP
        if let Some(ifindex) = self.ifindex {
            self.disconnect_all_clients().await;
            if let Err(e) = send_stop_ap(ifindex) {
                log::warn!("STOP_AP failed for ifindex {}: {}", ifindex, e);
            } else {
                log::info!("STOP_AP sent for ifindex {}", ifindex);
            }
        }
        self.ifindex = None;
        if let Some(fd) = self.eapol_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
        if let Some(task) = self.eapol_task.take() {
            let _ = task.abort();
        }

        // Disconnect all clients
        self.disconnect_all_clients().await;

        log::info!("Access Point stopped");
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> ApStats {
        let mut stats = self.stats.lock().await.clone();
        if let Some(start) = self.start_time {
            stats.uptime = start.elapsed();
        }
        stats.clients_connected = self.clients.read().await.len() as u32;
        stats
    }

    /// Get list of connected clients
    pub async fn get_clients(&self) -> Vec<ApClient> {
        self.clients.read().await.values().cloned().collect()
    }

    /// Disconnect a specific client
    pub async fn disconnect_client(&self, mac: &[u8; 6]) -> Result<()> {
        if let Some(_client) = self.clients.write().await.remove(mac) {
            {
                let mut stats = self.stats.lock().await;
                stats.deauth_sent += 1;
            }
            if let Some(ifindex) = self.ifindex {
                let _ = deauth_station(ifindex, mac);
            }
            log::info!(
                "Disconnected client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
        }
        Ok(())
    }

    /// Disconnect all clients
    async fn disconnect_all_clients(&self) {
        let clients: Vec<[u8; 6]> = self.clients.read().await.keys().copied().collect();
        for mac in clients {
            let _ = self.disconnect_client(&mac).await;
        }
    }

    /// Check if AP is running
    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}

fn send_start_ap(
    ifindex: u32,
    channel: u8,
    beacon_interval_tu: u16,
    dtim_period: u8,
    ssid: &[u8],
    beacon_head: &[u8],
    beacon_tail: &[u8],
    probe_resp: &[u8],
    hidden_ssid: u32,
    wpa_enabled: bool,
    basic_rates: &[u32],
    ht_enabled: bool,
) -> Result<()> {
    struct StartApAttempt {
        include_channel_type: bool,
        include_channel_width: bool,
        label: String,
    }

    let channel_attempts = [
        (true, false, "chandef (channel_width)"),
        (false, true, "legacy channel_type"),
    ];

    let mut attempts: Vec<StartApAttempt> = Vec::new();
    for (include_channel_width, include_channel_type, channel_label) in channel_attempts.iter() {
        attempts.push(StartApAttempt {
            include_channel_type: *include_channel_type,
            include_channel_width: *include_channel_width,
            label: format!("{} + full frames", channel_label),
        });
    }
    let mut last_err: Option<NetlinkError> = None;
    for attempt in attempts.iter() {
        log::info!("START_AP attempt using {}", attempt.label);
        eprintln!("[HOSTAPD] START_AP using {}", attempt.label);
        match send_start_ap_inner(
            ifindex,
            channel,
            beacon_interval_tu,
            dtim_period,
            ssid,
            beacon_head,
            beacon_tail,
            probe_resp,
            hidden_ssid,
            attempt.include_channel_type,
            attempt.include_channel_width,
            true,
            true,
            true,
            wpa_enabled,
            basic_rates,
            ht_enabled,
        ) {
            Ok(()) => return Ok(()),
            Err(err) => {
                if is_retryable_start_ap(&err) {
                    log::warn!("START_AP failed with {}; retrying", err);
                    eprintln!("[HOSTAPD] START_AP failed with {}; retrying", err);
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        NetlinkError::OperationFailed("START_AP failed after retries".to_string())
    }))
}

fn is_retryable_start_ap(err: &NetlinkError) -> bool {
    match err {
        NetlinkError::OperationFailed(msg) => {
            msg.contains("errno 34")
                || msg.contains("os error 34")
                || msg.contains("errno 22")
                || msg.contains("os error 22")
        }
        _ => false,
    }
}

fn send_start_ap_inner(
    ifindex: u32,
    channel: u8,
    beacon_interval_tu: u16,
    dtim_period: u8,
    ssid: &[u8],
    beacon_head: &[u8],
    beacon_tail: &[u8],
    probe_resp: &[u8],
    hidden_ssid: u32,
    include_channel_type: bool,
    include_channel_width: bool,
    include_basic_rates: bool,
    include_probe_resp: bool,
    include_beacon_tail: bool,
    wpa_enabled: bool,
    basic_rates: &[u32],
    ht_enabled: bool,
) -> Result<()> {
    let freq = channel_to_frequency(channel)
        .ok_or_else(|| NetlinkError::InvalidInput(format!("Unsupported channel {}", channel)))?;

    log::info!(
        "START_AP params: ifindex={} chan={} freq={} beacon_int={} dtim={} ssid_len={} head_len={} tail_len={} probe_len={} basic_rates_len={} channel_type={} channel_width={} basic_rates={} probe_resp={} beacon_tail={} wpa={}",
        ifindex,
        channel,
        freq,
        beacon_interval_tu,
        dtim_period,
        ssid.len(),
        beacon_head.len(),
        beacon_tail.len(),
        probe_resp.len(),
        basic_rates.len(),
        include_channel_type,
        include_channel_width,
        include_basic_rates,
        include_probe_resp,
        include_beacon_tail,
        wpa_enabled
    );

    let mut sock = NlSocketHandle::connect(neli::consts::socket::NlFamily::Generic, None, &[])
        .map_err(|e| {
            NetlinkError::ConnectionFailed(format!("Failed to open nl80211 socket: {}", e))
        })?;
    let family_id = sock.resolve_genl_family(NL80211_GENL_NAME).map_err(|e| {
        NetlinkError::ConnectionFailed(format!("Failed to resolve nl80211 family: {}", e))
    })?;

    let mut attrs = GenlBuffer::new();
    let mut attr_log: Vec<String> = Vec::new();
    let mut log_attr = |name: &str, len: usize, detail: Option<String>| {
        let entry = if let Some(detail) = detail {
            format!("{}(len={} {})", name, len, detail)
        } else {
            format!("{}(len={})", name, len)
        };
        attr_log.push(entry);
    };
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
        })?,
    );
    log_attr("IFINDEX", 4, Some(format!("ifindex={}", ifindex)));
    attrs.push(
        neli::genl::Nlattr::new(
            false,
            false,
            NL80211_ATTR_BEACON_INTERVAL,
            beacon_interval_tu as u32,
        )
        .map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build beacon interval attr: {}", e))
        })?,
    );
    log_attr(
        "BEACON_INTERVAL",
        4,
        Some(format!("beacon_interval={}", beacon_interval_tu)),
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_DTIM_PERIOD, dtim_period as u32)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build DTIM attr: {}", e))
            })?,
    );
    log_attr("DTIM_PERIOD", 4, Some(format!("dtim={}", dtim_period)));
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_SSID, ssid).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build SSID attr: {}", e))
        })?,
    );
    log_attr(
        "SSID",
        ssid.len(),
        Some(format!("ssid={}", String::from_utf8_lossy(ssid))),
    );
    if hidden_ssid != NL80211_HIDDEN_SSID_NOT_IN_USE {
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_HIDDEN_SSID, hidden_ssid).map_err(
                |e| {
                    NetlinkError::OperationFailed(format!(
                        "Failed to build hidden SSID attr: {}",
                        e
                    ))
                },
            )?,
        );
        log_attr(
            "HIDDEN_SSID",
            4,
            Some(format!("hidden={}", hidden_ssid)),
        );
    }
    if include_basic_rates && !basic_rates.is_empty() {
        let basic_rates_bytes = basic_rates_to_bytes(basic_rates);
        if basic_rates_bytes.is_empty() {
            log::warn!(
                "START_AP basic rates list empty after conversion (input={:?})",
                basic_rates
            );
        } else {
            let basic_rates_len = basic_rates_bytes.len();
            attrs.push(
                neli::genl::Nlattr::new(
                    false,
                    false,
                    NL80211_ATTR_BSS_BASIC_RATES,
                    basic_rates_bytes,
                )
                .map_err(|e| {
                    NetlinkError::OperationFailed(format!(
                        "Failed to build basic rates attr: {}",
                        e
                    ))
                })?,
            );
            log_attr(
                "BSS_BASIC_RATES",
                basic_rates_len,
                Some(format!("rates_100kbps={:?}", basic_rates)),
            );
        }
    }
    if wpa_enabled {
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_PRIVACY, &[] as &[u8]).map_err(
                |e| NetlinkError::OperationFailed(format!("Failed to build privacy attr: {}", e)),
            )?,
        );
        log_attr("PRIVACY", 0, None);
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_WPA_VERSIONS, WPA_VERSION_2)
                .map_err(|e| {
                    NetlinkError::OperationFailed(format!("Failed to build WPA versions attr: {}", e))
                })?,
        );
        log_attr("WPA_VERSIONS", 4, Some("WPA2".to_string()));
        attrs.push(
            neli::genl::Nlattr::new(
                false,
                false,
                NL80211_ATTR_CIPHER_SUITE_GROUP,
                CIPHER_SUITE_CCMP,
            )
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build group cipher attr: {}", e))
            })?,
        );
        log_attr("CIPHER_GROUP", 4, Some("CCMP".to_string()));
        let pairwise = u32_list_bytes(&[CIPHER_SUITE_CCMP]);
        let pairwise_len = pairwise.len();
        attrs.push(
            neli::genl::Nlattr::new(
                false,
                false,
                NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                pairwise,
            )
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build pairwise cipher attr: {}", e))
            })?,
        );
        log_attr("CIPHER_PAIRWISE", pairwise_len, Some("CCMP".to_string()));
        let akm = u32_list_bytes(&[AKM_SUITE_PSK]);
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_AKM_SUITES, akm).map_err(
                |e| NetlinkError::OperationFailed(format!("Failed to build AKM suites attr: {}", e)),
            )?,
        );
        log_attr("AKM_SUITES", 4, Some("PSK".to_string()));
    }
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_BEACON_HEAD, beacon_head).map_err(
            |e| NetlinkError::OperationFailed(format!("Failed to build beacon head attr: {}", e)),
        )?,
    );
    log_attr("BEACON_HEAD", beacon_head.len(), None);
    if include_beacon_tail && !beacon_tail.is_empty() {
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_BEACON_TAIL, beacon_tail).map_err(
                |e| {
                    NetlinkError::OperationFailed(format!(
                        "Failed to build beacon tail attr: {}",
                        e
                    ))
                },
            )?,
        );
        log_attr("BEACON_TAIL", beacon_tail.len(), None);
    } else {
        if !include_beacon_tail {
            log::debug!("START_AP beacon tail omitted by attempt");
        } else {
            log::debug!("START_AP beacon tail empty; skipping NL80211_ATTR_BEACON_TAIL");
        }
    }
    if include_probe_resp && !probe_resp.is_empty() {
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_PROBE_RESP, probe_resp).map_err(
                |e| {
                    NetlinkError::OperationFailed(format!(
                        "Failed to build probe response attr: {}",
                        e
                    ))
                },
            )?,
        );
        log_attr("PROBE_RESP", probe_resp.len(), None);
    }
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_WIPHY_FREQ, freq).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build freq attr: {}", e))
        })?,
    );
    log_attr("WIPHY_FREQ", 4, Some(format!("freq={}", freq)));
    let channel_width = if ht_enabled {
        NL80211_CHAN_WIDTH_20
    } else {
        NL80211_CHAN_WIDTH_20_NOHT
    };
    if include_channel_type {
        let chan_type = if ht_enabled { NL80211_CHAN_HT20 } else { NL80211_CHAN_NO_HT };
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_WIPHY_CHANNEL_TYPE, chan_type)
                .map_err(|e| {
                    NetlinkError::OperationFailed(format!(
                        "Failed to build channel type attr: {}",
                        e
                    ))
                })?,
        );
        log_attr(
            "CHANNEL_TYPE",
            4,
            Some(if ht_enabled { "HT20" } else { "NO_HT" }.to_string()),
        );
    }
    if include_channel_width {
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_CHANNEL_WIDTH, channel_width)
                .map_err(|e| {
                    NetlinkError::OperationFailed(format!(
                        "Failed to build channel width attr: {}",
                        e
                    ))
                })?,
        );
        log_attr(
            "CHANNEL_WIDTH",
            4,
            Some(if ht_enabled { "20" } else { "20_NOHT" }.to_string()),
        );
        if channel_width != NL80211_CHAN_WIDTH_20_NOHT {
            attrs.push(
                neli::genl::Nlattr::new(false, false, NL80211_ATTR_CENTER_FREQ1, freq).map_err(
                    |e| {
                        NetlinkError::OperationFailed(format!(
                            "Failed to build center freq1 attr: {}",
                            e
                        ))
                    },
                )?,
            );
            log_attr("CENTER_FREQ1", 4, Some(format!("freq={}", freq)));
        }
    }

    log::debug!(
        "START_AP building nl80211 frame: ifindex={} attrs={}",
        ifindex,
        attrs.len()
    );
    if !attr_log.is_empty() {
        log::debug!("START_AP attrs: {}", attr_log.join(", "));
    }

    let log_failure_details = || {
        if !attr_log.is_empty() {
            let attrs = attr_log.join(", ");
            log::error!("START_AP attrs: {}", attrs);
            eprintln!("[HOSTAPD] START_AP attrs: {}", attrs);
        }
        log_ie_summary("BEACON_HEAD", beacon_head, 36);
        let head_ies = parse_ie_list(beacon_head, 36);
        if head_ies.is_empty() {
            eprintln!(
                "[HOSTAPD] START_AP BEACON_HEAD IEs: none (len={})",
                beacon_head.len()
            );
        } else {
            eprintln!(
                "[HOSTAPD] START_AP BEACON_HEAD IEs (len={}): {}",
                beacon_head.len(),
                format_ie_list(&head_ies)
            );
        }
        if !beacon_tail.is_empty() {
            log_ie_summary("BEACON_TAIL", beacon_tail, 0);
            let tail_ies = parse_ie_list(beacon_tail, 0);
            if !tail_ies.is_empty() {
                eprintln!(
                    "[HOSTAPD] START_AP BEACON_TAIL IEs (len={}): {}",
                    beacon_tail.len(),
                    format_ie_list(&tail_ies)
                );
            }
        } else {
            log::error!("START_AP BEACON_TAIL len=0");
            eprintln!("[HOSTAPD] START_AP BEACON_TAIL len=0");
        }
        if !probe_resp.is_empty() {
            log_ie_summary("PROBE_RESP", probe_resp, 36);
            let probe_ies = parse_ie_list(probe_resp, 36);
            if !probe_ies.is_empty() {
                eprintln!(
                    "[HOSTAPD] START_AP PROBE_RESP IEs (len={}): {}",
                    probe_resp.len(),
                    format_ie_list(&probe_ies)
                );
            }
        } else {
            log::error!("START_AP PROBE_RESP len=0");
            eprintln!("[HOSTAPD] START_AP PROBE_RESP len=0");
        }
    };

    let genlhdr = Genlmsghdr::new(NL80211_CMD_START_AP, NL80211_GENL_VERSION, attrs);
    let nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    );

    sock.send(nlhdr).map_err(|e| {
        log_failure_details();
        NetlinkError::OperationFailed(format!("Failed to send START_AP: {}", e))
    })?;

    // Consume replies until ACK or ERR
    let resp: Option<Nlmsghdr<u16, Genlmsghdr<u8, u16>>> = sock.recv().map_err(|e| {
        log_failure_details();
        NetlinkError::OperationFailed(format!("Failed to receive START_AP response: {}", e))
    })?;

    let resp = resp.ok_or_else(|| {
        log_failure_details();
        NetlinkError::OperationFailed("No START_AP response received from kernel".to_string())
    })?;

    if resp.nl_type == neli::consts::nl::Nlmsg::Error.into() {
        match resp.nl_payload {
            NlPayload::Err(err) if err.error == 0 => {
                log::debug!("START_AP acked by kernel");
                return Ok(());
            }
            NlPayload::Ack(ack) if ack.error == 0 => {
                log::debug!("START_AP ack payload received");
                return Ok(());
            }
            NlPayload::Err(err) => {
                let errno = err.error.abs();
                let io_err = std::io::Error::from_raw_os_error(errno);
                log::error!(
                    "START_AP rejected: errno={} ({}) raw_err={:?}",
                    errno,
                    io_err,
                    err
                );
                log_failure_details();
                let hint = if errno == 34 {
                    // ERANGE - common with incompatible channel/bandwidth settings
                    " (ERANGE: channel/bandwidth not supported by driver - try different channel or NO_HT mode)"
                } else {
                    ""
                };
                return Err(NetlinkError::OperationFailed(format!(
                    "Kernel rejected START_AP: {} (errno {}){}",
                    io_err, errno, hint
                )));
            }
            NlPayload::Ack(ack) => {
                let errno = ack.error.abs();
                let io_err = std::io::Error::from_raw_os_error(errno);
                log::error!(
                    "START_AP rejected (ack err): errno={} ({}) raw_ack={:?}",
                    errno,
                    io_err,
                    ack
                );
                log_failure_details();
                return Err(NetlinkError::OperationFailed(format!(
                    "Kernel rejected START_AP (ack err): {} (errno {})",
                    io_err, errno
                )));
            }
            other => {
                log::error!("START_AP rejected: unexpected payload {:?}", other);
                log_failure_details();
                return Err(NetlinkError::OperationFailed(format!(
                    "Kernel rejected START_AP (unexpected payload {:?})",
                    other
                )));
            }
        }
    }

    Ok(())
}

fn send_stop_ap(ifindex: u32) -> Result<()> {
    let mut sock = NlSocketHandle::connect(neli::consts::socket::NlFamily::Generic, None, &[])
        .map_err(|e| {
            NetlinkError::ConnectionFailed(format!("Failed to open nl80211 socket: {}", e))
        })?;
    let family_id = sock.resolve_genl_family(NL80211_GENL_NAME).map_err(|e| {
        NetlinkError::ConnectionFailed(format!("Failed to resolve nl80211 family: {}", e))
    })?;

    let mut attrs = GenlBuffer::new();
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
        })?,
    );

    let genlhdr = Genlmsghdr::new(NL80211_CMD_STOP_AP, NL80211_GENL_VERSION, attrs);
    let nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    );

    sock.send(nlhdr)
        .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send STOP_AP: {}", e)))?;

    Ok(())
}

#[derive(Debug, Clone)]
struct ApFrameBundle {
    beacon_head: Vec<u8>,
    beacon_tail: Vec<u8>,
    probe_resp: Vec<u8>,
    ssid_bytes: Vec<u8>,
    basic_rates: Vec<u32>,
    ht_enabled: bool,
}

fn build_ap_frame_bundle(
    config: &ApConfig,
    bssid: [u8; 6],
    channel: u8,
    phy_caps: Option<&PhyCapabilities>,
) -> Result<ApFrameBundle> {
    let rate_sets = build_rate_sets(config, channel, phy_caps)?;
    let ht_info = select_ht_info(config, channel, phy_caps);
    let ht_enabled = ht_info.is_some();
    let wmm_enabled = ht_info.is_some();
    let capab = build_capability_info(config, channel, &rate_sets, wmm_enabled);

    log::debug!(
        "AP rates channel {}: supported={:?} extended={:?} basic={:?}",
        channel,
        rate_sets.supported,
        rate_sets.extended,
        rate_sets.basic
    );
    log::debug!(
        "AP frame caps channel {}: capab=0x{:04x} wmm={} ht={}",
        channel,
        capab,
        wmm_enabled,
        ht_info.is_some()
    );

    let (beacon_head, beacon_tail, ssid_bytes) = build_beacon_frames(
        config,
        bssid,
        channel,
        &rate_sets,
        capab,
        ht_info.as_ref(),
        phy_caps,
    )?;
    let probe_resp = build_probe_response_frame(
        config,
        bssid,
        channel,
        &rate_sets,
        capab,
        ht_info.as_ref(),
        phy_caps,
    )?;

    Ok(ApFrameBundle {
        beacon_head,
        beacon_tail,
        probe_resp,
        ssid_bytes,
        basic_rates: rate_sets.basic.clone(),
        ht_enabled,
    })
}

fn build_beacon_frames(
    config: &ApConfig,
    bssid: [u8; 6],
    channel: u8,
    rate_sets: &RateSets,
    capab: u16,
    ht_info: Option<&HtInfo>,
    phy_caps: Option<&PhyCapabilities>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let wmm_enabled = ht_info.is_some();

    let mut head = Vec::new();
    // 802.11 beacon header
    head.extend_from_slice(&[0x80, 0x00]); // Frame control
    head.extend_from_slice(&[0x00, 0x00]); // Duration
    head.extend_from_slice(&[0xff; 6]); // DA broadcast
    head.extend_from_slice(&bssid); // SA
    head.extend_from_slice(&bssid); // BSSID
    head.extend_from_slice(&[0x00, 0x00]); // Seq ctrl
    head.extend_from_slice(&[0x00; 8]); // Timestamp (kernel fills)
    head.extend_from_slice(&config.beacon_interval.to_le_bytes()); // Beacon interval
    head.extend_from_slice(&capab.to_le_bytes());

    // SSID IE (hidden => zero-length)
    let ssid_bytes = if config.hidden {
        Vec::new()
    } else {
        config.ssid.as_bytes().to_vec()
    };
    head.push(0); // SSID ID
    head.push(ssid_bytes.len() as u8);
    head.extend_from_slice(&ssid_bytes);

    // Supported rates IE
    if rate_sets.supported.is_empty() {
        return Err(NetlinkError::InvalidInput(
            "No supported rates available for beacon".to_string(),
        ));
    }
    head.push(1);
    head.push(rate_sets.supported.len() as u8);
    head.extend_from_slice(&rate_sets.supported);

    // DS Parameter Set (channel)
    head.push(3);
    head.push(1);
    head.push(channel);

    // TIM IE (must be in beacon head)
    let dtim_period = if config.dtim_period == 0 {
        1
    } else {
        config.dtim_period
    };
    head.extend_from_slice(&build_tim_ie(dtim_period));

    let mut tail = Vec::new();
    if channel <= 14 && config.hw_mode != HardwareMode::A {
        tail.extend_from_slice(&build_erp_ie());
    }

    // Extended supported rates IE (after TIM)
    if !rate_sets.extended.is_empty() {
        tail.push(50);
        tail.push(rate_sets.extended.len() as u8);
        tail.extend_from_slice(&rate_sets.extended);
    }

    if let Some(country) = build_country_ie(channel, phy_caps) {
        tail.extend_from_slice(&country);
    }

    if matches!(config.security, ApSecurity::Wpa2Psk { .. }) {
        let rsn = build_rsn_ie();
        tail.extend_from_slice(&rsn);
    }

    if let Some(ht_info) = ht_info {
        tail.extend_from_slice(&build_ht_cap_ie(&ht_info));
        tail.extend_from_slice(&build_ht_operation_ie(channel, &ht_info));
    }

    if wmm_enabled {
        tail.extend_from_slice(&build_wmm_param_ie());
    }

    Ok((head, tail, ssid_bytes))
}

fn build_probe_response_frame(
    config: &ApConfig,
    bssid: [u8; 6],
    channel: u8,
    rate_sets: &RateSets,
    capab: u16,
    ht_info: Option<&HtInfo>,
    phy_caps: Option<&PhyCapabilities>,
) -> Result<Vec<u8>> {
    let wmm_enabled = ht_info.is_some();

    let ssid_bytes = config.ssid.as_bytes().to_vec();
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x50, 0x00]); // Probe Response
    frame.extend_from_slice(&[0x00, 0x00]); // Duration
    frame.extend_from_slice(&[0xff; 6]); // DA broadcast (kernel will fill for directed probes)
    frame.extend_from_slice(&bssid); // SA
    frame.extend_from_slice(&bssid); // BSSID
    frame.extend_from_slice(&[0x00, 0x00]); // Seq ctrl
    frame.extend_from_slice(&[0x00; 8]); // Timestamp (kernel fills)
    frame.extend_from_slice(&config.beacon_interval.to_le_bytes()); // Beacon interval
    frame.extend_from_slice(&capab.to_le_bytes());

    // SSID IE
    frame.push(0);
    frame.push(ssid_bytes.len() as u8);
    frame.extend_from_slice(&ssid_bytes);

    if rate_sets.supported.is_empty() {
        return Err(NetlinkError::InvalidInput(
            "No supported rates available for probe response".to_string(),
        ));
    }
    // Supported rates IE
    frame.push(1);
    frame.push(rate_sets.supported.len() as u8);
    frame.extend_from_slice(&rate_sets.supported);

    // DS Parameter Set (channel)
    frame.push(3);
    frame.push(1);
    frame.push(channel);

    if channel <= 14 && config.hw_mode != HardwareMode::A {
        frame.extend_from_slice(&build_erp_ie());
    }

    if !rate_sets.extended.is_empty() {
        frame.push(50);
        frame.push(rate_sets.extended.len() as u8);
        frame.extend_from_slice(&rate_sets.extended);
    }

    if let Some(country) = build_country_ie(channel, phy_caps) {
        frame.extend_from_slice(&country);
    }

    if matches!(config.security, ApSecurity::Wpa2Psk { .. }) {
        frame.extend_from_slice(&build_rsn_ie());
    }

    if let Some(ht_info) = ht_info {
        frame.extend_from_slice(&build_ht_cap_ie(&ht_info));
        frame.extend_from_slice(&build_ht_operation_ie(channel, &ht_info));
    }

    if wmm_enabled {
        frame.extend_from_slice(&build_wmm_param_ie());
    }

    Ok(frame)
}

#[derive(Debug, Clone)]
struct RateSets {
    supported: Vec<u8>,
    extended: Vec<u8>,
    basic: Vec<u32>,
    has_ofdm: bool,
}

#[derive(Debug, Clone)]
struct HtInfo {
    capab: u16,
    ampdu_factor: u8,
    ampdu_density: u8,
    mcs_set: [u8; 16],
}

fn build_rate_sets(
    _config: &ApConfig,
    channel: u8,
    phy_caps: Option<&PhyCapabilities>,
) -> Result<RateSets> {
    let mut used_dynamic_rates = false;
    let (supported_rates, extended_rates, basic_rates) =
        if let Some(rates) = rates_from_wiphy(phy_caps, channel) {
            used_dynamic_rates = true;
            rates
        } else {
            let (supported, extended) = if channel <= 14 {
                (
                    vec![0x82, 0x84, 0x8b, 0x96],
                    vec![0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c],
                )
            } else {
                (vec![0x8c, 0x98, 0xb0], vec![0x12, 0x24, 0x48, 0x60, 0x6c])
            };
            let basic = supported
                .iter()
                .map(|rate| u32::from(rate & 0x7f) * 5)
                .collect();
            (supported, extended, basic)
        };

    if used_dynamic_rates {
        log::debug!(
            "Using wiphy rates for channel {}: supported={} extended={} basic_rates={}",
            channel,
            supported_rates.len(),
            extended_rates.len(),
            basic_rates.len()
        );
    }

    let has_ofdm = rates_have_ofdm(&supported_rates, &extended_rates);

    Ok(RateSets {
        supported: supported_rates,
        extended: extended_rates,
        basic: basic_rates,
        has_ofdm,
    })
}

fn rates_have_ofdm(supported: &[u8], extended: &[u8]) -> bool {
    supported
        .iter()
        .chain(extended.iter())
        .any(|rate| (rate & 0x7f) as u32 * 5 >= 60)
}

fn build_capability_info(
    config: &ApConfig,
    channel: u8,
    rate_sets: &RateSets,
    wmm_enabled: bool,
) -> u16 {
    let mut capab: u16 = 0x0001; // ESS
    if matches!(config.security, ApSecurity::Wpa2Psk { .. }) {
        capab |= 0x0010;
    }

    if channel <= 14 {
        capab |= 0x0020; // Short preamble
        if rate_sets.has_ofdm {
            capab |= 0x0400; // Short slot time
        }
    } else {
        capab |= 0x0400; // Short slot time (5GHz)
    }

    if wmm_enabled {
        capab |= 0x0200; // QoS
    }

    capab
}

fn select_ht_info(
    config: &ApConfig,
    channel: u8,
    phy_caps: Option<&PhyCapabilities>,
) -> Option<HtInfo> {
    if config.hw_mode != HardwareMode::N {
        return None;
    }
    let band = band_for_channel(phy_caps?, channel)?;
    let capab = band.ht_capab?;
    let mcs = band.ht_mcs_set.as_ref()?;
    if mcs.len() < 16 {
        return None;
    }
    let mut mcs_set = [0u8; 16];
    mcs_set.copy_from_slice(&mcs[..16]);
    Some(HtInfo {
        capab,
        ampdu_factor: band.ht_ampdu_factor.unwrap_or(0),
        ampdu_density: band.ht_ampdu_density.unwrap_or(0),
        mcs_set,
    })
}

fn build_ht_cap_ie(info: &HtInfo) -> Vec<u8> {
    let mut ie = Vec::with_capacity(28);
    ie.push(45); // HT Capabilities
    ie.push(26);
    ie.extend_from_slice(&info.capab.to_le_bytes());
    let ampdu_params = (info.ampdu_factor & 0x03) | ((info.ampdu_density & 0x07) << 2);
    ie.push(ampdu_params);
    ie.extend_from_slice(&info.mcs_set);
    ie.extend_from_slice(&0u16.to_le_bytes()); // HT extended capabilities
    ie.extend_from_slice(&0u32.to_le_bytes()); // TX Beamforming
    ie.push(0u8); // ASEL capability
    ie
}

fn build_ht_operation_ie(channel: u8, info: &HtInfo) -> Vec<u8> {
    let mut ie = Vec::with_capacity(24);
    ie.push(61); // HT Operation
    ie.push(22);
    ie.push(channel);
    ie.push(0); // HT operation info (no secondary channel)
    ie.extend_from_slice(&0u16.to_le_bytes()); // HT operation info 2
    ie.extend_from_slice(&0u16.to_le_bytes()); // HT operation info 3
    ie.extend_from_slice(&info.mcs_set);
    ie
}

fn build_wmm_param_ie() -> Vec<u8> {
    let mut ie = Vec::with_capacity(26);
    ie.push(221); // Vendor specific
    ie.push(24);
    ie.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // WMM OUI + type
    ie.push(0x01); // WMM subtype: Parameter
    ie.push(0x01); // Version
    ie.push(0x00); // QoS info (U-APSD disabled)
    ie.push(0x00); // Reserved

    // AC_BE
    ie.push(0x03); // ACI=0, AIFSN=3
    ie.push(0xA4); // ECWmin=4, ECWmax=10
    ie.extend_from_slice(&0u16.to_le_bytes()); // TXOP

    // AC_BK
    ie.push(0x27); // ACI=1, AIFSN=7
    ie.push(0xA4); // ECWmin=4, ECWmax=10
    ie.extend_from_slice(&0u16.to_le_bytes()); // TXOP

    // AC_VI
    ie.push(0x42); // ACI=2, AIFSN=2
    ie.push(0x43); // ECWmin=3, ECWmax=4
    ie.extend_from_slice(&94u16.to_le_bytes()); // TXOP 94 * 32us

    // AC_VO
    ie.push(0x62); // ACI=3, AIFSN=2
    ie.push(0x32); // ECWmin=2, ECWmax=3
    ie.extend_from_slice(&47u16.to_le_bytes()); // TXOP 47 * 32us

    ie
}

fn build_country_ie(channel: u8, phy_caps: Option<&PhyCapabilities>) -> Option<Vec<u8>> {
    let alpha2 = read_regdom_alpha2()?;
    let band = band_for_channel(phy_caps?, channel)?;
    let channels = allowed_channels_for_band(band);
    if channels.is_empty() {
        return None;
    }
    let max_tx = max_tx_power_dbm(band).unwrap_or(20);
    let triplets = build_country_triplets(&channels, max_tx);
    if triplets.is_empty() {
        return None;
    }

    let mut ie = Vec::new();
    ie.push(7); // Country
    ie.push((3 + triplets.len() * 3) as u8);
    ie.extend_from_slice(&[alpha2[0], alpha2[1], b' ']);
    for triplet in triplets {
        ie.extend_from_slice(&triplet);
    }
    Some(ie)
}

fn read_regdom_alpha2() -> Option<[u8; 2]> {
    let val = fs::read_to_string("/sys/module/cfg80211/parameters/ieee80211_regdom")
        .ok()?
        .trim()
        .to_uppercase();
    if val.len() != 2 {
        return None;
    }
    if val == "00" || val == "99" {
        return None;
    }
    let bytes = val.as_bytes();
    Some([bytes[0], bytes[1]])
}

fn build_country_triplets(channels: &[u8], max_tx_power: u8) -> Vec<[u8; 3]> {
    let mut chans = channels.to_vec();
    chans.sort_unstable();
    chans.dedup();
    let mut triplets = Vec::new();
    let mut idx = 0;
    while idx < chans.len() {
        let start = chans[idx];
        let step = if start >= 36 { 4 } else { 1 };
        let mut count = 1u8;
        let mut prev = start;
        idx += 1;
        while idx < chans.len() && chans[idx] == prev + step {
            count = count.saturating_add(1);
            prev = chans[idx];
            idx += 1;
        }
        triplets.push([start, count, max_tx_power]);
    }
    triplets
}

fn max_tx_power_dbm(band: &crate::wireless::BandInfo) -> Option<u8> {
    let mut values: Vec<u8> = band
        .frequencies
        .iter()
        .filter(|f| frequency_allows_ap(f))
        .filter_map(|f| f.max_tx_power.map(|mbm| (mbm / 100) as u8))
        .collect();
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    values.first().copied()
}

fn band_for_channel<'a>(
    phy_caps: &'a PhyCapabilities,
    channel: u8,
) -> Option<&'a crate::wireless::BandInfo> {
    let freq = channel_to_frequency(channel)?;
    phy_caps
        .band_info
        .iter()
        .find(|band| band.frequencies.iter().any(|f| f.freq == freq))
        .or_else(|| {
            if channel <= 14 {
                phy_caps.band_info.iter().find(|band| band.name.contains("2.4"))
            } else {
                phy_caps.band_info.iter().find(|band| band.name.contains("5"))
            }
        })
}

fn allowed_channels_for_band(band: &crate::wireless::BandInfo) -> Vec<u8> {
    let mut channels = Vec::new();
    for freq in &band.frequencies {
        if frequency_allows_ap(freq) {
            if let Some(channel) = frequency_to_channel(freq.freq) {
                channels.push(channel);
            }
        }
    }
    channels.sort_unstable();
    channels.dedup();
    channels
}

fn frequency_allows_ap(freq: &crate::wireless::FrequencyInfo) -> bool {
    if freq.disabled || freq.no_ir {
        return false;
    }
    if freq.radar {
        return false;
    }
    if let Some(state) = freq.dfs_state {
        if state != NL80211_DFS_AVAILABLE {
            return false;
        }
    }
    true
}

fn build_candidate_channels(config: &ApConfig, phy_caps: &PhyCapabilities) -> Vec<u8> {
    let preferred_band = band_for_channel(phy_caps, config.channel);
    let mut allowed = if let Some(band) = preferred_band {
        allowed_channels_for_band(band)
    } else {
        allowed_channels_from_phy(phy_caps)
    };

    if allowed.is_empty() {
        return Vec::new();
    }

    allowed.sort_unstable();
    allowed.dedup();

    let mut candidates = Vec::new();
    if allowed.contains(&config.channel) {
        candidates.push(config.channel);
    }

    let prefer_2g = config.channel <= 14;
    let preferred = if prefer_2g {
        vec![1u8, 6u8, 11u8]
    } else {
        vec![36u8, 40u8, 44u8, 48u8, 149u8, 153u8, 157u8, 161u8]
    };
    for ch in preferred {
        if allowed.contains(&ch) && !candidates.contains(&ch) {
            candidates.push(ch);
        }
    }

    if candidates.is_empty() {
        for ch in allowed.iter().take(3) {
            candidates.push(*ch);
        }
    } else {
        for ch in allowed {
            if !candidates.contains(&ch) {
                candidates.push(ch);
            }
        }
    }

    candidates
}

fn allowed_channels_from_phy(phy_caps: &PhyCapabilities) -> Vec<u8> {
    let mut channels = Vec::new();
    for band in &phy_caps.band_info {
        channels.extend(allowed_channels_for_band(band));
    }
    channels.sort_unstable();
    channels.dedup();
    channels
}

fn rates_from_wiphy(
    phy_caps: Option<&PhyCapabilities>,
    channel: u8,
) -> Option<(Vec<u8>, Vec<u8>, Vec<u32>)> {
    let phy_caps = phy_caps?;
    let freq = channel_to_frequency(channel)?;
    let band = phy_caps
        .band_info
        .iter()
        .find(|band| band.frequencies.iter().any(|f| f.freq == freq))
        .or_else(|| {
            if channel <= 14 {
                phy_caps.band_info.iter().find(|band| band.name.contains("2.4"))
            } else {
                phy_caps.band_info.iter().find(|band| band.name.contains("5"))
            }
        })?;
    if band.rates.is_empty() {
        return None;
    }
    build_rates_from_list(&band.rates, channel)
}

fn build_rates_from_list(
    rates_100kbps: &[u32],
    channel: u8,
) -> Option<(Vec<u8>, Vec<u8>, Vec<u32>)> {
    let mut rates: Vec<u32> = rates_100kbps.iter().copied().filter(|r| *r > 0).collect();
    rates.sort_unstable();
    rates.dedup();
    if rates.is_empty() {
        return None;
    }
    let mut basic_rates = select_basic_rates(&rates, channel);
    basic_rates.retain(|rate| rate % 5 == 0);
    basic_rates.retain(|rate| rates.contains(rate));
    if basic_rates.is_empty() {
        basic_rates.extend(rates.iter().copied().filter(|r| r % 5 == 0).take(4));
    }
    let (supported_rates, extended_rates) = encode_rates_ie(&rates, &basic_rates);
    if supported_rates.is_empty() {
        return None;
    }
    Some((supported_rates, extended_rates, basic_rates))
}

fn select_basic_rates(rates_100kbps: &[u32], channel: u8) -> Vec<u32> {
    let mandatory: &[u32] = if channel <= 14 {
        &[10, 20, 55, 110]
    } else {
        &[60, 120, 240]
    };
    let mut basic: Vec<u32> = mandatory
        .iter()
        .copied()
        .filter(|rate| rates_100kbps.contains(rate))
        .collect();

    if basic.is_empty() {
        basic.extend(rates_100kbps.iter().take(4).copied());
    }

    basic.sort_unstable();
    basic.dedup();
    basic
}

fn encode_rates_ie(rates_100kbps: &[u32], basic_rates_100kbps: &[u32]) -> (Vec<u8>, Vec<u8>) {
    let mut encoded = Vec::new();
    for rate in rates_100kbps {
        if rate % 5 != 0 {
            continue;
        }
        let rate_500 = (rate / 5) as u8;
        if rate_500 == 0 {
            continue;
        }
        let mut val = rate_500;
        if basic_rates_100kbps.contains(rate) {
            val |= 0x80;
        }
        encoded.push(val);
    }
    encoded.sort_by_key(|rate| rate & 0x7f);
    encoded.dedup_by(|a, b| (*a & 0x7f) == (*b & 0x7f));

    let supported: Vec<u8> = encoded.iter().take(8).copied().collect();
    let extended: Vec<u8> = encoded.iter().skip(8).copied().collect();
    (supported, extended)
}

fn read_interface_mac(interface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", interface);
    let mac_str = fs::read_to_string(&path).map_err(|e| NetlinkError::MacAddressError {
        interface: interface.to_string(),
        reason: format!("Failed to read {}: {}", path, e),
    })?;

    let parts: Vec<&str> = mac_str.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(NetlinkError::MacAddressError {
            interface: interface.to_string(),
            reason: format!("Invalid MAC format: {}", mac_str.trim()),
        });
    }

    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).map_err(|e| NetlinkError::MacAddressError {
            interface: interface.to_string(),
            reason: format!("Invalid MAC component {}: {}", p, e),
        })?;
    }
    Ok(mac)
}

fn read_ifindex(interface: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", interface);
    let idx_str = fs::read_to_string(&path).map_err(|e| NetlinkError::InterfaceIndexError {
        interface: interface.to_string(),
        reason: format!("Failed to read {}: {}", path, e),
    })?;
    idx_str
        .trim()
        .parse::<u32>()
        .map_err(|e| NetlinkError::InterfaceIndexError {
            interface: interface.to_string(),
            reason: format!("Failed to parse ifindex: {}", e),
        })
}

fn channel_to_frequency(channel: u8) -> Option<u32> {
    match channel {
        // 2.4 GHz
        1 => Some(2412),
        2 => Some(2417),
        3 => Some(2422),
        4 => Some(2427),
        5 => Some(2432),
        6 => Some(2437),
        7 => Some(2442),
        8 => Some(2447),
        9 => Some(2452),
        10 => Some(2457),
        11 => Some(2462),
        12 => Some(2467),
        13 => Some(2472),
        14 => Some(2484),
        // 5 GHz subset
        36 => Some(5180),
        40 => Some(5200),
        44 => Some(5220),
        48 => Some(5240),
        52 => Some(5260),
        56 => Some(5280),
        60 => Some(5300),
        64 => Some(5320),
        100 => Some(5500),
        104 => Some(5520),
        108 => Some(5540),
        112 => Some(5560),
        116 => Some(5580),
        120 => Some(5600),
        124 => Some(5620),
        128 => Some(5640),
        132 => Some(5660),
        136 => Some(5680),
        140 => Some(5700),
        144 => Some(5720),
        149 => Some(5745),
        153 => Some(5765),
        157 => Some(5785),
        161 => Some(5805),
        165 => Some(5825),
        _ => None,
    }
}

fn frequency_to_channel(freq: u32) -> Option<u8> {
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

fn build_rsn_ie() -> Vec<u8> {
    // RSN IE for WPA2-PSK with CCMP
    // Ref: 802.11-2016, Annex I.4
    let mut ie = Vec::new();
    ie.push(0x30); // RSN element ID
    ie.push(0); // length placeholder

    ie.extend_from_slice(&0x0001u16.to_le_bytes()); // RSN Version 1

    // Group Cipher Suite: 00-0f-ac-4 (CCMP)
    ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);

    // Pairwise Cipher Suite Count = 1
    ie.extend_from_slice(&1u16.to_le_bytes());
    // Pairwise Cipher Suite List: CCMP
    ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);

    // AKM Suite Count = 1
    ie.extend_from_slice(&1u16.to_le_bytes());
    // AKM Suite List: PSK
    ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x02]);

    // RSN Capabilities
    ie.extend_from_slice(&0u16.to_le_bytes());

    // PMKID Count = 0 (none)
    ie.extend_from_slice(&0u16.to_le_bytes());

    // Set length
    let len = ie.len() - 2;
    ie[1] = len as u8;
    ie
}

fn build_tim_ie(dtim_period: u8) -> [u8; 6] {
    // TIM IE: ID, length, DTIM count, DTIM period, bitmap control, partial virtual bitmap
    [5, 4, 0, dtim_period, 0, 0]
}

fn build_erp_ie() -> [u8; 3] {
    // ERP IE: ID, length, value (no protection)
    [42, 1, 0x00]
}

fn basic_rates_to_bytes(basic_rates_100kbps: &[u32]) -> Vec<u8> {
    let mut rates: Vec<u8> = basic_rates_100kbps
        .iter()
        .filter_map(|rate| {
            if *rate == 0 || rate % 5 != 0 {
                return None;
            }
            let val = rate / 5;
            if val == 0 || val > u32::from(u8::MAX) {
                return None;
            }
            Some(val as u8)
        })
        .collect();
    rates.sort_unstable();
    rates.dedup();
    rates
}

fn log_ie_summary(label: &str, frame: &[u8], offset: usize) {
    let ies = parse_ie_list(frame, offset);
    if ies.is_empty() {
        log::error!("START_AP {} IEs: none (len={})", label, frame.len());
        return;
    }
    log::error!(
        "START_AP {} IEs (len={}): {}",
        label,
        frame.len(),
        format_ie_list(&ies)
    );
}

fn parse_ie_list(frame: &[u8], offset: usize) -> Vec<(u8, u8)> {
    if frame.len() <= offset {
        return Vec::new();
    }
    let mut ies = Vec::new();
    let mut idx = offset;
    while idx + 2 <= frame.len() {
        let id = frame[idx];
        let len = frame[idx + 1] as usize;
        idx += 2;
        if idx + len > frame.len() {
            break;
        }
        ies.push((id, len as u8));
        idx += len;
    }
    ies
}

fn format_ie_list(ies: &[(u8, u8)]) -> String {
    let mut parts = Vec::new();
    for (id, len) in ies {
        parts.push(format!("{}(len={})", ie_name(*id), len));
    }
    parts.join(", ")
}

fn ie_name(id: u8) -> &'static str {
    match id {
        0 => "SSID",
        1 => "SUPPORTED_RATES",
        3 => "DS_PARAM",
        5 => "TIM",
        7 => "COUNTRY",
        42 => "ERP",
        45 => "HT_CAP",
        48 => "RSN",
        50 => "EXT_SUPPORTED_RATES",
        61 => "HT_OPERATION",
        221 => "VENDOR",
        _ => "IE",
    }
}

fn u32_list_bytes(values: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_ne_bytes());
    }
    bytes
}

fn derive_ptk(
    pmk: &[u8; 32],
    aa: &[u8; 6],
    spa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; 64] {
    // PRF-512 from WPA spec using HMAC-SHA1
    let mut ptk = [0u8; 64];
    let mut data = Vec::new();
    let (min_mac, max_mac) = if aa <= spa { (aa, spa) } else { (spa, aa) };
    let (min_nonce, max_nonce) = if anonce <= snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };
    data.extend_from_slice(min_mac);
    data.extend_from_slice(max_mac);
    data.extend_from_slice(min_nonce);
    data.extend_from_slice(max_nonce);

    let label = b"Pairwise key expansion";
    let mut output = Vec::new();
    let mut i = 0u8;
    while output.len() < 64 {
        let mut hmac = match HmacSha1::new_from_slice(pmk) {
            Ok(h) => h,
            Err(e) => {
                log::error!("[AP] HMAC init failed during PTK derivation: {}", e);
                return ptk;
            }
        };
        hmac.update(label);
        hmac.update(&[0x00]);
        hmac.update(&data);
        hmac.update(&[i]);
        let hash = hmac.finalize().into_bytes();
        output.extend_from_slice(&hash);
        i = i.wrapping_add(1);
    }
    if output.len() >= 64 {
        ptk.copy_from_slice(&output[..64]);
    } else {
        log::error!("[AP] PTK derivation output too short ({} bytes)", output.len());
    }
    ptk
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = match HmacSha1::new_from_slice(key) {
        Ok(h) => h,
        Err(e) => {
            log::error!("[AP] HMAC init failed: {}", e);
            return Vec::new();
        }
    };
    h.update(data);
    h.finalize().into_bytes().to_vec()
}

fn build_m3(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    replay_counter: u64,
    ptk: &[u8],
    gtk: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet header
    frame.extend_from_slice(sta); // DA
    frame.extend_from_slice(bssid); // SA
    frame.extend_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());

    // EAPOL header
    frame.push(2); // version
    frame.push(EAPOL_TYPE_KEY);
    frame.extend_from_slice(&0u16.to_be_bytes()); // length placeholder

    // Key descriptor
    frame.push(WPA2_KEY_DESCRIPTOR);
    let key_info = WPA2_KEY_INFO_KEY_ACK
        | WPA2_KEY_INFO_KEY_MIC
        | WPA2_KEY_INFO_INSTALL
        | WPA2_KEY_INFO_PAIRWISE
        | WPA2_KEY_INFO_SECURE;
    frame.extend_from_slice(&key_info.to_be_bytes());
    frame.extend_from_slice(&16u16.to_be_bytes()); // key length (CCMP)
    frame.extend_from_slice(&replay_counter.to_be_bytes());
    frame.extend_from_slice(anonce);
    frame.extend_from_slice(&[0u8; 16]); // key IV
    frame.extend_from_slice(&[0u8; 8]); // key RSC
    frame.extend_from_slice(&[0u8; 8]); // key ID
    frame.extend_from_slice(&[0u8; 16]); // key MIC placeholder

    // GTK KDE: type=1, OUI 00:0f:ac:1 (GTK KDE)
    let mut kde = Vec::new();
    kde.push(0xdd);
    kde.push((gtk.len() + 6) as u8);
    kde.extend_from_slice(&[0x00, 0x0f, 0xac, 0x01]); // OUI + type
    kde.push(0x00); // KeyID|Tx
    kde.push(0x00); // Reserved
    kde.extend_from_slice(gtk);

    // Key data length + data
    let key_data_len = kde.len() as u16;
    frame.extend_from_slice(&key_data_len.to_be_bytes());
    frame.extend_from_slice(&kde);

    // Set EAPOL length
    let eapol_len = (frame.len() - 14 - 2) as u16;
    frame[16] = (eapol_len >> 8) as u8;
    frame[17] = (eapol_len & 0xff) as u8;

    // Compute MIC over everything after Ethernet header
    let mic = hmac_sha1(&ptk[..16], &frame[14..]);
    frame[95..111].copy_from_slice(&mic[..16]);

    frame
}

fn open_eapol_socket(ifindex: u32) -> Result<RawFd> {
    let sock_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (0x888e as u16).to_be() as i32,
        )
    };
    if sock_fd < 0 {
        return Err(NetlinkError::OperationFailed(format!(
            "Failed to open raw EAPOL socket: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (0x888e as u16).to_be();
    sll.sll_ifindex = ifindex as i32;

    let bind_res = unsafe {
        libc::bind(
            sock_fd,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bind_res < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(sock_fd);
        }
        return Err(NetlinkError::OperationFailed(format!(
            "Failed to bind EAPOL socket: {}",
            err
        )));
    }

    // Set non-blocking to allow clean shutdown polling
    let flags = unsafe { libc::fcntl(sock_fd, libc::F_GETFL) };
    if flags >= 0 {
        let _ = unsafe { libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    log::info!("EAPOL raw socket opened on ifindex {}", ifindex);
    Ok(sock_fd)
}

fn spawn_eapol_task(
    fd: RawFd,
    running: Arc<Mutex<bool>>,
    stats: Arc<Mutex<ApStats>>,
    clients: Arc<RwLock<HashMap<[u8; 6], ApClient>>>,
    interface: String,
    pmk: Option<[u8; 32]>,
    bssid: [u8; 6],
    ifindex: u32,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 2048];
        let gtk: [u8; 16] = rand::random();
        let sta_state: StdMutex<StdHashMap<[u8; 6], StaHandshake>> =
            StdMutex::new(StdHashMap::new());
        if let Some(_pmk) = pmk {
            log::info!(
                "WPA2-PSK EAPOL handler active on {} (pmk set, bssid {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                interface,
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
            );
        } else {
            log::warn!(
                "EAPOL handler on {} has no PMK; WPA handshake will fail",
                interface
            );
        }

        loop {
            let run = running.blocking_lock();
            if !*run {
                break;
            }
            drop(run);

            let res =
                unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if res < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                break;
            }
            let len = res as usize;
            if len < 14 {
                continue;
            }
            let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
            if ethertype != ETHERTYPE_EAPOL {
                continue;
            }
            let _eapol_version = buf[14];
            let eapol_type = buf.get(15).cloned().unwrap_or(0);
            if eapol_type != EAPOL_TYPE_KEY {
                continue;
            }
            let key_info = u16::from_be_bytes([buf[19], buf[20]]);

            let mut s = stats.blocking_lock();
            s.auth_requests += 1;
            drop(s);

            if pmk.is_none() || len < 113 {
                continue;
            }

            // Extract header fields
            let key_desc = buf[18];
            if key_desc != WPA2_KEY_DESCRIPTOR {
                continue;
            }
            let key_data_len = u16::from_be_bytes([buf[111], buf[112]]) as usize;
            let mut snonce = [0u8; 32];
            snonce.copy_from_slice(&buf[31..63]);
            let key_mic = &buf[95..111];
            let replay = u64::from_be_bytes([
                buf[23], buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30],
            ]);
            log::debug!(
                "EAPOL M2 received len={} replay={} key_data_len={} sta={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                len,
                replay,
                key_data_len,
                buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]
            );

            let mic_set = (key_info & WPA2_KEY_INFO_KEY_MIC) != 0;
            let ack_set = (key_info & WPA2_KEY_INFO_KEY_ACK) != 0;
            let install_set = (key_info & WPA2_KEY_INFO_INSTALL) != 0;
            let secure_set = (key_info & WPA2_KEY_INFO_SECURE) != 0;

            // Generate/reuse ANonce and derive PTK
            let pmk = pmk.unwrap();
            let mut sta_mac = [0u8; 6];
            sta_mac.copy_from_slice(&buf[6..12]);
            if mic_set && !ack_set && secure_set {
                // Likely M4
                let mut state_guard = sta_state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(entry) = state_guard.get_mut(&sta_mac) {
                    if replay != 0 && replay < entry.last_replay {
                        log::warn!(
                            "M4 replay too old for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}: {} < {}",
                            sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
                            replay,
                            entry.last_replay
                        );
                        drop(state_guard);
                        continue;
                    }
                    if let Some(ptk) = entry.ptk {
                        let mut frame = buf[..len].to_vec();
                        for b in frame[95..111].iter_mut() {
                            *b = 0;
                        }
                        let calc_mic = hmac_sha1(&ptk[..16], &frame[..(113 + key_data_len)]);
                        if calc_mic.len() < 16 {
                            log::error!("[AP] Calculated MIC too short (len={})", calc_mic.len());
                            record_ap_error("Calculated MIC too short".to_string());
                            drop(state_guard);
                            continue;
                        }
                        if &calc_mic[..16] != key_mic {
                            let msg = format!("EAPOL M4 MIC validation failed on {}", interface);
                            log::warn!("{}", msg);
                            record_ap_error(msg);
                            drop(state_guard);
                            if let Err(e) = deauth_station(ifindex, &sta_mac) {
                                log::warn!(
                                    "Failed to deauth station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}: {}",
                                    sta_mac[0],
                                    sta_mac[1],
                                    sta_mac[2],
                                    sta_mac[3],
                                    sta_mac[4],
                                    sta_mac[5],
                                    e
                                );
                            }
                            continue;
                        }
                        entry.last_replay = replay;
                        if !entry.authorized {
                            if let Err(e) =
                                install_keys_and_authorize(ifindex, &sta_mac, &ptk[..16], &gtk)
                            {
                                let msg = format!(
                                    "Key install/authorize failed on {} during M4: {}",
                                    interface, e
                                );
                                log::warn!("{}", msg);
                                record_ap_error(msg);
                                drop(state_guard);
                                if let Err(deauth_err) = deauth_station(ifindex, &sta_mac) {
                                    log::warn!(
                                        "Failed to deauth station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} after key failure: {}",
                                        sta_mac[0],
                                        sta_mac[1],
                                        sta_mac[2],
                                        sta_mac[3],
                                        sta_mac[4],
                                        sta_mac[5],
                                        deauth_err
                                    );
                                }
                                continue;
                            }
                            entry.authorized = true;
                            log::info!(
                                "Station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} authorized (M4 complete)",
                                sta_mac[0],
                                sta_mac[1],
                                sta_mac[2],
                                sta_mac[3],
                                sta_mac[4],
                                sta_mac[5]
                            );
                            // Update clients map to reflect authorized state
                            let mut clients_guard = clients.blocking_write();
                            clients_guard
                                .entry(sta_mac)
                                .and_modify(|c| c.wpa_state = WpaState::Authenticated)
                                .or_insert_with(|| ApClient {
                                    mac_address: sta_mac,
                                    aid: 0,
                                    associated_at: Instant::now(),
                                    capabilities: 0,
                                    rates: Vec::new(),
                                    wpa_state: WpaState::Authenticated,
                                });
                        }
                    } else {
                        log::warn!(
                            "Received M4 without PTK for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            sta_mac[0],
                            sta_mac[1],
                            sta_mac[2],
                            sta_mac[3],
                            sta_mac[4],
                            sta_mac[5]
                        );
                    }
                } else {
                    log::warn!(
                        "Received M4 for unknown station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        sta_mac[0],
                        sta_mac[1],
                        sta_mac[2],
                        sta_mac[3],
                        sta_mac[4],
                        sta_mac[5]
                    );
                }
                drop(state_guard);
                continue;
            }

            // Expected M2: MIC set, ACK clear, secure clear
            if !mic_set || ack_set || secure_set || install_set {
                log::warn!(
                    "Unexpected EAPOL-Key (key_info=0x{:04x}) from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}; ignoring",
                    key_info,
                    sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]
                );
                continue;
            }

            let mut state_guard = sta_state.lock().unwrap_or_else(|e| e.into_inner());
            let entry = state_guard.entry(sta_mac).or_insert_with(|| StaHandshake {
                anonce: rand::random::<[u8; 32]>(),
                ptk: None,
                last_replay: 0,
                authorized: false,
            });

            // Drop MIC-only frames that reuse or decrease replay counter
            if replay != 0 && replay <= entry.last_replay {
                log::warn!(
                    "Replay counter not increasing for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}: {} <= {}",
                    sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
                    replay,
                    entry.last_replay
                );
                drop(state_guard);
                continue;
            }

            let ptk = derive_ptk(&pmk, &bssid, &sta_mac, &entry.anonce, &snonce);
            entry.ptk = Some(ptk);
            entry.last_replay = replay;
            let anonce = entry.anonce;
            drop(state_guard);

            // Verify MIC on incoming M2
            let mut frame = buf[..len].to_vec();
            for b in frame[95..111].iter_mut() {
                *b = 0;
            }
            let calc_mic = hmac_sha1(&ptk[..16], &frame[..(113 + key_data_len)]);
            if calc_mic.len() < 16 {
                log::error!("[AP] Calculated MIC too short (len={})", calc_mic.len());
                record_ap_error("Calculated MIC too short".to_string());
                continue;
            }
            if &calc_mic[..16] != key_mic {
                let msg = format!("EAPOL MIC validation failed on {}", interface);
                log::warn!("{}", msg);
                record_ap_error(msg);
                if let Err(e) = deauth_station(ifindex, &sta_mac) {
                    log::warn!(
                        "Failed to deauth station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}: {}",
                        sta_mac[0],
                        sta_mac[1],
                        sta_mac[2],
                        sta_mac[3],
                        sta_mac[4],
                        sta_mac[5],
                        e
                    );
                }
                continue;
            }
            log::info!(
                "EAPOL MIC validated for sta {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                sta_mac[0],
                sta_mac[1],
                sta_mac[2],
                sta_mac[3],
                sta_mac[4],
                sta_mac[5]
            );

            // Build M3
            let replay_counter = replay.saturating_add(1);
            let m3 = build_m3(&bssid, &sta_mac, &anonce, replay_counter, &ptk, &gtk);

            // Send M3 back to station
            let send_res =
                unsafe { libc::send(fd, m3.as_ptr() as *const libc::c_void, m3.len(), 0) };
            if send_res < 0 {
                let msg = format!(
                    "Failed to send EAPOL M3 on {}: {}",
                    interface,
                    std::io::Error::last_os_error()
                );
                log::warn!("{}", msg);
                record_ap_error(msg);
                if let Err(deauth_err) = deauth_station(ifindex, &sta_mac) {
                    log::warn!(
                        "Failed to deauth station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} after send failure: {}",
                        sta_mac[0],
                        sta_mac[1],
                        sta_mac[2],
                        sta_mac[3],
                        sta_mac[4],
                        sta_mac[5],
                        deauth_err
                    );
                }
            } else {
                log::info!(
                    "Sent EAPOL M3 to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} replay_counter={}",
                    buf[6],
                    buf[7],
                    buf[8],
                    buf[9],
                    buf[10],
                    buf[11],
                    replay_counter
                );
            }
            // Track client in shared map for visibility/stats
            let mut clients_guard = clients.blocking_write();
            clients_guard
                .entry(sta_mac)
                .and_modify(|c| c.wpa_state = WpaState::Authenticating)
                .or_insert_with(|| ApClient {
                    mac_address: sta_mac,
                    aid: 0,
                    associated_at: Instant::now(),
                    capabilities: 0,
                    rates: Vec::new(),
                    wpa_state: WpaState::Authenticating,
                });
        }
        let _ = unsafe { libc::close(fd) };
        log::info!("EAPOL listener stopped on {}", interface);
    })
}

impl Drop for AccessPoint {
    fn drop(&mut self) {
        // Try to clean up, but don't block
        if let Ok(running) = self.running.try_lock() {
            if *running {
                log::warn!("AccessPoint dropped while still running");
            }
        }
    }
}

fn install_keys_and_authorize(ifindex: u32, sta: &[u8; 6], ptk: &[u8], gtk: &[u8]) -> Result<()> {
    let mut sock = NlSocketHandle::connect(neli::consts::socket::NlFamily::Generic, None, &[])
        .map_err(|e| {
            NetlinkError::ConnectionFailed(format!("Failed to open nl80211 socket: {}", e))
        })?;
    let family_id = sock.resolve_genl_family(NL80211_GENL_NAME).map_err(|e| {
        NetlinkError::ConnectionFailed(format!("Failed to resolve nl80211 family: {}", e))
    })?;

    // Pairwise key
    {
        log::debug!(
            "Installing PTK for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (len={}) ifindex={}",
            sta[0],
            sta[1],
            sta[2],
            sta[3],
            sta[4],
            sta[5],
            ptk.len(),
            ifindex
        );
        let mut attrs = GenlBuffer::new();
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_MAC, &sta[..]).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build MAC attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_DATA, ptk).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build key data attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_CIPHER, CIPHER_SUITE_CCMP)
                .map_err(|e| {
                    NetlinkError::OperationFailed(format!("Failed to build cipher attr: {}", e))
                })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_IDX, 0u32).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build key idx attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(
                false,
                false,
                NL80211_ATTR_KEY_TYPE,
                NL80211_KEYTYPE_PAIRWISE,
            )
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build key type attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_NEW_KEY, NL80211_GENL_VERSION, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        sock.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send NEW_KEY (pairwise): {}", e))
        })?;
    }

    // Group key
    {
        log::debug!(
            "Installing GTK (idx=1, len={}) on ifindex {}",
            gtk.len(),
            ifindex
        );
        let mut attrs = GenlBuffer::new();
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_DATA, gtk).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build GTK key data attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_CIPHER, CIPHER_SUITE_CCMP)
                .map_err(|e| {
                    NetlinkError::OperationFailed(format!("Failed to build cipher attr: {}", e))
                })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_IDX, 1u32).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build GTK key idx attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP)
                .map_err(|e| {
                    NetlinkError::OperationFailed(format!("Failed to build key type attr: {}", e))
                })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_NEW_KEY, NL80211_GENL_VERSION, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        sock.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send NEW_KEY (group): {}", e))
        })?;
    }

    // Authorize station
    {
        log::debug!(
            "Authorizing station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} on ifindex {}",
            sta[0],
            sta[1],
            sta[2],
            sta[3],
            sta[4],
            sta[5],
            ifindex
        );
        let mut attrs = GenlBuffer::new();
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
            })?,
        );
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_MAC, &sta[..]).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build MAC attr: {}", e))
            })?,
        );

        // struct nl80211_sta_flag_update { u32 mask; u32 set; }
        let mut flag_payload = Vec::new();
        flag_payload.extend_from_slice(&NL80211_STA_FLAG_AUTHORIZED.to_le_bytes()); // mask
        flag_payload.extend_from_slice(&NL80211_STA_FLAG_AUTHORIZED.to_le_bytes()); // set

        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_STA_FLAGS2, flag_payload).map_err(
                |e| {
                    NetlinkError::OperationFailed(format!("Failed to build STA_FLAGS2 attr: {}", e))
                },
            )?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_SET_STATION, NL80211_GENL_VERSION, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        sock.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send SET_STATION authorize: {}", e))
        })?;
    }

    Ok(())
}

fn deauth_station(ifindex: u32, sta: &[u8; 6]) -> Result<()> {
    let mut sock = NlSocketHandle::connect(neli::consts::socket::NlFamily::Generic, None, &[])
        .map_err(|e| {
            NetlinkError::ConnectionFailed(format!("Failed to open nl80211 socket: {}", e))
        })?;
    let family_id = sock.resolve_genl_family(NL80211_GENL_NAME).map_err(|e| {
        NetlinkError::ConnectionFailed(format!("Failed to resolve nl80211 family: {}", e))
    })?;

    let mut attrs = GenlBuffer::new();
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_MAC, &sta[..]).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build MAC attr: {}", e))
        })?,
    );

    let genlhdr = Genlmsghdr::new(NL80211_CMD_DEL_STATION, NL80211_GENL_VERSION, attrs);
    let nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    );

    sock.send(nlhdr).map_err(|e| {
        NetlinkError::OperationFailed(format!(
            "Failed to send DEL_STATION for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}: {}",
            sta[0], sta[1], sta[2], sta[3], sta[4], sta[5], e
        ))
    })?;

    Ok(())
}

/// Helper to generate WPA2 Pairwise Master Key from passphrase and SSID.
/// Kept for API compatibility and potential future WPA support.
pub fn generate_pmk(passphrase: &str, ssid: &str) -> Result<[u8; 32]> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    if passphrase.len() < 8 || passphrase.len() > 63 {
        return Err(NetlinkError::InvalidInput(
            "Passphrase must be 8-63 characters".to_string(),
        ));
    }

    let mut pmk = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);

    Ok(pmk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ap_config_validation() {
        let mut config = ApConfig::default();
        assert!(config.validate().is_ok());

        config.ssid = "".to_string();
        assert!(config.validate().is_err());

        config.ssid = "a".repeat(33);
        assert!(config.validate().is_err());

        config.ssid = "ValidSSID".to_string();
        config.channel = 15;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_wpa2_security_validation() {
        let sec = ApSecurity::Open;
        assert!(sec.validate().is_ok());

        let sec = ApSecurity::Wpa2Psk {
            passphrase: "short".to_string(),
        };
        assert!(sec.validate().is_err());

        let sec = ApSecurity::Wpa2Psk {
            passphrase: "ValidPassword123".to_string(),
        };
        assert!(sec.validate().is_ok());
    }

    #[test]
    fn test_pmk_generation() {
        let pmk = generate_pmk("password123", "TestNetwork");
        assert!(pmk.is_ok());
        assert_eq!(pmk.unwrap().len(), 32);

        let invalid = generate_pmk("short", "TestNetwork");
        assert!(invalid.is_err());
    }
}
