use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Instant;

use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use rustyjack_netlink::{
    AccessPoint, ApConfig, ApSecurity, DhcpConfig, DhcpServer, DhcpServerLease, DnsConfig,
    DnsRule, DnsServer, InterfaceMode, IptablesManager,
};

use crate::error::{Result, WirelessError};
use crate::frames::MacAddress;
use crate::netlink_helpers::{
    netlink_add_address, netlink_flush_addresses, netlink_set_interface_down,
    netlink_set_interface_up, select_hw_mode,
};
use crate::nl80211::{set_interface_type_netlink, Nl80211IfType};
use crate::process_helpers::pkill_pattern;
use crate::rfkill_helpers::{rfkill_list, rfkill_unblock, rfkill_unblock_all};
use tracing::{debug, error, info, warn};

// Global lock to prevent concurrent hotspot operations
static HOTSPOT_LOCK: Mutex<()> = Mutex::new(());
static DHCP_SERVER: OnceLock<Mutex<Option<DhcpRuntime>>> = OnceLock::new();
static DNS_SERVER: OnceLock<Mutex<Option<DnsServer>>> = OnceLock::new();
static ACCESS_POINT: OnceLock<Mutex<Option<AccessPoint>>> = OnceLock::new();
static LAST_HOTSPOT_WARNING: OnceLock<Mutex<Option<String>>> = OnceLock::new();

struct DhcpRuntime {
    handle: Option<JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
    leases: Arc<Mutex<HashMap<[u8; 6], DhcpServerLease>>>,
    denylist: Arc<Mutex<HashSet<[u8; 6]>>>,
}

/// Configuration for starting an access point hotspot.
#[derive(Debug, Clone)]
pub struct HotspotConfig {
    /// Interface that will host the AP (must support AP mode)
    pub ap_interface: String,
    /// Upstream interface to NAT traffic through (e.g., eth0 or wlan0)
    pub upstream_interface: String,
    /// SSID for the hotspot
    pub ssid: String,
    /// WPA2 passphrase (8-63 chars); if empty, an open network is created
    pub password: String,
    /// Channel to use (2.4 GHz)
    pub channel: u8,
    /// Restore NetworkManager management on stop
    pub restore_nm_on_stop: bool,
}

impl Default for HotspotConfig {
    fn default() -> Self {
        Self {
            ap_interface: "wlan0".to_string(),
            upstream_interface: "eth0".to_string(),
            ssid: "rustyjack".to_string(),
            password: "rustyjack".to_string(),
            channel: 6,
            restore_nm_on_stop: false,
        }
    }
}

/// Runtime state for a hotspot session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HotspotState {
    pub ssid: String,
    pub password: String,
    pub ap_interface: String,
    pub upstream_interface: String,
    pub channel: u8,
    #[serde(default = "default_true")]
    pub upstream_ready: bool,
    #[serde(default)]
    pub nm_unmanaged: bool,
    #[serde(default)]
    pub nm_error: Option<String>,
    #[serde(default)]
    pub restore_nm_on_stop: bool,
    // No longer tracking external PIDs - managed by Rust
    #[serde(skip)]
    pub ap_running: bool,
}

fn default_true() -> bool {
    true
}

const STATE_PATH: &str = "/tmp/rustyjack_hotspot/state.json";
const CONF_DIR: &str = "/tmp/rustyjack_hotspot";
const AP_GATEWAY: &str = "10.20.30.1";

#[derive(Debug, Clone)]
pub struct RegdomInfo {
    pub raw: Option<String>,
    pub valid: bool,
}

/// Generate a random SSID suffix (user-friendly).
pub fn random_ssid() -> String {
    let rand: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    format!("RJ-{}", rand)
}

/// Generate a random WPA2 passphrase.
pub fn random_password() -> String {
    OsRng
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

pub fn take_last_hotspot_warning() -> Option<String> {
    let lock = LAST_HOTSPOT_WARNING.get_or_init(|| Mutex::new(None));
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    guard.take()
}

pub fn read_regdom_info() -> RegdomInfo {
    let raw = fs::read_to_string("/sys/module/cfg80211/parameters/ieee80211_regdom")
        .ok()
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty());
    let valid = match raw.as_deref() {
        Some(code) if code.len() == 2 && code != "00" && code != "99" => true,
        _ => false,
    };

    RegdomInfo { raw, valid }
}

fn stop_ap_best_effort(ap: &mut AccessPoint) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let _ = handle.block_on(async { ap.stop().await });
    } else if let Ok(rt) = tokio::runtime::Runtime::new() {
        let _ = rt.block_on(async { ap.stop().await });
    }
}

fn record_hotspot_warning(msg: impl Into<String>) {
    let lock = LAST_HOTSPOT_WARNING.get_or_init(|| Mutex::new(None));
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(msg.into());
}

fn stop_access_point_global() {
    if let Some(ap_mutex) = ACCESS_POINT.get() {
        if let Ok(mut guard) = ap_mutex.lock() {
            if let Some(mut ap) = guard.take() {
                stop_ap_best_effort(&mut ap);
                info!("Access Point stopped");
            }
        }
    }
}

fn stop_dns_server_global() {
    if let Some(dns_mutex) = DNS_SERVER.get() {
        if let Ok(mut guard) = dns_mutex.lock() {
            if let Some(mut server) = guard.take() {
                let _ = server.stop();
                info!("DNS server stopped");
            }
        }
    }
}

fn stop_dhcp_server_global() {
    if let Some(dhcp_mutex) = DHCP_SERVER.get() {
        if let Ok(mut guard) = dhcp_mutex.lock() {
            if let Some(mut dhcp) = guard.take() {
                if let Ok(mut running) = dhcp.running.lock() {
                    *running = false;
                }
                if let Some(handle) = dhcp.handle.take() {
                    let _ = handle.join();
                }
                info!("DHCP server stopped");
            }
        }
    }
}

struct HotspotCleanup {
    ap_interface: String,
    upstream_interface: String,
    upstream_ready: bool,
    restore_nm_on_stop: bool,
    nm_unmanaged: bool,
    nat_configured: bool,
    interface_configured: bool,
    ap_started: bool,
    ap: Option<AccessPoint>,
    active: bool,
}

impl HotspotCleanup {
    fn new(config: &HotspotConfig) -> Self {
        Self {
            ap_interface: config.ap_interface.clone(),
            upstream_interface: config.upstream_interface.clone(),
            upstream_ready: false,
            restore_nm_on_stop: config.restore_nm_on_stop,
            nm_unmanaged: false,
            nat_configured: false,
            interface_configured: false,
            ap_started: false,
            ap: None,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }

    fn take_ap(&mut self) -> Option<AccessPoint> {
        self.ap.take()
    }
}

impl Drop for HotspotCleanup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        if let Some(ap) = self.ap.as_mut() {
            if self.ap_started {
                stop_ap_best_effort(ap);
            }
        }

        stop_dns_server_global();
        stop_dhcp_server_global();

        if self.nat_configured && self.upstream_ready && !self.upstream_interface.is_empty() {
            if let Ok(ipt) = IptablesManager::new() {
                let _ =
                    ipt.teardown_nat_forwarding(&self.ap_interface, &self.upstream_interface);
            }
        }

        if self.interface_configured {
            let _ = netlink_set_interface_down(&self.ap_interface);
            let _ = netlink_flush_addresses(&self.ap_interface);
        }

        let _ = (self.restore_nm_on_stop, self.nm_unmanaged);
    }
}

/// Start a hotspot using Rust-native AccessPoint + DHCP + DNS servers.
pub fn start_hotspot(config: HotspotConfig) -> Result<HotspotState> {
    // Acquire lock to prevent concurrent hotspot start attempts
    let _lock = HOTSPOT_LOCK.lock().map_err(|_| {
        WirelessError::System(
            "Hotspot mutex poisoned - another thread panicked while starting hotspot".to_string(),
        )
    })?;
    let _start_time = Instant::now();

    info!("[HOTSPOT] ========== HOTSPOT START ATTEMPT ==========");
    info!(
        "[HOTSPOT] Starting hotspot: AP={}, upstream={}, SSID={}, channel={}",
        config.ap_interface, config.upstream_interface, config.ssid, config.channel
    );

    debug!("[HOTSPOT] Checking AP interface {}...", config.ap_interface);
    ensure_interface_exists(&config.ap_interface)?;
    debug!("[HOTSPOT] AP interface {} exists", config.ap_interface);

    if !config.upstream_interface.is_empty() {
        debug!(
            "[HOTSPOT] Checking upstream interface {}...",
            config.upstream_interface
        );
        ensure_interface_exists(&config.upstream_interface)?;
        debug!(
            "[HOTSPOT] Upstream interface {} exists",
            config.upstream_interface
        );
    }

    debug!(
        "[HOTSPOT] Checking AP capability for {}...",
        config.ap_interface
    );
    ensure_ap_capability(&config.ap_interface)?;
    debug!("[HOTSPOT] AP capability check passed");

    let mut upstream_ready = false;
    if !config.upstream_interface.is_empty() {
        debug!(
            "[HOTSPOT] Checking if upstream {} is ready...",
            config.upstream_interface
        );
        match ensure_upstream_ready(&config.upstream_interface) {
            Ok(_) => {
                upstream_ready = true;
                info!(
                    "[HOTSPOT] Upstream {} is ready with IP",
                    config.upstream_interface
                );
            }
            Err(err) => {
                error!("[HOTSPOT] Upstream check failed: {}", err);
                return Err(err);
            }
        }
    } else {
        info!("[HOTSPOT] No upstream interface specified; running in local-only mode");
    }

    let mut cleanup = HotspotCleanup::new(&config);
    cleanup.upstream_ready = upstream_ready;

    debug!("[HOTSPOT] Creating config directory...");
    fs::create_dir_all(CONF_DIR).map_err(|e| WirelessError::System(format!("mkdir: {e}")))?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(CONF_DIR, fs::Permissions::from_mode(0o700));
    }

    // Clean up any existing AP/DHCP/DNS from previous run
    debug!("[HOTSPOT] Cleaning up any existing hotspot services...");
    
    // Stop any existing Access Point in our global
    if let Some(ap_mutex) = ACCESS_POINT.get() {
        if let Ok(mut guard) = ap_mutex.lock() {
            if let Some(mut old_ap) = guard.take() {
                debug!("[HOTSPOT] Stopping previous Access Point instance...");
                let _ = tokio::runtime::Runtime::new().and_then(|rt| {
                    let _ = rt.block_on(async { old_ap.stop().await });
                    Ok(())
                });
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
    
    // Ensure previous instances are stopped to avoid dhcp bind failures
    let _ = pkill_pattern("hostapd");
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Rust-only mode: skip wpa_supplicant and NetworkManager integration.
    info!("[HOTSPOT] Rust-only mode: skipping external wpa_supplicant/NetworkManager");
    let nm_error: Option<String> = None;

    // Unblock rfkill for all wireless devices - AGGRESSIVELY
    info!("[HOTSPOT] Unblocking rfkill for all wireless devices...");

    // Try multiple times because something keeps re-blocking it
    for attempt in 1..=3 {
        debug!("[HOTSPOT] RF-kill unblock attempt {}...", attempt);
        let rfkill_result = rfkill_unblock_all();

        match rfkill_result {
            Ok(_) => {
                debug!("[HOTSPOT] rfkill unblocked successfully");
            }
            Err(e) => {
                warn!("[HOTSPOT] rfkill unblock failed: {}", e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // Give rfkill unblock time to take effect
    debug!("[HOTSPOT] Waiting for rfkill to stabilize...");
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Verify rfkill status
    debug!("[HOTSPOT] Verifying rfkill status...");
    let mut is_blocked = false;
    if let Ok(devices) = rfkill_list() {
        for dev in &devices {
            let state = dev.state_string();
            debug!(
                "[HOTSPOT] rfkill{}: {} - {}",
                dev.idx,
                dev.type_.name(),
                state
            );
            if dev.is_blocked() {
                is_blocked = true;
            }
        }
        if is_blocked {
            warn!("[HOTSPOT] Wireless is still blocked by rfkill");
            warn!("[HOTSPOT] Attempting aggressive unblock...");
        }
    }

    // If still blocked, try more aggressive unblocking
    if is_blocked {
        warn!("[HOTSPOT] Performing aggressive RF-kill unblock...");
        // Unblock by device ID specifically
        for id in 0..10 {
            let _ = rfkill_unblock(id);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Final unblock all
        let _ = rfkill_unblock_all();
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Check again
        if let Ok(devices) = rfkill_list() {
            debug!("[HOTSPOT] rfkill status after aggressive unblock:");
            for dev in &devices {
                debug!(
                    "[HOTSPOT]   rfkill{}: {} - {}",
                    dev.idx,
                    dev.type_.name(),
                    dev.state_string()
                );
            }
            if devices.iter().any(|d| d.is_blocked()) {
                error!("[HOTSPOT] RF-kill still blocking wireless after aggressive unblock");
                return Err(WirelessError::System(
                    "RF-kill still blocking wireless devices; check hardware switch or BIOS setting"
                        .to_string(),
                ));
            }
        }
    }

    let regdom = read_regdom_info();
    if !regdom.valid {
        let note = match regdom.raw.as_deref() {
            Some(raw) => format!("Regdom unset/invalid ({}); set a country code", raw),
            None => "Regdom unset/invalid; set a country code".to_string(),
        };
        warn!("[HOTSPOT] {}", note);
        record_hotspot_warning(note);
    }

    // Now configure AP interface with static IP
    info!(
        "[HOTSPOT] Configuring AP interface {} with IP {}",
        config.ap_interface, AP_GATEWAY
    );

    let gateway_ip: Ipv4Addr = AP_GATEWAY
        .parse()
        .map_err(|e| WirelessError::System(format!("Invalid AP gateway {}: {}", AP_GATEWAY, e)))?;

    debug!("[HOTSPOT] Bringing interface down via netlink...");
    netlink_set_interface_down(&config.ap_interface)?;
    info!("Hotspot: {} set down via netlink", config.ap_interface);
    cleanup.interface_configured = true;

    debug!("[HOTSPOT] Flushing addresses via netlink...");
    netlink_flush_addresses(&config.ap_interface)?;
    info!("Hotspot: flushed addresses on {}", config.ap_interface);

    // Ensure interface is in AP mode before setting channel to avoid EBUSY from nl80211
    info!(
        "[HOTSPOT] Setting interface {} to AP mode via nl80211...",
        config.ap_interface
    );
    match set_interface_type_netlink(&config.ap_interface, Nl80211IfType::Ap) {
        Ok(_) => {
            info!(
                "[HOTSPOT] Interface {} set to AP mode (netlink)",
                config.ap_interface
            );
        }
        Err(e) => {
            error!("[HOTSPOT] Failed to set interface to AP mode: {}", e);
            return Err(WirelessError::System(format!(
                "Failed to set {} to AP mode via nl80211: {}",
                config.ap_interface, e
            )));
        }
    }

    info!("[HOTSPOT] Adding IP address {}/24 via netlink...", AP_GATEWAY);
    netlink_add_address(&config.ap_interface, IpAddr::V4(gateway_ip), 24)?;

    info!("[HOTSPOT] Bringing interface up via netlink...");
    netlink_set_interface_up(&config.ap_interface)?;
    cleanup.interface_configured = true;

    debug!("[HOTSPOT] AP interface {} is up", config.ap_interface);

    // Give interface time to fully initialize with its IP
    debug!("[HOTSPOT] Waiting 2 seconds for interface to stabilize...");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Enable forwarding without sysctl binary
    enable_ip_forwarding()
        .map_err(|e| WirelessError::System(format!("Failed to enable IPv4 forwarding: {}", e)))?;
    info!("[HOTSPOT] IPv4 forwarding enabled");

    // NAT rules (only if upstream is present and ready)
    if upstream_ready && !config.upstream_interface.is_empty() {
        info!("[HOTSPOT] Configuring NAT forwarding via Rust iptables...");

        match IptablesManager::new() {
            Ok(ipt) => {
                if let Err(e) =
                    ipt.setup_nat_forwarding(&config.ap_interface, &config.upstream_interface)
                {
                    error!("Failed to setup NAT forwarding: {}", e);
                    warn!("[HOTSPOT] NAT setup failed: {}", e);
                } else {
                    debug!("NAT rules configured successfully");
                    cleanup.nat_configured = true;
                }
            }
            Err(e) => {
                error!("Failed to create iptables manager: {}", e);
                warn!("[HOTSPOT] Could not initialize iptables: {}", e);
            }
        }
    } else {
        info!("Skipping NAT setup (local-only mode)");
    }

    // Use Rust-native AccessPoint instead of external hostapd
    info!(
        "[HOTSPOT] Creating Rust-native Access Point on {} (SSID: {})",
        config.ap_interface, config.ssid
    );

    let ap_security = if config.password.is_empty() {
        ApSecurity::Open
    } else {
        ApSecurity::Wpa2Psk {
            passphrase: config.password.clone(),
        }
    };

    let hw_mode = select_hw_mode(&config.ap_interface, config.channel);
    info!(
        "Hotspot hardware mode selected: iface={} channel={} hw_mode={:?}",
        config.ap_interface,
        config.channel,
        hw_mode
    );

    let ap_config = ApConfig {
        interface: config.ap_interface.clone(),
        ssid: config.ssid.clone(),
        channel: config.channel,
        security: ap_security,
        hidden: false,
        beacon_interval: 100,
        max_clients: 0,
        dtim_period: 2,
        hw_mode,
    };

    // Double-check rfkill is still unblocked right before starting AP
    debug!("[HOTSPOT] Final rfkill unblock before starting Access Point...");
    let _ = rfkill_unblock_all();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Create and start the Access Point in a blocking context
    info!("[HOTSPOT] Starting Rust Access Point...");
    let ap = AccessPoint::new(ap_config).map_err(|e| {
        error!("[HOTSPOT] Failed to create Access Point: {}", e);
        WirelessError::System(format!("Failed to create AP: {}", e))
    })?;
    cleanup.ap = Some(ap);

    // Start AP using tokio runtime
    let ap_start_result = tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                cleanup.ap_started = true;
                let ap = cleanup
                    .ap
                    .as_mut()
                    .ok_or_else(|| WirelessError::System("AP not initialized".to_string()))?;
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
                        cleanup.ap_started = true;
                        let ap = cleanup
                            .ap
                            .as_mut()
                            .ok_or_else(|| WirelessError::System("AP not initialized".to_string()))?;
                        ap.start()
                            .await
                            .map_err(|e| WirelessError::System(format!("AP start failed: {}", e)))
                    })
                })
        });

    if let Err(e) = ap_start_result {
        error!("[HOTSPOT] Failed to start Access Point: {}", e);
        error!("Access Point startup failed: {}", e);
        return Err(WirelessError::System(format!("Failed to start Access Point: {}. \
            The interface may not support AP mode, may be managed by NetworkManager, or RF-kill may be blocking it.", e)));
    }

    info!("[HOTSPOT] Access Point started successfully");
    // Give AP time to fully initialize before starting DHCP/DNS
    debug!("[HOTSPOT] Waiting for AP to stabilize before starting DHCP/DNS servers...");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Start DHCP server
    info!(
        "[HOTSPOT] Starting Rust DHCP server on {}...",
        config.ap_interface
    );
    start_dhcp_server(&config.ap_interface, gateway_ip).map_err(|e| {
        error!("[HOTSPOT] DHCP server failed to start: {}", e);
        e
    })?;
    info!("[HOTSPOT] DHCP server started successfully");
    info!("DHCP server running on {}", config.ap_interface);

    // Start DNS server
    info!(
        "[HOTSPOT] Starting Rust DNS server on {}...",
        config.ap_interface
    );
    start_dns_server(&config.ap_interface, gateway_ip).map_err(|e| {
        error!("[HOTSPOT] DNS server failed to start: {}", e);
        e
    })?;
    info!("[HOTSPOT] DNS server started successfully");
    info!("DNS server running on {}", config.ap_interface);

    info!("[HOTSPOT] Hotspot started successfully!");
    info!("[HOTSPOT]   Access Point: Rust-native (no external hostapd)");
    info!("[HOTSPOT]   DHCP/DNS: Rust servers running");
    info!("[HOTSPOT]   SSID: {}", config.ssid);
    info!("[HOTSPOT]   Password: {}", config.password);
    info!("Hotspot started successfully with Rust-native AP, DHCP, and DNS servers");

    let state = HotspotState {
        ssid: config.ssid,
        password: config.password,
        ap_interface: config.ap_interface,
        upstream_interface: config.upstream_interface,
        channel: config.channel,
        upstream_ready,
        nm_unmanaged: cleanup.nm_unmanaged,
        nm_error,
        restore_nm_on_stop: cleanup.restore_nm_on_stop,
        ap_running: true,
    };
    persist_state(&state)?;

    // Store marker that Rust servers are running (they'll be cleaned up by stop_hotspot)
    let servers_state_path = format!("{}/rust_servers.marker", CONF_DIR);
    fs::write(&servers_state_path, "ap_dhcp_dns_running")
        .map_err(|e| WirelessError::System(format!("write server marker: {e}")))?;

    // Store AP in global so it can be stopped later
    let mut ap = cleanup
        .take_ap()
        .ok_or_else(|| WirelessError::System("AP missing after start".to_string()))?;
    let ap_lock = ACCESS_POINT.get_or_init(|| Mutex::new(None));
    let mut guard = ap_lock
        .lock()
        .map_err(|_| {
            stop_ap_best_effort(&mut ap);
            WirelessError::System("AP mutex poisoned".to_string())
        })?;
    *guard = Some(ap);
    cleanup.disarm();

    Ok(state)
}

/// Stop a running hotspot and clean up.
pub fn stop_hotspot() -> Result<()> {
    info!("[HOTSPOT] ========== HOTSPOT STOP ATTEMPT ==========");

    let state = status_hotspot();

    info!("[HOTSPOT] Stopping hotspot services...");
    stop_access_point_global();
    stop_dns_server_global();
    stop_dhcp_server_global();
    info!("[HOTSPOT] Rust AP/DHCP/DNS servers cleaned up");

    if let Some(s) = state {
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Remove iptables rules (ignore errors if not present)
        if s.upstream_ready && !s.upstream_interface.is_empty() {
            info!("[HOTSPOT] Removing NAT rules via Rust iptables...");
            if let Ok(ipt) = IptablesManager::new() {
                let _ = ipt.teardown_nat_forwarding(&s.ap_interface, &s.upstream_interface);
            }
        }

        info!("[HOTSPOT] Cleaning up interface {}...", s.ap_interface);

        // Bring interface down to clean state
        let _ = netlink_set_interface_down(&s.ap_interface);

        // Flush any remaining IPs
        let _ = netlink_flush_addresses(&s.ap_interface);

        if s.restore_nm_on_stop {
            info!(
                "[HOTSPOT] Skipping NetworkManager restore for {} (rust-only mode)",
                s.ap_interface
            );
        }

        // Ensure RF-kill stays unblocked
        debug!("[HOTSPOT] Ensuring RF-kill stays unblocked...");
        let _ = rfkill_unblock_all();
        std::thread::sleep(std::time::Duration::from_millis(500));
    } else {
        info!("[HOTSPOT] No hotspot state found, performing general cleanup...");
    }

    // Remove state file
    debug!("[HOTSPOT] Removing state file...");
    let _ = fs::remove_file(STATE_PATH);

    info!("[HOTSPOT] Hotspot stopped successfully");

    Ok(())
}

/// Check current hotspot state (if running).
pub fn status_hotspot() -> Option<HotspotState> {
    if Path::new(STATE_PATH).exists() {
        let content = fs::read_to_string(STATE_PATH).ok()?;
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

/// Return active hotspot DHCP leases (empty if no server running).
pub fn hotspot_leases() -> Vec<DhcpServerLease> {
    let dhcp_mutex = match DHCP_SERVER.get() {
        Some(mutex) => mutex,
        None => return Vec::new(),
    };
    let guard = match dhcp_mutex.lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    let runtime = match guard.as_ref() {
        Some(runtime) => runtime,
        None => return Vec::new(),
    };

    runtime
        .leases
        .lock()
        .map(|leases| {
            leases
                .values()
                .filter(|lease| !lease.is_expired())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Disconnect a hotspot client and release its DHCP lease.
pub fn hotspot_disconnect_client(mac: &str) -> Result<()> {
    let mac_bytes = parse_mac_bytes(mac)?;
    let mut did_action = false;

    if let Some(dhcp_mutex) = DHCP_SERVER.get() {
        if let Ok(guard) = dhcp_mutex.lock() {
            if let Some(runtime) = guard.as_ref() {
                if let Ok(mut leases) = runtime.leases.lock() {
                    leases.remove(&mac_bytes);
                    did_action = true;
                }
            }
        }
    }

    if let Some(ap_mutex) = ACCESS_POINT.get() {
        if let Ok(guard) = ap_mutex.lock() {
            if let Some(ap) = guard.as_ref() {
                if let Err(err) = deauth_client(ap, mac_bytes) {
                    warn!("Failed to deauth hotspot client {}: {}", mac, err);
                } else {
                    did_action = true;
                }
            }
        }
    }

    if !did_action {
        return Err(WirelessError::System(
            "Hotspot not running; no client action performed".to_string(),
        ));
    }

    Ok(())
}

/// Replace the hotspot DHCP denylist with the provided MACs.
pub fn hotspot_set_blacklist(macs: &[String]) -> Result<()> {
    let dhcp_mutex = DHCP_SERVER.get().ok_or_else(|| {
        WirelessError::System("Hotspot DHCP server not running".to_string())
    })?;

    let mut parsed = HashSet::new();
    for mac in macs {
        match parse_mac_bytes(mac) {
            Ok(bytes) => {
                parsed.insert(bytes);
            }
            Err(err) => {
                warn!("Skipping invalid blacklist MAC {}: {}", mac, err);
            }
        }
    }

    let to_disconnect: Vec<[u8; 6]> = parsed.iter().copied().collect();

    let guard = dhcp_mutex
        .lock()
        .map_err(|_| WirelessError::System("DHCP server mutex poisoned".to_string()))?;
    let runtime = guard.as_ref().ok_or_else(|| {
        WirelessError::System("Hotspot DHCP server not running".to_string())
    })?;
    if let Ok(mut denylist) = runtime.denylist.lock() {
        denylist.clear();
        denylist.extend(parsed.iter().copied());
    }
    if let Ok(mut leases) = runtime.leases.lock() {
        for mac in &parsed {
            leases.remove(mac);
        }
    }

    if let Some(ap_mutex) = ACCESS_POINT.get() {
        if let Ok(guard) = ap_mutex.lock() {
            if let Some(ap) = guard.as_ref() {
                for mac in to_disconnect {
                    if let Err(err) = deauth_client(ap, mac) {
                        warn!(
                            "Failed to deauth blacklisted client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}: {}",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], err
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn parse_mac_bytes(mac: &str) -> Result<[u8; 6]> {
    let addr = MacAddress::from_str(mac)?;
    Ok(addr.0)
}

fn deauth_client(ap: &AccessPoint, mac: [u8; 6]) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                ap.disconnect_client(&mac)
                    .await
                    .map_err(|e| WirelessError::System(format!("AP deauth failed: {}", e)))
            })
        })
        .unwrap_or_else(|_| {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?;
            rt.block_on(async {
                ap.disconnect_client(&mac)
                    .await
                    .map_err(|e| WirelessError::System(format!("AP deauth failed: {}", e)))
            })
        })
}

fn persist_state(state: &HotspotState) -> Result<()> {
    fs::create_dir_all(CONF_DIR).map_err(|e| WirelessError::System(format!("mkdir: {e}")))?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(CONF_DIR, fs::Permissions::from_mode(0o700));
    }
    let data = serde_json::to_string_pretty(state)
        .map_err(|e| WirelessError::System(format!("serialize state: {e}")))?;

    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(STATE_PATH)
        .map_err(|e| WirelessError::System(format!("open state: {e}")))?;
    use std::io::Write;
    file.write_all(data.as_bytes())
        .map_err(|e| WirelessError::System(format!("write state: {e}")))?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(STATE_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn enable_ip_forwarding() -> Result<()> {
    fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
        .map_err(|e| WirelessError::System(format!("Failed to enable ip_forward: {}", e)))?;
    fs::write("/proc/sys/net/ipv4/conf/all/forwarding", "1\n")
        .map_err(|e| WirelessError::System(format!("Failed to enable all/forwarding: {}", e)))?;
    Ok(())
}

fn start_dhcp_server(interface: &str, gateway_ip: Ipv4Addr) -> Result<()> {
    let dhcp_lock = DHCP_SERVER.get_or_init(|| Mutex::new(None));
    let mut guard = dhcp_lock
        .lock()
        .map_err(|_| WirelessError::System("DHCP server mutex poisoned".to_string()))?;

    if guard.is_some() {
        return Ok(());
    }

    let dhcp_cfg = DhcpConfig {
        interface: interface.to_string(),
        server_ip: gateway_ip,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        range_start: Ipv4Addr::new(10, 20, 30, 10),
        range_end: Ipv4Addr::new(10, 20, 30, 200),
        router: Some(gateway_ip),
        dns_servers: vec![gateway_ip],
        lease_time_secs: 7200,
        log_packets: false,
    };

    let mut server = DhcpServer::new(dhcp_cfg.clone())
        .map_err(|e| WirelessError::System(format!("Failed to create DHCP server: {}", e)))?;
    let running_handle = server.running_handle();
    let leases_handle = server.leases_handle();
    let denylist_handle = server.denylist_handle();
    server
        .start()
        .map_err(|e| WirelessError::System(format!("Failed to start DHCP server: {}", e)))?;
    info!(
        "DHCP server bound on {} offering {}-{}",
        interface,
        dhcp_cfg.range_start,
        dhcp_cfg.range_end
    );

    let handle = std::thread::spawn(move || {
        if let Err(e) = server.serve() {
            error!("DHCP server exited with error: {}", e);
        }
    });

    *guard = Some(DhcpRuntime {
        handle: Some(handle),
        running: running_handle,
        leases: leases_handle,
        denylist: denylist_handle,
    });

    Ok(())
}

fn start_dns_server(interface: &str, gateway_ip: Ipv4Addr) -> Result<()> {
    let dns_lock = DNS_SERVER.get_or_init(|| Mutex::new(None));
    let mut guard = dns_lock
        .lock()
        .map_err(|_| WirelessError::System("DNS server mutex poisoned".to_string()))?;

    if guard.is_some() {
        return Ok(());
    }

    let dns_cfg = DnsConfig {
        interface: interface.to_string(),
        listen_ip: gateway_ip,
        default_rule: DnsRule::WildcardSpoof(gateway_ip),
        custom_rules: std::collections::HashMap::new(),
        upstream_dns: None,
        log_queries: false,
    };

    let mut server = DnsServer::new(dns_cfg)
        .map_err(|e| WirelessError::System(format!("Failed to create DNS server: {}", e)))?;
    server
        .start()
        .map_err(|e| WirelessError::System(format!("Failed to start DNS server: {}", e)))?;
    info!("DNS server bound on {} ({})", interface, gateway_ip);

    *guard = Some(server);
    Ok(())
}

fn ensure_interface_exists(name: &str) -> Result<()> {
    let path = format!("/sys/class/net/{}", name);
    if !Path::new(&path).exists() {
        return Err(WirelessError::Interface(format!(
            "Interface {} not found",
            name
        )));
    }
    Ok(())
}

fn ensure_ap_capability(interface: &str) -> Result<()> {
    let mut mgr = rustyjack_netlink::WirelessManager::new().map_err(|e| {
        WirelessError::System(format!("Failed to query nl80211 for {}: {}", interface, e))
    })?;

    let caps = mgr.get_phy_capabilities(interface).map_err(|e| {
        WirelessError::Interface(format!(
            "Failed to read AP capability for {}: {}",
            interface, e
        ))
    })?;

    let supports_ap = caps.supports_ap
        || caps
            .supported_modes
            .iter()
            .any(|m| *m == InterfaceMode::AccessPoint);

    if supports_ap {
        debug!(
            "[HOTSPOT] Interface {} ({}) reports AP capability via nl80211",
            interface, caps.name
        );
        Ok(())
    } else {
        warn!(
            "[HOTSPOT] {} does not report AP mode support (nl80211 modes: {:?})",
            interface, caps.supported_modes
        );
        warn!("[HOTSPOT] Will attempt to start Rust AP anyway; driver may still reject AP mode");
        Ok(())
    }
}

fn ensure_upstream_ready(interface: &str) -> Result<()> {
    let fetch_interfaces = || {
        tokio::runtime::Handle::try_current()
            .map(|handle| {
                handle.block_on(async {
                    rustyjack_netlink::list_interfaces().await.map_err(|e| {
                        WirelessError::System(format!("Failed to list interfaces: {}", e))
                    })
                })
            })
            .unwrap_or_else(|_| {
                tokio::runtime::Runtime::new()
                    .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                    .block_on(async {
                        rustyjack_netlink::list_interfaces().await.map_err(|e| {
                            WirelessError::System(format!("Failed to list interfaces: {}", e))
                        })
                    })
            })
    };

    let mut interfaces = fetch_interfaces()?;
    let mut iface_info = interfaces
        .iter()
        .find(|i| i.name == interface)
        .cloned()
        .ok_or_else(|| {
            WirelessError::Interface(format!("Upstream interface {} not found", interface))
        })?;
    let mut has_ipv4 = iface_info
        .addresses
        .iter()
        .any(|addr| matches!(addr.address, std::net::IpAddr::V4(_)));

    if !has_ipv4 {
        if !interface_is_wireless(interface) {
            if !interface_has_carrier(interface) {
                warn!(
                    "[HOTSPOT] Upstream {} has no carrier; DHCP may fail",
                    interface
                );
            }

            info!(
                "[HOTSPOT] Upstream {} missing IPv4; attempting DHCP",
                interface
            );

            let dhcp_result = tokio::runtime::Handle::try_current()
                .map(|handle| {
                    handle.block_on(async {
                        rustyjack_netlink::dhcp_acquire(interface, None).await.map_err(|e| {
                            WirelessError::System(format!(
                                "DHCP acquire failed on {}: {}",
                                interface, e
                            ))
                        })
                    })
                })
                .unwrap_or_else(|_| {
                    tokio::runtime::Runtime::new()
                        .map_err(|e| {
                            WirelessError::System(format!(
                                "Failed to create runtime for DHCP: {}",
                                e
                            ))
                        })?
                        .block_on(async {
                            rustyjack_netlink::dhcp_acquire(interface, None).await.map_err(|e| {
                                WirelessError::System(format!(
                                    "DHCP acquire failed on {}: {}",
                                    interface, e
                                ))
                            })
                        })
                });

            match dhcp_result {
                Ok(lease) => {
                    info!(
                        "Upstream {} DHCP lease: {}/{} gateway={:?}",
                        interface,
                        lease.address,
                        lease.prefix_len,
                        lease.gateway
                    );
                    has_ipv4 = true;
                }
                Err(err) => {
                    warn!("Upstream DHCP failed for {}: {}", interface, err);
                }
            }
        }

        if !has_ipv4 {
            interfaces = fetch_interfaces()?;
            iface_info = interfaces
                .iter()
                .find(|i| i.name == interface)
                .cloned()
                .ok_or_else(|| {
                    WirelessError::Interface(format!(
                        "Upstream interface {} not found",
                        interface
                    ))
                })?;
            has_ipv4 = iface_info
                .addresses
                .iter()
                .any(|addr| matches!(addr.address, std::net::IpAddr::V4(_)));
        }
    }

    if !has_ipv4 {
        return Err(WirelessError::Interface(format!(
            "Upstream {} has no IPv4 address; connect it before starting hotspot",
            interface
        )));
    }
    Ok(())
}

fn interface_is_wireless(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    Path::new("/sys/class/net")
        .join(interface)
        .join("wireless")
        .exists()
}

fn interface_has_carrier(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    let carrier_path = format!("/sys/class/net/{}/carrier", interface);
    let oper_path = format!("/sys/class/net/{}/operstate", interface);
    let oper_state = fs::read_to_string(&oper_path)
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();
    let oper_ready = matches!(oper_state.as_str(), "up" | "unknown");
    match fs::read_to_string(&carrier_path) {
        Ok(val) => val.trim() == "1" || oper_ready,
        Err(_) => oper_ready,
    }
}
