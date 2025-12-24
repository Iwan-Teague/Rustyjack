use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Instant;

use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use rustyjack_netlink::{
    AccessPoint, ApConfig, ApSecurity, DhcpConfig, DhcpServer, DnsConfig, DnsRule, DnsServer,
    InterfaceMode, IptablesManager,
};

use crate::error::{Result, WirelessError};
use crate::netlink_helpers::{
    netlink_add_address, netlink_flush_addresses, netlink_set_interface_down,
    netlink_set_interface_up,
};
use crate::nl80211::{set_interface_type_netlink, Nl80211IfType};
use crate::process_helpers::pkill_pattern;
use crate::rfkill_helpers::{rfkill_list, rfkill_unblock, rfkill_unblock_all};

// Global lock to prevent concurrent hotspot operations
static HOTSPOT_LOCK: Mutex<()> = Mutex::new(());
static DHCP_SERVER: OnceLock<Mutex<Option<DhcpRuntime>>> = OnceLock::new();
static DNS_SERVER: OnceLock<Mutex<Option<DnsServer>>> = OnceLock::new();
static ACCESS_POINT: OnceLock<Mutex<Option<AccessPoint>>> = OnceLock::new();

struct DhcpRuntime {
    handle: Option<JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
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
}

impl Default for HotspotConfig {
    fn default() -> Self {
        Self {
            ap_interface: "wlan0".to_string(),
            upstream_interface: "eth0".to_string(),
            ssid: "rustyjack".to_string(),
            password: "rustyjack".to_string(),
            channel: 6,
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

fn stop_ap_best_effort(ap: &mut AccessPoint) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let _ = handle.block_on(async { ap.stop().await });
    } else if let Ok(rt) = tokio::runtime::Runtime::new() {
        let _ = rt.block_on(async { ap.stop().await });
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

    eprintln!("[HOTSPOT] ========== HOTSPOT START ATTEMPT ==========");
    eprintln!(
        "[HOTSPOT] Starting hotspot: AP={}, upstream={}, SSID={}, channel={}",
        config.ap_interface, config.upstream_interface, config.ssid, config.channel
    );
    log::info!(
        "Starting hotspot: AP={}, upstream={}, SSID={}, channel={}",
        config.ap_interface,
        config.upstream_interface,
        config.ssid,
        config.channel
    );

    eprintln!("[HOTSPOT] Checking AP interface {}...", config.ap_interface);
    ensure_interface_exists(&config.ap_interface)?;
    eprintln!("[HOTSPOT] AP interface {} exists", config.ap_interface);
    log::debug!("AP interface {} exists", config.ap_interface);

    if !config.upstream_interface.is_empty() {
        eprintln!(
            "[HOTSPOT] Checking upstream interface {}...",
            config.upstream_interface
        );
        ensure_interface_exists(&config.upstream_interface)?;
        eprintln!(
            "[HOTSPOT] Upstream interface {} exists",
            config.upstream_interface
        );
        log::debug!("Upstream interface {} exists", config.upstream_interface);
    }

    eprintln!(
        "[HOTSPOT] Checking AP capability for {}...",
        config.ap_interface
    );
    ensure_ap_capability(&config.ap_interface)?;
    eprintln!("[HOTSPOT] AP capability check passed");
    log::debug!("AP capability check passed for {}", config.ap_interface);

    let mut upstream_ready = false;
    if !config.upstream_interface.is_empty() {
        eprintln!(
            "[HOTSPOT] Checking if upstream {} is ready...",
            config.upstream_interface
        );
        match ensure_upstream_ready(&config.upstream_interface) {
            Ok(_) => {
                upstream_ready = true;
                eprintln!(
                    "[HOTSPOT] Upstream {} is ready with IP",
                    config.upstream_interface
                );
                log::info!("Upstream {} is ready with IP", config.upstream_interface);
            }
            Err(err) => {
                eprintln!(
                    "[HOTSPOT] ERROR: Upstream check failed: {}",
                    err
                );
                return Err(err);
            }
        }
    } else {
        eprintln!("[HOTSPOT] No upstream interface specified; running in local-only mode");
        log::info!("No upstream interface specified; running in local-only mode");
    }

    eprintln!("[HOTSPOT] Creating config directory...");
    fs::create_dir_all(CONF_DIR).map_err(|e| WirelessError::System(format!("mkdir: {e}")))?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(CONF_DIR, fs::Permissions::from_mode(0o700));
    }

    // Clean up any existing AP/DHCP/DNS from previous run
    eprintln!("[HOTSPOT] Cleaning up any existing hotspot services...");
    log::debug!("Cleaning up any existing hotspot services");
    
    // Stop any existing Access Point in our global
    if let Some(ap_mutex) = ACCESS_POINT.get() {
        if let Ok(mut guard) = ap_mutex.lock() {
            if let Some(mut old_ap) = guard.take() {
                eprintln!("[HOTSPOT] Stopping previous Access Point instance...");
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

    // Stop wpa_supplicant on the AP interface to prevent interference
    eprintln!(
        "[HOTSPOT] Stopping wpa_supplicant on {}...",
        config.ap_interface
    );
    if let Err(e) = rustyjack_netlink::stop_wpa_supplicant(&config.ap_interface) {
        log::debug!(
            "Failed to stop wpa_supplicant on {}: {}",
            config.ap_interface,
            e
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Set interface to unmanaged by NetworkManager to prevent interference
    eprintln!(
        "[HOTSPOT] Setting {} to unmanaged by NetworkManager...",
        config.ap_interface
    );

    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        WirelessError::System(format!(
            "Failed to create tokio runtime for NetworkManager unmanaged: {e}"
        ))
    })?;
    let nm_result = rt.block_on(async {
        rustyjack_netlink::networkmanager::set_device_managed(&config.ap_interface, false).await
    });

    match nm_result {
        Ok(()) => {
            eprintln!("[HOTSPOT] Interface set to unmanaged successfully");
            log::info!("Set {} to unmanaged by NetworkManager", config.ap_interface);
        }
        Err(e) => {
            eprintln!(
                "[HOTSPOT] WARNING: Failed to set interface unmanaged: {}",
                e
            );
            log::warn!(
                "Could not set {} unmanaged: may not have NetworkManager or D-Bus unavailable",
                config.ap_interface
            );
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Unblock rfkill for all wireless devices - AGGRESSIVELY
    eprintln!("[HOTSPOT] Unblocking rfkill for all wireless devices...");

    // Try multiple times because something keeps re-blocking it
    for attempt in 1..=3 {
        eprintln!("[HOTSPOT] RF-kill unblock attempt {}...", attempt);
        let rfkill_result = rfkill_unblock_all();

        match rfkill_result {
            Ok(_) => {
                eprintln!("[HOTSPOT] rfkill unblocked successfully");
            }
            Err(e) => {
                eprintln!("[HOTSPOT] WARNING: rfkill unblock failed: {}", e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // Give rfkill unblock time to take effect
    eprintln!("[HOTSPOT] Waiting for rfkill to stabilize...");
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Verify rfkill status
    eprintln!("[HOTSPOT] Verifying rfkill status...");
    let mut is_blocked = false;
    if let Ok(devices) = rfkill_list() {
        for dev in &devices {
            let state = dev.state_string();
            eprintln!(
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
            eprintln!("[HOTSPOT] WARNING: Wireless is still blocked by rfkill!");
            eprintln!("[HOTSPOT] Attempting aggressive unblock...");
            log::warn!("Wireless still blocked after rfkill unblock attempt");
        }
    }

    // If still blocked, try more aggressive unblocking
    if is_blocked {
        eprintln!("[HOTSPOT] Performing aggressive RF-kill unblock...");
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
            eprintln!("[HOTSPOT] rfkill status after aggressive unblock:");
            for dev in &devices {
                eprintln!(
                    "[HOTSPOT]   rfkill{}: {} - {}",
                    dev.idx,
                    dev.type_.name(),
                    dev.state_string()
                );
            }
            if devices.iter().any(|d| d.is_blocked()) {
                log::error!("[HOTSPOT] RF-kill still blocking wireless after aggressive unblock");
                return Err(WirelessError::System(
                    "RF-kill still blocking wireless devices; check hardware switch or BIOS setting"
                        .to_string(),
                ));
            }
        }
    }

    // Now configure AP interface with static IP
    eprintln!(
        "[HOTSPOT] Configuring AP interface {} with IP {}",
        config.ap_interface, AP_GATEWAY
    );
    log::debug!(
        "Configuring AP interface {} with IP {}",
        config.ap_interface,
        AP_GATEWAY
    );

    let gateway_ip: Ipv4Addr = AP_GATEWAY
        .parse()
        .map_err(|e| WirelessError::System(format!("Invalid AP gateway {}: {}", AP_GATEWAY, e)))?;

    eprintln!("[HOTSPOT] Bringing interface down via netlink...");
    netlink_set_interface_down(&config.ap_interface)?;
    log::info!("Hotspot: {} set down via netlink", config.ap_interface);

    eprintln!("[HOTSPOT] Flushing addresses via netlink...");
    netlink_flush_addresses(&config.ap_interface)?;
    log::info!("Hotspot: flushed addresses on {}", config.ap_interface);

    // Ensure interface is in AP mode before setting channel to avoid EBUSY from nl80211
    eprintln!(
        "[HOTSPOT] Setting interface {} to AP mode via nl80211...",
        config.ap_interface
    );
    match set_interface_type_netlink(&config.ap_interface, Nl80211IfType::Ap) {
        Ok(_) => {
            eprintln!(
                "[HOTSPOT] Interface {} set to AP mode (netlink)",
                config.ap_interface
            );
            log::info!(
                "Hotspot: {} set to AP mode via nl80211",
                config.ap_interface
            );
        }
        Err(e) => {
            eprintln!("[HOTSPOT] ERROR: Failed to set interface to AP mode: {}", e);
            return Err(WirelessError::System(format!(
                "Failed to set {} to AP mode via nl80211: {}",
                config.ap_interface, e
            )));
        }
    }

    eprintln!(
        "[HOTSPOT] Adding IP address {}/24 via netlink...",
        AP_GATEWAY
    );
    netlink_add_address(&config.ap_interface, IpAddr::V4(gateway_ip), 24)?;
    log::info!(
        "Hotspot: assigned {} to {} via netlink",
        AP_GATEWAY,
        config.ap_interface
    );

    eprintln!("[HOTSPOT] Bringing interface up via netlink...");
    netlink_set_interface_up(&config.ap_interface)?;
    log::info!("Hotspot: {} brought up via netlink", config.ap_interface);

    eprintln!("[HOTSPOT] AP interface {} is up", config.ap_interface);
    log::debug!("AP interface {} is up", config.ap_interface);

    // Give interface time to fully initialize with its IP
    eprintln!("[HOTSPOT] Waiting 2 seconds for interface to stabilize...");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Enable forwarding without sysctl binary
    enable_ip_forwarding()
        .map_err(|e| WirelessError::System(format!("Failed to enable IPv4 forwarding: {}", e)))?;
    log::info!("Hotspot: IPv4 forwarding enabled");

    // NAT rules (only if upstream is present and ready)
    if upstream_ready && !config.upstream_interface.is_empty() {
        log::debug!(
            "Setting up NAT rules for upstream {}",
            config.upstream_interface
        );
        eprintln!("[HOTSPOT] Configuring NAT forwarding via Rust iptables...");

        match IptablesManager::new() {
            Ok(ipt) => {
                if let Err(e) =
                    ipt.setup_nat_forwarding(&config.ap_interface, &config.upstream_interface)
                {
                    log::error!("Failed to setup NAT forwarding: {}", e);
                    eprintln!("[HOTSPOT] Warning: NAT setup failed: {}", e);
                } else {
                    log::debug!("NAT rules configured successfully");
                }
            }
            Err(e) => {
                log::error!("Failed to create iptables manager: {}", e);
                eprintln!("[HOTSPOT] Warning: Could not initialize iptables: {}", e);
            }
        }
    } else {
        log::info!("Skipping NAT setup (local-only mode)");
    }

    // Use Rust-native AccessPoint instead of external hostapd
    eprintln!(
        "[HOTSPOT] Creating Rust-native Access Point on {} (SSID: {})",
        config.ap_interface, config.ssid
    );
    log::info!(
        "Creating Rust-native AP: interface={}, SSID={}, channel={}",
        config.ap_interface,
        config.ssid,
        config.channel
    );

    let ap_security = if config.password.is_empty() {
        ApSecurity::Open
    } else {
        ApSecurity::Wpa2Psk {
            passphrase: config.password.clone(),
        }
    };

    let ap_config = ApConfig {
        interface: config.ap_interface.clone(),
        ssid: config.ssid.clone(),
        channel: config.channel,
        security: ap_security,
        hidden: false,
        beacon_interval: 100,
        max_clients: 0,
        dtim_period: 2,
        hw_mode: rustyjack_netlink::HardwareMode::G,
    };

    // Double-check rfkill is still unblocked right before starting AP
    eprintln!("[HOTSPOT] Final rfkill unblock before starting Access Point...");
    let _ = rfkill_unblock_all();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Create and start the Access Point in a blocking context
    eprintln!("[HOTSPOT] Starting Rust Access Point...");
    let mut ap = AccessPoint::new(ap_config).map_err(|e| {
        eprintln!("[HOTSPOT] ERROR: Failed to create Access Point: {}", e);
        WirelessError::System(format!("Failed to create AP: {}", e))
    })?;

    // Start AP using tokio runtime
    let ap_start_result = tokio::runtime::Handle::try_current()
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

    if let Err(e) = ap_start_result {
        eprintln!("[HOTSPOT] ERROR: Failed to start Access Point: {}", e);
        log::error!("Access Point startup failed: {}", e);
        return Err(WirelessError::System(format!("Failed to start Access Point: {}. \
            The interface may not support AP mode, may be managed by NetworkManager, or RF-kill may be blocking it.", e)));
    }

    eprintln!("[HOTSPOT] Access Point started successfully");
    log::info!(
        "Rust-native Access Point is running on {}",
        config.ap_interface
    );

    // Give AP time to fully initialize before starting DHCP/DNS
    eprintln!("[HOTSPOT] Waiting for AP to stabilize before starting DHCP/DNS servers...");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Start DHCP server
    eprintln!(
        "[HOTSPOT] Starting Rust DHCP server on {}...",
        config.ap_interface
    );
    start_dhcp_server(&config.ap_interface, gateway_ip).map_err(|e| {
        stop_ap_best_effort(&mut ap);
        log::error!("[HOTSPOT] DHCP server failed to start: {}", e);
        e
    })?;
    eprintln!("[HOTSPOT] DHCP server started successfully");
    log::info!("DHCP server running on {}", config.ap_interface);

    // Start DNS server
    eprintln!(
        "[HOTSPOT] Starting Rust DNS server on {}...",
        config.ap_interface
    );
    start_dns_server(&config.ap_interface, gateway_ip).map_err(|e| {
        stop_ap_best_effort(&mut ap);
        log::error!("[HOTSPOT] DNS server failed to start: {}", e);
        e
    })?;
    eprintln!("[HOTSPOT] DNS server started successfully");
    log::info!("DNS server running on {}", config.ap_interface);

    eprintln!("[HOTSPOT] Hotspot started successfully!");
    eprintln!("[HOTSPOT]   Access Point: Rust-native (no external hostapd)");
    eprintln!("[HOTSPOT]   DHCP/DNS: Rust servers running");
    eprintln!("[HOTSPOT]   SSID: {}", config.ssid);
    eprintln!("[HOTSPOT]   Password: {}", config.password);
    log::info!("Hotspot started successfully with Rust-native AP, DHCP, and DNS servers");

    let state = HotspotState {
        ssid: config.ssid,
        password: config.password,
        ap_interface: config.ap_interface,
        upstream_interface: config.upstream_interface,
        channel: config.channel,
        upstream_ready,
        ap_running: true,
    };
    persist_state(&state)?;

    // Store marker that Rust servers are running (they'll be cleaned up by stop_hotspot)
    let servers_state_path = format!("{}/rust_servers.marker", CONF_DIR);
    fs::write(&servers_state_path, "ap_dhcp_dns_running")
        .map_err(|e| WirelessError::System(format!("write server marker: {e}")))?;

    // Store AP in global so it can be stopped later
    let ap_lock = ACCESS_POINT.get_or_init(|| Mutex::new(None));
    let mut guard = ap_lock
        .lock()
        .map_err(|_| WirelessError::System("AP mutex poisoned".to_string()))?;
    *guard = Some(ap);

    Ok(state)
}

/// Stop a running hotspot and clean up.
pub fn stop_hotspot() -> Result<()> {
    eprintln!("[HOTSPOT] ========== HOTSPOT STOP ATTEMPT ==========");
    log::info!("Stopping hotspot");

    let state = status_hotspot();

    // Best-effort cleanup
    if let Some(s) = state {
        eprintln!("[HOTSPOT] Stopping hotspot services...");

        // Stop Access Point first
        if let Some(ap_mutex) = ACCESS_POINT.get() {
            if let Ok(mut guard) = ap_mutex.lock() {
                if let Some(mut ap) = guard.take() {
                    eprintln!("[HOTSPOT] Stopping Access Point...");
                    // Need to run in tokio context
                    let rt = tokio::runtime::Runtime::new()
                        .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?;
                    if let Err(e) = rt.block_on(async { ap.stop().await }) {
                        log::warn!("Failed to stop AP cleanly: {}", e);
                    } else {
                        log::info!("Access Point stopped");
                    }
                }
            }
        }

        // Stop DNS server
        if let Some(dns_mutex) = DNS_SERVER.get() {
            if let Ok(mut guard) = dns_mutex.lock() {
                if let Some(mut server) = guard.take() {
                    let _ = server.stop();
                    log::info!("DNS server stopped");
                }
            }
        }

        // Stop DHCP server
        if let Some(dhcp_mutex) = DHCP_SERVER.get() {
            if let Ok(mut guard) = dhcp_mutex.lock() {
                if let Some(mut dhcp) = guard.take() {
                    if let Ok(mut running) = dhcp.running.lock() {
                        *running = false;
                    }
                    if let Some(handle) = dhcp.handle.take() {
                        let _ = handle.join();
                    }
                    log::info!("DHCP server stopped");
                }
            }
        }

        eprintln!("[HOTSPOT] Rust AP/DHCP/DNS servers cleaned up");
        log::info!("Rust AP/DHCP/DNS servers stopped");

        std::thread::sleep(std::time::Duration::from_millis(500));

        // Remove iptables rules (ignore errors if not present)
        if s.upstream_ready && !s.upstream_interface.is_empty() {
            eprintln!("[HOTSPOT] Removing NAT rules via Rust iptables...");
            if let Ok(ipt) = IptablesManager::new() {
                let _ = ipt.teardown_nat_forwarding(&s.ap_interface, &s.upstream_interface);
            }
        }

        // DO NOT restore NetworkManager management immediately
        // NetworkManager re-blocks RF-kill when it takes control, which breaks subsequent hotspot starts
        // Instead, leave interface unmanaged but ensure it's in a clean state
        eprintln!(
            "[HOTSPOT] Cleaning up interface {} (leaving unmanaged to prevent RF-kill issues)...",
            s.ap_interface
        );
        log::info!(
            "Cleaning up interface {} after hotspot stop",
            s.ap_interface
        );

        // Bring interface down to clean state
        let _ = netlink_set_interface_down(&s.ap_interface);

        // Flush any remaining IPs
        let _ = netlink_flush_addresses(&s.ap_interface);

        // Ensure RF-kill stays unblocked
        eprintln!("[HOTSPOT] Ensuring RF-kill stays unblocked...");
        let _ = rfkill_unblock_all();
        std::thread::sleep(std::time::Duration::from_millis(500));

        eprintln!(
            "[HOTSPOT] NOTE: Interface {} left unmanaged to prevent RF-kill blocking",
            s.ap_interface
        );
        log::info!(
            "Interface {} left unmanaged to prevent RF-kill issues",
            s.ap_interface
        );
    } else {
        eprintln!("[HOTSPOT] No hotspot state found, performing general cleanup...");
        log::info!("No hotspot state found during stop");
    }

    // Remove state file
    eprintln!("[HOTSPOT] Removing state file...");
    let _ = fs::remove_file(STATE_PATH);

    eprintln!("[HOTSPOT] Hotspot stopped successfully");
    log::info!("Hotspot stopped successfully");

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
    server
        .start()
        .map_err(|e| WirelessError::System(format!("Failed to start DHCP server: {}", e)))?;
    log::info!(
        "DHCP server bound on {} offering {}-{}",
        interface,
        dhcp_cfg.range_start,
        dhcp_cfg.range_end
    );

    let handle = std::thread::spawn(move || {
        if let Err(e) = server.serve() {
            log::error!("DHCP server exited with error: {}", e);
        }
    });

    *guard = Some(DhcpRuntime {
        handle: Some(handle),
        running: running_handle,
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
    log::info!("DNS server bound on {} ({})", interface, gateway_ip);

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
        eprintln!(
            "[HOTSPOT] ✓ Interface {} ({}) reports AP capability via nl80211",
            interface, caps.name
        );
        Ok(())
    } else {
        eprintln!(
            "[HOTSPOT] WARNING: {} does not report AP mode support (nl80211 modes: {:?})",
            interface, caps.supported_modes
        );
        eprintln!(
            "[HOTSPOT] Will attempt to start Rust AP anyway - driver may still reject AP mode"
        );
        log::warn!(
            "Interface {} lacks reported AP support; attempting AP start anyway",
            interface
        );
        Ok(())
    }
}

fn ensure_upstream_ready(interface: &str) -> Result<()> {
    let interfaces = tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::list_interfaces()
                    .await
                    .map_err(|e| WirelessError::System(format!("Failed to list interfaces: {}", e)))
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
        })?;

    let iface_info = interfaces
        .iter()
        .find(|i| i.name == interface)
        .ok_or_else(|| {
            WirelessError::Interface(format!("Upstream interface {} not found", interface))
        })?;

    let has_ipv4 = iface_info
        .addresses
        .iter()
        .any(|addr| matches!(addr.address, std::net::IpAddr::V4(_)));

    if !has_ipv4 {
        return Err(WirelessError::Interface(format!(
            "Upstream {} has no IPv4 address; connect it before starting hotspot",
            interface
        )));
    }
    Ok(())
}
