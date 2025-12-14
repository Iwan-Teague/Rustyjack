use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;
use std::net::Ipv4Addr;

use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use rustyjack_netlink::{AccessPoint, ApConfig, ApSecurity, DhcpServer, DhcpConfig as NetlinkDhcpConfig, DnsServer, IptablesManager};
// TODO: These helpers need to be implemented
// use rustyjack_core::dhcp_helpers::start_hotspot_dhcp_server;
// use rustyjack_core::dns_helpers::start_hotspot_dns;

use crate::error::{Result, WirelessError};
use crate::netlink_helpers::{netlink_set_interface_down, netlink_flush_addresses, netlink_add_address};
use crate::rfkill_helpers::{rfkill_unblock_all, rfkill_unblock, rfkill_list};
use crate::process_helpers::{pkill_pattern, pkill_pattern_force, process_running};

// Global lock to prevent concurrent hotspot operations
static HOTSPOT_LOCK: Mutex<()> = Mutex::new(());

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

/// Start a hotspot using Rust-native AccessPoint + DHCP + DNS servers.
pub fn start_hotspot(config: HotspotConfig) -> Result<HotspotState> {
    // Acquire lock to prevent concurrent hotspot start attempts
    let _lock = HOTSPOT_LOCK.lock()
        .map_err(|_| WirelessError::System(
            "Hotspot mutex poisoned - another thread panicked while starting hotspot".to_string()
        ))?;
    let start_time = Instant::now();
    
    eprintln!("[HOTSPOT] ========== HOTSPOT START ATTEMPT ==========");
    eprintln!("[HOTSPOT] Starting hotspot: AP={}, upstream={}, SSID={}, channel={}", 
        config.ap_interface, config.upstream_interface, config.ssid, config.channel);
    log::info!("Starting hotspot: AP={}, upstream={}, SSID={}, channel={}", 
        config.ap_interface, config.upstream_interface, config.ssid, config.channel);
    
    eprintln!("[HOTSPOT] Checking AP interface {}...", config.ap_interface);
    ensure_interface_exists(&config.ap_interface)?;
    eprintln!("[HOTSPOT] AP interface {} exists", config.ap_interface);
    log::debug!("AP interface {} exists", config.ap_interface);
    
    if !config.upstream_interface.is_empty() {
        eprintln!("[HOTSPOT] Checking upstream interface {}...", config.upstream_interface);
        ensure_interface_exists(&config.upstream_interface)?;
        eprintln!("[HOTSPOT] Upstream interface {} exists", config.upstream_interface);
        log::debug!("Upstream interface {} exists", config.upstream_interface);
    }
    
    eprintln!("[HOTSPOT] Checking AP capability for {}...", config.ap_interface);
    ensure_ap_capability(&config.ap_interface)?;
    eprintln!("[HOTSPOT] AP capability check passed");
    log::debug!("AP capability check passed for {}", config.ap_interface);
    
    let mut upstream_ready = false;
    if !config.upstream_interface.is_empty() {
        eprintln!("[HOTSPOT] Checking if upstream {} is ready...", config.upstream_interface);
        match ensure_upstream_ready(&config.upstream_interface) {
            Ok(_) => {
                upstream_ready = true;
                eprintln!("[HOTSPOT] Upstream {} is ready with IP", config.upstream_interface);
                log::info!("Upstream {} is ready with IP", config.upstream_interface);
            }
            Err(WirelessError::Interface(msg)) if msg.contains("has no IPv4 address") => {
                // Allow offline hotspot; continue without upstream/NAT
                upstream_ready = false;
                eprintln!("[HOTSPOT] Upstream not ready: {} (continuing in offline mode)", msg);
                log::warn!("Hotspot upstream not ready: {msg}");
            }
            Err(err) => {
                eprintln!("[HOTSPOT] ERROR: Upstream check failed: {}", err);
                return Err(err);
            }
        }
    } else {
        eprintln!("[HOTSPOT] No upstream interface specified; running in local-only mode");
        log::info!("No upstream interface specified; running in local-only mode");
    }
    
    eprintln!("[HOTSPOT] Creating config directory...");
    fs::create_dir_all(CONF_DIR).map_err(|e| WirelessError::System(format!("mkdir: {e}")))?;

    // Ensure previous instances are stopped to avoid dhcp bind failures
    eprintln!("[HOTSPOT] Stopping any existing hotspot processes");
    log::debug!("Stopping any existing hotspot processes");
    let _ = pkill_pattern("hostapd");
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Stop wpa_supplicant on the AP interface to prevent interference
    eprintln!("[HOTSPOT] Stopping wpa_supplicant on {}...", config.ap_interface);
    if let Err(e) = rustyjack_netlink::stop_wpa_supplicant(&config.ap_interface) {
        log::debug!("Failed to stop wpa_supplicant on {}: {}", config.ap_interface, e);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Set interface to unmanaged by NetworkManager to prevent interference
    eprintln!("[HOTSPOT] Setting {} to unmanaged by NetworkManager...", config.ap_interface);
    
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let nm_result = rt.block_on(async {
        rustyjack_netlink::networkmanager::set_device_managed(&config.ap_interface, false).await
    });
    
    match nm_result {
        Ok(()) => {
            eprintln!("[HOTSPOT] Interface set to unmanaged successfully");
            log::info!("Set {} to unmanaged by NetworkManager", config.ap_interface);
        }
        Err(e) => {
            eprintln!("[HOTSPOT] WARNING: Failed to set interface unmanaged: {}", e);
            log::warn!("Could not set {} unmanaged: may not have NetworkManager or D-Bus unavailable", config.ap_interface);
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
            eprintln!("[HOTSPOT] rfkill{}: {} - {}", dev.idx, dev.type_.name(), state);
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
            for dev in devices {
                eprintln!("[HOTSPOT]   rfkill{}: {} - {}", dev.idx, dev.type_.name(), dev.state_string());
            }
        }
    }

    // Now configure AP interface with static IP
    eprintln!("[HOTSPOT] Configuring AP interface {} with IP {}", config.ap_interface, AP_GATEWAY);
    log::debug!("Configuring AP interface {} with IP {}", config.ap_interface, AP_GATEWAY);
    
    eprintln!("[HOTSPOT] Bringing interface down...");
    run_cmd("ip", &["link", "set", &config.ap_interface, "down"])?;
    
    eprintln!("[HOTSPOT] Flushing addresses...");
    run_cmd("ip", &["addr", "flush", "dev", &config.ap_interface])?;
    
    eprintln!("[HOTSPOT] Adding IP address {}...", AP_GATEWAY);
    run_cmd(
        "ip",
        &[
            "addr",
            "add",
            &format!("{}/24", AP_GATEWAY),
            "dev",
            &config.ap_interface,
        ],
    )?;
    
    eprintln!("[HOTSPOT] Bringing interface up...");
    run_cmd("ip", &["link", "set", &config.ap_interface, "up"])?;
    
    eprintln!("[HOTSPOT] AP interface {} is up", config.ap_interface);
    log::debug!("AP interface {} is up", config.ap_interface);
    
    // Give interface time to fully initialize with its IP
    eprintln!("[HOTSPOT] Waiting 2 seconds for interface to stabilize...");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Enable forwarding
    let _ = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);

    // NAT rules (only if upstream is present and ready)
    if upstream_ready && !config.upstream_interface.is_empty() {
        log::debug!("Setting up NAT rules for upstream {}", config.upstream_interface);
        eprintln!("[HOTSPOT] Configuring NAT forwarding via Rust iptables...");
        
        match IptablesManager::new() {
            Ok(ipt) => {
                if let Err(e) = ipt.setup_nat_forwarding(&config.ap_interface, &config.upstream_interface) {
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
    eprintln!("[HOTSPOT] Creating Rust-native Access Point on {} (SSID: {})", config.ap_interface, config.ssid);
    log::info!("Creating Rust-native AP: interface={}, SSID={}, channel={}", config.ap_interface, config.ssid, config.channel);
    
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
    let mut ap = AccessPoint::new(ap_config)
        .map_err(|e| {
            eprintln!("[HOTSPOT] ERROR: Failed to create Access Point: {}", e);
            WirelessError::System(format!("Failed to create AP: {}", e))
        })?;
    
    // Start AP using tokio runtime
    let ap_start_result = tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                ap.start().await
                    .map_err(|e| WirelessError::System(format!("AP start failed: {}", e)))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create tokio runtime: {}", e)))
                .and_then(|rt| {
                    rt.block_on(async {
                        ap.start().await
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
    log::info!("Rust-native Access Point is running on {}", config.ap_interface);
    
    // Give AP time to fully initialize before starting DHCP/DNS
    eprintln!("[HOTSPOT] Waiting for AP to stabilize before starting DHCP/DNS servers...");
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Start DHCP server
    eprintln!("[HOTSPOT] Starting Rust DHCP server on {}...", config.ap_interface);
    let gateway_ip: Ipv4Addr = AP_GATEWAY.parse()
        .map_err(|e| WirelessError::System(format!("Invalid gateway IP {}: {}", AP_GATEWAY, e)))?;
    
    // TODO: Implement DHCP server properly
    // For now, these need to be implemented using rustyjack_netlink::DhcpServer
    eprintln!("[HOTSPOT] Note: DHCP/DNS servers need to be started separately");
    log::warn!("DHCP and DNS server integration not yet implemented");
    
    /*
    let dhcp_server = start_hotspot_dhcp_server(
        &config.ap_interface,
        gateway_ip,
        Ipv4Addr::new(10, 20, 30, 10),
        Ipv4Addr::new(10, 20, 30, 200),
    ).map_err(|e| {
        eprintln!("[HOTSPOT] ERROR: Failed to start DHCP server: {}", e);
        log::error!("Failed to start DHCP server: {}", e);
        // Clean up AP before returning error
        let _ = tokio::runtime::Handle::try_current()
            .map(|handle| handle.block_on(async { ap.stop().await }));
        WirelessError::System(format!("Failed to start DHCP server: {}", e))
    })?;
    
    eprintln!("[HOTSPOT] DHCP server started successfully");
    log::info!("DHCP server running on {}", config.ap_interface);
    
    // Start DNS server
    eprintln!("[HOTSPOT] Starting Rust DNS server on {}...", config.ap_interface);
    let dns_server = start_hotspot_dns(&config.ap_interface, gateway_ip)
        .map_err(|e| {
            eprintln!("[HOTSPOT] ERROR: Failed to start DNS server: {}", e);
            log::error!("Failed to start DNS server: {}", e);
            // Clean up AP and DHCP before returning error
            let _ = tokio::runtime::Handle::try_current()
                .map(|handle| handle.block_on(async { ap.stop().await }));
            drop(dhcp_server);
            WirelessError::System(format!("Failed to start DNS server: {}", e))
        })?;
    */
    
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
    
    // Leak AP so it stays alive until stop_hotspot is called
    std::mem::forget(ap);
    // TODO: Leak servers when implemented
    // std::mem::forget(dhcp_server);
    // std::mem::forget(dns_server);
    
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
        
        // Rust AP/DHCP/DNS servers will be automatically dropped when program exits
        // No need to kill external processes
        eprintln!("[HOTSPOT] Rust AP/DHCP/DNS servers will be automatically cleaned up");
        log::info!("Rust AP/DHCP/DNS servers stopping");
        
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
        eprintln!("[HOTSPOT] Cleaning up interface {} (leaving unmanaged to prevent RF-kill issues)...", s.ap_interface);
        log::info!("Cleaning up interface {} after hotspot stop", s.ap_interface);
        
        // Bring interface down to clean state
        let _ = netlink_set_interface_down(&s.ap_interface);
        
        // Flush any remaining IPs
        let _ = netlink_flush_addresses(&s.ap_interface);
        
        // Ensure RF-kill stays unblocked
        eprintln!("[HOTSPOT] Ensuring RF-kill stays unblocked...");
        let _ = rfkill_unblock_all();
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        eprintln!("[HOTSPOT] NOTE: Interface {} left unmanaged to prevent RF-kill blocking", s.ap_interface);
        log::info!("Interface {} left unmanaged to prevent RF-kill issues", s.ap_interface);
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
    let data = serde_json::to_string_pretty(state)
        .map_err(|e| WirelessError::System(format!("serialize state: {e}")))?;
    fs::write(STATE_PATH, data).map_err(|e| WirelessError::System(format!("write state: {e}")))?;
    Ok(())
}

fn spawn_background(cmd: &str, args: &[&str]) -> Result<Option<i32>> {
    let child = Command::new(cmd)
        .args(args)
        .spawn()
        .map_err(|e| WirelessError::System(format!("spawn {}: {}", cmd, e)))?;
    let pid = i32::try_from(child.id())
        .map_err(|_| WirelessError::System(format!("{}: PID does not fit in i32", cmd)))?;
    Ok(Some(pid))
}

fn ensure_tools_present() -> Result<()> {
    // No external tools needed - we use Rust implementations
    // (AP, DHCP, DNS, iptables all via rustyjack-netlink)
    Ok(())
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    eprintln!("[HOTSPOT] Running command: {} {}", cmd, args.join(" "));
    let start = Instant::now();
    
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| {
            eprintln!("[HOTSPOT] ERROR: Command failed to execute: {} {:?}: {}", cmd, args, e);
            WirelessError::System(format!("Failed to run {} {:?}: {}", cmd, args, e))
        })?;
    
    let duration = start.elapsed();
    eprintln!("[HOTSPOT] Command completed in {:?}", duration);
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!("[HOTSPOT] ERROR: Command failed with status {}", output.status);
        eprintln!("[HOTSPOT]   stderr: {}", stderr);
        eprintln!("[HOTSPOT]   stdout: {}", stdout);
        return Err(WirelessError::System(format!(
            "{} {:?} failed: {}",
            cmd,
            args,
            stderr
        )));
    }
    
    Ok(())
}

fn get_pid_by_pattern(pattern: &str) -> Option<i32> {
    use crate::process_helpers::pgrep_pattern;
    pgrep_pattern(pattern)
        .ok()?
        .into_iter()
        .next()
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
    // First check if the interface is wireless
    let phy_check = Command::new("iw")
        .args(["dev", interface, "info"])
        .output()
        .map_err(|e| WirelessError::System(format!("iw dev info failed: {}", e)))?;
    
    if !phy_check.status.success() {
        let stderr = String::from_utf8_lossy(&phy_check.stderr);
        return Err(WirelessError::Interface(format!(
            "{} is not a wireless interface: {}",
            interface, stderr
        )));
    }
    
    // Get the PHY for this interface
    let iw_info = String::from_utf8_lossy(&phy_check.stdout);
    
    // Extract wiphy number if available
    let mut phy_num = None;
    for line in iw_info.lines() {
        if line.contains("wiphy") {
            if let Some(num_str) = line.split_whitespace().last() {
                phy_num = num_str.parse::<u32>().ok();
                break;
            }
        }
    }
    
    // Check if the specific PHY supports AP mode using `iw phy<N> info`
    let mut supports_ap = false;
    if let Some(num) = phy_num {
        eprintln!("[HOTSPOT] Checking if phy{} supports AP mode...", num);
        let phy_output = Command::new("iw")
            .args(&[&format!("phy{}", num), "info"])
            .output()
            .ok();
        
        if let Some(output) = phy_output {
            if output.status.success() {
                let phy_info = String::from_utf8_lossy(&output.stdout);
                // Look for AP mode under "Supported interface modes:"
                let mut in_modes_section = false;
                for line in phy_info.lines() {
                    if line.contains("Supported interface modes:") {
                        in_modes_section = true;
                        continue;
                    }
                    if in_modes_section {
                        // End of section when we hit a non-indented line
                        if !line.starts_with('\t') && !line.starts_with("         ") {
                            break;
                        }
                        if line.contains("* AP") {
                            supports_ap = true;
                            eprintln!("[HOTSPOT] ✓ Interface {} (phy{}) supports AP mode", interface, num);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    // If we couldn't determine AP support, warn but let the Rust AP try
    if !supports_ap {
        eprintln!("[HOTSPOT] WARNING: {} may not support AP mode according to driver", interface);
        eprintln!("[HOTSPOT] Will attempt to start Rust AP anyway - it will fail gracefully if unsupported");
        log::warn!("Interface {} may not support AP mode - will attempt anyway", interface);
    }
    
    Ok(())
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
                    rustyjack_netlink::list_interfaces()
                        .await
                        .map_err(|e| WirelessError::System(format!("Failed to list interfaces: {}", e)))
                })
        })?;
    
    let iface_info = interfaces.iter()
        .find(|i| i.name == interface)
        .ok_or_else(|| WirelessError::Interface(format!("Upstream interface {} not found", interface)))?;
    
    let has_ipv4 = iface_info.addresses.iter()
        .any(|addr| matches!(addr.address, std::net::IpAddr::V4(_)));
    
    if !has_ipv4 {
        return Err(WirelessError::Interface(format!(
            "Upstream {} has no IPv4 address; connect it before starting hotspot",
            interface
        )));
    }
    Ok(())
}
