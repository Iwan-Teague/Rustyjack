use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};

use crate::error::{Result, WirelessError};

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
    pub hostapd_pid: Option<i32>,
    pub dnsmasq_pid: Option<i32>,
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

/// Start a hotspot using hostapd + dnsmasq + iptables NAT.
pub fn start_hotspot(config: HotspotConfig) -> Result<HotspotState> {
    // Acquire lock to prevent concurrent hotspot start attempts
    let _lock = HOTSPOT_LOCK.lock().unwrap();
    let start_time = Instant::now();
    
    eprintln!("[HOTSPOT] ========== HOTSPOT START ATTEMPT ==========");
    eprintln!("[HOTSPOT] Starting hotspot: AP={}, upstream={}, SSID={}, channel={}", 
        config.ap_interface, config.upstream_interface, config.ssid, config.channel);
    log::info!("Starting hotspot: AP={}, upstream={}, SSID={}, channel={}", 
        config.ap_interface, config.upstream_interface, config.ssid, config.channel);
    
    eprintln!("[HOTSPOT] Checking tools...");
    ensure_tools_present()?;
    eprintln!("[HOTSPOT] Tools check passed");
    log::debug!("Tools check passed");
    
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
    let _ = Command::new("pkill").args(["-f", "hostapd"]).status();
    let _ = Command::new("pkill").args(["-f", "dnsmasq"]).status();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Stop wpa_supplicant on the AP interface to prevent interference
    eprintln!("[HOTSPOT] Stopping wpa_supplicant on {}...", config.ap_interface);
    let _ = Command::new("pkill")
        .args(["-f", &format!("wpa_supplicant.*{}", config.ap_interface)])
        .status();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Set interface to unmanaged by NetworkManager to prevent interference
    eprintln!("[HOTSPOT] Setting {} to unmanaged by NetworkManager...", config.ap_interface);
    let nmcli_result = Command::new("nmcli")
        .args(["device", "set", &config.ap_interface, "managed", "no"])
        .output();
    
    match nmcli_result {
        Ok(output) => {
            if output.status.success() {
                eprintln!("[HOTSPOT] Interface set to unmanaged successfully");
                log::info!("Set {} to unmanaged by NetworkManager", config.ap_interface);
            } else {
                eprintln!("[HOTSPOT] WARNING: Failed to set interface unmanaged: {}", 
                    String::from_utf8_lossy(&output.stderr));
                log::warn!("Could not set {} unmanaged: may not have NetworkManager", config.ap_interface);
            }
        }
        Err(e) => {
            eprintln!("[HOTSPOT] WARNING: nmcli not available: {}", e);
            log::warn!("nmcli not available: {}", e);
        }
    }
    
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Unblock rfkill for all wireless devices - AGGRESSIVELY
    eprintln!("[HOTSPOT] Unblocking rfkill for all wireless devices...");
    
    // Try multiple times because something keeps re-blocking it
    for attempt in 1..=3 {
        eprintln!("[HOTSPOT] RF-kill unblock attempt {}...", attempt);
        let rfkill_result = Command::new("rfkill")
            .args(&["unblock", "all"])
            .output();
        
        match rfkill_result {
            Ok(output) => {
                if !output.status.success() {
                    eprintln!("[HOTSPOT] WARNING: rfkill unblock failed: {}", 
                        String::from_utf8_lossy(&output.stderr));
                } else {
                    eprintln!("[HOTSPOT] rfkill unblocked successfully");
                }
            }
            Err(e) => {
                eprintln!("[HOTSPOT] WARNING: rfkill command failed: {}", e);
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
    if let Ok(output) = Command::new("rfkill").arg("list").output() {
        let status = String::from_utf8_lossy(&output.stdout);
        eprintln!("[HOTSPOT] rfkill status:\n{}", status);
        if status.contains("Soft blocked: yes") || status.contains("Hard blocked: yes") {
            eprintln!("[HOTSPOT] WARNING: Wireless is still blocked by rfkill!");
            eprintln!("[HOTSPOT] Attempting aggressive unblock...");
            log::warn!("Wireless still blocked after rfkill unblock attempt");
            is_blocked = true;
        }
    }
    
    // If still blocked, try more aggressive unblocking
    if is_blocked {
        eprintln!("[HOTSPOT] Performing aggressive RF-kill unblock...");
        // Unblock by device ID specifically
        for id in 0..10 {
            let _ = Command::new("rfkill")
                .args(&["unblock", &id.to_string()])
                .status();
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        // Final unblock all
        let _ = Command::new("rfkill").args(&["unblock", "all"]).status();
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        // Check again
        if let Ok(output) = Command::new("rfkill").arg("list").output() {
            let status = String::from_utf8_lossy(&output.stdout);
            eprintln!("[HOTSPOT] rfkill status after aggressive unblock:\n{}", status);
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
        let _ = run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                &config.upstream_interface,
                "-j",
                "MASQUERADE",
            ],
        );
        let _ = run_cmd(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-i",
                &config.upstream_interface,
                "-o",
                &config.ap_interface,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        );
        let _ = run_cmd(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-i",
                &config.ap_interface,
                "-o",
                &config.upstream_interface,
                "-j",
                "ACCEPT",
            ],
        );
        log::debug!("NAT rules configured");
    } else {
        log::info!("Skipping NAT setup (local-only mode)");
    }

    // Write hostapd.conf
    let hostapd_conf = format!(
        "interface={}\ndriver=nl80211\nssid={}\nhw_mode=g\nchannel={}\nwmm_enabled=1\n",
        config.ap_interface, config.ssid, config.channel
    );
    let hostapd_conf = if config.password.is_empty() {
        format!("{hostapd_conf}auth_algs=1\nignore_broadcast_ssid=0\n")
    } else {
        format!(
            "{hostapd_conf}wpa=2\nwpa_passphrase={}\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n",
            config.password
        )
    };
    let hostapd_path = format!("{CONF_DIR}/hostapd.conf");
    fs::write(&hostapd_path, &hostapd_conf)
        .map_err(|e| WirelessError::System(format!("writing hostapd.conf: {e}")))?;
    
    log::debug!("hostapd.conf written to {}", hostapd_path);
    log::debug!("hostapd config:\n{}", hostapd_conf);

    let logging_enabled = rustyjack_evasion::logs_enabled();

    // Write dnsmasq.conf
    let dns_logging = if logging_enabled {
        "log-queries\nlog-dhcp\n"
    } else {
        ""
    };
    let dns_conf = format!(
        "interface={}\n\
         bind-interfaces\n\
         listen-address={gw}\n\
         dhcp-range=10.20.30.10,10.20.30.200,255.255.255.0,12h\n\
         dhcp-option=1,255.255.255.0\n\
         dhcp-option=3,{gw}\n\
         dhcp-option=6,{gw}\n\
         dhcp-authoritative\n\
         no-resolv\n\
         no-poll\n\
         domain-needed\n\
         bogus-priv\n\
         server=8.8.8.8\n\
         server=8.8.4.4\n\
{dns_logging}",
        config.ap_interface,
        gw = AP_GATEWAY,
        dns_logging = dns_logging
    );
    let dns_path = format!("{CONF_DIR}/dnsmasq.conf");
    fs::write(&dns_path, &dns_conf)
        .map_err(|e| WirelessError::System(format!("writing dnsmasq.conf: {e}")))?;
    
    eprintln!("[HOTSPOT] dnsmasq.conf written to {}", dns_path);
    eprintln!("[HOTSPOT] dnsmasq config:\n{}", dns_conf);
    
    log::debug!("Configuration files written");

    // Give interface time to stabilize
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Double-check rfkill is still unblocked right before starting hostapd
    eprintln!("[HOTSPOT] Final rfkill unblock before starting hostapd...");
    let _ = Command::new("rfkill").args(&["unblock", "all"]).status();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Start hostapd in background mode
    eprintln!("[HOTSPOT] Starting hostapd on {} (SSID: {})", config.ap_interface, config.ssid);
    log::info!("Starting hostapd on {} (SSID: {})", config.ap_interface, config.ssid);
    
    let hostapd_output = Command::new("hostapd")
        .args(&["-B", &hostapd_path])
        .output()
        .map_err(|e| {
            eprintln!("[HOTSPOT] ERROR: Failed to spawn hostapd: {}", e);
            WirelessError::System(format!("spawn hostapd: {}", e))
        })?;
    
    if !hostapd_output.status.success() {
        let stderr = String::from_utf8_lossy(&hostapd_output.stderr);
        let stdout = String::from_utf8_lossy(&hostapd_output.stdout);
        eprintln!("[HOTSPOT] ERROR: hostapd command failed");
        eprintln!("[HOTSPOT]   stderr: {}", stderr);
        eprintln!("[HOTSPOT]   stdout: {}", stdout);
        log::error!("hostapd command failed: stderr={}, stdout={}", stderr, stdout);
        return Err(WirelessError::System(format!(
            "hostapd failed to start: {}",
            if stderr.is_empty() { stdout.as_ref() } else { stderr.as_ref() }
        )));
    }
    
    eprintln!("[HOTSPOT] hostapd command executed, waiting for initialization...");
    log::debug!("hostapd command executed, waiting for initialization...");
    
    // Give hostapd more time to initialize AP before checking
    std::thread::sleep(std::time::Duration::from_secs(3));
    
    // Verify hostapd is actually running by checking for our specific config file
    eprintln!("[HOTSPOT] Verifying hostapd is running...");
    let hostapd_running = Command::new("pgrep")
        .arg("-f")
        .arg(&format!("hostapd.*{}", hostapd_path))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    
    if !hostapd_running {
        eprintln!("[HOTSPOT] ERROR: hostapd is not running after start - checking logs");
        log::error!("hostapd is not running after start - checking logs");
        
        // Try to get error info from syslog
        let log_output = Command::new("grep")
            .args(&["hostapd", "/var/log/syslog"])
            .output();
        
        if let Ok(output) = log_output {
            let logs = String::from_utf8_lossy(&output.stdout);
            let recent_lines: Vec<&str> = logs.lines().rev().take(5).collect();
            eprintln!("[HOTSPOT] Recent syslog entries:");
            for line in recent_lines.iter().rev() {
                eprintln!("[HOTSPOT]   {}", line);
                log::error!("syslog: {}", line);
            }
        }
        
        return Err(WirelessError::System(
            "hostapd exited immediately after start - interface may not support AP mode, or driver issue. Check 'tail /var/log/syslog'".to_string()
        ));
    }
    
    eprintln!("[HOTSPOT] hostapd is running successfully");
    log::info!("hostapd is running, starting dnsmasq...");
    
    // Give hostapd and the interface more time to fully initialize
    // The interface needs to be fully up with its IP before dnsmasq can bind to it
    eprintln!("[HOTSPOT] Waiting for interface to stabilize before starting dnsmasq...");
    std::thread::sleep(std::time::Duration::from_secs(3));
    
    // Start dnsmasq
    eprintln!("[HOTSPOT] Starting dnsmasq with config: {}", dns_path);
    let dnsmasq_cmd_str = format!("--conf-file={}", dns_path);
    eprintln!("[HOTSPOT] Command: dnsmasq {}", dnsmasq_cmd_str);
    let dnsmasq_output = Command::new("dnsmasq")
        .arg(&dnsmasq_cmd_str)
        .output()
        .map_err(|e| {
            eprintln!("[HOTSPOT] ERROR: Failed to spawn dnsmasq: {}", e);
            WirelessError::System(format!("spawn dnsmasq: {}", e))
        })?;
    
    if !dnsmasq_output.status.success() {
        let stderr = String::from_utf8_lossy(&dnsmasq_output.stderr);
        let stdout = String::from_utf8_lossy(&dnsmasq_output.stdout);
        eprintln!("[HOTSPOT] ERROR: dnsmasq command failed");
        eprintln!("[HOTSPOT]   stderr: {}", stderr);
        eprintln!("[HOTSPOT]   stdout: {}", stdout);
        log::error!("dnsmasq failed: stderr={}, stdout={}", stderr, stdout);
        // Clean up hostapd before returning error
        let _ = Command::new("pkill").args(["-f", "hostapd"]).status();
        return Err(WirelessError::System(format!(
            "dnsmasq failed to start: {}",
            if stderr.is_empty() { stdout.as_ref() } else { stderr.as_ref() }
        )));
    }
    
    // Verify dnsmasq is actually running
    std::thread::sleep(std::time::Duration::from_millis(500));
    eprintln!("[HOTSPOT] Verifying dnsmasq is running...");
    let dnsmasq_running = Command::new("pgrep")
        .arg("-f")
        .arg(&format!("dnsmasq.*{}", dns_path))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    
    if !dnsmasq_running {
        eprintln!("[HOTSPOT] ERROR: dnsmasq is not running after start");
        log::error!("dnsmasq is not running after start");
        // Clean up hostapd before returning error
        let _ = Command::new("pkill").args(["-f", "hostapd"]).status();
        return Err(WirelessError::System(
            "dnsmasq started but is not running; port 53 or 67 may be in use".to_string()
        ));
    }
    
    eprintln!("[HOTSPOT] dnsmasq is running successfully");
    log::info!("dnsmasq is running");
    
    // Get actual PIDs after verification
    let hostapd_pid = get_pid_by_pattern(&format!("hostapd.*{}", hostapd_path));
    let dnsmasq_pid = get_pid_by_pattern(&format!("dnsmasq.*{}", dns_path));
    
    eprintln!("[HOTSPOT] Hotspot started successfully!");
    eprintln!("[HOTSPOT]   hostapd PID: {:?}", hostapd_pid);
    eprintln!("[HOTSPOT]   dnsmasq PID: {:?}", dnsmasq_pid);
    eprintln!("[HOTSPOT]   SSID: {}", config.ssid);
    eprintln!("[HOTSPOT]   Password: {}", config.password);
    log::info!("Hotspot started successfully: hostapd_pid={:?}, dnsmasq_pid={:?}", hostapd_pid, dnsmasq_pid);

    let state = HotspotState {
        ssid: config.ssid,
        password: config.password,
        ap_interface: config.ap_interface,
        upstream_interface: config.upstream_interface,
        channel: config.channel,
        upstream_ready,
        hostapd_pid,
        dnsmasq_pid,
    };
    persist_state(&state)?;
    Ok(state)
}

/// Stop a running hotspot and clean up.
pub fn stop_hotspot() -> Result<()> {
    eprintln!("[HOTSPOT] ========== HOTSPOT STOP ATTEMPT ==========");
    log::info!("Stopping hotspot");
    
    let state = status_hotspot();

    // Best-effort kill processes
    if let Some(s) = state {
        eprintln!("[HOTSPOT] Stopping hotspot processes...");
        
        // Kill hostapd
        if let Some(pid) = s.hostapd_pid {
            eprintln!("[HOTSPOT] Killing hostapd PID {}...", pid);
            let _ = Command::new("kill").arg(pid.to_string()).status();
        } else {
            eprintln!("[HOTSPOT] Killing any hostapd processes...");
            let _ = Command::new("pkill")
                .args(["-f", "hostapd"])
                .status();
        }
        
        // Small delay to let hostapd clean up
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        // Kill dnsmasq
        if let Some(pid) = s.dnsmasq_pid {
            eprintln!("[HOTSPOT] Killing dnsmasq PID {}...", pid);
            let _ = Command::new("kill").arg(pid.to_string()).status();
        } else {
            eprintln!("[HOTSPOT] Killing any dnsmasq processes...");
            let _ = Command::new("pkill").args(["-f", "dnsmasq"]).status();
        }
        
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Remove iptables rules (ignore errors if not present)
        if s.upstream_ready && !s.upstream_interface.is_empty() {
            eprintln!("[HOTSPOT] Removing iptables rules...");
            let _ = Command::new("iptables")
                .args([
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-o",
                    &s.upstream_interface,
                    "-j",
                    "MASQUERADE",
                ])
                .status();
            let _ = Command::new("iptables")
                .args([
                    "-D",
                    "FORWARD",
                    "-i",
                    &s.upstream_interface,
                    "-o",
                    &s.ap_interface,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ])
                .status();
            let _ = Command::new("iptables")
                .args([
                    "-D",
                    "FORWARD",
                    "-i",
                    &s.ap_interface,
                    "-o",
                    &s.upstream_interface,
                    "-j",
                    "ACCEPT",
                ])
                .status();
        }
        
        // DO NOT restore NetworkManager management immediately
        // NetworkManager re-blocks RF-kill when it takes control, which breaks subsequent hotspot starts
        // Instead, leave interface unmanaged but ensure it's in a clean state
        eprintln!("[HOTSPOT] Cleaning up interface {} (leaving unmanaged to prevent RF-kill issues)...", s.ap_interface);
        log::info!("Cleaning up interface {} after hotspot stop", s.ap_interface);
        
        // Bring interface down to clean state
        let _ = Command::new("ip")
            .args(["link", "set", &s.ap_interface, "down"])
            .status();
        
        // Flush any remaining IPs
        let _ = Command::new("ip")
            .args(["addr", "flush", "dev", &s.ap_interface])
            .status();
        
        // Ensure RF-kill stays unblocked
        eprintln!("[HOTSPOT] Ensuring RF-kill stays unblocked...");
        let _ = Command::new("rfkill").args(&["unblock", "all"]).status();
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        eprintln!("[HOTSPOT] NOTE: Interface {} left unmanaged to prevent RF-kill blocking", s.ap_interface);
        log::info!("Interface {} left unmanaged to prevent RF-kill issues", s.ap_interface);
    } else {
        eprintln!("[HOTSPOT] No hotspot state found, performing general cleanup...");
        
        // Kill any running processes anyway
        let _ = Command::new("pkill").args(["-f", "hostapd"]).status();
        let _ = Command::new("pkill").args(["-f", "dnsmasq"]).status();
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
    for tool in ["hostapd", "dnsmasq", "iptables"] {
        if Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool} >/dev/null 2>&1"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            continue;
        } else {
            return Err(WirelessError::System(format!(
                "Required tool missing: {tool}"
            )));
        }
    }
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
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(pattern)
        .output()
        .ok()?;
    
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next()?.trim().parse().ok()
    } else {
        None
    }
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
    
    // Check if the PHY supports AP mode using `iw list`
    let output = Command::new("iw")
        .arg("list")
        .output()
        .map_err(|e| WirelessError::System(format!("iw list failed: {}", e)))?;
    
    if !output.status.success() {
        return Err(WirelessError::System(format!(
            "iw list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Look for AP mode support - be more lenient and just warn if not found
    if !stdout.contains("* AP") && !stdout.contains("AP/VLAN") {
        log::warn!("{} may not support AP mode; attempting anyway", interface);
        // Don't fail here - let hostapd determine if it can run
    }
    
    Ok(())
}

fn ensure_upstream_ready(interface: &str) -> Result<()> {
    let output = Command::new("ip")
        .args(["-4", "addr", "show", "dev", interface])
        .output()
        .map_err(|e| WirelessError::System(format!("ip addr show failed: {}", e)))?;
    if !output.status.success() {
        return Err(WirelessError::System(format!(
            "ip addr show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let has_ip = stdout.lines().any(|l| l.trim_start().starts_with("inet "));
    if !has_ip {
        return Err(WirelessError::Interface(format!(
            "Upstream {} has no IPv4 address; connect it before starting hotspot",
            interface
        )));
    }
    Ok(())
}
