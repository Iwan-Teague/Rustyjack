use std::fs;
use std::path::Path;
use std::process::Command;

use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};

use crate::error::{Result, WirelessError};

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
    ensure_tools_present()?;
    ensure_interface_exists(&config.ap_interface)?;
    if !config.upstream_interface.is_empty() {
        ensure_interface_exists(&config.upstream_interface)?;
    }
    ensure_ap_capability(&config.ap_interface)?;
    let mut upstream_ready = false;
    if !config.upstream_interface.is_empty() {
        match ensure_upstream_ready(&config.upstream_interface) {
            Ok(_) => upstream_ready = true,
            Err(WirelessError::Interface(msg)) if msg.contains("has no IPv4 address") => {
                // Allow offline hotspot; continue without upstream/NAT
                upstream_ready = false;
                log::warn!("Hotspot upstream not ready: {msg}");
            }
            Err(err) => return Err(err),
        }
    }
    fs::create_dir_all(CONF_DIR).map_err(|e| WirelessError::System(format!("mkdir: {e}")))?;

    // Ensure previous instances are stopped to avoid dhcp bind failures
    let _ = Command::new("pkill").args(["-f", "hostapd"]).status();
    let _ = Command::new("pkill").args(["-f", "dnsmasq"]).status();

    // Bring AP interface up with static IP
    run_cmd("ip", &["link", "set", &config.ap_interface, "down"])?;
    run_cmd("ip", &["addr", "flush", "dev", &config.ap_interface])?;
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
    run_cmd("ip", &["link", "set", &config.ap_interface, "up"])?;

    // Enable forwarding
    let _ = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);

    // NAT rules (only if upstream is present and ready)
    if upstream_ready && !config.upstream_interface.is_empty() {
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
    fs::write(&hostapd_path, hostapd_conf)
        .map_err(|e| WirelessError::System(format!("writing hostapd.conf: {e}")))?;

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
    fs::write(&dns_path, dns_conf)
        .map_err(|e| WirelessError::System(format!("writing dnsmasq.conf: {e}")))?;

    // Give interface time to stabilize
    std::thread::sleep(std::time::Duration::from_millis(500));

    let hostapd = spawn_background("hostapd", &["-B", &hostapd_path])?;
    
    // Give hostapd time to initialize AP before starting DHCP
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    let dnsmasq = spawn_background("dnsmasq", &["--conf-file", &dns_path])?;

    let state = HotspotState {
        ssid: config.ssid,
        password: config.password,
        ap_interface: config.ap_interface,
        upstream_interface: config.upstream_interface,
        channel: config.channel,
        upstream_ready,
        hostapd_pid: hostapd,
        dnsmasq_pid: dnsmasq,
    };
    persist_state(&state)?;
    Ok(state)
}

/// Stop a running hotspot and clean up.
pub fn stop_hotspot() -> Result<()> {
    let state = status_hotspot();

    // Best-effort kill processes
    if let Some(s) = state {
        if let Some(pid) = s.hostapd_pid {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        } else {
            let _ = Command::new("pkill")
                .args(["-f", "hostapd.*rustyjack"])
                .status();
        }
        if let Some(pid) = s.dnsmasq_pid {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        } else {
            let _ = Command::new("pkill").args(["-f", "dnsmasq"]).status();
        }

        // Remove iptables rules (ignore errors if not present)
        if s.upstream_ready && !s.upstream_interface.is_empty() {
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
    }

    let _ = fs::remove_file(STATE_PATH);
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
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| WirelessError::System(format!("Failed to run {} {:?}: {}", cmd, args, e)))?;
    if !output.status.success() {
        return Err(WirelessError::System(format!(
            "{} {:?} failed: {}",
            cmd,
            args,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
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
    // Basic check: ensure interface is wireless and supports AP mode using `iw list`.
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
    if !stdout.contains("* AP") && !stdout.contains("AP/VLAN") {
        return Err(WirelessError::Unsupported(format!(
            "{} does not appear to support AP mode",
            interface
        )));
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
