use std::{fs, path::Path, process::Command, thread, time::Duration};

use anyhow::{anyhow, Context, Result};
use tracing::{debug, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use rustyjack_evasion::{MacAddress, MacManager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    pub mac_randomization: bool,
    pub mac_rotation_interval_secs: u64,
    pub ttl_randomization: bool,
    pub packet_fragmentation: bool,
    pub timing_randomization: bool,
    pub fingerprint_spoofing: Option<String>, // "windows", "macos", "linux"
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            mac_randomization: false,
            mac_rotation_interval_secs: 300, // 5 minutes
            ttl_randomization: false,
            packet_fragmentation: false,
            timing_randomization: false,
            fingerprint_spoofing: None,
        }
    }
}

/// Generate a random MAC address with a valid vendor prefix
pub fn generate_random_mac(preserve_vendor: bool, current_mac: Option<&str>) -> Result<String> {
    if preserve_vendor {
        if let Some(mac) = current_mac {
            if let Ok(parsed) = MacAddress::parse(mac) {
                let randomized = MacAddress::random_with_oui(parsed.oui())?;
                return Ok(randomized.to_string());
            }
        }
    }

    Ok(MacAddress::random()?.to_string())
}

/// Set MAC address for an interface
pub fn set_mac_address(interface: &str, mac: &str) -> Result<()> {
    let mut manager = MacManager::new().context("creating MacManager")?;
    manager.set_auto_restore(false);
    let mac = MacAddress::parse(mac)?;
    manager.set_mac(interface, &mac)?;
    info!("MAC address changed to {} on {}", mac, interface);
    Ok(())
}

/// Get current MAC address of an interface
pub fn get_mac_address(interface: &str) -> Result<String> {
    let manager = MacManager::new().context("creating MacManager")?;
    let mac = manager.get_mac(interface)?;
    Ok(mac.to_string())
}

/// Spoof OS fingerprint by modifying network stack parameters
pub fn spoof_os_fingerprint(os_type: &str) -> Result<()> {
    match os_type {
        "windows" => {
            // Windows 10 defaults
            set_sysctl("net.ipv4.tcp_window_scaling", "1")?;
            set_sysctl("net.ipv4.tcp_timestamps", "1")?;
            set_sysctl("net.ipv4.ip_default_ttl", "128")?; // Windows TTL
            set_sysctl("net.ipv4.tcp_sack", "1")?;
            info!("Fingerprint spoofed to Windows");
        }
        "macos" => {
            // macOS defaults
            set_sysctl("net.ipv4.tcp_window_scaling", "1")?;
            set_sysctl("net.ipv4.tcp_timestamps", "1")?;
            set_sysctl("net.ipv4.ip_default_ttl", "64")?; // macOS TTL
            set_sysctl("net.ipv4.tcp_sack", "1")?;
            info!("Fingerprint spoofed to macOS");
        }
        "linux" => {
            // Linux defaults (restore original)
            set_sysctl("net.ipv4.tcp_window_scaling", "1")?;
            set_sysctl("net.ipv4.tcp_timestamps", "1")?;
            set_sysctl("net.ipv4.ip_default_ttl", "64")?;
            set_sysctl("net.ipv4.tcp_sack", "1")?;
            info!("Fingerprint restored to Linux defaults");
        }
        _ => {
            return Err(anyhow!("Unknown OS type: {}", os_type));
        }
    }

    Ok(())
}

/// Set a sysctl parameter
fn set_sysctl(param: &str, value: &str) -> Result<()> {
    let status = Command::new("sysctl")
        .args(["-w", &format!("{}={}", param, value)])
        .status()
        .context("setting sysctl parameter")?;

    if !status.success() {
        warn!("Failed to set sysctl {} = {}", param, value);
    }

    Ok(())
}

/// Randomize TTL value for outgoing packets
pub fn randomize_ttl() -> Result<()> {
    let mut rng = rand::thread_rng();
    // Common TTL values: 64 (Linux/Mac), 128 (Windows), 255 (Cisco)
    let ttl = match rng.gen_range(0..3) {
        0 => 64,
        1 => 128,
        _ => 255,
    };

    set_sysctl("net.ipv4.ip_default_ttl", &ttl.to_string())?;
    debug!("TTL randomized to {}", ttl);
    Ok(())
}

/// Configure packet fragmentation using TCP MSS clamping
pub fn enable_packet_fragmentation(enable: bool) -> Result<()> {
    use rustyjack_netlink::IptablesManager;

    let ipt = IptablesManager::new()
        .context("Failed to initialize iptables manager for packet fragmentation")?;

    if enable {
        ipt.add_tcp_mss(500)
            .context("Failed to enable packet fragmentation via TCP MSS")?;
        info!("Packet fragmentation enabled (TCP MSS=500)");
    } else {
        ipt.delete_tcp_mss(500).ok();
        info!("Packet fragmentation disabled");
    }

    Ok(())
}

/// Add random delays to evade timing-based detection
pub fn random_delay(min_ms: u64, max_ms: u64) {
    let mut rng = rand::thread_rng();
    let delay_ms = rng.gen_range(min_ms..=max_ms);
    thread::sleep(Duration::from_millis(delay_ms));
}

/// Start MAC rotation daemon
pub fn start_mac_rotation(interface: String, interval_secs: u64) -> Result<()> {
    let iface_clone = interface.clone();

    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(interval_secs));

        match get_mac_address(&iface_clone) {
            Ok(current_mac) => match generate_random_mac(true, Some(&current_mac)) {
                Ok(new_mac) => {
                    if let Err(e) = set_mac_address(&iface_clone, &new_mac) {
                        warn!("Failed to rotate MAC: {}", e);
                    } else {
                        info!("MAC rotated on {}: {}", iface_clone, new_mac);
                    }
                }
                Err(e) => warn!("Failed to generate MAC: {}", e),
            },
            Err(e) => warn!("Failed to get current MAC: {}", e),
        }
    });

    info!(
        "MAC rotation started on {} (interval: {}s)",
        interface, interval_secs
    );
    Ok(())
}

/// Apply full evasion profile
pub fn apply_evasion_profile(interface: &str, config: &EvasionConfig) -> Result<()> {
    info!("Applying evasion profile to {}", interface);

    if config.mac_randomization {
        let current = get_mac_address(interface)?;
        let new_mac = generate_random_mac(true, Some(&current))?;
        set_mac_address(interface, &new_mac)?;

        if config.mac_rotation_interval_secs > 0 {
            start_mac_rotation(interface.to_string(), config.mac_rotation_interval_secs)?;
        }
    }

    if config.ttl_randomization {
        randomize_ttl()?;
    }

    if config.packet_fragmentation {
        enable_packet_fragmentation(true)?;
    }

    if let Some(ref os) = config.fingerprint_spoofing {
        spoof_os_fingerprint(os)?;
    }

    info!("Evasion profile applied successfully");
    Ok(())
}

/// Restore original network settings
pub fn restore_original_settings(interface: &str, original_mac: Option<&str>) -> Result<()> {
    info!("Restoring original settings for {}", interface);

    if let Some(mac) = original_mac {
        set_mac_address(interface, mac)?;
    }

    // Restore default TTL
    set_sysctl("net.ipv4.ip_default_ttl", "64")?;

    // Disable fragmentation
    enable_packet_fragmentation(false)?;

    info!("Original settings restored");
    Ok(())
}

/// Save current MAC addresses for restoration
pub fn save_original_macs(root: &Path) -> Result<()> {
    let interfaces = crate::system::list_interface_summaries()?;
    let mut macs = std::collections::HashMap::new();

    for iface in interfaces {
        if let Ok(mac) = get_mac_address(&iface.name) {
            macs.insert(iface.name, mac);
        }
    }

    let path = root.join("wifi").join("original_macs.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&macs)?;
    fs::write(&path, json)?;

    info!("Original MAC addresses saved");
    Ok(())
}

/// Load saved MAC addresses
pub fn load_original_macs(root: &Path) -> Result<std::collections::HashMap<String, String>> {
    let path = root.join("wifi").join("original_macs.json");

    if !path.exists() {
        return Ok(std::collections::HashMap::new());
    }

    let json = fs::read_to_string(&path)?;
    let macs = serde_json::from_str(&json)?;

    Ok(macs)
}
