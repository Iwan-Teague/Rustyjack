use std::{
    fs,
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use anyhow::{Result, Context, anyhow};
use log::{info, warn, debug};
use rand::Rng;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    pub mac_randomization: bool,
    pub mac_rotation_interval_secs: u64,
    pub ttl_randomization: bool,
    pub packet_fragmentation: bool,
    pub timing_randomization: bool,
    pub fingerprint_spoofing: Option<String>, // "windows", "macos", "linux"
    pub spoof_dhcp: bool,
    pub spoof_usb: bool,
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
            spoof_dhcp: false,
            spoof_usb: false,
        }
    }
}

/// Generate a random MAC address with a valid vendor prefix
pub fn generate_random_mac(preserve_vendor: bool, current_mac: Option<&str>) -> Result<String> {
    let mut rng = rand::thread_rng();
    
    if preserve_vendor {
        // Keep first 3 octets (OUI), randomize last 3
        if let Some(mac) = current_mac {
            let parts: Vec<&str> = mac.split(':').collect();
            if parts.len() == 6 {
                return Ok(format!(
                    "{}:{}:{}:{:02x}:{:02x}:{:02x}",
                    parts[0], parts[1], parts[2],
                    rng.gen::<u8>(),
                    rng.gen::<u8>(),
                    rng.gen::<u8>()
                ));
            }
        }
    }
    
    // Generate completely random MAC
    // Set locally administered bit (bit 1 of first octet)
    let first = rng.gen::<u8>() | 0x02;
    
    Ok(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        first,
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>()
    ))
}

/// Set MAC address for an interface
pub fn set_mac_address(interface: &str, mac: &str) -> Result<()> {
    // Bring interface down
    Command::new("ip")
        .args(["link", "set", interface, "down"])
        .status()
        .context("bringing interface down")?;
    
    // Set new MAC
    Command::new("ip")
        .args(["link", "set", interface, "address", mac])
        .status()
        .context("setting MAC address")?;
    
    // Bring interface back up
    Command::new("ip")
        .args(["link", "set", interface, "up"])
        .status()
        .context("bringing interface up")?;
    
    info!("MAC address changed to {} on {}", mac, interface);
    Ok(())
}

/// Get current MAC address of an interface
pub fn get_mac_address(interface: &str) -> Result<String> {
    let output = Command::new("ip")
        .args(["link", "show", interface])
        .output()
        .context("reading MAC address")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse MAC from output like: "link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"
    for line in stdout.lines() {
        if line.contains("link/ether") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Ok(parts[1].to_string());
            }
        }
    }
    
    Err(anyhow!("Could not parse MAC address from ip output"))
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

/// Configure iptables for packet fragmentation
pub fn enable_packet_fragmentation(enable: bool) -> Result<()> {
    if enable {
        // Fragment packets to evade IDS
        Command::new("iptables")
            .args(["-A", "OUTPUT", "-j", "TCPMSS", "--set-mss", "500"])
            .status()
            .context("enabling packet fragmentation")?;
        info!("Packet fragmentation enabled");
    } else {
        // Remove fragmentation rule
        Command::new("iptables")
            .args(["-D", "OUTPUT", "-j", "TCPMSS", "--set-mss", "500"])
            .status()
            .ok(); // Ignore errors if rule doesn't exist
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
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(interval_secs));
            
            match get_mac_address(&interface) {
                Ok(current_mac) => {
                    match generate_random_mac(true, Some(&current_mac)) {
                        Ok(new_mac) => {
                            if let Err(e) = set_mac_address(&interface, &new_mac) {
                                warn!("Failed to rotate MAC: {}", e);
                            } else {
                                info!("MAC rotated on {}: {}", interface, new_mac);
                            }
                        }
                        Err(e) => warn!("Failed to generate MAC: {}", e),
                    }
                }
                Err(e) => warn!("Failed to get current MAC: {}", e),
            }
        }
    });
    
    info!("MAC rotation started on {} (interval: {}s)", interface, interval_secs);
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

/// Configure DHCP client to send specific hostname
pub fn spoof_dhcp_hostname(interface: &str, hostname: &str) -> Result<()> {
    info!("Configuring DHCP hostname for {}", interface);
    
    // Create a temporary dhclient config
    let config_content = format!(
        "interface \"{}\" {{\n    send host-name \"{}\";\n}}\n",
        interface, hostname
    );
    
    let config_path = format!("/tmp/dhclient_{}.conf", interface);
    fs::write(&config_path, config_content)?;
    
    // Release current lease
    Command::new("dhclient")
        .args(["-r", interface])
        .status()
        .ok();
        
    // Request new lease with config
    Command::new("dhclient")
        .args(["-cf", &config_path, "-v", interface])
        .status()
        .context("running dhclient with spoofed hostname")?;
        
    info!("DHCP hostname spoofed to {}", hostname);
    Ok(())
}

/// Attempt to spoof USB gadget identity (if applicable)
pub fn spoof_usb_identity() -> Result<()> {
    // This targets the common configfs gadget setup on Pi Zero
    let gadget_path = Path::new("/sys/kernel/config/usb_gadget/g1");
    
    if !gadget_path.exists() {
        return Ok(()); // Not using configfs gadget mode
    }
    
    info!("Spoofing USB gadget identity");
    
    // Common generic Ethernet adapter IDs (e.g., Realtek)
    // Note: Changing these while connected might drop the connection
    // Ideally this runs at boot, but we can try to update strings
    
    let strings_path = gadget_path.join("strings/0x409");
    if strings_path.exists() {
        // Generic manufacturer
        let _ = fs::write(strings_path.join("manufacturer"), "Generic");
        // Generic product
        let _ = fs::write(strings_path.join("product"), "USB Ethernet Adapter");
        // Random serial
        let mut rng = rand::thread_rng();
        let serial: u32 = rng.gen();
        let _ = fs::write(strings_path.join("serialnumber"), format!("{:08X}", serial));
    }
    
    Ok(())
}
