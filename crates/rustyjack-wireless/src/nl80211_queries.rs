use crate::error::{Result, WirelessError};
use std::time::Duration;

/// Scan result entry
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub bssid: String,
    pub ssid: String,
    pub frequency: u32,
    pub channel: Option<u8>,
    pub signal_mbm: i32,
    pub signal_dbm: f32,
    pub seen_ms_ago: u32,
    pub beacon_interval: u16,
    pub capability: u16,
    pub tsf: u64,
}

impl ScanResult {
    /// Convert frequency to channel number (2.4GHz and 5GHz)
    pub fn freq_to_channel(freq: u32) -> Option<u8> {
        match freq {
            // 2.4 GHz
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
            // 5 GHz - basic channels
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
}

/// Link status information
#[derive(Debug, Clone)]
pub struct LinkStatus {
    pub connected: bool,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub frequency: Option<u32>,
    pub channel: Option<u8>,
    pub signal_dbm: Option<i32>,
    pub tx_bitrate_mbps: Option<f32>,
    pub rx_bitrate_mbps: Option<f32>,
}

/// Station information (for AP mode)
#[derive(Debug, Clone)]
pub struct StationInfo {
    pub mac: String,
    pub inactive_time_ms: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub signal_dbm: i8,
    pub signal_avg_dbm: i8,
    pub tx_bitrate_mbps: Option<f32>,
    pub rx_bitrate_mbps: Option<f32>,
    pub connected_time_sec: u32,
}

/// Interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ifindex: u32,
    pub wdev: u64,
    pub addr: Option<String>,
    pub ssid: Option<String>,
    pub iftype: u32,
    pub wiphy: u32,
    pub frequency: Option<u32>,
    pub channel: Option<u8>,
    pub channel_width: Option<String>,
    pub txpower_dbm: Option<i32>,
}

/// Get scan results via nl80211 scan
pub fn get_scan_results(interface: &str) -> Result<Vec<ScanResult>> {
    let results = rustyjack_netlink::scan_wifi_networks(interface, Duration::from_secs(5))
        .map_err(|e| WirelessError::System(format!("Failed to run nl80211 scan: {}", e)))?;

    let mut entries = Vec::new();
    for entry in results {
        let bssid = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            entry.bssid[0],
            entry.bssid[1],
            entry.bssid[2],
            entry.bssid[3],
            entry.bssid[4],
            entry.bssid[5]
        );
        let ssid = entry.ssid.unwrap_or_default();
        let frequency = entry.frequency.unwrap_or(0);
        let channel = ScanResult::freq_to_channel(frequency);
        let signal_dbm = entry
            .signal_mbm
            .map(|mbm| mbm as f32 / 100.0)
            .unwrap_or(0.0);

        entries.push(ScanResult {
            bssid,
            ssid,
            frequency,
            channel,
            signal_mbm: entry.signal_mbm.unwrap_or(0),
            signal_dbm,
            seen_ms_ago: entry.seen_ms_ago.unwrap_or(0),
            beacon_interval: entry.beacon_interval.unwrap_or(0),
            capability: entry.capability.unwrap_or(0),
            tsf: 0,
        });
    }

    Ok(entries)
}

/// Get link status for a connected interface
pub fn get_link_status(interface: &str) -> Result<LinkStatus> {
    let operstate = std::fs::read_to_string(format!("/sys/class/net/{}/operstate", interface))
        .unwrap_or_default();
    let connected = operstate.trim() == "up";
    let mut freq = None;
    if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
        if let Ok(info) = mgr.get_interface_info(interface) {
            freq = info.frequency;
        }
    }
    Ok(LinkStatus {
        connected,
        ssid: None,
        bssid: None,
        frequency: freq,
        channel: freq.and_then(ScanResult::freq_to_channel),
        signal_dbm: None,
        tx_bitrate_mbps: None,
        rx_bitrate_mbps: None,
    })
}

/// Interface capability information
#[derive(Debug, Clone)]
pub struct InterfaceCapabilities {
    pub name: String,
    pub is_wireless: bool,
    pub is_physical: bool,
    pub supports_monitor: bool,
    pub supports_ap: bool,
    pub supports_injection: bool,
    pub supports_5ghz: bool,
    pub supports_2ghz: bool,
    pub mac_address: Option<String>,
    pub driver: Option<String>,
    pub chipset: Option<String>,
}

/// Query interface capabilities via nl80211 and sysfs
pub fn query_interface_capabilities(iface: &str) -> Result<InterfaceCapabilities> {
    // Check if wireless
    let is_wireless = crate::is_wireless_interface(iface);

    let mut caps = InterfaceCapabilities {
        name: iface.to_string(),
        is_wireless,
        is_physical: true,
        supports_monitor: false,
        supports_ap: false,
        supports_injection: false,
        supports_5ghz: false,
        supports_2ghz: false,
        mac_address: None,
        driver: None,
        chipset: None,
    };

    // Get MAC address
    if let Ok(mac_bytes) = crate::nl80211::get_mac_address(iface) {
        caps.mac_address = Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
        ));
    }

    // Check if virtual interface
    let sysfs_path = format!("/sys/class/net/{}", iface);
    let device_path = format!("{}/device", sysfs_path);
    caps.is_physical = std::path::Path::new(&device_path).exists();

    if !is_wireless {
        return Ok(caps);
    }

    // Query wireless capabilities via WirelessManager
    if let Ok(mut mgr) = rustyjack_netlink::WirelessManager::new() {
        // Check supported interface types (monitor, AP, etc.)
        if let Ok(phy_caps) = mgr.get_phy_capabilities(iface) {
            // Check for monitor mode support
            caps.supports_monitor = phy_caps
                .supported_modes
                .contains(&rustyjack_netlink::InterfaceMode::Monitor);

            // Check for AP mode support
            caps.supports_ap = phy_caps
                .supported_modes
                .contains(&rustyjack_netlink::InterfaceMode::AccessPoint);

            // Check band support from band names
            for band_name in &phy_caps.supported_bands {
                if band_name.contains("2.4") || band_name.contains("2GHz") {
                    caps.supports_2ghz = true;
                } else if band_name.contains("5") || band_name.contains("5GHz") {
                    caps.supports_5ghz = true;
                }
            }
        }

        // Injection support heuristic:
        // If monitor mode is supported, assume injection is supported
        // (actual injection capability requires testing, but monitor is a good proxy)
        caps.supports_injection = caps.supports_monitor;
    }

    // Read driver info from sysfs
    let uevent_path = format!("{}/device/uevent", sysfs_path);
    if let Ok(contents) = std::fs::read_to_string(&uevent_path) {
        for line in contents.lines() {
            if let Some(driver_line) = line.strip_prefix("DRIVER=") {
                caps.driver = Some(driver_line.to_string());
            }
        }
    }

    // Try to identify chipset from driver
    if let Some(ref driver) = caps.driver {
        caps.chipset = match driver.as_str() {
            "ath9k" | "ath9k_htc" => Some("Atheros AR9xxx".to_string()),
            "rtl8812au" | "rtl8814au" | "88XXau" => Some("Realtek RTL88xxAU".to_string()),
            "rt2800usb" => Some("Ralink RT2800".to_string()),
            "mt7601u" => Some("MediaTek MT7601U".to_string()),
            "brcmfmac" => Some("Broadcom FullMAC".to_string()),
            _ if driver.starts_with("rtl") => Some(format!("Realtek {}", driver)),
            _ if driver.starts_with("ath") => Some(format!("Atheros {}", driver)),
            _ => Some(driver.clone()),
        };
    }

    Ok(caps)
}

/// Get station info for AP mode
pub fn get_station_info(interface: &str) -> Result<Vec<StationInfo>> {
    let mut stations = Vec::new();
    if let Ok(contents) = std::fs::read_to_string("/proc/net/arp") {
        for (idx, line) in contents.lines().enumerate() {
            if idx == 0 {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            if parts[5] != interface {
                continue;
            }
            let mac = parts[3];
            if mac == "00:00:00:00:00:00" {
                continue;
            }
            stations.push(StationInfo {
                mac: mac.to_string(),
                inactive_time_ms: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                signal_dbm: 0,
                signal_avg_dbm: 0,
                tx_bitrate_mbps: None,
                rx_bitrate_mbps: None,
                connected_time_sec: 0,
            });
        }
    }

    Ok(stations)
}

/// Get interface information
pub fn get_interface_info(interface: &str) -> Result<InterfaceInfo> {
    let mut mgr = rustyjack_netlink::WirelessManager::new()
        .map_err(|e| WirelessError::System(format!("Failed to open nl80211: {}", e)))?;
    let info = mgr.get_interface_info(interface).map_err(|e| {
        WirelessError::System(format!(
            "Failed to get interface info for {}: {}",
            interface, e
        ))
    })?;

    let addr = {
        use tokio::runtime::Handle;
        let fetch = |handle: &Handle| {
            handle.block_on(async {
                let mgr = rustyjack_netlink::InterfaceManager::new()
                    .map_err(|e| WirelessError::System(format!("Failed to open netlink: {}", e)))?;
                mgr.get_mac_address(interface)
                    .await
                    .map_err(|e| WirelessError::System(format!("Failed to read MAC: {}", e)))
            })
        };
        match Handle::try_current() {
            Ok(handle) => fetch(&handle).ok(),
            Err(_) => tokio::runtime::Runtime::new()
                .ok()
                .and_then(|rt| fetch(rt.handle()).ok()),
        }
    };

    let ssid = None;

    let iftype = match info.mode {
        Some(rustyjack_netlink::InterfaceMode::Adhoc) => 1,
        Some(rustyjack_netlink::InterfaceMode::Station) => 2,
        Some(rustyjack_netlink::InterfaceMode::AccessPoint) => 3,
        Some(rustyjack_netlink::InterfaceMode::Monitor) => 6,
        Some(rustyjack_netlink::InterfaceMode::MeshPoint) => 7,
        Some(rustyjack_netlink::InterfaceMode::P2PClient) => 8,
        Some(rustyjack_netlink::InterfaceMode::P2PGo) => 9,
        _ => 0,
    };

    Ok(InterfaceInfo {
        name: info.interface,
        ifindex: info.ifindex,
        wdev: 0,
        addr,
        ssid,
        iftype,
        wiphy: info.wiphy,
        frequency: info.frequency,
        channel: info.channel,
        channel_width: None,
        txpower_dbm: info.txpower_mbm.map(|v| (v / 100) as i32),
    })
}
