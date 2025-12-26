use crate::error::{Result, WirelessError};

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

/// Get scan results via wpa_supplicant scan results
pub fn get_scan_results(interface: &str) -> Result<Vec<ScanResult>> {
    if let Err(e) = rustyjack_netlink::start_wpa_supplicant(interface, None) {
        log::warn!("Failed to start wpa_supplicant for {}: {}", interface, e);
    }

    let wpa = rustyjack_netlink::WpaManager::new(interface)
        .map_err(|e| WirelessError::System(format!("Failed to open wpa control: {}", e)))?;
    wpa.scan()
        .map_err(|e| WirelessError::System(format!("Failed to trigger scan: {}", e)))?;

    let mut results = Vec::new();
    for entry in wpa
        .scan_results()
        .map_err(|e| WirelessError::System(format!("Failed to read scan results: {}", e)))?
    {
        let bssid = entry.get("bssid").cloned().unwrap_or_default();
        let ssid = entry.get("ssid").cloned().unwrap_or_default();
        let frequency = entry
            .get("frequency")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let channel = ScanResult::freq_to_channel(frequency);
        let signal_dbm = entry
            .get("signal")
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(0.0);

        results.push(ScanResult {
            bssid,
            ssid,
            frequency,
            channel,
            signal_mbm: (signal_dbm * 100.0) as i32,
            signal_dbm,
            seen_ms_ago: 0,
            beacon_interval: 0,
            capability: 0,
            tsf: 0,
        });
    }

    Ok(results)
}



/// Get link status for a connected interface
pub fn get_link_status(interface: &str) -> Result<LinkStatus> {
    let wpa = rustyjack_netlink::WpaManager::new(interface)
        .map_err(|e| WirelessError::System(format!("Failed to open wpa control: {}", e)))?;
    let status = wpa
        .status()
        .map_err(|e| WirelessError::System(format!("Failed to read wpa status: {}", e)))?;
    let connected = matches!(
        status.wpa_state,
        rustyjack_netlink::WpaSupplicantState::Completed
    );
    let frequency = status.freq;
    Ok(LinkStatus {
        connected,
        ssid: status.ssid,
        bssid: status.bssid,
        frequency,
        channel: frequency.and_then(ScanResult::freq_to_channel),
        signal_dbm: None,
        tx_bitrate_mbps: None,
        rx_bitrate_mbps: None,
    })
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
        WirelessError::System(format!("Failed to get interface info for {}: {}", interface, e))
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

    let ssid = rustyjack_netlink::WpaManager::new(interface)
        .ok()
        .and_then(|wpa| wpa.status().ok())
        .and_then(|status| status.ssid);

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
