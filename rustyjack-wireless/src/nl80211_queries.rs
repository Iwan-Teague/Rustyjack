use crate::error::{Result, WirelessError};
use std::collections::HashMap;

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

/// Get scan results by parsing iw dev scan output
pub fn get_scan_results(interface: &str) -> Result<Vec<ScanResult>> {
    use std::process::Command;
    
    let output = Command::new("iw")
        .args(["dev", interface, "scan"])
        .output()
        .map_err(|e| WirelessError::System(format!("Failed to run iw scan: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WirelessError::System(format!("iw scan failed: {}", stderr)));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_scan_output(&stdout)
}

fn parse_scan_output(output: &str) -> Result<Vec<ScanResult>> {
    let mut results = Vec::new();
    let mut current: Option<ScanResult> = None;
    
    for line in output.lines() {
        let line = line.trim();
        
        if line.starts_with("BSS ") {
            // Save previous entry
            if let Some(entry) = current.take() {
                results.push(entry);
            }
            
            // Parse BSSID from "BSS aa:bb:cc:dd:ee:ff"
            if let Some(bssid_part) = line.strip_prefix("BSS ") {
                let bssid = bssid_part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                
                current = Some(ScanResult {
                    bssid,
                    ssid: String::new(),
                    frequency: 0,
                    channel: None,
                    signal_mbm: 0,
                    signal_dbm: 0.0,
                    seen_ms_ago: 0,
                    beacon_interval: 0,
                    capability: 0,
                    tsf: 0,
                });
            }
        } else if let Some(ref mut entry) = current {
            if line.starts_with("SSID: ") {
                entry.ssid = line.strip_prefix("SSID: ").unwrap_or("").to_string();
            } else if line.starts_with("freq: ") {
                if let Some(freq_str) = line.strip_prefix("freq: ") {
                    if let Ok(freq) = freq_str.parse::<u32>() {
                        entry.frequency = freq;
                        entry.channel = ScanResult::freq_to_channel(freq);
                    }
                }
            } else if line.starts_with("signal: ") {
                if let Some(sig_str) = line.strip_prefix("signal: ") {
                    if let Some(dbm_str) = sig_str.split_whitespace().next() {
                        if let Ok(dbm) = dbm_str.parse::<f32>() {
                            entry.signal_dbm = dbm;
                            entry.signal_mbm = (dbm * 100.0) as i32;
                        }
                    }
                }
            } else if line.starts_with("last seen: ") {
                if let Some(seen_str) = line.strip_prefix("last seen: ") {
                    if let Some(ms_str) = seen_str.split_whitespace().next() {
                        if let Ok(ms) = ms_str.parse::<u32>() {
                            entry.seen_ms_ago = ms;
                        }
                    }
                }
            } else if line.starts_with("beacon interval: ") {
                if let Some(int_str) = line.strip_prefix("beacon interval: ") {
                    if let Some(val_str) = int_str.split_whitespace().next() {
                        if let Ok(val) = val_str.parse::<u16>() {
                            entry.beacon_interval = val;
                        }
                    }
                }
            } else if line.starts_with("TSF: ") {
                if let Some(tsf_str) = line.strip_prefix("TSF: ") {
                    if let Some(val_str) = tsf_str.split_whitespace().next() {
                        if let Ok(val) = val_str.parse::<u64>() {
                            entry.tsf = val;
                        }
                    }
                }
            } else if line.starts_with("capability: ") {
                if let Some(cap_str) = line.strip_prefix("capability: ") {
                    // Parse hex like "capability: 0x1234"
                    if let Some(hex_str) = cap_str.split_whitespace().next() {
                        if let Some(hex_val) = hex_str.strip_prefix("0x") {
                            if let Ok(val) = u16::from_str_radix(hex_val, 16) {
                                entry.capability = val;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Save last entry
    if let Some(entry) = current {
        results.push(entry);
    }
    
    Ok(results)
}

/// Get link status for a connected interface
pub fn get_link_status(interface: &str) -> Result<LinkStatus> {
    use std::process::Command;
    
    let output = Command::new("iw")
        .args(["dev", interface, "link"])
        .output()
        .map_err(|e| WirelessError::System(format!("Failed to run iw link: {}", e)))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // If not connected, output starts with "Not connected"
    if stdout.starts_with("Not connected") {
        return Ok(LinkStatus {
            connected: false,
            ssid: None,
            bssid: None,
            frequency: None,
            channel: None,
            signal_dbm: None,
            tx_bitrate_mbps: None,
            rx_bitrate_mbps: None,
        });
    }
    
    let mut status = LinkStatus {
        connected: true,
        ssid: None,
        bssid: None,
        frequency: None,
        channel: None,
        signal_dbm: None,
        tx_bitrate_mbps: None,
        rx_bitrate_mbps: None,
    };
    
    for line in stdout.lines() {
        let line = line.trim();
        
        if line.starts_with("Connected to ") {
            // "Connected to aa:bb:cc:dd:ee:ff"
            status.bssid = line.strip_prefix("Connected to ")
                .and_then(|s| s.split_whitespace().next())
                .map(|s| s.to_string());
        } else if line.starts_with("SSID: ") {
            status.ssid = line.strip_prefix("SSID: ").map(|s| s.to_string());
        } else if line.starts_with("freq: ") {
            if let Some(freq_str) = line.strip_prefix("freq: ") {
                if let Ok(freq) = freq_str.parse::<u32>() {
                    status.frequency = Some(freq);
                    status.channel = ScanResult::freq_to_channel(freq);
                }
            }
        } else if line.starts_with("signal: ") {
            if let Some(sig_str) = line.strip_prefix("signal: ") {
                if let Some(dbm_str) = sig_str.split_whitespace().next() {
                    if let Ok(dbm) = dbm_str.parse::<i32>() {
                        status.signal_dbm = Some(dbm);
                    }
                }
            }
        } else if line.starts_with("tx bitrate: ") {
            if let Some(rate_str) = line.strip_prefix("tx bitrate: ") {
                if let Some(mbps_str) = rate_str.split_whitespace().next() {
                    if let Ok(mbps) = mbps_str.parse::<f32>() {
                        status.tx_bitrate_mbps = Some(mbps);
                    }
                }
            }
        } else if line.starts_with("rx bitrate: ") {
            if let Some(rate_str) = line.strip_prefix("rx bitrate: ") {
                if let Some(mbps_str) = rate_str.split_whitespace().next() {
                    if let Ok(mbps) = mbps_str.parse::<f32>() {
                        status.rx_bitrate_mbps = Some(mbps);
                    }
                }
            }
        }
    }
    
    Ok(status)
}

/// Get station info for AP mode
pub fn get_station_info(interface: &str) -> Result<Vec<StationInfo>> {
    use std::process::Command;
    
    let output = Command::new("iw")
        .args(["dev", interface, "station", "dump"])
        .output()
        .map_err(|e| WirelessError::System(format!("Failed to run iw station dump: {}", e)))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_station_dump(&stdout)
}

fn parse_station_dump(output: &str) -> Result<Vec<StationInfo>> {
    let mut stations = Vec::new();
    let mut current: Option<StationInfo> = None;
    
    for line in output.lines() {
        let line = line.trim();
        
        if line.starts_with("Station ") {
            // Save previous entry
            if let Some(entry) = current.take() {
                stations.push(entry);
            }
            
            // Parse MAC from "Station aa:bb:cc:dd:ee:ff"
            if let Some(mac_part) = line.strip_prefix("Station ") {
                let mac = mac_part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                
                current = Some(StationInfo {
                    mac,
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
        } else if let Some(ref mut station) = current {
            if line.starts_with("inactive time:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Some(ms_str) = val.trim().split_whitespace().next() {
                        if let Ok(ms) = ms_str.parse::<u32>() {
                            station.inactive_time_ms = ms;
                        }
                    }
                }
            } else if line.starts_with("rx bytes:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(bytes) = val.trim().parse::<u64>() {
                        station.rx_bytes = bytes;
                    }
                }
            } else if line.starts_with("tx bytes:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(bytes) = val.trim().parse::<u64>() {
                        station.tx_bytes = bytes;
                    }
                }
            } else if line.starts_with("rx packets:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(packets) = val.trim().parse::<u32>() {
                        station.rx_packets = packets;
                    }
                }
            } else if line.starts_with("tx packets:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(packets) = val.trim().parse::<u32>() {
                        station.tx_packets = packets;
                    }
                }
            } else if line.starts_with("signal:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Some(dbm_str) = val.trim().split_whitespace().next() {
                        if let Ok(dbm) = dbm_str.parse::<i8>() {
                            station.signal_dbm = dbm;
                        }
                    }
                }
            } else if line.starts_with("signal avg:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Some(dbm_str) = val.trim().split_whitespace().next() {
                        if let Ok(dbm) = dbm_str.parse::<i8>() {
                            station.signal_avg_dbm = dbm;
                        }
                    }
                }
            } else if line.starts_with("tx bitrate:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Some(mbps_str) = val.trim().split_whitespace().next() {
                        if let Ok(mbps) = mbps_str.parse::<f32>() {
                            station.tx_bitrate_mbps = Some(mbps);
                        }
                    }
                }
            } else if line.starts_with("rx bitrate:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Some(mbps_str) = val.trim().split_whitespace().next() {
                        if let Ok(mbps) = mbps_str.parse::<f32>() {
                            station.rx_bitrate_mbps = Some(mbps);
                        }
                    }
                }
            } else if line.starts_with("connected time:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Some(sec_str) = val.trim().split_whitespace().next() {
                        if let Ok(sec) = sec_str.parse::<u32>() {
                            station.connected_time_sec = sec;
                        }
                    }
                }
            }
        }
    }
    
    // Save last entry
    if let Some(station) = current {
        stations.push(station);
    }
    
    Ok(stations)
}

/// Get interface information
pub fn get_interface_info(interface: &str) -> Result<InterfaceInfo> {
    use std::process::Command;
    
    let output = Command::new("iw")
        .args(["dev", interface, "info"])
        .output()
        .map_err(|e| WirelessError::System(format!("Failed to run iw dev info: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WirelessError::System(format!("iw dev info failed: {}", stderr)));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_interface_info(interface, &stdout)
}

fn parse_interface_info(interface: &str, output: &str) -> Result<InterfaceInfo> {
    let mut info = InterfaceInfo {
        name: interface.to_string(),
        ifindex: 0,
        wdev: 0,
        addr: None,
        ssid: None,
        iftype: 0,
        wiphy: 0,
        frequency: None,
        channel: None,
        channel_width: None,
        txpower_dbm: None,
    };
    
    for line in output.lines() {
        let line = line.trim();
        
        if line.starts_with("ifindex ") {
            if let Some(val) = line.split_whitespace().nth(1) {
                if let Ok(idx) = val.parse::<u32>() {
                    info.ifindex = idx;
                }
            }
        } else if line.starts_with("wdev ") {
            if let Some(val) = line.split_whitespace().nth(1) {
                // Remove "0x" prefix
                let val = val.strip_prefix("0x").unwrap_or(val);
                if let Ok(wdev) = u64::from_str_radix(val, 16) {
                    info.wdev = wdev;
                }
            }
        } else if line.starts_with("addr ") {
            if let Some(val) = line.split_whitespace().nth(1) {
                info.addr = Some(val.to_string());
            }
        } else if line.starts_with("ssid ") {
            info.ssid = line.strip_prefix("ssid ").map(|s| s.to_string());
        } else if line.starts_with("type ") {
            // Map type string to number (simplified)
            let type_str = line.strip_prefix("type ").unwrap_or("");
            info.iftype = match type_str {
                "managed" => 2,
                "AP" => 3,
                "monitor" => 6,
                _ => 0,
            };
        } else if line.starts_with("wiphy ") {
            if let Some(val) = line.split_whitespace().nth(1) {
                if let Ok(phy) = val.parse::<u32>() {
                    info.wiphy = phy;
                }
            }
        } else if line.starts_with("channel ") {
            // "channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz"
            if let Some(ch_str) = line.split_whitespace().nth(1) {
                if let Ok(ch) = ch_str.parse::<u8>() {
                    info.channel = Some(ch);
                }
            }
            // Extract frequency from parentheses
            if let Some(freq_part) = line.split('(').nth(1) {
                if let Some(freq_str) = freq_part.split_whitespace().next() {
                    if let Ok(freq) = freq_str.parse::<u32>() {
                        info.frequency = Some(freq);
                    }
                }
            }
            // Extract width
            if line.contains("width:") {
                if let Some(width_part) = line.split("width:").nth(1) {
                    if let Some(width_str) = width_part.split(',').next() {
                        info.channel_width = Some(width_str.trim().to_string());
                    }
                }
            }
        } else if line.starts_with("txpower ") {
            if let Some(val) = line.split_whitespace().nth(1) {
                // Remove ".00" if present
                let val = val.split('.').next().unwrap_or(val);
                if let Ok(power) = val.parse::<i32>() {
                    info.txpower_dbm = Some(power);
                }
            }
        }
    }
    
    Ok(info)
}
