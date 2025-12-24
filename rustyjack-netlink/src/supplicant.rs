use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::error::{NetlinkError, Result};
use crate::wpa::{BssInfo, WpaManager, WpaNetworkConfig, WpaState, WpaStatus};

// Station connect flow modeled after wpa_supplicant SME/scan logic (sme.c, scan.c, bss.c, wpa_ie.c).
const RSN_OUI: [u8; 3] = [0x00, 0x0f, 0xac];
const WPA_OUI: [u8; 3] = [0x00, 0x50, 0xf2];

#[derive(Debug, Clone)]
pub struct StationConfig {
    pub ssid: String,
    pub password: Option<String>,
    pub scan_timeout: Duration,
    pub connect_timeout: Duration,
    pub stage_timeout: Duration,
    pub max_attempts: u8,
    pub prefer_5ghz: bool,
    pub allow_wpa1: bool,
    pub force_scan_ssid: bool,
}

impl Default for StationConfig {
    fn default() -> Self {
        Self {
            ssid: String::new(),
            password: None,
            scan_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(20),
            stage_timeout: Duration::from_secs(8),
            max_attempts: 3,
            prefer_5ghz: false,
            allow_wpa1: true,
            force_scan_ssid: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StationOutcome {
    pub status: WpaStatus,
    pub selected_bssid: Option<String>,
    pub selected_freq: Option<u32>,
    pub attempts: u8,
    pub used_scan_ssid: bool,
    pub final_state: StationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StationState {
    Idle,
    Scanning,
    Selecting,
    Configuring,
    Authenticating,
    Associating,
    Associated,
    FourWayHandshake,
    GroupHandshake,
    Completed,
    Disconnected,
    Failed,
}

impl StationState {
    fn from_wpa_state(state: WpaState) -> Self {
        match state {
            WpaState::Scanning => StationState::Scanning,
            WpaState::Authenticating => StationState::Authenticating,
            WpaState::Associating => StationState::Associating,
            WpaState::Associated => StationState::Associated,
            WpaState::FourWayHandshake => StationState::FourWayHandshake,
            WpaState::GroupHandshake => StationState::GroupHandshake,
            WpaState::Completed => StationState::Completed,
            WpaState::Disconnected | WpaState::Unknown => StationState::Disconnected,
        }
    }
}

pub struct StationManager {
    interface: String,
    wpa: WpaManager,
}

impl StationManager {
    pub fn new(interface: &str) -> Result<Self> {
        let wpa = WpaManager::new(interface)?;
        Ok(Self {
            interface: interface.to_string(),
            wpa,
        })
    }

    pub fn connect(&self, config: &StationConfig) -> Result<StationOutcome> {
        if config.ssid.trim().is_empty() {
            return Err(NetlinkError::InvalidInput("SSID cannot be empty".to_string()));
        }

        self.cleanup_networks();

        let (mut candidates, used_scan_ssid) = self.scan_and_select_candidates(config)?;
        if candidates.is_empty() {
            warn!(
                "[WIFI] No scan candidates for ssid={} on {}, attempting hidden connect",
                config.ssid, self.interface
            );
            return self.connect_without_candidate(config, used_scan_ssid || config.force_scan_ssid);
        }

        candidates.sort_by(|a, b| b.score.cmp(&a.score));
        let mut tried = 0u8;
        let mut failed_bssids = HashSet::new();

        for candidate in candidates {
            if tried >= config.max_attempts {
                break;
            }

            if failed_bssids.contains(&candidate.bssid) {
                continue;
            }

            tried += 1;
            info!(
                "[WIFI] Attempting connect ssid={} bssid={} score={} freq={:?} signal={:?}",
                config.ssid,
                candidate.bssid,
                candidate.score,
                candidate.frequency,
                candidate.signal_dbm
            );

            let net_cfg = build_network_config(config, Some(&candidate), used_scan_ssid)?;
            let net_id = match self.wpa.connect_network(&net_cfg) {
                Ok(id) => id,
                Err(e) => {
                    failed_bssids.insert(candidate.bssid.clone());
                    warn!("[WIFI] Network config failed for {}: {}", candidate.bssid, e);
                    continue;
                }
            };

            match self.wait_for_connection(config.connect_timeout, config.stage_timeout) {
                Ok(status) => {
                    return Ok(StationOutcome {
                        status,
                        selected_bssid: Some(candidate.bssid),
                        selected_freq: candidate.frequency,
                        attempts: tried,
                        used_scan_ssid,
                        final_state: StationState::Completed,
                    });
                }
                Err(e) => {
                    let _ = self.wpa.disconnect();
                    let _ = self.wpa.remove_network(net_id);
                    failed_bssids.insert(candidate.bssid.clone());
                    warn!("[WIFI] Connect attempt failed (bssid={}): {}", candidate.bssid, e);
                }
            }
        }

        Err(NetlinkError::Wpa(format!(
            "Failed to connect to {} after {} attempts",
            config.ssid, tried
        )))
    }

    fn connect_without_candidate(
        &self,
        config: &StationConfig,
        scan_ssid: bool,
    ) -> Result<StationOutcome> {
        let net_cfg = build_network_config(config, None, scan_ssid)?;
        let net_id = self.wpa.connect_network(&net_cfg)?;

        match self.wait_for_connection(config.connect_timeout, config.stage_timeout) {
            Ok(status) => {
                let selected_bssid = status.bssid.clone();
                let selected_freq = status.freq;
                Ok(StationOutcome {
                    status,
                    selected_bssid,
                    selected_freq,
                    attempts: 1,
                    used_scan_ssid: scan_ssid,
                    final_state: StationState::Completed,
                })
            }
            Err(e) => {
                let _ = self.wpa.disconnect();
                let _ = self.wpa.remove_network(net_id);
                Err(e)
            }
        }
    }

    fn cleanup_networks(&self) {
        if let Err(e) = self.wpa.disconnect() {
            debug!(
                "[WIFI] Disconnect before connect returned error (may be disconnected): {}",
                e
            );
        }

        if let Ok(networks) = self.wpa.list_networks() {
            for net in networks {
                if let Some(id_str) = net.get("network_id") {
                    if let Ok(id) = id_str.parse::<u32>() {
                        let _ = self.wpa.remove_network(id);
                    }
                }
            }
        }
    }

    fn scan_and_select_candidates(
        &self,
        config: &StationConfig,
    ) -> Result<(Vec<BssCandidate>, bool)> {
        info!("[WIFI] Scanning for ssid={} on {}", config.ssid, self.interface);
        self.wpa.scan()?;

        let start = Instant::now();
        let mut results = Vec::new();
        while start.elapsed() < config.scan_timeout {
            if let Ok(scan_results) = self.wpa.scan_results() {
                results = parse_scan_results(scan_results);
                if !results.is_empty() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }

        if results.is_empty() {
            warn!(
                "[WIFI] Scan results empty for ssid={} on {}, continuing without candidate",
                config.ssid, self.interface
            );
            return Ok((Vec::new(), true));
        }

        let mut matching: Vec<ScanEntry> = results
            .iter()
            .cloned()
            .filter(|entry| entry.ssid == config.ssid)
            .collect();

        let mut used_scan_ssid = false;
        if matching.is_empty() {
            used_scan_ssid = true;
            matching = results
                .iter()
                .cloned()
                .filter(|entry| entry.ssid.is_empty())
                .collect();
        }

        let candidates = matching
            .into_iter()
            .filter_map(|entry| self.build_candidate(config, entry))
            .collect();

        Ok((candidates, used_scan_ssid || config.force_scan_ssid))
    }

    fn build_candidate(&self, config: &StationConfig, entry: ScanEntry) -> Option<BssCandidate> {
        let bss = self.wpa.bss(&entry.bssid).ok();
        let mut security = if let Some(ref info) = bss {
            security_from_bss(info)
        } else {
            security_from_flags(&entry.flags)
        };

        if security.is_empty() {
            security = security_from_flags(&entry.flags);
        }

        let score = score_candidate(config, &entry, &security)?;
        Some(BssCandidate {
            bssid: entry.bssid,
            frequency: entry.frequency,
            signal_dbm: entry.signal_dbm,
            security,
            score,
        })
    }

    fn wait_for_connection(
        &self,
        connect_timeout: Duration,
        stage_timeout: Duration,
    ) -> Result<WpaStatus> {
        let start = Instant::now();
        let mut last_state = StationState::Idle;
        let mut stage_start = Instant::now();

        loop {
            if start.elapsed() >= connect_timeout {
                return Err(NetlinkError::Timeout {
                    operation: "wifi connect".to_string(),
                    timeout_secs: connect_timeout.as_secs(),
                });
            }

            let status = self.wpa.status()?;
            let state = StationState::from_wpa_state(status.wpa_state);

            if state != last_state {
                info!(
                    "[WIFI] Station state {} -> {}",
                    format!("{:?}", last_state).to_lowercase(),
                    format!("{:?}", state).to_lowercase()
                );
                last_state = state;
                stage_start = Instant::now();
            }

            match state {
                StationState::Completed => return Ok(status),
                StationState::Disconnected => {
                    return Err(NetlinkError::Wpa(
                        "Connection failed (disconnected)".to_string(),
                    ))
                }
                _ => {
                    if stage_start.elapsed() > stage_timeout {
                        return Err(NetlinkError::Timeout {
                            operation: format!("wifi stage {:?}", state).to_lowercase(),
                            timeout_secs: stage_timeout.as_secs(),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ScanEntry {
    bssid: String,
    frequency: Option<u32>,
    signal_dbm: Option<i32>,
    flags: String,
    ssid: String,
}

fn parse_scan_results(results: Vec<HashMap<String, String>>) -> Vec<ScanEntry> {
    let mut entries = Vec::new();
    for net in results {
        let bssid = match net.get("bssid") {
            Some(value) => value.to_string(),
            None => continue,
        };
        let frequency = net.get("frequency").and_then(|v| v.parse::<u32>().ok());
        let signal_dbm = net.get("signal").and_then(|v| v.parse::<i32>().ok());
        let flags = net
            .get("flags")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let ssid = net.get("ssid").map(|v| v.to_string()).unwrap_or_default();

        entries.push(ScanEntry {
            bssid,
            frequency,
            signal_dbm,
            flags,
            ssid,
        });
    }
    entries
}

#[derive(Debug, Clone)]
struct BssCandidate {
    bssid: String,
    frequency: Option<u32>,
    signal_dbm: Option<i32>,
    security: SecurityInfo,
    score: i32,
}

#[derive(Debug, Clone, Default)]
struct SecurityInfo {
    rsn: Option<RsnInfo>,
    wpa: Option<RsnInfo>,
}

impl SecurityInfo {
    fn is_empty(&self) -> bool {
        self.rsn.is_none() && self.wpa.is_none()
    }

    fn is_open(&self) -> bool {
        self.is_empty()
    }

    fn supports_psk(&self) -> bool {
        self.rsn
            .as_ref()
            .map(|info| info.supports_psk())
            .unwrap_or(false)
            || self
                .wpa
                .as_ref()
                .map(|info| info.supports_psk())
                .unwrap_or(false)
    }

    fn supports_psk_rsn(&self) -> bool {
        self.rsn
            .as_ref()
            .map(|info| info.supports_psk())
            .unwrap_or(false)
    }

    fn supports_psk_wpa(&self) -> bool {
        self.wpa
            .as_ref()
            .map(|info| info.supports_psk())
            .unwrap_or(false)
    }

    fn prefers_rsn(&self) -> bool {
        self.rsn.is_some()
    }

    fn best_pairwise(&self) -> Option<&'static str> {
        if let Some(ref rsn) = self.rsn {
            if let Some(cipher) = rsn.preferred_pairwise() {
                return Some(cipher);
            }
        }
        if let Some(ref wpa) = self.wpa {
            return wpa.preferred_pairwise();
        }
        None
    }

    fn best_group(&self) -> Option<&'static str> {
        if let Some(ref rsn) = self.rsn {
            return rsn.group_cipher.to_wpa_str();
        }
        if let Some(ref wpa) = self.wpa {
            return wpa.group_cipher.to_wpa_str();
        }
        None
    }
}

#[derive(Debug, Clone)]
struct RsnInfo {
    group_cipher: CipherSuite,
    pairwise_ciphers: Vec<CipherSuite>,
    akm_suites: Vec<AkmSuite>,
}

impl RsnInfo {
    fn supports_psk(&self) -> bool {
        self.akm_suites.iter().any(|suite| {
            matches!(
                suite,
                AkmSuite::Psk | AkmSuite::FtPsk | AkmSuite::PskSha256
            )
        })
    }

    fn preferred_pairwise(&self) -> Option<&'static str> {
        if self.pairwise_ciphers.contains(&CipherSuite::Ccmp) {
            return Some("CCMP");
        }
        if self.pairwise_ciphers.contains(&CipherSuite::Tkip) {
            return Some("TKIP");
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherSuite {
    Wep40,
    Tkip,
    Ccmp,
    Wep104,
    Gcmp,
    Ccmp256,
    Gcmp256,
    Unknown(u8),
}

impl CipherSuite {
    fn from_suite_type(suite_type: u8) -> Self {
        match suite_type {
            1 => CipherSuite::Wep40,
            2 => CipherSuite::Tkip,
            4 => CipherSuite::Ccmp,
            5 => CipherSuite::Wep104,
            8 => CipherSuite::Gcmp,
            9 => CipherSuite::Gcmp256,
            10 => CipherSuite::Ccmp256,
            other => CipherSuite::Unknown(other),
        }
    }

    fn to_wpa_str(&self) -> Option<&'static str> {
        match self {
            CipherSuite::Ccmp => Some("CCMP"),
            CipherSuite::Tkip => Some("TKIP"),
            _ => None,
        }
    }
}

fn parse_cipher_suite(bytes: &[u8], expected_oui: &[u8; 3]) -> CipherSuite {
    if bytes.len() != 4 {
        return CipherSuite::Unknown(0);
    }
    if bytes[0..3] != expected_oui[..] {
        return CipherSuite::Unknown(bytes[3]);
    }
    CipherSuite::from_suite_type(bytes[3])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AkmSuite {
    Eap,
    Psk,
    FtEap,
    FtPsk,
    PskSha256,
    Sae,
    Owe,
    Unknown(u8),
}

impl AkmSuite {
    fn from_suite_type(suite_type: u8) -> Self {
        match suite_type {
            1 => AkmSuite::Eap,
            2 => AkmSuite::Psk,
            3 => AkmSuite::FtEap,
            4 => AkmSuite::FtPsk,
            6 => AkmSuite::PskSha256,
            8 => AkmSuite::Sae,
            18 => AkmSuite::Owe,
            other => AkmSuite::Unknown(other),
        }
    }
}

fn parse_akm_suite(bytes: &[u8], expected_oui: &[u8; 3]) -> AkmSuite {
    if bytes.len() != 4 {
        return AkmSuite::Unknown(0);
    }
    if bytes[0..3] != expected_oui[..] {
        return AkmSuite::Unknown(bytes[3]);
    }
    AkmSuite::from_suite_type(bytes[3])
}

fn score_candidate(
    config: &StationConfig,
    entry: &ScanEntry,
    security: &SecurityInfo,
) -> Option<i32> {
    let requires_password = config.password.is_some();

    if requires_password {
        if security.is_open() {
            return None;
        }
        if !security.supports_psk() {
            return None;
        }
        if !config.allow_wpa1 && !security.supports_psk_rsn() && security.supports_psk_wpa() {
            return None;
        }
    } else if !security.is_open() {
        return None;
    }

    let mut score = 0;
    score += signal_score(entry.signal_dbm);

    if let Some(freq) = entry.frequency {
        if freq >= 5000 {
            score += if config.prefer_5ghz { 20 } else { -10 };
        } else if freq >= 2400 {
            score += if config.prefer_5ghz { -5 } else { 5 };
        }
    }

    if security.prefers_rsn() {
        score += 20;
    } else if security.wpa.is_some() {
        score += 10;
    }

    if let Some(pairwise) = security.best_pairwise() {
        if pairwise == "CCMP" {
            score += 5;
        }
    }

    Some(score)
}

fn signal_score(signal_dbm: Option<i32>) -> i32 {
    let signal = signal_dbm.unwrap_or(-100);
    let normalized = (signal + 100).clamp(0, 100);
    normalized * 2
}

fn build_network_config(
    config: &StationConfig,
    candidate: Option<&BssCandidate>,
    scan_ssid: bool,
) -> Result<WpaNetworkConfig> {
    let mut network = WpaNetworkConfig {
        ssid: config.ssid.clone(),
        psk: config.password.clone(),
        scan_ssid,
        priority: 0,
        key_mgmt: if config.password.is_some() {
            "WPA-PSK".to_string()
        } else {
            "NONE".to_string()
        },
        bssid: None,
        proto: None,
        pairwise: None,
        group: None,
    };

    if let Some(candidate) = candidate {
        network.bssid = Some(candidate.bssid.clone());
        let security = &candidate.security;
        if config.password.is_some() {
            if security.prefers_rsn() {
                network.proto = Some("RSN".to_string());
            } else if security.wpa.is_some() {
                network.proto = Some("WPA".to_string());
            }

            network.pairwise = security.best_pairwise().map(|v| v.to_string());
            network.group = security.best_group().map(|v| v.to_string());
        } else {
            network.key_mgmt = "NONE".to_string();
        }
    }

    Ok(network)
}

fn security_from_bss(info: &BssInfo) -> SecurityInfo {
    let ies = if let Some(ref ie) = info.ie {
        if !ie.is_empty() {
            ie.as_slice()
        } else if let Some(ref beacon_ie) = info.beacon_ie {
            beacon_ie.as_slice()
        } else {
            &[]
        }
    } else if let Some(ref beacon_ie) = info.beacon_ie {
        beacon_ie.as_slice()
    } else {
        &[]
    };

    if ies.is_empty() {
        return SecurityInfo::default();
    }

    parse_security_from_ies(ies)
}

fn parse_security_from_ies(ies: &[u8]) -> SecurityInfo {
    let mut security = SecurityInfo::default();
    let mut idx = 0usize;
    while idx + 2 <= ies.len() {
        let id = ies[idx];
        let len = ies[idx + 1] as usize;
        idx += 2;
        if idx + len > ies.len() {
            break;
        }
        let body = &ies[idx..idx + len];
        if id == 48 {
            security.rsn = parse_rsn_ie(body);
        } else if id == 221 {
            if is_wpa_ie(body) {
                security.wpa = parse_wpa_ie(body);
            }
        }
        idx += len;
    }
    security
}

fn is_wpa_ie(body: &[u8]) -> bool {
    body.len() >= 4 && body[0..3] == WPA_OUI && body[3] == 0x01
}

fn parse_rsn_ie(body: &[u8]) -> Option<RsnInfo> {
    parse_rsn_like_ie(body, &RSN_OUI)
}

fn parse_wpa_ie(body: &[u8]) -> Option<RsnInfo> {
    if body.len() < 4 {
        return None;
    }
    parse_rsn_like_ie(&body[4..], &WPA_OUI)
}

fn parse_rsn_like_ie(body: &[u8], expected_oui: &[u8; 3]) -> Option<RsnInfo> {
    if body.len() < 8 {
        return None;
    }

    let mut idx = 0;
    let _version = u16::from_le_bytes([body[idx], body[idx + 1]]);
    idx += 2;

    if idx + 4 > body.len() {
        return None;
    }
    let group_cipher = parse_cipher_suite(&body[idx..idx + 4], expected_oui);
    idx += 4;

    if idx + 2 > body.len() {
        return None;
    }
    let pairwise_count = u16::from_le_bytes([body[idx], body[idx + 1]]) as usize;
    idx += 2;
    let mut pairwise_ciphers = Vec::new();
    for _ in 0..pairwise_count {
        if idx + 4 > body.len() {
            return None;
        }
        pairwise_ciphers.push(parse_cipher_suite(&body[idx..idx + 4], expected_oui));
        idx += 4;
    }

    if idx + 2 > body.len() {
        return None;
    }
    let akm_count = u16::from_le_bytes([body[idx], body[idx + 1]]) as usize;
    idx += 2;
    let mut akm_suites = Vec::new();
    for _ in 0..akm_count {
        if idx + 4 > body.len() {
            return None;
        }
        akm_suites.push(parse_akm_suite(&body[idx..idx + 4], expected_oui));
        idx += 4;
    }

    Some(RsnInfo {
        group_cipher,
        pairwise_ciphers,
        akm_suites,
    })
}

fn security_from_flags(flags: &str) -> SecurityInfo {
    let mut security = SecurityInfo::default();
    if flags.contains("WPA2") || flags.contains("RSN") {
        security.rsn = Some(RsnInfo {
            group_cipher: CipherSuite::Ccmp,
            pairwise_ciphers: vec![CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Psk],
        });
    }
    if flags.contains("WPA-") || flags.contains("WPA1") {
        security.wpa = Some(RsnInfo {
            group_cipher: CipherSuite::Tkip,
            pairwise_ciphers: vec![CipherSuite::Tkip],
            akm_suites: vec![AkmSuite::Psk],
        });
    }
    security
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rsn_ie_basic() {
        let rsn = parse_rsn_ie(&[
            0x01, 0x00, // version
            0x00, 0x0f, 0xac, 0x04, // group CCMP
            0x01, 0x00, // pairwise count
            0x00, 0x0f, 0xac, 0x04, // pairwise CCMP
            0x01, 0x00, // akm count
            0x00, 0x0f, 0xac, 0x02, // akm PSK
        ])
        .unwrap();

        assert!(rsn.supports_psk());
        assert_eq!(rsn.preferred_pairwise(), Some("CCMP"));
    }
}
