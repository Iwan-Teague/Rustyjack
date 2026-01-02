use std::collections::{HashMap, HashSet};
use std::time::Duration;

use log::{info, warn};

use crate::error::{NetlinkError, Result};
use crate::station::backend::{ScanOutcome, StationBackend, StationBackendKind};
use crate::wpa::{BssInfo, WpaNetworkConfig, WpaState, WpaStatus};

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
    pub(crate) fn from_wpa_state(state: WpaState) -> Self {
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
    backend: Box<dyn StationBackend>,
}

impl StationManager {
    pub fn new(interface: &str) -> Result<Self> {
        Self::new_with_backend(interface, StationBackendKind::RustWpa2)
    }

    pub fn new_with_backend(interface: &str, kind: StationBackendKind) -> Result<Self> {
        let backend: Box<dyn StationBackend> = match kind {
            StationBackendKind::ExternalWpa => {
                #[cfg(feature = "station_external")]
                {
                    Box::new(crate::station::external::ExternalBackend::new(interface)?)
                }
                #[cfg(not(feature = "station_external"))]
                {
                    return Err(NetlinkError::OperationNotSupported(
                        "station_external feature disabled".to_string(),
                    ));
                }
            }
            StationBackendKind::RustOpen => {
                #[cfg(feature = "station_rust_open")]
                {
                    Box::new(crate::station::rust_open::RustOpenBackend::new(interface)?)
                }
                #[cfg(not(feature = "station_rust_open"))]
                {
                    return Err(NetlinkError::OperationNotSupported(
                        "station_rust_open feature disabled".to_string(),
                    ));
                }
            }
            StationBackendKind::RustWpa2 => {
                #[cfg(feature = "station_rust_wpa2")]
                {
                    Box::new(crate::station::rust_wpa2::RustWpa2Backend::new(interface)?)
                }
                #[cfg(not(feature = "station_rust_wpa2"))]
                {
                    return Err(NetlinkError::OperationNotSupported(
                        "station_rust_wpa2 feature disabled".to_string(),
                    ));
                }
            }
        };

        Ok(Self {
            interface: interface.to_string(),
            backend,
        })
    }

    pub fn connect(&self, config: &StationConfig) -> Result<StationOutcome> {
        if config.ssid.trim().is_empty() {
            return Err(NetlinkError::InvalidInput("SSID cannot be empty".to_string()));
        }

        self.backend.ensure_ready()?;
        self.backend.cleanup()?;

        let ScanOutcome {
            mut candidates,
            used_scan_ssid,
        } = self.backend.scan(config)?;
        let used_scan_ssid = used_scan_ssid || config.force_scan_ssid;
        if candidates.is_empty() {
            warn!(
                "[WIFI] No scan candidates for ssid={} on {}, attempting hidden connect",
                config.ssid, self.interface
            );
            return self.connect_without_candidate(config, used_scan_ssid);
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

            let mut connect_cfg = config.clone();
            connect_cfg.force_scan_ssid = used_scan_ssid;

            match self.backend.connect(&connect_cfg, Some(&candidate)) {
                Ok(mut outcome) => {
                    outcome.attempts = tried;
                    outcome.used_scan_ssid = used_scan_ssid;
                    outcome.selected_bssid = Some(candidate.bssid);
                    outcome.selected_freq = candidate.frequency.or(outcome.selected_freq);
                    outcome.final_state = StationState::Completed;
                    return Ok(outcome);
                }
                Err(e) => {
                    let _ = self.backend.disconnect();
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
        let mut connect_cfg = config.clone();
        connect_cfg.force_scan_ssid = scan_ssid;
        let mut outcome = self.backend.connect(&connect_cfg, None)?;
        outcome.attempts = 1;
        outcome.used_scan_ssid = scan_ssid;
        outcome.final_state = StationState::Completed;
        Ok(outcome)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ScanEntry {
    pub(crate) bssid: String,
    pub(crate) frequency: Option<u32>,
    pub(crate) signal_dbm: Option<i32>,
    pub(crate) flags: String,
    pub(crate) ssid: String,
}

pub(crate) fn parse_scan_results(results: Vec<HashMap<String, String>>) -> Vec<ScanEntry> {
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
pub(crate) struct BssCandidate {
    pub(crate) bssid: String,
    pub(crate) frequency: Option<u32>,
    pub(crate) signal_dbm: Option<i32>,
    pub(crate) security: SecurityInfo,
    pub(crate) score: i32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SecurityInfo {
    rsn: Option<RsnInfo>,
    wpa: Option<RsnInfo>,
}

impl SecurityInfo {
    pub(crate) fn is_empty(&self) -> bool {
        self.rsn.is_none() && self.wpa.is_none()
    }

    pub(crate) fn is_open(&self) -> bool {
        self.is_empty()
    }

    pub(crate) fn supports_psk(&self) -> bool {
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

    pub(crate) fn supports_psk_rsn(&self) -> bool {
        self.rsn
            .as_ref()
            .map(|info| info.supports_psk())
            .unwrap_or(false)
    }

    pub(crate) fn supports_psk_wpa(&self) -> bool {
        self.wpa
            .as_ref()
            .map(|info| info.supports_psk())
            .unwrap_or(false)
    }

    pub(crate) fn prefers_rsn(&self) -> bool {
        self.rsn.is_some()
    }

    pub(crate) fn best_pairwise(&self) -> Option<&'static str> {
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

    pub(crate) fn best_group(&self) -> Option<&'static str> {
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

pub(crate) fn runtime_sleep(duration: Duration) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(tokio::time::sleep(duration));
        return;
    }
    std::thread::sleep(duration);
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

pub(crate) fn score_candidate(
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

pub(crate) fn build_network_config(
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

pub(crate) fn security_from_bss(info: &BssInfo) -> SecurityInfo {
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

pub(crate) fn security_from_flags(flags: &str) -> SecurityInfo {
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
