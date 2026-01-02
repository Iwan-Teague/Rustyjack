use std::sync::{Arc, Mutex};

use crate::error::{NetlinkError, Result};
use crate::station::backend::{ScanOutcome, StationBackend};
use crate::supplicant::{BssCandidate, StationConfig, StationOutcome, StationState};
use crate::wpa::{WpaState, WpaStatus};

use crate::station::rust_wpa2::keys::derive_pmk;
use crate::station::rust_wpa2::l2::EapolSocket;
use crate::station::rust_wpa2::nl80211_ctrl::{
    connect as nl_connect, disconnect as nl_disconnect, interface_index, interface_mac,
};
use crate::station::rust_wpa2::state::{run_handshake, HandshakeCtx};

pub mod keys;
pub mod l2;
pub mod nl80211_ctrl;
pub mod nl80211_keys;
pub mod rsn;
pub mod state;

pub struct RustWpa2Backend {
    interface: String,
    status: Arc<Mutex<WpaStatus>>,
}

impl RustWpa2Backend {
    pub fn new(interface: &str) -> Result<Self> {
        if interface.trim().is_empty() {
            return Err(NetlinkError::InvalidInput(
                "Interface cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            interface: interface.to_string(),
            status: Arc::new(Mutex::new(WpaStatus {
                ssid: None,
                bssid: None,
                freq: None,
                mode: Some("station".to_string()),
                pairwise_cipher: None,
                group_cipher: None,
                key_mgmt: None,
                wpa_state: WpaState::Disconnected,
                ip_address: None,
                address: None,
            })),
        })
    }
}

impl StationBackend for RustWpa2Backend {
    fn ensure_ready(&self) -> Result<()> {
        if self.interface.trim().is_empty() {
            return Err(NetlinkError::InvalidInput(
                "Interface cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    fn scan(&self, _cfg: &StationConfig) -> Result<ScanOutcome> {
        Ok(ScanOutcome {
            candidates: Vec::new(),
            used_scan_ssid: true,
        })
    }

    fn connect(&self, _cfg: &StationConfig, _candidate: Option<&BssCandidate>) -> Result<StationOutcome> {
        let cfg = _cfg;
        if cfg.ssid.trim().is_empty() {
            return Err(NetlinkError::InvalidInput("SSID cannot be empty".to_string()));
        }
        let passphrase = cfg.password.clone().ok_or_else(|| {
            NetlinkError::InvalidInput("WPA2-PSK requires a passphrase".to_string())
        })?;

        let bssid = _candidate.and_then(|c| parse_bssid(&c.bssid).ok());
        let freq = _candidate.and_then(|c| c.frequency);

        nl_connect(&self.interface, &cfg.ssid, bssid, freq)?;

        let ifindex = interface_index(&self.interface)?;
        let sta = interface_mac(&self.interface)?;
        let pmk = derive_pmk(&passphrase, &cfg.ssid)?;

        let mut ctx = HandshakeCtx {
            ssid: cfg.ssid.clone(),
            bssid: bssid.unwrap_or([0u8; 6]),
            sta,
            pmk,
            ifindex,
            ptk: None,
            gtk: None,
        };

        let sock = EapolSocket::open(&self.interface)?;
        if let Err(err) = run_handshake(&mut ctx, &sock, cfg.stage_timeout) {
            let _ = nl_disconnect(&self.interface);
            return Err(err);
        }

        let status = WpaStatus {
            ssid: Some(cfg.ssid.clone()),
            bssid: Some(format_mac(&ctx.bssid)),
            freq,
            mode: Some("station".to_string()),
            pairwise_cipher: Some("CCMP".to_string()),
            group_cipher: Some("CCMP".to_string()),
            key_mgmt: Some("WPA-PSK".to_string()),
            wpa_state: WpaState::Completed,
            ip_address: None,
            address: Some(format_mac(&sta)),
        };
        if let Ok(mut guard) = self.status.lock() {
            *guard = status.clone();
        }

        Ok(StationOutcome {
            status,
            selected_bssid: Some(format_mac(&ctx.bssid)),
            selected_freq: freq,
            attempts: 1,
            used_scan_ssid: cfg.force_scan_ssid,
            final_state: StationState::Completed,
        })
    }

    fn disconnect(&self) -> Result<()> {
        nl_disconnect(&self.interface)?;
        if let Ok(mut guard) = self.status.lock() {
            guard.wpa_state = WpaState::Disconnected;
            guard.ssid = None;
            guard.bssid = None;
            guard.freq = None;
        }
        Ok(())
    }

    fn status(&self) -> Result<WpaStatus> {
        self.status
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| NetlinkError::OperationFailed("WPA status lock poisoned".to_string()))
    }

    fn cleanup(&self) -> Result<()> {
        let _ = self.disconnect();
        Ok(())
    }
}

fn parse_bssid(value: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = value.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(NetlinkError::ParseError {
            what: "BSSID".to_string(),
            reason: format!("invalid format: {}", value.trim()),
        });
    }
    let mut mac = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        mac[idx] = u8::from_str_radix(part, 16).map_err(|e| NetlinkError::ParseError {
            what: "BSSID".to_string(),
            reason: e.to_string(),
        })?;
    }
    Ok(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
