use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::error::{NetlinkError, Result};
use crate::station::backend::{ScanOutcome, StationBackend};
use crate::supplicant::{
    build_network_config, parse_scan_results, runtime_sleep, score_candidate, security_from_bss,
    security_from_flags, BssCandidate, ScanEntry, StationConfig, StationOutcome, StationState,
};
use crate::wpa::WpaStatus;

pub mod ctrl;
pub mod process;

pub struct ExternalBackend {
    interface: String,
}

impl ExternalBackend {
    pub fn new(interface: &str) -> Result<Self> {
        if interface.trim().is_empty() {
            return Err(NetlinkError::InvalidInput(
                "Interface cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            interface: interface.to_string(),
        })
    }

    fn wpa(&self) -> Result<ctrl::WpaManager> {
        let control_path = process::ensure_wpa_control_socket(&self.interface, None)?;
        Ok(ctrl::WpaManager::new(&self.interface)?.with_control_path(control_path))
    }

    fn build_candidate(
        &self,
        config: &StationConfig,
        entry: ScanEntry,
        wpa: &ctrl::WpaManager,
    ) -> Option<BssCandidate> {
        let bss = wpa.bss(&entry.bssid).ok();
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

    fn scan_candidates(&self, config: &StationConfig) -> Result<ScanOutcome> {
        let wpa = self.wpa()?;
        info!("[WIFI] Scanning for ssid={} on {}", config.ssid, self.interface);
        wpa.scan()?;

        let start = Instant::now();
        let mut results = Vec::new();
        while start.elapsed() < config.scan_timeout {
            if let Ok(scan_results) = wpa.scan_results() {
                results = parse_scan_results(scan_results);
                if !results.is_empty() {
                    break;
                }
            }
            runtime_sleep(Duration::from_millis(250));
        }

        if results.is_empty() {
            warn!(
                "[WIFI] Scan results empty for ssid={} on {}, continuing without candidate",
                config.ssid, self.interface
            );
            return Ok(ScanOutcome {
                candidates: Vec::new(),
                used_scan_ssid: true,
            });
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
            .filter_map(|entry| self.build_candidate(config, entry, &wpa))
            .collect();

        Ok(ScanOutcome {
            candidates,
            used_scan_ssid,
        })
    }

    fn wait_for_connection(
        &self,
        wpa: &ctrl::WpaManager,
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

            let status = wpa.status()?;
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
                    runtime_sleep(Duration::from_millis(250));
                }
            }
        }
    }
}

impl StationBackend for ExternalBackend {
    fn ensure_ready(&self) -> Result<()> {
        process::ensure_wpa_control_socket(&self.interface, None)?;
        Ok(())
    }

    fn scan(&self, cfg: &StationConfig) -> Result<ScanOutcome> {
        self.scan_candidates(cfg)
    }

    fn connect(&self, cfg: &StationConfig, candidate: Option<&BssCandidate>) -> Result<StationOutcome> {
        if cfg.ssid.trim().is_empty() {
            return Err(NetlinkError::InvalidInput("SSID cannot be empty".to_string()));
        }

        let wpa = self.wpa()?;
        let net_cfg = build_network_config(cfg, candidate, cfg.force_scan_ssid)?;
        let net_id = wpa.connect_network(&net_cfg)?;

        match self.wait_for_connection(&wpa, cfg.connect_timeout, cfg.stage_timeout) {
            Ok(status) => {
                let selected_bssid = candidate
                    .map(|c| c.bssid.clone())
                    .or_else(|| status.bssid.clone());
                let selected_freq = candidate
                    .and_then(|c| c.frequency)
                    .or(status.freq);
                Ok(StationOutcome {
                    status,
                    selected_bssid,
                    selected_freq,
                    attempts: 1,
                    used_scan_ssid: cfg.force_scan_ssid,
                    final_state: StationState::Completed,
                })
            }
            Err(e) => {
                let _ = wpa.disconnect();
                let _ = wpa.remove_network(net_id);
                Err(e)
            }
        }
    }

    fn disconnect(&self) -> Result<()> {
        self.wpa()?.disconnect()?;
        Ok(())
    }

    fn status(&self) -> Result<WpaStatus> {
        self.wpa()?.status()
    }

    fn cleanup(&self) -> Result<()> {
        let wpa = self.wpa()?;
        if let Err(e) = wpa.disconnect() {
            debug!(
                "[WIFI] Disconnect before connect returned error (may be disconnected): {}",
                e
            );
        }

        if let Ok(networks) = wpa.list_networks() {
            for net in networks {
                if let Some(id_str) = net.get("network_id") {
                    if let Ok(id) = id_str.parse::<u32>() {
                        let _ = wpa.remove_network(id);
                    }
                }
            }
        }
        Ok(())
    }
}
