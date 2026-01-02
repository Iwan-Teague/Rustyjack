//! Response types and data structures for the UI
//!
//! This module contains all the Serde response types and internal
//! data structures used throughout the UI.

use serde::Deserialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, SystemTime},
};

#[cfg(target_os = "linux")]
use rustyjack_wpa::handshake::HandshakeExport;

// ==================== WiFi Response Types ====================

#[derive(Debug, Deserialize)]
pub struct WifiNetworkEntry {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub signal_dbm: Option<i32>,
    pub channel: Option<u8>,
    #[allow(dead_code)]
    pub encrypted: bool,
}

#[derive(Debug, Deserialize)]
pub struct WifiScanResponse {
    pub networks: Vec<WifiNetworkEntry>,
    #[allow(dead_code)]
    pub count: usize,
}

#[derive(Debug, Deserialize)]
pub struct WifiProfileSummary {
    pub ssid: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub interface: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WifiProfilesResponse {
    pub profiles: Vec<WifiProfileSummary>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WifiListResponse {
    pub interfaces: Vec<InterfaceSummary>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceSummary {
    pub name: String,
    pub kind: String,
    pub oper_state: String,
    pub ip: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RouteSnapshot {
    #[serde(default)]
    pub default_gateway: Option<String>,
    #[serde(default)]
    pub default_interface: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WifiStatusOverview {
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub ssid: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub signal_dbm: Option<i32>,
}

// ==================== Handshake Cracking Types ====================

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
pub struct HandshakeBundle {
    pub ssid: String,
    pub handshake: HandshakeExport,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub enum DictionaryOption {
    Quick {
        total: u64,
    },
    SsidPatterns {
        total: u64,
    },
    Bundled {
        name: String,
        path: PathBuf,
        total: u64,
    },
}

#[cfg(target_os = "linux")]
impl DictionaryOption {
    pub fn label(&self) -> String {
        match self {
            DictionaryOption::Quick { total } => format!("Quick (common+SSID) [{}]", total),
            DictionaryOption::SsidPatterns { total } => format!("SSID patterns [{}]", total),
            DictionaryOption::Bundled { name, total, .. } => {
                format!("{} [{}]", name, total)
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub enum CrackUpdate {
    Progress {
        attempts: u64,
        total: u64,
        rate: f32,
        current: String,
    },
    Done {
        password: Option<String>,
        attempts: u64,
        total: u64,
        cancelled: bool,
    },
    Error(String),
}

#[cfg(target_os = "linux")]
pub struct CrackOutcome {
    pub password: Option<String>,
    pub attempts: u64,
    pub total_attempts: u64,
    pub elapsed: Duration,
    pub cancelled: bool,
}

// ==================== MAC Tracking ====================

#[derive(Debug, Deserialize)]
pub struct MacUsageRecord {
    pub ts: String,
    pub interface: String,
    pub mac: String,
    pub context: String,
    pub tag: String,
}

// ==================== Loot/Artifact Types ====================

#[derive(Clone, Default)]
pub struct ArtifactItem {
    pub rel: String,
    pub kind: String,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub note: Option<String>,
    pub important: bool,
    pub pipeline_run: Option<String>,
}

#[derive(Default)]
pub struct PipelineStats {
    pub files: usize,
    pub captures: usize,
    pub creds: usize,
    pub visits: usize,
    pub logs: usize,
    pub latest: Option<SystemTime>,
}

#[derive(Default)]
pub struct TraversalResult {
    pub total_files: usize,
    pub counts: HashMap<String, usize>,
    pub items: Vec<ArtifactItem>,
    pub pipeline: HashMap<String, PipelineStats>,
    pub errors: Vec<String>,
}

// ==================== Pipeline & Attack Types ====================

/// Result from pipeline execution
#[allow(dead_code)]
pub struct PipelineResult {
    pub cancelled: bool,
    pub steps_completed: usize,
    pub pmkids_captured: u32,
    pub handshakes_captured: u32,
    pub password_found: Option<String>,
    pub networks_found: u32,
    pub clients_found: u32,
}

#[allow(dead_code)]
pub enum StepOutcome {
    Completed(Option<(u32, u32, Option<String>, u32, u32)>),
    Skipped(String),
}

/// Result of checking for cancel during an attack
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelAction {
    Continue,   // User wants to continue attack
    GoBack,     // User wants to go back one menu
    GoMainMenu, // User wants to go to main menu
}

// ==================== System Operation Types ====================

#[allow(dead_code)]
pub struct PurgeReport {
    pub removed: usize,
    pub service_disabled: bool,
    pub errors: Vec<String>,
}

// ==================== MITM Session ====================

use std::time::Instant;

#[allow(dead_code)]
#[derive(Clone)]
pub struct MitmSession {
    pub started: Instant,
    pub site: Option<String>,
    pub visit_log: Option<PathBuf>,
    pub cred_log: Option<PathBuf>,
}
