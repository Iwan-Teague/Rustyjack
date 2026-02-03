use rustyjack_commands::Commands;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::DaemonError;

pub type JobId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub kind: JobKind,
    pub requested_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Progress {
    pub phase: String,
    pub percent: u8,
    pub message: String,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum JobKind {
    Noop,
    Sleep { seconds: u64 },
    ScanRun { req: ScanRequestIpc },
    SystemUpdate { req: UpdateRequestIpc },
    WifiScan { req: WifiScanRequestIpc },
    WifiConnect { req: WifiConnectRequestIpc },
    HotspotStart { req: HotspotStartRequestIpc },
    PortalStart { req: PortalStartRequestIpc },
    MountStart { req: MountStartRequestIpc },
    UnmountStart { req: UnmountStartRequestIpc },
    InterfaceSelect { interface: String },
    CoreCommand { command: Commands },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanModeIpc {
    DiscoveryOnly,
    DiscoveryAndPorts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRequestIpc {
    pub target: String,
    pub mode: ScanModeIpc,
    pub ports: Option<Vec<u16>>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateRequestIpc {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStarted {
    pub job_id: JobId,
    pub accepted_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub job_id: JobId,
    pub kind: JobKind,
    pub state: JobState,
    pub created_at_ms: u64,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
    pub progress: Option<Progress>,
    pub result: Option<Value>,
    pub error: Option<DaemonError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobEvent {
    pub job_id: JobId,
    pub state: JobState,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiScanRequestIpc {
    pub interface: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiConnectRequestIpc {
    pub interface: String,
    pub ssid: String,
    pub psk: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HotspotStartRequestIpc {
    pub interface: String,
    pub upstream_interface: String,
    pub ssid: String,
    pub passphrase: Option<String>,
    pub channel: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortalStartRequestIpc {
    pub interface: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountStartRequestIpc {
    pub device: String,
    pub filesystem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnmountStartRequestIpc {
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSelectJobResult {
    pub interface: String,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub carrier: Option<bool>,
    pub dhcp: Option<InterfaceSelectDhcpResult>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSelectDhcpResult {
    pub ip: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
}
