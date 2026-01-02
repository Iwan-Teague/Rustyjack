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
    pub service: String,
    pub remote: String,
    pub branch: String,
    pub backup_dir: Option<String>,
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
