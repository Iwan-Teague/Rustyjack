use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AuthzSummary, DaemonError, JobEvent, JobInfo, JobKind, JobSpec, JobStarted};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureFlag {
    JobSubscribe,
    Compression,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol_version: u32,
    pub client_name: String,
    pub client_version: String,
    pub supports: Vec<FeatureFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub protocol_version: u32,
    pub daemon_version: String,
    pub features: Vec<FeatureFlag>,
    pub max_frame: u32,
    pub authz: AuthzSummary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    Health,
    Version,
    Status,
    CoreDispatch,
    JobStart,
    JobStatus,
    JobCancel,
    SystemStatusGet,
    DiskUsageGet,
    SystemReboot,
    SystemShutdown,
    SystemSync,
    HostnameRandomizeNow,
    BlockDevicesList,
    SystemLogsGet,
    WifiCapabilitiesGet,
    HotspotWarningsGet,
    HotspotDiagnosticsGet,
    HotspotClientsList,
    GpioDiagnosticsGet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub v: u32,
    pub request_id: u64,
    pub endpoint: Endpoint,
    pub body: RequestBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub v: u32,
    pub request_id: u64,
    pub body: ResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RequestBody {
    Health,
    Version,
    Status,
    CoreDispatch(CoreDispatchRequest),
    JobStart(JobStartRequest),
    JobStatus(JobStatusRequest),
    JobCancel(JobCancelRequest),
    SystemStatusGet,
    DiskUsageGet(DiskUsageRequest),
    SystemReboot,
    SystemShutdown,
    SystemSync,
    HostnameRandomizeNow,
    BlockDevicesList,
    SystemLogsGet,
    WifiCapabilitiesGet(WifiCapabilitiesRequest),
    HotspotWarningsGet,
    HotspotDiagnosticsGet(HotspotDiagnosticsRequest),
    HotspotClientsList,
    GpioDiagnosticsGet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ResponseBody {
    Ok(ResponseOk),
    Err(DaemonError),
    Event(DaemonEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ResponseOk {
    Health(HealthResponse),
    Version(VersionResponse),
    Status(StatusResponse),
    CoreDispatch(CoreDispatchResponse),
    JobStarted(JobStarted),
    JobStatus(JobStatusResponse),
    JobCancelled(JobCancelResponse),
    SystemStatus(SystemStatusResponse),
    DiskUsage(DiskUsageResponse),
    SystemAction(SystemActionResponse),
    Hostname(HostnameResponse),
    BlockDevices(BlockDevicesResponse),
    SystemLogs(SystemLogsResponse),
    WifiCapabilities(WifiCapabilitiesResponse),
    HotspotWarnings(HotspotWarningsResponse),
    HotspotDiagnostics(HotspotDiagnosticsResponse),
    HotspotClients(HotspotClientsResponse),
    GpioDiagnostics(GpioDiagnosticsResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub uptime_ms: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub daemon_version: String,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub uptime_ms: u64,
    pub jobs_active: usize,
    pub jobs_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatusResponse {
    pub uptime_ms: u64,
    pub hostname: Option<String>,
    pub status_text: Option<String>,
    pub mitm_running: Option<bool>,
    pub dnsspoof_running: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsageRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsageResponse {
    pub used_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemActionResponse {
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostnameResponse {
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub size: String,
    pub model: String,
    pub transport: String,
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDevicesResponse {
    pub devices: Vec<BlockDeviceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemLogsResponse {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCapabilitiesRequest {
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCapabilitiesResponse {
    pub native_available: bool,
    pub has_root: bool,
    pub interface_exists: bool,
    pub interface_is_wireless: bool,
    pub supports_monitor_mode: bool,
    pub supports_injection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotWarningsResponse {
    pub last_warning: Option<String>,
    pub last_ap_error: Option<String>,
    pub last_start_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotDiagnosticsRequest {
    pub ap_interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfkillEntry {
    pub idx: u32,
    pub type_name: String,
    pub state: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotApSupport {
    pub supports_ap: bool,
    pub supported_modes: Vec<String>,
    pub supported_bands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotDiagnosticsResponse {
    pub regdom_raw: Option<String>,
    pub regdom_valid: bool,
    pub rfkill: Vec<RfkillEntry>,
    pub ap_support: Option<HotspotApSupport>,
    pub allowed_channels: Vec<u8>,
    pub last_start_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotClient {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub lease_start: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotClientsResponse {
    pub clients: Vec<HotspotClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpioDiagnosticsResponse {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreDispatchRequest {
    pub command: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreDispatchResponse {
    pub message: String,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStartRequest {
    pub job: JobSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatusRequest {
    pub job_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatusResponse {
    pub job: JobInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCancelRequest {
    pub job_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCancelResponse {
    pub job_id: u64,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum DaemonEvent {
    JobUpdate(JobEvent),
}

pub fn endpoint_for_body(body: &RequestBody) -> Endpoint {
    match body {
        RequestBody::Health => Endpoint::Health,
        RequestBody::Version => Endpoint::Version,
        RequestBody::Status => Endpoint::Status,
        RequestBody::CoreDispatch(_) => Endpoint::CoreDispatch,
        RequestBody::JobStart(_) => Endpoint::JobStart,
        RequestBody::JobStatus(_) => Endpoint::JobStatus,
        RequestBody::JobCancel(_) => Endpoint::JobCancel,
        RequestBody::SystemStatusGet => Endpoint::SystemStatusGet,
        RequestBody::DiskUsageGet(_) => Endpoint::DiskUsageGet,
        RequestBody::SystemReboot => Endpoint::SystemReboot,
        RequestBody::SystemShutdown => Endpoint::SystemShutdown,
        RequestBody::SystemSync => Endpoint::SystemSync,
        RequestBody::HostnameRandomizeNow => Endpoint::HostnameRandomizeNow,
        RequestBody::BlockDevicesList => Endpoint::BlockDevicesList,
        RequestBody::SystemLogsGet => Endpoint::SystemLogsGet,
        RequestBody::WifiCapabilitiesGet(_) => Endpoint::WifiCapabilitiesGet,
        RequestBody::HotspotWarningsGet => Endpoint::HotspotWarningsGet,
        RequestBody::HotspotDiagnosticsGet(_) => Endpoint::HotspotDiagnosticsGet,
        RequestBody::HotspotClientsList => Endpoint::HotspotClientsList,
        RequestBody::GpioDiagnosticsGet => Endpoint::GpioDiagnosticsGet,
    }
}

pub fn is_dangerous_job(kind: &JobKind) -> bool {
    !matches!(
        kind,
        JobKind::Noop | JobKind::Sleep { .. } | JobKind::ScanRun { .. }
    )
}
