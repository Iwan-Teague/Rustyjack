use rustyjack_commands::{
    BridgeCommand, DnsSpoofCommand, EthernetCommand, HardwareCommand, HotspotCommand, LootCommand,
    MitmCommand, NotifyCommand, ProcessCommand, ReverseCommand, ScanCommand, StatusCommand,
    SystemCommand, WifiCommand,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AuthzSummary, DaemonError, JobEvent, JobInfo, JobKind, JobSpec, JobStarted};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureFlag {
    JobSubscribe,
    Compression,
    DangerousOpsEnabled,
    JobProgress,
    UdsTimeouts,
    GroupBasedAuth,
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
    OpsConfigGet,
    OpsConfigSet,
    CoreDispatch,
    StatusCommand,
    WifiCommand,
    EthernetCommand,
    LootCommand,
    NotifyCommand,
    SystemCommand,
    HardwareCommand,
    DnsSpoofCommand,
    MitmCommand,
    ReverseCommand,
    HotspotCommand,
    ScanCommand,
    BridgeCommand,
    ProcessCommand,
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
    ActiveInterfaceGet,
    ActiveInterfaceClear,
    InterfaceStatusGet,
    WifiCapabilitiesGet,
    HotspotWarningsGet,
    HotspotDiagnosticsGet,
    HotspotClientsList,
    GpioDiagnosticsGet,
    WifiInterfacesList,
    WifiDisconnect,
    WifiScanStart,
    WifiConnectStart,
    HotspotStart,
    HotspotStop,
    PortalStart,
    PortalStop,
    PortalStatus,
    MountList,
    MountStart,
    UnmountStart,
    SetActiveInterface,
    HotplugNotify,
    LogTailGet,
    LoggingConfigGet,
    LoggingConfigSet,
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
    OpsConfigGet,
    OpsConfigSet(OpsConfig),
    CoreDispatch(CoreDispatchRequest),
    StatusCommand(StatusCommand),
    WifiCommand(WifiCommand),
    EthernetCommand(EthernetCommand),
    LootCommand(LootCommand),
    NotifyCommand(NotifyCommand),
    SystemCommand(SystemCommand),
    HardwareCommand(HardwareCommand),
    DnsSpoofCommand(DnsSpoofCommand),
    MitmCommand(MitmCommand),
    ReverseCommand(ReverseCommand),
    HotspotCommand(HotspotCommand),
    ScanCommand(ScanCommand),
    BridgeCommand(BridgeCommand),
    ProcessCommand(ProcessCommand),
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
    ActiveInterfaceGet,
    ActiveInterfaceClear,
    InterfaceStatusGet(InterfaceStatusRequest),
    WifiCapabilitiesGet(WifiCapabilitiesRequest),
    HotspotWarningsGet,
    HotspotDiagnosticsGet(HotspotDiagnosticsRequest),
    HotspotClientsList,
    GpioDiagnosticsGet,
    WifiInterfacesList,
    WifiDisconnect(WifiDisconnectRequest),
    WifiScanStart(WifiScanStartRequest),
    WifiConnectStart(WifiConnectStartRequest),
    HotspotStart(HotspotStartRequest),
    HotspotStop,
    PortalStart(PortalStartRequest),
    PortalStop,
    PortalStatus,
    MountList,
    MountStart(MountStartRequest),
    UnmountStart(UnmountStartRequest),
    SetActiveInterface(SetActiveInterfaceRequest),
    HotplugNotify,
    LogTailGet(LogTailRequest),
    LoggingConfigGet,
    LoggingConfigSet(LoggingConfigSetRequest),
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
    OpsConfig(OpsConfig),
    OpsConfigSetAck { ops: OpsConfig },
    CoreDispatch(CoreDispatchResponse),
    StatusCommand(CoreDispatchResponse),
    WifiCommand(CoreDispatchResponse),
    EthernetCommand(CoreDispatchResponse),
    LootCommand(CoreDispatchResponse),
    NotifyCommand(CoreDispatchResponse),
    SystemCommand(CoreDispatchResponse),
    HardwareCommand(CoreDispatchResponse),
    DnsSpoofCommand(CoreDispatchResponse),
    MitmCommand(CoreDispatchResponse),
    ReverseCommand(CoreDispatchResponse),
    HotspotCommand(CoreDispatchResponse),
    ScanCommand(CoreDispatchResponse),
    BridgeCommand(CoreDispatchResponse),
    ProcessCommand(CoreDispatchResponse),
    JobStarted(JobStarted),
    JobStatus(JobStatusResponse),
    JobCancelled(JobCancelResponse),
    SystemStatus(SystemStatusResponse),
    DiskUsage(DiskUsageResponse),
    SystemAction(SystemActionResponse),
    Hostname(HostnameResponse),
    BlockDevices(BlockDevicesResponse),
    SystemLogs(SystemLogsResponse),
    ActiveInterface(ActiveInterfaceResponse),
    ActiveInterfaceCleared(ActiveInterfaceClearResponse),
    InterfaceStatus(InterfaceStatusResponse),
    WifiCapabilities(WifiCapabilitiesResponse),
    HotspotWarnings(HotspotWarningsResponse),
    HotspotDiagnostics(HotspotDiagnosticsResponse),
    HotspotClients(HotspotClientsResponse),
    GpioDiagnostics(GpioDiagnosticsResponse),
    WifiInterfaces(WifiInterfacesResponse),
    WifiDisconnect(WifiDisconnectResponse),
    HotspotAction(HotspotActionResponse),
    PortalAction(PortalActionResponse),
    PortalStatus(PortalStatusResponse),
    MountList(MountListResponse),
    SetActiveInterface(SetActiveInterfaceResponse),
    HotplugNotify(HotplugNotifyResponse),
    LogTail(LogTailResponse),
    LoggingConfig(LoggingConfigResponse),
    LoggingConfigSet(LoggingConfigSetResponse),
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
    pub ops: OpsStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpsConfig {
    pub wifi_ops: bool,
    pub eth_ops: bool,
    pub hotspot_ops: bool,
    pub portal_ops: bool,
    pub storage_ops: bool,
    pub power_ops: bool,
    pub system_ops: bool,
    pub update_ops: bool,
    pub dev_ops: bool,
    pub offensive_ops: bool,
    pub loot_ops: bool,
    pub process_ops: bool,
}

impl OpsConfig {
    pub fn appliance_defaults() -> Self {
        Self {
            wifi_ops: true,
            eth_ops: true,
            hotspot_ops: true,
            portal_ops: true,
            storage_ops: true,
            power_ops: true,
            system_ops: true,
            update_ops: true,
            dev_ops: false,
            offensive_ops: false,
            loot_ops: false,
            process_ops: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsStatus {
    pub wifi_ops: bool,
    pub eth_ops: bool,
    pub hotspot_ops: bool,
    pub portal_ops: bool,
    pub storage_ops: bool,
    pub power_ops: bool,
    pub system_ops: bool,
    pub update_ops: bool,
    pub dev_ops: bool,
    pub offensive_ops: bool,
    pub loot_ops: bool,
    pub process_ops: bool,
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
    pub transport: Option<String>,
    pub removable: bool,
    pub is_partition: bool,
    pub parent: Option<String>,
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
pub struct ActiveInterfaceResponse {
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveInterfaceClearResponse {
    pub cleared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatusRequest {
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceCapabilities {
    pub is_wireless: bool,
    pub is_physical: bool,
    pub supports_monitor: bool,
    pub supports_ap: bool,
    pub supports_injection: bool,
    pub supports_5ghz: bool,
    pub supports_2ghz: bool,
    pub mac_address: Option<String>,
    pub driver: Option<String>,
    pub chipset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatusResponse {
    pub interface: String,
    pub exists: bool,
    pub is_wireless: bool,
    pub oper_state: String,
    pub is_up: bool,
    pub carrier: Option<bool>,
    pub ip: Option<String>,
    pub capabilities: Option<InterfaceCapabilities>,
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
pub struct WifiInterfacesResponse {
    pub interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiDisconnectRequest {
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiDisconnectResponse {
    pub interface: String,
    pub disconnected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiScanStartRequest {
    pub interface: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConnectStartRequest {
    pub interface: String,
    pub ssid: String,
    pub psk: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotStartRequest {
    pub interface: String,
    pub upstream_interface: String,
    pub ssid: String,
    pub passphrase: Option<String>,
    pub channel: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotActionResponse {
    pub action: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalStartRequest {
    pub interface: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalActionResponse {
    pub action: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalStatusResponse {
    pub running: bool,
    pub interface: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub device: String,
    pub mountpoint: String,
    pub filesystem: String,
    pub size: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountListResponse {
    pub mounts: Vec<MountInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountStartRequest {
    pub device: String,
    pub filesystem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmountStartRequest {
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetActiveInterfaceRequest {
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetActiveInterfaceResponse {
    pub interface: String,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotplugNotifyResponse {
    pub acknowledged: bool,
}

// Logging and audit endpoints (Phase 4)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogComponent {
    Rustyjackd,
    RustyjackUi,
    Portal,
    Usb,
    Wifi,
    Net,
    Crypto,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogTailRequest {
    pub component: LogComponent,
    pub max_lines: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogTailResponse {
    pub component: LogComponent,
    pub lines: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfigResponse {
    pub enabled: bool,
    pub level: LogLevel,
    pub components: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfigSetRequest {
    pub enabled: bool,
    pub level: Option<LogLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfigSetResponse {
    pub enabled: bool,
    pub level: LogLevel,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyCommand {
    WifiScan,
    WifiConnect,
    WifiDisconnect,
    HotspotStart,
    HotspotStop,
    PortalStart,
    PortalStop,
    MountStart,
    MountStop,
    CommandDispatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreDispatchRequest {
    pub legacy: LegacyCommand,
    pub args: Value,
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
        RequestBody::OpsConfigGet => Endpoint::OpsConfigGet,
        RequestBody::OpsConfigSet(_) => Endpoint::OpsConfigSet,
        RequestBody::CoreDispatch(_) => Endpoint::CoreDispatch,
        RequestBody::StatusCommand(_) => Endpoint::StatusCommand,
        RequestBody::WifiCommand(_) => Endpoint::WifiCommand,
        RequestBody::EthernetCommand(_) => Endpoint::EthernetCommand,
        RequestBody::LootCommand(_) => Endpoint::LootCommand,
        RequestBody::NotifyCommand(_) => Endpoint::NotifyCommand,
        RequestBody::SystemCommand(_) => Endpoint::SystemCommand,
        RequestBody::HardwareCommand(_) => Endpoint::HardwareCommand,
        RequestBody::DnsSpoofCommand(_) => Endpoint::DnsSpoofCommand,
        RequestBody::MitmCommand(_) => Endpoint::MitmCommand,
        RequestBody::ReverseCommand(_) => Endpoint::ReverseCommand,
        RequestBody::HotspotCommand(_) => Endpoint::HotspotCommand,
        RequestBody::ScanCommand(_) => Endpoint::ScanCommand,
        RequestBody::BridgeCommand(_) => Endpoint::BridgeCommand,
        RequestBody::ProcessCommand(_) => Endpoint::ProcessCommand,
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
        RequestBody::ActiveInterfaceGet => Endpoint::ActiveInterfaceGet,
        RequestBody::ActiveInterfaceClear => Endpoint::ActiveInterfaceClear,
        RequestBody::InterfaceStatusGet(_) => Endpoint::InterfaceStatusGet,
        RequestBody::WifiCapabilitiesGet(_) => Endpoint::WifiCapabilitiesGet,
        RequestBody::HotspotWarningsGet => Endpoint::HotspotWarningsGet,
        RequestBody::HotspotDiagnosticsGet(_) => Endpoint::HotspotDiagnosticsGet,
        RequestBody::HotspotClientsList => Endpoint::HotspotClientsList,
        RequestBody::GpioDiagnosticsGet => Endpoint::GpioDiagnosticsGet,
        RequestBody::WifiInterfacesList => Endpoint::WifiInterfacesList,
        RequestBody::WifiDisconnect(_) => Endpoint::WifiDisconnect,
        RequestBody::WifiScanStart(_) => Endpoint::WifiScanStart,
        RequestBody::WifiConnectStart(_) => Endpoint::WifiConnectStart,
        RequestBody::HotspotStart(_) => Endpoint::HotspotStart,
        RequestBody::HotspotStop => Endpoint::HotspotStop,
        RequestBody::PortalStart(_) => Endpoint::PortalStart,
        RequestBody::PortalStop => Endpoint::PortalStop,
        RequestBody::PortalStatus => Endpoint::PortalStatus,
        RequestBody::MountList => Endpoint::MountList,
        RequestBody::MountStart(_) => Endpoint::MountStart,
        RequestBody::UnmountStart(_) => Endpoint::UnmountStart,
        RequestBody::SetActiveInterface(_) => Endpoint::SetActiveInterface,
        RequestBody::HotplugNotify => Endpoint::HotplugNotify,
        RequestBody::LogTailGet(_) => Endpoint::LogTailGet,
        RequestBody::LoggingConfigGet => Endpoint::LoggingConfigGet,
        RequestBody::LoggingConfigSet(_) => Endpoint::LoggingConfigSet,
    }
}

pub fn is_dangerous_job(kind: &JobKind) -> bool {
    !matches!(
        kind,
        JobKind::Noop
            | JobKind::Sleep { .. }
            | JobKind::ScanRun { .. }
            | JobKind::WifiScan { .. }
            | JobKind::InterfaceSelect { .. }
    )
}
