#![deny(unsafe_op_in_unsafe_fn)]
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME: u32 = 1_048_576;

mod authz;
mod error;
mod job;
mod types;
mod wire;

pub use authz::{AuthorizationTier, AuthzSummary};
pub use error::{DaemonError, ErrorCode};
pub use job::{
    HotspotStartRequestIpc, InterfaceSelectDhcpResult, InterfaceSelectJobResult,
    InterfaceSelectRollbackResult, InterfaceSelectStatusResult, JobEvent, JobId, JobInfo, JobKind,
    JobSpec, JobStarted, JobState, MountStartRequestIpc, PortalStartRequestIpc, Progress,
    ScanModeIpc, ScanRequestIpc, UnmountStartRequestIpc, UpdateRequestIpc, WifiConnectRequestIpc,
    WifiScanRequestIpc,
};
pub use rustyjack_commands::{
    BridgeCommand, Commands, DnsSpoofCommand, EthernetCommand, HardwareCommand, HotspotCommand,
    LootCommand, MitmCommand, NotifyCommand, ProcessCommand, ReverseCommand, ScanCommand,
    StatusCommand, SystemCommand, WifiCommand,
};
pub use types::{
    endpoint_for_body, is_dangerous_job, ActiveInterfaceClearResponse, ActiveInterfaceResponse,
    BlockDeviceInfo, BlockDevicesResponse, ClientHello, CoreDispatchRequest, CoreDispatchResponse,
    DaemonEvent, DiskUsageRequest, DiskUsageResponse, Endpoint, FeatureFlag,
    GpioDiagnosticsResponse, HealthResponse, HelloAck, HostnameResponse, HotplugNotifyResponse,
    HotspotActionResponse, HotspotApSupport, HotspotClient, HotspotClientsResponse,
    HotspotDiagnosticsRequest, HotspotDiagnosticsResponse, HotspotStartRequest,
    HotspotWarningsResponse, InterfaceCapabilities, InterfaceStatusRequest,
    InterfaceStatusResponse, InterfacesListResponse, JobCancelRequest, JobCancelResponse,
    JobStartRequest, JobStatusRequest, JobStatusResponse, LegacyCommand, LogComponent, LogLevel,
    LogTailRequest, LogTailResponse, LoggingConfigResponse, LoggingConfigSetRequest,
    LoggingConfigSetResponse, MountInfo, MountListResponse, MountStartRequest, OpsConfig,
    OpsStatus, PortalActionResponse, PortalStartRequest, PortalStatusResponse, RequestBody,
    RequestEnvelope, ResponseBody, ResponseEnvelope, ResponseOk, RfkillEntry,
    SetActiveInterfaceRequest, SetActiveInterfaceResponse, StatusResponse, SystemActionResponse,
    SystemLogsResponse, SystemStatusResponse, TxInMonitorCapability, UnmountStartRequest,
    VersionResponse, WifiCapabilitiesRequest, WifiCapabilitiesResponse, WifiConnectStartRequest,
    WifiDisconnectRequest, WifiDisconnectResponse, WifiInterfacesResponse, WifiScanStartRequest,
};
pub use wire::{decode_frame_length, encode_frame, FrameError};
