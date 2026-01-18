#![deny(unsafe_op_in_unsafe_fn)]
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME: u32 = 1_048_576;

mod authz;
mod error;
mod job;
mod types;
mod wire;

pub use rustyjack_commands::{
    BridgeCommand, Commands, DnsSpoofCommand, EthernetCommand, HardwareCommand, HotspotCommand,
    LootCommand, MitmCommand, NotifyCommand, ProcessCommand, ReverseCommand, ScanCommand,
    StatusCommand, SystemCommand, WifiCommand,
};
pub use authz::{AuthzSummary, AuthorizationTier};
pub use error::{DaemonError, ErrorCode};
pub use job::{
    HotspotStartRequestIpc, JobEvent, JobId, JobInfo, JobKind, JobSpec, JobStarted, JobState,
    MountStartRequestIpc, PortalStartRequestIpc, Progress, ScanModeIpc, ScanRequestIpc,
    UnmountStartRequestIpc, UpdateRequestIpc, WifiConnectRequestIpc, WifiScanRequestIpc,
    InterfaceSelectDhcpResult, InterfaceSelectJobResult,
};
pub use types::{
    endpoint_for_body, is_dangerous_job, BlockDeviceInfo, BlockDevicesResponse, ClientHello,
    CoreDispatchRequest, CoreDispatchResponse, DaemonEvent, DiskUsageRequest, DiskUsageResponse,
    Endpoint, FeatureFlag, GpioDiagnosticsResponse, HealthResponse, HelloAck, ActiveInterfaceResponse,
    ActiveInterfaceClearResponse, InterfaceCapabilities, InterfaceStatusRequest,
    InterfaceStatusResponse, HotplugNotifyResponse, HotspotActionResponse, HotspotApSupport,
    HotspotClient, HotspotClientsResponse, HotspotDiagnosticsRequest, HotspotDiagnosticsResponse,
    HotspotStartRequest, HotspotWarningsResponse, HostnameResponse, JobCancelRequest,
    JobCancelResponse, JobStartRequest, JobStatusRequest, JobStatusResponse, LegacyCommand,
    LoggingConfigResponse, LoggingConfigSetRequest, LoggingConfigSetResponse, LogComponent,
    LogLevel, LogTailRequest, LogTailResponse, MountInfo, MountListResponse, MountStartRequest,
    PortalActionResponse, PortalStartRequest, PortalStatusResponse, RequestBody, RequestEnvelope,
    ResponseBody, ResponseEnvelope, ResponseOk, RfkillEntry, SetActiveInterfaceRequest,
    SetActiveInterfaceResponse, StatusResponse, SystemActionResponse, SystemLogsResponse,
    SystemStatusResponse, UnmountStartRequest, VersionResponse, WifiCapabilitiesRequest,
    WifiCapabilitiesResponse, WifiConnectStartRequest, WifiDisconnectRequest,
    WifiDisconnectResponse, WifiInterfacesResponse, WifiScanStartRequest,
};
pub use wire::{decode_frame_length, encode_frame, FrameError};
