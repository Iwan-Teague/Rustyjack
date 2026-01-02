pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME: u32 = 1_048_576;

mod authz;
mod error;
mod job;
mod types;
mod wire;

pub use authz::{AuthzSummary, AuthorizationTier};
pub use error::{DaemonError, ErrorCode};
pub use job::{
    JobEvent, JobId, JobInfo, JobKind, JobSpec, JobStarted, JobState, Progress, ScanModeIpc,
    ScanRequestIpc, UpdateRequestIpc,
};
pub use types::{
    endpoint_for_body, is_dangerous_job, BlockDeviceInfo, BlockDevicesResponse, ClientHello,
    CoreDispatchRequest, CoreDispatchResponse, DaemonEvent, DiskUsageRequest, DiskUsageResponse,
    Endpoint, FeatureFlag, GpioDiagnosticsResponse, HealthResponse, HelloAck, HostnameResponse,
    HotspotApSupport, HotspotClient, HotspotClientsResponse, HotspotDiagnosticsRequest,
    HotspotDiagnosticsResponse, HotspotWarningsResponse, JobCancelRequest, JobCancelResponse,
    JobStartRequest, JobStatusRequest, JobStatusResponse, RequestBody, RequestEnvelope,
    ResponseBody, ResponseEnvelope, ResponseOk, RfkillEntry, StatusResponse, SystemActionResponse,
    SystemLogsResponse, SystemStatusResponse, VersionResponse, WifiCapabilitiesRequest,
    WifiCapabilitiesResponse,
};
pub use wire::{decode_frame_length, encode_frame, FrameError};
