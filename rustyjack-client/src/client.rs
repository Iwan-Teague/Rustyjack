use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustyjack_ipc::{
    endpoint_for_body, BlockDevicesResponse, ClientHello, CoreDispatchRequest, CoreDispatchResponse,
    DaemonError, DiskUsageRequest, DiskUsageResponse, ErrorCode, FeatureFlag,
    GpioDiagnosticsResponse, HealthResponse, HelloAck, HostnameResponse, HotspotClientsResponse,
    HotspotDiagnosticsRequest, HotspotDiagnosticsResponse, HotspotWarningsResponse, JobCancelRequest,
    JobCancelResponse, JobKind, JobSpec, JobStartRequest, JobStarted, JobStatusRequest,
    JobStatusResponse, RequestBody, RequestEnvelope, ResponseBody, ResponseEnvelope, ResponseOk,
    StatusResponse, SystemActionResponse, SystemLogsResponse, SystemStatusResponse, VersionResponse,
    WifiCapabilitiesRequest, WifiCapabilitiesResponse, MAX_FRAME, PROTOCOL_VERSION,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct DaemonClientInfo {
    pub daemon_version: String,
    pub protocol_version: u32,
    pub features: Vec<FeatureFlag>,
    pub authz: rustyjack_ipc::AuthzSummary,
    pub max_frame: u32,
}

pub struct DaemonClient {
    stream: UnixStream,
    next_request_id: AtomicU64,
    info: DaemonClientInfo,
}

impl DaemonClient {
    pub async fn connect<P: AsRef<Path>>(
        path: P,
        client_name: &str,
        client_version: &str,
    ) -> Result<Self> {
        let mut stream = UnixStream::connect(path).await?;
        let hello = ClientHello {
            protocol_version: PROTOCOL_VERSION,
            client_name: client_name.to_string(),
            client_version: client_version.to_string(),
            supports: Vec::new(),
        };
        let hello_bytes = serde_json::to_vec(&hello)?;
        write_frame(&mut stream, &hello_bytes, MAX_FRAME).await?;

        let ack_bytes = timeout(HANDSHAKE_TIMEOUT, read_frame(&mut stream, MAX_FRAME))
            .await
            .context("handshake timed out")??;
        let ack: HelloAck = serde_json::from_slice(&ack_bytes)?;
        if ack.protocol_version != PROTOCOL_VERSION {
            bail!(
                "protocol mismatch: client={} daemon={}",
                PROTOCOL_VERSION,
                ack.protocol_version
            );
        }

        let info = DaemonClientInfo {
            daemon_version: ack.daemon_version,
            protocol_version: ack.protocol_version,
            features: ack.features,
            authz: ack.authz,
            max_frame: ack.max_frame,
        };

        Ok(Self {
            stream,
            next_request_id: AtomicU64::new(1),
            info,
        })
    }

    pub fn info(&self) -> &DaemonClientInfo {
        &self.info
    }

    pub async fn request(&mut self, body: RequestBody) -> Result<ResponseBody> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.request_with_id(request_id, body).await
    }

    pub async fn request_with_id(
        &mut self,
        request_id: u64,
        body: RequestBody,
    ) -> Result<ResponseBody> {
        let envelope = RequestEnvelope {
            v: self.info.protocol_version,
            request_id,
            endpoint: endpoint_for_body(&body),
            body,
        };
        let payload = serde_json::to_vec(&envelope)?;
        write_frame(&mut self.stream, &payload, self.info.max_frame).await?;

        let response_bytes = timeout(RESPONSE_TIMEOUT, read_frame(&mut self.stream, self.info.max_frame))
            .await
            .context("response timed out")??;
        let response: ResponseEnvelope = serde_json::from_slice(&response_bytes)?;
        if response.request_id != request_id {
            bail!(
                "response request_id mismatch: expected {} got {}",
                request_id,
                response.request_id
            );
        }
        if response.v != self.info.protocol_version {
            bail!(
                "protocol version mismatch: expected {} got {}",
                self.info.protocol_version,
                response.v
            );
        }
        Ok(response.body)
    }

    pub async fn health(&mut self) -> Result<HealthResponse> {
        match self.request(RequestBody::Health).await? {
            ResponseBody::Ok(ResponseOk::Health(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn version(&mut self) -> Result<VersionResponse> {
        match self.request(RequestBody::Version).await? {
            ResponseBody::Ok(ResponseOk::Version(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn status(&mut self) -> Result<StatusResponse> {
        match self.request(RequestBody::Status).await? {
            ResponseBody::Ok(ResponseOk::Status(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn system_status(&mut self) -> Result<SystemStatusResponse> {
        match self.request(RequestBody::SystemStatusGet).await? {
            ResponseBody::Ok(ResponseOk::SystemStatus(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn disk_usage(&mut self, path: &str) -> Result<DiskUsageResponse> {
        let body = RequestBody::DiskUsageGet(DiskUsageRequest {
            path: path.to_string(),
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::DiskUsage(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn system_reboot(&mut self) -> Result<SystemActionResponse> {
        match self.request(RequestBody::SystemReboot).await? {
            ResponseBody::Ok(ResponseOk::SystemAction(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn system_shutdown(&mut self) -> Result<SystemActionResponse> {
        match self.request(RequestBody::SystemShutdown).await? {
            ResponseBody::Ok(ResponseOk::SystemAction(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn system_sync(&mut self) -> Result<SystemActionResponse> {
        match self.request(RequestBody::SystemSync).await? {
            ResponseBody::Ok(ResponseOk::SystemAction(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hostname_randomize_now(&mut self) -> Result<HostnameResponse> {
        match self.request(RequestBody::HostnameRandomizeNow).await? {
            ResponseBody::Ok(ResponseOk::Hostname(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn block_devices(&mut self) -> Result<BlockDevicesResponse> {
        match self.request(RequestBody::BlockDevicesList).await? {
            ResponseBody::Ok(ResponseOk::BlockDevices(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn system_logs(&mut self) -> Result<SystemLogsResponse> {
        match self.request(RequestBody::SystemLogsGet).await? {
            ResponseBody::Ok(ResponseOk::SystemLogs(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn wifi_capabilities(
        &mut self,
        interface: &str,
    ) -> Result<WifiCapabilitiesResponse> {
        let body = RequestBody::WifiCapabilitiesGet(WifiCapabilitiesRequest {
            interface: interface.to_string(),
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::WifiCapabilities(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hotspot_warnings(&mut self) -> Result<HotspotWarningsResponse> {
        match self.request(RequestBody::HotspotWarningsGet).await? {
            ResponseBody::Ok(ResponseOk::HotspotWarnings(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hotspot_diagnostics(
        &mut self,
        ap_interface: &str,
    ) -> Result<HotspotDiagnosticsResponse> {
        let body = RequestBody::HotspotDiagnosticsGet(HotspotDiagnosticsRequest {
            ap_interface: ap_interface.to_string(),
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::HotspotDiagnostics(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hotspot_clients(&mut self) -> Result<HotspotClientsResponse> {
        match self.request(RequestBody::HotspotClientsList).await? {
            ResponseBody::Ok(ResponseOk::HotspotClients(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn gpio_diagnostics(&mut self) -> Result<GpioDiagnosticsResponse> {
        match self.request(RequestBody::GpioDiagnosticsGet).await? {
            ResponseBody::Ok(ResponseOk::GpioDiagnostics(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn job_start(&mut self, kind: JobKind) -> Result<JobStarted> {
        let body = RequestBody::JobStart(JobStartRequest {
            job: JobSpec {
                kind,
                requested_by: None,
            },
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStarted(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn job_status(&mut self, job_id: u64) -> Result<JobStatusResponse> {
        let body = RequestBody::JobStatus(JobStatusRequest { job_id });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStatus(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn job_cancel(&mut self, job_id: u64) -> Result<JobCancelResponse> {
        let body = RequestBody::JobCancel(JobCancelRequest { job_id });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobCancelled(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn core_dispatch(&mut self, command: Value) -> Result<CoreDispatchResponse> {
        let body = RequestBody::CoreDispatch(CoreDispatchRequest { command });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::CoreDispatch(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }
}

fn daemon_error(err: DaemonError) -> anyhow::Error {
    let mut message = format!("{}", err.message);
    if let Some(detail) = err.detail {
        message.push_str(": ");
        message.push_str(&detail);
    }
    if err.retryable {
        message.push_str(" (retryable)");
    }
    anyhow!(message).context(match err.code {
        ErrorCode::Unauthorized => "unauthorized",
        ErrorCode::Forbidden => "forbidden",
        ErrorCode::NotFound => "not found",
        ErrorCode::Busy => "busy",
        ErrorCode::Timeout => "timeout",
        ErrorCode::Cancelled => "cancelled",
        ErrorCode::BadRequest => "bad request",
        ErrorCode::IncompatibleProtocol => "protocol",
        ErrorCode::Io => "io",
        ErrorCode::Netlink => "netlink",
        ErrorCode::MountFailed => "mount",
        ErrorCode::WifiFailed => "wifi",
        ErrorCode::UpdateFailed => "update",
        ErrorCode::CleanupFailed => "cleanup",
        ErrorCode::NotImplemented => "not implemented",
        ErrorCode::Internal => "internal",
    })
}

async fn read_frame(stream: &mut UnixStream, max_frame: u32) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = rustyjack_ipc::decode_frame_length(len_buf, max_frame)
        .map_err(|err| anyhow!("invalid frame length: {:?}", err))?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(stream: &mut UnixStream, payload: &[u8], max_frame: u32) -> Result<()> {
    if payload.is_empty() {
        bail!("empty payload");
    }
    if payload.len() as u32 > max_frame {
        bail!("payload exceeds max_frame");
    }
    let frame = rustyjack_ipc::encode_frame(payload);
    stream.write_all(&frame).await?;
    Ok(())
}
