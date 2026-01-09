use std::path::{Path, PathBuf};
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
    ActiveInterfaceClearResponse, ActiveInterfaceResponse, InterfaceStatusRequest,
    InterfaceStatusResponse, WifiCapabilitiesRequest, WifiCapabilitiesResponse, BridgeCommand,
    DnsSpoofCommand, EthernetCommand, HardwareCommand, HotspotCommand, LootCommand, MitmCommand,
    NotifyCommand, ProcessCommand, ReverseCommand, ScanCommand, StatusCommand, SystemCommand,
    WifiCommand, MAX_FRAME, PROTOCOL_VERSION,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const LONG_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RETRY_ATTEMPTS: u32 = 3;
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct DaemonClientInfo {
    pub daemon_version: String,
    pub protocol_version: u32,
    pub features: Vec<FeatureFlag>,
    pub authz: rustyjack_ipc::AuthzSummary,
    pub max_frame: u32,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub socket_path: PathBuf,
    pub client_name: String,
    pub client_version: String,
    pub request_timeout: Duration,
    pub long_request_timeout: Duration,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/rustyjack/rustyjackd.sock"),
            client_name: "rustyjack-client".to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            long_request_timeout: LONG_REQUEST_TIMEOUT,
            max_retries: MAX_RETRY_ATTEMPTS,
            retry_delay_ms: INITIAL_RETRY_DELAY.as_millis() as u64,
        }
    }
}

pub struct DaemonClient {
    #[cfg(unix)]
    stream: Option<UnixStream>,
    #[cfg(not(unix))]
    stream: Option<()>,
    next_request_id: AtomicU64,
    info: Option<DaemonClientInfo>,
    config: ClientConfig,
}

impl DaemonClient {
    #[cfg(unix)]
    pub async fn connect<P: AsRef<Path>>(
        path: P,
        client_name: &str,
        client_version: &str,
    ) -> Result<Self> {
        let config = ClientConfig {
            socket_path: path.as_ref().to_path_buf(),
            client_name: client_name.to_string(),
            client_version: client_version.to_string(),
            ..Default::default()
        };
        Self::connect_with_config(config).await
    }

    #[cfg(not(unix))]
    pub async fn connect<P: AsRef<Path>>(
        _path: P,
        _client_name: &str,
        _client_version: &str,
    ) -> Result<Self> {
        bail!("Unix domain sockets not supported on this platform")
    }

    #[cfg(unix)]
    pub async fn connect_with_config(config: ClientConfig) -> Result<Self> {
        let mut client = Self {
            stream: None,
            next_request_id: AtomicU64::new(1),
            info: None,
            config,
        };
        client.reconnect().await?;
        Ok(client)
    }

    #[cfg(not(unix))]
    pub async fn connect_with_config(_config: ClientConfig) -> Result<Self> {
        bail!("Unix domain sockets not supported on this platform")
    }

    pub fn new_disconnected(config: ClientConfig) -> Self {
        Self {
            stream: None,
            next_request_id: AtomicU64::new(1),
            info: None,
            config,
        }
    }

    #[cfg(unix)]
    async fn reconnect(&mut self) -> Result<()> {
        let mut stream = match UnixStream::connect(&self.config.socket_path).await {
            Ok(stream) => stream,
            Err(err) => {
                return Err(enhance_socket_connection_error(err, &self.config.socket_path));
            }
        };
        
        let hello = ClientHello {
            protocol_version: PROTOCOL_VERSION,
            client_name: self.config.client_name.clone(),
            client_version: self.config.client_version.clone(),
            supports: Vec::new(),
        };
        let hello_bytes = serde_json::to_vec(&hello)?;
        write_frame(&mut stream, &hello_bytes, MAX_FRAME).await?;

        let ack_bytes = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
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

        self.stream = Some(stream);
        self.info = Some(info);
        Ok(())
    }

    #[cfg(not(unix))]
    async fn reconnect(&mut self) -> Result<()> {
        bail!("Unix domain sockets not supported on this platform")
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn info(&self) -> Option<&DaemonClientInfo> {
        self.info.as_ref()
    }

    pub async fn ensure_connected(&mut self) -> Result<()> {
        if !self.is_connected() {
            self.reconnect().await?;
        }
        Ok(())
    }

    pub async fn request(&mut self, body: RequestBody) -> Result<ResponseBody> {
        self.request_with_timeout(body, self.config.request_timeout)
            .await
    }

    pub async fn request_long(&mut self, body: RequestBody) -> Result<ResponseBody> {
        self.request_with_timeout(body, self.config.long_request_timeout)
            .await
    }

    pub async fn request_with_timeout(
        &mut self,
        body: RequestBody,
        req_timeout: Duration,
    ) -> Result<ResponseBody> {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.config.max_retries {
            if attempts > 0 {
                let delay = Duration::from_millis(
                    self.config.retry_delay_ms * (1u64 << (attempts - 1).min(4)),
                );
                sleep(delay).await;
            }

            match self.try_request(&body, req_timeout).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    let should_retry = is_retryable_error(&err);
                    last_error = Some(err);
                    
                    if !should_retry {
                        break;
                    }
                    
                    attempts += 1;
                    
                    if attempts < self.config.max_retries {
                        self.stream = None;
                        if let Err(e) = self.reconnect().await {
                            last_error = Some(e);
                        }
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("request failed with no error")))
    }

    #[cfg(unix)]
    async fn try_request(
        &mut self,
        body: &RequestBody,
        req_timeout: Duration,
    ) -> Result<ResponseBody> {
        self.ensure_connected().await?;
        
        let stream = self.stream.as_mut().ok_or_else(|| anyhow!("not connected"))?;
        let info = self.info.as_ref().ok_or_else(|| anyhow!("no info"))?;

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let envelope = RequestEnvelope {
            v: info.protocol_version,
            request_id,
            endpoint: endpoint_for_body(body),
            body: body.clone(),
        };
        let payload = serde_json::to_vec(&envelope)?;
        write_frame(stream, &payload, info.max_frame).await?;

        let response_bytes = timeout(req_timeout, read_frame(stream, info.max_frame))
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
        if response.v != info.protocol_version {
            bail!(
                "protocol version mismatch: expected {} got {}",
                info.protocol_version,
                response.v
            );
        }
        Ok(response.body)
    }

    #[cfg(not(unix))]
    async fn try_request(
        &mut self,
        _body: &RequestBody,
        _req_timeout: Duration,
    ) -> Result<ResponseBody> {
        bail!("Unix domain sockets not supported on this platform")
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

    pub async fn active_interface(&mut self) -> Result<ActiveInterfaceResponse> {
        match self.request(RequestBody::ActiveInterfaceGet).await? {
            ResponseBody::Ok(ResponseOk::ActiveInterface(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn clear_active_interface(&mut self) -> Result<ActiveInterfaceClearResponse> {
        match self.request(RequestBody::ActiveInterfaceClear).await? {
            ResponseBody::Ok(ResponseOk::ActiveInterfaceCleared(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn interface_status(&mut self, interface: &str) -> Result<InterfaceStatusResponse> {
        let body = RequestBody::InterfaceStatusGet(InterfaceStatusRequest {
            interface: interface.to_string(),
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::InterfaceStatus(resp)) => Ok(resp),
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

    pub async fn wifi_interfaces(&mut self) -> Result<rustyjack_ipc::WifiInterfacesResponse> {
        match self.request(RequestBody::WifiInterfacesList).await? {
            ResponseBody::Ok(ResponseOk::WifiInterfaces(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn wifi_disconnect(&mut self, interface: &str) -> Result<rustyjack_ipc::WifiDisconnectResponse> {
        let body = RequestBody::WifiDisconnect(rustyjack_ipc::WifiDisconnectRequest {
            interface: interface.to_string(),
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::WifiDisconnect(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn wifi_scan_start(&mut self, interface: &str, timeout_ms: u64) -> Result<JobStarted> {
        let body = RequestBody::WifiScanStart(rustyjack_ipc::WifiScanStartRequest {
            interface: interface.to_string(),
            timeout_ms,
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStarted(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn wifi_connect_start(&mut self, interface: &str, ssid: &str, psk: Option<String>, timeout_ms: u64) -> Result<JobStarted> {
        let body = RequestBody::WifiConnectStart(rustyjack_ipc::WifiConnectStartRequest {
            interface: interface.to_string(),
            ssid: ssid.to_string(),
            psk,
            timeout_ms,
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStarted(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hotspot_start(
        &mut self,
        interface: &str,
        upstream_interface: &str,
        ssid: &str,
        passphrase: Option<String>,
        channel: Option<u8>,
    ) -> Result<JobStarted> {
        let body = RequestBody::HotspotStart(rustyjack_ipc::HotspotStartRequest {
            interface: interface.to_string(),
            upstream_interface: upstream_interface.to_string(),
            ssid: ssid.to_string(),
            passphrase,
            channel,
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStarted(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hotspot_stop(&mut self) -> Result<rustyjack_ipc::HotspotActionResponse> {
        match self.request(RequestBody::HotspotStop).await? {
            ResponseBody::Ok(ResponseOk::HotspotAction(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn portal_start(&mut self, interface: &str, port: u16) -> Result<JobStarted> {
        let body = RequestBody::PortalStart(rustyjack_ipc::PortalStartRequest {
            interface: interface.to_string(),
            port,
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStarted(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn portal_stop(&mut self) -> Result<rustyjack_ipc::PortalActionResponse> {
        match self.request(RequestBody::PortalStop).await? {
            ResponseBody::Ok(ResponseOk::PortalAction(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn portal_status(&mut self) -> Result<rustyjack_ipc::PortalStatusResponse> {
        match self.request(RequestBody::PortalStatus).await? {
            ResponseBody::Ok(ResponseOk::PortalStatus(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn mount_list(&mut self) -> Result<rustyjack_ipc::MountListResponse> {
        match self.request(RequestBody::MountList).await? {
            ResponseBody::Ok(ResponseOk::MountList(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn mount_start(&mut self, device: &str, filesystem: Option<String>) -> Result<JobStarted> {
        let body = RequestBody::MountStart(rustyjack_ipc::MountStartRequest {
            device: device.to_string(),
            filesystem,
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStarted(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn unmount_start(&mut self, device: &str) -> Result<JobStarted> {
        let body = RequestBody::UnmountStart(rustyjack_ipc::UnmountStartRequest {
            device: device.to_string(),
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::JobStarted(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn status_command(&mut self, command: StatusCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::StatusCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::StatusCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn wifi_command(&mut self, command: WifiCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::WifiCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::WifiCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn ethernet_command(&mut self, command: EthernetCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::EthernetCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::EthernetCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn loot_command(&mut self, command: LootCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::LootCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::LootCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn notify_command(&mut self, command: NotifyCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::NotifyCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::NotifyCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn system_command(&mut self, command: SystemCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::SystemCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::SystemCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hardware_command(&mut self, command: HardwareCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::HardwareCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::HardwareCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn dnsspoof_command(&mut self, command: DnsSpoofCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::DnsSpoofCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::DnsSpoofCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn mitm_command(&mut self, command: MitmCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::MitmCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::MitmCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn reverse_command(&mut self, command: ReverseCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::ReverseCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::ReverseCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn hotspot_command(&mut self, command: HotspotCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::HotspotCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::HotspotCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn scan_command(&mut self, command: ScanCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::ScanCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::ScanCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn bridge_command(&mut self, command: BridgeCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::BridgeCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::BridgeCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn process_command(&mut self, command: ProcessCommand) -> Result<CoreDispatchResponse> {
        let body = RequestBody::ProcessCommand(command);
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::ProcessCommand(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn core_dispatch(&mut self, legacy: rustyjack_ipc::LegacyCommand, args: Value) -> Result<CoreDispatchResponse> {
        let body = RequestBody::CoreDispatch(CoreDispatchRequest { legacy, args });
        match self.request_long(body).await? {
            ResponseBody::Ok(ResponseOk::CoreDispatch(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn set_active_interface(&mut self, interface: &str) -> Result<rustyjack_ipc::SetActiveInterfaceResponse> {
        let body = RequestBody::SetActiveInterface(rustyjack_ipc::SetActiveInterfaceRequest {
            interface: interface.to_string(),
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::SetActiveInterface(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    // Logging and configuration endpoints (Phase 4)
    pub async fn log_tail(&mut self, component: &str, max_lines: Option<usize>) -> Result<rustyjack_ipc::LogTailResponse> {
        let body = RequestBody::LogTailGet(rustyjack_ipc::LogTailRequest {
            component: component.to_string(),
            max_lines,
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::LogTail(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn logging_config_get(&mut self) -> Result<rustyjack_ipc::LoggingConfigResponse> {
        let body = RequestBody::LoggingConfigGet;
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::LoggingConfig(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }

    pub async fn logging_config_set(&mut self, enabled: bool, level: Option<String>) -> Result<rustyjack_ipc::LoggingConfigSetResponse> {
        let body = RequestBody::LoggingConfigSet(rustyjack_ipc::LoggingConfigSetRequest {
            enabled,
            level,
        });
        match self.request(body).await? {
            ResponseBody::Ok(ResponseOk::LoggingConfigSet(resp)) => Ok(resp),
            ResponseBody::Err(err) => Err(daemon_error(err)),
            _ => Err(anyhow!("unexpected response body")),
        }
    }
}

fn enhance_socket_connection_error(err: std::io::Error, socket_path: &Path) -> anyhow::Error {
    use std::io::ErrorKind;

    let socket_exists = socket_path.exists();
    let socket_display = socket_path.display();

    let detailed_message = match err.kind() {
        ErrorKind::NotFound => {
            format!(
                "Failed to connect to daemon socket at {}\n\
                 \n\
                 The socket file does not exist.\n\
                 \n\
                 Possible causes:\n\
                 • The rustyjackd daemon is not running\n\
                 • The daemon failed to start properly\n\
                 • The socket path is incorrect\n\
                 \n\
                 To fix:\n\
                 1. Check if daemon is running: systemctl status rustyjackd\n\
                 2. Start the daemon: systemctl start rustyjackd\n\
                 3. Check daemon logs: journalctl -u rustyjackd -n 50",
                socket_display
            )
        }
        ErrorKind::ConnectionRefused => {
            if socket_exists {
                format!(
                    "Failed to connect to daemon socket at {}\n\
                     \n\
                     The socket file exists but connection was refused.\n\
                     \n\
                     Possible causes:\n\
                     • The daemon is not running or crashed\n\
                     • The socket file is stale (leftover from previous daemon)\n\
                     \n\
                     To fix:\n\
                     1. Check if daemon is running: systemctl status rustyjackd\n\
                     2. Restart the daemon: systemctl restart rustyjackd\n\
                     3. Check daemon logs: journalctl -u rustyjackd -n 50\n\
                     4. If issue persists, remove stale socket: rm {} && systemctl restart rustyjackd",
                    socket_display, socket_display
                )
            } else {
                format!(
                    "Failed to connect to daemon socket at {}\n\
                     \n\
                     Connection refused - daemon is not running.\n\
                     \n\
                     To fix:\n\
                     1. Start the daemon: systemctl start rustyjackd\n\
                     2. Check daemon logs: journalctl -u rustyjackd -n 50",
                    socket_display
                )
            }
        }
        ErrorKind::PermissionDenied => {
            format!(
                "Failed to connect to daemon socket at {}\n\
                 \n\
                 Permission denied - you don't have access to the socket.\n\
                 \n\
                 Possible causes:\n\
                 • Your user is not in the 'rustyjack' group\n\
                 • Socket permissions are too restrictive\n\
                 \n\
                 To fix:\n\
                 1. Add your user to rustyjack group: sudo usermod -a -G rustyjack $USER\n\
                 2. Log out and back in for group changes to take effect\n\
                 3. Or run as root: sudo <your command>\n\
                 4. Check socket permissions: ls -l {}",
                socket_display, socket_display
            )
        }
        ErrorKind::TimedOut => {
            format!(
                "Failed to connect to daemon socket at {}\n\
                 \n\
                 Connection timed out.\n\
                 \n\
                 Possible causes:\n\
                 • The daemon is unresponsive or heavily loaded\n\
                 • System is under heavy load\n\
                 \n\
                 To fix:\n\
                 1. Check daemon status: systemctl status rustyjackd\n\
                 2. Check system load: uptime\n\
                 3. Restart daemon if needed: systemctl restart rustyjackd\n\
                 4. Check daemon logs: journalctl -u rustyjackd -n 50",
                socket_display
            )
        }
        _ => {
            let base_msg = format!(
                "Failed to connect to daemon socket at {}\n\
                 \n\
                 Error: {} ({})\n",
                socket_display, err, err.kind()
            );

            if socket_exists {
                format!(
                    "{}\
                     \n\
                     The socket file exists but connection failed.\n\
                     \n\
                     To diagnose:\n\
                     1. Check daemon status: systemctl status rustyjackd\n\
                     2. Check daemon logs: journalctl -u rustyjackd -n 50\n\
                     3. Check socket: ls -l {}\n\
                     4. Try restarting: systemctl restart rustyjackd",
                    base_msg, socket_display
                )
            } else {
                format!(
                    "{}\
                     \n\
                     The socket file does not exist - daemon is likely not running.\n\
                     \n\
                     To fix:\n\
                     1. Start the daemon: systemctl start rustyjackd\n\
                     2. Check daemon logs: journalctl -u rustyjackd -n 50",
                    base_msg
                )
            }
        }
    };

    anyhow!(detailed_message)
}

fn daemon_error(err: DaemonError) -> anyhow::Error {
    // Use the DaemonError's Display impl which shows message + detail
    let message = err.to_string();

    // Add retryable hint if applicable
    let final_message = if err.retryable {
        format!("{} (retryable)", message)
    } else {
        message
    };

    // Use ErrorCode's Display impl for the context
    anyhow!(final_message).context(err.code.to_string())
}

fn is_retryable_error(err: &anyhow::Error) -> bool {
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        matches!(
            io_err.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted
        )
    } else {
        err.to_string().contains("retryable")
            || err.to_string().contains("timed out")
            || err.to_string().contains("connection")
    }
}

#[cfg(unix)]
async fn read_frame(stream: &mut UnixStream, max_frame: u32) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = rustyjack_ipc::decode_frame_length(len_buf, max_frame)
        .map_err(|err| anyhow!("invalid frame length: {:?}", err))?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(unix)]
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
