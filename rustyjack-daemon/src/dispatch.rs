use std::sync::Arc;
use std::time::Instant;

use rustyjack_ipc::{
    is_dangerous_job, BlockDeviceInfo, BlockDevicesResponse, CoreDispatchRequest,
    DaemonError, DiskUsageRequest, DiskUsageResponse, ErrorCode,
    GpioDiagnosticsResponse, HealthResponse, HostnameResponse, HotspotClientsResponse,
    HotspotDiagnosticsRequest, HotspotDiagnosticsResponse, HotspotWarningsResponse,
    JobCancelRequest, JobCancelResponse, JobSpec, JobStarted, JobStartRequest, JobStatusRequest,
    JobStatusResponse, RequestBody, RequestEnvelope, ResponseBody, ResponseEnvelope, ResponseOk,
    StatusResponse, SystemActionResponse, SystemLogsResponse, SystemStatusResponse,
    VersionResponse, WifiCapabilitiesRequest, WifiCapabilitiesResponse, PROTOCOL_VERSION,
};
use tokio::task;

use crate::auth::PeerCred;
use crate::state::DaemonState;
use crate::telemetry::log_request;
use crate::validation;

async fn run_blocking<T, E, F>(label: &'static str, f: F) -> Result<T, DaemonError>
where
    T: Send + 'static,
    E: Into<DaemonError> + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    task::spawn_blocking(f)
        .await
        .map_err(|e| {
            DaemonError::new(
                ErrorCode::Internal,
                format!("{} panicked", label),
                false,
            )
            .with_detail(e.to_string())
            .with_source(format!("daemon.dispatch.{}", label))
        })?
        .map_err(|e| e.into())
}

pub async fn handle_request(
    state: &Arc<DaemonState>,
    request: RequestEnvelope,
    peer: PeerCred,
) -> ResponseEnvelope {
    let start = Instant::now();

    let response_body = match request.body {
        RequestBody::Health => ResponseBody::Ok(ResponseOk::Health(HealthResponse {
            ok: true,
            uptime_ms: state.uptime_ms(),
            message: "ok".to_string(),
        })),
        RequestBody::Version => ResponseBody::Ok(ResponseOk::Version(VersionResponse {
            daemon_version: state.version.clone(),
            protocol_version: PROTOCOL_VERSION,
        })),
        RequestBody::Status => {
            let (total, active) = state.jobs.job_counts().await;
            ResponseBody::Ok(ResponseOk::Status(StatusResponse {
                uptime_ms: state.uptime_ms(),
                jobs_active: active,
                jobs_total: total,
            }))
        }
        RequestBody::SystemStatusGet => {
            let result = run_blocking("system_status_get", || {
                let hostname = std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let summary = rustyjack_core::services::stats::status_summary()?;
                Ok::<_, rustyjack_core::services::error::ServiceError>((hostname, summary))
            })
            .await;

            match result {
                Ok((hostname, summary)) => {
                    ResponseBody::Ok(ResponseOk::SystemStatus(SystemStatusResponse {
                        uptime_ms: state.uptime_ms(),
                        hostname,
                        status_text: Some(summary.status_text),
                        mitm_running: Some(summary.mitm_running),
                        dnsspoof_running: Some(summary.dnsspoof_running),
                    }))
                }
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::DiskUsageGet(DiskUsageRequest { path }) => {
            let path_buf = std::path::PathBuf::from(path);
            let result = run_blocking("disk_usage_get", move || {
                rustyjack_core::services::stats::disk_usage(&path_buf)
            })
            .await;

            match result {
                Ok((used, total)) => ResponseBody::Ok(ResponseOk::DiskUsage(DiskUsageResponse {
                    used_bytes: used,
                    total_bytes: total,
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::SystemReboot => {
            let result = run_blocking("system_reboot", || {
                rustyjack_core::services::system::reboot()
            })
            .await;

            match result {
                Ok(()) => ResponseBody::Ok(ResponseOk::SystemAction(SystemActionResponse {
                    action: "reboot".to_string(),
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::SystemShutdown => {
            let result = run_blocking("system_shutdown", || {
                rustyjack_core::services::system::shutdown()
            })
            .await;

            match result {
                Ok(()) => ResponseBody::Ok(ResponseOk::SystemAction(SystemActionResponse {
                    action: "shutdown".to_string(),
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::SystemSync => {
            let result = run_blocking("system_sync", || {
                rustyjack_core::services::system::sync()
            })
            .await;

            match result {
                Ok(()) => ResponseBody::Ok(ResponseOk::SystemAction(SystemActionResponse {
                    action: "sync".to_string(),
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HostnameRandomizeNow => {
            let result = run_blocking("hostname_randomize", || {
                rustyjack_core::services::system::randomize_hostname_now()
            })
            .await;

            match result {
                Ok(hostname) => ResponseBody::Ok(ResponseOk::Hostname(HostnameResponse { hostname })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::BlockDevicesList => {
            let result = task::spawn_blocking(|| rustyjack_core::services::mount::list_block_devices())
                .await;
            match result {
                Ok(Ok(devices)) => {
                    let mapped = devices
                        .into_iter()
                        .map(|dev| BlockDeviceInfo {
                            name: dev.name,
                            size: dev.size,
                            model: dev.model,
                            transport: dev.transport,
                            removable: dev.removable,
                        })
                        .collect();
                    ResponseBody::Ok(ResponseOk::BlockDevices(BlockDevicesResponse {
                        devices: mapped,
                    }))
                }
                Ok(Err(err)) => ResponseBody::Err(err.to_daemon_error()),
                Err(err) => ResponseBody::Err(
                    DaemonError::new(ErrorCode::Internal, "block devices panicked", false)
                        .with_detail(err.to_string()),
                ),
            }
        }
        RequestBody::SystemLogsGet => {
            let root = match rustyjack_core::resolve_root(None) {
                Ok(root) => root,
                Err(err) => {
                    return ResponseEnvelope {
                        v: PROTOCOL_VERSION,
                        request_id: request.request_id,
                        body: ResponseBody::Err(
                            DaemonError::new(ErrorCode::Internal, "resolve root failed", false)
                                .with_detail(err.to_string()),
                        ),
                    }
                }
            };
            let result =
                task::spawn_blocking(move || rustyjack_core::services::logs::collect_log_bundle(&root))
                    .await;
            match result {
                Ok(Ok(content)) => ResponseBody::Ok(ResponseOk::SystemLogs(SystemLogsResponse {
                    content,
                })),
                Ok(Err(err)) => ResponseBody::Err(err.to_daemon_error()),
                Err(err) => ResponseBody::Err(
                    DaemonError::new(ErrorCode::Internal, "log bundle panicked", false)
                        .with_detail(err.to_string()),
                ),
            }
        }
        RequestBody::WifiCapabilitiesGet(WifiCapabilitiesRequest { interface }) => {
            let result = run_blocking("wifi_capabilities_get", move || {
                rustyjack_core::services::wifi::capabilities(&interface)
            })
            .await;

            match result {
                Ok(caps) => ResponseBody::Ok(ResponseOk::WifiCapabilities(
                    WifiCapabilitiesResponse {
                        native_available: caps.native_available,
                        has_root: caps.has_root,
                        interface_exists: caps.interface_exists,
                        interface_is_wireless: caps.interface_is_wireless,
                        supports_monitor_mode: caps.supports_monitor_mode,
                        supports_injection: caps.supports_injection,
                    },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HotspotWarningsGet => {
            let result = run_blocking("hotspot_warnings_get", || {
                rustyjack_core::services::hotspot::warnings()
            })
            .await;

            match result {
                Ok(resp) => ResponseBody::Ok(ResponseOk::HotspotWarnings(
                    HotspotWarningsResponse {
                        last_warning: resp.last_warning,
                        last_ap_error: resp.last_ap_error,
                        last_start_error: resp.last_start_error,
                    },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HotspotDiagnosticsGet(HotspotDiagnosticsRequest { ap_interface }) => {
            let result = run_blocking("hotspot_diagnostics_get", move || {
                rustyjack_core::services::hotspot::diagnostics(&ap_interface)
            })
            .await;

            match result {
                Ok(resp) => ResponseBody::Ok(ResponseOk::HotspotDiagnostics(
                    HotspotDiagnosticsResponse {
                        regdom_raw: resp.regdom_raw,
                        regdom_valid: resp.regdom_valid,
                        rfkill: resp.rfkill,
                        ap_support: resp.ap_support,
                        allowed_channels: resp.allowed_channels,
                        last_start_error: resp.last_start_error,
                    },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HotspotClientsList => {
            let result = run_blocking("hotspot_clients_list", || {
                rustyjack_core::services::hotspot::clients()
            })
            .await;

            match result {
                Ok(resp) => ResponseBody::Ok(ResponseOk::HotspotClients(HotspotClientsResponse {
                    clients: resp.clients,
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::GpioDiagnosticsGet => {
            let result = task::spawn_blocking(|| rustyjack_core::services::logs::gpio_diagnostics())
                .await;
            match result {
                Ok(Ok(content)) => ResponseBody::Ok(ResponseOk::GpioDiagnostics(
                    GpioDiagnosticsResponse { content },
                )),
                Ok(Err(err)) => ResponseBody::Err(err.to_daemon_error()),
                Err(err) => ResponseBody::Err(
                    DaemonError::new(ErrorCode::Internal, "gpio diagnostics panicked", false)
                        .with_detail(err.to_string()),
                ),
            }
        }
        RequestBody::WifiInterfacesList => {
            let result = run_blocking("wifi_interfaces_list", || {
                rustyjack_core::services::wifi::list_interfaces()
            })
            .await;

            match result {
                Ok(interfaces) => ResponseBody::Ok(ResponseOk::WifiInterfaces(
                    rustyjack_ipc::WifiInterfacesResponse { interfaces },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::WifiDisconnect(rustyjack_ipc::WifiDisconnectRequest { interface }) => {
            if let Err(err) = validation::validate_interface_name(&interface) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }

            let iface_clone = interface.clone();
            let result = run_blocking("wifi_disconnect", move || {
                rustyjack_core::services::wifi::disconnect(&iface_clone)
            })
            .await;

            match result {
                Ok(disconnected) => ResponseBody::Ok(ResponseOk::WifiDisconnect(
                    rustyjack_ipc::WifiDisconnectResponse {
                        interface,
                        disconnected,
                    },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::WifiScanStart(rustyjack_ipc::WifiScanStartRequest {
            interface,
            timeout_ms,
        }) => {
            if let Err(err) = validation::validate_interface_name(&interface) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_timeout_ms(timeout_ms) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            let job = JobSpec {
                kind: rustyjack_ipc::JobKind::WifiScan {
                    req: rustyjack_ipc::WifiScanRequestIpc {
                        interface,
                        timeout_ms,
                    },
                },
                requested_by: Some(format!("uid={}", peer.uid)),
            };
            if !state.config.dangerous_ops_enabled && is_dangerous_job(&job.kind) {
                ResponseBody::Err(DaemonError::new(
                    ErrorCode::Forbidden,
                    "dangerous operations disabled",
                    false,
                ))
            } else {
                let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
                ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                    job_id,
                    accepted_at_ms: DaemonState::now_ms(),
                }))
            }
        }
        RequestBody::WifiConnectStart(rustyjack_ipc::WifiConnectStartRequest {
            interface,
            ssid,
            psk,
            timeout_ms,
        }) => {
            if let Err(err) = validation::validate_interface_name(&interface) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_ssid(&ssid) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_psk(&psk) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_timeout_ms(timeout_ms) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            let job = JobSpec {
                kind: rustyjack_ipc::JobKind::WifiConnect {
                    req: rustyjack_ipc::WifiConnectRequestIpc {
                        interface,
                        ssid,
                        psk,
                        timeout_ms,
                    },
                },
                requested_by: Some(format!("uid={}", peer.uid)),
            };
            if !state.config.dangerous_ops_enabled && is_dangerous_job(&job.kind) {
                ResponseBody::Err(DaemonError::new(
                    ErrorCode::Forbidden,
                    "dangerous operations disabled",
                    false,
                ))
            } else {
                let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
                ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                    job_id,
                    accepted_at_ms: DaemonState::now_ms(),
                }))
            }
        }
        RequestBody::HotspotStart(rustyjack_ipc::HotspotStartRequest {
            interface,
            ssid,
            passphrase,
            channel,
        }) => {
            if let Err(err) = validation::validate_interface_name(&interface) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_ssid(&ssid) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_psk(&passphrase) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_channel(&channel) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            let job = JobSpec {
                kind: rustyjack_ipc::JobKind::HotspotStart {
                    req: rustyjack_ipc::HotspotStartRequestIpc {
                        interface,
                        ssid,
                        passphrase,
                        channel,
                    },
                },
                requested_by: Some(format!("uid={}", peer.uid)),
            };
            if !state.config.dangerous_ops_enabled && is_dangerous_job(&job.kind) {
                ResponseBody::Err(DaemonError::new(
                    ErrorCode::Forbidden,
                    "dangerous operations disabled",
                    false,
                ))
            } else {
                let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
                ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                    job_id,
                    accepted_at_ms: DaemonState::now_ms(),
                }))
            }
        }
        RequestBody::HotspotStop => {
            let result = run_blocking("hotspot_stop", || {
                rustyjack_core::services::hotspot::stop()
            })
            .await;

            match result {
                Ok(success) => ResponseBody::Ok(ResponseOk::HotspotAction(
                    rustyjack_ipc::HotspotActionResponse {
                        action: "stop".to_string(),
                        success,
                    },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::PortalStart(rustyjack_ipc::PortalStartRequest { interface, port }) => {
            if let Err(err) = validation::validate_interface_name(&interface) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_port(port) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            let job = JobSpec {
                kind: rustyjack_ipc::JobKind::PortalStart {
                    req: rustyjack_ipc::PortalStartRequestIpc { interface, port },
                },
                requested_by: Some(format!("uid={}", peer.uid)),
            };
            if !state.config.dangerous_ops_enabled && is_dangerous_job(&job.kind) {
                ResponseBody::Err(DaemonError::new(
                    ErrorCode::Forbidden,
                    "dangerous operations disabled",
                    false,
                ))
            } else {
                let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
                ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                    job_id,
                    accepted_at_ms: DaemonState::now_ms(),
                }))
            }
        }
        RequestBody::PortalStop => {
            let result = run_blocking("portal_stop", || {
                rustyjack_core::services::portal::stop()
            })
            .await;

            match result {
                Ok(success) => ResponseBody::Ok(ResponseOk::PortalAction(
                    rustyjack_ipc::PortalActionResponse {
                        action: "stop".to_string(),
                        success,
                    },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::PortalStatus => {
            let result = run_blocking("portal_status", || {
                rustyjack_core::services::portal::status()
            })
            .await;

            match result {
                Ok(status) => {
                    let running =
                        status.get("running").and_then(|v| v.as_bool()).unwrap_or(false);
                    let interface = status
                        .get("interface")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let port = status.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);
                    ResponseBody::Ok(ResponseOk::PortalStatus(
                        rustyjack_ipc::PortalStatusResponse {
                            running,
                            interface,
                            port,
                        },
                    ))
                }
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::MountList => {
            let result = run_blocking("mount_list", || {
                rustyjack_core::services::mount::list_mounts()
            })
            .await;

            match result {
                Ok(mounts) => {
                let mapped = mounts
                    .into_iter()
                    .map(|m| rustyjack_ipc::MountInfo {
                        device: m.device,
                        mountpoint: m.mountpoint,
                        filesystem: m.filesystem,
                        size: m.size,
                    })
                    .collect();
                ResponseBody::Ok(ResponseOk::MountList(rustyjack_ipc::MountListResponse {
                    mounts: mapped,
                }))
            }
            Err(err) => ResponseBody::Err(err),
        }
        RequestBody::MountStart(rustyjack_ipc::MountStartRequest { device, filesystem }) => {
            if let Err(err) = validation::validate_mount_device_hint(&device) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if let Err(err) = validation::validate_filesystem(&filesystem) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            let job = JobSpec {
                kind: rustyjack_ipc::JobKind::MountStart {
                    req: rustyjack_ipc::MountStartRequestIpc { device, filesystem },
                },
                requested_by: Some(format!("uid={}", peer.uid)),
            };
            if !state.config.dangerous_ops_enabled && is_dangerous_job(&job.kind) {
                ResponseBody::Err(DaemonError::new(
                    ErrorCode::Forbidden,
                    "dangerous operations disabled",
                    false,
                ))
            } else {
                let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
                ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                    job_id,
                    accepted_at_ms: DaemonState::now_ms(),
                }))
            }
        }
        RequestBody::UnmountStart(rustyjack_ipc::UnmountStartRequest { device }) => {
            if let Err(err) = validation::validate_mount_device_hint(&device) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            let job = JobSpec {
                kind: rustyjack_ipc::JobKind::UnmountStart {
                    req: rustyjack_ipc::UnmountStartRequestIpc { device },
                },
                requested_by: Some(format!("uid={}", peer.uid)),
            };
            if !state.config.dangerous_ops_enabled && is_dangerous_job(&job.kind) {
                ResponseBody::Err(DaemonError::new(
                    ErrorCode::Forbidden,
                    "dangerous operations disabled",
                    false,
                ))
            } else {
                let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
                ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                    job_id,
                    accepted_at_ms: DaemonState::now_ms(),
                }))
            }
        }
        RequestBody::CoreDispatch(CoreDispatchRequest { legacy, args }) => {
            if !state.config.allow_core_dispatch {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(DaemonError::new(
                        ErrorCode::NotImplemented,
                        "CoreDispatch is disabled",
                        false,
                    )),
                };
            }

            let command_str = format!("{:?}", legacy);
            let _ = args;
            
            ResponseBody::Err(DaemonError::new(
                ErrorCode::NotImplemented,
                &format!("Legacy command {} should be migrated to explicit endpoint", command_str),
                false,
            ))
        }
        RequestBody::JobStart(JobStartRequest { job }) => {
            if let Err(err) = validation::validate_job_kind(&job.kind) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            if !state.config.dangerous_ops_enabled && is_dangerous_job(&job.kind) {
                ResponseBody::Err(DaemonError::new(
                    ErrorCode::Forbidden,
                    "dangerous operations disabled",
                    false,
                ))
            } else {
                let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
                ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                    job_id,
                    accepted_at_ms: DaemonState::now_ms(),
                }))
            }
        }
        RequestBody::JobStatus(JobStatusRequest { job_id }) => {
            match state.jobs.job_status(job_id).await {
                Some(job) => ResponseBody::Ok(ResponseOk::JobStatus(JobStatusResponse { job })),
                None => ResponseBody::Err(DaemonError::new(
                    ErrorCode::NotFound,
                    "job not found",
                    false,
                )),
            }
        }
        RequestBody::JobCancel(JobCancelRequest { job_id }) => {
            let cancelled = state.jobs.cancel_job(job_id).await;
            let response = JobCancelResponse { job_id, cancelled };
            ResponseBody::Ok(ResponseOk::JobCancelled(response))
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    log_request(
        request.request_id,
        request.endpoint,
        peer,
        duration_ms,
        &response_body,
    );

    ResponseEnvelope {
        v: PROTOCOL_VERSION,
        request_id: request.request_id,
        body: response_body,
    }
}
