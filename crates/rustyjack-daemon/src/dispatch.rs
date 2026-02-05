use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use rustyjack_ipc::{
    ActiveInterfaceClearResponse, ActiveInterfaceResponse, BlockDeviceInfo, BlockDevicesResponse,
    CoreDispatchResponse, DaemonError, DiskUsageRequest, DiskUsageResponse, ErrorCode,
    GpioDiagnosticsResponse, HealthResponse, HostnameResponse, HotspotClientsResponse,
    HotspotDiagnosticsRequest, HotspotDiagnosticsResponse, HotspotWarningsResponse,
    InterfaceCapabilities, InterfaceStatusRequest, InterfaceStatusResponse, JobCancelRequest,
    JobCancelResponse, JobSpec, JobStartRequest, JobStarted, JobStatusRequest, JobStatusResponse,
    LogComponent, LogLevel, OpsStatus, RequestBody, RequestEnvelope, ResponseBody,
    ResponseEnvelope, ResponseOk, StatusResponse, SystemActionResponse, SystemLogsResponse,
    SystemStatusResponse, VersionResponse, WifiCapabilitiesRequest, WifiCapabilitiesResponse,
    PROTOCOL_VERSION,
};

#[cfg(feature = "core_dispatch")]
use rustyjack_ipc::{CoreDispatchRequest, LegacyCommand};
use tokio::task;

use crate::auth::PeerCred;
use crate::ops_apply::{apply_ops_delta, write_ops_override};
use crate::state::DaemonState;
use crate::telemetry::log_request;
use crate::validation;
use rustyjack_updater::{apply_update, UpdatePolicy};

async fn run_blocking<T, E, F>(label: &'static str, f: F) -> Result<T, DaemonError>
where
    T: Send + 'static,
    E: Into<DaemonError> + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    task::spawn_blocking(f)
        .await
        .map_err(|e| {
            DaemonError::new(ErrorCode::Internal, format!("{} panicked", label), false)
                .with_detail(e.to_string())
                .with_source(format!("daemon.dispatch.{}", label))
        })?
        .map_err(|e| e.into())
}

const MAX_LOG_TAIL_LINES: usize = 5000;
const MAX_LOG_TAIL_BYTES: usize = 1024 * 1024;

fn log_path_for(root: &PathBuf, component: &LogComponent) -> PathBuf {
    match component {
        LogComponent::Rustyjackd => root.join("logs").join("rustyjackd.log"),
        LogComponent::RustyjackUi => root.join("logs").join("rustyjack-ui.log"),
        LogComponent::Portal => root.join("logs").join("portal.log"),
        LogComponent::Usb => root.join("logs").join("usb.log"),
        LogComponent::Wifi => root.join("logs").join("wifi.log"),
        LogComponent::Net => root.join("logs").join("net.log"),
        LogComponent::Crypto => root.join("logs").join("crypto.log"),
        LogComponent::Audit => root.join("logs").join("audit").join("audit.log"),
    }
}

fn normalize_log_level(value: &str) -> LogLevel {
    value.parse().unwrap_or(LogLevel::Info)
}

fn update_policy_for(config: &crate::config::DaemonConfig) -> Result<UpdatePolicy, DaemonError> {
    let public_key = config.update_pubkey.ok_or_else(|| {
        DaemonError::new(
            ErrorCode::Internal,
            "update public key not configured",
            false,
        )
        .with_detail(format!(
            "missing or invalid {}",
            config.update_pubkey_path.display()
        ))
    })?;

    Ok(UpdatePolicy {
        public_key_ed25519: public_key,
        stage_dir: config.root_path.join("update").join("stage"),
        install_dir: PathBuf::from("/usr/local/bin"),
        unit_restart: "rustyjackd.service".to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceKind {
    Wired,
    Wireless,
}

fn classify_interface_kind(interface: &str) -> Result<InterfaceKind, DaemonError> {
    let list = rustyjack_core::system::list_interface_summaries().map_err(|err| {
        DaemonError::new(ErrorCode::Netlink, "failed to list interfaces", false)
            .with_detail(err.to_string())
            .with_source("daemon.dispatch.interface_kind")
    })?;
    let Some(entry) = list.into_iter().find(|item| item.name == interface) else {
        return Err(
            DaemonError::new(ErrorCode::NotFound, "interface not found", false)
                .with_detail(interface.to_string())
                .with_source("daemon.dispatch.interface_kind"),
        );
    };
    if entry.is_wireless {
        Ok(InterfaceKind::Wireless)
    } else {
        Ok(InterfaceKind::Wired)
    }
}

async fn dispatch_core_command(
    label: &'static str,
    root: PathBuf,
    command: rustyjack_core::Commands,
) -> Result<CoreDispatchResponse, DaemonError> {
    let result = run_blocking(label, move || {
        rustyjack_core::operations::dispatch_command(&root, command).map_err(|err| {
            let msg = err.to_string();
            let code = if msg.contains("mount") || msg.contains("filesystem not allowed") {
                ErrorCode::MountFailed
            } else if msg.contains("WiFi") || msg.contains("wifi") {
                ErrorCode::WifiFailed
            } else {
                ErrorCode::Internal
            };
            DaemonError::new(code, msg, false).with_source(format!("daemon.dispatch.{label}"))
        })
    })
    .await?;

    Ok(CoreDispatchResponse {
        message: result.0,
        data: result.1,
    })
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
            let ops_cfg = state.ops_runtime.read().await;
            let ops = OpsStatus {
                wifi_ops: ops_cfg.wifi_ops,
                eth_ops: ops_cfg.eth_ops,
                hotspot_ops: ops_cfg.hotspot_ops,
                portal_ops: ops_cfg.portal_ops,
                storage_ops: ops_cfg.storage_ops,
                power_ops: ops_cfg.power_ops,
                system_ops: ops_cfg.system_ops,
                update_ops: ops_cfg.update_ops,
                dev_ops: ops_cfg.dev_ops,
                offensive_ops: ops_cfg.offensive_ops,
                loot_ops: ops_cfg.loot_ops,
                process_ops: ops_cfg.process_ops,
            };
            ResponseBody::Ok(ResponseOk::Status(StatusResponse {
                uptime_ms: state.uptime_ms(),
                jobs_active: active,
                jobs_total: total,
                ops,
            }))
        }
        RequestBody::OpsConfigGet => {
            let ops = *state.ops_runtime.read().await;
            ResponseBody::Ok(ResponseOk::OpsConfig(ops))
        }
        RequestBody::OpsConfigSet(next_ops) => {
            let previous = *state.ops_runtime.read().await;
            {
                let mut ops = state.ops_runtime.write().await;
                *ops = next_ops;
            }

            if let Err(err) = write_ops_override(&state.config.root_path, next_ops) {
                let mut daemon_err =
                    DaemonError::new(ErrorCode::Internal, "failed to persist ops config", false);
                daemon_err = daemon_err
                    .with_detail(err.to_string())
                    .with_source("daemon.dispatch.ops_config_set");
                ResponseBody::Err(daemon_err)
            } else if let Err(err) = apply_ops_delta(previous, next_ops, state).await {
                let mut daemon_err =
                    DaemonError::new(ErrorCode::Internal, "failed to apply ops changes", false);
                daemon_err = daemon_err
                    .with_detail(err.to_string())
                    .with_source("daemon.dispatch.ops_config_set");
                ResponseBody::Err(daemon_err)
            } else {
                ResponseBody::Ok(ResponseOk::OpsConfigSetAck { ops: next_ops })
            }
        }
        RequestBody::StatusCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "status_command",
                root,
                rustyjack_core::Commands::Status(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::StatusCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::WifiCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "wifi_command",
                root,
                rustyjack_core::Commands::Wifi(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::WifiCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::EthernetCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "ethernet_command",
                root,
                rustyjack_core::Commands::Ethernet(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::EthernetCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::LootCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "loot_command",
                root,
                rustyjack_core::Commands::Loot(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::LootCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::NotifyCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "notify_command",
                root,
                rustyjack_core::Commands::Notify(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::NotifyCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::SystemCommand(command) => match command {
            rustyjack_ipc::SystemCommand::Update(args) => {
                let url = args.url.trim();
                if let Err(err) = validation::validate_update_url(url) {
                    ResponseBody::Err(err)
                } else {
                    let policy = match update_policy_for(&state.config) {
                        Ok(policy) => policy,
                        Err(err) => {
                            return ResponseEnvelope {
                                v: PROTOCOL_VERSION,
                                request_id: request.request_id,
                                body: ResponseBody::Err(err),
                            };
                        }
                    };
                    match apply_update(&policy, url).await {
                        Ok(()) => {
                            ResponseBody::Ok(ResponseOk::SystemCommand(CoreDispatchResponse {
                                message: "Update applied".to_string(),
                                data: serde_json::json!({ "status": "applied" }),
                            }))
                        }
                        Err(err) => ResponseBody::Err(
                            DaemonError::new(ErrorCode::UpdateFailed, "update failed", false)
                                .with_detail(err.to_string()),
                        ),
                    }
                }
            }
            _ => {
                let root = state.config.root_path.clone();
                match dispatch_core_command(
                    "system_command",
                    root,
                    rustyjack_core::Commands::System(command),
                )
                .await
                {
                    Ok(resp) => ResponseBody::Ok(ResponseOk::SystemCommand(resp)),
                    Err(err) => ResponseBody::Err(err),
                }
            }
        },
        RequestBody::HardwareCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "hardware_command",
                root,
                rustyjack_core::Commands::Hardware(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::HardwareCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::DnsSpoofCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "dnsspoof_command",
                root,
                rustyjack_core::Commands::DnsSpoof(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::DnsSpoofCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::MitmCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "mitm_command",
                root,
                rustyjack_core::Commands::Mitm(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::MitmCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::ReverseCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "reverse_command",
                root,
                rustyjack_core::Commands::Reverse(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::ReverseCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HotspotCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "hotspot_command",
                root,
                rustyjack_core::Commands::Hotspot(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::HotspotCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::ScanCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "scan_command",
                root,
                rustyjack_core::Commands::Scan(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::ScanCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::BridgeCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "bridge_command",
                root,
                rustyjack_core::Commands::Bridge(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::BridgeCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        #[cfg(feature = "process_ops")]
        RequestBody::ProcessCommand(command) => {
            let root = state.config.root_path.clone();
            match dispatch_core_command(
                "process_command",
                root,
                rustyjack_core::Commands::Process(command),
            )
            .await
            {
                Ok(resp) => ResponseBody::Ok(ResponseOk::ProcessCommand(resp)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        #[cfg(not(feature = "process_ops"))]
        RequestBody::ProcessCommand(_) => ResponseBody::Err(DaemonError::new(
            ErrorCode::Forbidden,
            "Process command disabled in this build",
            false,
        )),
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
            use rustyjack_core::audit::{operations, AuditEvent};

            let root = state.config.root_path.clone();
            let uid = peer.uid;
            let pid = peer.pid;

            let result = run_blocking("system_reboot", || {
                rustyjack_core::services::system::reboot()
            })
            .await;

            // Audit the operation
            let event = match &result {
                Ok(()) => AuditEvent::new(operations::SYSTEM_REBOOT)
                    .with_actor(uid, pid)
                    .success(),
                Err(err) => AuditEvent::new(operations::SYSTEM_REBOOT)
                    .with_actor(uid, pid)
                    .failure(err.message.clone()),
            };
            let _ = event.log(&root);

            match result {
                Ok(()) => ResponseBody::Ok(ResponseOk::SystemAction(SystemActionResponse {
                    action: "reboot".to_string(),
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::SystemShutdown => {
            use rustyjack_core::audit::{operations, AuditEvent};

            let root = state.config.root_path.clone();
            let uid = peer.uid;
            let pid = peer.pid;

            let result = run_blocking("system_shutdown", || {
                rustyjack_core::services::system::shutdown()
            })
            .await;

            // Audit the operation
            let event = match &result {
                Ok(()) => AuditEvent::new(operations::SYSTEM_SHUTDOWN)
                    .with_actor(uid, pid)
                    .success(),
                Err(err) => AuditEvent::new(operations::SYSTEM_SHUTDOWN)
                    .with_actor(uid, pid)
                    .failure(err.message.clone()),
            };
            let _ = event.log(&root);

            match result {
                Ok(()) => ResponseBody::Ok(ResponseOk::SystemAction(SystemActionResponse {
                    action: "shutdown".to_string(),
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::SystemSync => {
            let result =
                run_blocking("system_sync", || rustyjack_core::services::system::sync()).await;

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
                Ok(hostname) => {
                    ResponseBody::Ok(ResponseOk::Hostname(HostnameResponse { hostname }))
                }
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::BlockDevicesList => {
            let result =
                task::spawn_blocking(|| rustyjack_core::services::mount::list_block_devices())
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
                            is_partition: dev.is_partition,
                            parent: dev.parent,
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
            let result = task::spawn_blocking(move || {
                rustyjack_core::services::logs::collect_log_bundle(&root)
            })
            .await;
            match result {
                Ok(Ok(content)) => {
                    ResponseBody::Ok(ResponseOk::SystemLogs(SystemLogsResponse { content }))
                }
                Ok(Err(err)) => ResponseBody::Err(err.to_daemon_error()),
                Err(err) => ResponseBody::Err(
                    DaemonError::new(ErrorCode::Internal, "log bundle panicked", false)
                        .with_detail(err.to_string()),
                ),
            }
        }
        RequestBody::ActiveInterfaceGet => {
            let root = state.config.root_path.clone();
            let result = run_blocking("active_interface_get", move || {
                let prefs = rustyjack_core::system::PreferenceManager::new(root);
                prefs.get_preferred().map_err(|err| {
                    rustyjack_core::services::error::ServiceError::Internal(err.to_string())
                })
            })
            .await;

            match result {
                Ok(interface) => {
                    ResponseBody::Ok(ResponseOk::ActiveInterface(ActiveInterfaceResponse {
                        interface,
                    }))
                }
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::ActiveInterfaceClear => {
            let root = state.config.root_path.clone();
            let result = run_blocking("active_interface_clear", move || {
                let prefs = rustyjack_core::system::PreferenceManager::new(root);
                prefs.clear_preferred().map_err(|err| {
                    rustyjack_core::services::error::ServiceError::Internal(err.to_string())
                })
            })
            .await;

            match result {
                Ok(()) => ResponseBody::Ok(ResponseOk::ActiveInterfaceCleared(
                    ActiveInterfaceClearResponse { cleared: true },
                )),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::InterfaceStatusGet(InterfaceStatusRequest { interface }) => {
            let result = run_blocking("interface_status_get", move || {
                use rustyjack_core::services::error::ServiceError;
                use rustyjack_core::system::ops::{NetOps, RealNetOps};
                use std::fs;
                use std::path::Path;

                let iface = interface.trim();
                if iface.is_empty() {
                    return Err(ServiceError::InvalidInput("interface".to_string()));
                }

                let sys_path = Path::new("/sys/class/net").join(iface);
                let exists = sys_path.exists();
                if !exists {
                    return Ok(InterfaceStatusResponse {
                        interface: iface.to_string(),
                        exists,
                        is_wireless: false,
                        oper_state: "missing".to_string(),
                        is_up: false,
                        carrier: None,
                        ip: None,
                        capabilities: None,
                    });
                }

                let oper_state = fs::read_to_string(sys_path.join("operstate"))
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();

                // RC5: Report admin-up (IFF_UP flag) instead of operstate
                // Admin-up is what we set with netlink, operstate is derived policy
                // An interface can be admin-UP but operstate "down" when disconnected
                let is_up = if let Ok(flags_hex) = fs::read_to_string(sys_path.join("flags")) {
                    if let Ok(flags) =
                        u32::from_str_radix(flags_hex.trim().trim_start_matches("0x"), 16)
                    {
                        (flags & 0x1) != 0 // IFF_UP is bit 0
                    } else {
                        oper_state == "up" // fallback to operstate
                    }
                } else {
                    oper_state == "up" // fallback to operstate
                };
                let carrier = fs::read_to_string(sys_path.join("carrier"))
                    .ok()
                    .and_then(|val| match val.trim() {
                        "0" => Some(false),
                        "1" => Some(true),
                        _ => None,
                    });
                let is_wireless = sys_path.join("wireless").exists();

                let ops = RealNetOps;
                let ip = ops
                    .get_ipv4_address(iface)
                    .ok()
                    .flatten()
                    .map(|addr| addr.to_string());

                let capabilities =
                    ops.get_interface_capabilities(iface)
                        .ok()
                        .map(|caps| {
                            // Convert TxInMonitorCapability to IPC type
                            let tx_cap = match caps.tx_in_monitor {
                                rustyjack_core::system::ops::TxInMonitorCapability::Supported => {
                                    Some(rustyjack_ipc::types::TxInMonitorCapability::Supported)
                                }
                                rustyjack_core::system::ops::TxInMonitorCapability::NotSupported => {
                                    Some(rustyjack_ipc::types::TxInMonitorCapability::NotSupported)
                                }
                                rustyjack_core::system::ops::TxInMonitorCapability::Unknown => {
                                    Some(rustyjack_ipc::types::TxInMonitorCapability::Unknown)
                                }
                            };
                            InterfaceCapabilities {
                                is_wireless: caps.is_wireless,
                                is_physical: caps.is_physical,
                                supports_monitor: caps.supports_monitor,
                                supports_ap: caps.supports_ap,
                                supports_injection: caps.supports_injection,
                                supports_5ghz: caps.supports_5ghz,
                                supports_2ghz: caps.supports_2ghz,
                                mac_address: caps.mac_address,
                                driver: caps.driver,
                                chipset: caps.chipset,
                                tx_in_monitor: tx_cap,
                                tx_in_monitor_reason: Some(caps.tx_in_monitor_reason),
                            }
                        });

                Ok(InterfaceStatusResponse {
                    interface: iface.to_string(),
                    exists,
                    is_wireless,
                    oper_state,
                    is_up,
                    carrier,
                    ip,
                    capabilities,
                })
            })
            .await;

            match result {
                Ok(status) => ResponseBody::Ok(ResponseOk::InterfaceStatus(status)),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::WifiCapabilitiesGet(WifiCapabilitiesRequest { interface }) => {
            let result = run_blocking("wifi_capabilities_get", move || {
                rustyjack_core::services::wifi::capabilities(&interface)
            })
            .await;

            match result {
                Ok(caps) => {
                    // Convert TxInMonitorCapability to IPC type
                    let tx_cap = match caps.tx_in_monitor {
                        rustyjack_core::wireless_native::TxInMonitorCapability::Supported => {
                            Some(rustyjack_ipc::types::TxInMonitorCapability::Supported)
                        }
                        rustyjack_core::wireless_native::TxInMonitorCapability::NotSupported => {
                            Some(rustyjack_ipc::types::TxInMonitorCapability::NotSupported)
                        }
                        rustyjack_core::wireless_native::TxInMonitorCapability::Unknown => {
                            Some(rustyjack_ipc::types::TxInMonitorCapability::Unknown)
                        }
                    };
                    // Legacy supports_injection derived from tx_in_monitor
                    let supports_injection = matches!(
                        caps.tx_in_monitor,
                        rustyjack_core::wireless_native::TxInMonitorCapability::Supported
                    );
                    ResponseBody::Ok(ResponseOk::WifiCapabilities(WifiCapabilitiesResponse {
                        native_available: caps.native_available,
                        has_root: caps.has_root,
                        interface_exists: caps.interface_exists,
                        interface_is_wireless: caps.interface_is_wireless,
                        supports_monitor_mode: caps.supports_monitor_mode,
                        supports_injection,
                        tx_in_monitor: tx_cap,
                        tx_in_monitor_reason: Some(caps.tx_in_monitor_reason),
                        driver_name: caps.driver_name,
                        supports_ap: caps.supports_ap,
                    }))
                }
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HotspotWarningsGet => {
            let result = run_blocking("hotspot_warnings_get", || {
                rustyjack_core::services::hotspot::warnings()
            })
            .await;

            match result {
                Ok(resp) => {
                    ResponseBody::Ok(ResponseOk::HotspotWarnings(HotspotWarningsResponse {
                        last_warning: resp.last_warning,
                        last_ap_error: resp.last_ap_error,
                        last_start_error: resp.last_start_error,
                    }))
                }
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HotspotDiagnosticsGet(HotspotDiagnosticsRequest { ap_interface }) => {
            let result = run_blocking("hotspot_diagnostics_get", move || {
                rustyjack_core::services::hotspot::diagnostics(&ap_interface)
            })
            .await;

            match result {
                Ok(resp) => {
                    ResponseBody::Ok(ResponseOk::HotspotDiagnostics(HotspotDiagnosticsResponse {
                        regdom_raw: resp.regdom_raw,
                        regdom_valid: resp.regdom_valid,
                        rfkill: resp.rfkill,
                        ap_support: resp.ap_support,
                        allowed_channels: resp.allowed_channels,
                        last_start_error: resp.last_start_error,
                    }))
                }
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
            let result =
                task::spawn_blocking(|| rustyjack_core::services::logs::gpio_diagnostics()).await;
            match result {
                Ok(Ok(content)) => {
                    ResponseBody::Ok(ResponseOk::GpioDiagnostics(GpioDiagnosticsResponse {
                        content,
                    }))
                }
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
            let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
            ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                job_id,
                accepted_at_ms: DaemonState::now_ms(),
            }))
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
            let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
            ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                job_id,
                accepted_at_ms: DaemonState::now_ms(),
            }))
        }
        RequestBody::HotspotStart(rustyjack_ipc::HotspotStartRequest {
            interface,
            upstream_interface,
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
            if !upstream_interface.is_empty() {
                if let Err(err) = validation::validate_interface_name(&upstream_interface) {
                    return ResponseEnvelope {
                        v: PROTOCOL_VERSION,
                        request_id: request.request_id,
                        body: ResponseBody::Err(err),
                    };
                }
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
                        upstream_interface,
                        ssid,
                        passphrase,
                        channel,
                    },
                },
                requested_by: Some(format!("uid={}", peer.uid)),
            };
            let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
            ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                job_id,
                accepted_at_ms: DaemonState::now_ms(),
            }))
        }
        RequestBody::HotspotStop => {
            let result =
                run_blocking("hotspot_stop", || rustyjack_core::services::hotspot::stop()).await;

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
            let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
            ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                job_id,
                accepted_at_ms: DaemonState::now_ms(),
            }))
        }
        RequestBody::PortalStop => {
            let result =
                run_blocking("portal_stop", || rustyjack_core::services::portal::stop()).await;

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
                    let running = status
                        .get("running")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let interface = status
                        .get("interface")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let port = status
                        .get("port")
                        .and_then(|v| v.as_u64())
                        .map(|p| p as u16);
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
            let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
            ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                job_id,
                accepted_at_ms: DaemonState::now_ms(),
            }))
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
            let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
            ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                job_id,
                accepted_at_ms: DaemonState::now_ms(),
            }))
        }
        RequestBody::SetActiveInterface(rustyjack_ipc::SetActiveInterfaceRequest { interface }) => {
            let ops = state.ops_runtime.read().await;
            let allow_wifi = ops.wifi_ops;
            let allow_eth = ops.eth_ops;
            drop(ops);

            match classify_interface_kind(&interface) {
                Ok(InterfaceKind::Wireless) if !allow_wifi => {
                    return ResponseEnvelope {
                        v: PROTOCOL_VERSION,
                        request_id: request.request_id,
                        body: ResponseBody::Err(DaemonError::new(
                            ErrorCode::Forbidden,
                            "wifi ops disabled",
                            false,
                        )),
                    };
                }
                Ok(InterfaceKind::Wired) if !allow_eth => {
                    return ResponseEnvelope {
                        v: PROTOCOL_VERSION,
                        request_id: request.request_id,
                        body: ResponseBody::Err(DaemonError::new(
                            ErrorCode::Forbidden,
                            "ethernet ops disabled",
                            false,
                        )),
                    };
                }
                Err(err) => {
                    return ResponseEnvelope {
                        v: PROTOCOL_VERSION,
                        request_id: request.request_id,
                        body: ResponseBody::Err(err),
                    };
                }
                _ => {}
            }

            let root = state.config.root_path.clone();
            let iface = interface.clone();
            let result = run_blocking("set_active_interface", move || {
                rustyjack_core::operations::set_active_interface(&root, &iface).map_err(|e| {
                    // Extract the root cause for a clean user-facing message
                    let root_cause = e.root_cause().to_string();
                    let full_chain = format!("{:#}", e);
                    DaemonError::new(
                        ErrorCode::Internal,
                        format!("Failed to set interface '{}': {}", iface, root_cause),
                        false,
                    )
                    .with_detail(full_chain)
                    .with_source("set_active_interface")
                })
            })
            .await;

            match result {
                Ok(outcome) => {
                    let errors: Vec<String> = outcome
                        .errors
                        .iter()
                        .map(|e| format!("{}: {}", e.interface, e.message))
                        .collect();
                    ResponseBody::Ok(ResponseOk::SetActiveInterface(
                        rustyjack_ipc::SetActiveInterfaceResponse {
                            interface,
                            allowed: outcome.allowed,
                            blocked: outcome.blocked,
                            errors,
                        },
                    ))
                }
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::HotplugNotify => {
            let root = state.config.root_path.clone();
            tokio::spawn(async move {
                // Increased delay for USB WiFi driver loading (2 seconds)
                tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
                tokio::task::spawn_blocking(move || {
                    use rustyjack_core::system::{IsolationEngine, RealNetOps};
                    use std::sync::Arc;

                    let ops = Arc::new(RealNetOps);
                    let engine = IsolationEngine::new(ops, root);

                    match engine.enforce() {
                        Ok(outcome) => {
                            tracing::info!(
                                "Hotplug enforcement: allowed={:?}, blocked={:?}, errors={}",
                                outcome.allowed,
                                outcome.blocked,
                                outcome.errors.len()
                            );
                            if !outcome.errors.is_empty() {
                                for err in &outcome.errors {
                                    tracing::warn!(
                                        "Hotplug error on {}: {}",
                                        err.interface,
                                        err.message
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Hotplug enforcement failed: {}", e);
                        }
                    }
                })
                .await
                .ok();
            });
            ResponseBody::Ok(ResponseOk::HotplugNotify(
                rustyjack_ipc::HotplugNotifyResponse { acknowledged: true },
            ))
        }
        RequestBody::LogTailGet(rustyjack_ipc::LogTailRequest {
            component,
            max_lines,
        }) => {
            use rustyjack_ipc::LogTailResponse;

            let root = state.config.root_path.clone();
            let max_lines = max_lines.unwrap_or(500).clamp(1, MAX_LOG_TAIL_LINES);
            let component_clone = component.clone();

            let result = run_blocking("log_tail", move || {
                let log_path = log_path_for(&root, &component_clone);

                if !log_path.exists() {
                    return Ok((Vec::new(), false));
                }
                let (content, truncated) = crate::tail::tail_lines_with_truncation(
                    &log_path,
                    max_lines,
                    MAX_LOG_TAIL_BYTES,
                )
                .map_err(|e| {
                    DaemonError::new(ErrorCode::Io, "failed to tail log file", false)
                        .with_detail(e.to_string())
                })?;
                let lines = content.lines().map(|line| line.to_string()).collect();

                Ok::<(Vec<String>, bool), DaemonError>((lines, truncated))
            })
            .await;

            match result {
                Ok((lines, truncated)) => ResponseBody::Ok(ResponseOk::LogTail(LogTailResponse {
                    component,
                    lines,
                    truncated,
                })),
                Err(err) => ResponseBody::Err(err),
            }
        }
        RequestBody::LoggingConfigGet => {
            use rustyjack_ipc::LoggingConfigResponse;

            let cfg = rustyjack_logging::fs::read_config(&state.config.root_path);
            let components = vec![
                "rustyjackd".to_string(),
                "rustyjack-ui".to_string(),
                "portal".to_string(),
            ];

            ResponseBody::Ok(ResponseOk::LoggingConfig(LoggingConfigResponse {
                enabled: cfg.enabled,
                level: normalize_log_level(&cfg.level),
                components,
            }))
        }
        RequestBody::LoggingConfigSet(rustyjack_ipc::LoggingConfigSetRequest {
            enabled,
            level,
        }) => {
            use rustyjack_core::audit::{operations, AuditEvent};
            use rustyjack_ipc::LoggingConfigSetResponse;

            let root = state.config.root_path.clone();
            let uid = peer.uid;
            let pid = peer.pid;

            let mut cfg = rustyjack_logging::fs::read_config(&root);
            cfg.enabled = enabled;
            if let Some(new_level) = level.as_ref() {
                cfg.level = new_level.as_str().to_string();
            }
            if let Err(err) = rustyjack_logging::fs::write_config_atomic(&root, &cfg) {
                ResponseBody::Err(
                    DaemonError::new(ErrorCode::Io, "failed to write logging config", false)
                        .with_detail(err.to_string()),
                )
            } else {
                // Audit the configuration change
                let context = serde_json::json!({
                    "enabled": cfg.enabled,
                    "level": cfg.level.as_str(),
                    "keep_days": cfg.keep_days
                });

                let event = AuditEvent::new(operations::LOGGING_CONFIG_CHANGE)
                    .with_actor(uid, pid)
                    .with_context(context)
                    .success();

                let _ = event.log(&root);

                let applied = match rustyjack_logging::apply(&cfg, "rustyjackd") {
                    Ok(()) => true,
                    Err(err) => {
                        tracing::warn!("Failed to apply logging config: {}", err);
                        false
                    }
                };
                rustyjack_logging::apply_env(&cfg);
                tracing::info!(
                    operation = "logging_config_set",
                    enabled = cfg.enabled,
                    level = %cfg.level,
                    "Logging configuration updated"
                );

                ResponseBody::Ok(ResponseOk::LoggingConfigSet(LoggingConfigSetResponse {
                    enabled: cfg.enabled,
                    level: normalize_log_level(&cfg.level),
                    applied,
                }))
            }
        }
        #[cfg(feature = "core_dispatch")]
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

            match legacy {
                LegacyCommand::CommandDispatch => {
                    let root = state.config.root_path.clone();
                    let result = run_blocking("core_dispatch", move || {
                        let command: rustyjack_core::Commands = serde_json::from_value(args)
                            .map_err(|err| {
                                DaemonError::new(
                                    ErrorCode::BadRequest,
                                    "invalid command payload",
                                    false,
                                )
                                .with_detail(err.to_string())
                            })?;
                        rustyjack_core::operations::dispatch_command(&root, command).map_err(
                            |err| {
                                DaemonError::new(ErrorCode::Internal, "core dispatch failed", false)
                                    .with_detail(err.to_string())
                            },
                        )
                    })
                    .await;

                    match result {
                        Ok((message, data)) => {
                            ResponseBody::Ok(ResponseOk::CoreDispatch(CoreDispatchResponse {
                                message,
                                data,
                            }))
                        }
                        Err(err) => ResponseBody::Err(err),
                    }
                }
                _ => ResponseBody::Err(DaemonError::new(
                    ErrorCode::NotImplemented,
                    "legacy command not supported",
                    false,
                )),
            }
        }
        #[cfg(not(feature = "core_dispatch"))]
        RequestBody::CoreDispatch(_) => ResponseBody::Err(DaemonError::new(
            ErrorCode::NotImplemented,
            "CoreDispatch is disabled",
            false,
        )),
        RequestBody::JobStart(JobStartRequest { job }) => {
            if let Err(err) = validation::validate_job_kind(&job.kind) {
                return ResponseEnvelope {
                    v: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    body: ResponseBody::Err(err),
                };
            }
            let job_id = state.jobs.start_job(job, Arc::clone(state)).await;
            ResponseBody::Ok(ResponseOk::JobStarted(JobStarted {
                job_id,
                accepted_at_ms: DaemonState::now_ms(),
            }))
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
