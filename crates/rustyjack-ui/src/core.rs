use std::env;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustyjack_client::{ClientConfig, DaemonClient};
use rustyjack_commands::Commands;
use rustyjack_ipc::{
    BlockDeviceInfo, HotspotClient, HotspotDiagnosticsResponse, HotspotWarningsResponse,
    InterfaceStatusResponse, JobId, JobInfo, JobKind, JobState, OpsConfig, StatusResponse,
    UpdateRequestIpc, WifiCapabilitiesResponse,
};
use serde_json::Value;
use tokio::runtime::{Handle, Runtime};
use tokio::time::sleep;

/// Cached tokio runtime for the UI process.
/// Using OnceLock ensures the runtime is created exactly once and reused for all
/// daemon client calls, avoiding the overhead of creating a new runtime per call.
static UI_RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub type HandlerResult = (String, Value);

/// TX-in-monitor capability verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxInMonitorCapability {
    Supported,
    NotSupported,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct InterfaceCapabilities {
    pub name: String,
    pub is_wireless: bool,
    pub is_physical: bool,
    pub supports_monitor: bool,
    pub supports_ap: bool,
    /// Legacy field - use tx_in_monitor for accurate detection
    pub supports_injection: bool,
    pub supports_5ghz: bool,
    pub supports_2ghz: bool,
    pub mac_address: Option<String>,
    pub driver: Option<String>,
    pub chipset: Option<String>,
    /// TX-in-monitor capability with accurate driver-based detection
    pub tx_in_monitor: TxInMonitorCapability,
    /// Human-readable reason for tx_in_monitor verdict
    pub tx_in_monitor_reason: String,
}

impl InterfaceCapabilities {
    /// Check if the interface can perform TX-in-monitor operations (injection)
    pub fn is_injection_capable(&self) -> bool {
        matches!(self.tx_in_monitor, TxInMonitorCapability::Supported)
    }

    /// Check if injection capability is unknown (may or may not work)
    pub fn is_injection_unknown(&self) -> bool {
        matches!(self.tx_in_monitor, TxInMonitorCapability::Unknown)
    }
}

#[derive(Clone)]
pub struct CoreBridge {
    root: PathBuf,
}

impl CoreBridge {
    pub fn with_root(root: Option<PathBuf>) -> Result<Self> {
        let resolved = resolve_root(root)?;
        Ok(Self { root: resolved })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    async fn create_client(&self) -> Result<DaemonClient> {
        let config = ClientConfig {
            socket_path: daemon_socket_path(),
            client_name: "rustyjack-ui".to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            long_request_timeout: Duration::from_secs(300),
            ..Default::default()
        };
        DaemonClient::connect_with_config(config).await
    }

    pub fn dispatch(&self, command: Commands) -> Result<HandlerResult> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = match command {
                Commands::Status(cmd) => client.status_command(cmd).await?,
                Commands::Wifi(cmd) => client.wifi_command(cmd).await?,
                Commands::Ethernet(cmd) => client.ethernet_command(cmd).await?,
                Commands::Loot(cmd) => client.loot_command(cmd).await?,
                Commands::Notify(cmd) => client.notify_command(cmd).await?,
                Commands::System(cmd) => client.system_command(cmd).await?,
                Commands::Hardware(cmd) => client.hardware_command(cmd).await?,
                Commands::DnsSpoof(cmd) => client.dnsspoof_command(cmd).await?,
                Commands::Mitm(cmd) => client.mitm_command(cmd).await?,
                Commands::Reverse(cmd) => client.reverse_command(cmd).await?,
                Commands::Hotspot(cmd) => client.hotspot_command(cmd).await?,
                Commands::Scan(cmd) => client.scan_command(cmd).await?,
                Commands::Bridge(cmd) => client.bridge_command(cmd).await?,
                Commands::Process(cmd) => client.process_command(cmd).await?,
            };
            Ok((response.message, response.data))
        })
    }

    pub fn disk_usage(&self, path: &str) -> Result<(u64, u64)> {
        let path = path.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.disk_usage(&path).await?;
            Ok((response.used_bytes, response.total_bytes))
        })
    }

    pub fn block_devices(&self) -> Result<Vec<BlockDeviceInfo>> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.block_devices().await?;
            Ok(response.devices)
        })
    }

    pub fn system_logs(&self) -> Result<String> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.system_logs().await?;
            Ok(response.content)
        })
    }

    pub fn status(&self) -> Result<StatusResponse> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.status().await
        })
    }

    pub fn ops_config_get(&self) -> Result<OpsConfig> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.ops_config_get().await
        })
    }

    pub fn ops_config_set(&self, ops: OpsConfig) -> Result<OpsConfig> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.ops_config_set(ops).await
        })
    }

    pub fn logging_config_set(
        &self,
        enabled: bool,
        level: Option<rustyjack_ipc::LogLevel>,
    ) -> Result<rustyjack_ipc::LoggingConfigSetResponse> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.logging_config_set(enabled, level).await
        })
    }

    pub fn wifi_capabilities(&self, interface: &str) -> Result<WifiCapabilitiesResponse> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.wifi_capabilities(&interface).await
        })
    }

    pub fn hotspot_warnings(&self) -> Result<HotspotWarningsResponse> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.hotspot_warnings().await
        })
    }

    pub fn hotspot_diagnostics(&self, ap_interface: &str) -> Result<HotspotDiagnosticsResponse> {
        let ap_interface = ap_interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.hotspot_diagnostics(&ap_interface).await
        })
    }

    pub fn hotspot_clients(&self) -> Result<Vec<HotspotClient>> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.hotspot_clients().await?;
            Ok(response.clients)
        })
    }

    #[allow(dead_code)]
    pub fn gpio_diagnostics(&self) -> Result<String> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.gpio_diagnostics().await?;
            Ok(response.content)
        })
    }

    // ===== Job Management =====

    async fn poll_job_until_complete(
        &self,
        client: &mut DaemonClient,
        job_id: JobId,
    ) -> Result<Value> {
        let max_wait = Duration::from_secs(300);
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(500);

        loop {
            if start.elapsed() > max_wait {
                bail!("Job {} timed out after 5 minutes", job_id);
            }

            let status = client.job_status(job_id).await?;

            match status.job.state {
                JobState::Completed => {
                    return status
                        .job
                        .result
                        .ok_or_else(|| anyhow!("Job completed but no result"));
                }
                JobState::Failed => {
                    let err_msg = status
                        .job
                        .error
                        .map(|e| e.message)
                        .unwrap_or_else(|| "Job failed with unknown error".to_string());
                    bail!("Job failed: {}", err_msg);
                }
                JobState::Cancelled => {
                    bail!("Job was cancelled");
                }
                JobState::Queued | JobState::Running => {
                    sleep(poll_interval).await;
                }
            }
        }
    }

    pub fn poll_job(&self, job_id: JobId) -> Result<Value> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            self.poll_job_until_complete(&mut client, job_id).await
        })
    }

    pub fn start_core_command(&self, command: Commands) -> Result<JobId> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client.job_start(JobKind::CoreCommand { command }).await?;
            Ok(job.job_id)
        })
    }

    pub fn cancel_job(&self, job_id: JobId) -> Result<bool> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.job_cancel(job_id).await?;
            Ok(response.cancelled)
        })
    }

    pub fn job_status(&self, job_id: JobId) -> Result<JobInfo> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let status = client.job_status(job_id).await?;
            Ok(status.job)
        })
    }

    pub fn start_interface_select(&self, interface: &str) -> Result<JobId> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client
                .job_start(JobKind::InterfaceSelect { interface })
                .await?;
            Ok(job.job_id)
        })
    }

    pub fn start_system_update(&self, url: &str) -> Result<JobId> {
        let url = url.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client
                .job_start(JobKind::SystemUpdate {
                    req: UpdateRequestIpc { url },
                })
                .await?;
            Ok(job.job_id)
        })
    }

    // ===== WiFi Operations =====

    pub fn wifi_interfaces(&self) -> Result<Value> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.wifi_interfaces().await?;
            Ok(serde_json::to_value(response)?)
        })
    }

    pub fn wifi_scan(&self, interface: &str, timeout_ms: u64) -> Result<Value> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client.wifi_scan_start(&interface, timeout_ms).await?;
            self.poll_job_until_complete(&mut client, job.job_id).await
        })
    }

    pub fn wifi_connect(
        &self,
        interface: &str,
        ssid: &str,
        psk: Option<String>,
        timeout_ms: u64,
    ) -> Result<Value> {
        let interface = interface.to_string();
        let ssid = ssid.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client
                .wifi_connect_start(&interface, &ssid, psk, timeout_ms)
                .await?;
            self.poll_job_until_complete(&mut client, job.job_id).await
        })
    }

    pub fn wifi_disconnect(&self, interface: &str) -> Result<bool> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.wifi_disconnect(&interface).await?;
            Ok(response.disconnected)
        })
    }

    // ===== Hotspot Operations =====

    pub fn hotspot_start(
        &self,
        interface: &str,
        upstream_interface: &str,
        ssid: &str,
        passphrase: Option<String>,
        channel: Option<u8>,
    ) -> Result<JobId> {
        let interface = interface.to_string();
        let upstream_interface = upstream_interface.to_string();
        let ssid = ssid.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client
                .hotspot_start(&interface, &upstream_interface, &ssid, passphrase, channel)
                .await?;
            Ok(job.job_id)
        })
    }

    pub fn hotspot_stop(&self) -> Result<bool> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.hotspot_stop().await?;
            Ok(response.success)
        })
    }

    // ===== Portal Operations =====

    pub fn portal_start(&self, interface: &str, port: u16) -> Result<JobId> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client.portal_start(&interface, port).await?;
            Ok(job.job_id)
        })
    }

    pub fn portal_stop(&self) -> Result<bool> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.portal_stop().await?;
            Ok(response.success)
        })
    }

    pub fn portal_status(&self) -> Result<Value> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.portal_status().await?;
            Ok(serde_json::to_value(response)?)
        })
    }

    // ===== System Operations =====

    pub fn system_reboot(&self) -> Result<()> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.system_reboot().await?;
            Ok(())
        })
    }

    pub fn system_shutdown(&self) -> Result<()> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.system_shutdown().await?;
            Ok(())
        })
    }

    pub fn hostname_randomize_now(&self) -> Result<String> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.hostname_randomize_now().await?;
            Ok(response.hostname)
        })
    }

    // ===== Mount Operations =====

    pub fn mount_list(&self) -> Result<Value> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.mount_list().await?;
            Ok(serde_json::to_value(response)?)
        })
    }

    pub fn mount_device(&self, device: &str, filesystem: Option<String>) -> Result<JobId> {
        let device = device.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client.mount_start(&device, filesystem).await?;
            Ok(job.job_id)
        })
    }

    pub fn unmount_device(&self, device: &str) -> Result<JobId> {
        let device = device.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let job = client.unmount_start(&device).await?;
            Ok(job.job_id)
        })
    }

    // ===== Interface Selection =====

    pub fn set_active_interface(&self, interface: &str) -> Result<Value> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.set_active_interface(&interface).await?;
            Ok(serde_json::to_value(response)?)
        })
    }

    pub fn get_active_interface(&self) -> Result<Option<String>> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.active_interface().await?;
            Ok(response.interface)
        })
    }

    pub fn clear_active_interface(&self) -> Result<()> {
        self.block_on(async move {
            let mut client = self.create_client().await?;
            let response = client.clear_active_interface().await?;
            if response.cleared {
                Ok(())
            } else {
                Err(anyhow!("Failed to clear active interface"))
            }
        })
    }

    // ===== Interface Capabilities =====

    pub fn interface_status(&self, interface: &str) -> Result<InterfaceStatusResponse> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;
            client.interface_status(&interface).await
        })
    }

    pub fn get_interface_capabilities(&self, interface: &str) -> Result<InterfaceCapabilities> {
        let interface = interface.to_string();
        self.block_on(async move {
            let mut client = self.create_client().await?;

            let status = client.interface_status(&interface).await?;
            if let Some(caps) = status.capabilities {
                // Convert IPC TxInMonitorCapability to UI TxInMonitorCapability
                let tx_cap = match caps.tx_in_monitor {
                    Some(rustyjack_ipc::types::TxInMonitorCapability::Supported) => {
                        TxInMonitorCapability::Supported
                    }
                    Some(rustyjack_ipc::types::TxInMonitorCapability::NotSupported) => {
                        TxInMonitorCapability::NotSupported
                    }
                    _ => TxInMonitorCapability::Unknown,
                };
                return Ok(InterfaceCapabilities {
                    name: interface.clone(),
                    is_wireless: status.is_wireless,
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
                    tx_in_monitor_reason: caps.tx_in_monitor_reason.unwrap_or_default(),
                });
            }

            let response = client.wifi_capabilities(&interface).await?;
            // Convert IPC TxInMonitorCapability to UI TxInMonitorCapability
            let tx_cap = match response.tx_in_monitor {
                Some(rustyjack_ipc::types::TxInMonitorCapability::Supported) => {
                    TxInMonitorCapability::Supported
                }
                Some(rustyjack_ipc::types::TxInMonitorCapability::NotSupported) => {
                    TxInMonitorCapability::NotSupported
                }
                _ => TxInMonitorCapability::Unknown,
            };
            Ok(InterfaceCapabilities {
                name: interface.clone(),
                is_wireless: response.interface_is_wireless,
                is_physical: response.interface_exists,
                supports_monitor: response.supports_monitor_mode,
                supports_ap: response.supports_ap,
                supports_injection: response.supports_injection,
                supports_5ghz: false,
                supports_2ghz: response.interface_is_wireless,
                mac_address: None,
                driver: response.driver_name,
                chipset: None,
                tx_in_monitor: tx_cap,
                tx_in_monitor_reason: response.tx_in_monitor_reason.unwrap_or_default(),
            })
        })
    }

    pub fn interface_is_up(&self, interface: &str) -> Result<bool> {
        let status = self.interface_status(interface)?;
        Ok(status.is_up)
    }

    pub fn get_interface_ip(&self, _interface: &str) -> Result<Option<std::net::Ipv4Addr>> {
        let status = self.interface_status(_interface)?;
        match status.ip {
            Some(ip) => Ok(ip.parse().ok()),
            None => Ok(None),
        }
    }

    fn block_on<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        // If we're already in an async context, use the existing runtime
        if let Ok(handle) = Handle::try_current() {
            return handle.block_on(fut);
        }

        // Otherwise, use the cached UI runtime (created once, reused for all calls)
        let rt = UI_RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build UI tokio runtime")
        });
        rt.block_on(fut)
    }
}

fn daemon_socket_path() -> PathBuf {
    env::var("RUSTYJACKD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/rustyjack/rustyjackd.sock"))
}

fn resolve_root(input: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = input {
        return Ok(path);
    }

    if let Ok(env_path) = env::var("RUSTYJACK_ROOT") {
        return Ok(PathBuf::from(env_path));
    }

    let default = PathBuf::from("/var/lib/rustyjack");
    if default.exists() {
        return Ok(default);
    }

    let legacy = PathBuf::from("/root/Rustyjack");
    if legacy.exists() {
        return Ok(legacy);
    }

    env::current_dir().context("determining current directory")
}
