use std::env;
use std::path::PathBuf;
use std::time::Duration;

use rustyjack_ipc::MAX_FRAME;

pub const DEFAULT_SOCKET_PATH: &str = "/run/rustyjack/rustyjackd.sock";
pub const DEFAULT_JOB_RETENTION: usize = 200;
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 5000;
pub const DEFAULT_WRITE_TIMEOUT_MS: u64 = 5000;
pub const DEFAULT_ADMIN_GROUP: &str = "rustyjack-admin";
pub const DEFAULT_OPERATOR_GROUP: &str = "rustyjack";
pub const DEFAULT_ROOT_PATH: &str = "/opt/rustyjack";
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;
pub const DEFAULT_MAX_REQUESTS_PER_SECOND: u32 = 20;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub max_frame: u32,
    pub dangerous_ops_enabled: bool,
    pub allow_core_dispatch: bool,
    pub job_retention: usize,
    pub socket_group: Option<String>,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub admin_group: String,
    pub operator_group: String,
    pub root_path: PathBuf,
    pub network_manager_integration: bool,
    pub max_connections: usize,
    pub max_requests_per_second: u32,
}

impl DaemonConfig {
    pub fn from_env() -> Self {
        let socket_path = env::var("RUSTYJACKD_SOCKET")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
        let max_frame = env::var("RUSTYJACKD_MAX_FRAME")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(MAX_FRAME);
        let dangerous_ops_enabled = cfg!(feature = "dangerous_ops")
            && env::var("RUSTYJACKD_DANGEROUS_OPS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        let allow_core_dispatch = env::var("RUSTYJACKD_ALLOW_CORE_DISPATCH")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let job_retention = env::var("RUSTYJACKD_JOB_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_JOB_RETENTION);
        let socket_group = env::var("RUSTYJACKD_SOCKET_GROUP").ok();
        let read_timeout_ms = env::var("RUSTYJACKD_READ_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_READ_TIMEOUT_MS);
        let write_timeout_ms = env::var("RUSTYJACKD_WRITE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_WRITE_TIMEOUT_MS);
        let admin_group = env::var("RUSTYJACKD_ADMIN_GROUP")
            .unwrap_or_else(|_| DEFAULT_ADMIN_GROUP.to_string());
        let operator_group = env::var("RUSTYJACKD_OPERATOR_GROUP")
            .unwrap_or_else(|_| DEFAULT_OPERATOR_GROUP.to_string());
        let root_path = env::var("RUSTYJACK_ROOT")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT_PATH));
        let network_manager_integration = env::var("RUSTYJACKD_NM_INTEGRATION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let max_connections = env::var("RUSTYJACKD_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_CONNECTIONS);
        let max_requests_per_second = env::var("RUSTYJACKD_MAX_REQUESTS_PER_SECOND")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_MAX_REQUESTS_PER_SECOND);

        Self {
            socket_path,
            max_frame,
            dangerous_ops_enabled,
            allow_core_dispatch,
            job_retention,
            socket_group,
            read_timeout: Duration::from_millis(read_timeout_ms),
            write_timeout: Duration::from_millis(write_timeout_ms),
            admin_group,
            operator_group,
            root_path,
            network_manager_integration,
            max_connections,
            max_requests_per_second,
        }
    }
}
