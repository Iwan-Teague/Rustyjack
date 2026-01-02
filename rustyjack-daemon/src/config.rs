use std::env;
use std::path::PathBuf;

use rustyjack_ipc::MAX_FRAME;

pub const DEFAULT_SOCKET_PATH: &str = "/run/rustyjack/rustyjackd.sock";
pub const DEFAULT_JOB_RETENTION: usize = 200;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub max_frame: u32,
    pub dangerous_ops_enabled: bool,
    pub job_retention: usize,
    pub socket_group: Option<String>,
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
        let dangerous_ops_enabled = env::var("RUSTYJACKD_DANGEROUS_OPS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let job_retention = env::var("RUSTYJACKD_JOB_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_JOB_RETENTION);
        let socket_group = env::var("RUSTYJACKD_SOCKET_GROUP").ok();

        Self {
            socket_path,
            max_frame,
            dangerous_ops_enabled,
            job_retention,
            socket_group,
        }
    }
}
