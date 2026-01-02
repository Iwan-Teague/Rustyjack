use std::fs;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use log::{info, warn};

use crate::config::DaemonConfig;
use crate::jobs::JobManager;
use crate::locks::LockManager;

#[derive(Debug, Clone)]
pub struct DaemonState {
    pub config: DaemonConfig,
    pub start_time: Instant,
    pub jobs: Arc<JobManager>,
    pub locks: Arc<LockManager>,
    pub version: String,
}

impl DaemonState {
    pub fn new(config: DaemonConfig) -> Self {
        let start_time = Instant::now();
        let jobs = Arc::new(JobManager::new(config.job_retention));
        let locks = Arc::new(LockManager::new());
        let version = env!("CARGO_PKG_VERSION").to_string();
        Self {
            config,
            start_time,
            jobs,
            locks,
            version,
        }
    }

    pub fn uptime_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub async fn reconcile_on_startup(&self) {
        match fs::read_to_string("/proc/mounts") {
            Ok(contents) => {
                let count = contents.lines().count();
                info!("Startup mount table entries: {}", count);
            }
            Err(err) => warn!("Failed to read /proc/mounts: {}", err),
        }
    }
}
