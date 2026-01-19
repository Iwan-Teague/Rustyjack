use std::fs;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

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
        
        let root = self.config.root_path.clone();
        tokio::task::spawn_blocking(move || {
            use rustyjack_core::system::{IsolationEngine, RealNetOps};
            use std::sync::Arc;
            
            let ops = Arc::new(RealNetOps);
            let engine = IsolationEngine::new(ops, root);
            
            let mut retries = 0;
            let max_retries = 3;
            
            loop {
                match engine.enforce() {
                    Ok(outcome) => {
                        info!("Startup enforcement succeeded: allowed={:?}, blocked={:?}", 
                            outcome.allowed, outcome.blocked);
                        if !outcome.errors.is_empty() {
                            warn!("Enforcement had {} non-fatal errors", outcome.errors.len());
                            for err in &outcome.errors {
                                warn!("  {}: {}", err.interface, err.message);
                            }
                        }
                        break;
                    }
                    Err(e) => {
                        warn!("Startup enforcement failed (attempt {}/{}): {}", 
                            retries + 1, max_retries, e);
                        
                        retries += 1;
                        if retries >= max_retries {
                            tracing::error!("Startup enforcement failed after {} attempts, continuing anyway", max_retries);
                            break;
                        }
                        
                        std::thread::sleep(std::time::Duration::from_secs(2));
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|e| {
            warn!("Network reconciliation task panicked: {}", e);
        });
    }
}
