use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use log::{debug, info};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, ErrorCode, JobInfo, JobKind, JobSpec, JobState, Progress};

use crate::locks::LockKind;
use crate::state::DaemonState;

mod kinds;

#[derive(Debug)]
struct JobRecord {
    info: JobInfo,
    cancel: CancellationToken,
}

#[derive(Debug)]
pub struct JobManager {
    next_id: AtomicU64,
    jobs: Mutex<HashMap<u64, JobRecord>>,
    retention: usize,
}

impl JobManager {
    pub fn new(retention: usize) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            jobs: Mutex::new(HashMap::new()),
            retention,
        }
    }

    pub async fn start_job(self: &Arc<Self>, spec: JobSpec, state: Arc<DaemonState>) -> u64 {
        let job_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let created_at_ms = DaemonState::now_ms();
        
        let kind_name = job_kind_name(&spec.kind);
        let requested_by = spec.requested_by.as_deref().unwrap_or("unknown");
        
        info!(
            "job_id={} kind={} requested_by={} state=queued",
            job_id, kind_name, requested_by
        );
        
        let info = JobInfo {
            job_id,
            kind: spec.kind.clone(),
            state: JobState::Queued,
            created_at_ms,
            started_at_ms: None,
            finished_at_ms: None,
            progress: None,
            result: None,
            error: None,
        };

        let cancel = CancellationToken::new();
        let record = JobRecord {
            info,
            cancel: cancel.clone(),
        };

        {
            let mut jobs = self.jobs.lock().await;
            jobs.insert(job_id, record);
        }

        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager.run_job(job_id, spec, cancel, state).await;
        });

        job_id
    }

    async fn run_job(
        &self,
        job_id: u64,
        spec: JobSpec,
        cancel: CancellationToken,
        state: Arc<DaemonState>,
    ) {
        let kind_name = job_kind_name(&spec.kind);
        
        info!("job_id={} kind={} state=running", job_id, kind_name);
        
        self.update_job_state(job_id, JobState::Running, None, None)
            .await;
        self.update_job_started(job_id).await;

        let _lock_set = state.locks.acquire(&required_locks(&spec.kind)).await;

        let result = kinds::execute(&spec.kind, &cancel, |phase, percent, message| {
            let phase = phase.to_string();
            let message = message.to_string();
            self.update_progress(job_id, phase, percent, message)
        })
        .await;

        match result {
            Ok(value) => {
                info!("job_id={} kind={} state=completed", job_id, kind_name);
                self.update_job_state(job_id, JobState::Completed, Some(value), None)
                    .await;
            }
            Err(err) => {
                let job_state = match err.code {
                    ErrorCode::Cancelled => JobState::Cancelled,
                    _ => JobState::Failed,
                };
                
                let state_name = match job_state {
                    JobState::Cancelled => "cancelled",
                    JobState::Failed => "failed",
                    _ => "unknown",
                };
                
                info!(
                    "job_id={} kind={} state={} error_code={:?} message={}",
                    job_id, kind_name, state_name, err.code, err.message
                );
                
                if let Some(source) = &err.source {
                    debug!("job_id={} error_source={}", job_id, source);
                }
                if let Some(detail) = &err.detail {
                    debug!("job_id={} error_detail={}", job_id, detail);
                }
                
                self.update_job_state(job_id, job_state, None, Some(err)).await;
            }
        }

        self.update_job_finished(job_id).await;
        self.enforce_retention().await;
    }

    async fn update_job_started(&self, job_id: u64) {
        let mut jobs = self.jobs.lock().await;
        if let Some(record) = jobs.get_mut(&job_id) {
            record.info.started_at_ms = Some(DaemonState::now_ms());
        }
    }

    async fn update_job_finished(&self, job_id: u64) {
        let mut jobs = self.jobs.lock().await;
        if let Some(record) = jobs.get_mut(&job_id) {
            record.info.finished_at_ms = Some(DaemonState::now_ms());
        }
    }

    async fn update_job_state(
        &self,
        job_id: u64,
        state: JobState,
        result: Option<serde_json::Value>,
        error: Option<DaemonError>,
    ) {
        let mut jobs = self.jobs.lock().await;
        if let Some(record) = jobs.get_mut(&job_id) {
            record.info.state = state;
            if let Some(value) = result {
                record.info.result = Some(value);
            }
            if let Some(err) = error {
                record.info.error = Some(err);
            }
        }
    }

    pub async fn update_progress(&self, job_id: u64, phase: String, percent: u8, message: String) {
        let now = DaemonState::now_ms();
        let mut jobs = self.jobs.lock().await;
        if let Some(record) = jobs.get_mut(&job_id) {
            let should_update = match &record.info.progress {
                Some(progress) => {
                    progress.percent != percent
                        || progress.message != message
                        || now.saturating_sub(progress.updated_at_ms) >= 200
                }
                None => true,
            };
            if should_update {
                record.info.progress = Some(Progress {
                    phase,
                    percent,
                    message,
                    updated_at_ms: now,
                });
            }
        }
    }

    pub async fn job_status(&self, job_id: u64) -> Option<JobInfo> {
        let jobs = self.jobs.lock().await;
        jobs.get(&job_id).map(|record| record.info.clone())
    }

    pub async fn cancel_job(&self, job_id: u64) -> bool {
        let jobs = self.jobs.lock().await;
        if let Some(record) = jobs.get(&job_id) {
            record.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub async fn cancel_all(&self) {
        let jobs = self.jobs.lock().await;
        for record in jobs.values() {
            record.cancel.cancel();
        }
    }

    pub async fn job_counts(&self) -> (usize, usize) {
        let jobs = self.jobs.lock().await;
        let total = jobs.len();
        let active = jobs
            .values()
            .filter(|record| matches!(record.info.state, JobState::Queued | JobState::Running))
            .count();
        (total, active)
    }

    async fn enforce_retention(&self) {
        let mut jobs = self.jobs.lock().await;
        if jobs.len() <= self.retention {
            return;
        }

        let active_ids: std::collections::HashSet<u64> = jobs
            .values()
            .filter(|record| {
                matches!(record.info.state, JobState::Queued | JobState::Running)
            })
            .map(|record| record.info.job_id)
            .collect();

        let mut finished: Vec<(u64, u64)> = jobs
            .values()
            .filter(|record| {
                !matches!(record.info.state, JobState::Queued | JobState::Running)
            })
            .map(|record| (record.info.job_id, record.info.created_at_ms))
            .collect();

        finished.sort_by_key(|(_, created)| *created);

        while jobs.len() > self.retention && !finished.is_empty() {
            let (job_id, _) = finished.remove(0);
            jobs.remove(&job_id);
        }
    }
}

fn required_locks(kind: &JobKind) -> Vec<LockKind> {
    match kind {
        JobKind::Noop => Vec::new(),
        JobKind::Sleep { .. } => Vec::new(),
        JobKind::ScanRun { .. } => vec![LockKind::Wifi],
        JobKind::SystemUpdate { .. } => vec![LockKind::Update],
        JobKind::WifiScan { .. } => vec![LockKind::Wifi],
        JobKind::WifiConnect { .. } => vec![LockKind::Wifi],
        JobKind::HotspotStart { .. } => vec![LockKind::Wifi],
        JobKind::PortalStart { .. } => vec![LockKind::Portal],
        JobKind::MountStart { .. } => vec![LockKind::Mount],
        JobKind::UnmountStart { .. } => vec![LockKind::Mount],
    }
}

fn job_kind_name(kind: &JobKind) -> &'static str {
    match kind {
        JobKind::Noop => "noop",
        JobKind::Sleep { .. } => "sleep",
        JobKind::ScanRun { .. } => "scan",
        JobKind::SystemUpdate { .. } => "update",
        JobKind::WifiScan { .. } => "wifi_scan",
        JobKind::WifiConnect { .. } => "wifi_connect",
        JobKind::HotspotStart { .. } => "hotspot_start",
        JobKind::PortalStart { .. } => "portal_start",
        JobKind::MountStart { .. } => "mount_start",
        JobKind::UnmountStart { .. } => "unmount_start",
    }
}
