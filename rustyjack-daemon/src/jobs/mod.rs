use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
                self.update_job_state(job_id, JobState::Completed, Some(value), None)
                    .await;
            }
            Err(err) => {
                let state = match err.code {
                    ErrorCode::Cancelled => JobState::Cancelled,
                    _ => JobState::Failed,
                };
                self.update_job_state(job_id, state, None, Some(err)).await;
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

        let mut entries: Vec<_> = jobs.values().map(|record| record.info.clone()).collect();
        entries.sort_by_key(|info| info.created_at_ms);
        let remove_count = jobs.len().saturating_sub(self.retention);
        for info in entries.into_iter().take(remove_count) {
            jobs.remove(&info.job_id);
        }
    }
}

fn required_locks(kind: &JobKind) -> Vec<LockKind> {
    match kind {
        JobKind::Noop => Vec::new(),
        JobKind::Sleep { .. } => Vec::new(),
        JobKind::ScanRun { .. } => vec![LockKind::Wifi],
        JobKind::SystemUpdate { .. } => vec![LockKind::Update],
    }
}
