mod noop;
mod scan;
mod sleep;
mod update;

use std::future::Future;

use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, JobKind};

pub async fn execute<F, Fut>(
    kind: &JobKind,
    cancel: &CancellationToken,
    mut progress: F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: Future<Output = ()>,
{
    match kind {
        JobKind::Noop => noop::run().await,
        JobKind::Sleep { seconds } => sleep::run(*seconds, cancel).await,
        JobKind::ScanRun { req } => scan::run(req.clone(), cancel, &mut progress).await,
        JobKind::SystemUpdate { req } => update::run(req.clone(), cancel, &mut progress).await,
    }
}
