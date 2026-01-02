use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, ErrorCode, UpdateRequestIpc};

pub async fn run<F, Fut>(
    req: UpdateRequestIpc,
    cancel: &CancellationToken,
    progress: &mut F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if cancel.is_cancelled() {
        return Err(DaemonError::new(ErrorCode::Cancelled, "Job cancelled", false));
    }

    let root = rustyjack_core::resolve_root(None).map_err(|err| {
        DaemonError::new(ErrorCode::Internal, "resolve root failed", false)
            .with_detail(err.to_string())
    })?;

    let request = rustyjack_core::services::update::UpdateRequest {
        service: req.service,
        remote: req.remote,
        branch: req.branch,
        backup_dir: req.backup_dir.map(std::path::PathBuf::from),
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<(u8, String)>();
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::update::run_update(&root, request, |percent, message| {
            let _ = tx.send((percent, message.to_string()));
        })
    });

    let result = loop {
        tokio::select! {
            res = &mut handle => {
                break res;
            }
            Some((percent, message)) = rx.recv() => {
                progress("update", percent, &message).await;
            }
        }
    };

    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.to_daemon_error()),
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "update job panicked", false)
                .with_detail(err.to_string()),
        ),
    }
}
