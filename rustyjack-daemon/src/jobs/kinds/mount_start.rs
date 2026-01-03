use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, ErrorCode, MountStartRequestIpc};

pub async fn run<F, Fut>(
    req: MountStartRequestIpc,
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

    let request = rustyjack_core::services::mount::MountRequest {
        device: req.device,
        filesystem: req.filesystem,
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<(u8, String)>();
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::mount::mount(request, |percent, message| {
            let _ = tx.send((percent, message.to_string()));
        })
    });

    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                handle.abort();
                return Err(DaemonError::new(
                    ErrorCode::Cancelled,
                    "Job cancelled",
                    false
                ).with_source("daemon.jobs.mount_start"));
            }
            res = &mut handle => {
                break res;
            }
            Some((percent, message)) = rx.recv() => {
                progress("mount_start", percent, &message).await;
            }
        }
    };

    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.to_daemon_error_with_code(
            ErrorCode::MountFailed,
            "daemon.jobs.mount_start",
        )),
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "mount job panicked", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.mount_start"),
        ),
    }
}
