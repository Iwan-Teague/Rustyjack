use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::jobs::cancel_bridge::create_cancel_flag;
use rustyjack_ipc::{DaemonError, ErrorCode, UnmountStartRequestIpc};

pub async fn run<F, Fut>(
    req: UnmountStartRequestIpc,
    cancel: &CancellationToken,
    progress: &mut F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if cancel.is_cancelled() {
        return Err(DaemonError::new(
            ErrorCode::Cancelled,
            "Job cancelled",
            false,
        ));
    }

    let request = rustyjack_core::services::mount::UnmountRequest { device: req.device };

    let cancel_flag = create_cancel_flag(cancel);
    let cancel_flag_for_task = cancel_flag.clone();

    let (tx, mut rx) = mpsc::channel::<(u8, String)>(64);
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::mount::unmount(
            request,
            Some(&cancel_flag_for_task),
            |percent, message| {
                let _ = tx.try_send((percent, message.to_string()));
            },
        )
    });

    let mut cancel_notified = false;
    let result = loop {
        tokio::select! {
            _ = cancel.cancelled(), if !cancel_notified => {
                cancel_flag.store(true, Ordering::Relaxed);
                cancel_notified = true;
                progress("unmount_start", 90, "Cancelling...").await;
            }
            res = &mut handle => {
                break res;
            }
            Some((percent, message)) = rx.recv() => {
                progress("unmount_start", percent, &message).await;
            }
        }
    };

    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => {
            Err(err.to_daemon_error_with_code(ErrorCode::MountFailed, "daemon.jobs.unmount_start"))
        }
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "unmount job panicked", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.unmount_start"),
        ),
    }
}
