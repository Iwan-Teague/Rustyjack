use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::jobs::cancel_bridge::create_cancel_flag;
use crate::state::DaemonState;
use rustyjack_ipc::{Commands, DaemonError, ErrorCode};

pub async fn run<F, Fut>(
    command: Commands,
    state: Arc<DaemonState>,
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

    progress("start", 5, "Starting command").await;

    let root = state.config.root_path.clone();
    let cancel_flag = create_cancel_flag(cancel);
    let cancel_flag_for_task = Arc::clone(&cancel_flag);

    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::operations::dispatch_command_with_cancel(
            &root,
            command,
            Some(&cancel_flag_for_task),
        )
    });

    let mut cancel_notified = false;
    let result = loop {
        tokio::select! {
            _ = cancel.cancelled(), if !cancel_notified => {
                cancel_flag.store(true, Ordering::Relaxed);
                cancel_notified = true;
                progress("cancel", 90, "Cancelling...").await;
            }
            res = &mut handle => {
                break res;
            }
        }
    };

    match result {
        Ok(Ok((message, data))) => Ok(serde_json::json!({
            "message": message,
            "data": data,
        })),
        Ok(Err(err)) => {
            if rustyjack_core::operations::is_cancelled_error(&err) {
                Err(DaemonError::new(
                    ErrorCode::Cancelled,
                    "Job cancelled",
                    false,
                ))
            } else {
                Err(
                    DaemonError::new(ErrorCode::Internal, err.to_string(), false)
                        .with_detail(format!("{:#}", err))
                        .with_source("daemon.jobs.core_command"),
                )
            }
        }
        Err(join_err) => {
            Err(
                DaemonError::new(ErrorCode::Internal, "Core command job panicked", false)
                    .with_detail(join_err.to_string())
                    .with_source("daemon.jobs.core_command"),
            )
        }
    }
}
