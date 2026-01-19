use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use rustyjack_core::cancel::CancelFlag;
use rustyjack_ipc::{DaemonError, ErrorCode};

/// Run a blocking operation with cooperative cancellation support.
///
/// When the cancellation token fires, a cancel flag is set. The blocking
/// operation must check the flag and exit promptly for cancellation to take effect.
pub async fn run_blocking_cancellable<F, T>(
    cancel: &CancellationToken,
    f: F,
) -> Result<T, DaemonError>
where
    F: FnOnce(&CancelFlag) -> Result<T, DaemonError> + Send + 'static,
    T: Send + 'static,
{
    if cancel.is_cancelled() {
        return Err(DaemonError::new(
            ErrorCode::Cancelled,
            "operation cancelled",
            false,
        ));
    }

    let cancel_flag: CancelFlag = Arc::new(AtomicBool::new(false));
    let cancel_flag_for_task = cancel_flag.clone();
    let mut handle: JoinHandle<Result<T, DaemonError>> =
        tokio::task::spawn_blocking(move || f(&cancel_flag_for_task));
    let mut cancel_notified = false;

    loop {
        tokio::select! {
            _ = cancel.cancelled(), if !cancel_notified => {
                cancel_flag.store(true, Ordering::Relaxed);
                cancel_notified = true;
            }
            result = &mut handle => {
                return match result {
                    Ok(inner) => inner,
                    Err(err) => Err(
                        DaemonError::new(
                            ErrorCode::Internal,
                            "blocking task panicked",
                            false,
                        )
                        .with_detail(err.to_string())
                    ),
                };
            }
        }
    }
}

/// Run a blocking operation with progress reporting and cancellation support.
///
/// Progress messages are sent via the provided channel, allowing the caller
/// to update job progress while the blocking work executes.
pub async fn run_blocking_cancellable_with_progress<F, T>(
    cancel: &CancellationToken,
    f: F,
    mut on_progress: impl FnMut(u8, String) + Send,
    mut rx: tokio::sync::mpsc::Receiver<(u8, String)>,
) -> Result<T, DaemonError>
where
    F: FnOnce(&CancelFlag) -> Result<T, DaemonError> + Send + 'static,
    T: Send + 'static,
{
    if cancel.is_cancelled() {
        return Err(DaemonError::new(
            ErrorCode::Cancelled,
            "operation cancelled",
            false,
        ));
    }

    let cancel_flag: CancelFlag = Arc::new(AtomicBool::new(false));
    let cancel_flag_for_task = cancel_flag.clone();
    let mut handle: JoinHandle<Result<T, DaemonError>> =
        tokio::task::spawn_blocking(move || f(&cancel_flag_for_task));
    let mut cancel_notified = false;

    loop {
        tokio::select! {
            _ = cancel.cancelled(), if !cancel_notified => {
                cancel_flag.store(true, Ordering::Relaxed);
                cancel_notified = true;
            }
            result = &mut handle => {
                return match result {
                    Ok(inner) => inner,
                    Err(err) => Err(
                        DaemonError::new(
                            ErrorCode::Internal,
                            "blocking task panicked",
                            false,
                        )
                        .with_detail(err.to_string())
                    ),
                };
            }
            Some((percent, message)) = rx.recv() => {
                on_progress(percent, message);
            }
        }
    }
}
