use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::jobs::cancel_bridge::create_cancel_flag;
use rustyjack_ipc::{DaemonError, ErrorCode, PortalStartRequestIpc};

pub async fn run<F, Fut>(
    req: PortalStartRequestIpc,
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

    if std::env::var("RUSTYJACK_PORTAL_MODE").as_deref() == Ok("external") {
        tracing::warn!("External portal mode is not supported; using embedded portal");
    }

    run_embedded_portal(req, cancel, progress).await
}

async fn run_embedded_portal<F, Fut>(
    req: PortalStartRequestIpc,
    cancel: &CancellationToken,
    progress: &mut F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let request = rustyjack_core::services::portal::PortalStartRequest {
        interface: req.interface,
        port: req.port,
    };

    let cancel_flag = create_cancel_flag(cancel);
    let cancel_flag_for_task = cancel_flag.clone();

    let (tx, mut rx) = mpsc::channel::<(u8, String)>(64);
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::portal::start(
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
                let _ = tokio::task::spawn_blocking(|| {
                    let _ = rustyjack_core::services::portal::stop();
                }).await;
                progress("portal_start", 90, "Cancelling...").await;
            }
            res = &mut handle => {
                break res;
            }
            Some((percent, message)) = rx.recv() => {
                progress("portal_start", percent, &message).await;
            }
        }
    };

    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.to_daemon_error_with_source("daemon.jobs.portal_start")),
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "portal start job panicked", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.portal_start"),
        ),
    }
}
