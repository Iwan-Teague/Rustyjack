use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, ErrorCode, HotspotStartRequestIpc};

pub async fn run<F, Fut>(
    req: HotspotStartRequestIpc,
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

    let request = rustyjack_core::services::hotspot::HotspotStartRequest {
        interface: req.interface,
        ssid: req.ssid,
        passphrase: req.passphrase,
        channel: req.channel,
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<(u8, String)>();
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::hotspot::start(request, |percent, message| {
            let _ = tx.send((percent, message.to_string()));
        })
    });

    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                handle.abort();
                let _ = tokio::task::spawn_blocking(|| {
                    let _ = rustyjack_core::services::hotspot::stop();
                }).await;
                return Err(DaemonError::new(
                    ErrorCode::Cancelled,
                    "Job cancelled",
                    false
                ).with_source("daemon.jobs.hotspot_start"));
            }
            res = &mut handle => {
                break res;
            }
            Some((percent, message)) = rx.recv() => {
                progress("hotspot_start", percent, &message).await;
            }
        }
    };

    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.to_daemon_error_with_source("daemon.jobs.hotspot_start")),
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "hotspot start job panicked", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.hotspot_start"),
        ),
    }
}
