use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::jobs::cancel_bridge::create_cancel_flag;
use rustyjack_ipc::{DaemonError, ErrorCode, WifiConnectRequestIpc};

pub async fn run<F, Fut>(
    req: WifiConnectRequestIpc,
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

    let interface = req.interface.clone();
    let request = rustyjack_core::services::wifi::WifiConnectRequest {
        interface: req.interface,
        ssid: req.ssid,
        psk: req.psk,
        timeout_ms: req.timeout_ms,
    };

    let cancel_flag = create_cancel_flag(cancel);
    let cancel_flag_for_task = cancel_flag.clone();

    let (tx, mut rx) = mpsc::channel::<(u8, String)>(64);
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::wifi::connect(
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
                let interface = interface.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = rustyjack_core::services::wifi::disconnect(&interface);
                }).await;
                progress("wifi_connect", 90, "Cancelling...").await;
            }
            res = &mut handle => {
                break res;
            }
            Some((percent, message)) = rx.recv() => {
                progress("wifi_connect", percent, &message).await;
            }
        }
    };

    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => {
            Err(err.to_daemon_error_with_code(ErrorCode::WifiFailed, "daemon.jobs.wifi_connect"))
        }
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "wifi connect job panicked", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.wifi_connect"),
        ),
    }
}
