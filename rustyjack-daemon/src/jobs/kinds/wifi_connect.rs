use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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
        return Err(DaemonError::new(ErrorCode::Cancelled, "Job cancelled", false));
    }

    let request = rustyjack_core::services::wifi::WifiConnectRequest {
        interface: req.interface,
        ssid: req.ssid,
        psk: req.psk,
        timeout_ms: req.timeout_ms,
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<(u8, String)>();
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::wifi::connect(request, |percent, message| {
            let _ = tx.send((percent, message.to_string()));
        })
    });

    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                handle.abort();
                let _ = tokio::task::spawn_blocking(|| {
                    let _ = rustyjack_core::services::wifi::disconnect(&request.interface);
                }).await;
                return Err(DaemonError::new(
                    ErrorCode::Cancelled,
                    "Job cancelled",
                    false
                ).with_source("daemon.jobs.wifi_connect"));
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
        Ok(Err(err)) => Err(err.to_daemon_error_with_code(
            ErrorCode::WifiFailed,
            "daemon.jobs.wifi_connect",
        )),
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "wifi connect job panicked", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.wifi_connect"),
        ),
    }
}
