use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, ErrorCode, ScanModeIpc, ScanRequestIpc};

pub async fn run<F, Fut>(
    req: ScanRequestIpc,
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

    let request = rustyjack_core::services::scan::ScanRequest {
        target: req.target,
        mode: match req.mode {
            ScanModeIpc::DiscoveryOnly => rustyjack_core::services::scan::ScanMode::DiscoveryOnly,
            ScanModeIpc::DiscoveryAndPorts => {
                rustyjack_core::services::scan::ScanMode::DiscoveryAndPorts
            }
        },
        ports: req.ports,
        timeout_ms: req.timeout_ms,
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<(u8, String)>();
    let mut handle = tokio::task::spawn_blocking(move || {
        rustyjack_core::services::scan::run_scan(&root, request, |percent, message| {
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
                ).with_source("daemon.jobs.scan"));
            }
            res = &mut handle => {
                break res;
            }
            Some((percent, message)) = rx.recv() => {
                progress("scan", percent, &message).await;
            }
        }
    };

    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.to_daemon_error_with_source("daemon.jobs.scan")),
        Err(err) => Err(
            DaemonError::new(ErrorCode::Internal, "scan job panicked", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.scan"),
        ),
    }
}
