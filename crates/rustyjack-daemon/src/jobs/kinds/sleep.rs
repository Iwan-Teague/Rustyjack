use std::time::Duration;

use tokio::time;
use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, ErrorCode};

pub async fn run(
    seconds: u64,
    cancel: &CancellationToken,
) -> Result<serde_json::Value, DaemonError> {
    let sleep = time::sleep(Duration::from_secs(seconds));
    tokio::pin!(sleep);
    tokio::select! {
        _ = cancel.cancelled() => Err(DaemonError::new(ErrorCode::Cancelled, "Job cancelled", false)),
        _ = &mut sleep => Ok(serde_json::json!({ "slept_seconds": seconds })),
    }
}
