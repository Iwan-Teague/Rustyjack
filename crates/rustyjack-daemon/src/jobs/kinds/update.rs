use std::path::PathBuf;

use tokio_util::sync::CancellationToken;

use rustyjack_ipc::{DaemonError, ErrorCode, UpdateRequestIpc};
use rustyjack_updater::{apply_update, UpdatePolicy};

pub async fn run<F, Fut>(
    req: UpdateRequestIpc,
    cancel: &CancellationToken,
    progress: &mut F,
    root: PathBuf,
    update_pubkey: Option<[u8; 32]>,
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

    let url = req.url.trim();
    if url.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "update url is required",
            false,
        ));
    }

    let public_key = update_pubkey.ok_or_else(|| {
        DaemonError::new(
            ErrorCode::Internal,
            "update public key not configured",
            false,
        )
    })?;
    let policy = UpdatePolicy {
        public_key_ed25519: public_key,
        stage_dir: root.join("update").join("stage"),
        install_dir: PathBuf::from("/usr/local/bin"),
        unit_restart: "rustyjackd.service".to_string(),
    };

    progress("update", 5, "Starting update...").await;

    let result = tokio::select! {
        _ = cancel.cancelled() => Err(DaemonError::new(ErrorCode::Cancelled, "Job cancelled", false)),
        res = apply_update(&policy, url) => {
            res.map_err(|err| {
                DaemonError::new(ErrorCode::UpdateFailed, "update failed", false)
                    .with_detail(err.to_string())
                    .with_source("daemon.jobs.update")
            })
        }
    };

    result?;

    progress("update", 100, "Update applied").await;

    Ok(serde_json::json!({
        "status": "applied",
    }))
}
