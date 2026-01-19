use serde_json::json;

use rustyjack_ipc::DaemonError;

pub async fn run() -> Result<serde_json::Value, DaemonError> {
    Ok(json!({ "status": "ok" }))
}
