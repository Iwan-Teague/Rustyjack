use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::operations::run_system_update_with_progress;
use crate::services::error::ServiceError;
use rustyjack_commands::SystemUpdateArgs;

#[derive(Debug, Clone)]
pub struct UpdateRequest {
    pub service: String,
    pub remote: String,
    pub branch: String,
    pub backup_dir: Option<PathBuf>,
}

pub fn run_update<F>(
    root: &Path,
    req: UpdateRequest,
    mut on_progress: F,
) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    let args = SystemUpdateArgs {
        service: req.service,
        remote: req.remote,
        branch: req.branch,
        backup_dir: req.backup_dir,
    };

    let result = run_system_update_with_progress(root, args, |percent, message| {
        let clamped = percent.max(0.0).min(100.0);
        on_progress(clamped.round() as u8, message);
    });

    match result {
        Ok((_message, data)) => Ok(data),
        Err(err) => Err(ServiceError::External(err.to_string())),
    }
}
