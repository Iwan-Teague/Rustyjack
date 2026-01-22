use std::path::Path;

use serde_json::Value;

use crate::cancel::CancelFlag;
use crate::operations::run_system_update_with_progress;
use crate::services::error::ServiceError;
use rustyjack_commands::SystemUpdateArgs;

#[derive(Debug, Clone)]
pub struct UpdateRequest {
    pub url: String,
}

pub fn run_update<F>(
    root: &Path,
    req: UpdateRequest,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    let args = SystemUpdateArgs { url: req.url };

    let result = run_system_update_with_progress(root, args, cancel, |percent, message| {
        let clamped = percent.max(0.0).min(100.0);
        on_progress(clamped.round() as u8, message);
    });

    match result {
        Ok((_message, data)) => Ok(data),
        Err(err) => {
            if crate::operations::is_cancelled_error(&err) {
                Err(ServiceError::Cancelled)
            } else {
                Err(ServiceError::External(err.to_string()))
            }
        }
    }
}
