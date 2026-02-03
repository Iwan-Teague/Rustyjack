use anyhow::{anyhow, Result};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static SHARED_RUNTIME: OnceLock<Result<Runtime>> = OnceLock::new();

pub fn shared_runtime() -> Result<&'static Runtime> {
    match SHARED_RUNTIME.get_or_init(|| {
        Runtime::new().map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))
    }) {
        Ok(rt) => Ok(rt),
        Err(err) => Err(anyhow!("Failed to initialize tokio runtime: {}", err)),
    }
}
