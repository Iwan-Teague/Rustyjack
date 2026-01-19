use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use anyhow::Result;

#[derive(Debug)]
pub struct CancelledError;

impl std::fmt::Display for CancelledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation cancelled")
    }
}

impl std::error::Error for CancelledError {}

pub type CancelFlag = Arc<AtomicBool>;

pub fn check_cancel(cancel: Option<&CancelFlag>) -> Result<()> {
    if let Some(flag) = cancel {
        if flag.load(Ordering::Relaxed) {
            return Err(CancelledError.into());
        }
    }
    Ok(())
}

pub fn cancel_sleep(cancel: Option<&CancelFlag>, duration: Duration) -> Result<()> {
    if duration.is_zero() {
        return check_cancel(cancel);
    }

    let start = Instant::now();
    let tick = Duration::from_millis(100);
    while start.elapsed() < duration {
        check_cancel(cancel)?;
        let remaining = duration.saturating_sub(start.elapsed());
        std::thread::sleep(tick.min(remaining));
    }
    Ok(())
}
