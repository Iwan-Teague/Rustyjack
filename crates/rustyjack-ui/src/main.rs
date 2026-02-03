#![deny(unsafe_op_in_unsafe_fn)]
// This UI binary is Linux-only; building on non-Linux hosts is not supported because
// the application interacts with Linux-specific device files (SPI, GPIO) and system
// commands. Fail early on non-Linux targets with a clear message.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "rustyjack-ui (the UI) is intended to be built on Linux only. Build with a Linux target or use a Linux machine."
);

mod app;
mod config;
mod core;
mod display;
mod input;
mod menu;
mod ops;
mod stats;
mod types;
mod ui;
mod util;

use crate::core::CoreBridge;
use anyhow::Result;
use app::App;

fn main() -> Result<()> {
    let root = CoreBridge::with_root(None)?.root().to_path_buf();
    let log_cfg = rustyjack_logging::fs::read_config(&root);
    let _logging_guards = rustyjack_logging::init("rustyjack-ui", &root, &log_cfg)?;
    let _log_watcher = match rustyjack_logging::spawn_watcher(&root, "rustyjack-ui") {
        Ok(handle) => Some(handle),
        Err(err) => {
            tracing::warn!("Logging watcher disabled: {}", err);
            None
        }
    };

    // Wrap entire UI execution in a component span for log identity
    let span = tracing::info_span!("rustyjack-ui", component = "rustyjack-ui");
    let _span_guard = span.enter();

    App::new()?.run()
}
