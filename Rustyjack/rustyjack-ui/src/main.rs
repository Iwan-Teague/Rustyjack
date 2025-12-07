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
mod stats;

use anyhow::Result;

use app::App;

fn main() -> Result<()> {
    App::new()?.run()
}
