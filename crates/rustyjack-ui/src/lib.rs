#![deny(unsafe_op_in_unsafe_fn)]
// Library interface for rustyjack-ui to enable unit testing
// This exposes internal modules for testing without requiring hardware

#[cfg(not(target_os = "linux"))]
compile_error!(
    "rustyjack-ui is intended to be built on Linux only. Build with a Linux target or use a Linux machine."
);

pub mod app;
pub mod config;
pub mod core;
pub mod display;
pub mod input;
pub mod menu;
pub mod ops;
pub mod stats;
pub mod types;
pub mod ui;
pub mod util;
