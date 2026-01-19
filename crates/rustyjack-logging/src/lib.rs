#![deny(unsafe_op_in_unsafe_fn)]
pub mod config;
pub mod fs;
pub mod init;
pub mod retention;
pub mod targets;
pub mod watch;

pub use config::LoggingConfig;
pub use init::{apply, init, LoggingGuards};
pub use retention::run_retention;
pub use watch::{apply_env, spawn_watcher};
