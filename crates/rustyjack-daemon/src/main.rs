#![deny(unsafe_op_in_unsafe_fn)]
use anyhow::Result;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;
use tracing::{info, warn};

mod auth;
mod config;
mod dispatch;
mod jobs;
mod locks;
mod netlink_watcher;
mod server;
mod state;
mod systemd;
mod telemetry;
mod validation;

use config::DaemonConfig;
use state::DaemonState;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = DaemonConfig::from_env();
    let log_cfg = rustyjack_logging::fs::read_config(&config.root_path);
    let _logging_guards = rustyjack_logging::init("rustyjackd", &config.root_path, &log_cfg)?;
    let _log_watcher = match rustyjack_logging::spawn_watcher(&config.root_path, "rustyjackd") {
        Ok(handle) => Some(handle),
        Err(err) => {
            warn!("Logging watcher disabled: {}", err);
            None
        }
    };

    // Wrap entire daemon execution in a component span for log identity
    let span = tracing::info_span!("rustyjackd", component = "rustyjackd");
    let _span_guard = span.enter();

    let state = Arc::new(DaemonState::new(config.clone()));
    let listener = systemd::listener_or_bind(&config)?;

    state.reconcile_on_startup().await;
    systemd::notify_ready();
    systemd::spawn_watchdog_task();
    spawn_retention_task(config.root_path.clone());

    let shutdown = Arc::new(Notify::new());

    let watcher_state = Arc::clone(&state);
    let watcher_shutdown = Arc::clone(&shutdown);
    tokio::spawn(async move {
        tokio::select! {
            result = netlink_watcher::run_netlink_watcher(watcher_state) => {
                if let Err(e) = result {
                    warn!("Netlink watcher stopped with error: {}", e);
                }
            }
            _ = watcher_shutdown.notified() => {
                info!("Netlink watcher stopped by shutdown signal");
            }
        }
    });

    let shutdown_signal = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(err) => {
                warn!("Failed to register SIGTERM handler: {}", err);
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(signal) => signal,
            Err(err) => {
                warn!("Failed to register SIGINT handler: {}", err);
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
        }

        shutdown_signal.notify_waiters();
    });

    info!("rustyjackd ready");
    server::run(listener, Arc::clone(&state), Arc::clone(&shutdown)).await;

    state.jobs.cancel_all().await;
    info!("rustyjackd stopped");
    Ok(())
}

fn spawn_retention_task(root: std::path::PathBuf) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
        loop {
            let cfg = rustyjack_logging::fs::read_config(&root);
            if let Err(err) = rustyjack_logging::run_retention(&root, &cfg) {
                tracing::warn!("Log retention failed: {}", err);
            }
            interval.tick().await;
        }
    });
}
