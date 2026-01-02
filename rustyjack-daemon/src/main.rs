use anyhow::Result;
use log::{info, warn};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;

mod auth;
mod config;
mod dispatch;
mod jobs;
mod locks;
mod server;
mod state;
mod systemd;
mod telemetry;

use config::DaemonConfig;
use state::DaemonState;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();

    let config = DaemonConfig::from_env();
    let state = Arc::new(DaemonState::new(config.clone()));
    let listener = systemd::listener_or_bind(&config)?;

    state.reconcile_on_startup().await;
    systemd::notify_ready();
    systemd::spawn_watchdog_task();

    let shutdown = Arc::new(Notify::new());
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
