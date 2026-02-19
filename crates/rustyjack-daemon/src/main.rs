#![deny(unsafe_op_in_unsafe_fn)]

// Production guardrail: forbid lab builds in release profile.
#[cfg(all(not(debug_assertions), feature = "lab"))]
compile_error!(
    "rustyjack-daemon: the lab feature is not allowed in release builds. Use the default appliance build for production."
);
use anyhow::Result;
use std::panic;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

mod auth;
mod config;
mod dispatch;
mod jobs;
mod locks;
mod netlink_watcher;
mod ops;
mod ops_apply;
mod server;
mod state;
mod systemd;
mod tail;
mod telemetry;
mod validation;

use config::DaemonConfig;
use state::DaemonState;

// Using multi_thread runtime with 2 workers provides:
// 1. Resilience against accidental blocking (won't freeze entire daemon)
// 2. Better utilization of Pi Zero 2 W's 4-core ARM Cortex-A53
// 3. Parallel job execution capability
// All blocking operations should still use spawn_blocking for correctness.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let config = DaemonConfig::from_env();
    ensure_socket_parent(&config.socket_path);
    let log_cfg = rustyjack_logging::fs::read_config(&config.root_path);
    let _logging_guards = rustyjack_logging::init("rustyjackd", &config.root_path, &log_cfg)?;

    // Install panic hook to log panics with backtraces for diagnostics
    install_panic_hook();

    let _log_watcher = match rustyjack_logging::spawn_watcher(&config.root_path, "rustyjackd") {
        Ok(handle) => Some(handle),
        Err(err) => {
            warn!("Logging watcher disabled: {}", err);
            None
        }
    };
    if config.update_pubkey.is_some() {
        info!(
            "update_pubkey loaded from {}",
            config.update_pubkey_path.display()
        );
    } else {
        warn!(
            "update_pubkey missing or invalid at {}",
            config.update_pubkey_path.display()
        );
    }

    // Wrap entire daemon execution in a component span for log identity
    let span = tracing::info_span!("rustyjackd", component = "rustyjackd");
    let _span_guard = span.enter();

    let state = Arc::new(DaemonState::new(config.clone()));
    let listener = systemd::listener_or_bind(&config)?;

    state.reconcile_on_startup().await;
    systemd::notify_ready();
    systemd::spawn_watchdog_task();

    // Global cancellation token for graceful shutdown of background tasks
    let global_cancel = CancellationToken::new();

    // Spawn retention task with cancellation support
    spawn_retention_task(config.root_path.clone(), global_cancel.clone());

    let shutdown = Arc::new(Notify::new());

    // Netlink watcher with shutdown support
    let watcher_state = Arc::clone(&state);
    let watcher_shutdown = Arc::clone(&shutdown);
    let watcher_handle = tokio::spawn(async move {
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

    // Signal handler
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
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
            },
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
            },
        }

        shutdown_signal.notify_waiters();
    });

    info!("rustyjackd ready");
    server::run(listener, Arc::clone(&state), Arc::clone(&shutdown)).await;

    // =========================================================================
    // Graceful shutdown sequence
    // =========================================================================
    info!("Starting graceful shutdown...");

    // 1. Cancel all background tasks
    global_cancel.cancel();

    // 2. Wait for netlink watcher to stop (with timeout)
    let _ = tokio::time::timeout(Duration::from_secs(2), watcher_handle).await;

    // 3. Cancel all jobs and wait for them to complete
    // Use 25 seconds to stay within systemd's default 30s TimeoutStopSec
    let shutdown_timeout = Duration::from_secs(25);
    let still_active = state.jobs.shutdown_gracefully(shutdown_timeout).await;

    if still_active > 0 {
        warn!("Forced shutdown with {} jobs still active", still_active);
    }

    info!("rustyjackd stopped");
    Ok(())
}

fn ensure_socket_parent(path: &Path) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            warn!(
                "failed to create socket parent directory {}: {}",
                parent.display(),
                err
            );
            return;
        }
        if let Err(err) = fs::set_permissions(parent, fs::Permissions::from_mode(0o770)) {
            warn!(
                "failed to set socket directory permissions on {}: {}",
                parent.display(),
                err
            );
        }
    }
}

fn spawn_retention_task(root: std::path::PathBuf, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Log retention task stopped by shutdown signal");
                    break;
                }
                _ = interval.tick() => {
                    let cfg = rustyjack_logging::fs::read_config(&root);
                    if let Err(err) = rustyjack_logging::run_retention(&root, &cfg) {
                        warn!("Log retention failed: {}", err);
                    }
                }
            }
        }
    });
}

/// Install a custom panic hook that logs panics with backtraces.
/// This ensures panics are captured in logs for post-mortem debugging,
/// especially important since systemd will restart the daemon after a panic.
fn install_panic_hook() {
    let default_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info| {
        // Extract panic location
        let location = panic_info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        // Extract panic message
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        };

        // Capture backtrace
        let backtrace = std::backtrace::Backtrace::capture();

        // Log the panic with full context
        error!(
            target: "rustyjackd::panic",
            location = %location,
            message = %message,
            "PANIC: daemon panicked"
        );

        // Log backtrace if available
        let bt_status = backtrace.status();
        if bt_status == std::backtrace::BacktraceStatus::Captured {
            error!(
                target: "rustyjackd::panic",
                backtrace = %backtrace,
                "Panic backtrace"
            );
        } else {
            error!(
                target: "rustyjackd::panic",
                "Backtrace not available (set RUST_BACKTRACE=1 to enable)"
            );
        }

        // Call the default hook to preserve standard panic behavior
        default_hook(panic_info);
    }));
}
