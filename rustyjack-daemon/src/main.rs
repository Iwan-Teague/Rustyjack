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
    let _logging_guards = init_tracing(&config);

    // Wrap entire daemon execution in a component span for log identity
    let span = tracing::info_span!("rustyjackd", component = "rustyjackd");
    let _span_guard = span.enter();

    let state = Arc::new(DaemonState::new(config.clone()));
    let listener = systemd::listener_or_bind(&config)?;

    state.reconcile_on_startup().await;
    systemd::notify_ready();
    systemd::spawn_watchdog_task();

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

struct LoggingGuards {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

fn init_tracing(config: &DaemonConfig) -> LoggingGuards {
    use tracing_log::LogTracer;
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    
    let _ = LogTracer::init();

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    
    let stdout_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .compact();
    
    let log_dir = config.root_path.join("logs");
    let mut warn_msg = None;
    if let Err(err) = std::fs::create_dir_all(&log_dir) {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
        tracing::warn!("File logging disabled ({}): {}", log_dir.display(), err);
        return LoggingGuards { _file_guard: None };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o2770))
        {
            warn_msg = Some(format!(
                "Failed to set log directory permissions ({}): {}",
                log_dir.display(),
                err
            ));
        }
    }

    let file_appender = tracing_appender::rolling::daily(&log_dir, "rustyjackd.log");
    let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_ansi(false)
        .compact()
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    if let Some(message) = warn_msg {
        tracing::warn!("{message}");
    }

    LoggingGuards {
        _file_guard: Some(file_guard),
    }
}
