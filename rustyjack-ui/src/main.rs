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
mod types;
mod util;

use anyhow::Result;
use std::path::Path;

use app::App;
use crate::core::CoreBridge;

fn main() -> Result<()> {
    let root = CoreBridge::with_root(None)?.root().to_path_buf();
    let _logging_guards = init_logging(&root);

    // Wrap entire UI execution in a component span for log identity
    let span = tracing::info_span!("rustyjack-ui", component = "rustyjack-ui");
    let _span_guard = span.enter();

    App::new()?.run()
}

struct LoggingGuards {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

fn init_logging(root: &Path) -> LoggingGuards {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_line_number(true)
        .compact();

    let log_dir = root.join("logs");
    let mut file_guard = None;
    let mut file_layer = None;
    let mut warn_msg = None;

    if let Err(err) = std::fs::create_dir_all(&log_dir) {
        warn_msg = Some(format!(
            "File logging disabled ({}): {}",
            log_dir.display(),
            err
        ));
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(err) =
                std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o2770))
            {
                warn_msg = Some(format!(
                    "Failed to set log directory permissions ({}): {}",
                    log_dir.display(),
                    err
                ));
            }
        }

        let file_appender = tracing_appender::rolling::daily(&log_dir, "rustyjack-ui.log");
        let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
        file_guard = Some(guard);
        file_layer = Some(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_line_number(true)
                .with_ansi(false)
                .compact()
                .with_writer(file_writer),
        );
    }

    if let Some(layer) = file_layer {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(layer)
            .try_init()
            .ok();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .try_init()
            .ok();
    }

    if let Some(message) = warn_msg {
        tracing::warn!("{message}");
    }

    LoggingGuards {
        _file_guard: file_guard,
    }
}
