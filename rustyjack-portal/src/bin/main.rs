use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::signal;

use rustyjack_portal::{build_router, run_server, PortalConfig, PortalLogger, PortalState};

#[tokio::main]
async fn main() -> Result<()> {
    let root = resolve_root();
    let _logging_guards = init_logging(&root);

    tracing::info!("Rustyjack Portal starting");
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));

    let config = load_config()?;
    tracing::info!("Portal configuration loaded");
    tracing::info!("  Interface: {}", config.interface);
    tracing::info!("  Bind: {}:{}", config.listen_ip, config.listen_port);
    tracing::info!("  Site dir: {}", config.site_dir.display());
    tracing::info!("  Capture dir: {}", config.capture_dir.display());

    let index_path = config.site_dir.join("index.html");
    let index_html = std::fs::read_to_string(&index_path)
        .with_context(|| format!("reading portal HTML from {}", index_path.display()))?;

    let logger = PortalLogger::new(&config.capture_dir)?;
    let state = PortalState::new(logger, index_html);
    
    let router = build_router(&config, state);
    
    let addr = std::net::SocketAddr::new(config.listen_ip.into(), config.listen_port);
    let listener = std::net::TcpListener::bind(addr)
        .with_context(|| format!("binding portal listener to {}", addr))?;
    
    tracing::info!("Portal server listening on {}", addr);
    
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    
    let server_task = tokio::spawn(async move {
        if let Err(e) = run_server(listener, router, shutdown_rx).await {
            tracing::error!("Portal server error: {}", e);
        }
    });
    
    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            tracing::info!("Received SIGINT, shutting down...");
        }
        _ = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut term = signal(SignalKind::terminate()).expect("failed to setup SIGTERM handler");
                term.recv().await;
            }
            #[cfg(not(unix))]
            {
                futures::future::pending::<()>().await;
            }
        } => {
            tracing::info!("Received SIGTERM, shutting down...");
        }
    }
    
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_task).await;
    
    tracing::info!("Portal shutdown complete");
    Ok(())
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

        let file_appender = tracing_appender::rolling::daily(&log_dir, "portal.log");
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
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
    }

    if let Some(message) = warn_msg {
        tracing::warn!("{message}");
    }

    LoggingGuards {
        _file_guard: file_guard,
    }
}

fn resolve_root() -> PathBuf {
    if let Ok(env_path) = env::var("RUSTYJACK_ROOT") {
        return PathBuf::from(env_path);
    }

    let default = PathBuf::from("/var/lib/rustyjack");
    if default.exists() {
        return default;
    }

    let legacy = PathBuf::from("/root/Rustyjack");
    if legacy.exists() {
        return legacy;
    }

    env::current_dir().unwrap_or_else(|_| PathBuf::from("/var/lib/rustyjack"))
}

fn load_config() -> Result<PortalConfig> {
    let interface = env::var("RUSTYJACK_PORTAL_INTERFACE")
        .unwrap_or_else(|_| "wlan0".to_string());
    
    let listen_ip = env::var("RUSTYJACK_PORTAL_BIND")
        .unwrap_or_else(|_| "192.168.4.1".to_string())
        .parse()
        .context("invalid RUSTYJACK_PORTAL_BIND")?;
    
    let listen_port = env::var("RUSTYJACK_PORTAL_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .context("invalid RUSTYJACK_PORTAL_PORT")?;
    
    let site_dir = env::var("RUSTYJACK_PORTAL_SITE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/rustyjack/portal/site"));
    
    let capture_dir = env::var("RUSTYJACK_PORTAL_CAPTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/rustyjack/loot/Portal"));
    
    let dnat_mode = false;
    let bind_to_device = true;
    let request_timeout = std::time::Duration::from_secs(30);
    let max_body_bytes = 4096;
    let max_concurrency = 32;

    Ok(PortalConfig {
        interface,
        listen_ip,
        listen_port,
        site_dir,
        capture_dir,
        dnat_mode,
        bind_to_device,
        request_timeout,
        max_body_bytes,
        max_concurrency,
    })
}
