use std::path::Path;

use anyhow::Result;
use once_cell::sync::OnceCell;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_error::ErrorLayer;
use tracing_log::LogTracer;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::reload;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Layer, Registry};
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LoggingConfig;
use crate::targets::{T_CRYPTO, T_NET, T_USB, T_WIFI};
use crate::watch::apply_env;

static RELOAD: OnceCell<reload::Handle<EnvFilter, Registry>> = OnceCell::new();

pub struct LoggingGuards {
    _file_guards: Vec<WorkerGuard>,
}

pub fn init(component: &str, root: &Path, cfg: &LoggingConfig) -> Result<LoggingGuards> {
    let filter = build_filter(cfg);
    let (filter_layer, handle) = reload::Layer::new(filter);
    let _ = RELOAD.set(handle);

    let stdout_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .compact();

    let log_dir = root.join("logs");
    let mut warn_msg: Option<String> = None;

    let base = tracing_subscriber::registry()
        .with(filter_layer)
        .with(ErrorLayer::default())
        .with(stdout_layer);

    let mut guards = Vec::new();

    if let Err(err) = std::fs::create_dir_all(&log_dir) {
        base.try_init().ok();
        let _ = LogTracer::init();
        apply_env(cfg);
        tracing::warn!(
            "File logging disabled ({}): {}",
            log_dir.display(),
            err
        );
        return Ok(LoggingGuards { _file_guards: guards });
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

    let component_appender =
        tracing_appender::rolling::daily(&log_dir, component_log_name(component));
    let (component_writer, component_guard) = tracing_appender::non_blocking(component_appender);
    let component_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_ansi(false)
        .compact()
        .with_writer(component_writer)
        .with_filter(component_targets());
    guards.push(component_guard);

    let (usb_layer, usb_guard) = subsystem_layer(&log_dir, "usb.log", T_USB);
    let (wifi_layer, wifi_guard) = subsystem_layer(&log_dir, "wifi.log", T_WIFI);
    let (net_layer, net_guard) = subsystem_layer(&log_dir, "net.log", T_NET);
    let (crypto_layer, crypto_guard) = subsystem_layer(&log_dir, "crypto.log", T_CRYPTO);
    guards.extend([usb_guard, wifi_guard, net_guard, crypto_guard]);

    let registry = base
        .with(component_layer)
        .with(usb_layer)
        .with(wifi_layer)
        .with(net_layer)
        .with(crypto_layer);

    registry.try_init().ok();
    let _ = LogTracer::init();
    apply_env(cfg);

    if let Some(message) = warn_msg {
        tracing::warn!("{message}");
    }

    Ok(LoggingGuards { _file_guards: guards })
}

pub fn apply(cfg: &LoggingConfig, _component: &str) -> Result<()> {
    let handle = RELOAD
        .get()
        .ok_or_else(|| anyhow::anyhow!("logging not initialized"))?;
    handle.reload(build_filter(cfg))?;
    apply_env(cfg);
    Ok(())
}

fn build_filter(cfg: &LoggingConfig) -> EnvFilter {
    if !cfg.enabled {
        return EnvFilter::new("off");
    }
    EnvFilter::try_new(cfg.level.clone()).unwrap_or_else(|_| EnvFilter::new("info"))
}

fn component_log_name(component: &str) -> String {
    match component {
        "rustyjackd" => "rustyjackd.log".to_string(),
        "rustyjack-ui" => "rustyjack-ui.log".to_string(),
        "portal" => "portal.log".to_string(),
        other => format!("{other}.log"),
    }
}

fn component_targets() -> Targets {
    Targets::new()
        .with_default(LevelFilter::TRACE)
        .with_target(T_USB, LevelFilter::OFF)
        .with_target(T_WIFI, LevelFilter::OFF)
        .with_target(T_NET, LevelFilter::OFF)
        .with_target(T_CRYPTO, LevelFilter::OFF)
}

fn subsystem_layer<S>(
    log_dir: &Path,
    filename: &str,
    target: &'static str,
) -> (
    impl tracing_subscriber::Layer<S> + Send + Sync,
    WorkerGuard,
)
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let appender = tracing_appender::rolling::daily(log_dir, filename);
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_ansi(false)
        .compact()
        .with_writer(writer)
        .with_filter(Targets::new().with_target(target, LevelFilter::TRACE));
    (layer, guard)
}
