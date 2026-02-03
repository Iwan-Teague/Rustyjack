use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::config::LoggingConfig;
use crate::fs::{config_path, read_config};
use crate::init::apply;

pub fn apply_env(cfg: &LoggingConfig) {
    if cfg.enabled {
        std::env::remove_var("RUSTYJACK_LOGS_DISABLED");
    } else {
        std::env::set_var("RUSTYJACK_LOGS_DISABLED", "1");
    }
}

pub fn spawn_watcher(root: &Path, component: &str) -> Result<JoinHandle<()>> {
    let root = root.to_path_buf();
    let component = component.to_string();
    let path = config_path(&root);
    let watch_dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing logging config parent dir"))?
        .to_path_buf();

    std::fs::create_dir_all(&watch_dir)
        .with_context(|| format!("creating logging config dir {}", watch_dir.display()))?;

    let handle = thread::spawn(move || {
        let (tx, rx) = mpsc::channel();
        let mut watcher = match notify::recommended_watcher(tx) {
            Ok(watcher) => watcher,
            Err(err) => {
                tracing::warn!("Failed to start logging watcher: {}", err);
                return;
            }
        };

        if let Err(err) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            tracing::warn!("Failed to watch logging config dir: {}", err);
            return;
        }

        loop {
            match rx.recv() {
                Ok(event) => handle_event(event, &root, &component, &path),
                Err(err) => {
                    tracing::warn!("Logging watcher stopped: {}", err);
                    return;
                }
            }
        }
    });

    Ok(handle)
}

fn handle_event(event: notify::Result<Event>, root: &PathBuf, component: &str, path: &PathBuf) {
    let event = match event {
        Ok(event) => event,
        Err(err) => {
            tracing::warn!("Logging watcher error: {}", err);
            return;
        }
    };

    if !matches!(
        event.kind,
        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
    ) {
        return;
    }

    if !event.paths.iter().any(|p| p == path) {
        return;
    }

    let cfg = read_config(root);
    if let Err(err) = apply(&cfg, component) {
        tracing::warn!("Failed to apply logging config: {}", err);
    }
}
