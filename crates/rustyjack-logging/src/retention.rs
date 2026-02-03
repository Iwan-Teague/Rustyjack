use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use crate::config::LoggingConfig;

const MAX_LOG_BYTES: u64 = 200 * 1024 * 1024;

struct LogFile {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
}

pub fn run_retention(root: &Path, cfg: &LoggingConfig) -> Result<()> {
    let log_root = root.join("logs");
    let mut entries = collect_log_files(&log_root)?;

    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(
            cfg.keep_days.saturating_mul(24 * 60 * 60),
        ))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    entries.retain(|entry| {
        if entry.modified < cutoff {
            if let Err(err) = fs::remove_file(&entry.path) {
                tracing::warn!("Failed to remove old log {}: {}", entry.path.display(), err);
                true
            } else {
                false
            }
        } else {
            true
        }
    });

    let mut total_size: u64 = entries.iter().map(|e| e.size).sum();
    if total_size > MAX_LOG_BYTES {
        entries.sort_by_key(|e| e.modified);
        for entry in entries {
            if total_size <= MAX_LOG_BYTES {
                break;
            }
            if let Err(err) = fs::remove_file(&entry.path) {
                tracing::warn!(
                    "Failed to remove log {} during size cap cleanup: {}",
                    entry.path.display(),
                    err
                );
                continue;
            }
            total_size = total_size.saturating_sub(entry.size);
        }
    }

    Ok(())
}

fn collect_log_files(log_root: &Path) -> Result<Vec<LogFile>> {
    let mut files = Vec::new();
    if !log_root.exists() {
        return Ok(files);
    }

    collect_dir(log_root, &mut files)?;
    let audit_dir = log_root.join("audit");
    if audit_dir.exists() {
        collect_dir(&audit_dir, &mut files)?;
    }

    Ok(files)
}

fn collect_dir(dir: &Path, out: &mut Vec<LogFile>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("iterating {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(name) => name,
            None => continue,
        };

        if !is_log_name(name) {
            continue;
        }

        let metadata = fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        out.push(LogFile {
            path,
            modified,
            size: metadata.len(),
        });
    }

    Ok(())
}

fn is_log_name(name: &str) -> bool {
    const PREFIXES: [&str; 7] = [
        "rustyjackd.log",
        "rustyjack-ui.log",
        "portal.log",
        "usb.log",
        "wifi.log",
        "net.log",
        "crypto.log",
    ];

    if name.starts_with("audit.log") {
        return true;
    }

    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}
