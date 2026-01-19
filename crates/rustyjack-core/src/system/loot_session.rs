use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Local;
use rand::Rng;

use super::sanitize_label;

#[derive(Debug, Clone)]
pub struct LootSession {
    pub dir: PathBuf,
    pub artifacts: PathBuf,
    pub logs: Option<PathBuf>,
}

impl LootSession {
    pub fn new(root: &Path, op: &str, iface: &str) -> Result<Self> {
        let op = sanitize_label(op);
        let iface = sanitize_label(iface);
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let short_id: u16 = rand::thread_rng().gen();
        let id = format!("{}_{}_{}_{}", timestamp, op, iface, format!("{:04x}", short_id));

        let dir = root
            .join("loot")
            .join("Wireless")
            .join("sessions")
            .join(id);
        let artifacts = dir.join("artifacts");
        let logs = if crate::logs_enabled() {
            Some(dir.join("logs"))
        } else {
            None
        };

        fs::create_dir_all(&artifacts)
            .with_context(|| format!("creating {}", artifacts.display()))?;
        if let Some(ref logs_dir) = logs {
            fs::create_dir_all(logs_dir)
                .with_context(|| format!("creating {}", logs_dir.display()))?;
        }

        Ok(Self { dir, artifacts, logs })
    }
}
