use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::LoggingConfig;

pub fn config_path(root: &Path) -> PathBuf {
    root.join("config").join("logging.json")
}

pub fn read_config(root: &Path) -> LoggingConfig {
    let path = config_path(root);
    match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                let cfg = LoggingConfig::default();
                let _ = write_config_atomic(root, &cfg);
                cfg
            } else {
                LoggingConfig::default()
            }
        }
    }
}

pub fn write_config_atomic(root: &Path, cfg: &LoggingConfig) -> Result<()> {
    let path = config_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating logging config dir {}", parent.display()))?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(cfg).context("serializing logging config")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("opening {}", tmp_path.display()))?;
        std::io::Write::write_all(&mut file, &data)
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp_path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("opening {}", tmp_path.display()))?;
        std::io::Write::write_all(&mut file, &data)
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp_path.display()))?;
    }

    fs::rename(&tmp_path, &path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}
