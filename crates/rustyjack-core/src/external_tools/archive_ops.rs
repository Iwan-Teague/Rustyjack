use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Local;

use crate::external_tools::system_shell;

pub fn backup_repository(root: &Path, backup_dir: Option<&Path>) -> Result<PathBuf> {
    let dir = backup_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/root"));
    std::fs::create_dir_all(&dir)?;

    let ts = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let archive = dir.join(format!("rustyjack_backup_{ts}.tar.gz"));
    let parent = root
        .parent()
        .ok_or_else(|| anyhow!("Root path must have a parent directory"))?;
    let name = root
        .file_name()
        .ok_or_else(|| anyhow!("Root path must end with a directory component"))?;
    let name_str = name
        .to_str()
        .ok_or_else(|| anyhow!("Root path must be valid UTF-8"))?;
    let parent_str = parent
        .to_str()
        .ok_or_else(|| anyhow!("Root parent must be valid UTF-8"))?;
    let archive_str = archive
        .to_str()
        .ok_or_else(|| anyhow!("Archive path must be valid UTF-8"))?;

    system_shell::run(
        "tar",
        &["-czf", archive_str, "-C", parent_str, name_str],
    )
    .context("creating backup archive")?;

    Ok(archive)
}
