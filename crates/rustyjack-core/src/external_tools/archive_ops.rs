use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Local;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder;

pub fn backup_repository(root: &Path, backup_dir: Option<&Path>) -> Result<PathBuf> {
    let dir = backup_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/root"));
    std::fs::create_dir_all(&dir)?;

    let ts = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let archive = dir.join(format!("rustyjack_backup_{ts}.tar.gz"));
    let name = root
        .file_name()
        .ok_or_else(|| anyhow!("Root path must end with a directory component"))?;
    let name_str = name
        .to_str()
        .ok_or_else(|| anyhow!("Root path must be valid UTF-8"))?;

    let tar_gz = File::create(&archive).context("creating backup archive file")?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = Builder::new(enc);
    tar.append_dir_all(name_str, root)
        .context("adding repository to backup archive")?;
    let enc = tar.into_inner().context("finalizing backup archive")?;
    enc.finish().context("writing backup archive")?;

    Ok(archive)
}
