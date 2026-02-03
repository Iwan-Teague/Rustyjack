use anyhow::{anyhow, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing parent dir for {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let tmp = temp_path(path);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)
        .with_context(|| format!("open {}", tmp.display()))?;
    file.write_all(data)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", tmp.display()))?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(mode);
        fs::set_permissions(&tmp, perms).with_context(|| format!("chmod {}", tmp.display()))?;
    }

    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    fsync_parent(path)?;
    Ok(())
}

pub fn atomic_copy(src: &Path, dest: &Path, mode: u32) -> Result<()> {
    let data = fs::read(src).with_context(|| format!("read {}", src.display()))?;
    atomic_write(dest, &data, mode)
}

fn temp_path(dest: &Path) -> PathBuf {
    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let tmp_name = format!("{}.new", file_name);
    dest.with_file_name(tmp_name)
}

pub fn fsync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing parent dir for {}", path.display()))?;
    let dir = File::open(parent).with_context(|| format!("open {}", parent.display()))?;
    dir.sync_all()
        .with_context(|| format!("sync {}", parent.display()))?;
    Ok(())
}
