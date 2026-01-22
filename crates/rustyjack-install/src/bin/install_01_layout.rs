use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use rustyjack_install::atomic_copy;

fn main() -> Result<()> {
    let src_root = env::var("RUSTYJACK_INSTALL_SRC")
        .map(PathBuf::from)
        .unwrap_or(env::current_dir().context("read current dir")?);
    let bin_dir = env::var("RUSTYJACK_INSTALL_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| src_root.clone());
    let services_dir = src_root.join("services");
    let socket_src = src_root.join("rustyjackd.socket");

    install_bin(&bin_dir, "rustyjackd", true)?;
    install_bin(&bin_dir, "rustyjack-ui", false)?;
    install_bin(&bin_dir, "rustyjack-portal", false)?;

    install_unit(
        &services_dir.join("rustyjackd.service"),
        Path::new("/etc/systemd/system/rustyjackd.service"),
        true,
    )?;
    install_unit(
        &services_dir.join("rustyjack-ui.service"),
        Path::new("/etc/systemd/system/rustyjack-ui.service"),
        false,
    )?;
    install_unit(
        &services_dir.join("rustyjack-portal.service"),
        Path::new("/etc/systemd/system/rustyjack-portal.service"),
        false,
    )?;
    install_unit(
        &services_dir.join("rustyjack.service"),
        Path::new("/etc/systemd/system/rustyjack.service"),
        false,
    )?;
    install_unit(
        &socket_src,
        Path::new("/etc/systemd/system/rustyjackd.socket"),
        true,
    )?;

    Ok(())
}

fn install_bin(bin_dir: &Path, name: &str, required: bool) -> Result<()> {
    let src = bin_dir.join(name);
    if !src.exists() {
        if required {
            bail!("missing binary {}", src.display());
        }
        return Ok(());
    }
    let dest = Path::new("/usr/local/bin").join(name);
    atomic_copy(&src, &dest, 0o755)
        .with_context(|| format!("install {}", name))?;
    Ok(())
}

fn install_unit(src: &Path, dest: &Path, required: bool) -> Result<()> {
    if !src.exists() {
        if required {
            bail!("missing unit {}", src.display());
        }
        return Ok(());
    }
    atomic_copy(src, dest, 0o644)
        .with_context(|| format!("install {}", dest.display()))?;
    Ok(())
}
