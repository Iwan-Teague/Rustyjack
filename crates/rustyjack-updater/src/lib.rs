use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone)]
pub struct UpdatePolicy {
    pub public_key_ed25519: [u8; 32],
    pub stage_dir: PathBuf,
    pub install_dir: PathBuf,
    pub unit_restart: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    version: String,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    path: String,
    sha256: String,
    mode: String,
    install_to: String,
}

pub async fn apply_update(policy: &UpdatePolicy, url: &str) -> Result<()> {
    let trimmed_url = url.trim();
    if trimmed_url.is_empty() {
        bail!("update url is empty");
    }
    if policy.unit_restart.trim().is_empty() {
        bail!("unit restart name is empty");
    }

    tokio::fs::create_dir_all(&policy.stage_dir)
        .await
        .context("create stage dir")?;

    let incoming_dir =
        policy
            .stage_dir
            .join(format!("incoming-{}-{}", std::process::id(), now_ms()));
    tokio::fs::create_dir_all(&incoming_dir)
        .await
        .context("create incoming dir")?;

    let archive_path = incoming_dir.join("update.tar.zst");
    download_archive(trimmed_url, &archive_path).await?;

    let incoming_dir_clone = incoming_dir.clone();
    let archive_path_clone = archive_path.clone();
    tokio::task::spawn_blocking(move || extract_archive(&archive_path_clone, &incoming_dir_clone))
        .await
        .context("extract archive join")??;

    let verify_dir = incoming_dir.clone();
    let public_key = policy.public_key_ed25519;
    let manifest =
        tokio::task::spawn_blocking(move || verify_manifest_and_files(&verify_dir, public_key))
            .await
            .context("verify manifest join")??;

    let version_dir = policy.stage_dir.join(&manifest.version);
    if tokio::fs::metadata(&version_dir).await.is_ok() {
        tokio::fs::remove_dir_all(&version_dir)
            .await
            .context("remove existing stage version")?;
    }

    tokio::fs::rename(&incoming_dir, &version_dir)
        .await
        .context("rename stage dir")?;

    let install_dir = policy.install_dir.clone();
    tokio::task::spawn_blocking(move || install_files(&manifest, &version_dir, &install_dir))
        .await
        .context("install files join")??;

    restart_unit(&policy.unit_restart).await?;

    Ok(())
}

pub fn parse_public_key_hex(value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).context("decode public key hex")?;
    if bytes.len() != 32 {
        bail!("public key must be 32 bytes, got {}", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

async fn download_archive(url: &str, dest: &Path) -> Result<()> {
    if let Some(path) = local_archive_path(url) {
        let meta = tokio::fs::metadata(&path)
            .await
            .with_context(|| format!("stat {}", path.display()))?;
        if !meta.is_file() {
            bail!("update archive is not a file: {}", path.display());
        }
        tokio::fs::copy(&path, dest)
            .await
            .with_context(|| format!("copy {} -> {}", path.display(), dest.display()))?;
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(dest)
            .await
            .context("open copied archive")?;
        file.sync_all().await.context("sync archive file")?;
        return Ok(());
    }

    let client = reqwest::Client::new();
    let response = client.get(url).send().await?.error_for_status()?;

    let mut file = tokio::fs::File::create(dest)
        .await
        .context("create archive file")?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("download chunk")?;
        file.write_all(&chunk)
            .await
            .context("write archive chunk")?;
    }
    file.sync_all().await.context("sync archive file")?;
    Ok(())
}

fn local_archive_path(url: &str) -> Option<PathBuf> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(path) = trimmed.strip_prefix("file://") {
        if path.is_empty() {
            return None;
        }
        return Some(PathBuf::from(path));
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() || path.exists() {
        Some(path)
    } else {
        None
    }
}

fn extract_archive(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = File::open(archive_path).context("open archive")?;
    let decoder = zstd::Decoder::new(file).context("open zstd decoder")?;
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().context("read archive entries")? {
        let mut entry = entry.context("archive entry")?;
        let path = entry.path().context("archive entry path")?;
        validate_rel_path(&path)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            bail!("archive contains unsupported link: {}", path.display());
        }
        let dest_path = dest_dir.join(&path);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent).context("create archive parent")?;
        }
        entry.unpack(&dest_path).context("unpack archive entry")?;
    }

    let _ = fs::remove_file(archive_path);
    Ok(())
}

fn verify_manifest_and_files(stage_dir: &Path, public_key: [u8; 32]) -> Result<Manifest> {
    let manifest_path = stage_dir.join("manifest.json");
    let sig_path = stage_dir.join("manifest.sig");

    let manifest_bytes = fs::read(&manifest_path).context("read manifest")?;
    let sig_bytes = fs::read(&sig_path).context("read manifest signature")?;

    let key = VerifyingKey::from_bytes(&public_key).context("invalid public key")?;
    let signature = Signature::from_slice(&sig_bytes).context("invalid signature")?;
    key.verify(&manifest_bytes, &signature)
        .context("manifest signature verification failed")?;

    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).context("parse manifest")?;
    if manifest.version.trim().is_empty() {
        bail!("manifest version is empty");
    }
    if manifest.files.is_empty() {
        bail!("manifest files is empty");
    }

    for file in &manifest.files {
        let rel = Path::new(&file.path);
        validate_rel_path(rel)?;
        let file_path = stage_dir.join(rel);
        let expected = decode_sha256(&file.sha256)?;
        let actual = sha256_file(&file_path)?;
        if expected != actual {
            bail!("sha256 mismatch for {}", file.path);
        }
        if file.install_to.trim().is_empty() {
            bail!("install_to is empty for {}", file.path);
        }
    }

    Ok(manifest)
}

fn install_files(manifest: &Manifest, stage_dir: &Path, install_dir: &Path) -> Result<()> {
    for file in &manifest.files {
        let src = stage_dir.join(&file.path);
        let dest = resolve_install_path(&file.install_to, install_dir)?;
        install_one(&src, &dest, &file.mode)?;
    }
    Ok(())
}

fn install_one(src: &Path, dest: &Path, mode: &str) -> Result<()> {
    let mode_value = parse_mode(mode)?;
    let file_name = dest
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("install_to missing filename"))?;
    let tmp = dest.with_file_name(format!("{}.new", file_name.to_string_lossy()));
    let prev = dest.with_file_name(format!("{}.prev", file_name.to_string_lossy()));

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).context("create install parent")?;
    }

    let mut src_file = File::open(src).context("open staged file")?;
    let mut tmp_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)
        .context("open temp install file")?;

    std::io::copy(&mut src_file, &mut tmp_file).context("copy staged file")?;
    tmp_file.sync_all().context("sync temp file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(mode_value);
        fs::set_permissions(&tmp, perms).context("set file permissions")?;
    }

    if dest.exists() {
        let _ = fs::remove_file(&prev);
        fs::rename(dest, &prev).context("backup existing file")?;
    }

    fs::rename(&tmp, dest).context("replace binary")?;
    fsync_parent(dest)?;

    Ok(())
}

fn resolve_install_path(install_to: &str, install_dir: &Path) -> Result<PathBuf> {
    let trimmed = install_to.trim();
    if trimmed.is_empty() {
        bail!("install_to is empty");
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        validate_abs_path(path)?;
        Ok(path.to_path_buf())
    } else {
        validate_rel_path(path)?;
        Ok(install_dir.join(path))
    }
}

fn parse_mode(mode: &str) -> Result<u32> {
    let trimmed = mode.trim().trim_start_matches("0o");
    u32::from_str_radix(trimmed, 8).context("parse file mode")
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).context("open file for sha256")?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).context("read file for sha256")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    Ok(out)
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value.trim()).context("decode sha256")?;
    if bytes.len() != 32 {
        bail!("sha256 must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn validate_rel_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("path is empty");
    }
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                bail!("invalid path component")
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

fn validate_abs_path(path: &Path) -> Result<()> {
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            bail!("install_to contains parent dir traversal");
        }
    }
    Ok(())
}

fn fsync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent dir"))?;
    let dir = File::open(parent).context("open parent dir")?;
    dir.sync_all().context("sync parent dir")?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn restart_unit(unit: &str) -> Result<()> {
    let conn = zbus::Connection::system()
        .await
        .context("systemd dbus connect")?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .context("systemd dbus proxy")?;

    let (_job_path,): (zbus::zvariant::OwnedObjectPath,) = proxy
        .call("RestartUnit", &(unit, "replace"))
        .await
        .context("systemd restart unit")?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn restart_unit(_unit: &str) -> Result<()> {
    bail!("systemd restart is supported on Linux only")
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
