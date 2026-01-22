use std::env;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use rustyjack_install::atomic_write;

fn main() -> Result<()> {
    let target_dir = Path::new("/etc/rustyjack");
    fs::create_dir_all(target_dir)
        .with_context(|| format!("create {}", target_dir.display()))?;

    let source = if let Ok(hex) = env::var("RUSTYJACK_UPDATE_PUBKEY_HEX") {
        hex
    } else if let Ok(path) = env::var("RUSTYJACK_UPDATE_PUBKEY_FILE_SRC") {
        fs::read_to_string(&path)
            .with_context(|| format!("read {}", path))?
    } else {
        bail!("missing RUSTYJACK_UPDATE_PUBKEY_HEX or RUSTYJACK_UPDATE_PUBKEY_FILE_SRC");
    };

    let key = parse_pubkey_hex(&source)?;
    let normalized = format!("0x{}\n", hex::encode(key));
    let dest = target_dir.join("update_pubkey.ed25519");
    atomic_write(&dest, normalized.as_bytes(), 0o644)?;
    Ok(())
}

fn parse_pubkey_hex(value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).context("decode pubkey hex")?;
    if bytes.len() != 32 {
        bail!("pubkey must be 32 bytes, got {}", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}
