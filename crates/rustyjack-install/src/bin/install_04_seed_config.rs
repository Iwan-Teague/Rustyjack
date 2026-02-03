use std::env;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use rustyjack_install::atomic_write;

const DEFAULT_COUNTRY: &str = "IE";

fn main() -> Result<()> {
    let target_dir = Path::new("/etc/rustyjack");
    fs::create_dir_all(target_dir).with_context(|| format!("create {}", target_dir.display()))?;

    seed_update_pubkey(target_dir)?;
    seed_wpa_supplicant_conf(target_dir)?;

    Ok(())
}

fn seed_update_pubkey(target_dir: &Path) -> Result<()> {
    let source = if let Ok(hex) = env::var("RUSTYJACK_UPDATE_PUBKEY_HEX") {
        hex
    } else if let Ok(path) = env::var("RUSTYJACK_UPDATE_PUBKEY_FILE_SRC") {
        fs::read_to_string(&path).with_context(|| format!("read {}", path))?
    } else {
        bail!("missing RUSTYJACK_UPDATE_PUBKEY_HEX or RUSTYJACK_UPDATE_PUBKEY_FILE_SRC");
    };

    let key = parse_pubkey_hex(&source)?;
    let normalized = format!("0x{}\n", hex::encode(key));
    let dest = target_dir.join("update_pubkey.ed25519");
    atomic_write(&dest, normalized.as_bytes(), 0o644)?;
    Ok(())
}

fn seed_wpa_supplicant_conf(target_dir: &Path) -> Result<()> {
    let dest = target_dir.join("wpa_supplicant.conf");
    if dest.exists() {
        #[cfg(unix)]
        {
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&dest, perms)
                .with_context(|| format!("chmod {}", dest.display()))?;
        }
        return Ok(());
    }

    let country = env::var("RUSTYJACK_COUNTRY")
        .ok()
        .and_then(|raw| normalize_country(&raw))
        .unwrap_or_else(|| DEFAULT_COUNTRY.to_string());

    let contents = format!(
        "ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev\nupdate_config=0\ncountry={}\n",
        country
    );

    atomic_write(&dest, contents.as_bytes(), 0o600)
        .with_context(|| format!("write {}", dest.display()))?;
    Ok(())
}

fn normalize_country(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() != 2 {
        return None;
    }
    let mut upper = String::with_capacity(2);
    for ch in trimmed.chars() {
        if !ch.is_ascii_alphabetic() {
            return None;
        }
        upper.push(ch.to_ascii_uppercase());
    }
    Some(upper)
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
