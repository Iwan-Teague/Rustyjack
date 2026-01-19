#![deny(unsafe_op_in_unsafe_fn)]
//! AES-256-GCM helpers and simple process-wide key management.
//! Used by Rustyjack components to encrypt/decrypt small blobs and files.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use once_cell::sync::Lazy;
use rand::RngCore;
use std::fs;
use std::path::Path;
use std::sync::RwLock;
use zeroize::Zeroize;

type KeyBytes = [u8; 32];

static ENCRYPTION_KEY: Lazy<RwLock<Option<KeyBytes>>> = Lazy::new(|| RwLock::new(None));
static WIFI_PROFILE_ENCRYPTION: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));
static LOOT_ENCRYPTION: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));

/// Set the global encryption key (32 bytes).
pub fn set_encryption_key(key: &[u8]) -> anyhow::Result<()> {
    if key.len() != 32 {
        anyhow::bail!("Encryption key must be 32 bytes");
    }
    let mut guard = ENCRYPTION_KEY
        .write()
        .map_err(|_| anyhow!("Failed to lock encryption key"))?;
    if let Some(mut existing) = guard.take() {
        existing.zeroize();
    }
    let mut kb = [0u8; 32];
    kb.copy_from_slice(key);
    *guard = Some(kb);
    Ok(())
}

/// Clear any loaded encryption key.
pub fn clear_encryption_key() {
    if let Ok(mut guard) = ENCRYPTION_KEY.write() {
        if let Some(mut kb) = guard.take() {
            kb.zeroize();
        }
    }
}

/// Check if encryption key is loaded.
pub fn encryption_enabled() -> bool {
    ENCRYPTION_KEY
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|_| true))
        .unwrap_or(false)
}

fn current_key() -> anyhow::Result<KeyBytes> {
    ENCRYPTION_KEY
        .read()
        .map_err(|_| anyhow!("Failed to read encryption key"))?
        .ok_or_else(|| anyhow!("Encryption key not loaded"))
}

/// Control whether WiFi profiles should be encrypted on write.
pub fn set_wifi_profile_encryption(enabled: bool) {
    if let Ok(mut guard) = WIFI_PROFILE_ENCRYPTION.write() {
        *guard = enabled;
    }
}

/// Check if WiFi profile encryption is enabled.
pub fn wifi_profile_encryption_active() -> bool {
    WIFI_PROFILE_ENCRYPTION.read().map(|g| *g).unwrap_or(false)
}

/// Control whether loot encryption is enabled (for UI awareness).
pub fn set_loot_encryption(enabled: bool) {
    if let Ok(mut guard) = LOOT_ENCRYPTION.write() {
        *guard = enabled;
    }
}

/// Check if loot encryption is enabled.
pub fn loot_encryption_active() -> bool {
    LOOT_ENCRYPTION.read().map(|g| *g).unwrap_or(false)
}

/// Encrypt bytes with AES-256-GCM, returning nonce+ciphertext.
pub fn encrypt_bytes(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = current_key()?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("Invalid encryption key: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt bytes produced by `encrypt_bytes`.
pub fn decrypt_bytes(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() < 12 {
        anyhow::bail!("Encrypted data too short");
    }
    let key = current_key()?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("Invalid encryption key: {e}"))?;
    let (nonce_bytes, ct) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow!("Decryption failed - wrong key or corrupted data: {e}"))?;
    Ok(plaintext)
}

/// Encrypt and write to a file (overwrites).
pub fn encrypt_to_file(path: &Path, plaintext: &[u8]) -> anyhow::Result<()> {
    let data = encrypt_bytes(plaintext)?;
    fs::write(path, data)?;
    Ok(())
}

/// Read and decrypt from a file.
pub fn decrypt_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let data = fs::read(path)?;
    decrypt_bytes(&data)
}
