# rustyjack-encryption

Lightweight encryption helper crate used across Rustyjack for encrypting loot and Wi‑Fi profiles.

## Responsibilities
- Manage a process-wide encryption key (set/clear/check enabled).
- Toggle encryption for Wi‑Fi profiles and loot independently.
- Encrypt/decrypt bytes and files (AES-GCM via Rust crypto crates).

## API highlights
- `set_encryption_key`, `clear_encryption_key`, `encryption_enabled`.
- Feature toggles: `set_wifi_profile_encryption`, `wifi_profile_encryption_active`, `set_loot_encryption`, `loot_encryption_active`.
- Data helpers: `encrypt_bytes` / `decrypt_bytes`, `encrypt_to_file` / `decrypt_file`.

## Expectations
- Pure Rust crypto (no platform-specific assumptions).
- Key management is in-process; callers are responsible for securely sourcing/storing keys and zeroing when done.

## Notes for contributors
- Keep dependencies minimal and audited.
- Return meaningful errors; avoid panics in crypto paths.
- Consider zeroization and key lifecycle if expanding functionality.

## File-by-file breakdown
- `lib.rs` (single module):
  - Process-wide key management with `once_cell::sync::Lazy` and `RwLock`-guarded `Option<[u8; 32]>`. `set_encryption_key` validates 32 bytes, zeroizes any existing key; `clear_encryption_key` zeroizes and removes the key; `encryption_enabled` checks presence.
  - Feature flags: `WIFI_PROFILE_ENCRYPTION` and `LOOT_ENCRYPTION` toggles with setters/getters to inform callers (UI/core) whether to encrypt those assets.
  - Crypto: AES-256-GCM via `aes_gcm` using random 12-byte nonces (`OsRng`). `encrypt_bytes` prepends nonce to ciphertext; `decrypt_bytes` validates length and decrypts. File helpers `encrypt_to_file`/`decrypt_file` wrap the byte routines.
  - Error handling via `anyhow`; zeroization via `zeroize` for in-memory keys. Callers are responsible for securely sourcing/storing the key material.
