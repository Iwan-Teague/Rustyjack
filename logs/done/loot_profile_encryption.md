# Loot & Profile Encryption
Created: 2026-01-07

Optional encryption for loot and Wi‑Fi profiles using `rustyjack-encryption` (AES-256-GCM).

## How it works
- A process-wide 32-byte key is set via `rustyjack-encryption::set_encryption_key`.
- Feature flags: `set_wifi_profile_encryption` and `set_loot_encryption` toggle encryption for those assets.
- Encryption prepends a random 12-byte nonce; ciphertext written in-place (profiles) or to files via helpers.
- Decryption uses the loaded key; failures indicate missing/wrong key or corruption.

## Integration points
- Wi‑Fi profiles (`wifi/profiles/*.json`) are plaintext by default; can be encrypted if the key and flag are set.
- Loot encryption can be enabled to protect stored captures/logs; UI/core check the flags to decide whether to encrypt on write.

## Expectations
- Key management is caller’s responsibility (source, storage, lifecycle). Keys are held in-process; `clear_encryption_key` zeroizes.
- No hardware key storage; suitable for lightweight protection on the Pi.

## Notes
- If the key is not loaded, decryption will fail; ensure key is set before reading encrypted assets.
- Encryption status is surfaced in the UI toggles (logs disabled/enabled).
