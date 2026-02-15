# Area 12 — Loot management + encryption + export (Architecture Doc 2)

**Snapshot analyzed:** `watchdog_shallow_20260213-173640.zip` (unpacked to `/mnt/data/repo/watchdog`)  
**Report date:** 2026-02-14  
**Mode:** Read-only analysis (no repository modifications performed)

## Trust model used for this report

Per your constraints, **only** these sources are treated as normative requirements:

- **Root docs:** `README.md`, `CLAUDE.md`, `AGENTS.md`, `TESTING.md` (repo root)
- **Completed design logs:** `logs/done/*`

Everything else (including older logs, TODOs, comments) is treated as *informational*, not a requirement.

---

## 1) Data classification

### Sensitive data present in “loot” and adjacent storage

**Tier A — Secrets (must never be exported or logged in plaintext)**
- **Encryption key material** (32-byte AES key)  
  - In-memory: process-wide key in `rustyjack-encryption`  
  - At-rest: `rustyjack.key` on USB (hex) (`crates/rustyjack-ui/src/app/encryption.rs:89–118`)
- **Wi‑Fi PSKs / credentials** in Wi‑Fi profiles  
  - Stored under `root/wifi/profiles/*` and optionally encrypted (`crates/rustyjack-core/src/system/mod.rs:3753–3815`)
- **Discord webhook URL** (`root/discord_webhook.txt`)  
  - Can be encrypted to `discord_webhook.txt.enc` (`crates/rustyjack-ui/src/app/encryption.rs:940–977`)

**Tier B — Highly sensitive telemetry (encrypt at rest; export only in encrypted form)**
- **Captured traffic artifacts** (e.g., PCAPs), which can include credentials/tokens/content
  - Example: MITM PCAP paths under `loot/Ethernet/...` (`crates/rustyjack-core/src/system/mod.rs:820–960`)
- **Any credential capture logs** (even if later summarized)
  - Report generator intentionally avoids printing actual creds, but still reads them into memory (`crates/rustyjack-ui/src/app/report.rs:1240–1385`)

**Tier C — Sensitive identifiers / metadata (redact in logs; encrypt at rest if feasible)**
- **SSID/BSSID**, IPs, MACs, hostnames, device banners
  - Ethernet inventory JSON includes IP/hostname/banners/etc (`crates/rustyjack-core/src/operations.rs:690–752`)
- **Scan logs / reports** that include network labels and paths
  - Scan log loot path builder (`crates/rustyjack-core/src/system/mod.rs:520–553`)

### Handling requirements implied by trusted docs

- **Sensitive data redaction** is expected for logs and outputs (root `README.md` “Sensitive Data Redaction”, `README.md:270–278`).
- “Loot” has a defined structure and the code should write within it (trusted: `logs/done/loot_management.md:12–35`).
- Encryption crate behavior is defined (trusted: `logs/done/crate_rustyjack_encryption.md:15–41`) and must remain correct (AES-GCM, random nonce, nonce prepended, key in RAM, etc.).

### Practical policy for this area (recommended)
- Tier A: **never export in plaintext**; require explicit user opt-in + clear warnings if export is attempted while unencrypted.
- Tier B: **encrypt-at-rest by default** (or at minimum: encrypt-on-write when encryption is enabled).
- Tier C: **minimize**; redact in logs; keep only what is necessary for operational use.

---

## 2) Path safety audit

### What exists today (good)
- **Traversal prevention for loot paths:** `resolve_loot_path()` canonicalizes and checks `starts_with(root)` (`crates/rustyjack-core/src/operations.rs:5705–5728`).  
  This is the strongest “no escape” guard in the codebase for loot paths.
- **SSID/BSSID sanitization (directory component):** `wireless_target_directory()` replaces non `[A-Za-z0-9_-]` with `_` (`crates/rustyjack-core/src/operations.rs:5730–5769`).
- **Mount name sanitization:** `sanitize_mount_name()` for mount points (USB) (`crates/rustyjack-core/src/mount.rs:847–872`).

### Gaps (issues)
1) **No length limits on directory/file components**
- `wireless_target_directory()` and `sanitize_label()` can produce arbitrarily long components (risk: `ENAMETOOLONG`, UI crashes, zip/export failures).
- `sanitize_label()` is used in loot/Scan filenames (`crates/rustyjack-core/src/system/mod.rs:520–553`) and in Ethernet logging and elsewhere.

2) **Sanitization collisions**
- Different SSIDs can map to the same sanitized directory (e.g., `a/b` and `a_b`).  
  This can silently merge loot across targets.

3) **Report generation uses `join(network)` without explicit sanitization**
- `reports_root.join(network)` (`crates/rustyjack-ui/src/app/report.rs:513–520`) assumes `network` is safe.  
  Today it is likely sourced from directory names, but a malicious directory name created inside loot could produce traversal or confusing behavior unless the value is constrained.

### Recommended “safe path component” rule set
- Normalize to a **single safe component**:
  - Allowed: `[A-Za-z0-9._-]` (or your existing `[A-Za-z0-9_-]`).
  - Convert everything else to `_`.
- Enforce a **max byte length** (e.g., 64 or 80 bytes).
- Preserve uniqueness by appending a short hash suffix of the original (e.g., `_<hex8>`).
- For “empty” results, use a stable fallback like `unknown_<hex8>`.

---

## 3) Crypto audit (AES-GCM, key lifecycle, zeroization, correctness)

### What exists today (good / matches trusted design notes)
- **Algorithm:** AES-256-GCM via `aes_gcm::Aes256Gcm` (`crates/rustyjack-encryption/src/lib.rs:1–13`).
- **Nonce:** 12 bytes from `OsRng`, prepended to ciphertext (`crates/rustyjack-encryption/src/lib.rs:64–100`).
- **Decrypt:** reads nonce prefix and verifies tag via `decrypt()` (`crates/rustyjack-encryption/src/lib.rs:102–133`).
- **Key replacement and clearing:** previous key is zeroized before replacement; key is zeroized on clear (`crates/rustyjack-encryption/src/lib.rs:31–48`).

### Primary crypto risks
1) **Nonce uniqueness relies on randomness only**
- Random 96-bit nonces are standard and generally safe, but AES‑GCM’s hard requirement is **never reuse a nonce with the same key**.
- Recommendation: either
  - keep random nonces but **bound the number of encryptions per key** and document the bound, or
  - adopt a deterministic unique nonce scheme (monotonic counter stored durably, or per-file random 96-bit with a key-per-file scheme).

2) **Key copies exist and are not zeroized**
- `current_key()` returns a copy of the key bytes (`crates/rustyjack-encryption/src/lib.rs:50–58`), and `encrypt_bytes()`/`decrypt_bytes()` use it (`crates/rustyjack-encryption/src/lib.rs:64–83`, `114–129`).  
  Those stack copies are not wiped.

3) **Keyfile parsing uses heap strings and does not zeroize intermediate buffers**
- `parse_key_file()` reads bytes into a `Vec<u8>` and then a `String` (`crates/rustyjack-ui/src/app/encryption.rs:149–176`), leaving key material in memory beyond scope.

4) **In-place encryption/decryption for loot and profiles is not transactional**
- A crash between `write(dest)` and `remove(source)` can leave:
  - both plaintext and ciphertext (confidentiality leak), or
  - only partial ciphertext (data loss), depending on the order.

### Recommended crypto hardening (concrete)
- Wrap key copies in `zeroize::Zeroizing<[u8; 32]>` or similar.
- Implement **atomic encryption-to-file**:
  - write to `dest.tmp` (0600),
  - `fsync(file)`,
  - `rename(dest.tmp → dest)`,
  - `fsync(parent_dir)`.
- Add a small header/version in ciphertext format: `b"RJENC\0\1" || nonce || ciphertext` (helps future migrations).
- Consider **AAD (associated authenticated data)**:
  - bind ciphertext to context like `b"loot"` / `b"wifi_profile"` to prevent accidental swapping across types.

---

## 4) Export safety (USB mount + copy + robustness)

### What exists today (good)
- The **core mount module** enforces safe mount options: `MS_NOSUID | MS_NODEV | MS_NOEXEC` and includes `sync` for vfat (`crates/rustyjack-core/src/mount.rs:651–744`).
- The **log export** path does durability work:
  - `sync_all()` on the file,
  - `syncfs()` on the mount,
  - unmount (`crates/rustyjack-core/src/operations.rs:3657–3704`).

### Gaps (issues)
- **Loot export (UI `transfer_to_usb`) uses `fs::copy` with no durability guarantees** and does not `fsync` the destination or sync the filesystem (`crates/rustyjack-ui/src/app/usb.rs:110–182`).
- No **free-space preflight** for loot export (can fill USB, leaving partial sets).
- No **transaction marker** (e.g., `.incomplete` sentinel) to differentiate partial exports after failure/power loss.
- No explicit policy gate that prevents exporting plaintext loot when encryption is expected.

### Recommended export flow
- Create an export session dir: `Rustyjack_Loot/.staging_<timestamp>/...`
- Copy each file as:
  - open source, stream to `dest.tmp`,
  - `fsync(dest.tmp)`, rename to final name,
  - track progress.
- After all files copied:
  - write `MANIFEST.json` (list + sizes + hashes),
  - `fsync` manifest, `syncfs(mount)`,
  - atomically rename staging dir to `Rustyjack_Loot/<timestamp>/`,
  - optionally show “Safe to remove USB”.
- If failure:
  - leave `.staging_*` for a resumable cleanup path, or remove it safely.

---

## 5) Findings (18 total)

Each finding is formatted as:

**Problem → Why → Where → Fix → Fixed version looks like**

### F1 — Encrypted file writes are not atomic
- **Problem:** `encrypt_to_file()` uses `fs::write()` directly.
- **Why:** Power loss or crash can leave a truncated ciphertext file; later decrypt fails and plaintext may already be deleted by callers.
- **Where:** `crates/rustyjack-encryption/src/lib.rs:86–100`
- **Fix:** Add `encrypt_to_file_atomic()` that writes to temp + `fsync` + `rename` + `fsync(dir)`.
- **Fixed version looks like:**
  ```rust
  encrypt_to_file_atomic(dest, plaintext):
    write dest.tmp (0600)
    file.sync_all()
    rename(dest.tmp, dest)
    fsync(parent_dir)
  ```

### F2 — Loot “encrypt in place” is not transactional
- **Problem:** Loot encryption deletes plaintext after writing ciphertext, with no transaction boundary.
- **Why:** Crash between `encrypt_to_file(dest)` and `remove_file(path)` can leak plaintext or lose data (if ciphertext partial).
- **Where:** `crates/rustyjack-ui/src/app/encryption.rs:622–679`
- **Fix:** Use atomic ciphertext write and only delete plaintext after durable commit; optionally keep a small journal per file.
- **Fixed version looks like:** Plaintext removed **only after** `encrypt_to_file_atomic()` succeeds and destination is synced.

### F3 — Loot decrypt “write plaintext” is not atomic
- **Problem:** Decrypt path uses `fs::write(dest, data)` then removes `.enc`.
- **Why:** Crash can leave partial plaintext; future tooling may treat it as valid.
- **Where:** `crates/rustyjack-ui/src/app/encryption.rs:655–681`
- **Fix:** Use `write_atomic(dest, data, 0600)` pattern.
- **Fixed version looks like:** `dest` is either the old correct file or the new correct file; never partial.

### F4 — Wi‑Fi profile decrypt/write path is not atomic
- **Problem:** Profile conversion between `.json` and `.enc` uses `fs::write`.
- **Why:** Same crash/partial-file risk; also possible confidentiality leak if both remain.
- **Where:** `crates/rustyjack-ui/src/app/encryption.rs:446–509`
- **Fix:** Use atomic write + delete-on-commit.
- **Fixed version looks like:** Conversion creates new file durably, then deletes old file.

### F5 — Discord webhook disable leaves both plaintext and ciphertext
- **Problem:** When disabling webhook encryption, code writes plaintext but does not remove `.enc`.
- **Why:** Secret ends up duplicated; one can be stale, increasing attack surface and confusion.
- **Where:** `crates/rustyjack-ui/src/app/encryption.rs:965–977`
- **Fix:** After successful plaintext write + fsync, remove `discord_webhook.txt.enc` (or keep only enc and load-on-demand).
- **Fixed version looks like:** Exactly one canonical representation exists, consistent with the toggle.

### F6 — Key generation doesn’t zeroize the on-stack key after use
- **Problem:** `generate_encryption_key_on_usb()` sets the key and writes hex, but does not wipe the local `key`.
- **Why:** Key remains in stack memory until reused; not catastrophic, but avoidable.
- **Where:** `crates/rustyjack-ui/src/app/encryption.rs:102–118`
- **Fix:** `key.zeroize()` before returning; avoid string hex creation without wiping.
- **Fixed version looks like:** `let mut key = ...; ...; set_encryption_key(&key)?; key.zeroize();`

### F7 — Keyfile parsing leaves key material in heap buffers
- **Problem:** `parse_key_file()` builds a `String` and does not wipe buffers.
- **Why:** Secret remains in heap allocations beyond scope (until reused).
- **Where:** `crates/rustyjack-ui/src/app/encryption.rs:149–176`
- **Fix:** Use `Zeroizing<Vec<u8>>` for file bytes and decode hex without `String` (or wipe the string).
- **Fixed version looks like:** Key bytes never appear in an owned `String`.

### F8 — Key copies returned by `current_key()` are not wiped
- **Problem:** `current_key()` returns a copy of `[u8; 32]`.
- **Why:** Additional key copies increase exposure time in memory dumps.
- **Where:** `crates/rustyjack-encryption/src/lib.rs:50–83`
- **Fix:** Return a `Zeroizing<KeyBytes>` or perform encryption inside a closure while holding a guarded reference.
- **Fixed version looks like:** No long-lived key copies outside the lock scope (or copies are wiped on drop).

### F9 — Nonce uniqueness depends on RNG only; no guardrails
- **Problem:** AES-GCM requires never reusing nonce+key; random nonces make reuse unlikely but not structurally prevented.
- **Why:** A single nonce reuse can catastrophically break confidentiality/integrity for affected messages.
- **Where:** `crates/rustyjack-encryption/src/lib.rs:64–83`
- **Fix:** Add a per-key encryption counter (persisted) or define and enforce a safe upper bound per key; document it.
- **Fixed version looks like:** Nonce generation can’t repeat for the same key within expected operational limits.

### F10 — No ciphertext format versioning / magic header
- **Problem:** Encrypted files are `nonce || ciphertext` with no header.
- **Why:** Future migrations can’t reliably detect format; accidental input can cause confusing errors.
- **Where:** `crates/rustyjack-encryption/src/lib.rs:86–109`
- **Fix:** Prepend `MAGIC + VERSION`, then nonce, then ciphertext.
- **Fixed version looks like:** Decrypt rejects non-matching magic early and clearly.

### F11 — Loot target directory names can collide and can exceed FS limits
- **Problem:** Sanitization replaces invalid chars but doesn’t cap length or guarantee uniqueness.
- **Why:** `ENAMETOOLONG` failures; silent mixing of different targets into the same directory.
- **Where:** `wireless_target_directory()` (`crates/rustyjack-core/src/operations.rs:5730–5769`), `sanitize_label()` (`crates/rustyjack-core/src/system/mod.rs:1485–1499`)
- **Fix:** Implement `safe_component(original) -> (sanitized, hash_suffix)` with length cap.
- **Fixed version looks like:** `MySSID...` becomes `MySSID_<hash8>` and always fits.

### F12 — Report output directory join is not explicitly sanitized
- **Problem:** `reports_root.join(network)` trusts `network`.
- **Why:** A malicious directory name inside loot could steer writes or cause confusion.
- **Where:** `crates/rustyjack-ui/src/app/report.rs:513–520`
- **Fix:** Require `network` to be a *validated existing directory name* under loot and/or pass through `resolve_loot_path`.
- **Fixed version looks like:** Refuse names containing path separators, or resolve and verify under root.

### F13 — Ethernet inventory JSON is written non-atomically
- **Problem:** `fs::write()` writes inventory output directly.
- **Why:** Crash/power loss can leave partial JSON; downstream parsers may fail.
- **Where:** `crates/rustyjack-core/src/operations.rs:750–752`
- **Fix:** Use the existing `write_atomic()` pattern (or introduce a shared atomic writer for loot).
- **Fixed version looks like:** `inventory_*.json` is always complete or absent.

### F14 — Private file writes truncate in place; no durable commit
- **Problem:** `write_private_file()` truncates and writes, but does not `fsync`.
- **Why:** Power loss can corrupt profiles/config; integrity isn’t guaranteed.
- **Where:** `crates/rustyjack-core/src/system/mod.rs:4146–4204`
- **Fix:** Write to temp + `fsync` + `rename` + `fsync(dir)`, while preserving `0600`.
- **Fixed version looks like:** Updates are crash-safe.

### F15 — Loot export to USB has no fsync/syncfs or transactional staging
- **Problem:** `transfer_to_usb()` uses `fs::copy()` file-by-file.
- **Why:** Partial exports after unplug/power loss; no way to know completeness; risk of corrupted files.
- **Where:** `crates/rustyjack-ui/src/app/usb.rs:110–182`
- **Fix:** Copy via temp files + fsync, then `syncfs` at end; add manifest + staging dir.
- **Fixed version looks like:** Export produces either a complete timestamped export or an explicitly marked incomplete staging folder.

### F16 — Loot export lacks free-space preflight and size caps
- **Problem:** No check that USB has sufficient free space for loot.
- **Why:** Filling the device produces partial output and user confusion.
- **Where:** `crates/rustyjack-ui/src/app/usb.rs:110–182`
- **Fix:** Compute total size (streaming WalkDir metadata) and compare to filesystem free space; abort early.
- **Fixed version looks like:** User sees “Need X MB free, have Y MB” and export doesn’t start.

### F17 — “Disable all encryptions” can leave mixed state after errors
- **Problem:** Errors are accumulated, but operations are not rolled back.
- **Why:** Partial decrypt/encrypt produces inconsistent state (some `.enc`, some plaintext) and undermines policy.
- **Where:** `crates/rustyjack-ui/src/app/encryption.rs:332–406`
- **Fix:** Use a per-toggle transaction strategy: verify prereqs, process files, then flip the config flag only on success; record failures.
- **Fixed version looks like:** Flags reflect actual on-disk state.

### F18 — Redaction helpers exist but aren’t wired broadly into logging
- **Problem:** `redact_json()` / `redact_string()` exist but no widespread application is visible.
- **Why:** Sensitive values can leak through logs or exported reports.
- **Where:** `crates/rustyjack-core/src/redact.rs:1–218` (helpers), plus many `tracing::info!` call sites.
- **Fix:** Standardize: before logging structured payloads, run `redact_json()`; for text, apply `redact_string()` on known-dangerous lines.
- **Fixed version looks like:** Logs retain operational value without credential/token leakage.

---


### Addendum — Untrusted device banners can poison loot outputs (repo‑verified)
- **Problem:** Port-scan “banner” strings are written verbatim into loot text and JSON outputs.
- **Why:** Banners are attacker-controlled. Unescaped newlines and control characters can forge log/loot entries, confuse parsers/UI rendering, and (if viewed in a terminal) potentially trigger terminal escape-sequence mischief.
- **Where:** `crates/rustyjack-core/src/operations.rs` (portscan loot formatting that writes `b.banner` directly).
- **Fix:** Treat banners/hostnames as untrusted display data:
  - escape `\r`/`\n` and other control bytes before writing,
  - optionally strip/encode ANSI escape sequences,
  - consider length caps per banner to avoid “one host writes megabytes”.
- **Fixed version looks like:** `escape_log_value(b.banner)` (or equivalent) applied consistently for both `.txt` and `.json` loot outputs.

## 6) Test plan (focused on correctness + robustness)

### A. Power loss / crash safety
1) **Atomic write regression**
- Induce termination (SIGKILL) during:
  - `handle_eth_inventory` JSON write
  - loot encrypt/decrypt conversions
  - Wi‑Fi profile conversion
- Expected:
  - No partially written JSON/plaintext/ciphertext files.
  - Either old file remains or new file is complete.
  - If conversion is mid-flight, state is marked (staging/journal) and recoverable.

2) **USB export durability**
- Pull power / unmount mid-copy.
- Expected:
  - Exports land under a staging directory with a clear “incomplete” marker.
  - A subsequent export can resume or clean staging safely.

### B. Malicious / pathological SSID strings
Test inputs (and variants with Unicode):
- `../../etc/passwd`
- `a/b\c:d*e?f"g<h>i|j`
- `"."`, `".."`, `""` (empty)
- Very long SSID-like strings (> 255 bytes)
Expected:
- Sanitization never produces traversal.
- Component length is capped.
- Collisions are avoided (hash suffix).

### C. Permission regression
- Verify modes/ownership for:
  - `root/wifi/profiles` and files (expect 0700 dir, 0600 files as per current implementation)
  - `root/loot` and newly created subdirs/files
  - exported USB tree
Expected:
- Secrets are not world-readable.
- The UI’s effective user can still read what it needs (or the policy explicitly requires root-only).

### D. Export failure recovery
- Simulate:
  - disk full on USB,
  - read error from source file,
  - write error (permission/mount ro),
  - unplug during finalize step.
Expected:
- Clear user-facing error message.
- No silent truncation in final “completed” directory.
- Staging artifacts are either cleaned up or left with explicit incomplete marker + safe resume/cleanup path.

---

## Appendix — Current loot structure (trusted: logs/done/loot_management.md)

- `loot/Wireless/<SSID>_<BSSID>/...`
- `loot/Ethernet/<network>/...`
- `loot/reports/<network>/report.md`
- `loot/Scan/<label>_<timestamp>.txt`

(See `logs/done/loot_management.md:12–35` and the path builders in core.)
