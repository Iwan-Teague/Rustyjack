# Area 13 — Updates & supply‑chain integrity (READ‑ONLY report)

**Date:** 2026-02-14  
**Repo snapshot:** `watchdog/` workspace (Rust)  
**Scope:** `crates/rustyjack-updater` + daemon integration (signature verification, key loading, download pipeline, staging/apply, rollback posture, and “no shelling out” compliance).

> Evidence model: *Constraints* are taken only from repo‑root docs and `logs/done/`. Everything else is implementation evidence (Rust code, configs, scripts).

---

## Evidence & constraints (from trusted docs)

- Updates are treated as **dangerous operations**; the daemon has an env gate for “system updates” (`RUSTYJACKD_DANGEROUS_OPS=true`, commented out by default). `CLAUDE.md:211-211`
- Project direction emphasizes Rust‑native plumbing over “shelling out” (repo includes CI checks around process spawning), so update must not become a hidden compromise pipeline.

---

## 1) Trust model (what is trusted?)

### Trust anchors (must remain trustworthy)
1. **Ed25519 public key material** loaded by the daemon from a local file:
   - Default: `/etc/rustyjack/update_pubkey.ed25519` (hex‑encoded 32‑byte key), loaded at startup. `crates/rustyjack-daemon/src/config.rs:20-209`
2. **The running OS + filesystem permissions** protecting:
   - the public key file in `/etc/rustyjack/`
   - the update stage directory under the daemon root path (default `/opt/rustyjack/update/stage`)
   - the install target directory (`/usr/local/bin`)
3. **The updater binary itself**: if an attacker can replace `rustyjackd` or the updater crate, all bets are off.

### Untrusted inputs
- The **update URL** (string coming from IPC request) and all network responses.
- The **archive bytes** (`update.tar.zst`) and everything inside it.
- The **manifest JSON** and **signature bytes** *until* verified.
- The staged files on disk, unless the staging directory is permission‑hardened (see TOCTOU findings).

### “Trusted once verified”
- After successful verification:
  - `manifest.json` becomes trusted metadata *only within the policy constraints you enforce*.
  - each payload file becomes trusted **only for the exact bytes whose hash was verified** (important: avoid TOCTOU).

---

## 2) Verification chain (exactly what bytes are verified; TOCTOU risks)

### Current chain (as implemented)
1. **Download or copy** the archive to `incoming-<pid>-<ms>/update.tar.zst`. `crates/rustyjack-updater/src/lib.rs:102-139`
2. **Extract** archive entries into the same `incoming-*` directory, rejecting path traversal and rejecting symlinks/hardlinks. `crates/rustyjack-updater/src/lib.rs:159-182`
3. **Verify signature**: verify `manifest.sig` against the **exact byte sequence** of `manifest.json` on disk (no canonicalization). `crates/rustyjack-updater/src/lib.rs:183-219`
4. **Verify payload hashes**: for each file listed in the manifest, compute SHA‑256 of the staged file bytes and compare to the manifest digest. `crates/rustyjack-updater/src/lib.rs:183-219`
5. Install only after all listed files pass SHA‑256 verification.

### What’s verified, precisely
- **Ed25519 verify:** signature checked against raw `manifest.json` bytes as read via `fs::read`. `crates/rustyjack-updater/src/lib.rs:183-219`
- **SHA‑256:** computed over the exact file bytes read during `sha256_file(...)`. `crates/rustyjack-updater/src/lib.rs:290-306`

### TOCTOU (time‑of‑check vs time‑of‑use) risks
The updater verifies hashes, then later re‑opens and copies staged files during install. If anything can modify files in the stage directory between verification and install, the installed bytes may differ from verified bytes.

This is primarily a **local integrity** concern (filesystem permissions and symlink races), not a network signature concern. The clean fix is to bind verification to the install step.

---

## 3) Apply model (staging dir, rename swap, rollback if service fails)

### Current apply model (as implemented)
1. Ensure stage dir exists; create unique `incoming-*` dir. `crates/rustyjack-updater/src/lib.rs:33-90`
2. Download + extract into `incoming-*`.
3. Verify manifest signature + staged file hashes.
4. Rename `incoming-*` → stage version dir named by `manifest.version` (existing version dir removed first, if present). `crates/rustyjack-updater/src/lib.rs:33-90`
5. For each manifest entry, atomically replace each destination file using a `.new` temp and `.prev` backup. `crates/rustyjack-updater/src/lib.rs:229-269`
6. Restart systemd unit via D‑Bus (`RestartUnit`). `crates/rustyjack-updater/src/lib.rs:351-372`

### Observed rollback posture
- Per‑file rollback material exists (`*.prev`), but rollback is not automatic. `crates/rustyjack-updater/src/lib.rs:229-269`
- No explicit “commit point” across multi‑file updates; power loss mid‑loop can leave a mixed set.
- No health check after restart; updater may report success even if the service immediately fails.


## No shelling out compliance

- The updater implementation does **not** spawn external commands; it relies on Rust APIs for download, hashing, and filesystem operations.
- The systemd restart path is performed via D‑Bus (zbus) rather than invoking `systemctl`, which aligns with the repo’s “avoid shelling out” direction. `crates/rustyjack-updater/src/lib.rs:351-372`

---

## 4) Network robustness (timeouts, partial download, disk space checks)

### Current behavior
- Uses `reqwest::Client::new()` defaults, no explicit timeouts. `crates/rustyjack-updater/src/lib.rs:102-139`
- Streams chunks to disk; `sync_all()` at the end.
- No explicit size caps, redirect hardening, resume support, or disk‑space preflight.

### Baseline improvements worth implementing
- Explicit connect/read/overall timeouts + cancellation checks in loops.
- Maximum archive size and maximum extracted size.
- Disk‑space preflight on both stage and install filesystems.
- Crash‑consistency: fsync directories after important renames (stage commit and file swap).
- Rollback/replay defenses: monotonic version counters and/or expiry metadata (TUF/Uptane style).

---

## 5) Findings (18)

Each finding is in the required format: **Problem → Why → Where → Fix → Fixed version looks like**.

### 1) Unvalidated `manifest.version` is used as a filesystem path
- **Problem:** `manifest.version` is used directly in `stage_dir.join(&manifest.version)`; it can be absolute or contain separators.
- **Why:** A signed but malformed (or compromised‑key) manifest can cause stage writes/deletes outside the intended directory; also creates “foot‑gun” release tooling risk.
- **Where:** `crates/rustyjack-updater/src/lib.rs:33-90` (uses `stage_dir.join(&manifest.version)` and may `remove_dir_all` that path)
- **Fix:** Validate `version` as a single safe component (e.g., SemVer); reject absolute paths and any `/` or `..`.
- **Fixed version looks like:** `validate_version_component(&manifest.version)?; let version_dir = stage_dir.join(safe_component);`

### 2) Stage directory permissions are not enforced (local tampering risk)
- **Problem:** Stage/incoming dirs are created via `create_dir_all` with default perms/umask; no explicit `0700`/owner enforcement.
- **Why:** If a non‑root user can write into stage, they can race‑modify staged files after verification (TOCTOU) or influence extraction/installation via symlink tricks.
- **Where:** `crates/rustyjack-updater/src/lib.rs:33-90` (stage + incoming dir creation)
- **Fix:** Enforce owner‑only permissions (0700) for stage/incoming; verify owner uid/gid and refuse if too open.
- **Fixed version looks like:** `ensure_dir_secure(path, 0o700, owner=root) -> Result<()>;`

### 3) Extraction doesn’t reject all special tar entry types
- **Problem:** Extractor rejects symlinks/hardlinks, but does not explicitly reject device nodes, FIFOs, or other unusual entry types.
- **Why:** Special entries can create surprising filesystem effects and expand attack surface (even if only staged).
- **Where:** `crates/rustyjack-updater/src/lib.rs:159-182` (only checks `is_symlink()` / `is_hard_link()`) 
- **Fix:** Allow only regular files and directories; reject everything else.
- **Fixed version looks like:** `allow only Regular/Directory entry types; reject others`

### 4) Manifest signature is over raw JSON bytes (brittle tooling)
- **Problem:** Signature verifies `manifest.json` byte‑for‑byte; JSON whitespace/key‑order changes break signature.
- **Why:** Not a crypto flaw, but it creates avoidable release‑pipeline fragility and hard‑to‑diagnose failures.
- **Where:** `crates/rustyjack-updater/src/lib.rs:183-219` (verifies `manifest_bytes` directly)
- **Fix:** Canonicalize JSON before signing/verifying (JCS) or strictly define a canonical emitter and enforce it in CI/release tooling.
- **Fixed version looks like:** `release tool emits canonical JSON; updater verifies canonical bytes`

### 5) No replay / rollback protection (older valid update can be installed)
- **Problem:** Any correctly‑signed manifest is accepted regardless of version monotonicity.
- **Why:** A replayed older update can roll a device back to known‑vulnerable software.
- **Where:** `crates/rustyjack-updater/src/lib.rs:33-90` / `crates/rustyjack-updater/src/lib.rs:183-219` (no version state check)
- **Fix:** Persist current installed version/epoch and require `new >= current`; optionally add signed expiry and snapshot metadata (TUF/Uptane patterns).
- **Fixed version looks like:** `current = load_current_version(); require(new >= current); store_current_version(new);`

### 6) TOCTOU between hash verification and install copy
- **Problem:** Files are hashed during verification, then re‑opened and copied again during install.
- **Why:** If staged files can change after verification, installed bytes may not match verified bytes.
- **Where:** `crates/rustyjack-updater/src/lib.rs:183-219` (hash) then `crates/rustyjack-updater/src/lib.rs:229-269` (re-open/copy)
- **Fix:** Bind verification to install: compute SHA‑256 while copying into `dest.new`, compare to expected, and only then rename into place.
- **Fixed version looks like:** `stream copy + hash -> tmp; require(hash == expected); rename(tmp -> dest);`

### 7) `install_to` allows arbitrary absolute paths (large blast radius)
- **Problem:** Manifest entries can install to any absolute path; validation only rejects parent traversal.
- **Why:** Defense‑in‑depth: limiting install targets reduces damage from mistakes or partial key compromise.
- **Where:** `crates/rustyjack-updater/src/lib.rs:270-284` (absolute path allowed)
- **Fix:** Add allowlist for install roots (e.g., only `/usr/local/bin` and specific app directories).
- **Fixed version looks like:** `ensure_under_allowed_roots(dest, &[install_dir, ...])?;`

### 8) File modes are unconstrained (can set SUID/SGID or unsafe perms)
- **Problem:** Manifest controls mode bits without policy checks.
- **Why:** A signed manifest mistake can create privileged or overly writable targets.
- **Where:** `crates/rustyjack-updater/src/lib.rs:229-269` and `crates/rustyjack-updater/src/lib.rs:285-289` (mode parsing + chmod on temp file)
- **Fix:** Restrict allowed modes or mask dangerous bits by default (suid/sgid/sticky).
- **Fixed version looks like:** `reject suid/sgid unless explicitly allowed; allow only known-safe modes`

### 9) HTTP download has no explicit timeouts
- **Problem:** Uses `reqwest::Client::new()` with defaults; no connect/read/overall timeouts set.
- **Why:** Updates can hang indefinitely on poor networks; cancellation becomes unreliable; watchdog friendliness suffers.
- **Where:** `crates/rustyjack-updater/src/lib.rs:102-139`
- **Fix:** Use `ClientBuilder` timeouts; thread cancellation token into loops.
- **Fixed version looks like:** `Client::builder().connect_timeout(...).timeout(...).build()?;`

### 10) No maximum download or extraction size limits
- **Problem:** No cap on archive size or total extracted bytes.
- **Why:** Large downloads can fill disk; compressed archives can expand unexpectedly and exhaust storage/CPU.
- **Where:** `crates/rustyjack-updater/src/lib.rs:102-139` and `crates/rustyjack-updater/src/lib.rs:159-182`
- **Fix:** Enforce size caps: require `Content-Length` <= max (or enforce streaming cap); track extracted bytes and abort on overflow.
- **Fixed version looks like:** `if bytes_written > MAX_ARCHIVE_BYTES or bytes_extracted > MAX_EXTRACTED_BYTES => fail`

### 11) No disk space preflight (stage + install)
- **Problem:** Updater does not check available space before download/extract/install.
- **Why:** Running out of space mid‑apply can leave partial staging, partial installs, and confusing recovery.
- **Where:** `crates/rustyjack-updater/src/lib.rs:33-90` (no statvfs checks)
- **Fix:** Check free space in stage and install filesystems; require headroom for archive + extracted + backups.
- **Fixed version looks like:** `free = statvfs(dir).free_bytes; require(free >= needed_bytes);`

### 12) Stage commit rename is not made durable (directory fsync missing)
- **Problem:** Renaming `incoming` to `version_dir` is not followed by fsync on the containing directory.
- **Why:** On some filesystems/mount options, a power loss after rename can lose the directory entry even if file data was synced.
- **Where:** `crates/rustyjack-updater/src/lib.rs:33-90` (rename stage dir)
- **Fix:** After rename, fsync the parent directory (and consider syncing before/after as needed).
- **Fixed version looks like:** `rename(incoming -> version); fsync_dir(stage_parent_dir);`

### 13) Multi‑file updates are not atomic as a set
- **Problem:** Each file is swapped atomically, but the overall update has no single commit point.
- **Why:** A power loss or error mid‑loop can leave a mixed version set that may break compatibility.
- **Where:** `crates/rustyjack-updater/src/lib.rs:220-228` (install loop)
- **Fix:** Install into a versioned directory and atomically flip a single symlink or directory name as the commit step.
- **Fixed version looks like:** `install all into versions/<ver>/; atomically repoint current symlink; restart after commit`

### 14) No automatic rollback if service fails after restart
- **Problem:** Updater restarts systemd unit but does not verify it becomes active/healthy.
- **Why:** A bad update can brick the system until manual intervention, even though `.prev` exists.
- **Where:** `crates/rustyjack-updater/src/lib.rs:351-372` (restart without health probe)
- **Fix:** After restart, query systemd `ActiveState`/`SubState` with a timeout; if unhealthy, roll back and restart previous version.
- **Fixed version looks like:** `restart; wait_active(timeout); if unhealthy => rollback; restart;`

### 15) Cleanup and retention are missing (stage + `.prev` can accumulate)
- **Problem:** Incoming dirs may remain on failure; version dirs are overwritten but not pruned; `.prev` backups persist indefinitely.
- **Why:** Disk bloat eventually breaks updates and makes incident response harder.
- **Where:** `crates/rustyjack-updater/src/lib.rs:33-90` and `crates/rustyjack-updater/src/lib.rs:229-269` (no GC)
- **Fix:** Add scope‑guard cleanup for incoming dirs on failure; implement retention policy (keep last N staged versions and clear old `.prev` after successful commit).
- **Fixed version looks like:** `on failure: remove incoming; on success: keep last N versions; after health check: remove obsolete .prev`

### 16) Local path auto‑detection can bypass intended URL scheme policy
- **Problem:** `local_archive_path` treats any existing path (including relative) as a local archive source.
- **Why:** If the caller expects “only https URLs”, this silently expands trust boundaries to local filesystem inputs.
- **Where:** `crates/rustyjack-updater/src/lib.rs:140-158` (`local_archive_path`)
- **Fix:** Require explicit `file://` scheme (or an explicit `allow_local` policy flag) and otherwise enforce `https://` (or pinned domain allowlist).
- **Fixed version looks like:** `if url starts with file:// then local else require_https(url)`

### 17) Path‑based extraction/install makes symlink race defenses harder
- **Problem:** Most operations join paths and re-open by path strings instead of working with directory file descriptors.
- **Why:** If any attacker can manipulate stage contents, path‑based code is easier to trick than fd‑based code.
- **Where:** `crates/rustyjack-updater/src/lib.rs:159-182` and `crates/rustyjack-updater/src/lib.rs:229-269`
- **Fix:** Use fd/capability-based filesystem operations (`openat` patterns) and reject symlinks at every path component.
- **Fixed version looks like:** `operate within a secured directory handle; open files with no-follow semantics;`

### 18) Cancellation is only at the outer job layer; inner loops don’t observe it
- **Problem:** Daemon cancels by dropping `apply_update` via `select!`, but download/extract loops don’t check a cancellation token.
- **Why:** Cancellation may be delayed during long downloads/extracts; UX and safety degrade.
- **Where:** `crates/rustyjack-daemon/src/jobs/kinds/update.rs:1-70` (outer select) + `crates/rustyjack-updater/src/lib.rs:102-139` (inner loop)
- **Fix:** Thread a cancellation token into updater internals and check it periodically during streaming/extract/install.
- **Fixed version looks like:** `for each chunk: if cancelled => abort`

---

## 6) Test plan

Focused on integrity + resilience (no exploitation steps).

### A) Interrupted download
- Simulate a network drop mid‑stream (or cancel the update job) while downloading a valid archive.
- Expected:
  - updater fails cleanly (no install performed)
  - partial archive is not treated as success
  - after implementing cleanup (#15), no orphaned `incoming-*` directories remain

### B) Bad signature / bad manifest
- Cases:
  1. Modify one byte in `manifest.json` while keeping `manifest.sig` unchanged.
  2. Keep manifest intact but corrupt `manifest.sig`.
  3. Keep manifest+sig intact but corrupt one payload file.
- Expected:
  - (1) and (2) fail at Ed25519 verification
  - (3) fails at SHA‑256 mismatch before install
  - no restart is attempted on failure

### C) Rollback drills (service fails after apply)
- Apply a correctly signed update whose daemon binary is known to fail to start.
- Expected (after implementing auto‑rollback #14):
  - updater detects service not active within timeout
  - restores last known‑good (`.prev` or previous symlink)
  - service returns to healthy state
  - update is reported as failed, with clear logs

### D) Power loss mid‑apply
- Power‑cycle during each phase: download, extract, between verify/install, mid‑install, right after restart request.
- Expected:
  - filesystem is left in a recoverable state
  - update is safely re‑runnable (idempotent)
  - after implementing directory fsync + atomic commit model (#12–#13) and rollback (#14), the system boots into last known‑good state

---

## References (comparison only)

Ed25519/EdDSA and secure update framework references used for conceptual comparison:

```text
RFC 8032 (EdDSA / Ed25519): https://www.rfc-editor.org/rfc/rfc8032
TUF roles & metadata docs: https://theupdateframework.io/docs/metadata/
TUF specification: https://theupdateframework.github.io/specification/latest/
Uptane Standard: https://uptane.org/docs/latest/standard/uptane-standard
Crash consistency (fsync + rename) lecture: https://swift.sites.cs.wisc.edu/classes/cs736-sp16/wiki/uploads/Main/Lectures/18%20-%20FS%20Consistency.pdf
```
