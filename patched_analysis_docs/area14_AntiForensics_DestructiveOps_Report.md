# Area 14 — Anti-forensics + destructive operations (read-only audit)

**Snapshot analyzed:** `watchdog_shallow_20260213-173640.zip` (unpacked under `/mnt/data/repo/watchdog`)
**Date:** 2026-02-14 (Europe/Dublin)
**Scope requested:** secure-delete / purge modules, log purge behavior, “system purge” workflows, FDE scripts/helpers, confirmation UX requirements, and safety rails.

**Hard constraints I followed**
- I did **not** modify repository files.
- **Only** root docs (`README.md`, `AGENTS.md`, `CLAUDE.md`, `TESTING.md`) and `logs/done/*` were treated as *authoritative* for constraints / UX gating requirements (code/scripts were used only to confirm behavior).

---

## 0) Trusted requirements extracted (what users must be warned about)

### UX gating / safety expectations (root docs)
- UI actions must require **explicit user confirmation**; dialogs **must not auto-dismiss** and errors must not be hidden without acknowledgment. (AGENTS.md L75–L84)
- FDE operations are **destructive** and **irreversible**, and the user must understand the risk. (README.md L362–L369)
- The architecture plan for Area 14 explicitly calls out the need to be **truthful** about what secure deletion can and cannot guarantee on flash/SSD, and to use **strong confirmations** for destructive operations.

### Technical truthfulness requirement (Architecture Doc 2 → Area 14)
- Must clearly distinguish “best effort” vs “guaranteed” on flash media and storage stacks.
- Must include safety rails and confirmation UX.

---

## 1) Safety UX gates (confirmations, irreversible warnings, fail-safe behavior)

### What exists today (confirmed in UI/core)
**Log purge (UI-local deletion)**
- UI flow: one confirmation dialog → deletes “log-like” files under the loot tree only.
  Code: `crates/rustyjack-ui/src/app/system.rs` → `purge_logs()` + `is_log_file()`.

**Complete purge (UI + daemon command)**
- UI flow: two-step confirmation (checkbox + “final confirm”) with strong warning copy.
  Code: `system.rs` → `complete_purge()`.
- Daemon behavior: **preflight-only** (“authorization required”), no destructive action occurs in this snapshot.
  Code: `crates/rustyjack-core/src/operations.rs` → `handle_system_purge()` → `preflight_only_response()`.

**Secure shutdown (UI best-effort RAM wipe + poweroff)**
- UI flow: warning dialog → best-effort RAM overwrite attempt → poweroff request.
  Code: `system.rs` → `secure_shutdown()` + `best_effort_ram_wipe()`; daemon `SystemCommand::Poweroff`.

**FDE prepare / migrate (UI + daemon command)**
- UI explicitly labels these as **dry-run/preflight only**; it states execution “requires review”.
  Code: `crates/rustyjack-ui/src/app/encryption.rs`.
- Core handlers are **preflight-only** in this snapshot.
  Code: `operations.rs` → `handle_system_fde_prepare()`, `handle_system_fde_migrate()`.

### Gaps vs. trusted requirements
- The UI copy implies some effects that do not occur (see Finding #4). Truthful UX copy is part of safety.
- Log purge has only a single confirmation step and lacks a “show me exactly what will be deleted” preview.

### Recommended gating pattern (safe, non-weaponizable)
For any destructive action that affects data availability:
1. **Preflight summary first**: count of candidate files, total size, and *categories* (e.g., “application logs under loot”); no path-by-path list in the UI.
2. **Two-step confirmation**:
   - Step A: irreversible warning + “I understand” checkbox.
   - Step B: a *motor-memory* action that is hard to do accidentally (long-press confirm, or confirm twice with a cooldown).
3. **Fail-safe default**: if any preflight check fails, do nothing; surface actionable error.
4. **Post-action receipt**: record a non-sensitive audit receipt (e.g., “log purge ran; N files removed; timestamp”) without listing sensitive targets.

---

## 2) Technical realism (SD wear-leveling caveats; “best effort” vs guaranteed)

### The uncomfortable truth about “secure delete” on SD/SSD
Rustyjack targets Raspberry Pi-class systems, typically with SD cards or other flash media. On flash:
- Overwriting a file **does not reliably overwrite all physical locations** where its data may exist because controllers remap blocks (wear-leveling) and keep spare/over-provisioned areas. NIST explicitly warns that overwriting via native read/write interfaces may not cover all areas and may not reliably sanitize under wear-leveling.
- Empirical work shows “hard-drive style” overwrite techniques can fail to fully sanitize SSDs/flash due to flash translation layers and remapping.
- Surveys of secure deletion emphasize that guarantees depend on the interface layer; file-level overwrites are often the least trustworthy on modern storage stacks.

### What “best effort” can mean (and what it cannot)
**Best effort (honest claim):**
- Attempt to overwrite the *current* file mapping, fsync, then delete, and warn the user that flash may retain prior versions.

**Not honest to claim (on flash):**
- “Guaranteed unrecoverable secure deletion” for individual files solely by overwriting.

### Safer, more realistic posture (non-weaponizable)
- Prefer **encryption-at-rest** for sensitive artifacts so that “deletion” reduces to **key destruction / rotation** (crypto-erase). This aligns with NIST’s guidance that cryptographic erase is a viable sanitization approach for appropriate media and threat models.
- Treat “secure delete” UI as: **privacy hygiene**, not forensics-evasion. Make this explicit in UX copy.

---

## 3) Implementation map (what exists; where; what it would touch)

### User-facing entry points
1. **UI log purge**
   - File: `crates/rustyjack-ui/src/app/system.rs`
   - Functions: `purge_logs()`, `is_log_file()`
   - Touches: *loot tree only* (`root.join("loot")`), deleting files that heuristically look like logs, plus empty “logs/” directories.

2. **UI secure shutdown**
   - File: `crates/rustyjack-ui/src/app/system.rs`
   - Functions: `secure_shutdown()`, `best_effort_ram_wipe()`
   - Touches: system memory via allocations; then requests daemon poweroff.

3. **UI complete purge**
   - File: `crates/rustyjack-ui/src/app/system.rs`
   - Function: `complete_purge()`
   - Dispatches: `SystemCommand::Purge` (daemon)
   - Core: `crates/rustyjack-core/src/operations.rs` → `handle_system_purge()` (preflight-only)

4. **FDE helpers**
   - Commands: `SystemCommand::FdePrepare { device, execute }`, `SystemCommand::FdeMigrate { target, keyfile, execute }` (see `crates/rustyjack-commands/src/lib.rs`)
   - Core: `operations.rs` handlers are preflight-only
   - Shell scripts exist and are destructive when executed:
     - `scripts/fde_prepare_usb.sh` (wipes a removable USB device and writes a keyfile)
     - `scripts/fde_migrate_root.sh` (formats a target partition as LUKS and copies root into it; defaults to dry-run unless `--execute`)

### Latent / not wired-in but present in code
- File: `crates/rustyjack-core/src/external_tools/anti_forensics.rs`
- Contains routines for “secure delete”, “log clearing”, “emergency wipe”, and “dead-man’s switch”.
- In this snapshot, these routines are **not referenced** by the operations layer or command set (so they are effectively dormant), but they exist and represent substantial future risk if wired into UI/daemon.

---

## 4) Crash safety (partial purge; preventing bricking / inconsistent states)

### Current status in this snapshot
- The **most destructive** workflows (system purge, FDE migrate/prepare) are **preflight-only** at the daemon level, which is the strongest crash-safety posture: no destructive state transitions occur.

### Where crash safety would be needed if execution is enabled later
1. **Any “complete purge” implementation**
   - Avoid deleting binaries/services first. If purge must exist at all, sequence as:
     - stop services → remove app data → verify → then (optionally) remove app binaries, leaving OS stable.
   - Use an **idempotent state machine** with checkpoints (e.g., “phase 1 done”) stored outside the to-be-deleted directory and protected by permissions.

2. **FDE migration**
   - Primary failure mode is unbootable system if interrupted between formatting/copying and boot config changes.
   - Safe design would require: staged copy + verification + explicit reboot plan + rollback path.

3. **Best-effort RAM wipe**
   - Aggressive allocation can trigger OOM-killer, UI freeze, or slow shutdown.
   - Safer approach: cap allocation, show progress, allow cancel, and proceed to poweroff even if wipe is partial (while being honest about that).

---

## 5) Findings (18)

> Format: **Problem → Why → Where → Fix → Fixed version looks like**

### 1) “Anti-forensics” module contains evidence-destruction primitives
- **Problem:** The codebase includes routines that clear system logs / shell history and implements an emergency wipe/dead-man’s switch.
- **Why:** These capabilities are high-abuse and conflict with the project’s stated safety posture; they also create compliance and reputational risk even if not currently wired in.
- **Where:** `crates/rustyjack-core/src/external_tools/anti_forensics.rs` (`clear_system_logs`, `remove_shell_history`, `emergency_wipe`, `dead_mans_switch`).
- **Fix:** Remove these functions from shipping builds; if they must exist, isolate in a non-default crate/feature that cannot be enabled on production/appliance targets and requires explicit legal/ops approvals.
- **Fixed version looks like:** Core contains **no** system-log deletion or dead-man wipe functionality; decommissioning is handled via documented reimage procedures outside the app.

### 2) “Secure delete” language risks overpromising on flash media
- **Problem:** Root docs claim secure delete uses a 7-pass DoD-style overwrite, implying strong guarantees.
- **Why:** On SD/SSD, multi-pass overwrites are often not reliably sanitizing and increase wear; NIST warns native overwrite may not cover remapped areas under wear-leveling.
- **Where:** `AGENTS.md` (DoD 7-pass mention); implementation in `anti_forensics.rs` (`manual_secure_delete`).
- **Fix:** Reword to “best effort overwrite + delete; not guaranteed on flash”; steer users toward encryption + key destruction.
- **Fixed version looks like:** UI says: “This removes files from Rustyjack and attempts best-effort overwrite; on flash media it may not be recoverably erased.”

### 3) File-size proportional allocations in `manual_secure_delete` can OOM
- **Problem:** It allocates overwrite patterns sized to the full file length, multiplied by multiple passes.
- **Why:** Large files can exhaust memory and fail mid-delete, leaving inconsistent state.
- **Where:** `anti_forensics.rs` → `manual_secure_delete()` (builds `patterns: Vec<Vec<u8>>` of length `file_len`).
- **Fix:** Stream overwrites in fixed-size blocks (or remove overwrite entirely in favor of crypto-erase).
- **Fixed version looks like:** “Secure delete” is either removed, or implemented as a bounded-memory operation with explicit cancellation and failure reporting.

### 4) UI “complete purge” messaging claims effects not implemented
- **Problem:** UI copy states it will remove services/udev rules and vacuum journal logs.
- **Why:** In this snapshot, daemon purge is preflight-only, so the UI is misleading.
- **Where:** `crates/rustyjack-ui/src/app/system.rs` → `complete_purge()` (message text); core `operations.rs` → `handle_system_purge()` returns preflight-only.
- **Fix:** Make UI copy conditional on actual capability; if preflight-only, label it as such (“preview / authorization required; no changes made”).
- **Fixed version looks like:** Users see a preflight summary only, with an explicit “No changes were made” banner.

### 5) Log purge heuristic can delete non-log artifacts
- **Problem:** `is_log_file()` matches any filename containing “log” patterns and any file under a `logs/` directory.
- **Why:** False positives can delete valuable artifacts (e.g., a capture or report whose name includes “log”).
- **Where:** `crates/rustyjack-ui/src/app/system.rs` → `is_log_file()`.
- **Fix:** Use an allowlist of log extensions/known log directories produced by Rustyjack, and exclude known binary formats explicitly.
- **Fixed version looks like:** A preview lists “N files in loot logs” with a conservative matcher; exports/reports are preserved.

### 6) Log purge is UI-local with no daemon-side policy enforcement
- **Problem:** Deletion is performed directly by the UI process.
- **Why:** If UI is compromised, it can delete more than intended; also hard to audit centrally.
- **Where:** `system.rs` → `purge_logs()` uses direct filesystem operations.
- **Fix:** Move destructive deletion behind a daemon API that enforces scope rules (“loot-only”, “log-only”) and emits a minimal audit receipt.
- **Fixed version looks like:** UI requests “purge logs” and daemon applies strict allowlist rules.

### 7) Secure-delete directory traversal risks following symlinks
- **Problem:** `manual_secure_delete()` opens paths normally; if a symlink is present, it can follow to outside the intended directory.
- **Why:** A malicious or accidental symlink inside loot could cause deletion of unrelated files.
- **Where:** `anti_forensics.rs` → `secure_delete_dir()` + `manual_secure_delete()` (no `O_NOFOLLOW` / symlink hardening).
- **Fix:** Refuse symlinks; use `symlink_metadata` and/or `openat`-style APIs with `O_NOFOLLOW` semantics on Linux.
- **Fixed version looks like:** “Log purge” ignores symlinks entirely; “complete purge” never performs file-level overwrites.

### 8) “Dead-man’s switch” design is dangerously brittle
- **Problem:** Missing a heartbeat file triggers wipe+poweroff.
- **Why:** Ordinary crashes, disk-full, or tmp cleanup could trigger catastrophic behavior.
- **Where:** `anti_forensics.rs` → `dead_mans_switch()`.
- **Fix:** Remove entirely from production; if needed for safety-critical threat models, require hardware interlock + explicit opt-in + independent review.
- **Fixed version looks like:** No automatic destructive behavior based on file presence.

### 9) “Emergency wipe” is too broad and risks OS damage
- **Problem:** It targets broad directories (including `/tmp` and user home) and attempts overwrite/delete.
- **Why:** High chance of bricking, data loss beyond Rustyjack scope, and policy violations.
- **Where:** `anti_forensics.rs` → `emergency_wipe()`.
- **Fix:** Remove from product; restrict any “reset” to app-owned directories only.
- **Fixed version looks like:** A “factory reset” clears only `/var/lib/rustyjack/*` and leaves OS/system logs untouched.

### 10) Complete purge preflight lists `root` itself as a deletion target
- **Problem:** Purge candidate list includes the Rustyjack root directory as a whole.
- **Why:** If ever executed, deleting the root directory while code is running is prone to partial deletions and inconsistencies.
- **Where:** `operations.rs` → `handle_system_purge()` builds `purge_paths` including `root`.
- **Fix:** Define explicit subpaths for deletion and delete them in an order that preserves the program’s ability to finish.
- **Fixed version looks like:** Purge deletes `loot/`, `wifi/`, `logs/` etc, then removes the root directory last (or never).

### 11) REVIEW_APPROVED gating is file-based and potentially spoofable
- **Problem:** Authorization relies on a file named `REVIEW_APPROVED.md` under the Rustyjack root.
- **Why:** If non-root processes can write there, they can bypass “review required” gating later.
- **Where:** `operations.rs` → `preflight_only_response()` reads `root/REVIEW_APPROVED.md`.
- **Fix:** Move approval to a root-owned, permission-hardened location (e.g., `/etc/rustyjack/approval.d/`) or compile-time gate; log approval state.
- **Fixed version looks like:** Approval cannot be granted by the UI process; it’s provisioned by an admin channel.

### 12) FDE scripts rely on external binaries (policy mismatch risk)
- **Problem:** The shell scripts depend on tools like `cryptsetup`, `wipefs`, `sfdisk`.
- **Why:** Root docs emphasize appliance operation without external process spawning; shipping these scripts may violate platform constraints or create inconsistent behavior across devices.
- **Where:** `scripts/fde_prepare_usb.sh`, `scripts/fde_migrate_root.sh`.
- **Fix:** Treat scripts as developer/operator utilities only, not product features; if FDE must be productized, implement in Rust with explicit gating and platform checks.
- **Fixed version looks like:** UI only offers FDE flows when the platform supports them and the reviewed implementation is present.

### 13) FDE migrate leaves boot configuration as “manual next steps”
- **Problem:** Script finishes without updating boot chain, crypttab/fstab/initramfs.
- **Why:** Users can end up unbootable if they assume “migration complete”.
- **Where:** `scripts/fde_migrate_root.sh` end-of-script messages.
- **Fix:** UI and docs must state clearly that migration is incomplete unless boot config is updated; ideally do a verified end-to-end workflow or keep it preflight-only.
- **Fixed version looks like:** A single guided flow that either completes safely or refuses to proceed.

### 14) RAM wipe is best-effort but can be misinterpreted as strong sanitization
- **Problem:** UI copy suggests meaningful RAM sanitization; implementation only allocates/touches memory and drops it.
- **Why:** It can’t guarantee wiping other processes, kernel caches, swap, or DMA buffers.
- **Where:** `system.rs` → `best_effort_ram_wipe()`.
- **Fix:** Reword to “best-effort memory pressure overwrite”; add a note about limitations and swap.
- **Fixed version looks like:** The dialog says “This reduces residual data risk; it is not a forensic guarantee.”

### 15) RAM wipe allocation strategy may trigger OOM or prolonged shutdown
- **Problem:** Attempts to allocate 95% of MemAvailable.
- **Why:** MemAvailable includes reclaimable caches; allocating near that threshold can still trigger OOM-killer or heavy reclaim stalls.
- **Where:** `best_effort_ram_wipe()` calculates `wipe_bytes = mem_avail * 95 / 100`.
- **Fix:** Cap to a safer fraction (e.g., 50–70%), add a time budget, and proceed to shutdown even on partial wipe.
- **Fixed version looks like:** A progress bar with a hard stop; errors are surfaced but shutdown continues.

### 16) “Purge logs” UX lacks “what will be deleted” preview
- **Problem:** Users can’t review scope before deletion.
- **Why:** Increases accidental loss and reduces trust.
- **Where:** UI `purge_logs()` confirmation dialog.
- **Fix:** Add a preflight scan summary (“N files, total size”), and require a second confirm when N is large.
- **Fixed version looks like:** A preview screen listing categories (not raw paths) and counts.

### 17) No post-action audit receipt for destructive actions
- **Problem:** Log purge deletes files but produces no durable receipt.
- **Why:** Operators can’t confirm what happened later, and debugging becomes hard.
- **Where:** `purge_logs()` deletes then only shows a UI message.
- **Fix:** Record a minimal receipt (timestamp, counts) in an append-only app log or status file (without listing sensitive targets).
- **Fixed version looks like:** `loot/reports/maintenance.json` contains “log_purge”: {time, count, bytes}.

### 18) Dormant anti-forensics code increases future risk of accidental enablement
- **Problem:** High-risk functions are present but unused.
- **Why:** Future refactors can accidentally expose them; security posture becomes fragile.
- **Where:** `external_tools/anti_forensics.rs` module exists and is exported.
- **Fix:** Remove or quarantine behind a build flag that is not enabled in the workspace by default; add CI checks to forbid linkage in appliance builds.
- **Fixed version looks like:** A separate “lab-only” crate excluded from release builds, with explicit review gates.

---

## 6) Test plan (dry-run modes, simulated failures, confirmation bypass tests)

### A. Dry-run / preflight tests
1. **System purge remains preflight-only**
   - Run daemon dispatch for `SystemCommand::Purge` and assert response contains preflight summary and “authorization required”.
2. **FDE prepare/migrate remain preflight-only**
   - Dispatch `FdePrepare { execute: true }` and `FdeMigrate { execute: true }`; assert both return preflight-only.
3. **UI labeling matches backend capability**
   - Snapshot-test UI strings: if backend returns preflight-only, UI must display “No changes made”.

### B. Log purge correctness tests
4. **Matcher unit tests for `is_log_file()`**
   - Table-driven: ensure only known log artifacts match; ensure captures/reports with “log” in name do not.
5. **Scope test: loot-only**
   - Create a temp tree mimicking loot + an external file; include a symlink inside loot pointing outside; ensure purge does not follow/delete outside targets.
6. **Large loot scan performance**
   - Generate 100k files; ensure scan completes within time budget and UI remains responsive.

### C. Simulated failure tests
7. **Permission failure**
   - Make candidate files read-only / owned by root; ensure purge reports partial failures and does not crash.
8. **Disk-full / IO error injection**
   - Use a loopback fs with limited space; ensure RAM wipe and purge handle allocation/write failures gracefully.

### D. Confirmation-bypass tests (UX safety)
9. **Rapid-click / key-mash bypass**
   - Ensure destructive actions require distinct confirmations, cannot be triggered by spamming a single key.
10. **Timeout / focus-loss behavior**
   - Ensure confirmations do not auto-dismiss; ensure returning to the screen does not preserve “armed” state unintentionally.
11. **Cancel mid-operation**
   - For RAM wipe, confirm cancel stops wiping and still proceeds safely to shutdown only if the user confirms.

---

## References (external)
- NIST SP 800-88 Rev.1, *Guidelines for Media Sanitization*.
- NIST ITL Bulletin (Feb 2015) on sanitization limits with wear-leveling.
- Wei et al., USENIX FAST’11: *Reliably Erasing Data From Flash-Based Solid State Drives*.
- Reardon et al., IEEE S&P 2013: *SoK: Secure Data Deletion*.

---

## References (external)

- Linux kernel radiotap header documentation (extended present bitmaps, alignment): https://docs.kernel.org/networking/radiotap-headers.html
- Radiotap project (extended presence masks, alignment): https://www.radiotap.org/
- rfkill man page (hard vs soft block behavior): https://www.man7.org/linux/man-pages/man8/rfkill.8.html
- Tokio `spawn_blocking` docs (abort/cancellation semantics): https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- Rust Fuzz Book (`cargo-fuzz`/libFuzzer workflow): https://rust-fuzz.github.io/book/cargo-fuzz.html
- OWASP Log Injection overview: https://owasp.org/www-community/attacks/Log_Injection
- RustSec advisory re: ANSI escape sequence injection via logs (tracing-subscriber): https://rustsec.org/advisories/RUSTSEC-2025-0055
- Linux `packet(7)` man page (AF_PACKET, privilege): https://www.man7.org/linux/man-pages/man7/packet.7.html
- Linux `socket(7)` man page (socket options like SO_BINDTODEVICE): https://www.man7.org/linux/man-pages/man7/socket.7.html
- NIST SP 800-88 Rev.2 (2025) Guidelines for Media Sanitization: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf

