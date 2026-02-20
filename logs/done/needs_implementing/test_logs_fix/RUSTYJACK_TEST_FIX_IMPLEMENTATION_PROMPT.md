# RustyJack / Pi Zero 2 W — Test Suite Fix Implementation Prompt (Final)

You are an autonomous senior Rust + embedded Linux engineer. Your goal is to implement fixes so that running:

- `sudo ./scripts/rj_run_tests.sh --all`

on a Raspberry Pi Zero 2 W produces **no repeat FAILs** from the `test_logs/` failures captured in the repo.

This prompt is derived from:
- The repo’s `test_logs/*_run.log` ground truth
- The deep research reports provided with this task
- The AI agent execution guidance prompt (`AI_AGENT_FIX_EXECUTION_PROMPT.md`)
- Project constraints (`AGENTS.md`, `CLAUDE.md`, `TESTING.md`, `README.md`)

---

## 0) Hard Constraints (Non-Negotiable)

### Platform + operational constraints
- Target hardware: **Raspberry Pi Zero 2 W** (Ethernet HAT + Waveshare LCD HAT).
- **NetworkManager is removed** (purged). Do not assume `nmcli` exists.
- Networking is expected to be done via **pure Rust netlink operations**.

### “Pure Rust runtime” principle
- Do **not** introduce new runtime reliance on external system binaries (no `iptables`, no `nmcli`, no `dhclient`, etc.).
- The appliance build forbids external process spawning for core operations. Do not add new `std::process::Command` usage in appliance paths.
- Shell scripts in `scripts/` may call system utilities as part of the test harness (that’s already the design), but core Rust code must stay “native”.

### Security posture constraints
- Do not weaken daemon authorization or widen filesystem/socket permissions “just to satisfy tests”.
- If a test requires less restrictive daemon behavior, prefer a **test-only systemd drop-in override** under `/run/systemd/system/…` rather than changing production unit files permanently.

---

## 1) Failure Index (from `test_logs/`)

### 1.1 Tokio runtime panic (wireless + ethernet)
Observed in:
- `test_logs/wireless_run.log` → `wifi_scan_wlan0`, `wifi_scan_wlan1`
- `test_logs/ethernet_run.log` → `eth_discover_eth0`

Signature:
- `there is no reactor running, must be called from the context of a Tokio 1.x runtime`

### 1.2 Isolation route diffs (ethernet, loot, daemon, usb)
Observed as suite-level FAILs:
- `ethernet_run.log`: route snapshot diff after “readonly” operations
- `loot_run.log`: route snapshot diff during loot list/read
- `daemon_run.log`: route snapshot diff in daemon rpc readonly
- `usb_mount_run.log`: route snapshot diff

### 1.3 Daemon “UI runtime only” gate blocks tests
Observed:
- `interface_selection_run.log`: `set_active_eth0`, `set_active_wlan0`, `set_active_wlan1` fail with daemon error code and message:
  - `"operations are restricted to the UI runtime"`
- `daemon_run.log`: similar failures (e.g. system sync) under comprehensive test portions.

### 1.4 IPC schema mismatch: missing `timeout_ms` in WifiScanStart
Observed:
- `daemon_run.log` shows:
  - `invalid request: missing field timeout_ms ...`

### 1.5 Missing CLI commands (unrecognized subcommand)
Observed:
- `evasion_run.log`: `rustyjack evasion …` missing
- `physical_access_run.log`: `rustyjack physical-access …` missing
- `anti_forensics_run.log`: `rustyjack audit …` and `rustyjack anti-forensics …` missing
- `anti_forensics_run.log`: `rustyjack loot artifact-sweep …` missing

### 1.6 USB mount filesystem detection too strict
Observed:
- `usb_mount_run.log`: `rustyjack system usb-mount …` returns:
  - `{"status":"error","message":"unsupported or unknown filesystem",...}`

---

## 2) Fix Plan Overview (Order Matters)

Implement fixes in this order to reduce cascading noise:

1) **Enter a Tokio runtime in the CLI binary** (`crates/rustyjack-core/src/main.rs`).
2) **Fix strict isolation logic** to stop destroying the allowed interface’s IP/route state.
3) **Make daemon UI-only operations configurable for tests** via a test-only systemd drop-in, and ensure scripts use it.
4) **Fix IPC schema compatibility** for `WifiScanStart.timeout_ms` (script + serde defaults).
5) **Add missing CLI surface area** (evasion, physical-access, anti-forensics, audit log-status, loot artifact-sweep).
6) **Fix FAT/VFAT detection** in USB mount code to accept valid FAT volumes.

Each step includes acceptance criteria + verification commands.

---

## 3) Detailed Implementation Instructions

### 3.1 Fix: Tokio runtime entry for CLI (prevents netlink-sys panic)

#### Files
- `crates/rustyjack-core/src/main.rs`
- (use existing runtime helper) `crates/rustyjack-core/src/runtime.rs`

#### Root cause
The CLI calls code paths that create Tokio-backed netlink sockets, but `main.rs` never enters a runtime context.

#### Required change
In `main.rs`, create and enter the shared runtime **before** calling `dispatch_command`.

**Minimal patch sketch:**
- In `fn run(...)`:
  - `let _guard = rustyjack_core::runtime::shared_runtime()?.enter();`
  - then proceed to `resolve_root`, `dispatch_command`, etc.

Do NOT convert the whole CLI to async. Do NOT create a second runtime builder with divergent config.

#### Acceptance criteria
- `rustyjack wifi scan ...` no longer panics.
- `rustyjack ethernet discover ...` no longer panics.
- Wireless + ethernet suites no longer fail with rc=101.

---

### 3.2 Fix: Strict isolation must not wipe allowed interface routes/IP

#### Files
- `crates/rustyjack-core/src/system/mod.rs`
  - `apply_interface_isolation_with_ops_strict_impl(...)`

#### Root cause
Current strict isolation logic runs destructive operations on *allowed* interfaces:
- release DHCP
- flush addresses
- delete default route

This directly causes route snapshot diffs and can drop connectivity even in “readonly” flows.

#### Required change
Modify the “Phase 1: prepare allowed interfaces” block:

**Current behavior (bad):**
- For each allowed interface:
  - release DHCP
  - flush addresses
  - delete default route
  - bring up

**New behavior (correct):**
- For each allowed interface:
  - (wireless) ensure rfkill unblocked
  - bring interface admin-UP (if down)
  - DO NOT flush addresses
  - DO NOT delete default routes
  - DO NOT force DHCP release here

Then keep Phase 2 (blocking non-allowed interfaces) intact.

#### Additional nuance
If you need a “clean-slate reconfigure allowed iface” mode, that should be a separate, explicit mode (and tests should opt-in). Do not make destructive changes the default “enforce_single_interface” behavior.

#### Acceptance criteria
- Route snapshot diffs stop appearing in ethernet/loot/usb/daemon readonly checks.
- Default route on eth0 remains present across suites when eth0 is the active uplink.

---

### 3.3 Fix: Daemon UI-only operations gate — make test harness compatible

#### Files
- `crates/rustyjack-daemon/src/config.rs` (already supports env var)
- `scripts/rj_test_lib.sh` (add helpers)
- `scripts/rj_test_interface_selection.sh`
- `scripts/rj_test_daemon.sh` (and/or comprehensive test wrapper)

#### Background
Daemon gate currently rejects state-changing ops unless the peer UID matches the UI runtime user, when `ui_only_operations` is enabled.
Tests run legitimate admin operations via the unix socket and expect success.

#### Required approach (do NOT permanently weaken production units)
Use a test-only systemd drop-in under `/run/systemd/system/rustyjackd.service.d/` to set:

- `Environment=RUSTYJACKD_UI_ONLY_OPERATIONS=false`

Then:
- `systemctl daemon-reload`
- `systemctl restart rustyjackd.service`

Add cleanup to remove the drop-in and restart daemon after the suite.

#### Implementation detail
Add to `scripts/rj_test_lib.sh` functions similar to the existing UI virtual input drop-in pattern:
- `rj_daemon_testmode_enable()`:
  - create `/run/systemd/system/rustyjackd.service.d/50-tests.conf`
  - write `[Service]\nEnvironment=RUSTYJACKD_UI_ONLY_OPERATIONS=false\n`
  - reload + restart daemon
  - wait briefly, verify active
- `rj_daemon_testmode_disable()`:
  - remove drop-in
  - reload + restart

Then call:
- In `rj_test_interface_selection.sh`, enable testmode at start, disable in a trap/teardown.
- In `rj_test_daemon.sh`, do the same (especially for comprehensive job tests).

This keeps production security posture intact while allowing the CI/harness to exercise admin behavior.

#### Acceptance criteria
- Interface selection suite no longer fails with `"operations are restricted to the UI runtime"`.
- Daemon suite no longer fails on `SystemSync` and `SetActiveInterface` due to UI-only gate.

---

### 3.4 Fix: IPC compatibility — WifiScanStart.timeout_ms

#### Files
- `crates/rustyjack-ipc/src/types.rs` (WifiScanStartRequest)
- `scripts/rustyjack_comprehensive_test.sh`

#### Root cause
The script constructs:
- `{"body_type":"WifiScanStart","body":{"interface":"wlan0"}}`
But Rust struct requires:
- `timeout_ms: u64`

#### Required changes (do BOTH for robustness)

1) **Script fix**  
In `scripts/rustyjack_comprehensive_test.sh`, update the J1 WifiScanStart call to include timeout_ms, e.g.:
- `"timeout_ms": 5000`

2) **Serde compatibility fix**  
In `WifiScanStartRequest`, make `timeout_ms` backward-compatible:
- Option A: `#[serde(default = "default_scan_timeout_ms")] pub timeout_ms: u64`
- Option B: `pub timeout_ms: Option<u64>` and apply a default in server logic

Prefer Option A for minimal downstream churn.

#### Acceptance criteria
- Comprehensive daemon job J1 proceeds (no “missing field timeout_ms”).
- Daemon run log no longer shows invalid request errors for WifiScanStart.

---

### 3.5 Fix: Add missing CLI commands expected by tests

These suites are part of `--all`, and scripts treat “unrecognized subcommand” as FAIL.
Implement safe, modern Rust command surfaces with JSON output consistent with existing conventions:
- top-level: `{"status":"ok"|"error","message":...,"data":...}`

#### 3.5.1 `rustyjack evasion ...`
##### Requirements from `scripts/rj_test_evasion.sh`
Must exist and return JSON with:
- `evasion mac-status` → `data.current`, `data.randomization_enabled`
- `evasion hostname-status` → `data.current`, `data.randomization_enabled`
- `evasion tx-power-status` → `status:"ok"` (data can include interface/power if available)
- `evasion mode-status` → `data.current` (string)
- Dangerous-only commands (only executed if `--dangerous` passed to test runner):
  - `evasion randomize-mac` → `data.new_mac`
  - `evasion randomize-hostname` → `data.new_hostname`

##### Implementation strategy
- There is already a `rustyjack-evasion` crate and existing WiFi MAC randomize logic in core ops.
- Add an `EvasionCommand` enum in `crates/rustyjack-commands/src/lib.rs`.
- In `crates/rustyjack-core/src/operations.rs`, map evasion subcommands to existing handlers where possible:
  - randomize-mac → reuse `handle_wifi_mac_randomize`
  - randomize-hostname → reuse existing `SystemCommand::RandomizeHostname` handler
- Implement lightweight status endpoints:
  - MAC status: use `rustyjack_evasion::MacManager::get_mac(interface)` + policy config read (`load_mac_policy_config`) to determine whether randomization is enabled.
  - Hostname status: read `/proc/sys/kernel/hostname` (no external binaries).
  - Mode status: return a stable string like `"normal"` unless you have an existing mode state machine.
  - TX power status: if you already store desired power in config/state, expose it; otherwise return `"ok"` with `"unknown"` fields (tests only require `status == ok`).

#### 3.5.2 `rustyjack physical-access ...`
##### Requirements from `scripts/rj_test_physical_access.sh`
Commands required:
- `physical-access router-fingerprint --help` must succeed (help text is enough)
- `physical-access extract-credentials --help` must succeed
- `physical-access list-default-credentials --output json` must return JSON with `status:"ok"`

##### Implementation strategy
- Add `PhysicalAccessCommand` group with the three subcommands.
- For the first two, “help only” is sufficient (no runtime execution required by tests).
- For `list-default-credentials`, ship a small built-in list (static JSON array embedded in code) or load from a repo defaults file if one exists.
- Output format:
  - `data.count`, `data.items` (array), and `status:"ok"`.

#### 3.5.3 `rustyjack anti-forensics ...` and `rustyjack audit log-status ...`
##### Requirements from `scripts/rj_test_anti_forensics.sh`
Commands required:
- `rustyjack audit log-status --output json` → `status:"ok"`
- `rustyjack anti-forensics secure-delete --path /tmp/... --passes 1 --output json` → `status:"ok"` and file must be removed
- `rustyjack anti-forensics log-status --output json` → `status:"ok"`
- `rustyjack loot artifact-sweep --list-only --output json` → `status:"ok"`

##### Implementation strategy
- Add `AuditCommand` with subcommand `LogStatus`.
  - Implementation: detect whether audit log exists (`/var/log/audit/audit.log`) and return `enabled: bool`, `path: ...` while still `status:"ok"` even if absent.
- Add `AntiForensicsCommand` with subcommands:
  - `SecureDelete { path, passes }`
    - Implement in Rust:
      - Open file for write, get length
      - Overwrite with random bytes for N passes (use `rand` already in deps or OS RNG via `getrandom`)
      - `sync_all()`
      - Remove file
    - Safety: refuse to operate on directories; refuse symlinks; optionally restrict to `/tmp` and `/var/tmp` unless `--allow-any-path` flag is set (tests use `/tmp`, so safe).
  - `LogStatus`
    - Return `status:"ok"` and include high-level fields (e.g. “log retention configured: false”).
- Add `LootCommand::ArtifactSweep`
  - For test: `--list-only` returns `status:"ok"` with a list of candidate artifact paths (can be empty).

#### Acceptance criteria
- Evasion, physical-access, anti-forensics suites no longer fail with “unrecognized subcommand”.
- JSON keys expected by scripts are present.
- `secure-delete` actually deletes the test file.

---

### 3.6 Fix: USB mount VFAT detection robustness

#### Files
- `crates/rustyjack-core/src/mount.rs`
  - `fn detect_fs_type`
  - `fn is_vfat`

#### Root cause
`is_vfat` currently checks for the literal ASCII strings `"FAT16   "`, `"FAT12   "`, `"FAT32   "` at fixed offsets. Many valid FAT volumes don’t reliably store these labels, so detection returns “unsupported”.

#### Required change
Replace `is_vfat` with a more robust FAT boot sector sanity check:
- Verify boot sector signature bytes at offsets 510 and 511 are `0x55` and `0xAA`.
- Parse BPB fields (little-endian) and validate plausibility:
  - bytes_per_sector in {512,1024,2048,4096}
  - sectors_per_cluster is power of two and >0
  - reserved_sectors >0
  - num_fats is 1 or 2
  - total_sectors (16 or 32) nonzero
  - FAT size fields plausible (fat_size16 or fat_size32)
- Accept FAT12/16/32 if these checks pass.

Keep ext detection first (it’s already correct), then exfat, then vfat.

#### Acceptance criteria
- `rustyjack system usb-mount --device /dev/sda1 --mode read-write ...` succeeds on typical FAT32 USB sticks.
- `usb_mount` suite passes mountpoint checks.
- No new external binaries are used; this is pure Rust.

---

## 4) Verification Checklist (Pi Zero 2 W)

Run these in order:

1) Build:
- `cargo build --release` (or the repo’s documented build path)

2) Quick sanity (manual):
- `sudo ./target/release/rustyjack wifi scan --output json` (or whichever path)
- `sudo ./target/release/rustyjack ethernet discover --interface eth0 --output json`

3) Run the full harness:
- `sudo ./scripts/rj_run_tests.sh --all --outroot /var/tmp/rustyjack-tests`

4) Confirm:
- No `rc=101` panics
- No “operations are restricted to the UI runtime” failures
- No “unsupported or unknown filesystem” for usb mount
- No “unrecognized subcommand” failures
- Isolation route diffs are gone for “readonly” suites

---

## 5) Implementation Notes You MUST Produce
After changes, write an implementation note (short but precise) containing:
- What changed (file list + summary)
- Why each change was needed (tie to failing suite)
- How to verify (exact commands + expected outcomes)

---

## References (for correctness, not for runtime dependencies)
- Tokio runtime context guard (`Runtime::enter` / `EnterGuard`) documentation:
  https://docs.rs/tokio/latest/tokio/runtime/struct.EnterGuard.html
- FAT boot sector signature (0x55, 0xAA at offsets 510/511) and BPB structure:
  https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
  https://8dcc.github.io/programming/understanding-fat.html
- ext superblock magic (0xEF53 at superblock offset 0x38):
  https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html

END.
