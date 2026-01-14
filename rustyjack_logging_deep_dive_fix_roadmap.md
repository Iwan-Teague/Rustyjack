# Rustyjack Logging Deep-Dive & Fix Roadmap (Rust-only, No External Binaries)
**Project:** `rustyjack`  
**Date:** 2026-01-13  
**Author voice:** Senior Rust developer (Linux + networking systems)

## Scope and non-negotiables
- **Rust-only at runtime.** No `std::process::Command` for logging, export, or diagnostics.
- **No third-party binaries.** That includes `journalctl`, `dmesg`, `ip`, `mount`, etc.
- Kernel/OS interfaces are allowed (sysfs, procfs, netlink, `/dev/kmsg`, `mount(2)`), and Rust crates are allowed.
- This report focuses on **logging correctness and debuggability**, plus the **Export logs to USB** pipeline as it relates to logging.

---

# Executive summary (what is happening today)

## What the project already does well
1) **It is capable of its own logging.**  
The main processes initialize `tracing_subscriber` and write **daily-rotating log files** under the configured root:
- `rustyjack-daemon/src/main.rs` writes `<root>/logs/rustyjackd.log`
- `rustyjack-ui/src/main.rs` writes `<root>/logs/rustyjack-ui.log`
- `rustyjack-portal/src/bin/main.rs` writes `<root>/logs/portal.log`

2) **Export logs to USB exists and is Rust-native for kernel logs.**  
`rustyjack-core/src/services/logs.rs` collects:
- tails of Rustyjack log files
- kernel ring buffer tail via `/dev/kmsg`
- sysfs/proc snapshots (interfaces, routes, rfkill)
- and currently also reads journald for some unit tails (Rust API, not external binaries)

3) **Audit logging exists and is structured.**  
`rustyjack-core/src/audit.rs` writes JSON-line audit events to `<root>/logs/audit/audit.log`.

## Where the current system falls short (high impact)
1) **“Logs [OFF]” is not enforced for component log files.**  
The UI toggle only sets `RUSTYJACK_LOGS_DISABLED` inside the UI process; the daemon acknowledges that changes do not reconfigure tracing at runtime. Component file logs continue to be written.

2) **Logging is not consistently grouped by subsystem.**  
Network/USB/wireless events are mixed into broad component logs; operational debugging becomes grep archaeology.

3) **Retention is unbounded.**  
Daily rolling creates one file per day but nothing deletes old logs. This is a disk-fill problem waiting to happen.

4) **Secrets can leak to logs in some operations.**  
A redaction module exists (`rustyjack-core/src/redact.rs`), but it is not applied everywhere. Example: `rustyjack-core/src/physical_access.rs` logs `username:password` attempts in plaintext.

5) **Export bundle is not aligned to a “self-owned logging system.”**  
It currently includes journald tails for `NetworkManager.service` and `wpa_supplicant.service`, which (a) may be irrelevant in a Rust-owned networking stack and (b) adds noisy failure lines on systems where those units do not exist.

---

# Fix Roadmap (pipeline format, no options)

Each problem below follows: **Problem → Why → Exact code steps → What “done” looks like**.

---

## Problem 1 — “Logs [OFF]” does not stop writing to Rustyjack component log files

### Why it’s a problem
- `RUSTYJACK_LOGS_DISABLED` affects only code that explicitly checks `rustyjack_evasion::logs_disabled()`.
- The daemon/UI/portal set up `tracing_subscriber` once at startup and never reload it.
- The daemon explicitly admits this limitation in the LoggingConfigSet handler:
  - `rustyjack-daemon/src/dispatch.rs` notes that “requires process restart for full effect”.

**Result:** the UI can show “Logs OFF” while files like `rustyjackd.log` keep growing.

### Exact code steps (make “Logs OFF” real and system-wide)

#### 1. Create a shared logging crate to eliminate drift
**Add new workspace member:** `rustyjack-logging`

**File:** `Cargo.toml` (workspace)
- Add to `members`:
  ```toml
  "rustyjack-logging",
  ```

**New crate:** `rustyjack-logging/Cargo.toml`
```toml
[package]
name = "rustyjack-logging"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "registry"] }
tracing-appender = "0.2"
tracing-log = "0.2"
once_cell = "1"
notify = "6"
chrono = { workspace = true }
```

#### 2. Define a single source of truth: `<root>/config/logging.json`
**New file:** `rustyjack-logging/src/config.rs`
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub enabled: bool,          // “Logs [ON/OFF]”
    pub level: String,          // "error"|"warn"|"info"|"debug"|"trace"
    pub keep_days: u64,         // retention
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { enabled: true, level: "info".into(), keep_days: 14 }
    }
}
```

**New file:** `rustyjack-logging/src/fs.rs`
- Implement:
  - `read_config(root: &Path) -> LoggingConfig`
  - `write_config_atomic(root: &Path, cfg: &LoggingConfig) -> Result<()>`
- Use atomic write: write to `logging.json.tmp` then `rename()`.

Path definition:
```rust
pub fn config_path(root: &Path) -> PathBuf {
    root.join("config").join("logging.json")
}
```

#### 3. Make tracing dynamically reloadable (no restart)
**New file:** `rustyjack-logging/src/init.rs`

- Use `tracing_subscriber::reload` to create a reloadable filter layer.
- Store a global reload handle per-process.

Implementation requirements:
- `set_enabled(false)` must result in **no events emitted to any layer**.
- Changing `level` must immediately affect logging verbosity.
- This must work in daemon/UI/portal processes.

Sketch (the important shape):
```rust
use once_cell::sync::OnceCell;
use tracing_subscriber::{EnvFilter, Registry};
use tracing_subscriber::reload;

static RELOAD: OnceCell<reload::Handle<EnvFilter, Registry>> = OnceCell::new();

pub fn init(component: &str, root: &Path, cfg: &LoggingConfig) -> anyhow::Result<Guards> {
    let base_filter = build_filter(component, cfg);
    let (filter_layer, handle) = reload::Layer::new(base_filter);

    RELOAD.set(handle).ok();

    // stdout layer + file layers created here (see Problem 2 for subsystem layers)
    // registry().with(filter_layer).with(stdout).with(file).try_init();

    Ok(guards)
}

pub fn apply(cfg: &LoggingConfig, component: &str) -> anyhow::Result<()> {
    let handle = RELOAD.get().ok_or_else(|| anyhow::anyhow!("logging not initialized"))?;
    handle.reload(build_filter(component, cfg))?;
    Ok(())
}

fn build_filter(component: &str, cfg: &LoggingConfig) -> EnvFilter {
    if !cfg.enabled {
        return EnvFilter::new("off");
    }
    // Default policy: component defaults to cfg.level, plus allow per-target overrides later.
    EnvFilter::new(cfg.level.clone())
}
```

#### 4. Enforce config propagation across processes via file watcher
**New file:** `rustyjack-logging/src/watch.rs`
- Start a watcher on `<root>/config/logging.json`.
- On change: read file → call `apply(cfg, component)`.

Daemon: spawn watcher on startup.  
UI: spawn watcher thread at startup.  
Portal: spawn watcher task at startup.

This makes “Logs OFF” apply to **all three processes** without signals or restarts.

#### 5. Make the daemon endpoint actually apply logging immediately
**File:** `rustyjack-daemon/src/dispatch.rs`
In `RequestBody::LoggingConfigSet`:
- Replace the “requires restart” comment with real application:

Steps:
1) Persist config:
   - `rustyjack_logging::fs::write_config_atomic(&root, &cfg)`
2) Apply immediately:
   - `rustyjack_logging::init::apply(&cfg, "rustyjackd")?`
3) (Compatibility) set `RUSTYJACK_LOGS_DISABLED` inside the daemon process **as well**, because parts of the codebase gate file writes on this env var:
   - If `cfg.enabled == false` set env var to `"1"`, else remove it.

#### 6. Make UI toggle update the central config, not just an env var
**File:** `rustyjack-ui/src/app.rs`
- Replace `apply_log_setting()` and `toggle_logs()` behavior:

New rules:
- UI calls the daemon `LoggingConfigSet` endpoint to update config.
- UI does **not** rely on setting `RUSTYJACK_LOGS_DISABLED` locally for component tracing.
- UI may still set it locally for any *in-process* loot logging that checks the env var, but the watcher will keep it consistent anyway.

### What “done” looks like
- Switching “Logs [OFF]” results in:
  - **no new lines** appended to:
    - `<root>/logs/rustyjackd.log*`
    - `<root>/logs/rustyjack-ui.log*`
    - `<root>/logs/portal.log*`
  - Loot/artifact logs that obey `logs_disabled()` stop writing as they already do.
- Changing log level from UI updates immediately (no restart).
- The daemon’s LoggingConfigGet reflects real live behavior.

---

## Problem 2 — Logs are not grouped by subsystem (USB/Wi‑Fi/Ethernet/Crypto), making debugging slow and error-prone

### Why it’s a problem
- Today you get three big buckets: daemon/UI/portal logs.
- Network bring-up, DHCP, rfkill, mount/export and crypto events get mixed into those buckets.
- Debugging “why didn’t wlan0 come up” becomes manual filtering and guesswork.

### Exact code steps (add subsystem logs with strict routing)

#### 1. Establish a target taxonomy (stable names)
**New file:** `rustyjack-logging/src/targets.rs`
```rust
pub const T_USB: &str = "usb";
pub const T_WIFI: &str = "wifi";
pub const T_NET: &str = "net";
pub const T_CRYPTO: &str = "crypto";
pub const T_AUDIT: &str = "audit";
```

#### 2. Route targets into dedicated log files (no duplication)
Update `rustyjack-logging::init::init(...)` to create:
- Component file log:
  - `<root>/logs/rustyjackd.log` for daemon
  - `<root>/logs/rustyjack-ui.log` for UI
  - `<root>/logs/portal.log` for portal
- Subsystem log files:
  - `<root>/logs/usb.log`
  - `<root>/logs/wifi.log`
  - `<root>/logs/net.log`
  - `<root>/logs/crypto.log`

**Critical detail:** prevent subsystem events from also landing in the component file.
Implement this by filtering the component file layer to **OFF** for those targets.

Mechanically:
- Component file layer filter:
  - default = cfg.level
  - `usb/wifi/net/crypto` = OFF
- Subsystem file layer filter:
  - only that target = cfg.level
  - everything else OFF

Use `tracing_subscriber::filter::Targets` attached to each layer:
```rust
use tracing_subscriber::filter::{Targets, LevelFilter};

let component_targets = Targets::new()
    .with_default(LevelFilter::INFO)
    .with_target("usb", LevelFilter::OFF)
    .with_target("wifi", LevelFilter::OFF)
    .with_target("net", LevelFilter::OFF)
    .with_target("crypto", LevelFilter::OFF);

let usb_targets = Targets::new().with_target("usb", LevelFilter::INFO);
```

The reloadable `EnvFilter` (Problem 1) sets the global level and enable/disable; the `Targets` filters do routing.

#### 3. Move existing log statements into the correct targets
This is a direct, mechanical edit across the repo. The rule is: **any event emitted inside these domains must set the correct target**.

##### USB
- `rustyjack-core/src/mount.rs`
- `rustyjack-core/src/operations.rs` USB export/mount/unmount handlers

Change:
```rust
tracing::info!("Mounted {} at {}", dev, mountpoint);
```
To:
```rust
tracing::info!(target: "usb", device=%dev, mountpoint=%mountpoint, "mounted");
```

##### Wi‑Fi
- `rustyjack-core/src/system/mod.rs` Wi‑Fi connect path
- `rustyjack-core/src/wireless_native.rs`
- `rustyjack-netlink/src/rfkill.rs`

Example change:
```rust
tracing::warn!("Failed to release DHCP lease for {}: {}", interface, e);
```
To:
```rust
tracing::warn!(target:"wifi", iface=%interface, error=%e, "dhcp_release_failed");
```

##### Ethernet + DHCP
- `rustyjack-core/src/system/interface_selection.rs`
- `rustyjack-netlink/src/dhcp.rs`
- `rustyjack-core/src/system/ops.rs`

Example:
```rust
tracing::info!("Attempting DHCP (carrier up or unknown)");
```
To:
```rust
tracing::info!(target:"net", iface=%iface, carrier=?carrier_opt, "dhcp_start");
```

##### Crypto
- `rustyjack-encryption/*`
- Any log lines that mention encryption/keys/passwords must use `target:"crypto"` AND redaction (Problem 5).

#### 4. Add correlation fields (job_id, op_id) via spans
For long operations (connect, acquire dhcp, export logs), wrap in spans:
- `operation`, `iface`, `job_id` (if available)

Example:
```rust
let span = tracing::info_span!(target:"wifi", "wifi_connect", iface=%iface, ssid=%ssid);
let _g = span.enter();
```

### What “done” looks like
- The logs directory contains:
  - `rustyjackd.log*`, `rustyjack-ui.log*`, `portal.log*`
  - `usb.log*`, `wifi.log*`, `net.log*`, `crypto.log*`
- When a Wi‑Fi operation runs, **all relevant lines appear in `wifi.log`**, not scattered.
- Component logs become quieter and easier to use (UI remains UI, daemon remains daemon).

---

## Problem 3 — Log retention is unbounded (disk fill risk)

### Why it’s a problem
- `tracing_appender::rolling::daily` rotates, but it does **not** delete.
- Embedded and appliance deployments have finite storage.
- Once disk is full, everything fails in weird ways (including USB export).

### Exact code steps (daemon-managed retention)
The daemon is the correct place to do retention because it is always running.

#### 1. Implement retention in `rustyjack-logging`
**New file:** `rustyjack-logging/src/retention.rs`

Rules:
- Keep last `cfg.keep_days` for `*.log` rotated files.
- Also cap total size of `<root>/logs` to a hard ceiling (e.g. 200MB) to prevent pathological spam.

Implementation:
- Enumerate files in `<root>/logs`
- For files matching:
  - `rustyjackd.log*`, `rustyjack-ui.log*`, `portal.log*`
  - `usb.log*`, `wifi.log*`, `net.log*`, `crypto.log*`
  - `audit/audit.log*` (audit retention can be longer, but keep it consistent unless policy demands otherwise)
- Delete any file with `mtime < now - keep_days`.

#### 2. Run retention daily
**File:** `rustyjack-daemon/src/main.rs`
After daemon startup and watcher init:
- spawn a tokio task that runs:
  - once at startup
  - then every 24 hours

### What “done” looks like
- After running for weeks, `<root>/logs` does not grow without bound.
- “Export logs to USB” still works after long uptime because disk remains healthy.

---

## Problem 4 — Error logging is inconsistent; some failures are silently dropped or lack actionable context

### Why it’s a problem
- Some operations treat errors as best-effort and discard them (`.ok()`, `let _ = ...`).
- Logs become misleading: “Export succeeded” but critical sections are missing.
- Field debugging requires “what failed and where” with enough context to reproduce.

### Exact code steps (make failures visible without spamming)

#### 1. Add error-layer integration for structured causes
In each process logging init, add:
- `tracing_error::ErrorLayer` (crate `tracing-error`)

**Add dependency:** `tracing-error = "0.2"` in `rustyjack-logging`.

In `init(...)`:
```rust
use tracing_error::ErrorLayer;
tracing_subscriber::registry()
    .with(filter_layer)
    .with(ErrorLayer::default())
    .with(stdout_layer)
    .with(file_layers...)
    .try_init()?;
```

#### 2. Stop discarding errors in log export assembly
**File:** `rustyjack-core/src/services/logs.rs`

Replace patterns like:
- `append_file_section(...);` that internally writes `ERROR ...` text
with:
- a structured “section result” that is collected and printed once at the top as a summary.

Concrete implementation:
- Define:
```rust
struct SectionStatus { name: &'static str, ok: bool, err: Option<String> }
```
- Each append function returns `Result<(), ServiceError>` and on error pushes a status record.
- The exporter prints:
  - “Bundle Summary: missing sections: …” at the top
  - then continues writing best-effort content

This avoids silent loss and makes missing evidence obvious.

#### 3. Instrument boundary functions with `#[tracing::instrument]`
Add instrumentation to the highest-value boundary functions:
- USB export handler
- DHCP acquire/release
- rfkill unblock + verify
- Wi‑Fi connect/disconnect

Example:
```rust
#[tracing::instrument(target="usb", skip(root), fields(device=%device))]
fn export_logs_to_usb(root: &Path, device: &str) -> Result<...> { ... }
```

### What “done” looks like
- When a section fails during export, the exported file clearly says:
  - which section failed
  - why
  - and whether the rest is complete
- Operator can diagnose without “re-run with debug”.

---

## Problem 5 — Secrets can leak into logs; redaction exists but is not enforced

### Why it’s a problem
- You already have a redaction utility (`rustyjack-core/src/redact.rs`).
- But some code logs credentials directly. Confirmed example:
  - `rustyjack-core/src/physical_access.rs` logs `Trying username:password on gateway` and `SUCCESS: username:password`.

This violates “secure-by-default logging.”

### Exact code steps (enforce redaction everywhere)

#### 1. Replace plaintext credential logging
**File:** `rustyjack-core/src/physical_access.rs`

Change:
```rust
info!("Trying {}:{} on {}", username, password, gateway);
```
To:
```rust
use crate::redact;
info!(target:"net", user=%username, pass=%redact!(password), gateway=%gateway, "router_auth_try");
```

Change:
```rust
info!("SUCCESS: {}:{}", username, password);
```
To:
```rust
info!(target:"net", user=%username, pass=%redact!(password), "router_auth_success");
```

#### 2. Redact JSON contexts before logging
Wherever you log JSON blobs that could contain `password/psk/key/token`, run:
```rust
crate::redact::redact_json(&mut value);
```
before emitting.

#### 3. Protect crypto logs by policy
In any encryption-related logs:
- never print raw keys/passwords
- always log “fingerprints” or lengths if needed

Example:
```rust
tracing::info!(target:"crypto", key_len=key.len(), "key_loaded");
```

### What “done” looks like
- A grep over any log file for patterns like `admin:password` returns nothing.
- Sensitive fields appear as `[REDACTED]` when logged.

---

## Problem 6 — Export bundle is not aligned with “project-owned logging” and misses key internal artifacts

### Why it’s a problem
- `rustyjack-core/src/services/logs.rs` currently includes:
  - journald tails for `NetworkManager.service` and `wpa_supplicant.service`
- In a Rust-owned stack, those are usually irrelevant and add noise/failure text.
- The export bundle does **not** include `audit.log` tails, which are critical for privileged action trails.
- It does not include subsystem logs (because they don’t exist yet).

### Exact code steps (make export fully self-owned and complete)

**File:** `rustyjack-core/src/services/logs.rs`

#### 1. Add audit tail
Add:
```rust
append_rustyjack_log_tail(&mut out, root, "audit/audit.log", "Audit Log");
```
(Use a path-aware tail function or add `append_log_tail_path()`.)

#### 2. Include new subsystem logs
After implementing Problem 2, add:
- `usb.log`, `wifi.log`, `net.log`, `crypto.log`

#### 3. Remove irrelevant journald unit tails
Delete:
```rust
append_journald_unit_tail(&mut out, "NetworkManager.service", 200);
append_journald_unit_tail(&mut out, "wpa_supplicant.service", 200);
```

Keep `/dev/kmsg` and sysfs snapshots—those are system facts and are Rust-native.

#### 4. Add a manifest header
At the top of the bundle:
- timestamp
- Rustyjack version (from Cargo pkg)
- root path
- current logging config (enabled/level/keep_days)
- selected interface (if known)

### What “done” looks like
- Export bundle contains all Rustyjack logs that matter:
  - component logs
  - subsystem logs
  - audit log
  - kernel + sysfs snapshots
- No dependency on “external services I don’t use” for meaningful evidence.

---

## Problem 7 — “Logs disabled” semantics are split between tracing logs and loot/artifact logs

### Why it’s a problem
- Loot log writes check `rustyjack_evasion::logs_disabled()` (env var).
- Tracing logs (daemon/UI/portal) ignore it today.
- Result: “Logs OFF” inconsistently disables only some log streams.

### Exact code steps (single policy, consistent behavior)
1) After Problem 1, the central truth is `logging.json`.
2) Every process must:
   - read logging.json on startup
   - set its own tracing filter accordingly (reload)
   - set or clear `RUSTYJACK_LOGS_DISABLED` in its own environment to keep existing gating behavior consistent

Implement this in `rustyjack-logging::watch`:
- when config changes:
  - if disabled: `std::env::set_var("RUSTYJACK_LOGS_DISABLED", "1")`
  - else: `std::env::remove_var("RUSTYJACK_LOGS_DISABLED")`

### What “done” looks like
- “Logs OFF” disables:
  - tracing file logs (no new lines)
  - loot/artifact file writes (already gated)
- Audit log remains on (security trail). If you want audit to be disabled too, that is a policy decision—but default secure behavior is to keep audit enabled.

---

# Verification checklist (what QA should do)

## 1) Logs OFF is real
1. Start daemon/UI/portal.
2. Record current file sizes under `<root>/logs`.
3. Toggle “Logs OFF” in UI.
4. Perform actions that normally log (Wi‑Fi select, DHCP attempt, USB export).
5. Confirm:
   - `rustyjackd.log`, `rustyjack-ui.log`, `portal.log` sizes do not increase.
   - `usb.log/wifi.log/net.log/crypto.log` sizes do not increase.
   - `audit.log` **does** increase for privileged actions (expected).

## 2) Subsystem routing works
- Trigger USB export → verify entries appear in `usb.log`.
- Trigger Wi‑Fi connect → verify entries appear in `wifi.log`.
- Trigger Ethernet DHCP → verify entries appear in `net.log`.

## 3) Redaction works
- Run `physical_access` path and confirm logs show `[REDACTED]` for passwords.

## 4) Retention works
- Set `keep_days=1`, create fake dated logs, run cleanup; confirm old logs are deleted.

---

# Closing note
This roadmap is deliberately prescriptive and intentionally avoids branching “if you chose X” guidance. The system becomes:
- **config-file driven**
- **hot reloadable**
- **subsystem segmented**
- **retention safe**
- **secret-safe**
- **exportable without relying on external binaries**
