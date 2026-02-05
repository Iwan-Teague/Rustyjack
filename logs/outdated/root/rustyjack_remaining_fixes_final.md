20 Jan 2026
# RustyJack Appliance: Remaining Missing Features — Final Fix Specification (Snapshot 2026‑01‑20)

**Snapshot analysed:** `watchdog_shallow_20260120-160002.zip`  
**Target:** Raspberry Pi Zero 2 W (single-purpose appliance)  
**Hard constraints:**

- All fixes in **Rust**.
- The appliance build must **not spawn external processes** (no `std::process::Command`, no `bash`, no `system()` wrappers, no `wpa_supplicant` subprocess, no calling out to `systemctl`, `iptables`, `journalctl`, etc.).
- The device may assume full control (root privileges, systemd available, direct hardware access).

This document is intentionally “implementation-first”: it tells developers *exactly* what to change, where, and what finished behavior looks like.

All sections follow:

> **What is the problem → Where is the problem → Why is it a problem → How to fix → What fixed looks like**

---

## Remaining gaps in this snapshot

You already have: ops gating in the daemon, Rust-native WiFi station backend (`RustWpa2`) available and default in netlink, and a Rust-native updater.

**What still does not meet the appliance requirements:**

1. **Appliance build is not provably free of process-spawning code.** The repository still contains many `Command::new` call sites in `rustyjack-core` (and some tool-only modules). In an appliance, “it exists but is gated at runtime” is not good enough.
2. **Update signing public key is provisioned only via an env var** (`RUSTYJACKD_UPDATE_PUBKEY`) and is read in multiple places. That is fragile and makes installation non-deterministic.
3. **Install flow is not deterministic.** You asked whether it is installed correctly with “4 install scripts”; the repo does not currently ship a single, authoritative install path that creates identities, places unit files, seeds config, and enables socket/service.
4. **systemd watchdog is not enabled in the service unit.** The daemon can send watchdog pings, but systemd will not enforce them unless `WatchdogSec=` is set.5. **UI does not display ops toggles.** The daemon returns them in `StatusResponse`, but `rustyjack-ui` never renders them.

---
## A) Appliance build must compile with **zero process spawning**

### What is the problem
The codebase still contains `std::process::Command::new(...)` call sites. Even if ops gating prevents calling them at runtime, they can still compile into the shipped appliance binary.

### Where is the problem
In this snapshot, process spawning appears in multiple files, including:

- `crates/rustyjack-core/src/anti_forensics.rs`
- `crates/rustyjack-core/src/evasion.rs`
- `crates/rustyjack-core/src/physical_access.rs`
- `crates/rustyjack-core/src/system/mod.rs`
- `crates/rustyjack-core/src/operations.rs`

There is also a non-default WiFi backend that spawns `wpa_supplicant`:

- `crates/rustyjack-netlink/src/station/external/*` (already behind `feature = "station_external"`).

### Why is it a problem
- **Requirement breach:** the appliance must not shell out.
- **Security risk:** command spawning increases attack surface (PATH hijacking, env injection, output parsing).
- **Reliability:** appliances should not depend on a pile of external utilities.

### How to fix the problem
You will implement a compile-time contract:

- **Default build = appliance**
- **Appliance build cannot compile any module that spawns processes**
- External tooling is allowed only in an explicit opt-in “lab” build.

This is done with a feature split + code motion + CI enforcement.

#### A.1 — Feature contract (single source of truth)

**A.1.1 — `rustyjack-daemon` defaults to appliance**

File: `crates/rustyjack-daemon/Cargo.toml`

```toml
[features]
default = ["appliance"]

# Production profile.
appliance = [
  "rustyjack-core/appliance",
  "rustyjack-netlink/station_rust_wpa2",
]

# Explicit opt-in for dev/lab builds.
lab = [
  "rustyjack-core/lab",
  "rustyjack-netlink/station_external",
]
```

**A.1.2 — `rustyjack-core` declares what appliance and lab mean**

File: `crates/rustyjack-core/Cargo.toml`

```toml
[features]
default = ["appliance"]

# Appliance forbids external process spawning.
appliance = []

# Lab explicitly enables modules that use external tools.
lab = ["external_tools", "dev_tools", "offensive_tools"]

# The only feature allowed to compile std::process::Command usage.
external_tools = []

dev_tools = []
offensive_tools = []
```

This makes compliance auditable: running `cargo build` must produce an appliance-safe artifact.

#### A.2 — Physically isolate all process spawning into `external_tools/`

**A.2.1 — Create the namespace**

Create directory: `crates/rustyjack-core/src/external_tools/`

Create files:

- `mod.rs`
- `system_shell.rs` (the *only* place allowed to use `std::process::Command`)
- `archive_ops.rs`
- `git_ops.rs`

Move these modules into the namespace (move, don’t copy):

- `anti_forensics.rs` → `external_tools/anti_forensics.rs`
- `evasion.rs` → `external_tools/evasion.rs`
- `physical_access.rs` → `external_tools/physical_access.rs`

**A.2.2 — Gate the module**

File: `crates/rustyjack-core/src/lib.rs`

```rust
#[cfg(feature = "external_tools")]
pub mod external_tools;

#[cfg(not(feature = "external_tools"))]
pub mod external_tools {
    use anyhow::Result;

    #[inline]
    pub fn disabled() -> anyhow::Error {
        anyhow::anyhow!("external_tools disabled (appliance build)")
    }

    // Optional: keep stubs here if you need linking compatibility.
    pub fn run(_program: &str, _args: &[&str]) -> Result<()> {
        Err(disabled())
    }
}
```

**A.2.3 — Create a single façade for running external tools (lab only)**

File: `crates/rustyjack-core/src/external_tools/system_shell.rs`

```rust
use anyhow::{anyhow, Result};

#[cfg(feature = "external_tools")]
pub fn run(program: &str, args: &[&str]) -> Result<std::process::Output> {
    use std::process::Command;

    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| anyhow!("spawn {program} failed: {e}"))?;

    if !out.status.success() {
        return Err(anyhow!(
            "{program} failed (code={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    Ok(out)
}

#[cfg(not(feature = "external_tools"))]
pub fn run(_program: &str, _args: &[&str]) -> Result<std::process::Output> {
    Err(anyhow!("external_tools disabled (appliance build)"))
}
```

Then refactor every existing `Command::new` call site to either:

- Move it entirely into `external_tools/...` (if it’s not needed in appliance mode), or
- Replace the behavior with a Rust-native implementation (only if it is required in appliance mode).

#### A.3 — Decide which behaviors exist in the appliance

**Rule:** in appliance mode, you keep only the operations needed for:

- network connectivity (WiFi/Ethernet),
- hotspot/portal (if you ship those),
- update system,
- minimal status/telemetry.

Everything else (anti-forensics, physical access tooling, generic program execution, “run bash script”, etc.) must be compiled out under `feature = "external_tools"` and unavailable in appliance.

Concrete required changes:

1. In `rustyjack-core`, **disable** the following IPC commands in appliance builds by returning a deterministic error:
   - Anything that routes to `anti_forensics`, `evasion`, `physical_access`, or generic “run program/script”.

2. Keep the code **present** only behind `feature = "external_tools"`.

#### A.4 — Enforce the rule with CI (no debate, hard gate)

You already have a script that counts new command usage. Replace it with an allowlist-based check.

Create: `ci/forbid_command_new.rs`

**Behavior:**

- Walk the repo.
- For every `*.rs` file, if it contains `Command::new` or `std::process::Command`, it must be located under one of these allowlisted directories:
  - `crates/rustyjack-core/src/external_tools/`
  - `crates/rustyjack-netlink/src/station/external/`
- Otherwise, fail with a file+line report.

Minimal implementation (drop-in):

```rust
use std::{fs, path::{Path, PathBuf}};

fn main() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf();

    let allow = [
        repo.join("crates/rustyjack-core/src/external_tools"),
        repo.join("crates/rustyjack-netlink/src/station/external"),
    ];

    let mut violations = Vec::new();
    visit_rs(&repo, &allow, &mut violations);

    if !violations.is_empty() {
        eprintln!("forbid_command_new: found forbidden Command usage:");
        for v in violations { eprintln!("{v}"); }
        std::process::exit(1);
    }
}

fn visit_rs(dir: &Path, allow: &[PathBuf], out: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for e in entries.flatten() {
        let p = e.path();
        if p.file_name().map(|n| n == "target").unwrap_or(false) { continue; }
        if p.is_dir() { visit_rs(&p, allow, out); continue; }
        if p.extension().and_then(|e| e.to_str()) != Some("rs") { continue; }

        let text = match fs::read_to_string(&p) { Ok(t) => t, Err(_) => continue };
        if !(text.contains("Command::new") || text.contains("std::process::Command")) {
            continue;
        }

        let allowed = allow.iter().any(|a| p.starts_with(a));
        if allowed { continue; }

        // crude line reporting
        for (i, line) in text.lines().enumerate() {
            if line.contains("Command::new") || line.contains("std::process::Command") {
                out.push(format!("{}:{}: {}", p.display(), i+1, line.trim()));
            }
        }
    }
}
```

Add this to CI and run it **before** build/test.

#### A.5 — Lock WiFi to the Rust backend (no `wpa_supplicant` in appliance)

Even though `station_external` is already feature-gated, make this explicit in the service config so nobody ships a lab config accidentally.

1) In `services/rustyjackd.service`, set:

```ini
Environment=RUSTYJACK_WIFI_BACKEND=rust_wpa2
```

2) In `rustyjack-core` (or wherever you read the backend env), treat any unrecognized value as `RustWpa2`.

3) Ensure the appliance build does **not** enable `station_external` anywhere (see A.1).

### What fixed looks like
- `cargo build -p rustyjack-daemon` (default) compiles with **zero** `Command::new` occurrences outside the allowlist.
- Any attempt to call a lab-only command in appliance mode returns a deterministic “OperationNotSupported: external_tools disabled” error.
- The unit file pins WiFi backend to `rust_wpa2`, and no `wpa_supplicant` process is ever spawned.

---
## B) Update public key provisioning must be deterministic (not env-only)

### What is the problem
The update job and dispatch path load the update public key only from an environment variable (`RUSTYJACKD_UPDATE_PUBKEY`). That makes updates brittle and installation non-deterministic.

### Where is the problem
- `crates/rustyjack-daemon/src/jobs/kinds/update.rs` → `load_update_public_key()` reads `std::env::var("RUSTYJACKD_UPDATE_PUBKEY")`.
- `crates/rustyjack-daemon/src/dispatch.rs` also reads the same env var.

### Why is it a problem
- **Ops:** env vars are easy to forget and hard to audit across installs.
- **Security:** you want a stable trust anchor, not a runtime injection point.
- **Installability:** your “4 install scripts” need a file-based place to seed the key.

### How to fix the problem
You will change the daemon to load the update key once at startup from a well-defined file location, and store it in daemon state.

**New rule:**

- The daemon reads the update pubkey from `/etc/rustyjack/update_pubkey.ed25519` by default.
- An env var may override the file path, but **the appliance install flow must always place the file**.

#### B.1 — Define the file path and format

- Path: `/etc/rustyjack/update_pubkey.ed25519`
- Format: **32-byte Ed25519 public key as hex**, optionally prefixed with `0x`, with optional newlines.

Example content:

```
0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

#### B.2 — Centralize config loading

Create: `crates/rustyjack-daemon/src/config.rs` (or extend existing config module) with:

```rust
#[derive(Clone)]
pub struct DaemonConfig {
    pub update_pubkey: [u8; 32],
    pub update_pubkey_path: std::path::PathBuf,
    // ... other config
}
```

Add a loader:

```rust
fn load_update_pubkey() -> anyhow::Result<([u8; 32], std::path::PathBuf)> {
    use std::path::PathBuf;

    let path = std::env::var("RUSTYJACKD_UPDATE_PUBKEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/rustyjack/update_pubkey.ed25519"));

    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("read update pubkey {} failed: {e}", path.display()))?;

    let key = rustyjack_updater::parse_public_key_hex(text.trim())
        .map_err(|e| anyhow::anyhow!("invalid update pubkey {}: {e}", path.display()))?;

    Ok((key, path))
}
```

Load this once at startup and store it in `DaemonConfig`.

#### B.3 — Remove env reading from update job and dispatch

1) In `crates/rustyjack-daemon/src/jobs/kinds/update.rs`:

- Delete `load_update_public_key()`.
- Change `run()` signature to accept the key (or accept a shared config/state handle).

Example:

```rust
pub async fn run<...>(..., update_pubkey: [u8; 32], ...) -> Result<..., DaemonError> {
    let policy = UpdatePolicy { public_key_ed25519: update_pubkey, ... };
    ...
}
```

2) In `dispatch.rs`, remove any env var dependency and read from daemon state/config instead.

#### B.4 — Update the systemd unit

File: `services/rustyjackd.service`

Add:

```ini
ConfigurationDirectory=rustyjack
Environment=RUSTYJACKD_UPDATE_PUBKEY_FILE=/etc/rustyjack/update_pubkey.ed25519
```

(You may omit the env var once you are confident the daemon always uses the default path; keeping it is useful for staging.)

### What fixed looks like
- A fresh install with `/etc/rustyjack/update_pubkey.ed25519` present can run updates without any special env configuration.
- Removing `RUSTYJACKD_UPDATE_PUBKEY` from the environment does not break updates.
- The daemon logs a single startup line like: `update_pubkey loaded from /etc/rustyjack/update_pubkey.ed25519`.

---
## C) Deterministic installation: replace the missing “4 install scripts” with 4 Rust installer binaries

### What is the problem
There is no single, authoritative installation path in the repo that guarantees:

- users/groups exist,
- config directories exist,
- unit files are installed,
- socket/service are enabled,
- the update pubkey file is seeded.

### Where is the problem
The repo contains `services/*.service` and `services/*.socket`, but no end-to-end installer implementation.

### Why is it a problem
- A daemon can be perfect and still fail in production if install is “tribal knowledge”.
- Your security model depends on correct socket permissions, correct directories, and correct unit sandboxing.

### How to fix the problem
Create a new crate: `crates/rustyjack-install/` that builds **four** small Rust binaries (your “4 scripts”), each doing one deterministic stage.

The stages are designed so that they can be executed at image build time or first boot, and each stage is idempotent.

#### C.1 — Create the installer crate

Add a new crate:

```
crates/rustyjack-install/
  Cargo.toml
  src/bin/
    install_01_layout.rs
    install_02_identities.rs
    install_03_systemd.rs
    install_04_seed_config.rs
```

Add dependencies:

- `anyhow`
- `zbus` (systemd D-Bus control)
- `nix` or `libc` (filesystem perms, fsync, etc.)

#### C.2 — install_01_layout: place binaries and unit files

**What:** copy the built binaries and systemd unit files into their final locations.

**Where it writes:**

- Binaries: `/usr/local/bin/` (matches updater policy)
- Units: `/etc/systemd/system/` (explicit and local to device image)

**How:**

- Copy `rustyjackd` and (if you ship it) `rustyjack-ui`.
- Copy `services/rustyjackd.service` and `services/rustyjackd.socket`.
- Ensure file modes:
  - binaries: `0o755`
  - units: `0o644`

Implementation details (must do):

- Use atomic replace: write `*.new`, `fsync`, then `rename`.
- `fsync` the parent directory after renaming.

#### C.3 — install_02_identities: provision group and optional UI user using sysusers.d

Rather than editing `/etc/passwd` and `/etc/group` directly, use systemd’s declarative identity provisioning.

Create file: `/etc/sysusers.d/rustyjack.conf` with these exact lines:

```
g rustyjack -
u rustyjack-ui - "RustyJack UI" - -
m rustyjack-ui rustyjack
```

Notes:

- This creates group `rustyjack`.
- Creates user `rustyjack-ui` (no home/shell specified; systemd-sysusers defaults to `/usr/sbin/nologin`).
- Adds the UI user to the `rustyjack` group so it can connect to the daemon socket.

Your installer binary should:

- Write that file idempotently (same content every time).

You **do not** run `systemd-sysusers` from the installer (that would be “shelling out”). On a systemd system it is processed at boot by `systemd-sysusers.service`, and you can also trigger it via D-Bus if you choose later.

#### C.4 — install_03_systemd: reload units, enable socket, start socket (via D-Bus)

No `systemctl` allowed; use systemd D-Bus.

Implementation steps:

1) Connect to system bus.
2) Call `Reload()` on `org.freedesktop.systemd1.Manager`.
3) Call `EnableUnitFiles(["rustyjackd.socket"], false, true)`.
4) Call `StartUnit("rustyjackd.socket", "replace")`.

(Starting the socket is enough; it will activate the service on first client connect, or you can also `StartUnit("rustyjackd.service", ...)` if you want it hot immediately.)

#### C.5 — install_04_seed_config: create `/etc/rustyjack/` and seed required files

This stage seeds config that must exist on a fresh device.

Required outputs:

- `/etc/rustyjack/update_pubkey.ed25519` (see section B)

Optional but recommended (for auditability):

- `/etc/rustyjack/ops_profile.json` — initial ops toggles (all ON or a safe default).

Your daemon can read `ops_profile.json` on startup and apply it, so the device starts in a known state.

### What fixed looks like
- Running the four installer binaries on a fresh image results in:
  - `rustyjackd.socket` enabled and active,
  - daemon starts on demand,
  - `/etc/rustyjack/update_pubkey.ed25519` exists,
  - UI user (if shipped) can connect to the socket.

---
## D) systemd watchdog must be enabled (unit change + runtime expectations)

### What is the problem
The daemon may be sending watchdog notifications, but systemd will not enforce them unless watchdog supervision is enabled in the unit.

### Where is the problem
`services/rustyjackd.service` does not set `WatchdogSec=` (and should explicitly set `NotifyAccess=` to ensure systemd attributes notifications correctly).

### Why is it a problem
- Without watchdog enforcement, hangs/deadlocks become “silent failure”.
- The Pi is an appliance; you want automatic recovery.

### How to fix the problem
Modify `services/rustyjackd.service`:

Add to `[Service]`:

```ini
Type=notify
NotifyAccess=main
WatchdogSec=20s
```

Runtime contract:

- systemd will set `WATCHDOG_USEC` in the service environment.
- Your daemon must send `WATCHDOG=1` at least once every `WatchdogSec/2` (10s here).

If you already compute the interval from `WATCHDOG_USEC`, keep doing that.

### What fixed looks like
- With the unit updated, systemd restarts the service if watchdog pings stop.
- Your logs show periodic watchdog updates only when watchdog is enabled.

---
## E) UI must show Ops toggles as a first-class status line

### What is the problem
The daemon reports ops toggles in `StatusResponse`, but `rustyjack-ui` does not display them anywhere. Operators can’t tell at a glance why an action is denied.

### Where is the problem
- `crates/rustyjack-ui/src/display.rs` → `StatusOverlay` has no ops fields.
- `crates/rustyjack-ui/src/stats.rs` samples `StatusCommand::Summary` and extracts `status_text` and `dns_spoof_running`, but never extracts ops.

### Why is it a problem
- The UI is the operator’s ground truth on an appliance.
- Ops gating without visibility feels like random failure.

### How to fix the problem
You will thread ops toggles from the status JSON into `StatusOverlay`, then render a compact line in the toolbar.

#### E.1 — Extend StatusOverlay

File: `crates/rustyjack-ui/src/display.rs`

Add fields:

```rust
pub ops_wifi: bool,
pub ops_ethernet: bool,
pub ops_hotspot: bool,
pub ops_portal: bool,
pub ops_update: bool,
pub ops_system: bool,
```

Initialize via `Default` (bools default to false).

#### E.2 — Parse ops toggles in the stats sampler

File: `crates/rustyjack-ui/src/stats.rs`

Add extractor:

```rust
fn extract_ops(map: &serde_json::Map<String, serde_json::Value>) -> Option<(bool,bool,bool,bool,bool,bool)> {
    let ops = map.get("ops")?.as_object()?;
    let b = |k: &str| ops.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    Some((
        b("wifi"),
        b("ethernet"),
        b("hotspot"),
        b("portal"),
        b("update"),
        b("system"),
    ))
}
```

Then, in `sample_once()`, when you handle `StatusCommand::Summary`:

```rust
if let Some(obj) = data.as_object() {
    if let Some((w,e,h,p,u,s)) = extract_ops(obj) {
        overlay.ops_wifi = w;
        overlay.ops_ethernet = e;
        overlay.ops_hotspot = h;
        overlay.ops_portal = p;
        overlay.ops_update = u;
        overlay.ops_system = s;
    }
}
```

#### E.3 — Render the ops line in the toolbar

File: `crates/rustyjack-ui/src/display.rs`

In `draw_toolbar(...)`, add a line such as:

```
WiFi Ops [ON] Eth Ops [ON] HS [OFF] Portal [ON] Upd [ON] Sys [OFF]
```

Implementation detail: keep width short.

- Use abbreviations: `WiFi`, `Eth`, `HS`, `Port`, `Upd`, `Sys`.
- Render `[ON]` or `[OFF]`.
- If it wraps, split across two lines using your existing `wrap_text()` helper.

### What fixed looks like
- The UI always shows ops status.
- When a command is denied, the operator can see which capability is OFF.

---

## Final acceptance checklist (this is what “done” means)

1) **No shellouts in appliance build**
   - CI `forbid_command_new` passes.
   - Default `cargo build -p rustyjack-daemon` does not enable `lab`.

2) **Update pubkey is deterministic**
   - `/etc/rustyjack/update_pubkey.ed25519` exists on fresh image.
   - Update job does not read `RUSTYJACKD_UPDATE_PUBKEY` anywhere.

3) **Install flow is deterministic**
   - Running installer stage 1–4 results in an enabled socket and a working daemon on reboot.

4) **Watchdog enforced**
   - `WatchdogSec` present and daemon restarts on missed pings.

5) **Ops line visible**
   - LCD shows `WiFi Ops [ON] Eth Ops [ON] ...` reflecting daemon state.
