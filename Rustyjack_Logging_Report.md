# Rustyjack - Logging Deep Dive (Workspace Report)

**Date:** 2026-01-07  
**Target deployment:** Raspberry Pi Zero 2 W, Raspberry Pi OS Lite 32-bit (Trixie), CLI-only  
**Focus:** What gets logged today, where it goes, what is missing, and a roadmap to a custom Rust-native logging stack (minimizing or eliminating reliance on systemd/journald for Rustyjack logs).

---

## 0. Executive summary (what matters)

Rustyjack *does* currently rely on the Linux/systemd logging stack for end-to-end log collection and retrieval:

- Most Rustyjack components log to **stdout/stderr** (directly or via `env_logger` / `tracing_subscriber`) and **systemd-journald captures it**. Service units explicitly route output to the journal in places (e.g., `rustyjack-portal.service`) and implicitly in others (default behavior).
- Rustyjack’s “export logs / diagnostics” pipeline is implemented by calling external tools like **`journalctl`** (and for GPIO diagnostics: `gpioinfo`, `lsof`, `fuser`, `ls`). This is a hard dependency on the OS logging/userspace tooling.
- The codebase uses **three different “log surfaces”**:
  1) `log` crate macros (`log::info!`, `log::warn!`, …)  
  2) `tracing` macros (`info!`, `warn!`, spans, etc.)  
  3) raw `println!/eprintln!` (not level-controlled, always emitted)

### The big practical problem (right now)

In the current service-style deployment, **a large fraction of “instrumented” logs never actually get emitted**, because the daemon (`rustyjackd`) initializes **`tracing`**, but most of the work it calls (core / wireless / portal library / netlink helpers) uses the **`log`** crate.

Unless you install a `log` backend (or bridge `log` -> `tracing`), those `log::info!` lines are effectively **no-ops** in the daemon process. That means:

- The daemon emits request telemetry and a handful of `tracing` logs, **but the detailed core/wireless/portal logs are silently dropped**.
- Job lifecycle logs exist in `rustyjack-daemon/src/jobs/mod.rs` (queued/running/completed/failed), but they use `log::{info, debug}` and are currently **dropped** under daemon runtime.
- The embedded portal (`rustyjack_portal::start_portal`) uses `log` macros; when run embedded under `rustyjackd`, those logs are **dropped**, leaving you blind when portal startup fails.

So: Rustyjack *has logging call sites*, but in its current architecture it is **not consistently wired**.

### Roadmap headline

1) **Unify the logging pipeline in-process** (single approach, consistent sinks, bridging `log` <-> `tracing`).  
2) **Add a Rust-managed log store** (rotated file(s), optional in-memory ring buffer) so Rustyjack logs are available even without journald.  
3) **Replace the log export / diagnostics collector** with Rust-only implementations (no `journalctl`, no `gpioinfo`, no `lsof`, etc.).  
4) Optionally: **reduce systemd to “bootstrapping” only**, or go full appliance mode with a Rust supervisor (systemd replacement is possible but massive in scope).

---

## 1. System architecture (logging-relevant view)

### Processes / components you have today

- **`rustyjack-ui`**  
  Unprivileged UI (LCD/menu). Calls into the daemon over a Unix socket.

- **`rustyjackd` (rustyjack-daemon)**  
  Root daemon. Owns privileged ops. Receives IPC requests and dispatches work into `rustyjack-core` and other crates. Uses systemd socket activation and `sd_notify`.

- **`rustyjack-core`**  
  The “brains” library + CLI entrypoint (some CLI-only extras). Most of its logs are `log::info!/warn!/…`.

- **`rustyjack-wireless`**, **`rustyjack-netlink`**, **`rustyjack-wpa`**, **`rustyjack-evasion`**  
  Lower-level subsystems. Predominantly `log` macros plus a non-trivial amount of raw `println!/eprintln!`.

- **`rustyjack-portal`**  
  Captive portal. Exists as both:
  - an external binary (`rustyjack-portal/src/bin/main.rs`) using `env_logger`
  - an embedded library server (`rustyjack-portal/src/state.rs`) started from core and commonly run *inside the daemon process*

### systemd units / journald integration

Relevant unit files in the workspace:

- `rustyjack-ui.service` (runs UI; default stdout/stderr -> journal)
- `rustyjackd.socket` + `rustyjackd.service` (socket-activated daemon; stdout/stderr -> journal)
- `rustyjack-portal.service` (explicit `StandardOutput=journal`, `StandardError=journal`)

---

## 2. What Rustyjack uses for logging right now

### 2.1 Logging crates & patterns in the codebase

**(A) `log` crate** (dominant)

- Widely used across: `rustyjack-core`, `rustyjack-wireless`, `rustyjack-netlink`, `rustyjack-portal` (library mode), `rustyjack-evasion`, etc.
- Example patterns:
  - `log::info!("[WIFI] ...")`
  - `use log::{info, debug}; info!("job_id=...")`

**(B) `env_logger`** (used by some binaries)

- `rustyjack-core/src/main.rs` initializes `env_logger` if logs are enabled.
- `rustyjack-portal/src/bin/main.rs` initializes `env_logger` with default filter `info`.

This means those *binaries* are “log-wired”, but libraries aren’t (they rely on the binary to install a logger).

**(C) `tracing` + `tracing-subscriber`** (daemon-only today)

- `rustyjack-daemon/src/main.rs` sets up a `tracing_subscriber` registry and a compact fmt layer to stdout.
- This gives you structured-ish logs and spans *within the daemon*, but it **does not capture `log` crate events** unless bridged.

**(D) Raw `println!/eprintln!`** (not level-controlled)

Used heavily in:
- `rustyjack-wireless/src/hotspot.rs` (very chatty, mostly `eprintln!("[HOTSPOT] ...")`)
- `rustyjack-netlink/src/dns_server.rs`, `dhcp_server.rs`, `process.rs`
- `rustyjack-ui/src/display.rs` (console rendering fallback/diagnostics)

### 2.2 “System log bundle” exporter depends on Linux tools

The daemon exposes a “system logs” endpoint which calls `rustyjack_core::services::logs::collect_log_bundle(root)`.

This function shells out to:

- `journalctl` (UI unit, kernel logs, system logs, NetworkManager, wpa_supplicant)

And the GPIO diagnostics endpoint shells out to:

- `gpioinfo`
- `lsof`
- `fuser`
- `ls`

So log export is currently:
- journal-centric
- toolchain-dependent
- and not portable

There is already a planning doc in the repo: `LOGGING_USB_RUST_ONLY_PLAN.md` (root + docs/). Your instincts here are aligned with existing intent.

---

## 3. Does Rustyjack rely on Linux/systemd for logging?

### 3.1 In practice: yes

**Operationally** (on Raspberry Pi OS Lite with systemd), the “central truth” of logs is:

- stdout/stderr captured by journald
- queried via `journalctl`

Rustyjack explicitly uses `journalctl` in:
- `rustyjack-core/src/services/logs.rs` (log bundle collector)
- `rustyjack-core/src/anti_forensics.rs` (journal rotate/vacuum during log clearing / purge)

It also depends on systemd concepts for runtime behavior:
- socket activation (`LISTEN_FDS`, `LISTEN_PID` handling)
- readiness notification (`sd_notify`)

### 3.2 Important nuance: relying on journald is not inherently wrong

Systemd/journald gives you:
- log capture + metadata (unit, PID, UID)
- rotation, retention, compression
- query tooling
- rate limiting and abuse handling

For an appliance-like Pi deployment, that’s “free infrastructure”.

But: if the project goal is “as much Rust as possible” and portability/minimal external dependencies, you can absolutely move Rustyjack *logs* off journald and onto a Rust-native store.

Replacing **systemd itself** is a separate, much larger project (see Section 8).

---

## 4. What is logged today (and what *actually* gets emitted)

This section separates:
- **Instrumented**: code contains log statements
- **Emitted**: those statements are wired to a backend and show up in real logs

### 4.1 `rustyjackd` (daemon) - emitted logs

**What is emitted (today):**
- daemon startup/shutdown lines (`info!`)
- startup reconciliation enforcement (`state.rs`)
- netlink watcher events
- per-request telemetry via `telemetry::log_request()`:
  - request id, endpoint, peer uid/pid, duration, result

**What is instrumented but not emitted (today):**
- Job lifecycle logs (`rustyjack-daemon/src/jobs/mod.rs`) use `log::{info, debug}` and no log backend is installed in the daemon.
- Any `log::info!` inside `rustyjack-core`, `rustyjack-wireless`, `rustyjack-netlink`, `rustyjack-portal` (embedded) when invoked from the daemon.

**Net effect:** You currently get “RPC audit-ish” logs, but you *don’t get the deep operational logs* that would make debugging attacks/network state changes tractable.

### 4.2 `rustyjack-ui` - emitted logs

**What is emitted (today):**
- Console display output and diagnostics via `println!/eprintln!` in `display.rs` (only if console display path is active)
- Some errors printed directly via `eprintln!` in a few UI paths

**What is instrumented but not emitted:**
- `log::info!/warn!/…` call sites exist (e.g., `app.rs`), but the UI binary does **not initialize a logger**, so these are no-ops.

### 4.3 Portal logging - depends on mode

**External portal binary (`rustyjack-portal/src/bin/main.rs`):**
- Uses `env_logger`, so its `log::info!` events emit to stdout and are captured by journald.
- Additionally, it writes structured capture logs to files (below).

**Embedded portal library (common path via daemon):**
- Uses `log::info!/error!` in `rustyjack-portal/src/state.rs`, etc.
- When run inside `rustyjackd`, those are currently **dropped** (same log backend issue).

**Portal capture logs (file-based):**
- `PortalLogger` writes to:
  - `credentials.log` (captured credentials)
  - `visits.log` (requests/visits)
These are written under the configured `capture_dir` (defaults to `/var/lib/rustyjack/loot/Portal` in core’s embedded config).

### 4.4 File-based “loot / report” logs

These are *not* “system logs”, but they are part of Rustyjack’s logging footprint:

- `loot/reports/mac_usage.log` (JSON lines of MAC policy usage)
- `loot/reports/payload.log` (payload emissions)
- UI/core “scoped logs” under `loot/<scope>/<target>/<action>/logs/*.log` (created by:
  - `rustyjack-core/src/operations.rs::write_scoped_log_lines`
  - `rustyjack-ui/src/util.rs::write_scoped_log`)

These respect `RUSTYJACK_LOGS_DISABLED` in-process, but see Section 6.3: the UI toggle does not currently propagate to the daemon process.

### 4.5 Kernel / nf_tables logging

`rustyjack-netlink/src/iptables.rs` supports `RUSTYJACK_NFTABLES_LOG=1` which installs nftables rules that log packets with a `[NFTABLE]` prefix. Those messages go via the kernel log pathway and are visible via `journalctl -k` (or `dmesg`).

If you move away from journald, you’ll want to capture kernel log tail (`/dev/kmsg`) if you still care about these events.

---

## 5. Inventory snapshot (where the log statements are)

This is a quick “where to look” map. Counts are approximate and based on searching for `log::` and `println!/eprintln!` patterns.

| Crate | log:: usage | tracing:: usage | println/eprintln usage | Notes |
|------:|------------:|----------------:|------------------------:|------|
| `rustyjack-core` | ~173 | small | small | Rich instrumentation, currently dropped under daemon unless bridged |
| `rustyjack-netlink` | ~152 | 0 | ~47 | Mix of proper logging and raw prints |
| `rustyjack-wireless` | ~109 | 0 | ~73 | Hotspot path is extremely chatty via `eprintln!` |
| `rustyjack-portal` | ~18 | 0 | 0 | Emits only in external binary mode today |
| `rustyjack-ui` | ~14 | 0 | ~54 | UI does not init log backend; many prints are console-display related |
| `rustyjack-daemon` | few `log::` | some `tracing` | 0 | Mixed logging frameworks; missing bridging |

Top “hot files” by log/print density:
- `rustyjack-wireless/src/hotspot.rs` (largest print/log emitter)
- `rustyjack-netlink/src/hostapd.rs`
- `rustyjack-core/src/operations.rs`
- `rustyjack-core/src/system/mod.rs`

---

## 6. Gaps: what isn’t logged (or isn’t loggable) today

### 6.1 The “dropped logs” problem (framework mismatch)

As described earlier, **most operational logs never hit a sink** in the daemon runtime.

This makes the apparent instrumentation in core/wireless/netlink misleading:
- developers see `log::info!` in code and assume it exists in production logs
- but it is dropped when invoked via `rustyjackd`

### 6.2 Missing “who did what” audit trail

The daemon logs request telemetry, but it does not consistently log:

- authorization decisions (allowed/denied) at an appropriate level
- “dangerous operations” (reboot/shutdown, MAC randomization, iptables/nft changes) with actor context
- configuration changes (UI toggles) as durable events

### 6.3 The “logs toggle” does not propagate across processes

The UI toggles logging by setting/unsetting `RUSTYJACK_LOGS_DISABLED` **inside the UI process** and saving config.

That does **not** affect:
- `rustyjackd` (different process, started by systemd)
- any embedded portal running inside `rustyjackd`
- any file logs written by core while invoked in daemon

So the user-facing “Logs ON/OFF” is currently a partial illusion: it affects only UI-local log behavior (like scoped loot logs written from UI), not the system.

### 6.4 Overuse of raw `eprintln!` in library code

Anything that uses `println!/eprintln!`:

- cannot be filtered by log level
- cannot be redirected independently to different sinks
- may spam journald, create noise, and make log export huge
- makes “logs disabled” hard (you can disable `log` crate but not `eprintln!`)

The hotspot subsystem is the primary offender.

### 6.5 Sensitive data leakage risk

Some log statements include or can include secrets:
- WPA crack path logs “password found” (highly sensitive)
- portal captures are written to disk intentionally (credentials)
- some network configuration logs could include SSIDs, BSSIDs, etc (maybe fine)

If you unify logging and start writing everything to a persistent file store, you must make an explicit policy decision:
- which events go to the general operational log?
- which events are “loot” and should be stored separately and access-controlled?

---

## 7. Roadmap: custom, Rust-native logging for Rustyjack

This roadmap is designed to hit your goals in a sane order:
- Step 1: make logs correct and visible
- Step 2: make logs independent of journald
- Step 3: make log export tool-free (Rust-only)
- Step 4: add higher-quality structured/audit logging

### Phase 1 - Fix logging correctness (unify in-process)

**Goal:** All logging call sites emit consistently in every process (daemon/UI/portal), even before you replace journald.

#### 7.1.1 Standardize on `tracing` as the “one true pipeline”
Why `tracing`:
- supports spans (request/job context propagation)
- supports structured fields (great for tooling later)
- can output both human text and JSON
- works well in async code

**Immediate compatibility trick:** bridge `log` crate into `tracing`.

Add dependency:
```toml
# workspace / relevant crates
tracing-log = "0.2"
```

In the daemon init (early in `main()`), add:
```rust
use tracing_log::LogTracer;

fn init_logging() {
    // Route `log::info!` etc into tracing, so core/wireless/netlink logs aren't dropped.
    let _ = LogTracer::init();

    // Existing tracing_subscriber init...
}
```

Now, *without touching core/wireless/netlink*, their `log::...` statements become `tracing` events and start showing up.

This is the single highest-impact change for debugging.

#### 7.1.2 Fix `rustyjack-daemon` internal inconsistency

In `rustyjack-daemon/src/jobs/mod.rs`, change:
```rust
use log::{debug, info};
```

To:
```rust
use tracing::{debug, info};
```

Or keep it as-is if you add `LogTracer::init()`.  
But even with LogTracer, prefer `tracing` for daemon-owned code so spans/fields are first-class.

#### 7.1.3 Initialize logging in `rustyjack-ui`

Add a logging init at the top of `rustyjack-ui/src/main.rs`:
- either a minimal `env_logger::init()` (short-term)
- or the unified `tracing_subscriber` init (preferred)

If you keep journald for now, simply logging to stdout is enough.

#### 7.1.4 Decide what to do with `println!/eprintln!`

At minimum, move raw prints behind a log macro:

```rust
// before
eprintln!("[HOTSPOT] Starting hostapd...");

// after
tracing::info!(target: "hotspot", "Starting hostapd...");
```

For UI console-rendering prints, consider gating with an env flag:
- `RUSTYJACK_CONSOLE_RENDER=1` to allow verbose prints in dev
- keep it off in production services

### Phase 2 - Add a Rust-managed log store (no journald required)

**Goal:** Rustyjack logs persist even if journald is absent or unwanted.

#### 7.2.1 Add a dedicated log directory

Recommended:
- `/var/lib/rustyjack/logs/`

Ownership:
- daemon (root) owns it
- either:
  - make logs read-only to the UI via group permissions, or
  - expose log read endpoints via the daemon (preferred)

#### 7.2.2 Add file rotation (Rust side)

Use `tracing_appender` (pure Rust) with non-blocking writers:
```toml
tracing-appender = "0.2"
```

Sketch:
```rust
use tracing_appender::rolling;
use tracing_subscriber::{fmt, EnvFilter};

pub struct Guards {
    _file_guard: tracing_appender::non_blocking::WorkerGuard,
}

pub fn init(component: &str, log_dir: &Path) -> Guards {
    let file_appender = rolling::daily(log_dir, format!("{component}.log"));
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stdout))      // optional
        .with(fmt::layer().with_writer(file_writer).json())   // or compact text
        .init();

    Guards { _file_guard: guard }
}
```

**Pi Zero 2 W note:** prefer non-blocking + buffered writes and avoid fsync-per-line. Rotation “daily” is usually fine; size-based rotation is fine too.

#### 7.2.3 Component identity in every log event

Make sure every process includes a component field:
- `component=rustyjackd`
- `component=rustyjack-ui`
- `component=portal`

In `tracing`, you can enforce this with a span around `main`:
```rust
let span = tracing::info_span!("process", component="rustyjackd");
let _enter = span.enter();
```

Then file logs are filterable without systemd unit metadata.

### Phase 3 - Replace log export (`journalctl`) with Rust-only log extraction

**Goal:** The “export logs to USB” flow works without calling external binaries.

This aligns with the existing `LOGGING_USB_RUST_ONLY_PLAN.md`.

#### 7.3.1 Replace `journalctl` sections with “tail our own logs”

In `rustyjack-core/src/services/logs.rs`, replace the `append_command_output(...journalctl...)` calls with:
- read last N KB / last N lines from Rustyjack log files:
  - `/var/lib/rustyjack/logs/rustyjackd.log`
  - `/var/lib/rustyjack/logs/rustyjack-ui.log`
  - `/var/lib/rustyjack/logs/portal.log` (if external)
- optionally include:
  - kernel ring buffer tail via `/dev/kmsg` (see below)

Rust “tail” technique:
- seek near end (bounded) and read forward
- or read backwards line-by-line (more complex but doable)

Pseudo:
```rust
fn tail_file(path: &Path, max_bytes: usize) -> String {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len() as usize;
    let start = len.saturating_sub(max_bytes);
    f.seek(SeekFrom::Start(start as u64)).ok()?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).ok()?;
    buf
}
```

#### 7.3.2 Kernel log tail without journald

Read `/dev/kmsg` (root-only) or `/proc/kmsg`:
- you can capture last N lines by reading from the ring buffer
- or snapshot “since boot” at export time

Minimal approach for export:
- read `/dev/kmsg` non-blocking
- keep an in-memory ring buffer in daemon
- export its tail

This also captures `[NFTABLE]` messages if nftables logging is enabled.

#### 7.3.3 Replace GPIO diagnostics shell-outs

The existing plan document already lists replacements. The high-level Rust approach:

- Replace `gpioinfo` with direct interaction via `libgpiod` (Rust crate `gpiod`) or raw character device ioctls (more work).
- Replace `lsof` / `fuser` with scanning `/proc/*/fd` symlinks for `/dev/gpiochip0`.
- Replace `ls -l` with `std::fs::metadata` plus major/minor extraction (via `std::os::unix::fs::MetadataExt`).

### Phase 4 - Make logs first-class in the Rustyjack UI (without journald)

**Goal:** UI can view logs and export logs without being able to mutate them.

Recommended:
- daemon exposes:
  - `LogsTail { component, max_lines }`
  - `LogsExportBundle { include_kernel_tail, include_state_snapshots }`
- UI calls daemon and renders logs on-screen / exports to USB

This avoids permission complexity (UI doesn’t need read access to `/var/lib/rustyjack/logs`).

### Phase 5 - Optional: reduce or eliminate systemd’s role

At this point, Rustyjack logs are journald-independent.

If you want to reduce systemd further:

- **Option A (realistic):** Keep systemd as “boot launcher” only  
  Run a single `rustyjack-supervisor` service (Rust) which:
  - starts `rustyjackd`, `rustyjack-ui`, optionally portal
  - captures stdout/stderr
  - writes unified logs
  - restarts children on failure

- **Option B (hard mode):** Replace PID 1 / init with Rust  
  This is a huge scope jump:
  - mounting filesystems, udev, networking, time sync, watchdog, etc.
  - you basically become your own distro

For a dedicated Pi appliance, Option A gives 90% of the benefit with 10% of the pain.

---

## 8. “Can systemd/journald be part of Rustyjack, fully in Rust?”

Short answer:
- **Logging:** yes, you can replicate the parts you need in Rust.
- **Systemd as a whole:** not realistically, unless Rustyjack becomes its own OS distribution or ships a custom init.

What you *can* do (pragmatic middle ground):
- implement a Rust-native **log daemon** (or embed into `rustyjackd`)
- implement a Rust-native **process supervisor** (optional)
- leave systemd in place as the bootstrapping init

This still satisfies the “Rustyjack controls its own logging and storage” requirement.

---

## 9. Concrete “where to add code” plan (developer-facing)

This section is intentionally specific.

### 9.1 Add a new crate: `rustyjack-logging`

Create `rustyjack-logging/` with:
- `init(component, root_path, mode)` that:
  - checks `logs_disabled()` (and/or daemon-config)
  - installs `LogTracer` to capture `log` crate
  - sets up `tracing_subscriber`:
    - stdout layer (optional)
    - file layer (rotated)
    - optional JSON format for file

Expose a return guard that must be held for lifetime:
```rust
pub struct LoggingGuards {
    _file: tracing_appender::non_blocking::WorkerGuard,
}
```

Add to workspace `Cargo.toml` and depend from binaries:
- `rustyjack-daemon`
- `rustyjack-ui`
- `rustyjack-portal` binary
- `rustyjack-core` CLI

### 9.2 Modify `rustyjack-daemon/src/main.rs`

Replace `init_tracing()` with:
```rust
let _guards = rustyjack_logging::init("rustyjackd", &config.root_path)?;
```

Then, make sure work is under spans:

- request spans already exist in `server.rs`
- add job spans in `JobManager::run_job`:
```rust
let span = tracing::info_span!(
    "job",
    job_id,
    kind = %kind_name,
    requested_by = %requested_by
);
let _enter = span.enter();
// execute the job...
```

Now, all bridged `log::info!` from core/wireless/netlink/portal inside this job include `job_id` context.

### 9.3 Modify `rustyjack-ui/src/main.rs`

Add:
```rust
let root = ...; // existing root resolution
let _guards = rustyjack_logging::init("rustyjack-ui", &root)?;
```

If you choose “daemon-owned logs only”, then UI logging should send to daemon (Phase 4). But you can start with local file logs and consolidate later.

### 9.4 Fix the log toggle propagation

Add a daemon IPC endpoint (new in `rustyjack-ipc`):

- `SystemLoggingSet { enabled: bool }`
- daemon:
  - updates its `tracing` filter dynamically (use `tracing_subscriber::reload`)
  - persists to `root/config/logging.json` (or reuse `gui_conf.json`, but separate is cleaner)
- UI:
  - when toggle is changed, call the daemon endpoint
  - stop setting env var as the primary mechanism

Then update `rustyjack-evasion::logs_disabled()` to check:
- env var (dev override)
- config file (system-wide truth)

### 9.5 Replace raw prints in subsystems

Start with the high-impact ones:

- `rustyjack-wireless/src/hotspot.rs`
- `rustyjack-netlink/src/dns_server.rs`
- `rustyjack-netlink/src/dhcp_server.rs`
- `rustyjack-netlink/src/process.rs`

Mechanically:
- `eprintln!` -> `tracing::info!` or `tracing::warn!`
- add structured fields:
  - interface names
  - ports
  - channels
  - durations
- guard very-chatty logs behind debug level

Example:
```rust
tracing::debug!(target="hotspot", step="hostapd", "waiting for hostapd ready");
```

### 9.6 Update the log bundle collector

In `rustyjack-core/src/services/logs.rs`:

- include daemon logs (today it collects only `rustyjack-ui.service` journal output)
- after Phase 3, stop calling journalctl entirely:
  - include `tail_file(/var/lib/rustyjack/logs/rustyjackd.log, ...)`
  - include kernel tail
  - include sysfs snapshots (already Rust-native)

---

## 10. Suggested logging policy (so you don’t regret this later)

Given Rustyjack’s domain, define categories:

1) **Operational log** (debuggable, non-sensitive)
   - job start/stop, interface changes, errors, state transitions
   - redacted values
   - rotated retention

2) **Audit log** (who did what)
   - actor identity (uid/gid/group), request_id
   - privileged operations performed
   - minimal data, durable (but still purgeable if anti-forensics)

3) **Loot logs** (sensitive outcomes)
   - cracked keys, captured credentials, etc.
   - stored under loot with strict permissions
   - never mirrored to the operational log by default

4) **High-volume trace** (optional)
   - packet-level, DNS query debug, hostapd handshake debug
   - off by default; can be enabled with explicit knob

Enforce redaction by design:
- Provide `redact!()` helper for secrets
- Use `#[instrument(skip(password, psk, ...))]` patterns when you migrate to `tracing`

---

## 11. Closing assessment: are current logs detailed enough?

- **Detail exists in code** (core/wireless/netlink have many call sites), but **it isn’t wired** under the daemon runtime, so the system is effectively under-logged where it matters.
- Some subsystems (hotspot) are *over-logged* via raw prints, and that verbosity is not controllable.
- The log export bundle does not currently include daemon logs, which is where most operations now run. So even if journald capture is working, the exported diagnostics will miss key data.

The immediate priority is therefore not “more log lines”, but **make existing log lines actually show up**, then shape them into a coherent, Rust-owned log store with clear policy boundaries.

---
