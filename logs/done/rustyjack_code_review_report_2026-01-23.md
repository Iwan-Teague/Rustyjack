# RustyJack Project Review (Pi Zero 2 W “single‑purpose appliance”)

**Date:** 2026‑01‑23  
**Scope:** Source review of the supplied repo snapshot (Rust workspace).  
**Goal:** Identify **big, obvious** improvements, errors, or risks—especially around **daemon behavior, hardware interaction, reliability, and security**—while keeping the “100% Rust / no shelling out” direction in view.

> ⚠️ Important note: This repo contains **“lab/offensive” capabilities** (e.g., reverse shells / MITM / credential capture / anti‑forensics). This review treats those as **high‑risk** and focuses on **hardening the appliance** and **reducing attack surface**, not on improving the offensive functionality.

---

## 1) Executive summary (what to tackle first)

### Priority 0 — “Don’t ship foot‑guns”
1. **Make “appliance” a compile‑time product, not just a runtime profile.**  
   Runtime gating via `RUSTYJACKD_OPS_*` is good, but many high‑risk features appear to be *compiled in* and merely rejected at runtime. If the UI or IPC ever misroutes an operation, the daemon could still execute dangerous code paths.
2. **Eliminate (or quarantine) all external-binary execution from the appliance build.**  
   Source contains calls to tools like `bash`, `openssl`, `exiftool`, `shred`, etc. Even if feature‑gated, they increase audit surface and can drift into “shipping by accident.”
3. **Harden “root autonomy” the right way.**  
   If you keep `User=root`, keep the **capability bounding set** tight and add systemd sandboxing that meaningfully reduces blast radius if a network‑reachable component is compromised.

### Priority 1 — “Reliability on a tiny box”
1. **Audit all blocking operations in async contexts** (daemon + portal): ensure blocking work is in `spawn_blocking` and that the runtime flavor matches the workload.
2. **UI responsiveness / structure:** `crates/rustyjack-ui/src/app.rs` is ~13.5k LOC—high risk for regressions and latent state bugs. Modularize into screen/state machines + reduce polling where possible.
3. **Input validation & file safety:** validate *every* IPC request path (some do; ensure coverage), and enforce safe filesystem writes (atomic writes, permissions, path traversal defense).

### Priority 2 — “Maintainability / cleanup”
1. Remove repo artifacts that shouldn’t ship (`target/`, `target-32/`, bundled logs).
2. Normalize workspace lockfiles (currently multiple `Cargo.lock` files).
3. Reduce `#[allow(dead_code)]`, especially in UI.

---

## 2) Repository + workspace snapshot

### High-level layout
- `crates/…` multi-crate workspace (daemon, UI, portal, netlink, wifi, encryption, updater, etc.)
- `services/*.service` + `rustyjackd.socket` for systemd deployment
- `docs/` contains one UI migration status doc
- `target/` and `target-32/` present in the snapshot (should not be shipped in-source)

### Approximate size
Total Rust LOC (excluding `target*`): **~85,175 lines**

#### LOC by crate (approx.)
- **rustyjack-ui**: ~20,056 LOC
- **rustyjack-core**: ~19,718 LOC
- **rustyjack-netlink**: ~18,079 LOC
- **rustyjack-wireless**: ~10,049 LOC
- **rustyjack-daemon**: ~6,330 LOC
- **rustyjack-evasion**: ~3,357 LOC
- **rustyjack-ethernet**: ~1,508 LOC
- **rustyjack-ipc**: ~1,123 LOC
- **rustyjack-client**: ~1,025 LOC
- **rustyjack-commands**: ~993 LOC
- **rustyjack-wpa**: ~717 LOC
- **rustyjack-portal**: ~700 LOC
- **rustyjack-logging**: ~486 LOC
- **rustyjack-updater**: ~384 LOC
- **root/other**: ~273 LOC
- **rustyjack-install**: ~245 LOC
- **rustyjack-encryption**: ~132 LOC

#### Largest files
- `crates/rustyjack-ui/src/app.rs` (~13,490 LOC)
- `crates/rustyjack-core/src/operations.rs` (~5,423 LOC)
- `crates/rustyjack-core/src/system/mod.rs` (~4,097 LOC)
- `crates/rustyjack-netlink/src/hostapd.rs` (~3,181 LOC)
- `crates/rustyjack-netlink/src/dhcp.rs` (~1,835 LOC)
- `crates/rustyjack-netlink/src/wireless.rs` (~1,710 LOC)
- `crates/rustyjack-ui/src/display.rs` (~1,698 LOC)
- `crates/rustyjack-daemon/src/dispatch.rs` (~1,540 LOC)
- `crates/rustyjack-ethernet/src/lib.rs` (~1,508 LOC)
- `crates/rustyjack-wireless/src/hotspot.rs` (~1,237 LOC)

---

## 3) Deployment architecture review (as implemented)

### Systemd units (good pattern)
- **`rustyjackd.service`**: privileged daemon (currently `User=root`) with socket activation.
- **`rustyjack-ui.service`**: unprivileged UI process using unix socket IPC to daemon.
- **`rustyjack-portal.service`**: separate HTTP server (unprivileged), sandboxed.

This split is the *right* shape for a dedicated appliance: UI/portal should stay unprivileged even if the box “only does this one thing.” Root + network listeners is how you invent your own malware.

---

## 4) Root privilege, sandboxing, and security posture

### What’s already good
- **Socket activation** and **unix-domain IPC**: reduces network exposure.
- Daemon checks **peer credentials** (`SO_PEERCRED`) and enforces group-based tiers in `crates/rustyjack-daemon/src/auth.rs`.
- Systemd hardening already present in daemon/portal units:
  - `NoNewPrivileges=true`
  - `ProtectSystem=strict`, `ProtectHome=true`
  - `PrivateDevices=true` (daemon & portal)
  - capability bounding + ambient caps

### Big improvements to consider (even if you keep `User=root`)
1. **Run the daemon as a dedicated non-root user + capabilities**  
   You already define a bounding set and ambient caps. That’s *exactly* the setup to run as `User=rustyjackd` instead of UID 0.  
   Benefits: filesystem permissions and accidental “root powers” shrink dramatically.
2. **Systemd: add *additional* hardening knobs** (test carefully)
   - `ProtectControlGroups=yes`
   - `ProtectKernelLogs=yes`
   - `ProtectClock=yes`
   - `RestrictNamespaces=yes`
   - `RestrictSUIDSGID=yes`
   - `SystemCallFilter=@system-service` (or a tailored allowlist)
   - `SystemCallErrorNumber=EPERM`
   - `UMask=0077` (daemon unit already sets; keep consistent)
3. **Narrow write access for updates**
   - `ReadWritePaths=/usr/local/bin` is broad. Prefer a dedicated dir:
     - e.g., `/usr/local/lib/rustyjack/` with an atomic symlink swap for binaries
     - or use `StateDirectory=rustyjack` + `BindPaths=` to mount only what’s needed.
4. **Protect the ops override file**
   - `ops_override.json` under the root path can expand permissions. Ensure it is:
     - owned by root
     - mode `0600`
     - and validated against a strict schema with allowlisted keys.
5. **Network egress policy and updates**
   - Daemon/portal units use `IPAddressDeny=any` with a small allowlist. That’s great for minimizing surprise egress—but it likely means **online updates will fail** unless the updater is separated into a unit with broader egress or you add the needed ranges.

---

## 5) Async + blocking analysis (daemon & portal)

### Daemon runtime choice
- `crates/rustyjack-daemon/src/main.rs:26` uses:
  - `#[tokio::main(flavor = "current_thread")]`

**Risk:** any accidental blocking call inside async tasks can freeze the entire daemon.  
**Mitigation pattern:** either
- switch to `multi_thread` (Pi Zero 2 W has multiple cores), or
- keep `current_thread` but enforce a strict rule: *all* blocking work must be `spawn_blocking` (and audited).

### Good news
- `reconcile_on_startup` correctly uses `spawn_blocking` (and its internal sleeps occur inside that blocking closure).
- `netlink_watcher` uses `spawn_blocking` for enforcement calls.

### Suggested improvements
1. **Add an audit CI check** for blocking calls in async contexts.
   - Grep for `std::thread::sleep`, heavy `std::fs::*`, and synchronous netlink reads on the async runtime thread.
2. **Explicit “blocking boundary” modules**
   - Put all blocking work behind functions named `*_blocking()` or in a `blocking` module.
3. **Improve daemon shutdown**
   - The logging watcher threads never stop (fine), but consider explicit shutdown hooks so systemd `StopTimeoutSec` is respected for long operations.

---

## 6) IPC protocol + request validation

### What’s strong
- Frame size limit: `rustyjack-ipc/src/lib.rs` sets `MAX_FRAME = 1_048_576`.
- Daemon config reads `RUSTYJACKD_MAX_FRAME` and uses it consistently.
- Request rate limiting exists per connection (`max_requests_per_second`).

### Improvements
1. **Global rate limiting** (in addition to per-connection)
   - prevents a local process in the operator group from creating many connections and bypassing per-conn throttles.
2. **Validation coverage**
   - `crates/rustyjack-daemon/src/validation.rs` defines good constraints (SSID length, PSK length, etc.). Ensure every route calls the appropriate validators.
3. **Error taxonomy for UI**
   - Ensure all errors propagate as structured codes (vs ad-hoc strings) so the UI can provide actionable guidance instead of “failed.”

---

## 7) Error handling + panic resilience

### Observations
- There are **many** `unwrap()` uses across the workspace (CI appears to enforce a “no new unwraps” baseline, which is good).
- Most crates use `anyhow` + `Context` well in I/O-heavy paths.

### Recommendations
1. **Start removing unwraps in daemon-exposed paths first**
   - The “appliance daemon” should be extremely hostile to panics. Prefer:
     - `thiserror` for domain errors
     - `anyhow` at boundaries only
2. **Use `Result<T, DaemonError>` all the way out**
   - Especially for anything reachable over IPC.
3. **Add a “panic hook”**
   - Log panic backtraces and include a last-known-op in state; systemd restarts are good, but you want actionable diagnostics.

#### Unwrap hot spots (top files)
- `crates/rustyjack-core/src/system/ops.rs`: 28 unwrap() occurrences
- `crates/rustyjack-core/src/system/isolation.rs`: 18 unwrap() occurrences
- `crates/rustyjack-core/src/system/preference.rs`: 16 unwrap() occurrences
- `crates/rustyjack-core/src/system/dns.rs`: 12 unwrap() occurrences
- `crates/rustyjack-core/src/system/mod.rs`: 9 unwrap() occurrences
- `crates/rustyjack-evasion/src/mac.rs`: 9 unwrap() occurrences
- `crates/rustyjack-core/src/system/routing.rs`: 8 unwrap() occurrences
- `crates/rustyjack-wireless/src/pcap.rs`: 5 unwrap() occurrences
- `crates/rustyjack-evasion/src/vendor.rs`: 5 unwrap() occurrences
- `crates/rustyjack-wireless/src/karma.rs`: 4 unwrap() occurrences
- `crates/rustyjack-netlink/src/dhcp_server.rs`: 4 unwrap() occurrences
- `crates/rustyjack-core/src/services/portal.rs`: 4 unwrap() occurrences
- `crates/rustyjack-portal/src/state.rs`: 3 unwrap() occurrences
- `crates/rustyjack-wireless/src/probe.rs`: 3 unwrap() occurrences
- `crates/rustyjack-netlink/src/arp.rs`: 3 unwrap() occurrences

---

## 8) Unsafe code review strategy

This project *must* use unsafe in low-level netlink/wireless work. The question is whether unsafe is:
- contained
- testable
- fuzzable

### Recommended approach
1. **Push unsafe down into the smallest modules possible**
2. **Add fuzzing for parsers**
   - Especially anything parsing frames / netlink attrs / radiotap / 802.11
3. **Use Miri + sanitizers on x86 CI** where possible (even if Pi is target)
4. **Document invariants next to unsafe blocks** (what must be true)

#### Unsafe hot spots (top files)
- `crates/rustyjack-netlink/src/dhcp.rs`: 21 `unsafe` occurrences
- `crates/rustyjack-core/src/system/mod.rs`: 19 `unsafe` occurrences
- `crates/rustyjack-ethernet/src/lib.rs`: 13 `unsafe` occurrences
- `crates/rustyjack-daemon/src/netlink_watcher.rs`: 11 `unsafe` occurrences
- `crates/rustyjack-wireless/src/recon.rs`: 10 `unsafe` occurrences
- `crates/rustyjack-netlink/src/arp_scanner.rs`: 10 `unsafe` occurrences
- `crates/rustyjack-netlink/src/hostapd.rs`: 10 `unsafe` occurrences
- `crates/rustyjack-netlink/src/station/rust_wpa2/l2.rs`: 9 `unsafe` occurrences
- `crates/rustyjack-netlink/src/bridge.rs`: 8 `unsafe` occurrences
- `crates/rustyjack-netlink/src/nf_tables.rs`: 8 `unsafe` occurrences
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs`: 8 `unsafe` occurrences
- `crates/rustyjack-wireless/src/capture.rs`: 7 `unsafe` occurrences
- `crates/rustyjack-wireless/src/inject.rs`: 6 `unsafe` occurrences
- `crates/rustyjack-daemon/src/systemd.rs`: 6 `unsafe` occurrences
- `crates/rustyjack-core/src/mount.rs`: 5 `unsafe` occurrences

---

## 9) Hardware interaction (Pi Zero 2 W)

### UI display + GPIO
- UI uses `linux_embedded_hal::Spidev` + `gpio_cdev` (good modern approach).
- Systemd unit gives UI the right groups: `SupplementaryGroups=… gpio spi`.

### Risks / improvements
1. **Boot-time dependency clarity**
   - Ensure SPI enabled in `/boot/config.txt`, and fail gracefully (headless mode) if not present.
2. **Button input polling**
   - `crates/rustyjack-ui/src/input.rs` polls and sleeps. Consider edge-triggered GPIO events to reduce CPU usage and improve responsiveness.
3. **Error surfaces**
   - If display init fails, UI should provide a clear fallback (e.g., log + blink code + safe shutdown).

---

## 10) Wi‑Fi / networking operations (appliance-focused)

> This section intentionally avoids guidance that improves unauthorized/offensive functionality.

### What looks “architecturally” sound
- There is a strong push toward **pure-Rust Wi‑Fi primitives**:
  - nl80211-based AP bring-up in `crates/rustyjack-netlink/src/hostapd.rs`
  - Rust WPA2 station backend appears to be the default feature (`rustyjack-core` default features include `rust_wpa2`).
- Code explicitly warns and forces the Rust station backend even if env requests an external backend (`wifi_backend_from_env` in `crates/rustyjack-core/src/system/mod.rs`).

### Things to verify on real hardware
1. **Driver/firmware compatibility**
   - nl80211 behavior can vary by chipset/driver.
2. **AP stability**
   - The AP implementation notes that WPA2 is “experimental / CCMP-only.” Plan for soak tests and robust failure reporting.
3. **Interface isolation / reconciliation**
   - Startup reconciliation (`DaemonState::reconcile_on_startup`) is good—validate that it can’t accidentally clobber the UI/uplink interface state.

---

## 11) Captive portal (device security angle)

Portal uses Axum with body size limits, timeouts, and concurrency limits (good).  
However:

1. **Log injection**
   - `PortalLogger` writes raw `ua`, `user`, `pass` into logs without escaping. A crafted value could inject newlines or confuse parsers.
2. **File permissions**
   - `OpenOptions` doesn’t set explicit permissions; it relies on umask. Ensure umask is always set in the unit (or set mode to `0600` in code).

---

## 12) External binaries: inventory + plan

Even if some of this is feature-gated, it is worth tracking aggressively because:
- it breaks the “Rust-only” story,
- it complicates sandboxing,
- and it broadens the audit surface.

### Commands observed in source
- **journalctl**: 5 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:174`)
- **systemctl**: 4 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:260`)
- **tar**: 4 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:408`)
- **bash**: 3 callsite(s) (e.g. `crates/rustyjack-core/src/operations.rs:3357`)
- **openssl**: 3 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:411`)
- **git**: 2 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/git_ops.rs:12`)
- **timeout**: 2 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/physical_access.rs:218`)
- **dphys-swapfile**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:850`)
- **exiftool**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:534`)
- **hostnamectl**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:786`)
- **mount**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:351`)
- **nscd**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:334`)
- **ps**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:756`)
- **shred**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:72`)
- **shutdown**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:626`)
- **swapoff**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:847`)
- **sync**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:314`)
- **sysctl**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/evasion.rs:103`)
- **ulimit**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:485`)
- **umount**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:381`)
- **which**: 1 callsite(s) (e.g. `crates/rustyjack-core/src/external_tools/anti_forensics.rs:56`)
- **wpa_supplicant**: 1 callsite(s) (e.g. `crates/rustyjack-netlink/src/station/external/process.rs:62`)

### Call-site details
### `bash`
  - `crates/rustyjack-core/src/operations.rs:3357` — `crate::external_tools::system_shell::run_allow_failure("bash", &arg_refs)`
  - `crates/rustyjack-core/src/operations.rs:3293` — `let output = crate::external_tools::system_shell::run_allow_failure(`
  - `crates/rustyjack-core/src/operations.rs:3482` — `let output = crate::external_tools::system_shell::run_with_env_allow_failure(`

### `dphys-swapfile`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:850` — `let _ = system_shell::run_allow_failure("dphys-swapfile", &["swapoff"]);`

### `exiftool`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:534` — `let _ = system_shell::run_allow_failure(`

### `git`
  - `crates/rustyjack-core/src/external_tools/git_ops.rs:12` — `system_shell::run("git", &["-C", root_str, "fetch", remote])`
  - `crates/rustyjack-core/src/external_tools/git_ops.rs:16` — `system_shell::run("git", &["-C", root_str, "reset", "--hard", target.as_str()])`

### `hostnamectl`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:786` — `system_shell::run("hostnamectl", &["set-hostname", new_hostname.as_str()])`

### `journalctl`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:174` — `let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:175` — `let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:306` — `let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:307` — `let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:308` — `let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-size=1K"]);`

### `mount`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:351` — `system_shell::run(`

### `nscd`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:334` — `let _ = system_shell::run_allow_failure("nscd", &["-i", "hosts"]);`

### `openssl`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:411` — `system_shell::run(`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:456` — `system_shell::run(`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:716` — `system_shell::run(`

### `ps`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:756` — `let output = system_shell::run_allow_failure("ps", &["aux"])?;`

### `shred`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:72` — `system_shell::run("shred", &arg_refs).context("running shred")?;`

### `shutdown`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:626` — `let _ = system_shell::run_allow_failure("shutdown", &["-h", "now"]);`

### `swapoff`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:847` — `let _ = system_shell::run_allow_failure("swapoff", &["-a"]);`

### `sync`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:314` — `let _ = system_shell::run_allow_failure("sync", &[]);`

### `sysctl`
  - `crates/rustyjack-core/src/external_tools/evasion.rs:103` — `let output = system_shell::run_allow_failure("sysctl", &["-w", arg.as_str()])`

### `systemctl`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:260` — `system_shell::run_allow_failure("systemctl", &["disable", "rustyjack.service"])`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:309` — `let _ = system_shell::run_allow_failure("systemctl", &["daemon-reload"]);`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:310` — `let _ = system_shell::run_allow_failure(`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:328` — `let _ = system_shell::run_allow_failure(`

### `tar`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:408` — `system_shell::run("tar", &["-czf", tar_str, loot_dir_str])`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:472` — `system_shell::run("tar", &["-xzf", tar_str, "-C", root_str])`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:713` — `system_shell::run("tar", &["-czf", tar_str, loot_dir_str])`
  - `crates/rustyjack-core/src/external_tools/archive_ops.rs:32` — `system_shell::run(`

### `timeout`
  - `crates/rustyjack-core/src/external_tools/physical_access.rs:218` — `system_shell::run_allow_failure("timeout", &["10", "avahi-browse", "-at", "-r"]);`
  - `crates/rustyjack-core/src/external_tools/physical_access.rs:445` — `let output = system_shell::run_allow_failure(`

### `ulimit`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:485` — `let _ = system_shell::run_allow_failure("ulimit", &["-c", "0"]);`

### `umount`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:381` — `system_shell::run("umount", &[ram_dir_str]).context("unmounting tmpfs")?;`

### `which`
  - `crates/rustyjack-core/src/external_tools/anti_forensics.rs:56` — `let shred_available = system_shell::run_allow_failure("which", &["shred"])`

### `wpa_supplicant`
  - `crates/rustyjack-netlink/src/station/external/process.rs:62` — `let output = Command::new("wpa_supplicant")`

### Recommendations
1. **Appliance build should compile without these modules**
   - Prefer `cfg(feature = "lab")` fences around entire files/modules.
2. **Add a “release gate” CI job**
   - Build the exact appliance binaries and assert:
     - `ripgrep "Command::new" crates/…` returns zero reachable callsites
     - no `external_tools` modules are included
3. **Move lab tools into a separate workspace or crate**
   - So the appliance tree remains small and auditable.

---

## 13) Dependency and supply-chain hygiene

### Observations
- There are multiple lockfiles:
  - workspace root `Cargo.lock`
  - `crates/rustyjack-core/Cargo.lock`
  - `crates/rustyjack-ui/Cargo.lock`

This can produce non-reproducible builds and makes auditing harder.

### Recommendations
1. **Single workspace lockfile** for the appliance build.
2. Add:
   - `cargo audit`
   - `cargo deny` (licenses + bans + advisories)
   - `cargo vet` (optional but strong)
3. Use `reqwest` with `rustls` (already configured 👍) and pin minimum TLS where possible.

---

## 14) Repo hygiene / removal candidates

### Likely “should not be in source distribution”
- `target/`
- `target-32/`
- `logs/` (pre-existing logs should not ship; let the runtime create)

### Dead-code allowances (signals for cleanup)
- `crates/rustyjack-ui/src/app.rs`: 9 `#[allow(dead_code)]`
- `crates/rustyjack-ui/src/types.rs`: 7 `#[allow(dead_code)]`
- `crates/rustyjack-ui/src/display.rs`: 6 `#[allow(dead_code)]`
- `crates/rustyjack-netlink/src/wireless.rs`: 5 `#[allow(dead_code)]`
- `crates/rustyjack-ui/src/menu.rs`: 4 `#[allow(dead_code)]`
- `crates/rustyjack-wireless/src/process_helpers.rs`: 4 `#[allow(dead_code)]`
- `crates/rustyjack-wireless/src/interface.rs`: 2 `#[allow(dead_code)]`
- `crates/rustyjack-wireless/src/rfkill_helpers.rs`: 2 `#[allow(dead_code)]`
- `crates/rustyjack-netlink/src/dhcp.rs`: 2 `#[allow(dead_code)]`
- `crates/rustyjack-portal/src/logging.rs`: 1 `#[allow(dead_code)]`
- `crates/rustyjack-ui/src/core.rs`: 1 `#[allow(dead_code)]`
- `crates/rustyjack-ui/src/util.rs`: 1 `#[allow(dead_code)]`

---

## 15) Suggested roadmap (“what to do next”)

### Phase A — Appliance hardening (1–2 sprints)
- Introduce `feature = "appliance"` that **compiles out** lab/offensive code paths.
- Ensure daemon runs as a non-root user with capabilities (or keep root but tighten sandboxing).
- Add a “release build” CI job that produces appliance artifacts and runs:
  - `cargo audit`
  - “no external binaries reachable” checks
  - basic integration tests

### Phase B — Reliability & UX polish (2–4 sprints)
- Break `app.rs` into modules: screens, state machine, render, input, rpc client.
- Replace polling GPIO with edge events where possible.
- Improve daemon progress reporting so UI can show “what’s happening” (timeouts, retries, current step).

### Phase C — Robustness & correctness (ongoing)
- Fuzz parsers and unsafe-heavy modules.
- Expand validation and structured error codes.
- Add soak tests: AP up for 24h, station connect/disconnect loops, portal request bursts.

---

## Appendix A — Quick “high-risk” code locations to audit

- Daemon runtime configuration:
  - `crates/rustyjack-daemon/src/main.rs` (`current_thread` runtime)
- Large stateful UI logic:
  - `crates/rustyjack-ui/src/app.rs` (~13.5k LOC)
- Operational dispatch surface:
  - `crates/rustyjack-daemon/src/dispatch.rs`
  - `crates/rustyjack-core/src/operations.rs`
- Low-level network + unsafe:
  - `crates/rustyjack-netlink/src/*`
  - `crates/rustyjack-wireless/src/*`
- Portal logging:
  - `crates/rustyjack-portal/src/logging.rs`

---

## Appendix B — Notes on scope and constraints

- This review did **not** attempt to validate “offensive” capability correctness (nor recommend improvements there).
- Hardware correctness ultimately needs a short **on-device validation plan** (smoke tests + soak tests) because nl80211 and timing behaviors are chipset/firmware sensitive.


---

## References (external)

- systemd unit hardening options: `systemd.exec` manual: https://www.freedesktop.org/software/systemd/man/systemd.exec.html
- systemd IP allow/deny filtering: `systemd.resource-control` manual: https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html
- Tokio runtime scheduling details: Tokio runtime docs: https://docs.rs/tokio/latest/tokio/runtime/index.html
- RustSec advisory tooling: `cargo-audit` README: https://github.com/rustsec/rustsec/blob/main/cargo-audit/README.md and RustSec overview: https://rustsec.org/
