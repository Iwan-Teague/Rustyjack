# Shell-out audit report

Project: **watchdog_shallow/watchdog (Rustyjack)**  
Snapshot date: **2026-01-27**


## Executive summary

This scan looked for any runtime process execution (i.e., shelling out to non-Rust binaries) in the uploaded snapshot. In the current code, **all** shell-outs are either:

- `std::process::Command` directly (only `wpa_supplicant`), or
- routed through `crates/rustyjack-core/src/external_tools/system_shell.rs` (feature-gated `external_tools`).

So the fastest path to a “Rust-only appliance build” is already encoded in Cargo features: **ship with `rustyjack-core` default `appliance` feature and do not enable `external_tools` or `station_external`.**

That said, the repo still contains many shell-out code paths behind those features. The rest of this report inventories every binary and provides Rust-only replacement directions.


## Scope update: ignore install_rustyjack scripts

This version of the report treats **anything executed only during install / provisioning** as **out of scope** for “Rust-only at runtime on the Pi”.

That means:
- Any shell-outs performed by `install_rustyjack*.sh` (the installers) are **allowed to remain**.
- Any binaries that appear *both* at install time **and** at runtime are still a runtime concern — but their *installer* usage is marked as “NO ACTION (setup-only)”.

⚠️ Note: the actual `install_rustyjack*.sh` script bodies are **not present in this snapshot** (only referenced in docs), so “Install scripts?” markings are based on the project’s installer documentation (e.g. `AGENTS.md`, `INSTALL_SCRIPTS_FIX.md`). Expect some false negatives.

### Installer binaries observed / referenced in docs (setup-only)

These are treated as **NO ACTION** when they only occur during install/provisioning:

- `apt-get`, `bash`, `cargo`, `chmod`, `chown`, `cp`, `curl`, `docker`, `gpioset`, `grep`, `groupadd`, `id`, `install`, `journalctl`, `ls`, `mkdir`, `nmcli`, `ps`, `rm`, `stat`, `systemctl`, `tar`, `useradd`, `which`, `wpa_cli`, `wpasupplicant`

## Inventory (ordered by priority)

| Priority | Binary | Direct calls | Nested calls | Feature gate(s) | Install scripts? | Pi runtime action | Primary locations |
|---|---:|---:|---:|---|---|---|---|
| P0 | `bash` | 3 | 0 | rustyjack-core: feature=external_tools (gated sections in operations.rs) | CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only) | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/operations.rs:3293, crates/rustyjack-core/src/operations.rs:3357, crates/rustyjack-core/src/operations.rs:3482 |
| P0 | `timeout` | 2 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/physical_access.rs:218, crates/rustyjack-core/src/external_tools/physical_access.rs:445 |
| P0 | `<dynamic:program>` | 1 | 0 | rustyjack-core: feature=external_tools (gated sections in operations.rs) | No evidence (runtime only via external_tools wrapper) | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/operations.rs:2852 |
| P0 | `avahi-browse` | 0 | 1 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/physical_access.rs:218 |
| P0 | `reaver` | 0 | 1 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/physical_access.rs:445 |
| P0 | `wpa_supplicant` | 1 | 0 | rustyjack-netlink: feature=station_external | No evidence of install-script usage in this snapshot | REPLACE if you want zero shell-outs at runtime (prefer Rust station backend) | crates/rustyjack-netlink/src/station/external/process.rs:62 |
| P1 | `journalctl` | 5 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only) | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/anti_forensics.rs:174, crates/rustyjack-core/src/external_tools/anti_forensics.rs:175, crates/rustyjack-core/src/external_tools/anti_forensics.rs:306, crates/rustyjack-core/src/external_tools/anti_forensics.rs:307, … |
| P1 | `systemctl` | 4 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only) | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/anti_forensics.rs:260, crates/rustyjack-core/src/external_tools/anti_forensics.rs:309, crates/rustyjack-core/src/external_tools/anti_forensics.rs:310, crates/rustyjack-core/src/external_tools/anti_forensics.rs:328 |
| P1 | `git` | 2 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | LIKELY: referenced in installer docs/flow (not present in snapshot) — treat as setup-only unless proven runtime | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/git_ops.rs:12, crates/rustyjack-core/src/external_tools/git_ops.rs:16 |
| P1 | `dphys-swapfile` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:850 |
| P1 | `hostnamectl` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:786 |
| P1 | `mount` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | LIKELY: referenced in installer docs/flow (not present in snapshot) — treat as setup-only unless proven runtime | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/anti_forensics.rs:351 |
| P1 | `nscd` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:334 |
| P1 | `shutdown` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:626 |
| P1 | `swapoff` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:847 |
| P1 | `sysctl` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/evasion.rs:103 |
| P1 | `umount` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | LIKELY: referenced in installer docs/flow (not present in snapshot) — treat as setup-only unless proven runtime | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/anti_forensics.rs:381 |
| P2 | `tar` | 4 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only) | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/anti_forensics.rs:408, crates/rustyjack-core/src/external_tools/anti_forensics.rs:472, crates/rustyjack-core/src/external_tools/anti_forensics.rs:713, crates/rustyjack-core/src/external_tools/archive_ops.rs:32 |
| P2 | `openssl` | 3 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:411, crates/rustyjack-core/src/external_tools/anti_forensics.rs:456, crates/rustyjack-core/src/external_tools/anti_forensics.rs:716 |
| P2 | `exiftool` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:534 |
| P2 | `ps` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only) | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/anti_forensics.rs:756 |
| P2 | `shred` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:72 |
| P2 | `sync` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:314 |
| P2 | `ulimit` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | No evidence of install-script usage in this snapshot | NO ACTION for Pi runtime (lab-only), but replace if you want fully Rust in all builds | crates/rustyjack-core/src/external_tools/anti_forensics.rs:485 |
| P2 | `which` | 1 | 0 | rustyjack-core: feature=external_tools (enabled by feature=lab) | CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only) | NO ACTION (setup-only / installer) | crates/rustyjack-core/src/external_tools/anti_forensics.rs:56 |


## Notes on scope and limitations

- **Installer scripts are out of scope for runtime.** Any binaries executed only by `install_rustyjack*.sh` are intentionally treated as “NO ACTION”.

- This report is based on static scanning of the uploaded snapshot. It does **not** include binaries that might be invoked by missing external scripts (e.g., `scripts/*.sh` referenced from `operations.rs`), because those script files are not present here.
- Nested executions are included where a wrapper binary (`timeout`, `bash`) executes another program that’s visible in arguments.
- Some modules (notably `external_tools`) contain behavior that is security-sensitive. For those areas, the safe Rust-only guidance is generally to **remove or strictly gate** the capability rather than re‑implement concealment/attack tooling.


## Global remediation plan

1) **Make shell-outs impossible in production builds**
   - Keep `appliance` as the default feature (already the case) and ensure CI builds it.
   - Add a CI check that forbids `system_shell` usage outside explicitly-labeled lab crates.

2) **Replace `system_shell` usage with typed Rust APIs**
   - Introduce a new crate (suggested name: `rustyjack-platform`) that centralizes platform operations:
     - `platform::mount`, `platform::swap`, `platform::reboot`, `platform::hostname`, `platform::sysctl`, `platform::systemd`, `platform::proc`.

3) **For networking/Wi‑Fi**
   - Prefer the existing Rust Wi‑Fi backends (`station_rust_wpa2`, `station_rust_open`) over `station_external`.
   - For discovery and network ops, use Rust crates (mDNS, netlink) rather than CLI tools.

4) **Stage replacements**
   - Stage 0: remove wrappers (`timeout`, `which`, `ulimit`) and use Rust equivalents while still calling the underlying tool.
   - Stage 1: replace the underlying tool itself with Rust implementation.


# Detailed findings


## bash

**Priority:** P0  
**Direct call sites:** 3  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (gated sections in operations.rs)
**Install-script usage:** CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only)
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
GNU Bash shell. In this codebase it is being used as a general-purpose *script runner* (i.e., "run this `.sh` file and hope the system looks like Debian").

### Why this is a big deal
If the goal is "Rust-only" (no runtime dependency on ad‑hoc shell tooling), `bash` is basically a portal to **whatever** the script calls: `ip`, `iw`, `apt`, `modprobe`, `cryptsetup`, etc. Even if we remove `bash` calls from Rust, any script the systemd units or deploy tooling runs will reintroduce that dependency chain.

### Rust-only replacement strategy
**Replace scripts with Rust subcommands** (or library functions) and keep them behind a clear interface:
- Create a crate like `rustyjack-platform` (or `watchdog-platform`) with modules:
  - `storage::` (mount/umount, partition probing, filesystem ops)
  - `wifi::` (driver/firmware handling if you really must do it at runtime; ideally do it at image build time)
  - `fde::` (full-disk encryption prep/migration — see security note below)
- Every "script" becomes a Rust `Operation` variant executed by a strongly-typed function that returns structured errors.

**Practical note:** the referenced scripts (`fde_prepare_usb.sh`, `fde_migrate_root.sh`, `wifi_driver_installer.sh`) are not present in this snapshot, so we can't enumerate *their* internal binaries. The safest route is: **delete/ban runtime scripting** and do installation/driver setup at build-image time.

### Working fix sketch
1) Remove the `system_shell::run("bash", ...)` call sites.
2) Introduce Rust functions, e.g.:

```rust
pub fn install_wifi_driver_bundle(root: &Path) -> anyhow::Result<()> {
    // Example shape: unpack a bundled driver archive into /lib/firmware
    // (Prefer doing this at image build time, not at runtime.)
    Ok(())
}
```

3) Add a CI rule: forbid `bash` (and forbid `system_shell` in non-lab builds).

### Call sites

- `crates/rustyjack-core/src/operations.rs:3293` (system_shell::run_allow_failure)

```text
  3289 |     }
  3290 |     let script_str = script
  3291 |         .to_str()
  3292 |         .ok_or_else(|| anyhow!("FDE prep script path must be valid UTF-8"))?;
> 3293 |     let output = crate::external_tools::system_shell::run_allow_failure(
  3294 |         "bash",
  3295 |         &[script_str, device.as_str()],
  3296 |     )
  3297 |     .with_context(|| format!("running {}", script.display()))?;
```

- `crates/rustyjack-core/src/operations.rs:3357` (system_shell::run_allow_failure)

```text
  3353 |         args.push("--execute".to_string());
  3354 |     }
  3355 |     let arg_refs: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();
  3356 |     let output =
> 3357 |         crate::external_tools::system_shell::run_allow_failure("bash", &arg_refs)
  3358 |             .with_context(|| format!("running {}", script.display()))?;
  3359 | 
  3360 |     let stdout = String::from_utf8_lossy(&output.stdout).to_string();
  3361 |     let stderr = String::from_utf8_lossy(&output.stderr).to_string();
```

- `crates/rustyjack-core/src/operations.rs:3482` (system_shell::run_with_env_allow_failure)

```text
  3478 |         .ok_or_else(|| anyhow!("Installer script path must be valid UTF-8"))?;
  3479 |     let root_str = root
  3480 |         .to_str()
  3481 |         .ok_or_else(|| anyhow!("Root path must be valid UTF-8"))?;
> 3482 |     let output = crate::external_tools::system_shell::run_with_env_allow_failure(
  3483 |         "bash",
  3484 |         &[script_str],
  3485 |         &[("RUSTYJACK_ROOT", root_str)],
  3486 |     )
```

## timeout

**Priority:** P0  
**Direct call sites:** 2  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
`timeout` (coreutils) wraps another command and kills it if it exceeds a time limit.

### Where/why
Used as a "poor man's async timeout" around other external binaries (`avahi-browse`, `reaver`).

### Rust-only replacement strategy
- Replace the *outer* timeout wrapper with Rust's own timeout control:
  - If you still spawn a process: `tokio::time::timeout()` + `child.kill().await`.
  - If you go Rust-only: remove the spawned process entirely and implement the underlying operation in Rust (recommended).

### Working fix sketch
If you must keep a child process temporarily, at least delete `timeout`:

```rust
use tokio::{process::Command, time::{timeout, Duration}};

pub async fn run_with_timeout(program: &str, args: &[&str], dur: Duration) -> anyhow::Result<Vec<u8>> {
    let mut child = Command::new(program).args(args).stdout(std::process::Stdio::piped()).spawn()?;
    let out = timeout(dur, child.wait_with_output()).await??;
    Ok(out.stdout)
}
```

Then, *separately*, eliminate the underlying child process by replacing `avahi-browse` with mDNS in Rust (see that section).

### Call sites

- `crates/rustyjack-core/src/external_tools/physical_access.rs:218` (system_shell::run_allow_failure)

```text
   214 |     let mut creds = Vec::new();
   215 | 
   216 |     // Use avahi-browse to discover services
   217 |     let output =
>  218 |         system_shell::run_allow_failure("timeout", &["10", "avahi-browse", "-at", "-r"]);
   219 | 
   220 |     if let Ok(output) = output {
   221 |         let stdout = String::from_utf8_lossy(&output.stdout);
   222 | 
```

- `crates/rustyjack-core/src/external_tools/physical_access.rs:445` (system_shell::run_allow_failure)

```text
   441 |     if let Some(iface) = wireless {
   442 |         info!("Attempting WPS PIN attack on {}", iface.name);
   443 | 
   444 |         // Use reaver for WPS attack (simplified - real impl would be more complex)
>  445 |         let output = system_shell::run_allow_failure(
   446 |             "timeout",
   447 |             &[
   448 |                 "60",
   449 |                 "reaver",
```

## <dynamic:program>

**Priority:** P0  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (gated sections in operations.rs)
**Install-script usage:** No evidence (runtime only via external_tools wrapper)
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
An unbounded `spawn_piped(&program, ...)` call where `program` is derived from user/network input (`spawn_reverse_shell` / `run_shell_command`).

### Why this is priority zero
Even in a trusted lab, "arbitrary process execution" is the opposite of a defendable appliance design. It's also impossible to make "Rust-only" if you can ask the system to exec any binary on PATH.

### Rust-only replacement strategy
- **Delete the capability** in appliance builds (and ideally entirely).
- If you need remote administration, replace it with:
  - a narrow, authenticated RPC API that calls explicit Rust operations,
  - strong auditing,
  - and compile-time feature gates that make it impossible to include in production.

### Working fix sketch
- Remove `run_shell_command` + `spawn_reverse_shell` operations.
- Replace with a command dispatcher like:

```rust
enum AdminOp {
    GetStatus,
    RestartWifi,
    RotateLogs,
}

pub async fn handle_admin_op(op: AdminOp) -> anyhow::Result<()> {
    match op {
        AdminOp::GetStatus => Ok(()),
        AdminOp::RestartWifi => Ok(()),
        AdminOp::RotateLogs => Ok(()),
    }
}
```

This gives your seniors a clean surface area to harden.

### Call sites

- `crates/rustyjack-core/src/operations.rs:2852` (system_shell::spawn_piped)

```text
  2848 | 
  2849 |     let (program, args) = parse_shell_command(shell)?;
  2850 |     let arg_refs: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();
  2851 |     let mut child =
> 2852 |         crate::external_tools::system_shell::spawn_piped(&program, &arg_refs)?;
  2853 | 
  2854 |     let pid = child.id();
  2855 |     let mut child_stdin = child.stdin.take().context("opening shell stdin")?;
  2856 |     let mut child_stdout = child.stdout.take().context("opening shell stdout")?;
```

## avahi-browse

**Priority:** P0  
**Direct call sites:** 0  
**Nested executions:** 1  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
Avahi's CLI browser for mDNS / DNS-SD service discovery.

### Where/why
Used to discover services on the LAN, parsed from CLI output.

### Rust-only replacement strategy
Use an mDNS/DNS-SD library crate instead of calling Avahi tooling. There are Rust crates that can browse services and return structured results (no parsing CLI output).

### Working fix sketch
Replace the `timeout 10 avahi-browse -at -r` call with an mDNS browse loop:

```rust
// Pseudocode-ish: exact API depends on chosen crate.
pub async fn discover_services() -> anyhow::Result<Vec<DiscoveredService>> {
    // 1) Start mDNS browse for _services._dns-sd._udp.local
    // 2) Collect answers for ~10 seconds
    // 3) Return structured service records
    Ok(vec![])
}
```

Then delete the string parsing logic.

### Call sites

- `crates/rustyjack-core/src/external_tools/physical_access.rs:218` (via timeout)

```text
   214 |     let mut creds = Vec::new();
   215 | 
   216 |     // Use avahi-browse to discover services
   217 |     let output =
>  218 |         system_shell::run_allow_failure("timeout", &["10", "avahi-browse", "-at", "-r"]);
   219 | 
   220 |     if let Ok(output) = output {
   221 |         let stdout = String::from_utf8_lossy(&output.stdout);
   222 | 
```

## reaver

**Priority:** P0  
**Direct call sites:** 0  
**Nested executions:** 1  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
`reaver` is a WPS attack tool. It's executed via `timeout`.

### Safety note
I can’t help implement or port Wi‑Fi attack tooling. That includes giving a “working fix” that recreates WPS PIN attacks in Rust.

### Rust-only replacement strategy
- Remove/disable the feature path entirely (recommended).
- If you genuinely need WPS for *legitimate provisioning*, implement **WPS enrollment** using supported, non-offensive mechanisms (e.g., via a Wi‑Fi management daemon’s legitimate APIs), but do not implement attack workflows.

### Call sites

- `crates/rustyjack-core/src/external_tools/physical_access.rs:445` (via timeout)

```text
   441 |     if let Some(iface) = wireless {
   442 |         info!("Attempting WPS PIN attack on {}", iface.name);
   443 | 
   444 |         // Use reaver for WPS attack (simplified - real impl would be more complex)
>  445 |         let output = system_shell::run_allow_failure(
   446 |             "timeout",
   447 |             &[
   448 |                 "60",
   449 |                 "reaver",
```

## wpa_supplicant

**Priority:** P0  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-netlink: feature=station_external
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** RUNTIME (only if station_external enabled); otherwise not used
**Needs edit for Pi runtime:** YES (if you enable station_external); otherwise NO

### What it is
`wpa_supplicant` is a Wi‑Fi client daemon. The code starts it as a background process with `-B`, passing interface, config, driver, and log file.

### Where/why
It’s used as a backend implementation for station mode when `rustyjack-netlink` is built with `feature=station_external`.

### Rust-only replacement strategy (two levels)
**Level 1 (no shell-out, but still uses daemon):**
- Stop *spawning* `wpa_supplicant` from Rust.
- Run it under systemd as a managed service.
- Control it via its control socket from Rust (there are crates for wpa control).

**Level 2 (Rust-only Wi‑Fi station):**
- Don’t enable `station_external`.
- Use the existing in-tree Rust backends (`station_rust_wpa2`, `station_rust_open`) and extend them.
- For low-level Wi‑Fi control (scan/auth/associate), use nl80211 via netlink (there are Rust crates for nl80211 messaging).

### Working fix sketch
**Simplest:** remove `station_external` from your builds and enforce `RUSTYJACK_WIFI_BACKEND=rust_wpa2` (already present in the systemd unit).

If you must control an existing daemon without spawning it:

```rust
pub fn connect_via_wpa_ctrl(_iface: &str) -> anyhow::Result<()> {
    // Use a wpa-control crate to send commands over the UNIX control socket.
    Ok(())
}
```

### Call sites

- `crates/rustyjack-netlink/src/station/external/process.rs:62` (Command::new)

```text
    58 |         "Starting wpa_supplicant for {} (ctrl_interface={})",
    59 |         interface,
    60 |         control_dir.display()
    61 |     );
>   62 |     let output = Command::new("wpa_supplicant")
    63 |         .args(["-B", "-i", interface, "-c", &conf_path])
    64 |         .output()
    65 |         .map_err(|e| NetlinkError::Wpa(format!("Failed to start wpa_supplicant: {}", e)))?;
    66 | 
```

## journalctl

**Priority:** P1  
**Direct call sites:** 5  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only)
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
`journalctl` is the systemd journal CLI.

### Where/why
Used to rotate/vacuum logs (and in one place to aggressively vacuum to near-zero). This is part of the `anti_forensics` module.

### Rust-only replacement strategy
If your goal is legitimate log *management* (not concealment):
- Prefer configuring journald via config files and letting systemd handle retention.
- If you must automate, use systemd/journald APIs (D-Bus or libsystemd bindings) rather than shelling out.

If the goal is to “clear traces,” I’m not going to provide a porting guide for that. The safe “Rust-only fix” is: **remove the anti-forensics capability** from production builds and guard it behind a compile-time feature with an explicit policy and audit trail.

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:174` (system_shell::run_allow_failure)

```text
   170 |         }
   171 |     }
   172 | 
   173 |     // Clear systemd journal
>  174 |     let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);
   175 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);
   176 | 
   177 |     info!("System logs cleared");
   178 |     Ok(())
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:175` (system_shell::run_allow_failure)

```text
   171 |     }
   172 | 
   173 |     // Clear systemd journal
   174 |     let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);
>  175 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);
   176 | 
   177 |     info!("System logs cleared");
   178 |     Ok(())
   179 | }
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:306` (system_shell::run_allow_failure)

```text
   302 |             }
   303 |         }
   304 |     }
   305 | 
>  306 |     let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);
   307 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);
   308 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-size=1K"]);
   309 |     let _ = system_shell::run_allow_failure("systemctl", &["daemon-reload"]);
   310 |     let _ = system_shell::run_allow_failure(
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:307` (system_shell::run_allow_failure)

```text
   303 |         }
   304 |     }
   305 | 
   306 |     let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);
>  307 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);
   308 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-size=1K"]);
   309 |     let _ = system_shell::run_allow_failure("systemctl", &["daemon-reload"]);
   310 |     let _ = system_shell::run_allow_failure(
   311 |         "systemctl",
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:308` (system_shell::run_allow_failure)

```text
   304 |     }
   305 | 
   306 |     let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);
   307 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);
>  308 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-size=1K"]);
   309 |     let _ = system_shell::run_allow_failure("systemctl", &["daemon-reload"]);
   310 |     let _ = system_shell::run_allow_failure(
   311 |         "systemctl",
   312 |         &["reset-failed", "rustyjack.service"],
```

## systemctl

**Priority:** P1  
**Direct call sites:** 4  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only)
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
Systemd service manager CLI.

### Where/why
Used to stop/disable various services and perform daemon reload/reset-failed. Also part of anti-forensics / cleanup behavior.

### Rust-only replacement strategy
Talk to systemd over D‑Bus (no `systemctl`):
- Use `zbus` (already a dependency in `rustyjack-netlink`) to call `org.freedesktop.systemd1.Manager` methods like `StopUnit`, `DisableUnitFiles`, `DaemonReload`, `ResetFailed`.

### Working fix sketch
```rust
// Pseudocode-ish: show the shape, not a full implementation.
async fn systemd_stop_unit(unit: &str) -> anyhow::Result<()> {
    // 1) Connect to the system bus
    // 2) Call org.freedesktop.systemd1.Manager.StopUnit(unit, "replace")
    Ok(())
}
```

Then replace each `systemctl` invocation with typed D‑Bus calls and explicit error handling.

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:260` (system_shell::run_allow_failure)

```text
   256 |     };
   257 | 
   258 |     // Disable service first before using delete_path closure
   259 |     if let Ok(output) =
>  260 |         system_shell::run_allow_failure("systemctl", &["disable", "rustyjack.service"])
   261 |     {
   262 |         if output.status.success() {
   263 |             service_disabled = true;
   264 |         }
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:309` (system_shell::run_allow_failure)

```text
   305 | 
   306 |     let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);
   307 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);
   308 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-size=1K"]);
>  309 |     let _ = system_shell::run_allow_failure("systemctl", &["daemon-reload"]);
   310 |     let _ = system_shell::run_allow_failure(
   311 |         "systemctl",
   312 |         &["reset-failed", "rustyjack.service"],
   313 |     );
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:310` (system_shell::run_allow_failure)

```text
   306 |     let _ = system_shell::run_allow_failure("journalctl", &["--rotate"]);
   307 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-time=1s"]);
   308 |     let _ = system_shell::run_allow_failure("journalctl", &["--vacuum-size=1K"]);
   309 |     let _ = system_shell::run_allow_failure("systemctl", &["daemon-reload"]);
>  310 |     let _ = system_shell::run_allow_failure(
   311 |         "systemctl",
   312 |         &["reset-failed", "rustyjack.service"],
   313 |     );
   314 |     let _ = system_shell::run_allow_failure("sync", &[]);
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:328` (system_shell::run_allow_failure)

```text
   324 | pub fn clear_dns_cache() -> Result<()> {
   325 |     info!("Clearing DNS cache");
   326 | 
   327 |     // systemd-resolved
>  328 |     let _ = system_shell::run_allow_failure(
   329 |         "systemctl",
   330 |         &["restart", "systemd-resolved"],
   331 |     );
   332 | 
```

## git

**Priority:** P1  
**Direct call sites:** 2  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** LIKELY: referenced in installer docs/flow (not present in snapshot) — treat as setup-only unless proven runtime
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
Git CLI.

### Where/why
Used for “reset to remote” (fetch + hard reset).

### Rust-only replacement strategy
Use a Rust Git implementation instead of shelling out:
- Prefer a pure-Rust option (e.g., `gix` / gitoxide) for a “no external binaries” stance.
- Alternative: `git2` (libgit2 bindings) if C libs are acceptable.

### Working fix sketch
```rust
pub fn hard_reset_to_remote(_repo_path: &std::path::Path, _remote: &str, _branch: &str) -> anyhow::Result<()> {
    // Use gix to open repo, fetch remote, resolve ref, reset worktree/index.
    Ok(())
}
```

Design tip: keep update logic in its own crate with a very small API surface and excellent tests (corrupt repo, detached HEAD, no network).

### Call sites

- `crates/rustyjack-core/src/external_tools/git_ops.rs:12` (system_shell::run)

```text
     8 |     let root_str = root
     9 |         .to_str()
    10 |         .ok_or_else(|| anyhow!("Root path must be valid UTF-8"))?;
    11 | 
>   12 |     system_shell::run("git", &["-C", root_str, "fetch", remote])
    13 |         .context("git fetch")?;
    14 | 
    15 |     let target = format!("{remote}/{branch}");
    16 |     system_shell::run("git", &["-C", root_str, "reset", "--hard", target.as_str()])
```

- `crates/rustyjack-core/src/external_tools/git_ops.rs:16` (system_shell::run)

```text
    12 |     system_shell::run("git", &["-C", root_str, "fetch", remote])
    13 |         .context("git fetch")?;
    14 | 
    15 |     let target = format!("{remote}/{branch}");
>   16 |     system_shell::run("git", &["-C", root_str, "reset", "--hard", target.as_str()])
    17 |         .context("git reset")?;
    18 | 
    19 |     Ok(())
    20 | }
```

## dphys-swapfile

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
Debian/Raspbian helper script for managing a swap file.

### Where/why
Called opportunistically as part of `disable_swap()`.

### Rust-only replacement strategy
Don’t rely on distro helper scripts:
- Enumerate active swaps via `/proc/swaps`
- Call `swapoff()` for each swap device/file
- Remove/disable the swap file and config as needed (and/or disable the systemd unit that enables it)

### Working fix sketch
```rust
pub fn disable_swap_everywhere() -> anyhow::Result<()> {
    // 1) parse /proc/swaps
    // 2) call libc::swapoff(path_cstr.as_ptr())
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:850` (system_shell::run_allow_failure)

```text
   846 |     // Try swapoff -a
   847 |     let _ = system_shell::run_allow_failure("swapoff", &["-a"]);
   848 | 
   849 |     // Try dphys-swapfile if on Raspbian
>  850 |     let _ = system_shell::run_allow_failure("dphys-swapfile", &["swapoff"]);
   851 | 
   852 |     Ok(())
   853 | }
```

## hostnamectl

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
Systemd-hostnamed CLI for setting hostname.

### Where/why
Used to randomize hostname.

### Rust-only replacement strategy
- Use the `sethostname(2)` syscall (via `nix` or `libc`)
- Update `/etc/hostname` and `/etc/hosts` in Rust.

### Working fix sketch
```rust
pub fn set_hostname(new_hostname: &str) -> anyhow::Result<()> {
    // nix::unistd::sethostname(new_hostname)?;
    std::fs::write("/etc/hostname", format!("{new_hostname}
"))?;
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:786` (system_shell::run)

```text
   782 |     let suffix: u32 = rng.gen_range(1000..9999);
   783 |     let new_hostname = format!("{}-{}", prefix, suffix);
   784 | 
   785 |     // Set hostname
>  786 |     system_shell::run("hostnamectl", &["set-hostname", new_hostname.as_str()])
   787 |         .context("setting hostname via hostnamectl")?;
   788 | 
   789 |     // Update /etc/hosts to prevent sudo warnings
   790 |     let hosts_path = Path::new("/etc/hosts");
```

## mount

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** LIKELY: referenced in installer docs/flow (not present in snapshot) — treat as setup-only unless proven runtime
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
`mount` CLI.

### Where/why
Mounts a tmpfs at `/tmp/rustyjack_ram` for RAM-only mode.

### Rust-only replacement strategy
Use `mount(2)` via `nix::mount::mount` on Linux.

### Working fix sketch
```rust
use nix::mount::{mount, MsFlags};

pub fn mount_tmpfs(target: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(target)?;
    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=500M,mode=0700"),
    )?;
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:351` (system_shell::run)

```text
   347 | 
   348 |     let ram_dir_str = ram_dir
   349 |         .to_str()
   350 |         .ok_or_else(|| anyhow!("ram dir must be valid UTF-8"))?;
>  351 |     system_shell::run(
   352 |         "mount",
   353 |         &[
   354 |             "-t",
   355 |             "tmpfs",
```

## nscd

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
Name Service Cache Daemon CLI interface (`nscd -i hosts`) to invalidate caches.

### Where/why
Part of “clear DNS cache” behavior.

### Rust-only replacement strategy
Prefer interacting with the actually-used resolver on modern systems:
- If systemd-resolved is in use: use its D‑Bus API to flush caches.
- If not: this should be a no-op (there is no universal “DNS cache” to clear).

### Working fix sketch
```rust
pub fn clear_dns_cache() -> anyhow::Result<()> {
    // Detect resolved/nscd; call D-Bus if appropriate; otherwise no-op.
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:334` (system_shell::run_allow_failure)

```text
   330 |         &["restart", "systemd-resolved"],
   331 |     );
   332 | 
   333 |     // nscd
>  334 |     let _ = system_shell::run_allow_failure("nscd", &["-i", "hosts"]);
   335 | 
   336 |     Ok(())
   337 | }
   338 | 
```

## shutdown

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
System shutdown CLI.

### Where/why
Called after a “dead man’s switch” wipe.

### Rust-only replacement strategy
Use `reboot(2)` / `poweroff(2)` via `nix`/`libc` when running with appropriate privileges.

### Working fix sketch
```rust
pub fn poweroff_now() -> anyhow::Result<()> {
    // nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF)?;
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:626` (system_shell::run_allow_failure)

```text
   622 |         warn!("Dead man's switch triggered! Wiping data...");
   623 |         emergency_wipe(root)?;
   624 | 
   625 |         // Shutdown system
>  626 |         let _ = system_shell::run_allow_failure("shutdown", &["-h", "now"]);
   627 |     }
   628 | 
   629 |     Ok(())
   630 | }
```

## swapoff

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
Swap management CLI.

### Where/why
Part of `disable_swap()`.

### Rust-only replacement strategy
Same as `dphys-swapfile` section: parse `/proc/swaps` and call `swapoff()`.

### Working fix sketch
See `dphys-swapfile`.

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:847` (system_shell::run_allow_failure)

```text
   843 | pub fn disable_swap() -> Result<()> {
   844 |     info!("Disabling swap");
   845 | 
   846 |     // Try swapoff -a
>  847 |     let _ = system_shell::run_allow_failure("swapoff", &["-a"]);
   848 | 
   849 |     // Try dphys-swapfile if on Raspbian
   850 |     let _ = system_shell::run_allow_failure("dphys-swapfile", &["swapoff"]);
   851 | 
```

## sysctl

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
Kernel parameter CLI.

### Where/why
Used to tweak network stack parameters for “fingerprint spoofing” and TTL randomization.

### Rust-only replacement strategy
Write directly to `/proc/sys/...` with strict allowlisting:
- Convert `net.ipv4.ip_default_ttl` → `/proc/sys/net/ipv4/ip_default_ttl`
- Write the value with proper permissions
- Keep an allowlist so you don’t accidentally permit arbitrary sysctl writes.

### Working fix sketch
```rust
pub fn set_proc_sys(param: &str, value: &str) -> anyhow::Result<()> {
    let path = format!("/proc/sys/{}", param.replace('.', "/"));
    std::fs::write(path, value)?;
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/evasion.rs:103` (system_shell::run_allow_failure)

```text
    99 | 
   100 | /// Set a sysctl parameter
   101 | fn set_sysctl(param: &str, value: &str) -> Result<()> {
   102 |     let arg = format!("{}={}", param, value);
>  103 |     let output = system_shell::run_allow_failure("sysctl", &["-w", arg.as_str()])
   104 |         .context("setting sysctl parameter")?;
   105 | 
   106 |     if !output.status.success() {
   107 |         warn!("Failed to set sysctl {} = {}", param, value);
```

## umount

**Priority:** P1  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** LIKELY: referenced in installer docs/flow (not present in snapshot) — treat as setup-only unless proven runtime
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
`umount` CLI.

### Where/why
Unmounts the tmpfs created for RAM-only mode.

### Rust-only replacement strategy
Use `umount2(2)` via `nix`.

### Working fix sketch
```rust
use nix::mount::umount;
pub fn unmount(target: &std::path::Path) -> anyhow::Result<()> {
    umount(target)?;
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:381` (system_shell::run)

```text
   377 | 
   378 |         let ram_dir_str = ram_dir
   379 |             .to_str()
   380 |             .ok_or_else(|| anyhow!("ram dir must be valid UTF-8"))?;
>  381 |         system_shell::run("umount", &[ram_dir_str]).context("unmounting tmpfs")?;
   382 |     }
   383 | 
   384 |     Ok(())
   385 | }
```

## tar

**Priority:** P2  
**Direct call sites:** 4  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only)
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
Tar CLI.

### Where/why
Used to package directories before encrypting (loot backup, safety backup) and to extract after decrypting.

### Rust-only replacement strategy
Use the `tar` crate + `flate2` for gzip.

### Working fix sketch
```rust
use std::{fs::File, path::Path};
use flate2::{Compression, write::GzEncoder};
use tar::Builder;

pub fn create_tar_gz(src_dir: &Path, out_path: &Path) -> anyhow::Result<()> {
    let out = File::create(out_path)?;
    let enc = GzEncoder::new(out, Compression::default());
    let mut tar = Builder::new(enc);
    tar.append_dir_all("loot", src_dir)?;
    tar.finish()?;
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:408` (system_shell::run)

```text
   404 |     let tar_path = root.join("loot.tar.gz");
   405 |     let tar_str = tar_path
   406 |         .to_str()
   407 |         .ok_or_else(|| anyhow!("tar path must be valid UTF-8"))?;
>  408 |     system_shell::run("tar", &["-czf", tar_str, loot_dir_str])
   409 |         .context("creating loot archive")?;
   410 |     let pass_arg = format!("pass:{}", password);
   411 |     system_shell::run(
   412 |         "openssl",
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:472` (system_shell::run)

```text
   468 |             tar_str,
   469 |         ],
   470 |     )
   471 |     .context("decrypting loot")?;
>  472 |     system_shell::run("tar", &["-xzf", tar_str, "-C", root_str])
   473 |         .context("extracting loot archive")?;
   474 |     let _ = fs::remove_file(&tar_path);
   475 | 
   476 |     info!("Loot decrypted successfully");
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:713` (system_shell::run)

```text
   709 |     let tar_path = root.join("backup.tar.gz");
   710 |     let tar_str = tar_path
   711 |         .to_str()
   712 |         .ok_or_else(|| anyhow!("tar path must be valid UTF-8"))?;
>  713 |     system_shell::run("tar", &["-czf", tar_str, loot_dir_str])
   714 |         .context("creating backup archive")?;
   715 |     let pass_arg = format!("pass:{}", password);
   716 |     system_shell::run(
   717 |         "openssl",
```

- `crates/rustyjack-core/src/external_tools/archive_ops.rs:32` (system_shell::run)

```text
    28 |     let archive_str = archive
    29 |         .to_str()
    30 |         .ok_or_else(|| anyhow!("Archive path must be valid UTF-8"))?;
    31 | 
>   32 |     system_shell::run(
    33 |         "tar",
    34 |         &["-czf", archive_str, "-C", parent_str, name_str],
    35 |     )
    36 |     .context("creating backup archive")?;
```

## openssl

**Priority:** P2  
**Direct call sites:** 3  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
OpenSSL CLI.

### Where/why
Used for encrypt/decrypt of tarballs with AES-256-CBC + PBKDF2 password.

### Rust-only replacement strategy
Strong recommendation: switch to a modern, misuse-resistant scheme instead of reimplementing OpenSSL CLI flags.
Two sane options:
- Use the `age` crate for file encryption (password mode or key-based).
- Or use an AEAD (e.g., ChaCha20-Poly1305) + a KDF (Argon2id / scrypt) with clear versioning and tests.

### Working fix sketch (age-style)
```rust
pub fn encrypt_file_age(_in_path: &Path, _out_path: &Path, _passphrase: &str) -> anyhow::Result<()> {
    // Use age crate to encrypt in->out
    Ok(())
}
```

Then delete all OpenSSL invocations.

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:411` (system_shell::run)

```text
   407 |         .ok_or_else(|| anyhow!("tar path must be valid UTF-8"))?;
   408 |     system_shell::run("tar", &["-czf", tar_str, loot_dir_str])
   409 |         .context("creating loot archive")?;
   410 |     let pass_arg = format!("pass:{}", password);
>  411 |     system_shell::run(
   412 |         "openssl",
   413 |         &[
   414 |             "enc",
   415 |             "-aes-256-cbc",
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:456` (system_shell::run)

```text
   452 |     let tar_str = tar_path
   453 |         .to_str()
   454 |         .ok_or_else(|| anyhow!("tar path must be valid UTF-8"))?;
   455 |     let pass_arg = format!("pass:{}", password);
>  456 |     system_shell::run(
   457 |         "openssl",
   458 |         &[
   459 |             "enc",
   460 |             "-aes-256-cbc",
```

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:716` (system_shell::run)

```text
   712 |         .ok_or_else(|| anyhow!("tar path must be valid UTF-8"))?;
   713 |     system_shell::run("tar", &["-czf", tar_str, loot_dir_str])
   714 |         .context("creating backup archive")?;
   715 |     let pass_arg = format!("pass:{}", password);
>  716 |     system_shell::run(
   717 |         "openssl",
   718 |         &[
   719 |             "enc",
   720 |             "-aes-256-cbc",
```

## exiftool

**Priority:** P2  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
ExifTool CLI for stripping metadata.

### Where/why
Used to remove EXIF/metadata from files.

### Rust-only replacement strategy
Depends on file types you need to support:
- For images you can decode + re-encode (JPEG/PNG), which naturally drops most metadata.
- For richer formats, you may need format-specific parsing; ExifTool is broad, so Rust-only parity may be staged.

### Working fix sketch (JPEG/PNG re-encode)
```rust
pub fn strip_image_metadata(path: &std::path::Path) -> anyhow::Result<()> {
    let img = image::open(path)?;
    img.save(path)?; // re-encode; metadata dropped
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:534` (system_shell::run_allow_failure)

```text
   530 |     // Use exiftool to strip metadata
   531 |     let path_str = path
   532 |         .to_str()
   533 |         .ok_or_else(|| anyhow!("path must be valid UTF-8"))?;
>  534 |     let _ = system_shell::run_allow_failure(
   535 |         "exiftool",
   536 |         &["-all=", "-overwrite_original", path_str],
   537 |     );
   538 | 
```

## ps

**Priority:** P2  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only)
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
Process listing CLI.

### Where/why
Used in `verify_clean()` to grep for “rustyjack”.

### Rust-only replacement strategy
Read `/proc` (or use `procfs` crate) and scan command lines.

### Working fix sketch
```rust
pub fn any_process_contains(substr: &str) -> anyhow::Result<bool> {
    // Iterate /proc/<pid>/cmdline and search
    Ok(false)
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:756` (system_shell::run_allow_failure)

```text
   752 |         }
   753 |     }
   754 | 
   755 |     // Check for suspicious processes
>  756 |     let output = system_shell::run_allow_failure("ps", &["aux"])?;
   757 | 
   758 |     let stdout = String::from_utf8_lossy(&output.stdout);
   759 |     if stdout.contains("rustyjack") {
   760 |         artifacts.push("Suspicious processes found".to_string());
```

## shred

**Priority:** P2  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
GNU `shred` secure-delete CLI.

### Where/why
Optional fast-path in `secure_delete_file()` when present; the file already contains a Rust fallback.

### Rust-only replacement strategy
Delete the `which`+`shred` branch and always use the Rust implementation.
(Also: secure delete semantics on flash/SSD are tricky; document your threat model.)

### Working fix sketch
- Remove the `which shred` probe
- Keep `secure_wipe_file_contents()` + `remove_file()`

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:72` (system_shell::run)

```text
    68 |             "-u".to_string(),
    69 |             path_str.to_string(),
    70 |         ];
    71 |         let arg_refs: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();
>   72 |         system_shell::run("shred", &arg_refs).context("running shred")?;
    73 |     } else {
    74 |         // Fallback: manual overwrite
    75 |         manual_secure_delete(path, passes)?;
    76 |     }
```

## sync

**Priority:** P2  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
`sync` CLI.

### Where/why
Used to flush filesystem buffers.

### Rust-only replacement strategy
Use the `sync(2)` syscall via `libc::sync()` (or fsync specific fds where possible).

### Working fix sketch
```rust
pub fn sync_all() {
    unsafe { libc::sync() };
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:314` (system_shell::run_allow_failure)

```text
   310 |     let _ = system_shell::run_allow_failure(
   311 |         "systemctl",
   312 |         &["reset-failed", "rustyjack.service"],
   313 |     );
>  314 |     let _ = system_shell::run_allow_failure("sync", &[]);
   315 | 
   316 |     PurgeReport {
   317 |         removed,
   318 |         service_disabled,
```

## ulimit

**Priority:** P2  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** No evidence of install-script usage in this snapshot
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO for default appliance runtime (lab-only)

### What it is
Shell builtin / external wrapper used here as if it were a standalone binary. In practice `ulimit` is commonly a shell builtin, so this call is not portable and may do nothing.

### Where/why
Attempted to disable core dumps.

### Rust-only replacement strategy
Use `setrlimit(RLIMIT_CORE, 0)`.

### Working fix sketch
```rust
use nix::sys::resource::{setrlimit, Resource, Rlim};

pub fn disable_core_dumps() -> anyhow::Result<()> {
    setrlimit(Resource::RLIMIT_CORE, Rlim::from_raw(0), Rlim::from_raw(0))?;
    Ok(())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:485` (system_shell::run_allow_failure)

```text
   481 | pub fn enable_anti_dump_protection() -> Result<()> {
   482 |     info!("Enabling anti-memory dump protection");
   483 | 
   484 |     // Prevent core dumps
>  485 |     let _ = system_shell::run_allow_failure("ulimit", &["-c", "0"]);
   486 | 
   487 |     // Disable ptrace for this process (prevents debugging)
   488 |     #[cfg(target_os = "linux")]
   489 |     {
```

## which

**Priority:** P2  
**Direct call sites:** 1  
**Nested executions:** 0  
**Feature gates:** rustyjack-core: feature=external_tools (enabled by feature=lab)
**Install-script usage:** CONFIRMED: used by install_rustyjack* scripts or their documented verification steps — out of scope (setup-only)
**Runtime relevance:** NOT in default Pi runtime (appliance); lab/maintenance only unless you ship external_tools
**Needs edit for Pi runtime:** NO (setup-only / installer / lab)

### What it is
`which` CLI to test if `shred` exists.

### Where/why
Used only as a probe for `shred`.

### Rust-only replacement strategy
- If you remove `shred`, you can remove this too.
- Otherwise implement a PATH search in Rust (or use a small helper crate).

### Working fix sketch
```rust
pub fn find_in_path(exe: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH")?.to_string_lossy().split(':')
        .map(|p| std::path::Path::new(p).join(exe))
        .find(|p| p.is_file())
}
```

### Call sites

- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:56` (system_shell::run_allow_failure)

```text
    52 |         passes
    53 |     );
    54 | 
    55 |     // Use shred if available (better than our implementation)
>   56 |     let shred_available = system_shell::run_allow_failure("which", &["shred"])
    57 |         .map(|o| o.status.success())
    58 |         .unwrap_or(false);
    59 | 
    60 |     if shred_available {
```
