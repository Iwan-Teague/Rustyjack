# RustyJack Daemon Deep Dive (Pi Zero 2 W)
Created: 2026-01-19

**Snapshot analysed:** `watchdog_shallow_20260118-234504.zip` (workspace version `0.1.0`)

This report is written as if the device is operated **only via the on-device UI** (no SSH heroics), and assumes the platform is a Raspberry Pi Zero 2 W running a typical Debian/Raspberry Pi OS style userspace.

Constraints you gave (treated as hard requirements):

- **All fixes/features must be implemented in Rust** (no “just call X” solutions).
- **No new third‑party binaries** added to the image to make features work.
- The user experience must be robust: errors should be actionable, not mystic.

---

## Executive summary

A lot of the “random” failures you’re seeing are not random. They’re the predictable result of a mismatch between:

1) **What the daemon code is trying to do** (mount filesystems, tweak sysctls, manipulate interfaces, set up NAT), and
2) **How the daemon is sandboxed by systemd** (`rustyjackd.service`).

The biggest offenders:

- **USB mount/export fails** because the daemon’s systemd unit applies `SystemCallFilter=@system-service`, which **explicitly excludes the `@mount` syscall set**. That blocks `mount(2)`/`umount2(2)` regardless of whether you run as root.
- **Hotspot networking setup can fail** because `ProtectKernelTunables=true` makes `/proc/sys` and parts of `/sys` effectively read‑only inside the service. Your hotspot code **unconditionally writes** to `/proc/sys/net/ipv4/ip_forward`.
- **Regulatory domain / channel selection fails** because the project currently **only warns** when regdom is unset/invalid; it does not set it. On a Pi, regdom is often left at `00` until user-space sets it, leading to “no valid channels / invalid channel” symptoms.
- **Some system operations will never work** under `ProtectSystem=strict` unless the unit explicitly grants write access (e.g. `/etc/resolv.conf` is treated as read-only by the service, while the code checks it is writable).

Once the systemd sandbox is aligned with the daemon’s responsibilities, the remaining issues (country code automation, better MAC randomisation reliability, FS support detection) are straightforward and can be handled cleanly in Rust.

---

## Architecture refresher (what calls what)

This matters because “daemon is broken” can mean several layers.

- **UI**: `rustyjack-ui` calls `rustyjack-client::Client` over IPC (`Client::system_command` etc.).
- **Daemon**: `rustyjack-daemon` receives IPC and (when allowed) dispatches into `rustyjack-core::dispatch_command`.
  - See: `rustyjack-daemon/src/server.rs` and `rustyjack-daemon/src/dispatch.rs`.
- **Core**: `rustyjack-core` implements most user-visible operations under `operations.rs` (system, wifi, hotspot, USB, logs, etc.).
- **Wireless/Netlink**: low-level Linux interface/wifi operations live under `rustyjack-wireless` and `rustyjack-netlink`.

### Why systemd matters here

`rustyjackd.service` is not just “how it starts”. It is **part of the program’s runtime environment**. In practice, it decides which syscalls and which files the daemon is allowed to touch. If the daemon is sandboxed too aggressively, you get errors that look like driver bugs but are actually policy blocks.

---

# Findings and fixes

Each item uses your requested format:

**What is the problem? -> Why is it a problem? -> Where is the problem? -> How to solve -> What “fixed” looks like**

---

## 1) USB mounting fails because the daemon is sandboxed away from `mount(2)`

**What is the problem?**  
The daemon cannot mount USB devices (and therefore “Export Logs to USB” fails) because the service denies mount/umount syscalls.

**Why is it a problem?**  
Your code uses the kernel `mount(2)` syscall directly (good: no external `mount` binary), but systemd blocks the syscall. So even a correct implementation will always fail.

Also: even if the syscall were allowed, mounting requires privileges (CAP_SYS_ADMIN), which you *do* include in `CapabilityBoundingSet`, so the primary blocker is the syscall filter.

**Where is the problem?**

- **systemd unit**: `rustyjackd.service`
  - `SystemCallFilter=@system-service`
  - `SystemCallFilter=~@raw-io @module @mount ...`

- **code path**:
  - UI triggers `SystemCommand::ExportLogsToUsb` (UI: `rustyjack-ui/src/app.rs` around `export_logs_to_usb`).
  - Daemon dispatches into core: `rustyjack-core/src/operations.rs` -> `handle_system_export_logs_to_usb` -> `mount::mount_device`.
  - Mount implementation: `rustyjack-core/src/mount.rs` uses `unsafe { libc::mount(...) }` and `unsafe { libc::umount2(...) }`.

**How to solve the problem**

### Fix A (recommended): allow mount syscalls in `rustyjackd.service`

Minimal, targeted change:

- Keep `SystemCallFilter=@system-service`
- **Add** `@mount` to the allowlist *or* remove `~@mount` from the denylist.

Concrete unit diff (illustrative):

```ini
# rustyjackd.service
# Existing:
SystemCallFilter=@system-service
SystemCallFilter=~@raw-io @module @mount @swap @reboot @clock @debug @cpu-emulation @obsolete @resources @privileged

# Recommended change:
SystemCallFilter=@system-service @mount
SystemCallFilter=~@raw-io @module @swap @reboot @clock @debug @cpu-emulation @obsolete @resources @privileged
```

Why this works: `@system-service` deliberately excludes `@mount`, so you must add it explicitly for filesystem mounting.

### Fix B (defense-in-depth): split mounting into a tiny privileged helper

If you want the daemon to remain “mostly sandboxed”, create a **small Rust helper daemon** (or a `Type=oneshot` systemd service) dedicated to mounting/unmounting under tight constraints, and communicate with it via a unix socket.

This is more work, but gives clean privilege separation:

- Main daemon: no `CAP_SYS_ADMIN`, no `@mount`
- Mount helper: only `CAP_SYS_ADMIN`, only `@mount` and minimal filesystem access

Given your current state, Fix A is the fastest stabiliser.

**What “fixed” looks like**

- `Settings -> Logs -> Export Logs to USB` succeeds on a FAT32/ext4 stick.
- `journalctl -u rustyjackd` shows mount and copy steps without `EPERM`.
- Mount failures, when they happen, are real (unsupported filesystem / corrupted media) rather than sandbox artifacts.

---

## 2) USB export fails on some filesystems because FS support is assumed, not detected

**What is the problem?**  
`mount.rs` is willing to attempt mounting ExFAT, but many Pi images do not ship with ExFAT kernel support. The mount syscall then fails with EINVAL/ENODEV.

**Why is it a problem?**  
Users see “mount failed” and get a generic hint, but the real issue is: **kernel can’t mount that filesystem**. Without checking `/proc/filesystems`, you can’t provide a deterministic fix path.

**Where is the problem?**

- `rustyjack-core/src/mount.rs`
  - `MountPolicy { allow_exfat: true, ... }` in `handle_system_usb_mount` and `handle_system_export_logs_to_usb`.
  - `detect_fs_type()` identifies `exfat` based on magic bytes.
  - There is **no check** for runtime support (`/proc/filesystems`).

**How to solve the problem**

Implement a “supported filesystem” check before trying to mount:

- Read `/proc/filesystems`.
- Build a `HashSet<String>` of supported fs names.
- If detected fs is not supported, fail fast with a **specific** error.

Pseudo-code (Rust):

```rust
fn kernel_supported_filesystems() -> anyhow::Result<HashSet<String>> {
    let content = std::fs::read_to_string("/proc/filesystems")?;
    let mut set = HashSet::new();
    for line in content.lines() {
        // lines look like: "nodev\tsysfs" or "ext4"
        if let Some(fs) = line.split_whitespace().last() {
            set.insert(fs.to_string());
        }
    }
    Ok(set)
}

fn ensure_fs_supported(fs: FilesystemType) -> anyhow::Result<()> {
    let supported = kernel_supported_filesystems()?;
    let name = fs.as_str(); // "vfat" / "ext4" / "exfat" ...
    if !supported.contains(name) {
        anyhow::bail!(
            "Filesystem {name} detected but not supported by kernel. Use FAT32 (vfat) or ext4, or enable kernel support for {name}."
        );
    }
    Ok(())
}
```

Call this inside `mount_device()` after `detect_fs_type()` and policy checks, before `do_mount()`.

**What “fixed” looks like**

- If a user plugs an ExFAT stick into an image without ExFAT support, they get:
  - A clean, deterministic error: “exfat not supported by kernel; use FAT32/ext4”.
- FAT32/ext4 sticks mount reliably.

---

## 3) Hotspot fails with “regdom/channel invalid” because the project doesn’t set regulatory domain

**What is the problem?**  
Hotspot start can fail because the regulatory domain (country code) is unset/invalid, so the channel selection logic can end up with no valid channels or rejects the requested channel.

**Why is it a problem?**  
On Linux, allowed channels and transmit power are constrained by the regulatory domain. If the device is left in the world domain (`00`) or an unset state, many channels can be prohibited and AP start will fail.

The project currently *detects* this condition, but does not fix it.

**Where is the problem?**

- `rustyjack-wireless/src/hotspot.rs`
  - `regdom_warning(&config.ap_interface, config.channel)` detects “unset/invalid” and warns.
  - Channel selection depends on `WirelessManager::list_valid_channels(&phy_name)`.

**How to solve the problem**

You asked specifically: “make sure the install scripts fetch the country code and set it”. The clean approach is **install-time persistence**, with a runtime verification.

### Step 1 — determine country code (install-time, Rust)

Add a small Rust routine used by installer (or by a `rustyjack country-detect` subcommand) to choose an ISO3166 alpha‑2 code:

Priority order (deterministic):

1. `RUSTYJACK_COUNTRY=IE` env var (explicit override)
2. Parse `/etc/wpa_supplicant/wpa_supplicant.conf` for `country=XX`
3. Parse `/etc/default/locale` or `/etc/locale.conf` for `LANG=xx_YY` -> `YY`
4. Parse `/etc/timezone` (e.g. `Europe/Dublin`) and map to country (IE)
5. Final fallback: `GB` (or `US`) but *print a warning loudly* and tell user how to override

### Step 2 — persist regulatory domain without external tools

Prefer **module option** + **boot cmdline fallback**:

1) Write `/etc/modprobe.d/cfg80211.conf`:

```text
options cfg80211 ieee80211_regdom=IE
```

2) Also ensure kernel cmdline contains:

```text
cfg80211.ieee80211_regdom=IE
```

Write to whichever cmdline exists:

- `/boot/firmware/cmdline.txt` (common on newer Pi OS)
- `/boot/cmdline.txt` (older layouts)

This avoids needing `iw`/`crda` binaries.

### Step 3 — runtime verification + user-visible logging

On hotspot start:

- Read `/sys/module/cfg80211/parameters/ieee80211_regdom`
- If it’s empty/`00`, warn and emit an actionable error:
  - “Regulatory domain is unset. Re-run installer or set RUSTYJACK_COUNTRY.”

Also print the effective channel selection:

- After you compute `chosen_channel`, log:
  - `info!("[HOTSPOT] Regulatory domain={regdom}, selected channel={chosen_channel}")`

This shows up in `journalctl -u rustyjackd` and in any console log capture.

**What “fixed” looks like**

- First boot/installer output:
  - “Detected country: IE”
  - “Configured cfg80211 regdom: IE”
  - “Default hotspot channel preference: 6 (fallback list: 1/6/11)”
- Hotspot starts without regdom warnings.
- If regdom is wrong, the error explains exactly what to change.

---

## 4) Hotspot can fail because `ProtectKernelTunables=true` blocks sysctl writes

**What is the problem?**  
Hotspot startup unconditionally enables IPv4 forwarding by writing to `/proc/sys/net/ipv4/ip_forward`. The daemon service is configured with `ProtectKernelTunables=true`, which makes `/proc/sys` read-only for the service.

**Why is it a problem?**  
Even if everything else is correct, forwarding and NAT will silently fail (or hard-fail) because the kernel tunable can’t be changed.

**Where is the problem?**

- systemd unit: `rustyjackd.service` -> `ProtectKernelTunables=true`
- code: `rustyjack-wireless/src/hotspot.rs` -> `enable_ip_forwarding()` writes to `/proc/sys/net/ipv4/ip_forward`.

**How to solve the problem**

You have two valid strategies. Pick one based on your security posture.

### Strategy A (simple): disable `ProtectKernelTunables`

In `rustyjackd.service`:

```ini
ProtectKernelTunables=false
```

This matches what the daemon actually does.

### Strategy B (more locked down): preconfigure sysctls at install time + make code idempotent

1) Installer writes `/etc/sysctl.d/99-rustyjack.conf`:

```text
net.ipv4.ip_forward=1
```

2) Modify `enable_ip_forwarding()` to:

- Read the file first.
- If it is already `1`, do nothing.
- Only attempt a write when it’s not `1`.

Pseudo-code:

```rust
fn enable_ip_forwarding() -> Result<()> {
    let path = "/proc/sys/net/ipv4/ip_forward";
    let cur = std::fs::read_to_string(path).unwrap_or_default();
    if cur.trim() == "1" {
        tracing::info!("[HOTSPOT] IPv4 forwarding already enabled");
        return Ok(());
    }
    std::fs::write(path, "1")
        .map_err(|e| WirelessError::System(format!("Failed to enable ip_forward: {e}")))?;
    Ok(())
}
```

With this, `ProtectKernelTunables=true` is still *incompatible* unless ip_forward is already 1. But now it becomes stable: you configure it once, and runtime doesn’t fight the sandbox.

**What “fixed” looks like**

- Hotspot start no longer fails on “permission denied” / “read-only” when enabling forwarding.
- NAT works when an upstream interface is configured.

---

## 5) Hotspot default upstream interface is wrong for Pi Zero 2 W (no `eth0`)

**What is the problem?**  
`HotspotConfig::default()` sets `upstream_interface: "eth0"`. A Pi Zero 2 W typically has **no built-in ethernet**, so hotspot start will fail unless the UI overrides this.

**Why is it a problem?**  
Out-of-box reliability matters. Requiring a hidden UI setting to avoid an immediate failure is how you get “it works on my desk” syndrome.

**Where is the problem?**

- `rustyjack-wireless/src/hotspot.rs` -> `impl Default for HotspotConfig`.
- `start_hotspot()` checks `ensure_interface_exists(&config.upstream_interface)` and fails if it doesn’t exist.

**How to solve the problem**

Make upstream optional by default:

- Default `upstream_interface` to empty string.
- In the UI, allow selecting an upstream interface explicitly (USB ethernet gadget, `wlan1`, etc.).

Concrete change:

```rust
upstream_interface: "".to_string(),
```

Additionally, implement “auto-upstream” logic (safe heuristic):

- If upstream is empty, run local-only mode (already supported).
- If user enables “Share internet”, auto-pick the first interface that:
  - is up,
  - has an IPv4 address,
  - is not the AP interface.

You can implement this using your existing netlink helpers (`rustyjack_netlink::InterfaceManager`).

**What “fixed” looks like**

- On a Pi Zero 2 W with only `wlan0`, hotspot can still start in local-only mode.
- If the user plugs in USB ethernet, enabling upstream sharing works without manual editing.

---

## 6) MAC randomisation fails intermittently because of interface state + missing guard rails

**What is the problem?**  
MAC randomisation can fail with “internal error… Check permissions/drivers”. The underlying reasons are likely one of:

- Interface is busy (associated, AP mode running, or managed by another subsystem).
- Driver refuses MAC changes in current mode/state.
- The daemon sandbox/capabilities prevent the netlink operation.

The current UX collapses these into one opaque error.

**Why is it a problem?**  
MAC randomisation is a “confidence feature”: if it fails randomly, users will assume the whole device is untrustworthy.

**Where is the problem?**

- UI error mapping: `rustyjack-ui/src/app.rs` around `MacRandomize` error hints.
- Core dispatch: `rustyjack-core/src/operations.rs` -> `handle_wifi_mac_randomize`.
- MAC logic: `rustyjack-evasion/src/mac.rs` (`MacManager`).
- Low-level: `rustyjack-netlink/src/interface.rs` (`InterfaceManager::set_mac_address`).

**How to solve the problem**

### A) Make MAC randomisation explicitly stateful

Before attempting to change MAC:

1. Detect interface mode:
   - If hotspot is running on that interface, stop hotspot first.
   - If connected to Wi-Fi, disconnect first.

You already have the primitives:

- Hotspot state is tracked (`HotspotState` in `hotspot.rs`).
- Wi-Fi disconnect exists via netlink ctrl.

### B) Add a retry path that handles the common case

Observed in the field: some drivers require interface down + settle time.

Implement:

- Bring interface down.
- Sleep 200–500ms.
- Set MAC.
- Bring interface up.
- If `set_mac` fails with `EBUSY`, try one extra cycle after killing conflicting processes (you already have a Rust `/proc` pkill implementation).

Pseudo-code:

```rust
for attempt in 0..2 {
    iface.down()?;
    std::thread::sleep(Duration::from_millis(300));
    match iface.set_mac(new) {
        Ok(_) => break,
        Err(e) if attempt == 0 && is_busy(&e) => {
            // stop hotspot/wifi users, then retry
            stop_hotspot_if_using(iface_name);
            disconnect_wifi(iface_name);
            continue;
        }
        Err(e) => return Err(e),
    }
}
iface.up()?;
```

### C) Improve error classification (so UI can say what to do)

When `InterfaceManager::set_mac_address` fails, capture:

- `errno` (from netlink error / io error)
- interface state (up/down, operstate)
- current mode (AP/managed/monitor)

Then map to user-facing hints:

- EPERM -> “daemon lacks CAP_NET_ADMIN (check systemd unit)”.
- EBUSY -> “interface busy; disconnect/stop hotspot and retry”.
- EOPNOTSUPP -> “driver does not support MAC changes in this mode”.

**What “fixed” looks like**

- MAC randomisation succeeds reliably when invoked from the UI in supported states.
- When it fails, the UI points to a concrete action: disconnect wifi, stop hotspot, or adjust service permissions.

---

## 7) Daemon health checks can fail because `/etc` is read-only under `ProtectSystem=strict`

**What is the problem?**  
Some core operations include checks that require `/etc/resolv.conf` to be writable. But `rustyjackd.service` sets `ProtectSystem=strict`, and does not include `ReadWritePaths=/etc/resolv.conf`.

**Why is it a problem?**  
This creates failures that look like “network broken” but are actually “service is not allowed to manage DNS state”.

**Where is the problem?**

- systemd unit: `rustyjackd.service` -> `ProtectSystem=strict`
- code: `rustyjack-core/src/operations.rs` -> `ensure_route_health_check()` checks writability.

**How to solve the problem**

Pick one:

### Option A: allow the daemon to manage `/etc/resolv.conf`

Add to unit:

```ini
ReadWritePaths=/etc/resolv.conf
```

(You already rely on installer steps that “claim” resolv.conf, so this matches intent.)

### Option B: stop requiring `/etc/resolv.conf` to be writable at runtime

- If you only need to **read DNS servers**, just read it (already implemented in `system/mod.rs::read_dns_servers`).
- If you need to update DNS, move it to a controlled path under `/run/rustyjack/` and make `/etc/resolv.conf` a symlink to that during install.

This is more work but more sandbox-friendly.

**What “fixed” looks like**

- Route/DNS related operations do not fail due to “permission denied” on `/etc/resolv.conf`.
- If DNS must be managed, the write path is either explicitly permitted or redesigned into `/run`.

---

## 8) Observability gaps: UI gets a generic hint instead of the real root cause

**What is the problem?**  
Several UI actions collapse different failure modes into the same “internal error / check permissions” message.

**Why is it a problem?**  
When you’re running headless-ish hardware, the UI is the product. If it can’t tell the user what happened, you’ll end up debugging in the field.

**Where is the problem?**

- UI hinting: `rustyjack-ui/src/app.rs` (progress/hint mapping)
- Error creation: multiple modules return `anyhow::Error` or `WirelessError::System(String)` without structured codes.

**How to solve the problem**

- Introduce a small “error taxonomy” shared between core and UI:
  - `PermissionDenied`
  - `SandboxDenied`
  - `DriverUnsupported`
  - `DeviceBusy`
  - `FilesystemUnsupported`
  - `HardwareMissing`

In Rust, you already use `thiserror`; add variants and attach context (errno, interface, syscall group suspected).

Then UI can show:

- a short reason
- a “Fix:” line that is actually correct for that error class

**What “fixed” looks like**

- When mounting fails because `@mount` is blocked, the UI literally says:
  - “Mount syscall blocked by daemon sandbox. Fix: update rustyjackd.service (SystemCallFilter).”

---

# Install-time country code handling (action plan)

You asked for install scripts to “fetch and set country code” and print it.

The snapshot you provided **does not include** the `install_rustyjack*.sh` scripts referenced in `README.md`. The docs mention them, but the actual script bodies are not in this zip.

So: I can’t point at “line 143 of install_rustyjack.sh” because it isn’t here. What I *can* do is give you a drop-in Rust-first approach that those scripts should call.

## Proposed: a Rust subcommand used by installer

Add a `rustyjack-core` (or `rustyjack-commands`) subcommand:

- `rustyjack system set-regdom --auto`

What it does:

1. Determine country code (priority list above).
2. Print it.
3. Persist it:
   - write `/etc/modprobe.d/cfg80211.conf`
   - patch `/boot/*/cmdline.txt` to include `cfg80211.ieee80211_regdom=XX` if not present
4. (Optional) Print valid channels for the AP interface, by calling existing `WirelessManager::list_valid_channels`.

Installer then just runs that one command and prints output.

No new external binaries. No guesswork.

---

# Suggested test plan (Pi Zero 2 W)

## Hotspot

1. Start hotspot with upstream empty.
2. Verify `journalctl -u rustyjackd` includes:
   - regdom
   - selected channel
3. Verify AP is visible and clients can associate.

## USB export

1. FAT32 stick: export logs.
2. ext4 stick: export logs.
3. ExFAT stick (on image without exfat): verify deterministic “kernel unsupported” error.

## MAC randomise

1. Randomise MAC while disconnected: must succeed.
2. Randomise while hotspot running: should stop hotspot or refuse with clear reason.
3. Randomise twice rapidly: must not leave interface down.

---

# Reference notes (external docs)

(These are for developers, not user-facing UI.)

- systemd syscall filtering and `@system-service` excluding `@mount`: https://man7.org/linux/man-pages/man5/systemd.exec.5.html
- `mount(2)` privilege requirements (CAP_SYS_ADMIN): https://man7.org/linux/man-pages/man2/mount.2.html
- Linux wireless regulatory domain discussion: https://wireless.wiki.kernel.org/en/developers/regulatory

