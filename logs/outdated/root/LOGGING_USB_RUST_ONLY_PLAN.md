# Rust-Only Logging and USB Export Plan
Created: 2026-01-07

This document outlines how to replace shell-based log collection with Rust-only implementations and keep USB export fully Rust-based. It also proposes a daemon-owned log file so only the daemon writes logs while the UI reads and exports them.

## Goals
- Remove `Command::new(...)` usage in log collection (no `journalctl`, `gpioinfo`, `lsof`, `fuser`, or `ls`).
- Replace systemd/journald dependence with Rust-owned logs.
- Preserve the current UI export flow (user selects USB, exports logs).
- Keep USB mounting and file writing Rust-only.
- Use only Rust crates and kernel interfaces (`/proc`, `/sys`, syscalls), no external binaries.

## Current UI Pipeline (for context)
1. User selects **Export Logs to USB**.
2. UI asks daemon for removable devices (BlockDevices RPC).
3. UI requests daemon to mount the device if needed (UsbMount RPC).
4. UI asks daemon for a log bundle (SystemLogsGet RPC).
5. UI writes the bundle to `<mount>/Rustyjack_Logs/rustyjack_logs_<timestamp>.txt`.

USB mounting already uses Rust syscalls (`mount(2)` / `umount2)` in `rustyjack-core/src/mount.rs`. The remaining shell usage is in `rustyjack-core/src/services/logs.rs`.

## Proposed Rust-Only Logging Architecture

### 1) Daemon-Owned Log File
Create a single log file owned and written by the daemon:
- Path: `/var/lib/rustyjack/logs/rustyjack_log.txt`
- Permissions: directory `0700`, file `0600` (daemon-only write)
- Format: structured text or JSON lines with timestamp, level, module, request_id
- Rotation: size-based (for example, 5 MB max, keep 3 backups) or daily

Implementation plan:
- Add logging initialization in the daemon entrypoint (`rustyjack-daemon/src/main.rs` or equivalent).
- Use `tracing_subscriber` + `tracing_appender::rolling` for file rotation.
- Bridge existing `log::info!` macros via `tracing_log::LogTracer`.
- Ensure log directory is created on startup if missing.

Daemon-only writer requirement:
- The UI should not open the log file directly for append.
- If UI log messages matter, add an IPC endpoint like `LogAppend` so the daemon can write them.

### 2) Log Bundle Inputs (Rust-Only)
Replace `collect_log_bundle` to include:
- Tail of `rustyjack_log.txt` (last N bytes or lines).
- Optional kernel log tail from `/dev/kmsg` or a daemon-maintained ring buffer.
- Existing Rust diagnostics already collected from `/proc` and `/sys`.

If `/dev/kmsg` access is restricted, skip it and emit a clear line in the bundle.

### 3) Replace Shell Diagnostics With Rust

The current log bundle uses these external commands:
- `journalctl` (service + kernel logs)
- `gpioinfo`
- `lsof /dev/gpiochip0`
- `fuser -v /dev/gpiochip0`
- `ls -l /dev/gpiochip0 /dev/spidev0.0 /dev/spidev0.1`

Proposed replacements:

1) `journalctl` replacement
   - Replace with daemon log file tail.
   - For kernel messages: use `/dev/kmsg` or `/proc/kmsg` (optional).
   - For NetworkManager/wpa_supplicant visibility: log Rust-side operations and outcomes
     (connect, DHCP, route apply, wpa control calls, netlink events).

2) `gpioinfo` replacement
   - Use `gpio-cdev` (or similar ioctl-based crate) to list chips and lines.
   - Report: chip name, line count, line name, consumer, direction, and active state.

3) `lsof` and `fuser` replacement
   - Scan `/proc/<pid>/fd/*` symlinks and match device paths.
   - Collect PID, process name (`/proc/<pid>/comm`), and command line.
   - Crate option: `procfs` for easier iteration.

4) `ls -l /dev/...` replacement
   - Use `std::fs::metadata` + `libc::stat` to report mode, uid, gid, major/minor.
   - Format output similar to `ls -l` for clarity.

## USB Mounting (Already Rust-Only)
USB mounting uses:
- sysfs detection (`/sys/block`), removable+USB checks
- `libc::mount` and `libc::umount2`
- `/proc/mounts` or `/proc/self/mountinfo` for mount discovery

No shell binaries are invoked in the USB path, so no changes are required unless you want to consolidate mount listing or permission checks.

## Where the Rust Replacements Should Live (and whether new crates are needed)
The log bundle is assembled in `rustyjack-core/src/services/logs.rs`, so the Rust replacements should live in `rustyjack-core` and be called from there.

Recommended layout (no new crate required):
- `rustyjack-core/src/diagnostics/mod.rs`
- `rustyjack-core/src/diagnostics/gpio.rs` (replaces `gpioinfo`)
- `rustyjack-core/src/diagnostics/procfs.rs` (replaces `lsof`/`fuser`)
- `rustyjack-core/src/diagnostics/devinfo.rs` (replaces `ls -l` for device metadata)
- `rustyjack-core/src/diagnostics/kmsg.rs` (optional kernel ring buffer tail)

Why no new crate is required:
- These diagnostics are only needed to build the log bundle in core.
- Keeping them in `rustyjack-core` reduces cross-crate wiring and IPC surface.

When a new crate makes sense:
- If you want diagnostics usable in multiple crates (daemon + UI + core), consider
  a shared `rustyjack-diagnostics` crate with a small, stable API.
- The daemon can depend on it directly; `rustyjack-core` can re-export it.

Dependencies (Rust crates only, no binaries):
- Add `procfs` for `/proc` enumeration helpers.
- Add `gpio-cdev` for GPIO line/chip enumeration.
- Add any platform-specific dependencies under `cfg(target_os = "linux")` in
  `rustyjack-core/Cargo.toml` to keep non-Linux builds clean.

## Refactor Plan (Files and Steps)

1) Add daemon logging init
   - File: `rustyjack-daemon/src/main.rs` (or `rustyjack-daemon/src/logging.rs`)
   - Initialize `tracing_subscriber` and file appender.

2) Replace log bundle assembly
   - File: `rustyjack-core/src/services/logs.rs`
   - Remove `Command::new(...)` calls.
   - Add:
     - `append_daemon_log_tail`
     - `append_gpio_snapshot`
     - `append_open_device_users`
     - `append_device_metadata`
     - `append_kmsg_tail` (optional)

3) (Optional) Add daemon-only log append endpoint
   - Files:
     - `rustyjack-ipc/src/types.rs`: `LogAppendRequest/Response`
     - `rustyjack-daemon/src/dispatch.rs`: endpoint handler
     - `rustyjack-client/src/client.rs`: `log_append(...)`
     - `rustyjack-ui/src/core.rs`: `log_event(...)`
   - UI can forward critical events to the daemon log.

4) Keep export flow unchanged
   - UI still calls `SystemLogsGet` and writes to USB.
   - The log bundle is now generated fully in Rust.

## Example Rust-Only Log Bundle Format
```
===== rustyjack daemon log (tail) =====
2025-01-04T12:09:22Z INFO daemon: hotspot start requested iface=wlan0 upstream=eth0
2025-01-04T12:09:25Z WARN core: dhcp lease failed iface=wlan0 err=timeout

===== gpio snapshot =====
gpiochip0: lines=54
  line 24: name=BL consumer=rustyjack-ui dir=out active=1

===== /dev/gpiochip0 users =====
pid=421 comm=rustyjack-ui cmdline="/usr/bin/rustyjack-ui"

===== device metadata =====
/dev/gpiochip0: mode=crw------- uid=0 gid=0 major=254 minor=0
/dev/spidev0.0: mode=crw------- uid=0 gid=0 major=153 minor=0
```

## Validation Checklist
- Verify daemon log file exists and is writable only by daemon.
- Ensure log bundle export works and includes Rust-only sections.
- Confirm no `Command::new(...)` calls remain in log collection.
- Export logs to USB and verify file contents and permissions.

## Summary
USB export is already Rust-only. The key work is replacing shell-based log collection with Rust-owned logs and Rust diagnostics. The plan above keeps the same UI flow while removing external binaries entirely.
