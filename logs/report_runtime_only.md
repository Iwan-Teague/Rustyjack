# Runtime shell-out audit (Pi runtime only)

**Repo snapshot:** `watchdog_shallow_20260129-003838.zip`  
**Date:** 2026-01-29  
**Scope rule (per request):** This report **only** covers binaries spawned **at runtime on the Pi** by the *running* project (Rust code + any runtime-side helper tooling). The four `install_rustyjack*.sh` scripts are treated as **setup only** and are **not** targets for refactoring. Where a binary is also mentioned/used in those install scripts, that is explicitly marked **“installer usage is OK.”**

---

## Executive summary

### What I found
1. **The default Pi daemon build (`rustyjack-daemon`) uses the `appliance` feature by default**, and `rustyjack-core` explicitly states that the `appliance` feature *forbids external process spawning*. In this snapshot, that means: **no runtime `Command::new(...)` / shell-outs are compiled into the production daemon unless you enable “lab/external tools” features.**
2. **All runtime shell-outs I found fall into two buckets:**
   - **Optional “lab/external tools” code paths** inside `crates/rustyjack-core/src/external_tools/**` (feature-gated behind `rustyjack-core/external_tools`, which is enabled by `rustyjack-daemon --features lab`).
   - **Optional WiFi station implementation** `rustyjack-netlink/station_external`, which spawns **`wpa_supplicant`**.

### What this means
- If your goal is “**the shipped Pi runtime never shells out**”, your simplest, highest-confidence fix is:
  - **Keep shipping `rustyjack-daemon` with default features (appliance)**, and
  - **add CI / build-system guardrails** to prevent `--features lab` (or `station_external`) from being enabled in production builds.

- If your goal is “**no code path anywhere in the repo ever shells out**”, then you’ll want to either **delete** the lab/external-tools features or **rewrite** them to use Rust libraries / syscalls / DBus APIs.

---

## Priority list (runtime binaries found in code)

> Counts below are *call sites in Rust* (direct) plus *indirect* invocations where the code spawns a wrapper binary (e.g., `timeout`) that then runs another tool.

| Priority | Binary | Total runtime call sites | Direct spawns | Indirect (via wrapper) | Feature gate | Also referenced in install scripts? |
|---:|---|---:|---:|---:|---|---|
| 1 | `reaver` | 1 | 0 | 1 | rustyjack-core: external_tools (via daemon --features lab) | No |
| 1 | `wpa_supplicant` | 1 | 1 | 0 | rustyjack-netlink: station_external (enabled via rustyjack-core lab) | Yes (keep installer usage) |
| 2 | `bash` | 2 | 2 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 2 | `timeout` | 2 | 2 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 2 | `avahi-browse` | 1 | 0 | 1 | rustyjack-core: external_tools (via daemon --features lab) | No |
| 3 | `journalctl` | 5 | 5 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 3 | `systemctl` | 4 | 4 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 3 | `hostnamectl` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 3 | `shutdown` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 3 | `sysctl` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 4 | `tar` | 4 | 4 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `openssl` | 3 | 3 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `dphys-swapfile` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `exiftool` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `mount` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 4 | `nscd` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `ps` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `shred` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `swapoff` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 4 | `sync` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `ulimit` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 4 | `umount` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | No |
| 5 | `git` | 2 | 2 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |
| 5 | `which` | 1 | 1 | 0 | rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab) | Yes (keep installer usage) |

---

## Detailed findings and Rust-first replacement guidance

## `reaver`

**Total runtime invocations:** 1 (direct: 0, indirect: 1)

**Feature gate:** rustyjack-core: external_tools (via daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/physical_access.rs:445` (`try_wps_attack`) — **indirect** via `timeout`

### Why it’s used
`reaver` is invoked (indirectly via `timeout`) by `try_wps_attack` in `external_tools/physical_access.rs`. This is an **offensive WPS attack tool**.

### How to replace it (Rust-only)
I can’t help with building a Rust replacement for an automated WPS attack tool. That would be directly enabling abuse.

What I *can* do is give you a clean Rust-first path to remove this runtime dependency:

1. **Delete the feature** (preferred): remove the `try_wps_attack` command surface entirely from your command routing/UI.
2. **Compile it out** by default: keep it only behind a `lab` feature that is **never** enabled in production, and make production builds fail fast if it’s enabled.

### What a working fix looks like
- Replace the runtime behavior with a disabled stub outside of lab builds:

```rust
#[cfg(feature = "lab")]
pub fn try_wps_attack(/* ... */) -> Result<WpsResult> {
    // existing code (still consider whether this should exist at all)
}

#[cfg(not(feature = "lab"))]
pub fn try_wps_attack(/* ... */) -> Result<WpsResult> {
    anyhow::bail!("WPS attack tooling is not available in production builds");
}
```

- Add a **policy gate** in your build pipeline: any release artifact targeting the Pi must be built without `--features lab`.

---

## `wpa_supplicant`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-netlink: station_external (enabled via rustyjack-core lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-netlink/src/station/external/process.rs:62` (`start_wpa_supplicant`)

### Why it’s used
`wpa_supplicant` is spawned as the “external station mode” WiFi implementation. In this snapshot it lives under `rustyjack-netlink/src/station/external/` and is only reachable when the **`station_external`** feature is enabled.

### How to replace it (Rust-only)
**Best option:** remove/disable `station_external` and standardize on your native Rust WiFi station implementation (`station_rust_wpa2`).  
If `station_external` exists as a fallback, keep it **behind a dev-only feature** that is not built for production.

To build a Rust-only station mode on Linux, you typically:
1. Use **nl80211** (netlink WiFi API) to configure the interface, scan, authenticate/associate, etc. (`wl_nl80211` is a Rust-facing nl80211 interface).
2. Implement WPA2/WPA3 key management in Rust (or integrate a library). This is non-trivial; the point here is to **not** spawn `wpa_supplicant`.

### What a working fix looks like
- **Hard block** the feature in production builds:

```rust
// in rustyjack-netlink/src/lib.rs (or a central features module)
#[cfg(all(feature = "station_external", feature = "production"))]
compile_error!("station_external must not be enabled in production builds");
```

- **Route selection**: in whichever factory selects the station backend, default to the Rust implementation and only compile the external backend with `#[cfg(feature="station_external")]`.

If you still want a runtime control channel similar to `wpa_supplicant`’s ctrl socket, study the wpa_ctrl interface docs as a behavioral reference (not as an implementation dependency).

---

## `bash`

**Total runtime invocations:** 2 (direct: 2, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/operations.rs:3293` (`handle_system_fde_prepare`)
- `crates/rustyjack-core/src/operations.rs:3357` (`handle_system_fde_migrate`)

### Why it’s used
`bash` is used to run full-disk-encryption migration scripts:
- `scripts/fde_prepare_usb.sh`
- `scripts/fde_migrate_root.sh`

These scripts are referenced from `rustyjack-core/src/operations.rs` but **are not present in this snapshot**, so I can’t enumerate their internal binary usage. (In practice these scripts often depend on tools like `cryptsetup`, `lsblk`, `mount`, `rsync`, etc.)

### How to replace it (Rust-only)
If you want “no shell scripts at runtime,” the strategy is:

1. **Pull the FDE workflow into a Rust crate** (e.g., `rustyjack-fde`), with an explicit, testable state machine:
   - detect target disk & partitions
   - create/resize partitions
   - create LUKS container
   - migrate rootfs
   - update `fstab`, initramfs hooks, bootloader config
   - reboot into encrypted root
2. For LUKS/cryptsetup, use **FFI bindings** instead of spawning `cryptsetup` binaries (e.g., `libcryptsetup_rs`).  
   (This avoids shelling out, while still leaning on the battle-tested library.)

### What a working fix looks like
- Replace the script runner with a Rust API:

```rust
pub fn prepare_usb(device: &Path) -> Result<()> {
    // 1) partition changes (use ioctl/netlink/udev as needed)
    // 2) create luks container via libcryptsetup bindings
    // 3) format inner FS, mount, copy, etc. (Rust + syscalls)
    Ok(())
}
```

- Then update `handle_system_fde_*` to call the Rust functions directly and delete the `bash` calls.

---

## `timeout`

**Total runtime invocations:** 2 (direct: 2, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/physical_access.rs:218` (`extract_from_mdns`)
- `crates/rustyjack-core/src/external_tools/physical_access.rs:445` (`try_wps_attack`)

### Why it’s used
`timeout` wraps other commands so they don’t hang forever (service discovery and the WPS tool path).

### How to replace it (Rust-only)
Use a Rust timeout around the underlying operation. If the underlying thing is another external binary, the real fix is to remove *that* dependency too — but the timeout wrapper itself is easy to replace.

### What a working fix looks like
With Tokio:

```rust
use tokio::time::{timeout, Duration};

let result = timeout(Duration::from_secs(10), async {
    // do the Rust-native operation here (e.g., mdns browse)
}).await;

match result {
    Ok(inner) => inner?,
    Err(_) => anyhow::bail!("operation timed out"),
}
```

---

## `avahi-browse`

**Total runtime invocations:** 1 (direct: 0, indirect: 1)

**Feature gate:** rustyjack-core: external_tools (via daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/physical_access.rs:218` (`extract_from_mdns`) — **indirect** via `timeout`

### Why it’s used
`avahi-browse` is executed indirectly via `timeout` to discover local network services (mDNS / DNS-SD).

### How to replace it (Rust-only)
Use a Rust mDNS/DNS-SD library instead of shelling out. One practical option is `mdns-sd`, which provides service browsing/resolving APIs in Rust.

### What a working fix looks like
A minimal browsing example (shape-level sketch):

```rust
use mdns_sd::{ServiceDaemon, ServiceEvent};

let mdns = ServiceDaemon::new()?;
let receiver = mdns.browse("_services._dns-sd._udp.local.")?;
while let Ok(event) = receiver.recv() {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            println!("found: {} @ {:?}", info.get_fullname(), info.get_addresses());
        }
        _ => {}
    }
}
```

Then delete the `avahi-browse` call and drive the discovery UI from these events.

---

## `journalctl`

**Total runtime invocations:** 5 (direct: 5, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:174` (`clear_system_logs`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:175` (`clear_system_logs`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:306` (`perform_complete_purge`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:307` (`perform_complete_purge`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:308` (`perform_complete_purge`)

### Why it’s used
The current code calls `journalctl` from `external_tools/anti_forensics.rs` (e.g., log manipulation).

### How to replace it (Rust-only)
If you need *log reading for diagnostics*, use a Rust wrapper around journald APIs instead of shelling out — for example the `systemd` crate’s `journal` module or `sd-journal`.

If the goal is to *erase/rotate logs*, I’m not going to provide “working code” for that. That’s a classic anti-forensics capability. The safe refactor path is to **remove that feature entirely** or restrict it to a controlled, audited administrative environment.

### What a working fix looks like
- Replace `journalctl` *reading* with Rust:

```rust
use systemd::journal::Journal;

let mut j = Journal::open(Journal::default_open_options())?;
j.seek_tail()?;
```

- For anything that’s “log deletion/cleaning,” the working fix is: delete the feature or hard-gate it behind a build flag that is never shipped.

---

## `systemctl`

**Total runtime invocations:** 4 (direct: 4, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:260` (`perform_complete_purge`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:309` (`perform_complete_purge`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:310` (`perform_complete_purge`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:328` (`clear_dns_cache`)

### Why it’s used
In `external_tools/anti_forensics.rs` it’s used for things like `daemon-reload`, `reset-failed`, and service manipulation.

### How to replace it (Rust-only)
Use systemd’s DBus API instead of spawning `systemctl`. A Rust-native approach is `zbus_systemd` (auto-generated interfaces for systemd DBus services).

### What a working fix looks like
Shape-level sketch (API names based on `zbus_systemd` systemd1 manager proxy):

```rust
use zbus_systemd::zbus;
use zbus_systemd::systemd1::ManagerProxy;

let conn = zbus::Connection::system().await?;
let mgr = ManagerProxy::new(&conn).await?;

// e.g., restart a unit
mgr.restart_unit("rustyjack.service", "replace").await?;
```

You can map other `systemctl` behaviors to DBus methods (start/stop/reload/enable/disable) via the same proxy.

---

## `hostnamectl`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:786` (`randomize_hostname`)

### Why it’s used
Used to randomize/set the system hostname.

### How to replace it (Rust-only)
Use DBus interface `org.freedesktop.hostname1` via `zbus_systemd` instead of `hostnamectl`.  
Alternatively, write `/etc/hostname` and call `sethostname(2)` (but DBus keeps systemd components in sync).

### What a working fix looks like
Syscall sketch:

```rust
use std::ffi::CString;
let hn = CString::new("new-hostname")?;
unsafe { libc::sethostname(hn.as_ptr() as *const _, hn.as_bytes().len()); }
```

---

## `shutdown`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:626` (`check_dead_mans_switch`)

### Why it’s used
Used as a “dead man’s switch” action.

### How to replace it (Rust-only)
Prefer systemd’s DBus interfaces (logind) for poweroff/reboot on systemd systems, rather than shelling out. `zbus_systemd` supports systemd services over DBus.

### What a working fix looks like
- Use DBus (logind) to request poweroff/reboot (API details depend on module you enable), or
- As a last resort, call the Linux reboot syscall via `libc` (requires privileges).

---

## `sysctl`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/evasion.rs:103` (`set_sysctl`)

### Why it’s used
Used to set kernel parameters at runtime (`sysctl -w ...`).

### How to replace it (Rust-only)
Write directly to `/proc/sys/...` for the parameter you need, or manage persistent settings via `/etc/sysctl.d/*.conf` and reload.

### What a working fix looks like
```rust
use std::fs;

fn set_sysctl(path: &str, value: &str) -> std::io::Result<()> {
    fs::write(path, value.as_bytes())
}

// e.g. set_sysctl("/proc/sys/net/ipv4/ip_forward", "1\n")?;
```

---

## `tar`

**Total runtime invocations:** 4 (direct: 4, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:408` (`encrypt_loot`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:472` (`decrypt_loot`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:713` (`create_safety_backup`)
- `crates/rustyjack-core/src/external_tools/archive_ops.rs:32` (`backup_repository`)

### Why it’s used
Used to pack/unpack “loot” archives and safety backups.

### How to replace it (Rust-only)
Use the `tar` crate for archive creation/extraction and `flate2` for gzip compression.

### What a working fix looks like
Create `tar.gz`:

```rust
use std::fs::File;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder;

let tar_gz = File::create("loot.tar.gz")?;
let enc = GzEncoder::new(tar_gz, Compression::default());
let mut tar = Builder::new(enc);
tar.append_dir_all("loot", "/path/to/loot")?;
let enc = tar.into_inner()?; // finish tar
enc.finish()?;               // finish gzip
```

Extract:

```rust
use std::fs::File;
use flate2::read::GzDecoder;
use tar::Archive;

let tar_gz = File::open("loot.tar.gz")?;
let dec = GzDecoder::new(tar_gz);
let mut ar = Archive::new(dec);
ar.unpack("/restore/here")?;
```

---

## `openssl`

**Total runtime invocations:** 3 (direct: 3, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:411` (`encrypt_loot`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:456` (`decrypt_loot`)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:716` (`create_safety_backup`)

### Why it’s used
Used as an external crypto tool for encrypting/decrypting archives.

### How to replace it (Rust-only)
Use a Rust-native encryption format/library. A pragmatic choice is the `age` crate (modern file encryption with small explicit keys).

### What a working fix looks like
Stream encrypt to a file:

```rust
use age::{Encryptor, x25519};
use std::fs::File;

let identity = x25519::Identity::generate();
let recipient = identity.to_public();

let encryptor = Encryptor::with_recipients(vec![Box::new(recipient)]);
let out = File::create("loot.age")?;
let mut writer = encryptor.wrap_output(out)?;
std::io::copy(&mut File::open("loot.tar.gz")?, &mut writer)?;
writer.finish()?;
```

(Then decrypt with the matching `Identity`.)

---

## `dphys-swapfile`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:850` (`disable_swap`)

### Why it’s used
Used to disable the Raspberry Pi swapfile service.

### How to replace it (Rust-only)
Instead of spawning `dphys-swapfile`, manage the underlying configuration:
- update its config file (if present), and/or
- disable the service using systemd DBus.

### What a working fix looks like
Treat swap policy as **install-time** configuration, not a runtime action:
- move this logic out of runtime or feature-gate it out of production.

---

## `exiftool`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:534` (`sanitize_file_metadata`)

### Why it’s used
Used to strip/inspect metadata on files.

### How to replace it (Rust-only)
If the goal is to sanitize images, the simplest robust approach is to re-encode via the `image` crate, which discards most metadata by construction.  
If you need finer control, parse EXIF with a Rust EXIF parser crate and write back only what you want.

### What a working fix looks like
Re-encode sketch:

```rust
let img = image::open(input_path)?;
img.save(output_path)?; // drops most metadata
```

---

## `mount`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:351` (`enable_ram_only_mode`)

### Why it’s used
Used to enable “RAM-only mode” by mounting a tmpfs (or similar) at runtime.

### How to replace it (Rust-only)
Use the `mount(2)` syscall directly via the `nix` crate.

### What a working fix looks like
```rust
use nix::mount::{mount, MsFlags};

mount(
    Some("tmpfs"),
    "/mnt/rustyjack_ram",
    Some("tmpfs"),
    MsFlags::empty(),
    Some("size=64M"),
)?;
```

---

## `nscd`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:334` (`clear_dns_cache`)

### Why it’s used
Used to clear DNS cache by spawning `nscd -i hosts`.

### How to replace it (Rust-only)
Two cleaner options:
1. If the Pi uses **systemd-resolved**, talk to it over DBus (again `zbus_systemd` has a `resolve1` module) rather than spawning `nscd`.
2. If you don’t actually need this at runtime, **remove the “clear DNS cache” feature** and rely on normal resolver semantics.

### What a working fix looks like
- Replace the current “best-effort cache flush” with either:
  - a no-op in production, or
  - a DBus call to resolved (implementation depends on which resolver is deployed).

---

## `ps`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:756` (`verify_clean`)

### Why it’s used
Used to verify process state (currently shells out to `ps`).

### How to replace it (Rust-only)
Read `/proc` directly using the `procfs` crate.

### What a working fix looks like
```rust
use procfs::process::all_processes;

for p in all_processes()? {
    let p = p?;
    let stat = p.stat()?;
    println!("pid={} comm={}", stat.pid, stat.comm);
}
```

---

## `shred`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:72` (`secure_delete`)

### Why it’s used
Used for “secure delete” behavior.

### How to replace it (Rust-only)
You *can* overwrite file contents in Rust, but be careful: on modern filesystems (journaling, copy-on-write, SSD wear leveling), “secure delete by overwrite” is not reliably secure.

Safer Rust-first options:
- Prefer **encryption-at-rest** (FDE) and delete keys, rather than trying to overwrite plaintext.
- If you still want best-effort overwrites, implement a bounded overwrite + fsync + unlink.

### What a working fix looks like
Best-effort overwrite sketch:

```rust
use std::fs::{OpenOptions, remove_file};
use std::io::{Seek, SeekFrom, Write};

let mut f = OpenOptions::new().write(true).open(path)?;
let len = f.metadata()?.len();
f.seek(SeekFrom::Start(0))?;
f.write_all(&vec![0u8; len as usize])?;
f.sync_all()?;
drop(f);
remove_file(path)?;
```

Again: **best-effort**, not a cryptographic guarantee.

---

## `swapoff`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:847` (`disable_swap`)

### Why it’s used
Used to disable swap.

### How to replace it (Rust-only)
Implement swap management without spawning `swapoff`:
- Call `swapoff(2)` via `libc` for known swap devices/files, or
- Manage swap configuration via files (e.g., disable a configured swapfile service) through systemd DBus.

### What a working fix looks like
A safe “configuration-first” approach is usually better than runtime swap tampering:
- disable swap services (systemd DBus) and reboot into the desired state.

---

## `sync`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:314` (`unknown`)

### Why it’s used
Used to flush filesystem buffers after operations.

### How to replace it (Rust-only)
Call the `sync(2)` syscall (via `libc`) rather than spawning the `sync` binary.

### What a working fix looks like
```rust
unsafe { libc::sync(); }
```

---

## `ulimit`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:485` (`enable_anti_dump_protection`)

### Why it’s used
Used to apply resource limits.

### How to replace it (Rust-only)
Use `setrlimit(2)` via `nix::sys::resource`.

### What a working fix looks like
```rust
use nix::sys::resource::{setrlimit, Resource};

setrlimit(Resource::RLIMIT_CORE, 0, 0)?;
```

---

## `umount`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** No

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:381` (`disable_ram_only_mode`)

### Why it’s used
Used to undo “RAM-only mode” by unmounting the mountpoint.

### How to replace it (Rust-only)
Use `umount2(2)` via `nix`.

### What a working fix looks like
```rust
use nix::mount::{umount2, MntFlags};

umount2("/mnt/rustyjack_ram", MntFlags::MNT_DETACH)?;
```

---

## `git`

**Total runtime invocations:** 2 (direct: 2, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/git_ops.rs:12` (`git_reset_to_remote`)
- `crates/rustyjack-core/src/external_tools/git_ops.rs:16` (`git_reset_to_remote`)

### Why it’s used
Used to query repository state / status in external tooling.

### How to replace it (Rust-only)
Use `git2` (Rust bindings to libgit2) instead of spawning `git`.

### What a working fix looks like
```rust
use git2::Repository;

let repo = Repository::open(".")?;
let statuses = repo.statuses(None)?;
println!("changed files: {}", statuses.len());
```

---

## `which`

**Total runtime invocations:** 1 (direct: 1, indirect: 0)

**Feature gate:** rustyjack-core: external_tools (enabled via rustyjack-daemon --features lab)

**Also referenced in install scripts?** Yes (installer usage is OK; only runtime needs refactor)

### Where it’s used (call sites)
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs:56` (`secure_delete`)

### Why it’s used
Used to locate binaries on `PATH`.

### How to replace it (Rust-only)
Resolve commands by searching `PATH` in Rust (or use `which` crate).

### What a working fix looks like
```rust
use std::env;
use std::path::PathBuf;

fn which(cmd: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let full = dir.join(cmd);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}
```

---


## Appendix A — Production guardrails (recommended)

Even if you eventually rewrite the lab tooling, you can prevent accidental regressions **today**:

1. **Make the Pi release build explicit**:
   - Build `rustyjack-daemon` with `--no-default-features --features appliance` (or keep default but enforce it).
2. **Fail the build if lab features are enabled in a release profile**:
   - Add `compile_error!` checks for `lab`, `external_tools`, and `station_external`.
3. **CI enforcement**:
   - Add a job that runs `cargo tree -e features` and fails if forbidden features appear in the release artifact.
4. **Kill the footgun**:
   - Consider moving `external_tools` into a separate workspace or crate that is not included in the Pi build graph at all.

## Appendix B — References (for implementers)

```text
zbus_systemd (systemd DBus interfaces): https://docs.rs/zbus_systemd/
systemd1 Manager proxy methods: https://docs.rs/zbus_systemd/latest/zbus_systemd/systemd1/struct.ManagerProxy.html
systemd journal (Rust): https://docs.rs/systemd/latest/systemd/journal/
sd-journal (Rust wrapper): https://docs.rs/sd-journal/
nix mount/umount: https://docs.rs/nix/latest/nix/mount/index.html
nix setrlimit: https://docs.rs/nix/latest/nix/sys/resource/index.html
tar crate: https://docs.rs/tar/latest/tar/
age crate: https://docs.rs/age/
mdns-sd crate: https://docs.rs/mdns-sd/
wl_nl80211 crate: https://docs.rs/wl-nl80211/
procfs crate: https://docs.rs/procfs/
git2 crate: https://docs.rs/git2/
libcryptsetup_rs: https://docs.rs/libcryptsetup_rs/
```

## Appendix C — Coverage and limitations

- **Method:** Static source scan of the repo snapshot listed at the top. No runtime execution or dynamic tracing.
- **Scope enforced:** Installer scripts are explicitly excluded; only runtime behavior in Rust code (and runtime-side helper tooling) is covered.
- **Feature flags:** All runtime shell-outs listed above are gated behind `external_tools` and/or `station_external`. If those features are enabled, the corresponding binaries apply.
- **Dynamic configuration:** Any future `Command::new(...)` that constructs argv from config could introduce new runtime dependencies. This report does not cover binaries referenced only in config or documentation.

## Appendix D — Quick action checklist

- [x] Ensure production Pi builds **never** enable `lab`, `external_tools`, or `station_external`.
- [x] Add a CI guard that fails if forbidden features appear in release builds.
- [ ] If “no shell-outs anywhere” is required, delete the `external_tools` modules and the `station_external` station backend.

## Appendix E — Guardrail implementation (2026-01-29)

### What I changed
- Added **compile-time guardrails** that fail release builds if `lab`, `external_tools`, or `station_external` are enabled.
- Added a **CI check** that intentionally attempts a release build with `--features lab` and verifies the guardrail triggers.
- Replaced several runtime shell-outs with Rust implementations and disabled the remaining ones that had no safe Rust equivalent yet.

### Where I changed it
- `crates/rustyjack-core/src/lib.rs`: release-only `compile_error!` for `lab`, `external_tools`, `dev_tools`, `offensive_tools`.
- `crates/rustyjack-netlink/src/lib.rs`: release-only `compile_error!` for `station_external`.
- `crates/rustyjack-daemon/src/main.rs`: release-only `compile_error!` for `lab`.
- `.github/workflows/ci.yml`: added a guard step that runs `cargo check --release -p rustyjack-daemon --features lab` and requires the guard message.
- `crates/rustyjack-core/src/external_tools/anti_forensics.rs`: replaced `sysctl`, `mount/umount`, `ulimit`, `ps`, `hostnamectl`, `swapoff`, `sync`, `tar`, `openssl`, `exiftool`, `journalctl`, `systemctl`, `nscd`, `shutdown` with Rust/syscall equivalents or safe no-ops.
- `crates/rustyjack-core/src/external_tools/archive_ops.rs`: replaced `tar` shell-out with `tar` + `flate2` crates.
- `crates/rustyjack-core/src/external_tools/git_ops.rs`: replaced `git` shell-out with `git2`.
- `crates/rustyjack-core/src/external_tools/physical_access.rs`: removed `avahi-browse` and `reaver` calls; mDNS/WPS steps now warn and return empty results.
- `crates/rustyjack-core/src/operations.rs`: disabled FDE and WiFi driver script execution (no Rust implementation yet).
- `crates/rustyjack-core/src/operations.rs`: disabled reverse shell spawn (external shell launch removed).
- `crates/rustyjack-netlink/src/station/external/process.rs`: removed `wpa_supplicant` spawn; station_external now reports disabled.

### Why this approach
- It **prevents accidental production builds** from including runtime shell-outs without relying on git state or human memory.
- The guardrails are **release-only**, so developer `debug` builds remain flexible.
- The CI check ensures the guardrails **stay in place** and fail loudly if removed.
