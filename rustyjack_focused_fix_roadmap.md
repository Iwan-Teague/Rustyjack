# Rustyjack “Close-the-Loop” Roadmap (USB Log Export, Wi‑Fi Selection, Wired DHCP)
**Scope:** This roadmap is limited to:
1) **USB mounting + log export**
2) **Wireless interface selection via UI → Hardware Detect**
3) **Wired Ethernet DHCP + gateway detection**

**Hard constraints:** Rust-only behavior at runtime; **no third‑party binaries invoked** (no `journalctl`, `dmesg`, `mount`, `ip`, `dhclient`, etc.). Using kernel interfaces (sysfs, netlink, `/dev/rfkill`, `mount(2)` syscall) and Rust crates is allowed.

This document is intentionally prescriptive: **what the code does today**, **why it fails**, and **exactly what to change** to reach the goal state.

---

## 0) Where these features live in the repo
- **Daemon service hardening:** `rustyjackd.service`
- **USB mount implementation:** `rustyjack-core/src/mount.rs`
- **USB mount/unmount commands used by the UI:** `rustyjack-core/src/operations.rs` (`handle_system_usb_mount`, `handle_system_usb_unmount`)
- **Block-device listing used by the UI:** `rustyjack-core/src/services/mount.rs` → daemon endpoint `BlockDevicesList`
- **UI log export flow:** `rustyjack-ui/src/app.rs` (Export logs to USB UI + auto-mount helpers)
- **Log bundle collection:** `rustyjack-core/src/services/logs.rs`
- **Interface selection job (used by Hardware Detect):** `rustyjack-core/src/system/interface_selection.rs`
- **NetOps implementation:** `rustyjack-core/src/system/ops.rs`
- **DHCP client:** `rustyjack-netlink/src/dhcp.rs`
- **RFKill manager + mapping:** `rustyjack-netlink/src/rfkill.rs`

---

# 1) USB mounting + log export

## Goal state (acceptance)
From `/Settings/Logs → Export logs to USB`:
- UI lists **only real, mountable USB partitions** (no “phantom” entries).
- Selecting an entry **mounts successfully**, writes the log artifact, **syncs**, and **unmounts**.
- USB can be inserted **after boot** and will be detected on refresh (no reboot requirement).
- Security: USB is mounted with `nosuid,nodev,noexec` and only under Rustyjack’s state root.

---

## Problem A — systemd sandbox blocks `mount(2)`/`umount(2)` for the daemon
### What the code does today
The daemon runs under `rustyjackd.service`, which contains:
- an allow-list: `SystemCallFilter=@system-service`
- a deny-list that **includes `@mount`**, explicitly blocking mount syscalls.

### Why this is a problem
`rustyjack-core/src/mount.rs` uses **real Linux syscalls** (`mount(2)`, `umount2(2)`), not `/bin/mount`.
When `@mount` is denied, every mount attempt fails regardless of correctness.

### Fix steps (exact changes)
**File:** `rustyjackd.service`

1) Remove `@mount` from the deny-list line.
   - Find the line similar to:
     ```ini
     SystemCallFilter=~@keyring @ipc @module @reboot @swap @cpu-emulation @obsolete @raw-io @privileged @resources @debug @mount
     ```
   - Replace it with:
     ```ini
     SystemCallFilter=~@keyring @ipc @module @reboot @swap @cpu-emulation @obsolete @raw-io @privileged @resources @debug
     ```

2) Ensure the daemon actually has `CAP_SYS_ADMIN` available **at runtime**.
   - `CapabilityBoundingSet` already includes it; **add it to AmbientCapabilities too** so it survives `NoNewPrivileges=true` in a predictable way:
     ```ini
     AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN
     ```
     (This line currently lacks `CAP_SYS_ADMIN`.)

### What “done” looks like
- A USB mount attempt from the UI succeeds on a systemd-hardened install.
- `journalctl -u rustyjackd` contains successful mount log lines from `rustyjack-core::mount`.

---

## Problem B — the UI mount path uses the wrong mount root (`/mnt/rustyjack`) and trips hardening
### What the code does today
There are **two mount roots** in the codebase:
- The mount **service** path (`rustyjack-core/src/services/mount.rs`) builds policy under:
  - `resolve_root(None).join("mounts")` → typically `/var/lib/rustyjack/mounts`
- The **SystemCommand** path (used by UI export) uses:
  - `MountPolicy::default()` from `rustyjack-core/src/mount.rs` → **`/mnt/rustyjack`**

The UI “Export logs to USB” flow calls the SystemCommand handler in:
- `rustyjack-core/src/operations.rs` → `handle_system_usb_mount`
…and that uses the wrong default mount root.

### Why this is a problem
With `ProtectSystem=strict` + current `ReadWritePaths`, `/mnt/rustyjack` is not a valid writable mount target.
So even if syscalls are allowed, the mount will still fail due to filesystem permissions/sandboxing.

### Fix steps (exact changes)
**File:** `rustyjack-core/src/mount.rs`

1) Add a canonical policy constructor and make `Default` use the daemon state root:
   ```rust
   impl MountPolicy {
       pub fn for_root(root: &std::path::Path) -> Self {
           Self {
               mount_root: root.join("mounts"),
               allowed_fs: vec![FsType::Vfat, FsType::Exfat, FsType::Ext2, FsType::Ext3, FsType::Ext4],
               max_device_size: Some(1u64 << 40), // keep your existing cap if different
               max_files: Some(10_000),
               max_total_bytes: Some(512 * 1024 * 1024),
               allow_readonly: false,
           }
       }
   }

   impl Default for MountPolicy {
       fn default() -> Self {
           let root = crate::system::resolve_root(None);
           Self::for_root(&root)
       }
   }
   ```

**File:** `rustyjack-core/src/operations.rs`

2) In both handlers:
- `handle_system_usb_mount(root, args)`
- `handle_system_usb_unmount(root, args)`

Replace:
```rust
let policy = MountPolicy::default();
```
with:
```rust
let policy = MountPolicy::for_root(root);
```

### What “done” looks like
- All mounts land under `/var/lib/rustyjack/mounts/...`
- Nothing in the system ever mounts under `/mnt/rustyjack`.

---

## Problem C — “phantom USB devices” because USB detection is too permissive and USB ancestry check is brittle
### What the code does today
In `rustyjack-core/src/mount.rs`:
- `enumerate_usb_block_devices()` currently accepts devices when **(is_usb OR removable)**.
- “USB detection” is implemented by checking if a sysfs symlink target contains the substring `"/usb"`.

### Why this is a problem
- “Removable” can include things that are not USB storage (and on embedded systems can produce surprising results).
- Checking for a `"/usb"` substring is a heuristic; it is not a proof of USB ancestry, and it can fail or mis-detect.

### Fix steps (exact changes)
**File:** `rustyjack-core/src/mount.rs`

1) Tighten enumeration to USB-only:
   - In `enumerate_usb_block_devices()`, replace:
     ```rust
     if !is_usb && !removable {
         continue;
     }
     ```
     with:
     ```rust
     if !(is_usb && removable) {
         continue;
     }
     ```

2) Replace the heuristic USB check with a sysfs ancestry proof:
   - Delete or stop using `sysfs_path_contains_usb(...)`.
   - Add:
     ```rust
     fn sysfs_has_usb_ancestor(block_sysfs: &std::path::Path) -> bool {
         // block_sysfs is the resolved path for /sys/class/block/<name>
         // Walk upward looking for USB identity files.
         let mut cur = Some(block_sysfs);
         while let Some(p) = cur {
             if p.join("idVendor").exists() && p.join("idProduct").exists() {
                 return true;
             }
             cur = p.parent();
         }
         false
     }
     ```
   - Then implement `is_usb_block_device(sysfs_path: &Path)` as:
     1) canonicalize `/sys/class/block/<name>`
     2) call `sysfs_has_usb_ancestor(&canonical_path)`

This makes “USB” a topological fact (presence of usb device ID files), not a string guess.

### What “done” looks like
- With no USB inserted, the export UI lists **zero devices**.
- With a USB inserted, only the real partitions appear (e.g., `/dev/sda1`), not invented candidates.

---

## Problem D — UI still guesses partitions and uses incorrect sysfs paths
### What the code does today
In `rustyjack-ui/src/app.rs`, the export flow:
- invents candidate partitions (`sda1..sda9`)
- constructs sysfs paths like `/sys/block/<partition>` (which is wrong; partitions are under `/sys/class/block/`)

This is why the UI sometimes “finds” devices that do not exist or fails to mount real ones.

### Why this is a problem
The daemon already has correct block-device enumeration logic; the UI duplicating it (incorrectly) is the source of phantom UX and mount flakiness.

### Fix steps (exact changes)
**File:** `rustyjack-ipc/src/types.rs`
1) Extend `BlockDeviceInfo` to include whether the entry is a partition and, if so, its parent disk:
   ```rust
   pub struct BlockDeviceInfo {
       pub name: String,          // /dev/sda or /dev/sda1
       pub size_bytes: u64,
       pub removable: bool,
       pub transport: Option<String>,
       pub is_partition: bool,
       pub parent: Option<String>, // "/dev/sda" for "/dev/sda1"
   }
   ```

**File:** `rustyjack-core/src/services/mount.rs`
2) When emitting list entries:
   - For the disk entry: `is_partition=false`, `parent=None`
   - For each partition: `is_partition=true`, `parent=Some(dev.devnode.clone())`

**File:** `rustyjack-ui/src/app.rs`
3) Delete the UI-side sysfs scanning and partition guessing:
   - Remove `find_usb_block_devices()`, `resolve_usb_mount_for_device()`, and `try_auto_mount_usb()` (they are now the wrong abstraction).
4) In the export dialog:
   - List only entries where `transport == Some("usb")` AND `is_partition == true`
   - When the user selects one, mount exactly that devnode:
     ```rust
     let args = UsbMountArgs { device: selected.name.clone(), read_only: false };
     let mountpoint = self.core.system_command(SystemCommand::UsbMount(args))?;
     ```

### What “done” looks like
- The UI never touches `/sys/block` for USB export.
- The UI never invents `/dev/sda2` candidates.

---

## Problem E — log export is not “appliance reliable” and still uses external binaries in log collection
### What the code does today
1) **Reliability:** The UI writes a log file and may leave the device mounted; it does not guarantee `syncfs` + unmount sequencing.
2) **No-binaries constraint violation:** `rustyjack-core/src/services/logs.rs` still shells out to:
   - `journalctl` for unit logs
   - `dmesg` as a fallback for kernel logs

### Why this is a problem
- Without `syncfs` + unmount sequencing, a user can yank the stick and lose the last write.
- Invoking `journalctl`/`dmesg` violates the “Rust-only, no binaries” constraint and can fail under sandboxing anyway.

### Fix steps (exact changes)

#### E1) Move the *whole* export operation into the daemon (mount → write → sync → unmount)
**File:** `rustyjack-commands` (system command definitions)
1) Add a new system command:
   ```rust
   ExportLogsToUsb { device: String }
   ```
**File:** `rustyjack-core/src/operations.rs`
2) Implement handler:
   - Mount the requested partition RW using `MountPolicy::for_root(root)` and `mount_usb(...)`
   - Collect log bundle via `services::logs::collect_log_bundle(root)`
   - Write to a timestamped file under the mountpoint:
     - `rustyjack_logs_YYYYMMDD_HHMMSS.txt`
   - Reliability sequence:
     1) `file.sync_all()`
     2) `syncfs(open(mountpoint))`
     3) `umount(mountpoint)`
   - Return the exported filename (string) to the UI.

**File:** `rustyjack-ui/src/app.rs`
3) Replace UI-side write logic with a single daemon call:
   - UI selects the partition devnode and calls `ExportLogsToUsb { device }`
   - UI only displays success/error + exported filename.

This makes the export reliable and keeps all privileged operations in one place.

#### E2) Remove `Command::new(...)` from log bundle collection
**File:** `rustyjack-core/src/services/logs.rs`

1) Delete the journalctl blocks entirely and replace them with a Rust journal reader:
   - Add dependency **in `rustyjack-core/Cargo.toml`**:
     - `systemd = "0.10"` (or the project’s pinned compatible version)
   - Implement:
     ```rust
     fn append_journald_unit_tail(out: &mut String, unit: &str, max_entries: usize) { ... }
     ```
     Behavior:
     - open the journal
     - match `_SYSTEMD_UNIT=<unit>`
     - seek to tail
     - iterate backwards up to `max_entries`
     - append timestamp + MESSAGE

2) Fix kernel log tail without `dmesg`:
   - Open `/dev/kmsg` with **O_NONBLOCK** and read up to N lines, then stop on `EAGAIN`.
   - Remove the `dmesg` fallback entirely.

This keeps logging 100% Rust + kernel interfaces.

### What “done” looks like
- Export logs produces a file on USB every time, even if the stick is removed immediately after the UI shows success.
- `collect_log_bundle()` contains no `std::process::Command` usage.

---

# 2) Wired Ethernet DHCP + gateway detection

## Goal state (acceptance)
When selecting an Ethernet interface (e.g., `eth0`) in Hardware Detect:
- DHCP is attempted even when carrier is **unknown**.
- If a DHCP server exists: lease acquired within **≤ 30 seconds**.
- Default route is set when a gateway is provided.
- DNS is written to Rustyjack resolv.conf.

---

## Problem A — carrier `None` is treated as `false`, so DHCP is skipped
### What the code does today
In `rustyjack-core/src/system/interface_selection.rs`:
```rust
let carrier = ops.has_carrier(iface)?.unwrap_or(false);
if carrier {
    // do DHCP
} else {
    // skip
}
```

### Why this is a problem
Some drivers (and some embedded configurations) do not expose a readable carrier file; `None` is “unknown”, not “down”.
Skipping DHCP on unknown carrier breaks wired bring-up on real hardware.

### Fix steps (exact changes)
**File:** `rustyjack-core/src/system/interface_selection.rs`

Replace the carrier gating logic with:
```rust
let carrier_opt = ops.has_carrier(iface)?;
outcome.carrier = carrier_opt;

match carrier_opt {
    Some(false) => {
        progress_emit(..., "Ethernet link down; skipping DHCP");
        // leave interface up but without IP
    }
    Some(true) | None => {
        progress_emit(..., "Attempting DHCP (carrier up or unknown)");
        // run DHCP flow
    }
}
```

### What “done” looks like
- On a driver that returns carrier `None`, DHCP still runs and obtains an IP when available.

---

## Problem B — DHCP timeout requested by interface selection is not honored
### What the code does today
In `rustyjack-core/src/system/ops.rs`:
```rust
fn acquire_dhcp(&self, iface: &str, _timeout: Duration) -> Result<(Option<OpsDhcpLease>, Option<DhcpAcquireReport>)> {
    // timeout ignored
}
```

### Why this is a problem
The UI and job framework expect a deterministic bound (≤ 30s). Ignoring it causes:
- UI “stuck” behavior
- non-deterministic failures due to long raw/udp retries in the DHCP client

### Fix steps (exact changes)
**Files:** `rustyjack-core/src/system/ops.rs`, `rustyjack-netlink/src/dhcp.rs`

1) Thread the timeout into the DHCP client as a **hard deadline**:
   - In `rustyjack-netlink/src/dhcp.rs`, add:
     ```rust
     impl DhcpClient {
         pub async fn acquire_report_timeout(
             &self,
             interface: &str,
             hostname: Option<&str>,
             timeout: std::time::Duration,
         ) -> Result<DhcpAcquireReport> {
             let deadline = std::time::Instant::now() + timeout;
             self.acquire_report_with_deadline(interface, hostname, deadline).await
         }
     }
     ```
   - Implement `acquire_report_with_deadline(...)` by:
     - checking `Instant::now() >= deadline` at the start of each retry loop
     - computing per-recv timeouts as `min(5s, deadline-now)`
     - returning `DhcpClientError::Timeout` when the deadline expires

2) In `rustyjack-core/src/system/ops.rs` `RealNetOps::acquire_dhcp`, call:
   ```rust
   let report = client.acquire_report_timeout(interface, hostname, timeout).await;
   ```
   and return the report/lease.

This makes the timeout real and prevents runaway DHCP attempts.

### What “done” looks like
- Selecting ethernet never blocks longer than the UI/job timeout.
- The job result contains a lease and gateway when DHCP is available.

---

# 3) Wi‑Fi interface selection via Hardware Detect (rfkill + bring-up)

## Goal state (acceptance)
When the user selects a Wi‑Fi interface (e.g., `wlan0`) in Hardware Detect:
- rfkill soft-block ends up **soft=0 within ≤ 5 seconds**
- Interface is **admin-UP**
- All other interfaces are down and address-flushed (isolation)
- The selection step does **not** require network-manager binaries

---

## Problem A — rfkill ↔ interface mapping is currently unreliable
### What the code does today
In `rustyjack-netlink/src/rfkill.rs`, `find_index_by_interface()` tries:
- substring match of interface name inside `/sys/class/rfkill/rfkillN/device/uevent`
- or `rfkillN/name == interface`

### Why this is a problem
On real devices, `uevent` contents and rfkill “name” are not guaranteed to match the netdev name.
When the mapping fails, Rustyjack unblocks nothing and the interface remains soft-blocked.

### Fix steps (exact changes)
**File:** `rustyjack-netlink/src/rfkill.rs`

Replace `find_index_by_interface()` with a sysfs topology match:

1) Resolve the physical device for the interface:
   - `iface_dev = canonicalize("/sys/class/net/<iface>/device")` (if it exists)
2) For each `rfkillN`:
   - `rf_dev = canonicalize("/sys/class/rfkill/rfkillN/device")`
3) Match if:
   - `iface_dev.starts_with(&rf_dev)` OR `rf_dev.starts_with(&iface_dev)`
4) Return that `N` as the rfkill index.

This binds rfkill devices to netdevs by real device topology, not by strings.

### What “done” looks like
- On Pi Zero 2 W, selecting `wlan0` finds the correct rfkill index consistently.

---

## Problem B — wireless selection can fail even after successful bring-up
### What the code does today
In `rustyjack-core/src/system/interface_selection.rs`, after bringing up the selected interface:
- For wireless interfaces, it currently **bails** if an IPv4 address is present.

### Why this is a problem
Even without NetworkManager, some environments can auto-assign or preserve addresses (or a prior run might have left one behind).
Selection should force the system into the desired state, not fail because the state was “dirty”.

### Fix steps (exact changes)
**File:** `rustyjack-core/src/system/interface_selection.rs`

Replace the “wireless must have no IP or fail” check with a “force clean state” step:
1) After `ops.bring_up(selected)` and rfkill unblock:
   - Call `ops.flush_addresses(selected)` unconditionally.
   - Call `route_mgr.delete_default_route(selected)` unconditionally.
2) Verification becomes:
   - interface is admin-UP
   - rfkill soft=0 (or no rfkill device exists)
   - no IPv4 address is present **after we flushed it**

The key change: selection becomes deterministic even if the starting state is messy.

### What “done” looks like
- Selecting Wi‑Fi always finishes with `wlan0` UP + unblocked + no IP, ready for later operations (scan/connect).

---

# 4) Minimal test plan (what to run to prove “done”)
## USB
1) Boot with no USB inserted → Export dialog shows **no devices**.
2) Insert USB after boot → refresh → device appears (partition only).
3) Export logs → success:
   - file exists on USB and is non-empty
   - removing USB immediately after success does not corrupt the file
4) After export, USB is **not** mounted (verify `/proc/mounts`).

## Ethernet
1) Select `eth0` with link connected to DHCP network:
   - within 30s: IP set, default route set, gateway visible in job report
2) Select `eth0` with carrier file missing/unknown:
   - DHCP still attempted; succeeds when server exists.

## Wi‑Fi
1) Ensure rfkill soft-block is set (`/sys/class/rfkill/.../soft == 1`), then select `wlan0`:
   - within 5s, soft becomes `0`
   - `wlan0` is admin-UP
   - other interfaces are DOWN and address-flushed

---

## Notes on scope discipline
This roadmap deliberately ignores any other external binaries used elsewhere in the project. It only bans binaries in the three targeted feature areas above (USB export/logging, wireless selection, wired DHCP/gateway).
