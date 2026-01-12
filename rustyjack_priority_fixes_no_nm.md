# Rustyjack “No NetworkManager” — Priority Fixes + Verified Repo Findings (Senior Rust Dev Review)

**Scope of “important fixes right now” (per your note):**
1) **Interface selection / bring-up** (remove NetworkManager coupling; make bring-up deterministic)
2) **Isolation enforcement** (NM-free; reliable “only one interface is allowed”)
3) **USB mounting problems** (make the existing UI → daemon mount flow actually work for partitioned USB drives)
4) Keep the overall plan consistent with “NetworkManager is completely removed”.

This document is written as an implementation handoff for Rust developers.

---

## A) Repo checks you asked me to confirm

### A1) “Do we have an adequate all-Rust wpa_supplicant replacement?”
**What the repo actually contains**
- `rustyjack-netlink` ships multiple station backends:
  - `ExternalWpa` (explicitly external wpa_supplicant-based)
  - `RustOpen` (**stub / not implemented**)
  - `RustWpa2` (**implemented** and the **default feature**)  
  See: `rustyjack-netlink/src/station/backend.rs` and `rustyjack-netlink/src/supplicant.rs` (default chooses `RustWpa2`).

**What I can conclude from code inspection**
- The project **does have a Rust-native WPA2 station backend** and it is **enabled by default** in `rustyjack-netlink/Cargo.toml` (`default = ["station_rust_wpa2"]`).
- The project also **still carries an external backend and external-process code** under `rustyjack-netlink/src/station/external/*`.
- The installers still install `wpasupplicant`.

**Bottom line**
- If your requirements are “WPA2-PSK only, and we have tested the RustWpa2 backend on the target hardware + AP types”, then you *can* plan to drop `wpasupplicant`.
- If you need anything beyond what the current RustWpa2 backend supports (enterprise auth, WPA3, edge-case drivers, etc.), then dropping `wpasupplicant` is risky.

✅ **Recommendation (right now):** *Do not drop `wpasupplicant` in the “important fixes” sprint.*  
Instead, make it **non-owning** (disable/mask services) and schedule the “Rust-only station” validation later.

---

### A2) “Does Rustyjack use systemd-networkd.service?”
**Direct usage:** none found in code/scripts as a required dependency.

So Rustyjack does not *depend on* `systemd-networkd`. It may coexist on some images, but it is not a required component for Rustyjack logic.

✅ **Recommendation:** disable/mask `systemd-networkd` on appliance images **to avoid competing ownership**, unless you have another component that truly depends on it.

---

### A3) “Please confirm zbus is only used by (the now removed) NM”
It is **not** only used by NetworkManager.

Repo contains `zbus` usage in:
- `rustyjack-core/src/system/nm.rs` (NetworkManager — to be deleted)
- `rustyjack-netlink/src/networkmanager.rs` (NetworkManager — to be deleted)
- **`rustyjack-netlink/src/systemd.rs`** (systemd integration — remains)

✅ **Recommendation:** you may be able to remove `zbus` from **rustyjack-core** after the NM purge, but you **cannot** drop `zbus` workspace-wide without also removing/refactoring `rustyjack-netlink` systemd integration.

---

## B) Immediate NM purge: what will break and what to remove (must-do)

### B1) Remove all NM-facing Rust codepaths
Delete these modules and remove their exports/uses:
- `rustyjack-core/src/system/nm.rs`
- `rustyjack-netlink/src/networkmanager.rs`

Remove the `NetOps::apply_nm_managed(...)` method and every call site (details in section C).

### B2) Remove NM references from systemd unit
In `rustyjackd.service`, delete the unused hardening entry:
- Remove `/etc/NetworkManager` from `ReadOnlyPaths=...`

---

## C) Priority Fix #1: Interface selection / bring-up without NetworkManager

### Problem
`select_interface_with_ops()` currently attempts `apply_nm_managed(...)` and even **bails** on the selected interface if the NM call fails. With NM removed, this becomes a guaranteed failure path.

### Fix (exactly what to change)
File: `rustyjack-core/src/system/interface_selection.rs`

1) **Remove the NM step in the “deactivate others” loop**
Delete:
- `ops.apply_nm_managed(other, false)` block

2) **Remove the NM step for the selected interface**
Delete:
- `if let Err(e) = ops.apply_nm_managed(iface, false) { bail!(...) }`

3) **Replace NM “ownership” semantics with Rustyjack-native ownership steps**
Right after “Step 3: bring up target interface”, add a *Rustyjack-owned* sequence:

For **selected iface** (both wired + wireless):
- `ops.release_dhcp(iface)` (best-effort)
- `ops.flush_addresses(iface)` (best-effort)
- `routes.delete_default_route(iface)` (best-effort)
- `ops.bring_up(iface)` + `wait_for_admin_state(..., true, ...)`

For **non-selected ifaces**:
- `ops.release_dhcp(other)` + `ops.flush_addresses(other)` + `routes.delete_default_route(other)`
- `ops.bring_down(other)`
- for wireless: `ops.set_rfkill_block(other, true)` (best-effort)

**Why this works**
- You are not asking a removed component (NM) to “let go”.
- You are directly implementing ownership by clearing addresses/routes and enforcing admin-down + rfkill where appropriate.

---

## D) Priority Fix #2: Isolation enforcement without NetworkManager

### Problem
Isolation currently contains NM “unmanaged” calls in the activation pipeline and the block flow.

### Fix (exactly what to change)
File: `rustyjack-core/src/system/isolation.rs`

1) In `activate_interface(...)`:
- Delete **STEP 2: Set NetworkManager unmanaged**
- Renumber the pipeline steps.

2) In `block_interface(...)`:
- Delete:
  - `self.ops.apply_nm_managed(iface, false).ok();`

**Replacement (Rustyjack-native)**
- Keep the real isolation mechanics:
  - delete default route(s)
  - flush addresses
  - bring link down
  - rfkill block if wireless

---

## E) Priority Fix #3: USB mounting problems (this is currently broken for partitioned drives)

### Root cause (verified)
The USB mount flow refuses to mount “whole disks with partitions”:

`rustyjack-core/src/mount.rs` contains:
- `if is_whole_disk(dev_name)? && has_partitions(dev_name)? { bail!("refusing to mount whole disk ..."); }`

At the same time:
- `enumerate_usb_block_devices()` enumerates **only `/sys/block/*`** devices and does **not** populate `BlockDevice.partitions` (it sets `partitions: Vec::new()` and never calls `enumerate_partitions()`).

Result:
- UI sees `/dev/sda` (disk), but mount refuses because `/dev/sda` has partitions (normal case).
- Partitions (`/dev/sda1`) are not being offered to UI reliably.

### Fix strategy (best for “plug and go” and minimal UI changes)
Make `mount_device()` accept a disk and automatically choose a mountable partition.

#### E1) Populate partitions during enumeration (UI quality improvement)
File: `rustyjack-core/src/mount.rs`
In `enumerate_usb_block_devices()`:
- After creating `dev`, do:
  - `dev.partitions = enumerate_partitions(&dev)?;`

This allows UI to present partitions as selectable entries.

#### E2) Change mount_device() behavior (the *actual fix*)
File: `rustyjack-core/src/mount.rs`
Replace the “refuse to mount disk with partitions” behavior:

Current:
- bail if whole disk has partitions

New:
- if whole disk has partitions:
  1) enumerate partitions
  2) select the “best” partition:
     - prefer the largest partition with a supported filesystem
     - OR prefer the first partition that passes filesystem detection
  3) mount that partition instead of the disk

Pseudo-logic:
- if `is_whole_disk(dev_name)` and `has_partitions(dev_name)`:
  - `let parts = enumerate_partitions_for_name(dev_name)?;`
  - `let chosen = choose_mountable_partition(parts, req.filesystem)?;`
  - `return mount_device(policy, MountRequest { device: chosen.devnode, ..req_adjusted })`

This immediately unblocks “user plugs USB, UI mounts it” without requiring the UI to change its device request format.

### About “plug in USB and don’t worry about mounting”
Right now, the product model appears to be:
- User action in UI triggers mount job (not udev auto-mount).

If you want true auto-mount on insertion, add later:
- a udev rule + small helper to call the daemon `MountStart` RPC.

But **the urgent brokenness** is the disk/partition mismatch, and the above changes fix it.

---

## F) Socket activation vs always-on for USB plug-and-write (security + reliability)

You asked: *Which most securely allows “plug USB and write to it” without manual mount?*

**Important repo fact:** the daemon supports systemd socket activation (checks `LISTEN_PID/LISTEN_FDS`) in `rustyjack-daemon/src/systemd.rs`.

### Best choice for your goal: **Enable the socket unit**
Why:
- The socket exists even if the daemon restarts/crashes.
- Hotplug helpers (later) can always connect to the socket; systemd will start the daemon if needed.
- It reduces “race on startup” for clients.

✅ **Recommendation (long term and also good now):**
- Do **not** mask `rustyjackd.socket`.
- Enable `rustyjackd.socket`.
- Start the daemon at boot *if you need startup enforcement*:
  - enable `rustyjackd.service` as well.
- Ensure `rustyjackd.service` has:
  - `Requires=rustyjackd.socket`
  - `After=rustyjackd.socket`
so the socket is always present before the daemon starts.

**Also fix any scripts that use the wrong path**
- The canonical socket path is: `/run/rustyjack/rustyjackd.sock` (see `rustyjack-daemon/src/config.rs` and `rustyjackd.socket` unit).
- `scripts/wifi_hotplug.sh` currently references `/run/rustyjackd.socket` which is wrong and will fail.

---

## G) DNS symlink-safe ownership (keep ProtectSystem=strict)

Keep the previously recommended approach:
- Real DNS file in Rustyjack state: `/var/lib/rustyjack/resolv.conf`
- `/etc/resolv.conf` is a symlink pointing to that file
- Daemon writes only to the Rustyjack-owned file, not `/etc`

This removes the “atomic rename replaces symlink” failure mode and keeps hardening consistent.

---

## H) Installer updates (only the parts needed for the current sprint)

### H1) `install_rustyjack_usb.sh` (must be NM-free)
- Remove `network-manager` from PACKAGES
- Delete `configure_network_manager()` and the “purge vs configure” branch
- Always run `purge_network_manager`
- Remove any writes to `/etc/NetworkManager`

### H2) Add: disable/mask competing owners (but keep wpasupplicant package for now)
- mask `wpa_supplicant.service` and any `wpa_supplicant@*.service` instances
- disable/mask `systemd-resolved`, `dhcpcd`, `resolvconf`
- disable/mask `systemd-networkd` (recommended on appliance builds)

---

## I) What your Rust developers should do in order (action list)

1) **Remove NM integration**
   - delete NM modules, delete trait method, delete call sites

2) **Fix interface selection**
   - remove NM step
   - make bring-up deterministic using netlink ops, DHCP release, addr flush, route clean

3) **Fix isolation**
   - remove NM step from activation pipeline + block flow

4) **Fix USB mounting**
   - populate partitions on enumeration (UI improvement)
   - allow mount_device() to accept disks and automatically mount a partition

5) **Fix service hardening**
   - remove `/etc/NetworkManager` from unit

6) **Socket model decision**
   - enable socket unit for reliable IPC and future hotplug auto-mount
   - start service at boot if you need startup enforcement

---

## J) Recommendations you asked me to explicitly add (1, 2, 5 + disable networkd + check supplicant)

### (1) DNS ownership: **state file + symlink**
Keep it. Best long-term with `ProtectSystem=strict`.

### (2) USB installer socket behavior: **enable socket unit**
Use socket activation as the secure + reliable IPC foundation for future “auto mount on insert”.

### (5) systemd hardening: remove dead NM paths; keep hardening minimal-but-real
Remove `/etc/NetworkManager` from hardening directives, and tighten only where it’s actually used.

### Disable systemd-networkd (recommended)
Disable/mask unless something else on your image depends on it.

### Rust-native supplicant status
RustWpa2 exists and is default; RustOpen is not implemented; external backend exists.  
Keep `wpasupplicant` installed for now unless you validate RustWpa2 for your full Wi-Fi requirements.
