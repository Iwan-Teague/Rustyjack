# RustyJack Network Interface Selection Deep Dive (Pi Zero 2 W)
Date: 2026-02-10


**Goal:** fix the “Hardware / Network Interface Select” feature so a user can reliably switch between `eth0` and `wlan0` on a Raspberry Pi Zero 2 W **without ever getting stranded** in an “all interfaces DOWN” state, while keeping the **only 1 active interface** isolation invariant.

**Repo snapshot analyzed:** `watchdog_shallow_20260210-093806.zip` (extracted as `watchdog/`), Feb 10, 2026.

---

## What you’re seeing

On a Pi Zero 2 W connected via **ethernet**:

1. Install the latest prebuilt binaries via `install_rustyjack_prebuilt.sh`.
2. Pi reboots; SSH over ethernet still works ✅
3. User opens the UI and tries to select a different network interface (usually `wlan0`).
4. The operation fails, and afterward **everything shows DOWN**. Further attempts to activate any interface fail.

That exact failure pattern is explained by **three interacting classes of bugs**:

- **Wrong data in UI** (it doesn’t list ethernet at all).
- **Unsafe switching algorithm** (non-transactional, no rollback).
- **Background enforcement races** (watcher can fight with the job, and can error in “Connectivity” mode).

---

## Fast diagnosis in one paragraph

The UI calls the daemon endpoint `WifiInterfacesList`, which returns only interfaces that have `/sys/class/net/<iface>/wireless`. That hides `eth0`, so the user can’t pick the currently-working uplink from the UI. When they try selecting `wlan0`, the core switching routine disables *other* interfaces first (including `eth0`), and then attempts Wi‑Fi activation steps that can legitimately fail (rfkill mapping/unblock, timeouts, etc.). Because there is no rollback, the device can end up with **no administratively-UP interface**, i.e. no uplink you can use. Making this worse: the daemon’s netlink watcher can concurrently enforce isolation and requires a default route in “Connectivity” mode—an assumption that often breaks during transitions—so it can further wedge the system.

---

## Architecture: how it works today

### UI (TUI)
- `crates/rustyjack-ui/src/app/iface_select.rs`
  - `select_active_interface()` lists interfaces and starts the job
  - `run_interface_selection_job()` polls job progress and displays it

### Daemon
- `crates/rustyjack-daemon/src/jobs/kinds/interface_select.rs`
  - calls into core in `spawn_blocking`
- `crates/rustyjack-daemon/src/netlink_watcher.rs`
  - watches link events and periodically enforces isolation
  - correctly uses the daemon **Uplink lock** (`state.locks.acquire_uplink().await`) for enforcement

### Core
- Interface selection algorithm:
  - `crates/rustyjack-core/src/system/interface_selection.rs`
- Background isolation engine:
  - `crates/rustyjack-core/src/system/isolation.rs`
- Preferences:
  - `crates/rustyjack-core/src/system/mod.rs` (PreferenceManager; used by selection + isolation)

### Netlink/rfkill implementation (Rust-only)
- `crates/rustyjack-netlink/src/rfkill.rs` uses `/dev/rfkill`
- rfkill mapping uses sysfs canonical symlink comparisons:
  - `/sys/class/net/<iface>/device` vs `/sys/class/rfkill/rfkill*/device`

---

## The invariant we must preserve

**Final-state invariant:**
- Exactly one “uplink” interface is **administratively UP** (IFF_UP).
- All other uplink-capable interfaces are **administratively DOWN** and (if wireless) rfkill soft-blocked best-effort.

**Transition invariant (recommended):**
- During switching, it’s acceptable to briefly have both interfaces UP **if and only if**:
  - the UI shows “processing…”, and
  - the system guarantees that one of them will be brought down before completion, and
  - on failure, the system returns to the previous working interface.

This keeps isolation true as a **postcondition**, while making the system survivable.

---

# Issues and fixes

Each issue is structured as: **Where → What → Why → Fix → Fixed version**.

---

## Issue 1 — UI lists only Wi‑Fi interfaces (ethernet not selectable)

### Where
- UI selection uses Wi‑Fi list:
  - `crates/rustyjack-ui/src/app/iface_select.rs::select_active_interface()`
  - `crates/rustyjack-ui/src/app/iface_select.rs::view_interface_status()`
- UI core only exposes:
  - `crates/rustyjack-ui/src/core.rs::wifi_interfaces()`
- Daemon endpoint:
  - `RequestBody::WifiInterfacesList` in `crates/rustyjack-daemon/src/dispatch.rs`
- Wi‑Fi-only filter:
  - `crates/rustyjack-core/src/services/wifi.rs::list_interfaces()`

### What is the problem
The UI only sees interfaces that pass `wifi::list_interfaces()`:

```rust
// rustyjack-core/src/services/wifi.rs
let path = Path::new("/sys/class/net").join(&name).join("wireless");
if path.exists() { interfaces.push(name); }
```

So `eth0` is invisible in the selection UI.

### Why it’s a problem
- You can’t select the currently-working uplink from the UI.
- After a failed Wi‑Fi switch, the UI offers no recovery path.
- The “Interface Status” screen is misleading (it prints Wi‑Fi names only).

### How to fix
Add a **real uplink interface listing** endpoint returning **truthful data** in one call.

You already have `InterfaceStatusResponse` (exists / is_wireless / oper_state / is_up / carrier / ip / capabilities), and you already implemented `InterfaceStatusGet` in the daemon. So the missing piece is simply: **list all relevant interfaces**.

Recommended behavior:
- enumerate `/sys/class/net/*` excluding `lo`
- compute status (same as `InterfaceStatusGet`)
- filter to **physical** devices:
  - `capabilities.is_physical == true` (when available)
- optionally filter out obvious non-uplinks (bridges, veth) if you want

### Fixed version: concrete patch (server + client + UI)

#### 1) IPC types (`crates/rustyjack-ipc/src/types.rs`)
Add:

```rust
pub enum Endpoint {
    // ...
    InterfacesListGet,
    // ...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfacesListResponse {
    pub interfaces: Vec<InterfaceStatusResponse>,
}
```

Add request/response bodies:

```rust
pub enum RequestBody {
    // ...
    InterfacesListGet,
}

pub enum ResponseOk {
    // ...
    InterfacesList(InterfacesListResponse),
}
```

#### 2) Daemon dispatch (`crates/rustyjack-daemon/src/dispatch.rs`)
Add a match arm (patterned after `WifiInterfacesList` and `InterfaceStatusGet`):

```rust
RequestBody::InterfacesListGet => {
    let result = run_blocking("interfaces_list_get", move || {
        use rustyjack_core::system::ops::{NetOps, RealNetOps};
        use std::fs;
        use std::path::Path;

        let ops = RealNetOps;
        let mut out = Vec::new();

        for entry in fs::read_dir("/sys/class/net")? {
            let entry = entry?;
            let iface = entry.file_name().to_string_lossy().to_string();
            if iface == "lo" { continue; }

            let sys_path = Path::new("/sys/class/net").join(&iface);
            let oper_state = fs::read_to_string(sys_path.join("operstate"))
                .unwrap_or_else(|_| "unknown".to_string())
                .trim().to_string();

            let is_up = if let Ok(flags_hex) = fs::read_to_string(sys_path.join("flags")) {
                u32::from_str_radix(flags_hex.trim().trim_start_matches("0x"), 16)
                    .map(|flags| (flags & 0x1) != 0)
                    .unwrap_or(oper_state == "up")
            } else {
                oper_state == "up"
            };

            let carrier = fs::read_to_string(sys_path.join("carrier"))
                .ok()
                .and_then(|val| match val.trim() { "0" => Some(false), "1" => Some(true), _ => None });

            let is_wireless = sys_path.join("wireless").exists();
            let ip = ops.get_ipv4_address(&iface).ok().flatten().map(|a| a.to_string());

            let capabilities = ops.get_interface_capabilities(&iface).ok().map(|caps| {
                // convert to rustyjack_ipc::InterfaceCapabilities ...
                // (copy the conversion from InterfaceStatusGet)
                todo!()
            });

            // Filter to physical devices when known
            if let Some(ref caps) = capabilities {
                if !caps.is_physical { continue; }
            }

            out.push(rustyjack_ipc::InterfaceStatusResponse {
                interface: iface,
                exists: true,
                is_wireless,
                oper_state,
                is_up,
                carrier,
                ip,
                capabilities,
            });
        }

        Ok::<_, rustyjack_core::services::error::ServiceError>(out)
    }).await;

    match result {
        Ok(interfaces) => ResponseBody::Ok(ResponseOk::InterfacesList(
            rustyjack_ipc::InterfacesListResponse { interfaces }
        )),
        Err(err) => ResponseBody::Err(err),
    }
}
```

(Replace `todo!()` by literally copying the conversion code already used in `InterfaceStatusGet`.)

#### 3) Client (`crates/rustyjack-client/src/client.rs`)
Add:

```rust
pub async fn interfaces_list(&mut self) -> Result<rustyjack_ipc::InterfacesListResponse> {
    match self.request(RequestBody::InterfacesListGet).await? {
        ResponseBody::Ok(ResponseOk::InterfacesList(resp)) => Ok(resp),
        ResponseBody::Err(err) => Err(daemon_error(err)),
        _ => Err(anyhow!("unexpected response body")),
    }
}
```

#### 4) UI core wrapper (`crates/rustyjack-ui/src/core.rs`)
Add:

```rust
pub fn interfaces_list(&self) -> Result<Value> {
    self.with_client(|client| async move {
        let resp = client.interfaces_list().await?;
        Ok(serde_json::to_value(resp)?)
    })
}
```

#### 5) UI screen (`crates/rustyjack-ui/src/app/iface_select.rs`)
- Replace `self.core.wifi_interfaces()` with `self.core.interfaces_list()`.
- Render labels with truthful status:

```rust
let resp: InterfacesListResponse = serde_json::from_value(data)?;
let mut options = Vec::new();
for i in &resp.interfaces {
    let up = if i.is_up { "UP" } else { "DOWN" };
    let car = match i.carrier { Some(true)=>"carrier✓", Some(false)=>"carrier×", None=>"" };
    let ip = i.ip.as_deref().unwrap_or("-");
    options.push(format!("{:<6} {:<4} {:<9} ip {}", i.interface, up, car, ip));
}
```

Now the UI can always offer `eth0` as a safe recovery target.

---

## Issue 2 — Switching is non‑transactional; failures strand all interfaces DOWN

### Where
- `crates/rustyjack-core/src/system/interface_selection.rs::select_interface_with_ops()`

### What is the problem
The algorithm disables other interfaces first:

- Step 2:
  - DHCP release
  - flush addresses
  - delete default route
  - bring DOWN
  - rfkill block (wireless)
- Step 3:
  - rfkill unblock selected (wireless)
  - bring selected UP

If Step 3 fails for any reason, you are stranded. There is no rollback.

### Why it’s a problem
On embedded devices, Wi‑Fi activation can fail for reasons that are *not* “system is broken”:
- rfkill mapping unavailable
- `/dev/rfkill` permissions/sandboxing issues
- driver quirks / delayed state transitions

The current ordering guarantees that a late failure can destroy the prior working state.

### How to fix (transactional switching + rollback)
Implement **two-phase switching**:

**Phase A: preflight & prepare target**
1. Determine previous active interface:
   - PreferenceManager “preferred interface”, else default route iface, else “first physical interface that’s UP”.
2. Validate target:
   - exists?
   - physical?
3. If target is wireless:
   - if hard blocked ⇒ fail (nothing you can do in software)
   - if soft blocked ⇒ attempt unblock (best-effort; Issue 2a)
4. Bring target admin-UP and confirm admin-UP.

**Phase B: commit isolation**
5. Bring down all non-target uplinks (and rfkill block wireless).
6. Apply wired DHCP/default route if appropriate.
7. Verify invariant “only target admin-UP” (and optionally “target has expected default route” for explicit connectivity workflows).
8. Persist preference.
9. Return result including truthful status and warnings.

**Rollback rule:**
- If anything fails **before step 5**, do *nothing* to other interfaces.
- If anything fails **after step 5**, restore previous interface admin-UP (and DHCP) so SSH recovery remains possible.

### Fixed version: concrete code skeleton

Create a new function (or refactor existing one) that makes the ordering explicit:

```rust
pub fn select_interface_with_ops_transactional<F>(
    ops: Arc<dyn NetOps>,
    root: PathBuf,
    target: &str,
    progress: Option<&mut F>,
    cancel: Option<&CancelFlag>,
) -> Result<InterfaceSelectionOutcome>
where
    F: FnMut(&str, u8, &str),
{
    // Identify previous active interface early
    let prev = determine_prev_active(&ops, &root).ok();

    // ----- Phase A: preflight and bring target up -----
    preflight_target(&ops, target)?;

    if ops.is_wireless(target) {
        // fail only on hard-block; otherwise best-effort unblock
        ensure_rfkill_soft_unblocked_best_effort(&ops, target, &mut outcome)?;
    }

    ops.bring_up(target)?;
    wait_for_admin_state(target, true, Duration::from_secs(5), cancel)?;

    // ----- Phase B: commit isolation -----
    // (only now do we touch other interfaces)
    for iface in list_uplink_interfaces(&ops)? {
        if iface == target { continue; }
        deactivate_interface_best_effort(&ops, &iface, &mut outcome)?;
    }

    // Wired DHCP (only if target is wired + carrier true)
    if !ops.is_wireless(target) {
        maybe_run_dhcp_and_route(&ops, target, &mut outcome)?;
    }

    verify_single_admin_up(&ops, target)?;
    persist_preference(&root, target)?;

    Ok(outcome)
}
```

You already have many helper pieces in `interface_selection.rs`:
- `wait_for_admin_state`
- `wait_for_rfkill`
- `read_rfkill_state`
- `read_interface_admin_state`
- `read_carrier_state`
- DHCP helpers

The key change is **ordering** and **rollback**.

---

## Issue 2a — rfkill unblock is fatal for the selected interface, but non-fatal elsewhere

### Where
- `crates/rustyjack-core/src/system/interface_selection.rs`
  - Step 2 blocks other wireless interfaces with warning on error
  - Step 3 unblocks selected wireless interface and `bail!()` on error

### What is the problem
rfkill failures are treated inconsistently, and the “fatal” choice is the one that strands devices most often.

### Why it’s a problem
If rfkill mapping is not available for `wlan0`, selection fails after you already took down `eth0` (Issue 2).

### How to fix
Make selected rfkill unblock:
- **fatal only for hard-blocked**
- otherwise **best-effort** with warnings surfaced to UI

### Fixed version snippet

```rust
if is_wireless {
    let rf = read_rfkill_state(iface).ok(); // Option<RfkillState>
    if matches!(rf, Some(RfkillState { hard: true, .. })) {
        bail!("{} is hard-blocked (physical switch)", iface);
    }

    if let Err(e) = ops.set_rfkill_block(iface, false) {
        outcome.notes.push(format!(
            "Warning: could not clear rfkill for {} (continuing): {}",
            iface, e
        ));
    } else {
        // only wait if we actually issued unblock
        wait_for_rfkill(iface, Duration::from_secs(5), cancel)?;
    }
}
```

---

## Issue 3 — Interface select job doesn’t take the daemon Uplink lock (race with netlink watcher)

### Where
- Job: `crates/rustyjack-daemon/src/jobs/kinds/interface_select.rs`
- Lock infra: `crates/rustyjack-daemon/src/locks.rs`
- Watcher uses lock: `crates/rustyjack-daemon/src/netlink_watcher.rs`

### What is the problem
The watcher enforces isolation (and can flip interfaces) while selection is running, because the job does not acquire `Uplink`.

### Why it’s a problem
- Intermittent failures and “always fails” depending on timing
- Selection can be undone mid-run by enforcement
- Two independent code paths mutate the same kernel state

### How to fix
Acquire `state.locks.acquire_uplink().await` for the duration of the job.

### Fixed version (minimal patch)

```rust
pub async fn run(...) -> Result<serde_json::Value, DaemonError> {
    let _lock = state.locks.acquire_uplink().await;

    // existing logic...
}
```

---

## Issue 4 — Watcher enforcement uses Connectivity mode; missing default route becomes an error and can wedge isolation

### Where
- `crates/rustyjack-daemon/src/netlink_watcher.rs`
- `crates/rustyjack-core/src/system/isolation.rs::verify_enforcement()`

### What is the problem
Connectivity mode treats “no default route” as failure when a preferred interface exists.

During boot or switching, “no default route” is normal. If enforcement fails after it has already blocked interfaces, you can be stranded.

### Why it’s a problem
- Race with DHCP
- Carrier-down scenarios are common on embedded devices
- Switching itself temporarily deletes routes

### How to fix
Use **Passive enforcement** in the watcher. Reserve Connectivity enforcement for explicit “bring online” workflows.

### Fixed version (daemon side)
In `netlink_watcher.rs`, replace strict enforcement call with a passive one (you may implement a new helper):

```rust
rustyjack_core::system::apply_interface_isolation_with_ops_passive(&ops)?;
```

### Fixed version (core helper)
Add in `rustyjack-core/src/system/mod.rs` (or `isolation.rs` helpers):

```rust
pub fn apply_interface_isolation_with_ops_passive(ops: &Arc<dyn NetOps>) -> Result<()> {
    let mut engine = IsolationEngine::new(ops.clone(), PreferenceManager::new("/".into()), None);
    let _outcome = engine.enforce_passive()?;
    Ok(())
}
```

(Use the same PreferenceManager root path you currently use for strict enforcement.)

---

## Issue 5 — UI doesn’t present a true state machine; no “processing” semantics + weak post-verification

### Where
- `crates/rustyjack-ui/src/app/iface_select.rs`
  - progress exists, but the overall UX still reads like “toggle a setting”
  - success screen does not explicitly confirm the interface is really UP after isolation completes

### What is the problem
Users need to understand **time** and **state**:
- switching takes time
- isolation and activation happen in stages
- failure should show what got rolled back (or what to do next)

### Why it’s a problem
Without explicit state semantics, users interpret any “success” message as “connectivity is live”, even though admin-UP ≠ working link (carrier/association/IP may not exist yet).

### How to fix
1. Use job progress messages as “state machine steps”:
   - “Phase A: bringing target UP…”
   - “Phase B: isolating others…”
   - “Phase C: DHCP…”
   - “Verifying…”
2. After job completion, call `InterfaceStatusGet` for:
   - selected interface
   - (optionally) previous interface
3. Only show “Interface Set” after:
   - job completed successfully, and
   - `InterfaceStatusGet(selected).is_up == true`
4. Update action wording:
   - Menu item: “Switch active interface”
   - While running: show “Processing…” and hide/disable selection controls

### Fixed version: UI post-verify snippet

```rust
let status_v = self.core.interface_status(&result.interface)?;
let st: InterfaceStatusResponse = serde_json::from_value(status_v)?;
if !st.is_up {
    self.show_message("Interface Set (warning)", [
        "Switch completed, but interface is not admin-UP.",
        "Check cables / rfkill / Wi-Fi association."
    ])?;
}
```

---

# Implementation order (strongly recommended)

### Phase 1 — Make the system recoverable
1. Implement `InterfacesListGet` and update UI to list ethernet too (Issue 1).
2. Acquire daemon Uplink lock for interface selection jobs (Issue 3).
3. Make watcher use passive enforcement (Issue 4).

After Phase 1, a failed Wi‑Fi selection should not permanently strand the device, because the user can always reselect `eth0` from the UI and enforcement won’t wedge on “no default route”.

### Phase 2 — Make switching safe
4. Transactional switching with rollback (Issue 2).
5. Best-effort rfkill unblock + warnings (Issue 2a).

### Phase 3 — Make UI maximally truthful
6. Rich interface display (carrier/IP/operstate).
7. Explicit “processing” / “done” semantics and post-verification (Issue 5).

---

# Testing plan (Pi Zero 2 W)

### Smoke tests
1. Boot with ethernet connected; verify interface list shows `eth0` + `wlan0`.
2. Switch to `eth0`:
   - expect `eth0` admin-UP
   - `wlan0` admin-DOWN (rfkill block best-effort)
3. Switch to `wlan0` (no association required to “admin-UP”):
   - expect `wlan0` admin-UP
   - `eth0` admin-DOWN
4. Unplug ethernet cable; switch to `eth0`:
   - expect admin-UP but carrier false; DHCP skipped; UI truthfully reports it

### Race tests
- Rapid switching back and forth while plugging/unplugging ethernet.
- Confirm watcher never fights the job (lock should prevent).

### Failure injection
- Make `/dev/rfkill` inaccessible and ensure:
  - selection does not strand ethernet down
  - UI shows warning note
- DHCP failure (network with no DHCP) should not prevent admin-UP + isolation.

---

# Why “UP” and “operstate” are different (UI must show both)

Linux distinguishes:
- **Administrative state** (IFF_UP): what you set with `ip link set dev X up/down`
- **Operational state** (`operstate`): whether the interface is actually usable

Kernel docs explicitly describe this distinction, and it’s why the daemon reports `is_up` from flags instead of relying on operstate alone.

---

# Appendix: key code references in this repo

- UI interface selection: `crates/rustyjack-ui/src/app/iface_select.rs`
- Wi‑Fi-only interface listing: `crates/rustyjack-core/src/services/wifi.rs::list_interfaces()`
- Selection algorithm: `crates/rustyjack-core/src/system/interface_selection.rs`
- Watcher: `crates/rustyjack-daemon/src/netlink_watcher.rs`
- Enforcement engine: `crates/rustyjack-core/src/system/isolation.rs`
- InterfaceStatusGet handler: `crates/rustyjack-daemon/src/dispatch.rs`

---

# External references

- Linux kernel docs on administrative vs operational state (`operstate`):  
  https://www.kernel.org/doc/html/latest/networking/operstates.html
- `ip-link(8)` (admin up/down semantics):  
  https://www.man7.org/linux/man-pages/man8/ip-link.8.html
- Linux kernel rfkill docs (`/dev/rfkill` interface):  
  https://www.kernel.org/doc/html/latest/driver-api/rfkill.html
- Red Hat docs describing rfkill userspace (`/dev/rfkill` + sysfs):  
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/power_management_guide/rfkill
- systemd rfkill state restore:  
  https://www.man7.org/linux/man-pages/man8/systemd-rfkill.8.html
