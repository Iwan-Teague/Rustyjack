# Rustyjack PI0W2 – UI/Daemon/USB/Wi‑Fi Fixpack  
## Strict Isolation • Rust‑only • No third‑party binaries

**Target:** Raspberry Pi Zero W 2 • Raspberry Pi OS / Raspbian 32‑bit CLI

---

## Non‑negotiables (hard rules)

- **Rust-only runtime behavior.** Do not add new dependencies on external tools/binaries (`ip`, `iw`, `mount`, `bash`, etc.).
- **No security regressions.**
- **Strict interface isolation is mandatory:**
  - Only the **selected** interface may be operational (**admin‑UP**).
  - Every other interface must be **admin‑DOWN**, including Ethernet.
  - Isolation must be enforced **continuously**.
  - Only explicit exceptions may allow **two interfaces** temporarily (e.g., hotspot AP + upstream).
  - Disrupting SSH by bringing down unselected Ethernet is **intended** behavior.

---

## What this fixpack resolves

### User-visible failures
1) **Export logs to USB** → `internal error`  
2) **Select target network** → `missing field 'count'`  
3) **Select target network** → `interface wlan0 is down`  
4) **Import from USB** → `USB device detected but not mounted`  
5) **Hardware Detect** shows selected interface still `down` after selection

---

## At-a-glance: Symptoms → Root causes → Fixes

| Symptom | Confirmed root cause (in code) | Fix section |
|---|---|---|
| `missing field 'count'` | UI expects `count`; daemon scan response omits it | Fix 1 |
| “interface is down” after selection | UI scan checks **admin state**; daemon may fail-closed or block interface if selection is absent/invalid; auto-selection depends on `operstate == "up"` | Fix 3 |
| Hardware Detect shows “down” | Hardware Detect list uses **operstate**, not **admin‑UP** | Fix 2 |
| “USB detected but not mounted” | USB gating requires sysfs `removable==1` in **two places**; many USB drives report removable=0 | Fix 4 |
| “Export logs: internal error” | Daemon wraps core errors as `ErrorCode::Internal`; UI hides mount errors | Fix 4 + Fix 5 |

---

## Table of contents

- [Ground truth from the repo](#ground-truth-from-the-repo)
- [Fix 1 — Wi‑Fi scan JSON schema: add `count`](#fix-1--wi-fi-scan-json-schema-add-count)
- [Fix 2 — Hardware Detect: show admin‑UP vs operstate](#fix-2--hardware-detect-show-admin-up-vs-operstate)
- [Fix 3 — Isolation selection: stop depending on operstate](#fix-3--isolation-selection-stop-depending-on-operstate)
- [Fix 4 — USB mount policy + UI mount errors](#fix-4--usb-mount-policy--ui-mount-errors)
- [Fix 5 — Daemon error mapping: stop “internal error” masking](#fix-5--daemon-error-mapping-stop-internal-error-masking)
- [Fix 6 — Isolation hardening: never ignore bring_down failures](#fix-6--isolation-hardening-never-ignore-bring_down-failures)
- [Patch order and verification](#patch-order-and-verification)

---

## Ground truth from the repo

### 1) Isolation is always-on (daemon-enforced)
**File:** `rustyjack-daemon/src/netlink_watcher.rs`

- Isolation enforcement is triggered:
  - **after netlink events** (debounced)
  - **periodically (every 3 seconds)**

Both paths construct `IsolationEngine` and call `engine.enforce()`.

**Implication:** even if something brings up a disallowed interface briefly, it will be forced DOWN shortly after.

---

### 2) “DOWN” has two meanings in this system

#### A) Admin state (IFF_UP)
- Read from: `/sys/class/net/<iface>/flags`
- Used by:
  - daemon API `InterfaceStatusGet`
  - UI preflight for scan/connect

**Daemon:** `rustyjack-daemon/src/dispatch.rs` checks IFF_UP via `(flags & 0x1) != 0`.

#### B) Operstate
- Read from: `/sys/class/net/<iface>/operstate`
- Used by:
  - interface summary listing in hardware detect

**Core:** `rustyjack-core/src/system/mod.rs` `list_interface_summaries()` reads operstate.

**Implication:** Wi‑Fi can be **admin‑UP** but still have `operstate=down` until it associates.

---

### 3) Wi‑Fi scan is a strict producer/consumer schema mismatch
- UI expects `WifiScanResponse { networks, count }`
- Daemon scan response omits `count`

---

### 4) USB mount rejection is deterministic on many real drives
**File:** `rustyjack-core/src/mount.rs`

Two hard gates require `removable==1`:
- enumeration gate: `enumerate_usb_block_devices()`
- mount gate: `ensure_usb_removable()`

Many valid USB devices report `removable=0` → mount fails.

---

### 5) Mount errors are hidden twice
- UI swallows mount errors: `rustyjack-ui/src/app.rs` `mount_usb_device()` logs but returns `Ok(None)`
- Daemon wraps core errors as `Internal`: `rustyjack-daemon/src/dispatch.rs` `dispatch_core_command()`

---

# Fix 1 — Wi‑Fi scan JSON schema: add `count`

## Problem
UI fails decoding scan response with: `missing field 'count'`.

## Root cause (confirmed)
- UI struct requires `count`
- core service response omits `count`
- daemon job uses the service output directly

## How to fix (patch guide)

### Patch 1A (required): add `count` in the producer
**File:** `rustyjack-core/src/services/wifi.rs`  
**Function:** `scan(...)`

Replace the return JSON with:

```rust
let count = networks.len();

Ok(serde_json::json!({
    "interface": req.interface,
    "count": count,
    "networks": networks
}))
```

### Patch 1B (strongly recommended): make the UI resilient to future drift
**File:** `rustyjack-ui/src/types.rs`

```rust
#[derive(Debug, Deserialize)]
pub struct WifiScanResponse {
    pub networks: Vec<WifiNetworkEntry>,
    #[serde(default)]
    pub count: usize,
}
```

Normalize right after parsing:

```rust
if resp.count == 0 && !resp.networks.is_empty() {
    resp.count = resp.networks.len();
}
```

## Done looks like
- “Select target network” never errors on missing `count`.
- Scan list renders consistently.

---

# Fix 2 — Hardware Detect: show admin‑UP vs operstate

## Problem
Hardware Detect shows the selected interface as “down” after selection.

## Root cause (confirmed)
Interface summaries use **operstate** only. Wi‑Fi operstate can be `down` even while admin‑UP.

## How to fix (patch guide)

### Patch 2A: extend `InterfaceSummary` to include admin state (and optionally carrier)
**File:** `rustyjack-core/src/system/ops.rs`  
**Struct:** `InterfaceSummary`

Add:

```rust
pub admin_up: bool,
pub carrier: Option<bool>,
```

### Patch 2B: populate `admin_up` and `carrier` in summaries
**File:** `rustyjack-core/src/system/mod.rs`  
**Function:** `list_interface_summaries()`

```rust
let flags_hex = fs::read_to_string(entry.path().join("flags")).unwrap_or_default();
let flags = u32::from_str_radix(flags_hex.trim().trim_start_matches("0x"), 16).unwrap_or(0);
let admin_up = (flags & 0x1) != 0; // IFF_UP

let carrier = fs::read_to_string(entry.path().join("carrier"))
    .ok()
    .and_then(|v| match v.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    });
```

Return it in the summary.

### Patch 2C: update UI rendering
**File:** `rustyjack-ui/src/app.rs`  
Where interface status is displayed, show *both*:

- **Admin:** UP/DOWN (IFF_UP)
- **Operstate:** string (`up/down/dormant/...`)
- **Carrier:** yes/no if present

## Done looks like
- After selecting `wlan0`, Hardware Detect shows **Admin: UP** immediately.
- Operstate may remain down until association (expected and visible).

---

# Fix 3 — Isolation selection: stop depending on operstate

## Problem
UI scan preflight reports: `interface wlan0 is down` (admin-DOWN).

## Root cause (confirmed)
When preferred interface is missing/invalid, isolation may “fail‑closed” by selecting **None** if no interface has `oper_state == "up"`. Wi‑Fi commonly has operstate down until associated, so this can block everything even when you intended wlan0.

**File:** `rustyjack-core/src/system/isolation.rs`  
**Function:** `select_active_interface(...)`

## How to fix (patch guide)

### Patch 3A (mandatory): make auto-selection operstate-independent
Replace the “only operstate==up is eligible” behavior with deterministic selection:

**Selection rules (authoritative):**
1) If **preferred** interface exists → select it.
2) Else select a deterministic default even if operstate is down:
   - prefer non-wireless (e.g., `eth0`) if present
   - else prefer wireless (e.g., `wlan0`)
   - else first non-loopback interface
3) Return `None` only if no interfaces exist besides `lo`.

#### Pseudocode (drop-in structure)
```rust
if let Some(pref) = preferred {
    if interfaces.iter().any(|i| i.name == pref) {
        return Ok(Some(pref.to_string()));
    }
}

let candidates: Vec<&InterfaceSummary> =
    interfaces.iter().filter(|i| i.name != "lo").collect();

if candidates.is_empty() {
    return Ok(None);
}

if let Some(wired) = candidates.iter().find(|i| !i.is_wireless) {
    return Ok(Some(wired.name.clone()));
}

if let Some(wifi) = candidates.iter().find(|i| i.is_wireless) {
    return Ok(Some(wifi.name.clone()));
}

Ok(Some(candidates[0].name.clone()))
```

## Done looks like
- Selecting `wlan0` results in daemon reporting **admin‑UP** for wlan0 immediately.
- Scan preflight does not fail unless selection truly doesn’t exist.
- Fail‑closed still happens only in the real edge case (no interfaces besides `lo`).

---

# Fix 4 — USB mount policy + UI mount errors

## Problem A
Import from USB: “USB device detected but not mounted”.

## Problem B
Export logs to USB: “internal error”.

## Root cause (confirmed)
1) Core mount policy requires sysfs `removable==1` in two locations → many real USB devices rejected.
2) UI hides mount errors (returns `Ok(None)`).
3) Export logs error becomes “internal error” because daemon wraps core errors as Internal (addressed fully in Fix 5 too).

## How to fix (patch guide)

## 4A — Mount policy: remove `removable` as a hard gate (keep USB topology proof)
**File:** `rustyjack-core/src/mount.rs`

### Patch 4A.1: enumeration gate
In `enumerate_usb_block_devices()` replace:

```rust
if !(is_usb && removable) { continue; }
```

with:

```rust
if !is_usb { continue; }
// removable is informational only
```

Keep `removable` for logging/diagnostics if useful.

### Patch 4A.2: mount gate
Rename `ensure_usb_removable()` semantics to “ensure allowed USB device”.

Replace the removable requirement with:

```rust
let is_usb = is_usb_block_device(&sys_base).unwrap_or(false);
if !is_usb {
    bail!("device is not a USB storage device");
}

let removable = read_sysfs_flag(sys_base.join("removable")).unwrap_or(false);
tracing::info!(target:"usb", device=%base, removable=%removable, "usb_device_removable_flag");
```

**Security remains intact** because the allowed device checks and USB topology proof remain the boundary.

---

## 4B — UI must show mount failure reason
**File:** `rustyjack-ui/src/app.rs`  
**Function:** `mount_usb_device(...)`

On `Err(e)`, do not silently return `Ok(None)`. Show a message that includes the real error:

```rust
self.show_message(
    "USB Mount Failed",
    [
        "Mount failed:",
        &truncate_error(&e.to_string(), 120),
        "Fix: format USB as FAT32/ext4 or verify kernel filesystem support",
    ],
)?;
```

Keep the log line too.

## Done looks like
- USB import/export works for valid USB devices even if sysfs reports removable=0.
- When mount fails, the UI displays the real reason (filesystem unsupported, device not allowed, etc.)

---

# Fix 5 — Daemon error mapping: stop “internal error” masking

## Problem
UI sees “internal error” for mount/export failures.

## Root cause (confirmed)
**File:** `rustyjack-daemon/src/dispatch.rs`  
`dispatch_core_command()` wraps core errors as `ErrorCode::Internal` with a generic message.

## How to fix (patch guide)

### Patch 5A (mandatory): preserve the real message and map obvious classes
Replace:

```rust
DaemonError::new(ErrorCode::Internal, "command dispatch failed", false)
  .with_detail(err.to_string())
```

with:

```rust
let msg = err.to_string();
let code = if msg.contains("mount") || msg.contains("filesystem not allowed") {
    ErrorCode::MountFailed
} else if msg.contains("WiFi") || msg.contains("wifi") {
    ErrorCode::WifiFailed
} else {
    ErrorCode::Internal
};

DaemonError::new(code, msg, false)
    .with_source(format!("daemon.dispatch.{label}"))
```

## Done looks like
- Export logs failures are reported as `MountFailed` (and show the real message).
- UI no longer collapses meaningful errors into “internal error”.

---

# Fix 6 — Isolation hardening: never ignore bring_down failures

## Problem
Strict isolation can be violated if bringing down an interface fails but code continues.

## Root cause (confirmed)
**File:** `rustyjack-core/src/system/isolation.rs`  
`block_interface()` logs a warning when bring_down fails rather than failing.

## How to fix (patch guide)

### Patch 6A (mandatory): treat bring_down failure as critical
Change bring_down to:

```rust
self.ops.bring_down(iface)
    .with_context(|| format!("CRITICAL: failed to bring down {}", iface))?;
```

### Patch 6B (recommended): retry + verify admin state
```rust
for _ in 0..3 {
    if self.ops.bring_down(iface).is_ok() {
        break;
    }
    std::thread::sleep(Duration::from_millis(100));
}

if self.ops.admin_is_up(iface)? {
    bail!("CRITICAL: {} remained admin-UP after bring_down retries", iface);
}
```

## Done looks like
- If any non-selected interface cannot be forced down, enforcement fails loudly.
- No silent isolation violations.

---

# Patch order and verification

## Suggested patch order (minimize user-visible pain fast)
1) Fix 1A (add scan `count`) + Fix 1B (UI parse hardening)  
2) Fix 4A (USB removable gates)  
3) Fix 5A (daemon error mapping) + Fix 4B (UI mount error display)  
4) Fix 2 (admin_up in summaries)  
5) Fix 3 (operstate-independent selection)  
6) Fix 6 (hard isolation bring_down enforcement)

---

## Verification checklist (no external binaries required)

### Verify strict isolation: exactly one admin‑UP
Read `/sys/class/net/<iface>/flags` for each interface; ensure only one has IFF_UP bit set.

### Verify Wi‑Fi scan schema
- Trigger scan from UI
- Ensure no “missing field count”
- Ensure list populates

### Verify “wlan0 down” no longer happens spuriously
- Ensure selection exists
- Ensure `select_active_interface()` does not depend on operstate
- Scan should pass preflight (admin-UP)

### Verify USB import/export
- Insert FAT32/ext4 USB stick
- Import mounts and lists files
- Export logs writes successfully
- If filesystem unsupported, UI shows precise error and daemon uses `MountFailed`

---

## Files to patch (single consolidated list)

### Wi‑Fi scan
- `rustyjack-core/src/services/wifi.rs` — add `count`
- `rustyjack-ui/src/types.rs` — `#[serde(default)] count`
- `rustyjack-ui/src/app.rs` — normalize count after parse

### Interface display (hardware detect)
- `rustyjack-core/src/system/ops.rs` — add `admin_up`, `carrier` to `InterfaceSummary`
- `rustyjack-core/src/system/mod.rs` — populate `admin_up`, `carrier` in `list_interface_summaries()`
- `rustyjack-ui/src/app.rs` — show Admin vs Operstate

### Isolation selection
- `rustyjack-core/src/system/isolation.rs` — make `select_active_interface()` operstate-independent

### USB mount and error handling
- `rustyjack-core/src/mount.rs` — remove removable gating in `enumerate_usb_block_devices()`
- `rustyjack-core/src/mount.rs` — change `ensure_usb_removable()` to require USB topology, not removable
- `rustyjack-ui/src/app.rs` — display mount errors (do not swallow)
- `rustyjack-daemon/src/dispatch.rs` — map mount failures to `MountFailed` and preserve message

### Isolation hardening
- `rustyjack-core/src/system/isolation.rs` — hard-fail on bring_down failure (+ retry + verify)

---

## Non‑negotiables (restated)
- No third‑party binaries added.
- Strict isolation remains mandatory.
- Disallowed interfaces must not remain operational.
- Errors must be actionable, not generic.

