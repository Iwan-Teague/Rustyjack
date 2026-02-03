# report.md — RustyJack / Watchdog (Pi Zero 2 W) Implementation Plan (Static UI, Full Feature Wiring)

**Date:** 2026‑02‑02  
**Scope:** Implementation plan for the attached Rust workspace.  
**Goal:** UI remains **static**, and **every UI operation must be runnable** (i.e., it must execute a real backend path, return a structured result, and never be a dead/stub menu item).

> Note on “security‑sensitive/offensive” UI operations: the codebase/UI may include operations that can materially affect other networks/devices. This document does **not** remove those UI entries. However, it also does **not** provide step‑by‑step implementation guidance for any operation that would enable wrongdoing. For such operations, this plan requires a **separate review and explicit authorization** before implementation details are finalized. Until then, the requirement is: the UI action must be runnable via a **safe preflight path** (capability checks + audit logging + explicit status), without implementing harmful behavior.

---

## 0. Executive summary

We will implement the following decisions:

1) **Static UI, full wiring**: every UI action must invoke a non‑stub backend path and return a result (success, or explicit error with remediation).  
2) **Ops split (Power vs System/Maintenance)**: split daemon authorization so reboot/shutdown are allowed without enabling broad “system maintenance” operations.  
3) **Remove driver installation**: assume a known hardware set; replace “install driver” flows with robust **hardware sanity checks**.  
4) **Wi‑Fi station via `wpa_supplicant` over D‑Bus**: implement a new station backend that talks to `wpa_supplicant` via its documented D‑Bus API (no shelling out). Keep the existing Rust station backend in place as a fallback and test oracle.

Authoritative references used for D‑Bus/system integration:
- wpa_supplicant D‑Bus API (interfaces/methods/errors): https://w1.fi/wpa_supplicant/devel/dbus.html  
- Linux wireless docs describing D‑Bus service file patterns and `-u` / nl80211 usage: https://wireless.docs.kernel.org/en/latest/en/users/documentation/wpa_supplicant.html  
- `-u` flag enabling D‑Bus control interface (manpage): https://man.archlinux.org/man/wpa_supplicant.8.en  
- Typical D‑Bus usage pattern example (`GetInterface`/`CreateInterface`/`Scan`): https://android.googlesource.com/platform/external/wpa_supplicant_8/+/master/wpa_supplicant/examples/wpas-dbus-new.py  
- systemd service sandboxing directives (`DevicePolicy=`, `DeviceAllow=`, etc.): https://www.freedesktop.org/software/systemd/man/systemd.exec.html  
- Supplicant’s role in key negotiation and the handoff to “higher level config such as DHCP”: https://manpages.debian.org/wheezy/wpasupplicant/wpa_supplicant.8.en.html  
- A manpage mirror describing the association flow ending with key install (normal traffic proceeds): https://man.developpez.com/man8/wpa_supplicant/

---

## 1. Non‑negotiables (what the implementation must guarantee)

### 1.1 Static UI
- Do **not** dynamically build, hide, or remove menu entries at runtime.
- If the UI displays an operation, invoking it must:
  - call a real code path (UI → IPC → daemon → job/backend)
  - return a structured “result” to the UI
  - never crash, hang, or silently no‑op

### 1.2 Full feature wiring
- Eliminate all “bail!(not implemented)”, disabled handlers, or placeholder endpoints that are reachable from the UI.
- For any operation that is blocked by policy/review, implement a **safe preflight execution** (capability checks + audit logging + deterministic safe outcome) and return an explicit status message.

### 1.3 Rust-first, minimal external binaries
- Prefer kernel APIs (netlink/nl80211), Rust libraries, and D‑Bus control.
- If an external daemon is required (e.g., `wpa_supplicant`), integrate via D‑Bus (no spawning from Rust).
- If an external binary is unavoidable (not planned in this document), it must be invoked by the daemon without a shell, with absolute paths, clear environment, and strict timeouts.

---

## 2. Ops split: Power vs System/Maintenance

### 2.1 Motivation
The existing ops model makes “System” an all-or-nothing capability. That blocks basic appliance affordances (reboot/shutdown) when `ops_system=false`.

### 2.2 Target model
Introduce a new ops class:

- `RequiredOps::Power` (or similar):
  - reboot
  - shutdown
  - sync (if you expose it as a UI action)

- `RequiredOps::System` (renamed/repurposed as “Maintenance” in code or docs):
  - anything that changes base OS state, drivers, packages, deep logging config, etc.

### 2.3 Implementation steps
1) Update IPC config structs to include `ops_power: bool`.
2) Update daemon authorization mapping:
   - remap reboot/shutdown endpoints to require Power ops
   - keep other deep system actions under System/Maintenance ops
3) Update environment parsing:
   - `RUSTYJACKD_OPS_POWER=true` in the appliance systemd unit by default
4) Add unit tests:
   - “endpoint → required ops” table tests
   - regression tests ensuring reboot/shutdown remain usable when System/Maintenance ops are disabled

### 2.4 Acceptance criteria
- With `ops_power=true` and `ops_system=false`:
  - reboot/shutdown/sync UI operations succeed
  - maintenance-only operations return a structured “not permitted” result (not a crash)

---

## 3. Remove driver installation; hardcode expected hardware

### 3.1 Policy decision
Remove driver installation capability entirely. Assume a curated set of supported hardware and ship images accordingly.

### 3.2 Replace with “Hardware Sanity Check” operation
The UI entry that formerly performed installation should instead run:
- interface presence checks (e.g., `wlan0`, optionally `eth0`)
- driver binding checks via sysfs:
  - `/sys/class/net/<iface>/device/driver` symlink existence
- operstate checks:
  - `/sys/class/net/<iface>/operstate`
- rfkill availability checks (if used):
  - `/dev/rfkill` and/or netlink rfkill enumeration
- optionally, firmware presence checks if your platform needs it (paths are vendor-specific)

No shelling out is permitted here.

### 3.3 Implementation steps
1) Delete the driver installation MenuAction and any IPC/daemon handlers that exist solely for installing drivers.
2) Add/expand a `HardwareSanityCheck` action:
   - Runs in daemon (privileged) or UI (unprivileged) depending on what paths are required.
   - Returns a structured report:
     - OK / WARN / FAIL
     - list of missing paths/symlinks
     - remediation guidance (e.g., “image mismatch” vs “hardware missing”)
3) Add automated tests for sysfs parsing (mock files in tests).

### 3.4 Acceptance criteria
- There is no “install driver” code path reachable from UI.
- The replacement action returns deterministic results and is safe to run repeatedly.

---

## 4. Wi‑Fi station via `wpa_supplicant` over D‑Bus (keep existing Rust work)

### 4.1 Decision
Implement a new station backend that uses `wpa_supplicant`’s **documented D‑Bus API** and keep the existing Rust station backend:
- as a fallback (for environments where `wpa_supplicant` is unavailable)
- as a test oracle (scan/connect semantics, error mapping)

D‑Bus API reference: https://w1.fi/wpa_supplicant/devel/dbus.html

### 4.2 Performance: what to expect
`wpa_supplicant` is control-plane (auth/association/key negotiation). After it configures the network device, higher level configuration like DHCP proceeds (Debian manpage). https://manpages.debian.org/wheezy/wpasupplicant/wpa_supplicant.8.en.html  
A manpage mirror describes the association flow ending with key installation, after which normal traffic can proceed. https://man.developpez.com/man8/wpa_supplicant/  
In practice, on embedded Linux, the runtime throughput impact is typically dominated by the kernel driver/firmware path, not the user-space control component.

### 4.3 System integration requirement
`wpa_supplicant` must run with D‑Bus enabled:
- `-u` enables the D‑Bus control interface (manpage). https://man.archlinux.org/man/wpa_supplicant.8.en  
Linux wireless docs discuss typical D‑Bus service files and enabling nl80211. https://wireless.docs.kernel.org/en/latest/en/users/documentation/wpa_supplicant.html

**Do not spawn `wpa_supplicant` from Rust.** Provide/adjust a systemd unit (or use the distro unit) so the daemon can rely on D‑Bus being available.

### 4.4 D‑Bus object model (minimum)
Your backend should implement these minimum flows:

**Acquire interface object**
- Call `GetInterface("wlan0")` on `/fi/w1/wpa_supplicant1`; if unknown, call `CreateInterface({ Ifname: "wlan0", Driver: "nl80211" })`.  
See example script pattern. https://android.googlesource.com/platform/external/wpa_supplicant_8/+/master/wpa_supplicant/examples/wpas-dbus-new.py

**Scan**
- Call `Scan({Type:"active"})` (or equivalent per API docs).
- Subscribe to `PropertiesChanged` and BSS added/removed signals to update scan results.

**Connect**
- Add a network (set SSID, PSK / key_mgmt fields as required).
- Select/Enable network.
- Wait for state transition to a connected/authorized state; enforce timeouts and cancellation.

**Disconnect**
- Disconnect and clean up temporary networks created by the UI action.

### 4.5 Design: coexistence with existing Rust station backend
Do **not** delete the Rust backend. Instead:
- Define a trait/enum that allows selecting backend:
  - `StationBackend::WpaSupplicantDbus`
  - `StationBackend::RustNative`
- Select default backend via config/env.
- Keep a small shared representation for:
  - scan results
  - connect result state machine
  - error mapping into user-facing messages

### 4.6 systemd hardening for `wpa_supplicant` and the daemon
Use systemd sandboxing directives carefully, ensuring required device access remains available. systemd docs: https://www.freedesktop.org/software/systemd/man/systemd.exec.html  
If you use `DevicePolicy=closed`, explicitly allow required devices via `DeviceAllow=`.

### 4.7 Acceptance criteria
- Scanning and connecting via the UI works on Pi Zero 2 W hardware using `wpa_supplicant` over D‑Bus.
- Existing Rust backend remains compiled and usable (fallback/test oracle).
- No shelling out is introduced for Wi‑Fi operations.

---

## 5. UI feature parity checklist (required implementation workflow)

### 5.1 Build a comprehensive UI → backend map
Create a single source of truth mapping file (for the repo, not necessarily user-facing):
- Each MenuAction / UI command
- The IPC message it generates
- The daemon endpoint/job it triggers
- The required ops category (Power/System/etc)
- Expected success and error modes

### 5.2 For each UI operation
- If backend exists: ensure it’s not stubbed, and add tests.
- If backend is missing: implement minimal viable backend.
- If operation is “security-sensitive/offensive”:
  - Implement **safe preflight + capability checks + audit logging**
  - Return explicit status
  - Do not finalize active behavior until separate review/authorization completes (outside this document).

### 5.3 “No stubs reachable from UI” build guard
Add a test harness that iterates every MenuAction dispatch arm and asserts:
- it emits a valid daemon request OR completes a bounded local op
- it never calls `unimplemented!()`, `todo!()`, or a “disabled” `bail!()`

---

## 6. Milestones (recommended PR breakdown)

**PR 1 — Ops split**
- New `Power` ops, updated auth mapping, env parsing, unit tests.

**PR 2 — Remove driver installation**
- Delete install action paths; add Hardware Sanity Check action + tests.

**PR 3 — `wpa_supplicant` D‑Bus backend**
- Implement `WpaSupplicantDbus` station backend.
- Add systemd unit adjustments and D‑Bus reliability.
- Keep Rust backend in place.

**PR 4 — UI parity harness**
- Add MenuAction coverage tests and “no UI stubs” build guard.

---

## 7. Open items requiring review (not removed)

This plan intentionally does **not** remove any UI entries. Some UI operations may require:
- threat modeling
- legal/compliance approval
- explicit user consent flows
- safe default configuration

Those items must be reviewed and approved before implementation details are finalized. Until approval, they must still be **runnable** via a safe preflight path as described in §5.2.

---
