# Area 3 — Interface isolation & interface selection state machine (Report)
Date: 2026-02-15


**Scope (per Architecture Doc 2, Area 3):** isolation engine/state machine, interface selection logic, watcher/enforcer loops, rollback, verification; interaction with DHCP/DNS/routing/rfkill; hotspot exceptions.  
**Safety property (hard requirement):** *“Only one network interface can be up at one time; others down; rfkill where applicable”* must be **continuously enforced** (no deliberate overlap windows), except for an explicit, bounded hotspot exception.

**Repository snapshot analyzed:** `watchdog_shallow_20260213-173640.zip` (extracted under `watchdog/`)  
**Primary implementation files inspected:**
- `crates/rustyjack-core/src/system/interface_selection.rs`
- `crates/rustyjack-core/src/system/isolation.rs`
- `crates/rustyjack-core/src/system/mod.rs` (isolation helpers)
- `crates/rustyjack-daemon/src/netlink_watcher.rs`
- Supporting: `crates/rustyjack-core/src/system/ops.rs`, `routing.rs`, `dns.rs`, `services/hotspot.rs`, `crates/rustyjack-daemon/src/locks.rs`, `crates/rustyjack-ui/src/app/iface_select.rs`

---

## Executive summary

### What’s solid
- There **is** a coherent “selection job” (`select_interface`) with: preflight → isolate → verify → persist, plus rollback on failure.
- There **is** a background enforcement loop (daemon netlink watcher) that re-applies policy on events + timer and tries to keep the system converged.
- There’s a strict invariant checker for allow-lists (`verify_only_allow_list_admin_up`) that can enforce “allowed admin-UP only; other wireless rfkill-blocked.”

### High-risk issues (safety/correctness)
1. **Deliberate overlap windows (two interfaces admin-UP simultaneously)** exist in multiple pathways:
   - UI interface switch job: brings the target interface UP **before** forcing other uplinks DOWN.
   - Rollback: brings previous interface UP **before** forcing the failed target DOWN.
   - Strict allow-list isolation: “Phase 1 bring allowed UP” happens **before** “Phase 2 bring others DOWN.”
2. **Isolation verification is inconsistent**:
   - Strict allow-list path verifies the isolation invariant (including rfkill for non-allowed wireless).
   - IsolationEngine’s `verify_enforcement` **does not** verify “single interface admin-UP” nor rfkill state; it primarily checks default route + DNS.
3. **Daemon watcher has a configuration-dependent branch** that may allow **multiple** uplinks admin-UP (all wireless or all wired) when only one of `wifi_ops`/`eth_ops` is enabled.
4. **Interface selection considers only “uplink interfaces” (physical)**; this can exclude monitor/virtual wireless interfaces, meaning it can claim success while leaving additional interfaces UP, contradicting the README’s “all other interfaces down” wording.

Net result: the system *often converges* to compliance, but **can intentionally violate** the “only one interface UP at a time” safety property during normal operations, and can claim “success” without checking all safety invariants.

---

## Evidence base & trust model

### Trusted invariants (authoritative, per your rule)
Only these files are treated as defining non-negotiable isolation invariants:

- Root docs:
  - `README.md`
  - `TESTING.md`
  - `AGENTS.md` (DNS ownership constraints)
- Logs/done:
  - `logs/done/interface_isolation_overview.md`

Everything else (code, non-done logs, scripts) is **implementation evidence**, not the source of truth for invariants.

### Architecture Doc 2 (analysis guide)
`rustyjack_architecture_analysis_plan.md` is used as analysis guidance and required deliverable structure, but **not** as the authority for invariants.

---

## Non-negotiable invariants

This section lists isolation rules **verbatim** from trusted docs, then maps each rule to current enforcement points (and gaps).

### Invariant I1 — “only one active interface”
**Verbatim (README.md L178–L180):**  
> “When selecting an active interface, the other interfaces are brought DOWN.”  
> “Non-selected wireless interfaces are also rfkill-blocked (soft block).”  
> “Hotspot exception: wlan1 is allowed to be UP when wlan0 is used as the upstream connection.”

**Verbatim (TESTING.md L68–L70):**  
> “Interface isolation active: only the selected interface is admin-UP; others forced DOWN; other wireless rfkill-blocked.”

**Verbatim (logs/done/interface_isolation_overview.md L5–L6):**  
> “We enforce isolation: only the selected interface stays UP; all others are forced DOWN and rfkill-blocked if wireless.”

**Code enforcement points (current):**
- Strict allow-list enforcement & verification:
  - `crates/rustyjack-core/src/system/mod.rs`:
    - `apply_interface_isolation_with_ops_strict` (blocks/bring-up + verification)
    - `verify_only_allow_list_admin_up` (explicit invariant checks, including rfkill for non-allowed wireless)
- UI switch job (selection):
  - `crates/rustyjack-core/src/system/interface_selection.rs`:
    - `deactivate_non_target_uplinks` (forces other uplinks down + rfkill-block)
    - `verify_single_admin_up` (checks “target UP, others DOWN” for the *uplink list* it computed)
- Background enforcement:
  - `crates/rustyjack-core/src/system/isolation.rs` (`IsolationEngine`):
    - `block_interface` called for every non-active interface
    - `enforce_with_hotspot` allows AP + upstream

**Gaps (current):**
- **Continuity gap:** multiple paths intentionally create a “two admin-UP uplinks” window.
- **Coverage gap:** interface selection’s “other_ifaces” list filters to *physical* uplinks, risking unaccounted UP interfaces.
- **Verification gap:** IsolationEngine’s `verify_enforcement` does not check rfkill or “exactly one admin-UP”.

---

### Invariant I2 — Hotspot exception is explicit and bounded
**Verbatim (README.md L180):**  
> “Hotspot exception: wlan1 is allowed to be UP when wlan0 is used as the upstream connection.”

**Code enforcement points (current):**
- `crates/rustyjack-core/src/system/isolation.rs`:
  - `set_hotspot_exception(ap_interface, upstream_interface)`
  - `enforce_with_hotspot` allows exactly `{AP, upstream}` and blocks others
- Hotspot service sets/clears exception:
  - `crates/rustyjack-core/src/services/hotspot.rs`

**Gaps (current):**
- Exception is **in-memory only**; a daemon/crate restart forgets it.
- Interface selection UI/job does **not** check hotspot state; it can try to force “single uplink” during hotspot.

---

### Invariant I3 — Verification before UI reports success
**Verbatim (Architecture Doc 2 Area 3.1 / 6.1):** *(analysis requirement; not counted as a trusted invariant)*  
**Trusted analogue:** `TESTING.md` explicitly requires verification semantics and SSH-safety behavior.

**Verbatim (TESTING.md L18–L20):**  
> “When running over SSH, the suite skips switching away from the SSH uplink by default.”  
> “Override only if you have local console access: `--allow-remote-switch`.”

**Code enforcement points (current):**
- UI waits for `InterfaceSelectJob` completion then checks `admin_is_up` for the selected interface:
  - `crates/rustyjack-ui/src/app/iface_select.rs`:
    - shows “Active Interface Set” only when `admin_up == true`
- Core selection job verifies single-admin-up invariant *for its uplink set* before persisting:
  - `interface_selection.rs: verify_single_admin_up`

**Gaps (current):**
- UI success criteria does not include rfkill verification or “all other interfaces down.”
- Background watcher “success” is mostly log-level; it can claim enforcement complete without checking the full invariant set.

---

### Invariant I4 — DNS ownership is Rustyjack-managed at runtime root
**Verbatim (AGENTS.md L9–L15):**  
> “DNS is managed by writing `resolv.conf` directly (root-owned).”  
> “Raspberry Pi OS uses `resolvconf` and `systemd-resolved` is disabled.”  
> “Write DNS to `/var/lib/rustyjack/resolv.conf` and bind-mount it to `/etc/resolv.conf`.”

**Code enforcement points (current):**
- `crates/rustyjack-core/src/system/dns.rs` (`DnsManager`) writes to a provided path (typically runtime root).
- `IsolationEngine` verifies DNS via `DnsManager::verify_dns`.
- Interface selection sets DNS in wired DHCP case via `DnsManager::set_dns`.

**Gaps (current):**
- Some enforcement paths (strict allow-list isolation) do not configure/verify DNS at all.

---

## System overview

### A) Isolation primitives & helpers
There are three distinct “isolation” pathways:

1. **Best-effort allow-list**: `apply_interface_isolation_with_ops`  
   - Brings allowed UP (unblocks rfkill for allowed wireless), then brings others DOWN and rfkill-blocks.  
   - **No waiting, no invariant verification, and wireless bring-up failures are often not surfaced.**

2. **Strict allow-list**: `apply_interface_isolation_with_ops_strict`  
   - Brings allowed UP (with waits), then brings non-allowed DOWN (with waits), rfkill-blocks non-allowed wireless, then verifies invariant with `verify_only_allow_list_admin_up`.  
   - **Problem:** ordering creates an overlap window.

3. **IsolationEngine**: `IsolationEngine::enforce_{passive,connectivity}`  
   - Selects a single active interface (based on preference else wired-first), blocks all others, then runs a verified “activation pipeline”.  
   - Contains the explicit **hotspot exception** path.

### B) Interface selection job
`select_interface(...)` (core) is the UI-facing transactional switch.

It includes:
- preflight (wireless rfkill hard-block check/unblock attempt)
- “Phase A”: prep target interface (bring up, ensure DHCP if wired)
- “Phase B”: deactivate other uplinks (bring down, rfkill-block, drop DHCP/route)
- verify invariant (target admin-UP, others down)
- persist preference

It also has rollback that attempts to restore the previous interface.

### C) Watcher/enforcer loop
Daemon’s `NetlinkWatcher` runs:
- on netlink events (link change, route change) and
- every ~3 seconds as a periodic “keep converged” pulse.

It acquires a daemon-level `uplink` lock before performing enforcement. Enforcement uses either:
- IsolationEngine (default when both wifi_ops and eth_ops enabled), or
- strict allow-list isolation (when one side is disabled).

---

## 1) Explicit state machine (phases + transitions + postconditions)

Below are **explicit, named state machines** that combine code reality and the continuous-safety requirement.

### 1.1 User-initiated interface switch job (`select_interface`)

#### States (as-implemented)
| State | Code locus | Entry actions | Exit condition | Postcondition |
|---|---|---|---|---|
| S0 Idle | caller | N/A | user triggers job | N/A |
| S1 Snapshot | `select_interface` | gather `uplinks`, previous iface | always | have rollback snapshot |
| S2 Preflight | `preflight_wireless_target` | check hard rfkill, attempt unblock | ok or fail | target not hard-blocked (wireless) |
| S3 Phase A: Prepare target | `prepare_target_interface` | bring up target; for wired: DHCP + default route + DNS | ok or fail | target is (attempted) admin-UP; may have config |
| S4 Phase B: Deactivate non-target | `deactivate_non_target_uplinks` | bring down others; rfkill-block wireless; delete routes; release DHCP; flush addresses | ok (best effort) | others requested DOWN; rfkill-block attempted |
| S5 Verify | `verify_single_admin_up` | require target admin-UP, others admin-DOWN | ok or fail | *for `other_ifaces` list* invariants hold |
| S6 Persist | `prefs.set_preferred`, `write_interface_preference` | persist preferred iface | ok or fail | preference saved |
| S7 Done | return | N/A | N/A | outcome returned |
| SR Rollback | `rollback_after_commit_failure` | restore previous, clear target | ok-ish | attempt to revert |

#### Critical transition hazard (continuous safety)
- **S3 occurs before S4**, meaning there is a *deliberate window* where the previous interface may remain admin-UP while the target is brought admin-UP.

#### Recommended “continuous safety” ordering
To continuously enforce “at most one interface admin-UP”, the state machine should be:

- **S3’ Block others first** (bring non-target down + rfkill-block + wait)  
- **S4’ Bring target up** (wait for admin-UP; then connectivity config)  
- **S5 Verify** and persist only after invariants are true.

This preserves correctness even if it introduces a short connectivity gap (which the test suite already treats as sensitive under SSH).

---

### 1.2 Background watcher enforcement (`NetlinkWatcher` + `IsolationEngine`)

#### States
| State | Trigger | Action | Postcondition |
|---|---|---|---|
| W0 Sleep | timer tick or netlink event | collect event(s) | N/A |
| W1 Acquire uplink lock | watcher loop | `state.locks.acquire_uplink()` | prevents concurrent UI interface switch job |
| W2 Debounce | link/route changes | wait ~150ms after last event | reduces thrash |
| W3 Spawn enforcement | spawn_blocking | run `enforce_passive` or strict allow-list | enforcement attempted |
| W4 Release uplink lock | drop permit | allow other jobs | lock freed |
| W5 Repeat | timer tick | loop | convergence over time |

#### Postconditions (current)
- With default ops config (both wifi_ops and eth_ops enabled), `IsolationEngine` converges toward:
  - one selected interface active, others blocked
  - route and DNS set for ethernet in passive mode if carrier+DHCP
- But **verification does not guarantee isolation invariant** (single admin-UP + rfkill) is true; it mostly checks default route + DNS presence.

---

### 1.3 Hotspot exception state machine (core)

| State | Trigger | Allowed admin-UP set | Notes |
|---|---|---|---|
| H0 None | normal operation | `{selected_uplink}` | enforce single-interface |
| H1 Exception set | hotspot start | `{AP, upstream}` | `set_hotspot_exception` |
| H2 Exception cleared | hotspot stop | `{selected_uplink}` | `clear_hotspot_exception` |

**Continuity requirement:** transitioning into/out of hotspot should not create multi-uplink overlap beyond the allowed set.

---

## 2) Concurrency model (watchers vs switch jobs; locking)

### 2.1 Locks in play

#### Daemon-level locks
`crates/rustyjack-daemon/src/locks.rs` defines semaphores:
- `uplink` (used by netlink watcher and interface selection job)
- `wifi`
- `ethernet`

**Current usage:**
- `NetlinkWatcher` acquires `uplink`.
- `InterfaceSelectJob` acquires `uplink`.
- Many other jobs use `wifi`/`ethernet` but **not** `uplink`.

#### Core-level lock
`crates/rustyjack-core/src/system/isolation.rs` has a process-global `ENFORCEMENT_LOCK` used only inside `IsolationEngine::enforce_with_mode`.

### 2.2 Current concurrency behavior
- While a UI interface switch job runs, the watcher is blocked by the daemon’s uplink lock. Good.
- However, other code paths can call isolation helpers directly (e.g., `enforce_single_interface → apply_interface_isolation_strict`) **without** taking the daemon’s uplink lock and **without** `ENFORCEMENT_LOCK`.

### 2.3 Observed race classes
1. **Watcher vs non-uplink-locked operations**  
   A job that mutates interfaces under the `wifi` lock can run concurrently with watcher enforcement under `uplink`, because these locks are distinct. If both touch link state, rfkill, or routes, they can conflict.

2. **Multiple isolation entrypoints, different locking semantics**  
   - IsolationEngine uses `ENFORCEMENT_LOCK` (core), plus daemon uplink lock if called by watcher.
   - Strict allow-list and selection job do not use `ENFORCEMENT_LOCK`.

### 2.4 Recommended locking model
- Define “network isolation is global” and unify around a single **network-state lock**:
  - Either **always** acquire daemon `uplink` for any interface-up/down/rfkill/route/DHCP mutations, or
  - Move `ENFORCEMENT_LOCK` into the daemon as a single authority and require all entrypoints to hold it.
- Enforce a **lock hierarchy** if multiple locks remain:
  - `uplink` → `wifi`/`ethernet` (never the reverse) to prevent deadlocks.

---

## 3) Failure injection matrix

This matrix focuses on correctness + safety (not offensive operations).

| Fault / injection | Where to inject | Expected behavior (per invariants) | Current behavior | Gap / risk | Suggested fix |
|---|---|---|---|---|---|
| Wireless hard rfkill ON | `preflight_wireless_target` | fail fast; do not claim switch | does fail with clear error | OK | ensure UI displays hard-block reason |
| Wireless soft rfkill unblock fails | `set_rfkill_block(false)` | switch must fail or degrade explicitly | selection job records warning; may proceed | Might claim “set” while radio blocked | treat unblock failure as fatal when selecting wireless |
| bring_up fails (target) | `prepare_target_interface` | fail and rollback; no overlap | selection job may treat wireless bring_up failures as non-fatal in some paths | may persist pref incorrectly if admin-up check passes later | make bring_up failure fatal for selected interface |
| bring_down fails (non-target) | `deactivate_non_target_uplinks` | must fail verification; rollback | errors pushed; verify catches if still up | OK-ish | add retries + bounded wait in selection |
| **Two-UP overlap window** | selection Phase A before B | must never happen | happens by design | violates continuous safety | reorder to “down others first, then up target” |
| DHCP timeout (wired) | `acquire_dhcp` | selection should still be “admin-up success”, but UI must not claim connectivity | selection continues; UI shows warning if admin-up only | OK | separate “isolation success” vs “connectivity success” in outcome |
| Default route add fails | `RouteManager::set_default_route` | should fail in connectivity mode; warn in passive | selection treats as error in wired config | OK | ensure cleanup removes partial routes |
| DNS write fails | `DnsManager::set_dns` | should fail in connectivity mode; warn in passive | selection errors in wired config | OK | ensure atomic rename errors reported clearly |
| netlink list_interfaces error | watcher / selection | should fail safely, avoid changing state | watcher logs & continues | might miss enforcement | add backoff + health metric |
| netlink monitor drop | watcher socket | system should fall back to periodic enforcement | watcher also ticks every 3s | OK | ensure monitor errors don’t kill task |
| crash mid-switch (after target up, before others down) | kill during selection | on restart, watcher must converge to single interface | watcher likely converges, but can leave overlap window | violation persists until watcher runs | reorder to avoid overlap; persist “switch-in-progress” marker |
| crash after persisting preference, before cleanup | kill between persist and return | invariants should already be true | mostly true | OK | ensure persist happens only after full invariant check (including rfkill) |
| hotspot exception lost on restart | restart daemon/core | hotspot should remain stable or self-heal | exception is in-memory; enforcement will collapse to single iface | hotspot breaks | persist exception state (runtime root) |
| watcher strict allow-list branch | disable wifi_ops or eth_ops | still must keep exactly one admin-UP uplink | strict allow-list may allow multiple interfaces UP | violates steady-state invariant | make allow-list be exactly one target, not “all of type” |
| rfkill device missing | `set_rfkill_block` returns error | should treat “rfkill where applicable” as best-effort but visible | strict mode errors; selection warns; watcher may ignore | inconsistent | define policy: if wireless has rfkill index missing, treat as warn but don’t claim full compliance |

---

## 4) Verification semantics

This is where “safety audit” turns into “define what success means.”

### 4.1 Levels of success (recommended)
1. **Isolation success (hard gate):**
   - Exactly one interface in the *uplink set* is admin-UP (or exactly two in hotspot exception mode).
   - All non-selected uplinks are admin-DOWN.
   - All non-selected wireless uplinks are rfkill soft-blocked (when rfkill device exists).

2. **Configuration success (mode-dependent):**
   - For wired selection in connectivity mode: DHCP lease acquired; default route via selected; DNS set.

3. **Operational success (optional):**
   - Reachability check (gateway ARP/ping) or DNS resolution check.  
   *(Not currently implemented; should be optional to avoid “false negatives” on captive portals.)*

### 4.2 Current semantics (as-implemented)
- **Selection job success:** returns Ok after `verify_single_admin_up` for the uplink list it computed; persists preference.
- **UI success display:** shows “Active Interface Set” only if the selected iface is admin-UP when polled after job completion.
- **Watcher success:** “enforcement complete” logged after `verify_enforcement` (default route + DNS), not after “single admin-UP + rfkill” verification.

### 4.3 When UI is allowed to claim success (recommended rule)
UI may claim “Isolation enforced” only after:
- strict invariant check passes (admin-up set matches expected; rfkill blocks confirmed), and
- the system has either:
  - persisted preference (for user switch), or
  - converged enforcement snapshot (for watcher re-enforcement).

Anything less should be labeled:
- “Interface requested” / “Attempted” / “Admin-UP only” / “Connectivity not verified”.

---

## 5) Findings (20)

Each finding is formatted as: **Problem → Why → Where → Fix → Fixed version looks like**.

> Line numbers below refer to the extracted snapshot; they’re included to make code navigation fast.

---

### F1 — Deliberate “two uplinks admin-UP” overlap during interface switch
- **Problem:** `select_interface` brings the target interface UP before bringing other uplinks DOWN.
- **Why:** violates the continuous safety property; can leak traffic, confuse routing, and break assumptions in other subsystems.
- **Where:** `crates/rustyjack-core/src/system/interface_selection.rs`  
  - `prepare_target_interface(...)` runs before `deactivate_non_target_uplinks(...)` (approx L169–L197).
- **Fix:** reorder to “down others first, then up target”; treat the brief “no uplink” window as acceptable (the test suite already treats remote switching as dangerous).
- **Fixed version looks like:** state machine becomes: preflight → **deactivate non-target** → bring up target → (DHCP/DNS/route if needed) → verify → persist.

---

### F2 — Rollback can also create an overlap window
- **Problem:** rollback restores the previous interface (bring up + verify) before bringing the failed target down.
- **Why:** creates a second “two-UP” window during the exact time the system is already in a failure state.
- **Where:** `interface_selection.rs` `restore_previous_interface(...)` (approx L665–L722) and rollback sequence.
- **Fix:** rollback should first guarantee target is DOWN (and rfkill-blocked if wireless), then restore previous.
- **Fixed version looks like:** rollback ordering: `block(target)` → wait down → restore previous → verify invariant.

---

### F3 — Strict allow-list isolation has the same overlap ordering bug
- **Problem:** `apply_interface_isolation_with_ops_strict` performs “Phase 1 bring allowed UP” then “Phase 2 bring non-allowed DOWN.”
- **Why:** if the system is currently compliant, this ordering **creates** a transient violation. If it’s non-compliant, it can worsen routing ambiguity.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` (approx L2266–L2389).
- **Fix:** invert phases: block non-allowed first, then bring allowed up.
- **Fixed version looks like:** strict isolation becomes a true two-phase commit: (1) block others; (2) activate allowed; (3) verify; else rollback.

---

### F4 — Best-effort isolation does not wait or verify, and may hide wireless bring-up failures
- **Problem:** `apply_interface_isolation_with_ops` brings allowed UP without waiting, and for wireless bring-up errors it often does not record failures.
- **Why:** callers can treat it as “isolation done” when it’s still in-flight or partially failed.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` (approx L2489–L2576).
- **Fix:** either deprecate this function in safety-critical paths, or add wait + invariant verification (or return a structured outcome that forces callers to decide).
- **Fixed version looks like:** best-effort path becomes “best-effort *but observable*”: explicit “pending” vs “verified” status and consistent error reporting.

---

### F5 — Interface selection invariant check scope may exclude non-physical interfaces
- **Problem:** `list_uplink_interfaces` filters interfaces by `caps.is_physical` (default true if missing), which can exclude virtual/monitor interfaces.
- **Why:** README says “all other interfaces are brought DOWN”; excluding some interfaces lets the system violate that while claiming success.
- **Where:** `interface_selection.rs` `list_uplink_interfaces(...)` (approx L280–L292).
- **Fix:** define the isolation domain explicitly:
  - either “all non-lo interfaces” (strongest), or
  - “all physical uplinks + all wireless radios” (still broader than current).
- **Fixed version looks like:** verification enumerates all interfaces except `lo` and ensures non-allowed are DOWN and rfkill-blocked where applicable.

---

### F6 — IsolationEngine verifies route/DNS, but not the isolation invariant
- **Problem:** `IsolationEngine::verify_enforcement` checks default route expectations + DNS contents, but does not assert “single admin-UP” or rfkill compliance.
- **Why:** the watcher may log/return success while allowing multiple admin-UP or unblocked radios.
- **Where:** `crates/rustyjack-core/src/system/isolation.rs` `verify_enforcement(...)` (approx L821–L885).
- **Fix:** add an invariant verification step comparable to `verify_only_allow_list_admin_up` (or reuse it) and include rfkill checks.
- **Fixed version looks like:** watcher enforcement returns “compliant” only when isolation + mode-dependent routing/DNS constraints hold.

---

### F7 — Watcher branch when only wifi_ops or eth_ops enabled can violate “exactly one uplink admin-UP”
- **Problem:** if ops config disables one side, watcher uses strict allow-list with **all interfaces of the enabled type** (wired or wireless) as the allow-list.
- **Why:** strict verifier then allows multiple allowed interfaces admin-UP, contradicting the “exactly one uplink admin-UP” steady-state requirement in trusted docs.
- **Where:** `crates/rustyjack-daemon/src/netlink_watcher.rs` (approx L226–L253) builds `allowed` as all wired or all wireless.
- **Fix:** even in “single-side ops” mode, pick exactly one target using the same selection policy (preference / wired-first / carrier-aware).
- **Fixed version looks like:** watcher always runs IsolationEngine selection, but simply “ignores” ops it shouldn’t run rather than widening allow-list.

---

### F8 — Interface selection does not consider hotspot exception state
- **Problem:** selection job insists on “single uplink admin-UP” and will bring down other uplinks—even if hotspot is running.
- **Why:** trusted docs explicitly allow a hotspot exception; selection can break hotspot unexpectedly.
- **Where:** `select_interface` has no hotspot exception check; hotspot exception is managed in `isolation.rs`.
- **Fix:** gate interface selection while hotspot exception is set, or treat “hotspot exception” as an alternate allowed set during selection.
- **Fixed version looks like:** UI disables switching while hotspot active (or provides explicit “stop hotspot then switch”).

---

### F9 — Hotspot exception is lost on restart
- **Problem:** hotspot exception is stored in a process-local `OnceLock<Mutex<Option<...>>>`.
- **Why:** daemon restart forgets exception; watcher then enforces single-interface and can collapse hotspot.
- **Where:** `crates/rustyjack-core/src/system/isolation.rs` `HOTSPOT_EXCEPTION` + `get_hotspot_exception`.
- **Fix:** persist exception state under runtime root and restore on startup; or encode hotspot state in daemon state and feed into enforcement policy.
- **Fixed version looks like:** startup reads `hotspot_state.json` (or similar) and re-establishes exception before watcher starts enforcing.

---

### F10 — Strict allow-list verification allows multiple “allowed” admin-UP (policy mismatch)
- **Problem:** `verify_only_allow_list_admin_up` ensures “allowed are UP; non-allowed UP is forbidden”; it does not enforce “allowed list length == 1”.
- **Why:** if caller passes multiple allowed interfaces, the verifier will accept it—contrary to the steady-state invariant.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` `verify_only_allow_list_admin_up(...)` (approx L2398–L2446).
- **Fix:** enforce “allowed length == 1” unless hotspot exception is explicitly active; otherwise treat multiple allowed as a policy violation.
- **Fixed version looks like:** verifier takes a structured policy: `{mode: Single | Hotspot{ap,upstream}}` rather than a raw list.

---

### F11 — Interface selection wired teardown may delete default route globally in a confusing way
- **Problem:** `RouteManager::delete_default_route(iface)` calls `ops.delete_default_route(iface)`, but RealNetOps ignores the iface and deletes global default route.
- **Why:** callers may believe they’re deleting per-interface routes and make unsafe assumptions; repeated calls during transitions could remove a newly-added route unexpectedly in future refactors.
- **Where:** `crates/rustyjack-core/src/system/ops.rs` `delete_default_route`, `routing.rs`.
- **Fix:** rename API to reflect reality (“delete_default_route_global”), or implement true per-interface route deletion via netlink filters.
- **Fixed version looks like:** route deletion is explicit and verifiable; call sites are unambiguous.

---

### F12 — Watcher enforcement uses spawn_blocking but still reads/modifies shared state; snapshot timing can be misleading
- **Problem:** watcher collects snapshots, then debounces, then spawns blocking enforcement; snapshots can be stale relative to enforcement completion.
- **Why:** logs and UI observers may interpret stale snapshots as “current”.
- **Where:** `netlink_watcher.rs` around enforcement spawn and snapshot storage (approx L265–L290).
- **Fix:** snapshot should be taken after enforcement and tagged with a monotonic “enforcement epoch.”
- **Fixed version looks like:** `state.enforcement_epoch += 1` and every snapshot includes `epoch`, making races observable.

---

### F13 — Selection job uses `CancelFlag`, but cancellation points don’t ensure “safe partial state”
- **Problem:** cancellation can occur between bring-up and bring-down phases, leaving overlap.
- **Why:** cancellation is a failure injection case; it should still preserve invariants.
- **Where:** `select_interface` checks `check_cancel` between phases and sub-steps.
- **Fix:** if cancellation is requested after any mutation, immediately enter “rollback-to-safe” mode that first enforces isolation invariant.
- **Fixed version looks like:** cancellation triggers a “safety rollback” that ensures at most one interface UP, regardless of the prior state.

---

### F14 — IsolationEngine’s selection is “wired-first” but not “carrier-aware”
- **Problem:** if no preference is set, `select_active_interface` picks a wired interface even if unplugged.
- **Why:** causes repeated activation attempts and can pin the system to a dead uplink until the user sets preference.
- **Where:** `isolation.rs` `select_active_interface` (approx L390–L400).
- **Fix:** include carrier state in selection ranking (prefer wired *with carrier*, else wifi).
- **Fixed version looks like:** selection policy: preferred if present else wired+carrier else wifi else any.

---

### F15 — IsolationEngine’s passive enforcement can “succeed” with no default route but still claim completion
- **Problem:** in passive mode, verify allows “no default route” even if an interface is selected, and DHCP failure is non-fatal.
- **Why:** this is valid for “admin-up only”, but it must not be conflated with “connectivity success.”
- **Where:** `isolation.rs` `verify_enforcement` and ethernet passive pipeline behavior.
- **Fix:** return structured status: `{admin_ok, dhcp_ok, route_ok, dns_ok}`.
- **Fixed version looks like:** UI and logs display “Selected: admin-up; Connectivity: pending/failed” explicitly.

---

### F16 — Best-effort isolation path can leave rfkill state unverified
- **Problem:** `apply_interface_isolation_with_ops` calls rfkill block/unblock but does not verify `is_rfkill_blocked` afterward.
- **Why:** rfkill is part of the invariant (“where applicable”); unverified toggles can silently fail.
- **Where:** `system/mod.rs` best-effort isolation function.
- **Fix:** perform rfkill verification like strict path does, at least for non-selected wireless.
- **Fixed version looks like:** if rfkill cannot be verified, outcome must be “degraded compliance” not “success.”

---

### F17 — UI can claim “Active Interface Set” based solely on admin-up, even if isolation invariant is violated elsewhere
- **Problem:** UI sets status messages based on `admin_up` check for the selected interface.
- **Why:** it can report success even if another interface remains UP (especially if excluded by the selection job’s uplink filtering).
- **Where:** `crates/rustyjack-ui/src/app/iface_select.rs` around success messaging.
- **Fix:** expose and display the core invariant verification result (single admin-up, rfkill status).
- **Fixed version looks like:** UI shows: “Isolation: OK/DEGRADED/FAILED” separately from “Selected iface admin-UP: yes/no”.

---

### F18 — Watcher strict allow-list path bypasses IsolationEngine’s hotspot exception logic
- **Problem:** when watcher uses strict allow-list (single-side ops config), hotspot exception is ignored.
- **Why:** hotspot needs two allowed interfaces; strict path will likely collapse it (or allow too many interfaces of a type).
- **Where:** `netlink_watcher.rs` `enforce_with_ops` strict branch.
- **Fix:** always route through IsolationEngine selection + hotspot logic; simply disable side-effects (like wifi connection attempts) based on ops config.
- **Fixed version looks like:** watcher policy engine is single-source-of-truth; ops config just affects “what extra work to do,” not isolation semantics.

---

### F19 — Selection job wired teardown flushes addresses after releasing DHCP, but does not ensure interface is DOWN first
- **Problem:** teardown sequences can be reordered, and some steps ignore errors.
- **Why:** leaving an interface admin-UP with flushed addresses might create weird kernel behavior and complicate verification.
- **Where:** `interface_selection.rs` `teardown_wired_interface` / `deactivate_non_target_uplinks`.
- **Fix:** canonical teardown ordering: route deletion → DHCP release → address flush → bring down → verify down.
- **Fixed version looks like:** teardown returns a structured “fully down” confirmation used by invariant checks.

---

### F20 — Multiple isolation entrypoints create inconsistent guarantees to callers
- **Problem:** callers can pick between “best-effort”, “strict”, and “IsolationEngine” enforcement, each with different semantics and verification.
- **Why:** makes it easy for future code to “use the wrong tool” and accidentally break safety.
- **Where:** `system/mod.rs`, `system/isolation.rs`, and call sites across services/jobs.
- **Fix:** establish one canonical isolation API that always enforces invariants; provide explicit opt-in “degraded/best-effort” only for non-safety contexts.
- **Fixed version looks like:** a single `NetworkIsolationController` that exposes `enforce(policy, mode)` and always returns a verified compliance report.

---

## 6) Test plan (on-device + simulated netlink + SSH safety)

This plan is designed to validate continuous enforcement and prevent regressions, without providing offensive “how-to” content.

### 6.1 On-device scripts (existing + recommended extensions)

**Use existing trusted test entrypoints:**
- `TESTING.md` references:
  - `scripts/rj_test_interface_selection.sh`
  - `scripts/rj_run_tests.sh --iface-select`
- SSH safety rule is explicit:
  - default behavior avoids switching away from the SSH uplink unless `--allow-remote-switch`.

**Recommended extensions:**
1. **“No-overlap invariant probe”**  
   Add a probe in the test harness that samples admin state for all interfaces at a high frequency during switching and asserts *never more than one uplink admin-UP* (or exactly two in hotspot exception mode).
2. **rfkill compliance probe**  
   For each non-selected wireless interface, confirm it is soft-blocked (when an rfkill device exists).
3. **Route/DNS sanity probe**  
   - If wired selected and DHCP succeeded: confirm default route interface and DNS list match.
   - If DHCP failed: confirm UI/daemon report “admin-up only” and do not claim connectivity.

### 6.2 Simulated netlink events (unit/integration)

**Unit tests (MockNetOps):**
- Extend `MockNetOps` to model:
  - rfkill blocked state
  - admin transitions with delays/timeouts
  - DHCP acquisition failures/timeouts
  - netlink errors on bring_up/down
- Add tests for:
  - strict isolation ordering (should not create overlap)
  - selection rollback ordering (should not create overlap)
  - hotspot exception allow-set enforcement

**Integration tests (Linux netns / dummy links):**
- Use an isolated network namespace and dummy/veth interfaces to simulate:
  - link flaps
  - route changes
  - daemon restarts mid-switch  
  Validate that watcher converges to the correct single-interface state without introducing overlap.

### 6.3 SSH safety checks (trusted requirement)
From `TESTING.md`:
- Ensure the suite detects the current SSH uplink and **skips** switching away by default.
- Add an explicit test case to verify this detection remains correct after:
  - interface renaming
  - default route changes
  - DHCP renew events

### 6.4 Crash/restart scenarios
Run (automated if possible):
- Crash during:
  - immediately after target-up (pre-fix: overlap window)
  - mid-deactivation
  - mid-rollback
- On restart, assert:
  - watcher converges to compliant state
  - preference state matches last known good switch or clearly indicates “incomplete transaction”

### 6.5 Hotspot exception scenarios
- Start hotspot (AP + upstream).
- Trigger watcher events (link/route changes) and confirm it maintains exactly the allowed set.
- Restart daemon and confirm hotspot exception persists (this requires implementing persistence).

---

## Appendix A — Minimal “fixed” state machine sketch (non-code)

A safe, continuously enforced interface switch transaction should follow:

1. **Preflight**: validate target exists; for wireless, verify not hard-blocked; determine rollback snapshot.
2. **Isolate**: bring all non-target uplinks DOWN; rfkill-block non-selected wireless; wait until down/blocked.
3. **Activate target**: bring target UP; if wireless, rfkill-unblock; wait admin-UP.
4. **Configure (optional)**: DHCP/route/DNS only if required by mode and interface type.
5. **Verify**: assert invariant set (single admin-UP; rfkill; route/DNS as required).
6. **Persist**: write preference only after verification.
7. **Rollback on any failure**: first restore invariant safety (no overlap), then restore previous as needed.

---

## Appendix B — Key “safety enforcement points” map

- **Core switch job:** `interface_selection.rs`
  - should be the strongest invariant enforcer for UI operations.
- **Background convergence:** `netlink_watcher.rs` + `IsolationEngine`
  - should never claim compliance without invariant verification.
- **Isolation helpers:** `system/mod.rs`
  - strict path should be reorder-fixed and require single-target policy unless hotspot exception is explicitly active.

---

*End of report.*
