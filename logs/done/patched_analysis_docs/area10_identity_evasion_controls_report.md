# Area 10 — Identity & evasion controls (Architecture Doc 2)

**Repository snapshot:** `watchdog_shallow_20260213-173640.zip` (extracted read-only)  
**Report date:** 2026-02-14  
**Scope:** MAC randomization/restore, hostname changes, TX power controls, passive/stealth mode toggles, persistence rules, and interactions with interface switching + rfkill.  
**Non-goal:** operational “how-to” for evasion. This report focuses on correctness, state management, and truth-in-UI.

## Trusted definitions & constraints (must drive wording and behavior)

The codebase treats “evasion/identity hardening” as **fingerprint reduction and UI/UX guardrails**, not as a guarantee of invisibility. The trusted docs emphasize:
- **Truth-in-UI:** avoid implying “stealth” beyond what code can actually enforce (especially “no TX” / “RF silent” claims).
- **Isolation invariant awareness:** identity changes should not accidentally violate the “only allowed interfaces admin-up” policy.
- **Restore semantics matter:** “restore” must be well-defined, and **stale restore** (restoring an identity captured for a different physical device/session) must be prevented.

Primary in-repo trusted sources:
- `logs/done/evasion_identity_controls.md`
- `logs/done/crate_rustyjack_evasion.md`
- `logs/done/interface_isolation_overview.md`

---

## 1) State model

This area touches multiple “identity-like” knobs that live in different layers:

### 1.1 MAC address (per-interface identity)

**Observed implementations / stores:**

1) **Core command handlers** (runtime, no persistence):
- Randomize: `crates/rustyjack-core/src/operations.rs` → `handle_wifi_mac_randomize` (≈L6002) calls `MacManager::set_mac` and returns `{original_mac, randomized_mac, ...}`.
- Restore: `handle_wifi_mac_restore` (≈L6117) sets the MAC to a *caller-supplied* `original_mac`.

2) **Evasion crate in-memory state** (per-interface, process lifetime):
- `crates/rustyjack-evasion/src/mac.rs`
  - `MacManager` holds a `HashMap<String, MacState>` keyed by interface name.
  - State contains `{ original_mac, current_mac }` captured from *current MAC at time of first change*, not from a permanent hardware identity.
  - **Restore semantics (manager-local):** `restore(&mut self, interface)` sets MAC back to recorded `original_mac`.

3) **UI persistence** (per-interface, across UI restarts):
- `crates/rustyjack-ui/src/config.rs` → `SettingsConfig` (≈L47) persists:
  - `original_macs: HashMap<String, String>`
  - `current_macs: HashMap<String, String>`
  - `per_network_macs: HashMap<String, HashMap<String, String>>`

**Key state questions and current answers:**
- **Original identity capture:** today it means “the MAC address present when *Rustyjack first changed it in this session*” (MacManager) or “whatever the UI last stored as original” (GUI config).
- **Per-interface vs global:** MAC is per-interface everywhere, but identity records are keyed **only by interface name**, not by a stable hardware fingerprint.
- **Restore semantics:** “restore” means “set MAC to some previously captured value” — but whether that value is truly the *permanent* MAC is not verified.

**Stale restore risk (high):**
If the physical device behind `wlan0` changes (USB adapter swap, udev renaming, driver resets, etc.), stored “original_macs[wlan0]” may refer to a different NIC. Current code does not guard against that.

---

### 1.2 Hostname (global identity)

**Implementation:**
- Core: `crates/rustyjack-core/src/system/mod.rs` → `randomize_hostname` (≈L357)
  - Picks a hostname using time + PID-derived hex suffix.
  - Calls `sethostname(2)` and writes `/etc/hostname`.

**State model:**
- **Original capture:** not implemented.
- **Restore semantics:** not implemented.
- **Persistence:** written to `/etc/hostname` (survives reboot).

This makes hostname “one-way” in practice unless an operator manually restores it.

---

### 1.3 TX power (per wireless interface)

There are *two* overlapping implementations:

1) **Core command:**
- `crates/rustyjack-core/src/operations.rs` → `handle_wifi_tx_power` (≈L6249)
  - Uses `rustyjack_netlink::WirelessManager::set_tx_power_dbm(...)`.
  - Does not capture original TX power.
  - No restore command path exists.

2) **Evasion crate:**
- `crates/rustyjack-evasion/src/txpower.rs`
  - Tracks `{ interface, original_dbm, current_level }` in an in-memory vector.
  - Provides `restore(&mut self, interface)` (≈L177).

**State model issues:**
- **Original capture is unreliable**: `get_power()` falls back to `20 dBm` on read failure.
- **Restore logic is currently incorrect** (see Findings).

---

### 1.4 Passive / “stealth” modes (behavioral, not a single knob)

**What exists:**
- UI has an “operation mode” toggle that sets `passive_mode_enabled` + `tx_power_level` and blocks some UI actions (`mode_allows_active` in `identity.rs` ≈L266).
- UI has a stubbed “Passive recon” launcher that explicitly states it is not implemented.
- Evasion crate has a `PassiveManager` that creates a monitor interface and can set TX power on it (`crates/rustyjack-evasion/src/passive.rs`).

**What does *not* exist (yet) as enforceable guarantees:**
- A system-wide, verified “no transmissions” mode.
- A unified policy that prevents other subsystems from transmitting while “passive/stealth” is enabled.

So “stealth” is currently best understood as:
- **UI gating + preferred settings**, not an RF guarantee.

---

### 1.5 Interface switching + rfkill (cross-cutting)

**Interface switching:**
- Core stores a preference file via `write_interface_preference` (system mod ≈L48).
- UI stores a separate `active_network_interface` inside `gui_conf.json` and does not necessarily call the core “switch” command.

**rfkill + isolation:**
- The isolation engine (core system) can rfkill-block disallowed wireless interfaces.
- The daemon (`crates/rustyjack-daemon/src/netlink_watcher.rs`) enforces isolation reactively on events; if a monitor interface is created and not allowlisted, it may be brought down or blocked during enforcement.

Identity changes that bounce link state (MAC set, monitor interface creation, etc.) must be designed to **cooperate** with isolation/rfkill, or they will intermittently fail and/or violate invariants.

---

## 2) Randomness & correctness audit

### 2.1 MAC generation correctness

**What’s correct today:**
- Both core (`operations.rs`) and UI (`util.rs`) explicitly force:
  - Locally-administered bit set (0x02)
  - Unicast bit set (clear multicast bit 0x01)
- `rustyjack-evasion::MacAddress::random_with_oui` also applies those bits.

**What’s missing:**
- Collision avoidance across:
  - other local interfaces
  - prior randomized values in session
  - per-network stored values
- “Stale restore” safeguards (see below).

### 2.2 Hostname randomness

Hostname “randomization” uses time/PID-derived suffix (predictable-ish, and not uniform). This is fine for “avoid obvious default name” but is weaker than OS RNG and can correlate changes with boot timing.

### 2.3 TX power correctness

- Power is specified in dBm presets, but drivers/regulatory domains may clamp. Current UX should assume “requested” ≠ “actual” unless readback confirms.
- Current `get_power()` fallback (20 dBm) is dangerous as a “best guess”.

---

## 3) Side effects audit

### 3.1 MAC changes require link state changes

`MacManager::set_mac` currently forces:
- interface down
- MAC set
- interface up

This has side effects:
- disrupts connectivity
- may trigger supplicant/network-manager churn
- can violate isolation expectations if the interface was intentionally admin-down

Also, `set_mac_raw` calls into a netlink helper that itself brings the interface down again, causing redundant “down” operations.

### 3.2 Isolation invariant interactions

Isolation aims to keep non-allowed interfaces admin-down and rfkill-blocked (wireless). MAC operations that force “up” can accidentally bring a disallowed interface up, even briefly.

### 3.3 Monitor interface creation is “new interface surface area”

Monitor interfaces:
- may not be in allowlists
- may be seen as a second “wireless interface” by enforcement loops
- may remain admin-up beyond intended lifetime if error paths skip cleanup

### 3.4 Hostname writes `/etc/hostname`

This persists across reboots. Without a captured “original hostname”, restore cannot be safe or automatic.

---

## 4) UX truthfulness audit

The code currently contains UI strings and status fields that can easily overclaim:

- **“NO transmissions” / “Zero transmission mode”** is not enforced end-to-end (UI stub exists; other subsystems can transmit; isolation passive mode is not RF silence).
- **“isolation_enforced: true”** is returned in places where enforcement is not actually performed (e.g., saving preference only).
- “Stealth mode” currently means “UI disables active operations + sets preferred knobs”, not “RF invisible”.

The UI should only claim:
- what is directly verified (e.g., “MAC set to X”, “requested TX power Y dBm; driver reports Z dBm”)
- what is a best-effort preference (e.g., “Passive mode requested; does not guarantee RF silence”)

---

## 5) Findings (20)

Each finding follows: **Problem → Why → Where → Fix → Fixed version looks like**.

### F01 — MAC “restore” can be stale (interface-name key is not a hardware identity)
- **Problem:** UI persists `original_macs` keyed only by interface name; restore sets that value blindly.
- **Why:** If the NIC behind `wlan0` changes, restore can write a foreign MAC to the new NIC (stale restore).
- **Where:** `crates/rustyjack-ui/src/config.rs` SettingsConfig `original_macs` (≈L47); UI restore path in `crates/rustyjack-ui/src/app/identity.rs` (MacRestore around ≈L1050+); core restore handler `handle_wifi_mac_restore` (≈L6117).
- **Fix:** Persist a **hardware fingerprint** alongside the saved “original”:
  - e.g., `{iface, sysfs_device_path, perm_mac_or_addr_assign_type, boot_id, captured_at}`.
  - On restore: verify fingerprint matches current interface; otherwise refuse/recapture.
- **Fixed version looks like:** Restore UI says: “Original MAC recorded for adapter X; current adapter differs; restore disabled until recaptured.”

### F02 — MAC set forces interface **up** even if it started **down**
- **Problem:** `MacManager::set_mac` always calls `interface_up` at the end.
- **Why:** This can violate isolation intent and can trigger transmissions or network-manager actions.
- **Where:** `crates/rustyjack-evasion/src/mac.rs` `set_mac` (≈L75).
- **Fix:** Capture `was_up` at entry; restore original admin state on exit:
  - If it was down, leave it down after MAC change.
- **Fixed version looks like:** “MAC updated; interface remained admin-down (as before).”

### F03 — MAC state is recorded even if the set fails
- **Problem:** `MacManager` inserts a state entry before attempting the set; on failure, `is_active()` becomes true.
- **Why:** UI/logic can think “randomization is active” even though no change occurred.
- **Where:** `crates/rustyjack-evasion/src/mac.rs` `set_mac` (≈L75).
- **Fix:** Only insert/commit state after successful set (or mark as `pending` and clear on error).
- **Fixed version looks like:** Failed MAC set leaves no “active” state and surfaces the error.

### F04 — Redundant “link down” calls during MAC set
- **Problem:** `MacManager::set_mac` brings link down, then `set_mac_raw` calls a helper that brings it down again.
- **Why:** Extra churn increases flakiness across drivers; error handling becomes harder.
- **Where:** `crates/rustyjack-evasion/src/mac.rs` `set_mac` (≈L75) and `set_mac_raw` (≈L143); `crates/rustyjack-netlink/src/interface.rs` `set_mac_address` brings link down internally.
- **Fix:** Make exactly one layer responsible for link transitions (preferably the MAC manager) and ensure helpers do not duplicate.
- **Fixed version looks like:** Single down → set → (optional) up transition, with clear error semantics.

### F05 — No collision avoidance for generated MACs
- **Problem:** MAC generators do not check for collisions with local interfaces or prior values.
- **Why:** Collisions can break LAN connectivity or cause confusing behavior.
- **Where:** `crates/rustyjack-core/src/operations.rs` `generate_vendor_aware_mac` (≈L1138); `crates/rustyjack-ui/src/util.rs` same-named function (≈L66); `crates/rustyjack-evasion/src/mac_policy.rs` stable/hashed MAC generation.
- **Fix:** Before applying:
  - collect all current interface MACs via netlink/sysfs
  - reject duplicates; resample
  - optionally keep a short “recently used” set per boot
- **Fixed version looks like:** “MAC randomized after 1–N attempts; guaranteed not to match any local interface.”

### F06 — Duplicate MAC generation logic across crates
- **Problem:** Three places generate MACs (core, UI, evasion) with overlapping but not identical behavior.
- **Why:** Divergence leads to inconsistent bits, OUIs, lifetimes, and test coverage gaps.
- **Where:** core `operations.rs` (≈L1138), UI `util.rs` (≈L66), evasion `mac.rs` / `mac_policy.rs`.
- **Fix:** Consolidate into a single library function (ideally in `rustyjack-evasion`) and reuse everywhere.
- **Fixed version looks like:** One MAC generation API with unit tests for bit correctness + collision avoidance.

### F07 — Core MAC restore does not mirror preconditions used for randomize
- **Problem:** Randomize stops hotspot/disconnects first; restore does not.
- **Why:** Restore may fail or produce inconsistent state when Wi-Fi/AP is active.
- **Where:** `handle_wifi_mac_randomize` (≈L6002) vs `handle_wifi_mac_restore` (≈L6117).
- **Fix:** Restore should:
  - stop hotspot if needed
  - disconnect before change
  - optionally reconnect after
- **Fixed version looks like:** Restore behaves symmetrically with randomize.

### F08 — Hostname randomization is one-way (no original capture, no restore)
- **Problem:** No stored “original hostname”; no restore command.
- **Why:** Can’t safely undo; also complicates “stealth mode” expectations.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` `randomize_hostname` (≈L357); `operations.rs` `handle_randomize_hostname` (≈L5832).
- **Fix:** Capture original hostname once (with fingerprint + boot_id), store in state file, add restore command.
- **Fixed version looks like:** UI shows “Original hostname saved; restore available” and “restored successfully”.

### F09 — Hostname randomness uses time/PID instead of OS RNG
- **Problem:** Suffix is derived from epoch nanos + PID hash.
- **Why:** Predictable-ish; correlates with boot timing.
- **Where:** `randomize_hostname` (≈L357).
- **Fix:** Use OS RNG (`getrandom`) to generate suffix; keep word prefix list if desired.
- **Fixed version looks like:** Hostname changes are not trivially correlated with time.

### F10 — TX power in core has no state capture or restore path
- **Problem:** Core can set TX power, but cannot restore.
- **Why:** “Stealth/low power” becomes sticky and surprises users; truth-in-UI suffers.
- **Where:** `handle_wifi_tx_power` (≈L6249); UI settings `tx_power_level` persisted but not consistently applied/restored.
- **Fix:** Introduce a TX power state store:
  - capture original per interface (with fingerprint)
  - apply requested power
  - restore on exit / on crash recovery
- **Fixed version looks like:** “TX power restored to previous value” after operations, even across partial failures.

### F11 — Evasion TxPowerManager restore is logically broken (re-records state)
- **Problem:** `restore()` removes state, then calls `set_power(...)`, which creates a *new* state record using the pre-restore value as “original”.
- **Why:** Next restore can flip back to the wrong value (classic stale restore pattern).
- **Where:** `crates/rustyjack-evasion/src/txpower.rs` `restore` (≈L177) calling `set_power` (≈L92).
- **Fix:** Add `set_power_raw()` used by restore that does not touch state; or add a `record_state: bool` flag.
- **Fixed version looks like:** After restore, no leftover TX power state exists for that interface.

### F12 — TxPowerManager records state before confirming the set succeeded
- **Problem:** State is pushed before netlink operations.
- **Why:** Failed set leaves state claiming a change was made.
- **Where:** `txpower.rs` `set_power` (≈L92).
- **Fix:** Only record state after successful set, or rollback on error.
- **Fixed version looks like:** Failed TX set leaves no “active” state; UI surfaces error cleanly.

### F13 — TxPowerManager `get_power()` returns a hardcoded fallback (20 dBm) on error
- **Problem:** Read failures turn into “20 dBm”.
- **Why:** Restores can set an arbitrary value; UI misleads.
- **Where:** `txpower.rs` `get_power` (≈L70).
- **Fix:** Return `Option<i32>` / explicit error; require readback for restore eligibility.
- **Fixed version looks like:** UI: “Original TX power unknown; restore disabled (safe default).”

### F14 — “Passive recon” UI path is a stub but claims “NO transmissions”
- **Problem:** `launch_passive_recon` shows strong claims; code is not implemented.
- **Why:** Violates truth-in-UI.
- **Where:** `crates/rustyjack-ui/src/app/identity.rs` `launch_passive_recon` (≈L350).
- **Fix:** Either:
  - remove/disable the menu entry, or
  - change copy to “not implemented”, or
  - implement and *verify* “no active operations invoked”.
- **Fixed version looks like:** No claims beyond what is enforced; if stub, it says so.

### F15 — “Stealth mode” is mainly UI gating, not an enforceable RF guarantee
- **Problem:** Operation mode sets preferences and blocks menu items, but does not enforce “RX-only”.
- **Why:** Other components can transmit; CLI can bypass UI gating.
- **Where:** `identity.rs` operation mode selection (≈L392) + `mode_allows_active` (≈L266); daemon isolation passive mode does not imply RF silence.
- **Fix:** Treat “stealth mode” copy as “UI safety mode” unless a system-wide enforcement mechanism exists.
- **Fixed version looks like:** UI copy: “Restricts active operations in the UI; does not guarantee RF silence.”

### F16 — Monitor interface lifecycle may conflict with isolation enforcement
- **Problem:** PassiveManager creates `wlan0mon` and can bring it up; isolation enforcement may later bring it down if not allowlisted.
- **Why:** Flaky passive workflows; hard-to-debug failures.
- **Where:** `crates/rustyjack-evasion/src/passive.rs` (monitor creation), `crates/rustyjack-daemon/src/netlink_watcher.rs` enforcement path.
- **Fix:** When enabling monitor:
  - extend allowlist to include monitor interface
  - mark it as a child of base iface
  - ensure cleanup on all error paths
- **Fixed version looks like:** Monitor survives enforcement during its intended lifetime and is reliably removed afterward.

### F17 — Interface switching “source of truth” is split (UI vs core)
- **Problem:** UI uses `active_network_interface` in gui config; core uses `wifi/interface_preference.json`.
- **Why:** Confusing behavior; identity settings may apply to a different interface than isolation/policy expects.
- **Where:** UI settings in `crates/rustyjack-ui/src/app/settings.rs` (writes UI config only); core preference in `crates/rustyjack-core/src/system/mod.rs` `write_interface_preference` (≈L48).
- **Fix:** Make one source authoritative and synchronize:
  - UI should call core switch, or core should read UI config (pick one).
- **Fixed version looks like:** Changing interface in the UI deterministically changes the interface used by all subsystems.

### F18 — Core Wifi “Switch” reports isolation enforced when it isn’t
- **Problem:** Response includes `isolation_enforced: true` even though only preference is written.
- **Why:** Violates truth-in-UI and breaks troubleshooting.
- **Where:** `crates/rustyjack-core/src/operations.rs` `handle_wifi_switch` (≈L3118).
- **Fix:** Either:
  - actually enforce isolation immediately, or
  - change response to `preference_saved: true` and note enforcement timing.
- **Fixed version looks like:** UI can display accurate status: “preference saved; will apply on next enforcement tick.”

### F19 — Persistence model lacks “session/boot” invalidation (stale restore amplifier)
- **Problem:** Identity state in UI persists across reboots without a boot/session key.
- **Why:** After reboot, the system returns to permanent MAC, but UI can think “randomization active” or offer stale restore paths.
- **Where:** `gui_conf.json` values loaded by UI; no `boot_id`/timestamp fencing.
- **Fix:** Store `boot_id` at capture time; on load, invalidate state if boot_id differs, or re-verify by reading current state.
- **Fixed version looks like:** After reboot, UI shows “No active MAC override detected.”

### F20 — Partial failure paths can leave “half applied” identity changes
- **Problem:** Several operations ignore certain failures (e.g., interface_up errors) or clear UI state on partial success.
- **Why:** Users see “restored” but the interface may be down or rfkill-blocked; state becomes desynced.
- **Where:** `identity.rs` restore path clears maps after command success; `MacManager::restore` ignores interface_up errors; TX power set records state early.
- **Fix:** Treat identity changes as a transaction:
  - apply → verify → commit state
  - on partial failure, do not clear state; show “needs recovery”
- **Fixed version looks like:** UI shows “Restore partially failed; click ‘Recover’” and recovery is safe/idempotent.

---

## 6) Test plan

Focus: interface switching, reboot, partial failures, restore-after-crash, stale restore prevention.

### 6.1 Harness assumptions
- Tests should run against a machine with:
  - at least one Wi-Fi interface (plus ideally a second Wi-Fi dongle for stale restore tests)
  - ability to toggle rfkill (hardware switch or software)
- Prefer integration tests that call the same Rust entrypoints as UI/core operations (not shelling out).

### 6.2 Core identity tests

1) **MAC randomize preserves admin state**
- Start with `wlan0` admin-down.
- Randomize MAC.
- Assert: `wlan0` remains admin-down; MAC changed (or operation refused if policy forbids).
- Repeat with admin-up and connected; assert reconnect behavior matches spec.

2) **MAC restore symmetry**
- With hotspot active: randomize then restore.
- Assert: restore stops hotspot/disconnects first; final MAC equals captured original; hotspot state handled as intended.

3) **Collision avoidance**
- Force generator to produce a collision (mock RNG or stub list of used MACs).
- Assert: generator retries and never applies a duplicate among local interfaces.

4) **Stale restore prevention**
- Record `original_macs[wlan0]` for adapter A.
- Swap adapters (or rename interfaces so A becomes `wlan1` and B becomes `wlan0`).
- Attempt restore on `wlan0`.
- Assert: restore is refused due to fingerprint mismatch; UI prompts recapture.

5) **Boot invalidation**
- Randomize MAC, then reboot.
- On startup, assert:
  - UI/state store detects mismatch (boot_id differs and/or current MAC equals perm MAC) and clears “active override”.

### 6.3 TX power tests

6) **Set → readback → restore**
- Capture original TX power (must be readback-confirmed, not guessed).
- Set to low value.
- Read back actual power; assert within expected clamp behavior.
- Restore; assert readback returns to original.

7) **Restore does not re-record state**
- Set power then restore.
- Assert: state store is empty after restore; second restore is a no-op.

8) **Error path safety**
- Simulate rfkill-block or driver refusing txpower set.
- Assert: state is not committed; UI shows failure and no “restore” is offered.

### 6.4 Passive/monitor + isolation tests

9) **Monitor interface allowlisting**
- Enable passive/monitor mode on `wlan0`.
- Assert: monitor interface exists and stays up through an isolation enforcement tick.
- Disable; assert: monitor removed; base interface state restored.

10) **Isolation interaction regression**
- While monitor exists, trigger daemon enforcement (netlink event).
- Assert: it does not down/block the monitor interface if policy says it’s allowed.

### 6.5 Crash / partial failure recovery tests

11) **Crash after down, before set**
- Inject crash between “link down” and “MAC set”.
- Restart; assert: recovery logic leaves interface in previous admin state, and does not apply stale restore.

12) **Crash after set, before up**
- Inject crash after MAC set but before restoring admin state.
- Restart; assert: recovery path restores admin state safely and updates state store accordingly.

13) **Partial restore failure**
- Force interface_up to fail (rfkill).
- Assert: restore reports partial failure; state remains and recovery is offered; no false “restored” messaging.

---

## Appendix — “Stale restore” prevention pattern (recommended)

A robust restore system needs:
- **Identity record:** `{ iface_name, device_fingerprint, captured_original_value, captured_at, boot_id }`
- **Validation:** refuse restore if fingerprint or boot_id mismatch, or if current state indicates “already restored”.
- **Transactions:** apply → verify → commit; on failure, keep enough state to safely retry or rollback.
- **Truthful UI:** show *measured* state, not just “requested” state.
