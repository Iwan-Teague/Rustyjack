# Rustyjack (Pi Zero 2 W) — Offensive Ops & Workflow Deep Dive  
**Snapshot reviewed:** `watchdog_shallow_20260204-175618.zip` (Feb 4, 2026)  
**Reviewer stance:** Senior Rust networking dev doing a *code/architecture audit*.

> **Safety / scope note:** I can help you **verify what exists**, **judge whether it can run on the stated hardware**, and **suggest robustness + safety improvements** (capability detection, cleanup, audit trails, privilege boundaries, UX).  
> I **will not** provide instructions to add or optimize disruptive/credential-capture attacks against networks you don’t own or don’t have explicit permission to test.

---

## 0) Executive summary (the “surprises first” section)

### What you *thought* was missing (e.g., deauth) is actually present
Your repo already contains implementations and UI/CLI plumbing for multiple “offensive” Wi‑Fi operations, including:
- Deauthentication (“deauth”) + handshake capture
- Evil Twin
- PMKID capture
- Probe sniffing
- Karma
- Handshake/PMKID cracking helpers

**Where:**  
- Core dispatcher: `crates/rustyjack-core/src/operations.rs` (handlers like `handle_wifi_deauth`, `handle_wifi_evil_twin`, …)  
- Native Wi‑Fi backend: `crates/rustyjack-core/src/wireless_native.rs` + `crates/rustyjack-wireless/*`  
- UI wizard wiring: `crates/rustyjack-ui/src/ops/*` and parts of `crates/rustyjack-ui/src/app/*`

### The big practical blocker for “Pi Zero 2 W only”
Your own README explicitly states:

> “Built-in Cypress/Infineon radio cannot monitor/inject; all wireless attacks require an external adapter that supports monitor + injection.”

So if your goal is *strictly* “no external Wi‑Fi adapter”, the current repo’s design intent conflicts with that goal.  
Even if some monitor/injection can be enabled by patched firmware on some Pi builds, **that’s outside Rustyjack’s direct control** (kernel driver + firmware capability governs it).

### Your “all ops go through the same wizard” hypothesis is basically correct
The UI has an `Operation` trait and a single `OperationRunner` that provides a consistent flow:

**preflight → setup → confirm → run (job) → results**

**Where:**  
- `crates/rustyjack-ui/src/ops/mod.rs` (`Operation`, `OperationContext`, `OperationOutcome`)  
- `crates/rustyjack-ui/src/ops/runner.rs` (the runner/wizard)  
- `crates/rustyjack-ui/src/ops/shared/jobs.rs` (job dispatch + cancel loop)

---

## 1) Architecture / workflow: what actually happens when you “run an operation”

### 1.1 The process model (who runs as root, who doesn’t)
- **UI service** is intended to be unprivileged (`services/rustyjack-ui.service`).
- **Daemon** is privileged and performs system/network operations (`services/rustyjackd.service`).
- A separate **portal service** exists for captive portal features (`services/rustyjack-portal.service`).

This is good practice: it’s privilege separation. It also means your “only one program runs” goal is *not literally true*, but **the running services are still “authorized by the project.”**

### 1.2 The operation “wizard” is real and mostly unified
The UI uses a common runner:
- Each operation implements `Operation` (title, preflight, setup, confirm, run, render results).
- `OperationRunner::run()` executes those steps in a standard order and handles navigation.

**Confirmed:** Most operations go through that runner.  
**Caveat:** There is still some legacy-style UI logic in `crates/rustyjack-ui/src/app/*` that directly dispatches commands; it largely *coexists* with the `ops/*` pattern.

### 1.3 The “job” model is the execution backbone
UI → daemon uses IPC jobs:
- UI starts a core command (`start_core_command`)
- polls job status (`job_status`)
- supports cancellation (`cancel_job`) with a small wait loop

**Where:** `crates/rustyjack-ui/src/ops/shared/jobs.rs`

---

## 2) Offensive Wi‑Fi operations audit (existence + viability + issues)

Below I treat each operation as **(A) does it exist? (B) will it work on “Pi Zero 2 W only”? (C) what problems did I find?**

### 2.1 Wi‑Fi Deauth + handshake capture

#### Does it exist?
✅ Yes.

**Where:**
- UI: `crates/rustyjack-ui/src/ops/wifi.rs` (deauth op) and also legacy flow in `crates/rustyjack-ui/src/app/wifi/attacks.rs`
- Core handler: `crates/rustyjack-core/src/operations.rs` (`handle_wifi_deauth`)
- Backend: `crates/rustyjack-core/src/wireless_native.rs` calling into `crates/rustyjack-wireless/src/deauth.rs` / `inject.rs` etc.

#### Will it work on “Pi Zero 2 W only”?
**Usually not on stock Pi OS + stock firmware**, because the built‑in radio/driver frequently lacks usable monitor/injection support (your README also claims it cannot).  
Even where monitor mode exists, injection may not—**and your current detection tends to over-claim injection** (see problem below).

#### Problem A: Injection capability is inferred too optimistically
- **Is it a problem?** Yes.
- **Why it’s a problem:** UI preflight can report “injection supported” for adapters that merely support monitor mode, causing user confusion and wasted runs.
- **Where:** `crates/rustyjack-wireless/src/nl80211_queries.rs` (`query_interface_capabilities`) and `crates/rustyjack-core/src/wireless_native.rs` (`check_capabilities`)
- **What exactly:** `supports_injection = supports_monitor` is a heuristic that is **false** on some “FullMAC” devices (notably `brcmfmac` class).
- **How to fix (safe + robust):**
  1. Treat injection as **unknown/false by default**, then enable it only when:
     - The driver/chipset is on a known-good allowlist, *or*
     - A non-destructive, local self-test proves TX of raw frames is possible (a capability probe, not an attack).
  2. Add a **driver blacklist**: if driver is `brcmfmac` and no patched firmware flag is present, force `supports_injection = false`.
  3. Add UI copy that explains: “monitor ≠ injection.”
- **What “fixed” looks like:** Preflight blocks disruptive ops on unsupported hardware with a clear message, instead of letting them fail mid-run.
- **End result:** Dramatically fewer false starts, less operator confusion, more deterministic behavior.

#### Problem B: Two different gating systems can confuse operators
- **Is it a problem?** Mildly, yes (UX/consistency).
- **Why:** The UI blocks active ops in Stealth mode, but the core also requires a local artifact file to exist for “offensive review approval”.
- **Where:**  
  - UI stealth checks: `crates/rustyjack-ui/src/ops/shared/preflight.rs` (`require_not_stealth`)  
  - Core “review file” gate: `crates/rustyjack-core/src/operations.rs` (`offensive_review_approved`, `REVIEW_APPROVED.md`)
- **What specifically:** You can pass UI preflight but still be blocked by the daemon if the review file isn’t present (or vice-versa).
- **How to fix:** Make the daemon return a structured “authorization required” status that the UI displays consistently, and unify the user-facing messaging.
- **Fixed result:** Operators always understand whether a block is due to stealth mode, missing privileges, missing capabilities, or missing authorization.

---

### 2.2 Evil Twin

#### Does it exist?
✅ Yes.

**Where:**
- UI: `crates/rustyjack-ui/src/ops/wifi.rs`
- Core: `crates/rustyjack-core/src/operations.rs` (`handle_wifi_evil_twin`)
- Backend: `crates/rustyjack-wireless/src/evil_twin.rs` + `rustyjack-netlink` AP/DHCP/DNS/nftables pieces

#### Will it work on “Pi Zero 2 W only”?
**Partially**, depending on whether the adapter supports AP mode and whether the implementation assumes multiple interfaces for simultaneous behaviors.

#### Problem: Resource model vs isolation model conflict
- **Is it a problem?** Yes (architectural correctness).
- **Why:** Some “multi-role” wireless flows implicitly want **two radios** (AP + monitor/injection), but the system aggressively enforces “single interface isolation”.
- **Where:**  
  - Enforcement: `crates/rustyjack-core/src/system/mod.rs` (`enforce_single_interface`)  
  - Evil Twin handler calls `enforce_single_interface` early: `crates/rustyjack-core/src/operations.rs`
- **What specifically:** If an operation requests multiple interfaces (or wants a mix of interface modes), the current isolation behavior can break it or produce confusing failures.
- **How to fix (safe):**
  1. Introduce an explicit **Operation Resource Request** model:
     - “Needs {wifi: monitor}” / “Needs {wifi: AP}” / “Needs {wifi: 2 interfaces}”
  2. Teach isolation to allow the minimal set of interfaces requested, and deny with a clear explanation if the hardware can’t satisfy the request.
- **What fixed looks like:** Evil Twin (and similar multi-role ops) either:
  - run in a “single-radio safe mode” with limited functionality, or
  - fail fast with a crisp “requires 2 Wi‑Fi interfaces” message.
- **End result:** No more mysterious failures caused by isolation rules contradicting operation needs.

---

### 2.3 PMKID capture

#### Does it exist?
✅ Yes.

**Where:** `crates/rustyjack-core/src/operations.rs` (`handle_wifi_pmkid_capture`) and `crates/rustyjack-wireless/src/pmkid.rs`

#### Will it work on “Pi Zero 2 W only”?
Depends on how capture is performed. Your implementation strongly leans on monitor mode. If the adapter can’t do monitor mode, this will fail.

#### Problem: Preflight is too permissive compared to actual runtime requirements
- **Is it a problem?** Yes.
- **Why:** UI preflight for PMKID capture (`pmkid_capture`) only checks “is wireless” but not “supports monitor”, but the backend expects monitor mode in parts of the logic.
- **Where:** `crates/rustyjack-ui/src/ops/shared/preflight.rs` (`pmkid_capture`) vs backend requirements in `crates/rustyjack-wireless/*`
- **What:** The UI can allow the user into a run that will fail later on adapters lacking monitor mode.
- **How to fix:** Align preflight to the backend’s actual requirements (even if you add a “passive-only” mode that truly doesn’t require monitor).
- **End result:** PMKID capture behaves predictably across hardware.

---

### 2.4 Probe sniff

#### Does it exist?
✅ Yes.

**Where:** `handle_wifi_probe_sniff` + `crates/rustyjack-wireless/src/probe.rs`

#### Will it work on “Pi Zero 2 W only”?
If monitor mode works, sniffing generally has the best chance of succeeding because it doesn’t inherently require injection.

#### Problem: User expectation mismatch (“passive” vs “active”)
- **Is it a problem?** Potentially.
- **Why:** Users may treat “probe sniff” as passive/low-risk, but monitor-mode collection can still be sensitive; it also depends on hardware mode changes.
- **Where:** UI exposure and mode presets (`operation_mode` logic)
- **Fix:** Make a clear “passive recon” mode that:
  - never transmits,
  - refuses to toggle interface modes that break connectivity unless explicitly confirmed,
  - writes clearly labeled artifacts.
- **End result:** Reduced risk of accidental disruption.

---

### 2.5 Karma

#### Does it exist?
✅ Yes.

**Where:** `handle_wifi_karma` + `crates/rustyjack-wireless/src/karma.rs`

#### Will it work on “Pi Zero 2 W only”?
Often not, because these flows usually require both capturing and transmitting crafted management frames (hardware/driver-dependent).

#### Problem: Capability model doesn’t express “TX in monitor mode”
- **Is it a problem?** Yes.
- **Why:** “monitor supported” isn’t enough; you need a capability that represents “can transmit in the required mode.”
- **Where:** `InterfaceCapabilities` currently has `supports_monitor` and `supports_injection`, but injection is not truly detected.
- **Fix:** See the injection-detection fix above; also consider adding a more explicit capability (e.g., `supports_tx_in_monitor`), so UI copy is accurate.
- **End result:** Karma becomes a “supported/unsupported” feature by hardware, not a roulette wheel.

---

### 2.6 Crack (offline)

#### Does it exist?
✅ Yes.

**Where:** `handle_wifi_crack` + `crates/rustyjack-wpa/*` and wordlists under `wordlists/`

#### Will it work on “Pi Zero 2 W only”?
Yes, as long as you can capture or import the needed artifacts and have CPU budget (Pi Zero 2 W is limited).

#### Problem: UX/compute budget on Zero 2 W
- **Is it a problem?** Sometimes.
- **Why:** Offline cracking is CPU-heavy; running it on-device can freeze UI responsiveness if not isolated.
- **Where:** daemon job execution model + UI polling
- **Fix:** Ensure cracking runs at reduced priority / with time budgeting, and provide “export for offline processing” as the default workflow.
- **End result:** UI stays responsive; operator gets predictable timing.

---

## 3) Ethernet “offensive” operations (high-level audit)

You have ethernet-side MITM and DNS spoof features in `crates/rustyjack-core/src/operations.rs` (ARP spoofing/capture orchestration) backed by `rustyjack-ethernet` + `rustyjack-netlink`.

Because these capabilities can also be used maliciously, I’m keeping this at *workflow + safety* level:

### Problem: Cleanup correctness must be treated as a first-class requirement
- **Is it a problem?** Yes (operational safety).
- **Why:** Ethernet MITM/DNS spoof typically modifies:
  - ARP state (poisoning)
  - IP forwarding toggles
  - nftables NAT/redirect rules
  - local DNS service state
  If cleanup is partial, the Pi can remain in a broken networking state or continue interfering after “stop.”
- **Where:** MITM start/stop logic in core operations; nftables via `rustyjack-netlink`.
- **Fix:** Make every operation implement a “transaction” model:
  - Apply steps with a recorded rollback stack
  - Always rollback on error/cancel/panic (best-effort)
  - Emit an “environment restored” status at the end
- **End result:** “Stop” and “Cancel” always returns the Pi to a known good networking baseline.

---

## 4) Confirming your “single wizard” theory + how to improve it

### Confirmation
Yes: the UI’s `OperationRunner` is the central “wizard” for most operations. It standardizes:
- preflight checks (mode, privileges, capabilities, required fields)
- setup prompts / parameter selection
- a confirm screen
- a cancellable run loop
- a results view

### Improvements (productivity + correctness)

#### Improvement A: Make operation resource requirements explicit
Right now, each operation ad-hoc checks capabilities and then calls `enforce_single_interface`.  
Instead, add a per-operation declaration:

```text
needs:
  - wifi: monitor
  - wifi: injection (optional)
  - wifi: ap (optional)
  - privileges: CAP_NET_ADMIN
  - storage: loot write
```

Then have a shared resolver that:
- chooses interface(s),
- validates capabilities,
- enforces isolation with the chosen set,
- returns a structured “ready to run” plan.

**End result:** You eliminate duplicated preflight logic and prevent “operation says it needs two radios but isolation kills one.”

#### Improvement B: One schema for “results data”
Operations return JSON-ish `data` blobs today. That’s flexible but leads to UI conditionals (lots of `data.get("foo")`).  
Instead:
- define typed result structs per operation in a shared crate (derive `Serialize`)
- include a stable `kind` + `version` field
- keep `extra` for forward-compatible fields

**End result:** fewer runtime “missing key” failures; easier UI evolution.

#### Improvement C: Unify legacy app flows with `ops/*`
You have both:
- direct command dispatch flows under `crates/rustyjack-ui/src/app/*`
- the more structured `ops/*` model

Pick one pattern (I’d pick `ops/*`) and migrate fully.  
**End result:** less duplicated UI logic, fewer subtle mismatches in preflight/confirm.

---

## 5) The “Pi Zero 2 W only” reality check (what to do with the mismatch)

### Is it a problem?
Yes — at least from a product-truth perspective.

### Why it’s a problem
Your current repo messaging + code suggests:
- the *target hardware is a Pi Zero 2 W*, but
- several wireless operations assume monitor/injection support that is commonly unavailable on the onboard radio (and your README says it is unavailable).

### Where
- README “Architecture” and “Wireless Access” sections
- capability heuristics in `crates/rustyjack-wireless/src/nl80211_queries.rs`

### What to do (safe framing)
1. Decide which of these is the real goal:
   - **A.** “Pi Zero 2 W only, no external Wi‑Fi adapter”  
   - **B.** “Pi Zero 2 W base platform, external adapter allowed for certain features”
2. If **A**, then:
   - treat most “attack” features as **conditionally unsupported** by default,
   - emphasize passive recon + ethernet ops,
   - add explicit documentation stating wireless attack features require firmware/driver capability that may not exist on stock builds.
3. If **B**, keep current but make hardware requirements explicit in UI.

### End result
Operators know, ahead of time, what will actually work on the specific device image/driver stack they’re running.

---

## 6) References (external, for grounding claims)

I’m including these as plain URLs in a code block so the `.md` remains self-contained:

```text
Linux wireless subsystem documentation (cfg80211/nl80211/mac80211):
https://wireless.docs.kernel.org/en/latest/

Protected Management Frames (802.11w) overview and protected frame types (incl. deauth/disassoc):
https://www.cisco.com/c/en/us/support/docs/wireless-mobility/wireless-lan-wlan/212576-configure-802-11w-management-frame-prote.html
https://documentation.meraki.com/Wireless/Design_and_Configure/Architecture_and_Best_Practices/802.11w_Management_Frame_Protection_MFP

Kali discussion of Nexmon-based monitor mode / injection support on Raspberry Pi onboard Wi‑Fi:
https://www.kali.org/blog/raspberry-pi-wi-fi-glow-up/
https://github.com/seemoo-lab/bcm-rpi3
```

---

## 7) What I would do next (practical, non-harmful engineering plan)

1. **Fix capability detection** (separate monitor vs injection; blacklist `brcmfmac` unless explicitly patched).
2. Add **Operation Resource Requests** and centralize the “plan + isolate” logic.
3. Build a **cleanup transaction framework** for all ops that mutate system networking.
4. Consolidate UI flows to a single `ops/*` architecture.
5. Add “hardware profile” reporting to the dashboard (driver, phy, modes supported) so reality is obvious.

---

*End of report.*
