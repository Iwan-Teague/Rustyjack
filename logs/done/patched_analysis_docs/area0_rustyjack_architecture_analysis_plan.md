# RustyJack (Pi Zero 2 W) — Architecture & Deep‑Dive Analysis Plan
Date: 2026-02-13  
Repo snapshot: `watchdog/` workspace (Rust)

## 0) Scope, evidence model, and “trust rules”
This document is **an analysis plan**, not a verdict. It breaks the project into reviewable areas, lists the **constraints/invariants** that must hold, and defines what a good review of each area looks like.

### 0.1 What I treated as authoritative
Per your instruction, **constraints and “rules of the appliance” are taken only from**:
- **Doc files in the repository root** (e.g., `README.md`, `AGENTS.md`, `CLAUDE.md`, `TESTING.md`)
- **Doc files in `logs/done/`** (e.g., `interface_isolation_overview.md`, wireless/ethernet operation notes, display reports)

Everything else (Rust code, scripts, configs) is treated as *implementation evidence* of what the tool actually does.

### 0.2 What “deep dive” means here
For each area below, the analysis should answer:
- **What is the job?** (responsibilities + boundaries)
- **What are the invariants/constraints?** (global + area-specific)
- **Where is it implemented?** (crate/modules/paths)
- **How should it be tested?** (unit/integration/on-device)
- **What are modern, robust ways to do this?** (design alternatives, hardening patterns)
- **Where are likely weaknesses?** (security, correctness, reliability, performance)
- **Fix format** (mandatory):  
  **Problem → Why → Where → Fix → Fixed version looks like**

---

## 1) Project snapshot: what exists today (from the repo)
### 1.1 Hardware + OS target
- Dedicated **Raspberry Pi Zero 2 W** with Ethernet HAT + Waveshare LCD HAT (ST7735S default profile `128x128`).  
  (Root docs: `AGENTS.md`, `CLAUDE.md`)
- Runs as a dedicated appliance (network managers removed/disabled, device-owned DNS, etc.). (`AGENTS.md`)

### 1.2 High-level architecture
- **Unprivileged UI** (`rustyjack-ui`) talks to a **privileged daemon** (`rustyjackd`) over a Unix domain socket. (`CLAUDE.md`, `README.md`)
- Many functions are “pure Rust replacements” for common system tools: netlink/rtnetlink, nftables control, rfkill, DHCP/DNS, etc. (`CLAUDE.md`, `README.md`, code in `crates/rustyjack-netlink/`)

### 1.3 Workspace crates / major directories (where to look)
Workspace crates listed in root docs and `Cargo.toml`:
- Privilege + orchestration: `crates/rustyjack-daemon/`, `crates/rustyjack-core/`
- UI + device I/O: `crates/rustyjack-ui/`
- IPC: `crates/rustyjack-ipc/`, `crates/rustyjack-client/`, `crates/rustyjack-commands/`
- Networking primitives: `crates/rustyjack-netlink/`
- Wireless feature layer: `crates/rustyjack-wireless/`, `crates/rustyjack-wpa/`
- Ethernet feature layer: `crates/rustyjack-ethernet/`
- Captive portal: `crates/rustyjack-portal/`, templates in `DNSSpoof/`
- Identity/evasion: `crates/rustyjack-evasion/`
- Encryption: `crates/rustyjack-encryption/`
- Updates: `crates/rustyjack-updater/`
- Install/system integration: `install_*.sh`, `services/`, `scripts/`
- Quality gates: `ci/`

---

## 2) Global invariants (must hold across *all* areas)

### 2.1 Dedicated device ownership constraints
From `AGENTS.md` / `CLAUDE.md`:
- **NetworkManager is removed** (not just disabled). Don’t assume `nmcli` exists.
- RustyJack **claims `/etc/resolv.conf`** (symlink to `/var/lib/rustyjack/resolv.conf`) and disables competing DNS managers to ensure deterministic DNS control.
- Runs under systemd; privileged ops require `CAP_NET_ADMIN` / `CAP_NET_RAW` / `CAP_SYS_ADMIN`.

**Analysis focus:** confirm these assumptions are consistently true across code paths, install scripts, and runtime behaviors (including failure/rollback).

### 2.2 “Pure Rust / no external binaries” rule (with reality check)
Root docs assert the **principle**: avoid external binaries at runtime; implement operations natively in Rust.  
Reality check in `AGENTS.md` / `CLAUDE.md`: installers may still pull `wpa_supplicant`, `hostapd`, `dnsmasq`, `isc-dhcp-client` for compatibility.

**Analysis focus:**
- Identify all runtime code paths that can spawn external processes.
- Confirm “appliance” builds hard-disable those code paths (feature gating + CI checks).
- Ensure scripts are the only place external tooling is required (and still minimize it).

### 2.3 Interface isolation invariant (the big one)
From `logs/done/interface_isolation_overview.md` and `TESTING.md`:
- **Exactly one network uplink is allowed admin‑UP at steady state** (loopback excluded).
- All other interfaces must be forced **DOWN**.
- Wireless interfaces should be **rfkill soft-blocked** when not selected (where applicable).
- Switching should be **transactional** (rollback on failure) and UI must not claim success before verification.

**Analysis focus:** treat this as a “safety property” that is continuously enforced and must not be violated even under crashes, partial failures, or concurrent jobs.

### 2.4 UX / embedded constraints
From `AGENTS.md`, `logs/done/dynamic_display_resolution_implementation_report.md`, `logs/done/rustyjack_ui_theme_stabilization_implementation_2026-02-07.md`:
- Exactly **8 physical buttons**: no assumptions of touch/keyboard.
- Smallest supported target is **128×128** (best-effort below that with warnings).
- Display discovery/calibration: detect backend → query caps → calibrate only when needed → cache effective geometry; recalculation is manual.

### 2.5 Dangerous operations must be explicit + reversible when possible
From root docs and logs:
- FDE and system purge are **destructive and irreversible** → must be gated behind explicit confirmations and highly visible warnings.
- Network attacks / intrusive operations must be gated by operation mode / confirmation steps; a “Stealth” posture should be able to prevent active transmissions (`logs/done/evasion_identity_controls.md`).

---

## 3) Analysis area map (what to break the project into)
This is the proposed review decomposition. Each area is intentionally sized so you can:
1) understand it end-to-end,  
2) write targeted tests, and  
3) enforce constraints locally.

**Top-level areas:**
1. Platform & system integration (installers, services, filesystem ownership)
2. Privilege separation, IPC, authorization, job lifecycle
3. Interface isolation & interface selection state machine
4. Netlink networking primitives (links/routes/DNS/DHCP/ARP/rfkill/nftables)
5. Wireless operations layer (scan/capture/injection-dependent features)
6. Ethernet operations layer (discovery/scan + any MITM-related plumbing)
7. Identity & evasion controls (MAC/hostname/TX power/passive mode)
8. Captive portal + DNS spoof templates
9. Loot management + encryption + export
10. Updates & supply-chain integrity
11. Anti-forensics + destructive ops (secure delete/purge/FDE)
12. UI + display subsystem + GPIO input
13. Observability: logging, redaction, audit trails, telemetry
14. Quality gates: CI checks + test harnesses + on-device verification

The rest of this document expands each area into a detailed analysis plan.

---

## 4) Area 1 — Platform & system integration
### 4.1 Responsibilities
- Set up the device as a dedicated appliance.
- Install dependencies (temporarily, where unavoidable).
- Deploy services, users/groups, permissions.
- Ensure state directories exist and are writable where intended.

### 4.2 Evidence locations
- Install scripts: `install_rustyjack.sh`, `install_rustyjack_dev.sh`, `install_rustyjack_prebuilt.sh`
- Services: `services/*.service`, `services/*.socket`
- Scripts: `scripts/*` (driver installer, FDE helpers, hotplug helpers)
- Root constraints: `AGENTS.md`, `CLAUDE.md`

### 4.3 Constraints (area-specific)
- Must preserve the dedicated-device assumptions: no NetworkManager, deterministic DNS ownership, expected users/groups.
- Must keep runtime “external binary” usage to *minimum possible*; runtime should not depend on installers remaining present.

### 4.4 How to analyze (broad + detailed)
- **Idempotency audit:** running installers twice should not brick the box, leak state, or corrupt resolv.conf ownership.
- **Rollback and recovery:** if a mid-install step fails (e.g., apt failure), ensure the system is still bootable/recoverable.
- **Service hardening posture:** evaluate systemd directives, capability bounding, filesystem isolation, device access.
- **Permission model:** confirm:
  - `rustyjackd` has only what it needs (capabilities vs root).
  - UI user can only access GPIO/SPI and *not* raw network operations.

### 4.5 Likely weaknesses to hunt
- “Implicit dependency” on a removed tool (e.g., code assumes `nmcli`).
- `/etc/resolv.conf` races: other services trying to own it again.
- Overly broad permissions for UI user or portal service.
- External tool drift (installer changes but runtime assumes old behavior).

### 4.6 Fix template examples
- **Problem:** installer claims `/etc/resolv.conf` but doesn’t re-assert it after package updates  
  **Why:** apt/postinst scripts can rewrite the symlink; DNS control becomes nondeterministic  
  **Where:** `install_*.sh`, `crates/rustyjack-core/src/system/dns.rs` (and any boot-time fixups)  
  **Fix:** add a boot-time verification/repair step in daemon startup (before network ops)  
  **Fixed version:** daemon checks resolv.conf is the symlink target and repairs atomically, logs a single high-signal event.

---

## 5) Area 2 — Privilege separation, IPC, authorization, job lifecycle
### 5.1 Responsibilities
- Ensure the UI cannot directly perform privileged actions.
- Authenticate/authorize incoming requests.
- Provide cancellable long-running jobs with safe cleanup.
- Prevent IPC-level denial of service.

### 5.2 Evidence locations
- Daemon: `crates/rustyjack-daemon/src/*` (notably `auth.rs`, `server.rs`, `dispatch.rs`, `jobs/*`)
- IPC types: `crates/rustyjack-ipc/`
- Client: `crates/rustyjack-client/`
- Commands: `crates/rustyjack-commands/`
- Root docs: `CLAUDE.md` (architecture diagram), `TESTING.md` (protocol robustness suite references)

### 5.3 Constraints
- Only daemon does privileged operations; UI only requests them.
- Authorization tiers must be coherent and testable.
- Operations must be cancellable without leaving interfaces “half-up” or loot in inconsistent state.

### 5.4 How to analyze
- **Threat model the socket:** permissions on `/run/rustyjack/rustyjackd.sock`, group ownership, umask.
- **Input validation:** size limits, structured parsing, failure behavior.
- **Backpressure:** ensure daemon can reject/queue requests without RAM blowups.
- **Job safety:** cancellation should invoke cleanup hooks and restore invariants (especially interface isolation).
- **Crash consistency:** what happens if daemon restarts mid-job?

### 5.5 Modern/robust patterns to compare against
- Strict message framing + max payload sizes.
- Separate “control plane” (requests) from “data plane” (log streaming, loot export) with different quotas.
- Authorization checks as a single gate early in dispatch (not sprinkled).

### 5.6 Fix template examples
- **Problem:** large IPC payload can allocate unbounded memory  
  **Why:** DoS; Pi Zero has tiny RAM and swap is painful  
  **Where:** `crates/rustyjack-daemon/src/server.rs` (read loop), IPC decode paths  
  **Fix:** enforce max frame length; reject early; log a rate-limited security event  
  **Fixed version:** server reads length prefix, caps at e.g. 64KiB, and returns a structured error without crashing.

---

## 6) Area 3 — Interface isolation & interface selection state machine
### 6.1 Responsibilities
- Choose the active uplink per policy/preferences.
- Apply the isolation invariant (“one interface up”).
- Handle exceptions (e.g., hotspot AP + upstream).
- Verify success before UI reports it.

### 6.2 Evidence locations
- Trusted design notes: `logs/done/interface_isolation_overview.md`, root `TESTING.md`
- Implementation:
  - `crates/rustyjack-core/src/system/isolation.rs`
  - `crates/rustyjack-core/src/system/mod.rs` (isolation helpers)
  - `crates/rustyjack-daemon/src/netlink_watcher.rs` (watcher enforcement)
  - Netlink primitives: `crates/rustyjack-netlink/src/interface.rs`, `rfkill.rs`, `route.rs`, `dhcp.rs`, `wireless.rs`

### 6.3 Constraints (from trusted docs)
- Steady state: exactly one uplink admin‑UP.
- Others: forced DOWN; wireless not selected should be soft-blocked with rfkill (when possible).
- Switch must be transactional + verifiable; rollback on failure; SSH safety rules in test suite (`TESTING.md`).

### 6.4 How to analyze
- **State machine audit:** draw explicit phases (preflight → isolate others → bring target up → DHCP/route (mode dependent) → verify → commit policy).
- **Concurrency audit:** ensure no racing between:
  - user-triggered switch job
  - background watcher re-enforcement
  - hotspot exception toggles
- **Failure injection:** simulate:
  - rfkill denied
  - DHCP timeout
  - cable unplug
  - netlink errors
  - daemon restart mid-switch
- **Verification semantics:** confirm UI success happens only after target is admin‑UP (not after “we tried”).

### 6.5 Common weakness classes
- “Split brain” enforcement (watcher fights a switch job).
- Leaving two interfaces admin‑UP during a window.
- Forgetting to rfkill-block dormant radios.
- Confusing “carrier up” (link) with “admin up” (desired state).

### 6.6 Fix template examples
- **Problem:** transient window where old and new uplink are both admin‑UP  
  **Why:** violates the isolation invariant; causes traffic leaks + ambiguous routing  
  **Where:** isolation/selection commit logic (`crates/rustyjack-core/src/system/isolation.rs`)  
  **Fix:** enforce strict order + verification: bring target up only after others down; add global lock and post-check  
  **Fixed version:** two-phase commit: (1) block all non-target, (2) set target up, (3) verify, else rollback.

---

## 7) Area 4 — Netlink networking primitives (links/routes/DNS/DHCP/ARP/rfkill/nftables)
### 7.1 Responsibilities
- Provide the “Rust replacement” substrate:
  - interface link operations
  - routing + DNS ownership
  - DHCP client/server
  - ARP scanning/spoofing primitives
  - rfkill control
  - nftables (via nf_tables netlink API)

### 7.2 Evidence locations
- Crate: `crates/rustyjack-netlink/src/*` (notably `interface.rs`, `route.rs`, `dhcp.rs`, `dns_server.rs`, `rfkill.rs`, `nf_tables.rs`, `iptables.rs`)
- Invariant consumers: `crates/rustyjack-core/src/system/*`, daemon watcher, wireless/hotspot.

### 7.3 Constraints
- No NetworkManager dependency.
- Prefer Rust-native implementations; external tools only as explicit compatibility fallback.
- Must be safe under Pi constraints: low RAM, slow SD I/O, intermittent power.

### 7.4 How to analyze
- **Correctness:** verify netlink message building/parsing; ensure kernel error codes are surfaced with context.
- **Safety:** audit all `unsafe` blocks (raw sockets, ioctl, C FFI) for bounds + lifetimes.
- **Async safety:** ensure async code doesn’t block the runtime (project includes CI checks under `ci/no_blocking_in_async.rs`).
- **Determinism:** avoid “best effort” behavior in primitives; let policy live above, not inside.

### 7.5 Modern patterns to compare against
- Central “net ops” trait with mockable implementations (already present: `NetOps` in core).
- Single source of truth for interface state (avoid having both daemon and core maintain separate caches).

### 7.6 Fix template examples
- **Problem:** rfkill soft-block is attempted but failure is silently ignored  
  **Why:** dormant radio may still transmit; violates isolation intent  
  **Where:** `crates/rustyjack-netlink/src/rfkill.rs`, and callers in isolation engine  
  **Fix:** surface failure as warning with remediation hints; add “degraded mode” indicator in UI  
  **Fixed version:** activation report includes `rfkill_status`, UI shows a persistent warning until resolved.

---

## 8) Area 5 — Wireless operations layer
> **Note:** This section treats wireless “attack” capabilities as *software modules to audit*, not as instructions for use.

### 8.1 Responsibilities
- Wireless recon/capture/injection-dependent feature set.
- Handle external adapter requirements (monitor/injection) vs built-in Pi radio limitations.
- Store captures reliably; minimize device fingerprinting under evasion settings.

### 8.2 Evidence locations
Trusted operation notes:
- `logs/done/wireless_probe_sniff_capture.md`
- `logs/done/wireless_deauth_attack.md`
- `logs/done/wireless_pmkid_capture.md`
- `logs/done/wireless_karma_attack.md`
- `logs/done/wireless_evil_twin_attack.md`

Implementation:
- `crates/rustyjack-wireless/src/*` (frames parsing, capture, injection, recon, rfkill helpers, nl80211 glue)
- WPA logic: `crates/rustyjack-wpa/`
- Orchestration: command handlers in `crates/rustyjack-core/`

### 8.3 Constraints
- Built-in Pi radio can be limited; many features require a USB adapter (root docs).
- Must obey global isolation invariant (non-selected radios down/blocked).
- Must obey evasion controls (TX power, passive mode, MAC randomization).
- Must be **explicitly user-confirmed** for disruptive actions (UI rules in `AGENTS.md`).

### 8.4 How to analyze
- **Parser safety:** fuzz or property-test 802.11 frame parsing (`frames.rs`, `radiotap.rs`).
- **Driver capability detection:** confirm the tool refuses features that require monitor/injection when hardware lacks it.
- **Rate limiting + guardrails:** ensure disruptive transmissions have:
  - explicit confirmation
  - clear stop/cancel behavior
  - strict scoping to selected interface
- **State restoration:** channel/monitor mode/MAC must restore on cancel or crash.

### 8.5 Vulnerability/weakness classes
- Unsafe raw socket operations (capture/inject) and bounds errors.
- Path sanitization issues when using SSID/BSSID for directories (loot paths).
- “Mode leak”: monitor mode left enabled or radio left unblocked.

### 8.6 Fix template examples
- **Problem:** capture loop uses raw socket reads without strict length validation  
  **Why:** malformed frames can crash the process or corrupt loot  
  **Where:** `crates/rustyjack-wireless/src/capture.rs`, `frames.rs`  
  **Fix:** treat every packet as untrusted; validate minimum lengths before parsing; fuzz test  
  **Fixed version:** parsing functions return structured errors; capture loop drops malformed frames and increments counters.

---

## 9) Area 6 — Ethernet operations layer
### 9.1 Responsibilities
- LAN discovery (ICMP/ARP sweep), port scanning, banner grabbing, device inventory.
- Any “active manipulation” plumbing should be separated and strongly gated.

### 9.2 Evidence locations
Trusted notes:
- `logs/done/ethernet_recon_overview.md`
- `logs/done/ethernet_mitm_dns_spoof.md` (treat as sensitive; audit for guardrails and safety)

Implementation:
- `crates/rustyjack-ethernet/src/lib.rs` (synchronous raw socket logic)
- Supporting primitives: `crates/rustyjack-netlink/src/arp*.rs`, `dns_server.rs`, `nf_tables.rs`
- Orchestration: `rustyjack-core` pipelines + daemon job wrappers

### 9.3 Constraints
- Must respect interface isolation.
- Must respect Pi resource limits (avoid long synchronous sleeps in daemon runtime).
- Must not leave the network in a manipulated state after cancel/exit.

### 9.4 How to analyze
- **Blocking model:** ethernet crate is synchronous; ensure daemon runs it in a non-blocking context (dedicated thread or `spawn_blocking`).
- **Safety:** audit `unsafe` segments (raw socket recv, `MaybeUninit`, FDs).
- **Scan correctness:** timeouts, retries, and rate limits—especially on Pi.
- **Data ingestion:** banner parsing; avoid terminal escape injection in UI/logs.
- **Guardrails:** if any MITM capability exists, ensure explicit gating and easy teardown.

### 9.5 Fix template examples
- **Problem:** synchronous scan does `std::thread::sleep` inside a daemon async task  
  **Why:** freezes the event loop; watchdog races; UI stalls  
  **Where:** `crates/rustyjack-ethernet/src/lib.rs`, daemon dispatch wrappers  
  **Fix:** run ethernet sweeps in a dedicated blocking worker thread; use cancellation token  
  **Fixed version:** daemon spawns a blocking task, streams progress via IPC events, and ensures teardown on cancel.

---

## 10) Area 7 — Identity & evasion controls
### 10.1 Responsibilities
- MAC randomization, hostname randomization, TX power controls, passive mode.
- Restore original state on demand, cancel, or failure.

### 10.2 Evidence locations
Trusted note: `logs/done/evasion_identity_controls.md`  
Implementation:
- `crates/rustyjack-evasion/src/*`
- `crates/rustyjack-netlink/src/wireless.rs` (TX power / interface ops)
- Orchestration: `rustyjack-core` ties controls into pipelines/UI

### 10.3 Constraints
- MAC must be locally administered + unicast; vendor-aware policies.
- Passive mode should reduce active emissions, but must be truthfully represented (no “magic stealth”).

### 10.4 How to analyze
- **Randomness quality:** confirm CSPRNG usage, no predictable seeds.
- **Policy correctness:** vendor matching logic, OUI handling, restore behavior.
- **Side effects:** MAC changes often require iface down/up; ensure this doesn’t violate interface isolation or strand connectivity unexpectedly.
- **Persistence:** store original state safely; prevent stale restores after interface swaps.

### 10.5 Fix template examples
- **Problem:** original MAC restore state is stored globally and becomes stale after interface changes  
  **Why:** restore could apply wrong identity to wrong interface  
  **Where:** evasion state tracking + core preference manager  
  **Fix:** key restore state by interface + session ID; clear on switch  
  **Fixed version:** restore map `{ iface -> original_state }` with explicit invalidation when active interface changes.

---

## 11) Area 8 — Captive portal + DNSSpoof templates
### 11.1 Responsibilities
- Serve a local HTTP portal (Axum) for captive flows.
- Provide templates/resources stored in `DNSSpoof/`.

### 11.2 Evidence locations
- Portal crate: `crates/rustyjack-portal/`
- Templates/assets: `DNSSpoof/`
- Net plumbing: nftables DNAT rules (`crates/rustyjack-netlink/src/iptables.rs` / `nf_tables.rs`)

### 11.3 Constraints
- Portal must run unprivileged; networking redirection handled by privileged daemon.
- Templates and credential-like inputs must be treated as sensitive loot; must be redacted in logs.

### 11.4 How to analyze
- **Web security basics:** input validation, request size limits, CSRF-ish concerns (even in local portal), XSS in templates.
- **Isolation correctness:** ensure DNAT/forward rules are added/removed transactionally.
- **Logging:** verify no secrets end up in journal logs or UI logs.

### 11.5 Fix template examples
- **Problem:** portal logs full form submissions  
  **Why:** leaks credentials into system logs; violates sensitive-data handling  
  **Where:** `rustyjack-portal` handlers, logging middleware  
  **Fix:** redact at source; only log event types + hashed identifiers  
  **Fixed version:** portal emits “credential_received” with a session ID; actual content stored encrypted as loot.

---

## 12) Area 9 — Loot management + encryption + export
### 12.1 Responsibilities
- Organize artifacts by session/target.
- Generate reports.
- Export to USB or upload (where supported).
- Encrypt sensitive loot with AES-GCM; zeroize key material.

### 12.2 Evidence locations
Trusted note: `logs/done/loot_management.md`  
Implementation:
- `crates/rustyjack-core/src/*` (loot session, report generation, USB mount policy)
- `crates/rustyjack-encryption/src/*`

### 12.3 Constraints
- Loot paths must be deterministic and safe; avoid path traversal.
- Sensitive data must be redacted from logs (`crates/rustyjack-core/src/redact.rs` per root docs).
- Encryption must zeroize secrets; key handling must be explicit.

### 12.4 How to analyze
- **Filename sanitization:** SSID/BSSID/IP-derived directories must be sanitized.
- **Permissions:** loot on disk should be readable only by intended users; UI should not need raw secrets unless explicitly requested.
- **Atomic writes:** avoid partial files on power loss.
- **Crypto correctness:** AEAD nonce uniqueness, key derivation/storage, secure deletion expectations (see anti-forensics caveats).

### 12.5 Fix template examples
- **Problem:** SSID used directly as directory name (contains `/`, control chars, very long strings)  
  **Why:** path traversal / filesystem issues / UI rendering glitches  
  **Where:** loot path builder in `rustyjack-core`  
  **Fix:** canonical “target slug” function: allowlist chars, length cap, fallback to hashed ID  
  **Fixed version:** `target_slug(ssid, bssid) -> String` used everywhere; old unsanitized paths are migrated.

---

## 13) Area 10 — Updates & supply-chain integrity
### 13.1 Responsibilities
- Fetch update artifacts.
- Verify authenticity (Ed25519 signatures are present in code dependencies).
- Apply updates safely and atomically.

### 13.2 Evidence locations
- `crates/rustyjack-updater/src/lib.rs`
- Daemon integration: `crates/rustyjack-daemon/` (where updater is invoked)

### 13.3 Constraints
- Updates must be verifiable, atomic, and recoverable.
- Update mechanism must not become an RCE pipeline (no shelling out, no unsigned scripts).

### 13.4 How to analyze
- **Signature verification:** ensure signature covers the content that gets executed.
- **Key management:** where is the public key stored? how is rotation handled?
- **Atomic install:** use staging directory + rename swap; rollback if service fails.
- **Network safety:** timeouts, partial downloads, disk space checks.

### 13.5 Fix template examples
- **Problem:** updater verifies signature of a manifest but not the payload bytes  
  **Why:** TOCTOU; attacker can swap the payload after manifest verification  
  **Where:** updater download/verify/apply flow  
  **Fix:** verify signature on the payload hash; lock file descriptors; apply only verified bytes  
  **Fixed version:** `verify(sig, sha256(payload))` before unpack; unpack only from verified in-memory stream or verified-on-disk file with locked permissions.

---

## 14) Area 11 — Anti-forensics + destructive operations
### 14.1 Responsibilities
- Secure deletion, log purging, “system purge”, RAM wipe policies.
- Full Disk Encryption helpers.

### 14.2 Evidence locations
- Root docs mention anti-forensics modules in `crates/rustyjack-core/src/external_tools/anti_forensics.rs`
- FDE scripts: `scripts/fde_*`
- UI confirmation requirements: `AGENTS.md`
- Warning notes: `AGENTS.md` (FDE is destructive/irreversible)

### 14.3 Constraints
- Must require explicit confirmations.
- Must be truthful about what secure deletion can/can’t guarantee on flash media.

### 14.4 How to analyze
- **Safety UX:** confirm user cannot trigger destructive actions accidentally.
- **Correctness:** ensure purge operations wipe all relevant dirs and don’t leave breadcrumbs.
- **Limits:** SD cards and SSDs have wear leveling; overwriting may not actually erase prior data.

### 14.5 Fix template examples
- **Problem:** secure-delete claims “guaranteed” wipe on SD storage  
  **Why:** false sense of security; wear leveling breaks overwrite assumptions  
  **Where:** user-facing messages + docs, anti-forensics module  
  **Fix:** change copy to “best effort”; prefer encryption-at-rest + key destruction for strong guarantees  
  **Fixed version:** documentation and UI phrasing updated; encrypted loot default enabled; purge offers “destroy key material” as primary.

---

## 15) Area 12 — UI + display subsystem + GPIO input
### 15.1 Responsibilities
- Render UI on the LCD; handle input from 8 buttons.
- Display discovery/calibration + caching.
- Show job progress/errors without hiding failures.

### 15.2 Evidence locations
Trusted:
- `logs/done/dynamic_display_resolution_implementation_report.md`
- `logs/done/rustyjack_ui_theme_stabilization_implementation_2026-02-07.md`
- `logs/done/waveshare_gpio_pin_mapping.md`
- Root doc: `AGENTS.md` (button mapping, display policies)

Implementation:
- `crates/rustyjack-ui/src/*`

### 15.3 Constraints
- Min supported display: `128x128`.
- Exactly 8-button control model.
- UI dialogs must require explicit confirmation; no auto-dismiss.

### 15.4 How to analyze
- **Rendering performance:** frame time, allocations per frame, IO frequency (Pi SD is slow).
- **Input handling:** debouncing, long-press handling, preventing accidental repeats.
- **Error surfacing:** errors must be visible and persist until acknowledged.
- **State coherence:** avoid UI showing stale network states during switching jobs; use structured progress events.

### 15.5 Fix template examples
- **Problem:** UI refreshes interface status by polling too aggressively  
  **Why:** burns CPU, causes heat and jitter, drains power; can starve daemon comms  
  **Where:** UI status refresh loop  
  **Fix:** use event-driven updates from daemon + low-rate polling fallback  
  **Fixed version:** daemon publishes “interface_state_changed”; UI listens and re-renders only on changes.

---

## 16) Area 13 — Observability: logging, redaction, audit trails, telemetry
### 16.1 Responsibilities
- Provide useful logs for debugging on a constrained device.
- Prevent sensitive data leakage.
- Maintain operation history for accountability.

### 16.2 Evidence locations
- Logging crate: `crates/rustyjack-logging/`
- Redaction: `crates/rustyjack-core/src/redact.rs` (per root docs)
- Root env toggles: `RUSTYJACK_LOGS_DISABLED=1` etc (root docs)

### 16.3 Constraints
- Default logs must not include secrets.
- Debug logs in lab mode may be richer, but must still redact by default.

### 16.4 How to analyze
- **Redaction coverage:** ensure all sensitive fields are passed through the redactor before logging.
- **Log volume:** journal spam can fill storage; rate-limit noisy warnings.
- **Audit integrity:** ensure operation history is append-only and timestamped.

---

## 17) Area 14 — Quality gates: CI checks + test harnesses + on-device verification
### 17.1 Evidence locations
- CI tools: `ci/no_blocking_in_async.rs`, `ci/forbid_command_new.rs`, `ci/no_new_unwrap_expect.rs`, etc.
- Test suite scripts: `scripts/rj_run_tests.sh`, `scripts/rj_test_interface_selection.sh` (referenced by `TESTING.md`)

### 17.2 Constraints
- Appliance builds should not regress into spawning system binaries (`forbid_command_new` exists for a reason).
- Async contexts should not block (CI scanner exists for a reason).
- Interface isolation is acceptance-tested (`TESTING.md`).

### 17.3 How to analyze
- Extend CI with: unsafe block inventory, fuzz harnesses for parsers, “golden” netlink state simulations.
- Ensure test suite is runnable on-device with safe defaults (SSH safety checks already exist).

---

## 18) Cross-cutting review checklists (use these in every area)
### 18.1 Security checklist
- All untrusted inputs validated (IPC payloads, network frames, SSIDs, banners, portal POST bodies).
- No secret logging; redaction applied.
- Minimal privileges; services sandboxed.
- Dangerous ops gated by explicit confirmation + mode flags.

### 18.2 Correctness checklist
- Invariants explicitly encoded (not “by convention”).
- All state machines have clear phases and post-conditions.
- Rollback path exists and is tested.

### 18.3 Performance checklist (Pi Zero reality)
- Avoid blocking in async contexts; isolate synchronous modules.
- Bound memory usage; streaming IO for large artifacts.
- Rate-limit scans and log volume.

### 18.4 “Home-grown Rust” compliance checklist
- No runtime reliance on `nmcli`, `iptables`, `rfkill` binaries.
- External binaries (if any) must be feature-gated behind `lab` builds and fail closed on appliance builds.
- Installer exceptions are documented and tracked to removal.

---

## 19) Suggested deliverables for the next phase of the deep dive
For each area, produce:
1. **Component map** (modules + call graph sketch)
2. **Invariants list** (global + area-specific)
3. **Threat model** (attacker model + abuse cases + mitigations)
4. **Failure injection matrix** (what happens if X fails?)
5. **Top 10 issues** in the required format  
   (**Problem → Why → Where → Fix → Fixed version**)
6. **Test plan** (unit/integration/on-device) + required fixtures

---

## Appendix A — Trusted docs used (per your rule)
Root docs:
- `README.md`
- `AGENTS.md`
- `CLAUDE.md`
- `TESTING.md`

`logs/done/`:
- `interface_isolation_overview.md`
- `evasion_identity_controls.md`
- `crate_rustyjack_ethernet.md`
- `crate_rustyjack_evasion.md`
- `crate_rustyjack_encryption.md`
- `ethernet_recon_overview.md`
- `ethernet_mitm_dns_spoof.md`
- `wireless_probe_sniff_capture.md`
- `wireless_deauth_attack.md`
- `wireless_pmkid_capture.md`
- `wireless_karma_attack.md`
- `wireless_evil_twin_attack.md`
- `loot_management.md`
- `dynamic_display_resolution_implementation_report.md`
- `rustyjack_ui_theme_stabilization_implementation_2026-02-07.md`
- `waveshare_gpio_pin_mapping.md`
