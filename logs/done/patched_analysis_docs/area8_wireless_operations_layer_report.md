# Area 8 — Wireless operations layer (Architecture Doc 2)
Date: 2026-02-15

**Repository snapshot:** `watchdog/` workspace (Rust)
**Report type:** Codebase audit (safety, correctness, guardrails, secure engineering) — **no operational “how‑to”** content.

## Evidence model (what counts as a constraint)
This report follows the evidence/trust rule stated in Architecture Doc 2: constraints come only from **root docs** and **`logs/done/`**, while code is treated as implementation evidence.
This section is explicitly scoped to the “Wireless operations layer” responsibilities and analysis prompts in that doc.

---

## Component map (what “wireless ops layer” is in this repo)

### Primary crates / modules
- **Wireless feature layer:** `crates/rustyjack-wireless/`
  - capture pipeline: `capture.rs`, `recon.rs`
  - frame parsing: `radiotap.rs`, `frames.rs`
  - injection/raw TX plumbing: `inject.rs`
  - mode switching + channel ops: `interface.rs`, `nl80211.rs`, `netlink_helpers.rs`
  - rfkill helpers: `rfkill_helpers.rs`
- **Netlink substrate:** `crates/rustyjack-netlink/`
  - nl80211 capabilities + scanning + txpower: `wireless.rs`
  - rfkill control: `rfkill.rs`
- **Orchestration + guardrails:** `crates/rustyjack-core/`
  - capability report + refusal logic: `wireless_native.rs`
  - command handlers for Wi‑Fi actions + UX gates: `operations.rs`
  - interface isolation enforcement: `system/*`
- **UI gating (implementation evidence):** `crates/rustyjack-ui/`

### Invariant the wireless layer must never violate
The repo’s “big” safety invariant is interface isolation: **one uplink admin‑UP at steady state; others forced DOWN; non-selected wireless should be rfkill soft-blocked** (`logs/done/interface_isolation_overview.md`, root `TESTING.md`).

---

## 1) Capability matrix

This is “what requires what,” and how the code detects/refuses.

> **Hardware baseline constraint (trusted docs):** the **Pi Zero 2 W built‑in Wi‑Fi is not suitable for monitor/injection**; a USB adapter is required for those features (root docs + wireless notes). Example: `AGENTS.md` “wireless note” + `logs/done/wireless_*` docs.

### Key detection mechanisms (implementation evidence)
- **Driver/phy capability query:** `rustyjack_netlink::WirelessManager::get_phy_capabilities()`
  used in `crates/rustyjack-wireless/src/nl80211_queries.rs` to compute:
  - `supports_monitor_mode`
  - `supports_tx_in_monitor` (aka injection-in-monitor)
  - `supports_ap_mode`, `supports_5ghz`, etc.
- **Front-door capability report:** `crates/rustyjack-core/src/wireless_native.rs::check_capabilities()`
  consolidates results for UI/daemon refusal paths.
- **Privilege checks:** many operations call `is_root()` early (e.g., `evil_twin.rs`, `nl80211.rs`), but not uniformly in the lower-level plumbing.

### Capability matrix (feature → requirements → detection/refusal)

| Feature family | Required interface/driver state | Required privileges | Hardware/driver needs | Detection (current) | Refusal behavior (current) |
|---|---|---|---|---|---|
| **Managed scan + connect** | Managed (station) mode | `CAP_NET_ADMIN` for netlink ops (scan), plus WPA control where used | Works on built-in Pi Wi‑Fi (constraint) | nl80211 scan (netlink); driver name/phy caps in `check_capabilities` | Mostly “best effort”; some calls warn and continue |
| **Passive capture (monitor sniff)** | Monitor mode + radiotap on RX path | `CAP_NET_RAW` | Requires adapter/driver supporting monitor mode (constraint) | `supports_monitor_mode` from phy capabilities | Core layer preflights & refuses where wired; some module-level checks missing |
| **Injection-dependent features** | Monitor mode **and** TX allowed in monitor | `CAP_NET_RAW` + `CAP_NET_ADMIN` | Requires adapter/driver supporting “TX in monitor” (constraint) | `supports_tx_in_monitor` exists but not consistently enforced end-to-end | Some enforcement in core; in wireless crate `supports_injection()` is currently too weak |
| **AP / hotspot operations** | AP mode (or managed + additional plumbing depending on design) | `CAP_NET_ADMIN` | Built-in Pi Wi‑Fi may do limited AP; drivers vary | `supports_ap_mode` exists in phy caps | Refusal inconsistent; hotspot uses broad rfkill unblock |
| **Channel switching / hopping** | Monitor mode usually, but can be used in other modes depending on kernel/driver | `CAP_NET_ADMIN` | driver must allow `NL80211_CMD_SET_CHANNEL`/`WIPHY_FREQ` | `set_channel()` via netlink | On failure: typically warn, continue |
| **MAC randomization** | Interface down/up + set MAC | `CAP_NET_ADMIN` | driver must permit MAC change | `nl80211.rs::set_mac_address()` | Attempts and warns; restoration tracking is split across crates |
| **rfkill enforcement** | `/dev/rfkill` or netlink rfkill | `CAP_NET_ADMIN` typically | depends on kernel rfkill support | `rustyjack-netlink::rfkill` | Isolation layer tries; hotspot path can override |

**rfkill semantics note:** rfkill distinguishes software “soft block” vs hardware “hard block” (cannot be undone in software).
This matters for “restore state” logic: a hard-blocked radio cannot be “restored” by the daemon; UX needs to tell the truth.

---

## 2) Parser safety review (radiotap + 802.11)

### What’s in tree
- `crates/rustyjack-wireless/src/radiotap.rs`: minimal radiotap parser producing `RadiotapInfo`
- `crates/rustyjack-wireless/src/frames.rs`: minimal 802.11 parser producing `Ieee80211Frame`

### Good news
- Both parsers are **slice-based** and use **bounds checks**; they return `Result` rather than panicking.
- Parsing functions are small and deterministic → **excellent fuzz targets**.

### Major correctness/safety risks
1) **Radiotap present bitmap handling is incomplete**
   Radiotap supports **extended present words** and field **alignment rules**. If the parser ignores extra present words or alignment, you can:
   - miscompute the “payload starts at” offset,
   - feed garbage into downstream 802.11 parsing,
   - silently mis-classify frames.
   Radiotap itself is designed to be extensible; ignoring the extended bitmap is a correctness footgun.

2) **802.11 header length is not universally 24 bytes**
   Data/QoS frames and “4-address” cases change header layout. A parser that assumes fixed offsets can still be memory-safe but semantically wrong, which becomes a **policy bug** (filters, capture selection, gating decisions). IEEE 802.11 frame control encodes variants that require conditional parsing.

3) **SSID handling is lossy**
   SSIDs are 0–32 bytes and need not be valid UTF‑8. “Lossy” UTF‑8 conversions or aggressive filters can create collisions in UI/display logic (not a memory safety issue; a correctness/UX issue).

### Unsafe code / raw socket adjacency
- The core parsers are safe Rust, but:
  - `frames.rs` uses `#[repr(C, packed)]` for `Ieee80211Header` plus a raw byte-view helper (`as_bytes`), which should stay confined and carefully documented.
  - capture/inject use raw sockets and receive attacker-controlled bytes: parser robustness is part of your attack surface.

---

## 3) State restoration on cancel/crash
**Goal:** monitor mode, channel, MAC, rfkill state should be restored to a known-good baseline.

### What exists today (implementation evidence)
- **Monitor mode restoration (best-effort):**
  - `WirelessInterface` tracks whether it enabled monitor and tries to revert to managed mode in `Drop` (`interface.rs`).
  - Multiple higher-level workflows explicitly call `set_managed_mode()` at end and on cancellation (e.g., `pmkid.rs`, `wireless_native.rs`).
- **Channel restoration:** generally **not tracked/restored**.
  Channel hopping uses `iface.set_channel(...)` and does not restore the original channel in several workflows (e.g., `probe.rs` hopping).
- **MAC restoration:** there is state tracking in `rustyjack-evasion` (trusted doc notes restoration intent), but the wireless layer also keeps an `original_mac` field that is not currently used for rollback in `interface.rs`.
- **rfkill restoration:** done by the **interface isolation engine**, not by the wireless module itself. Hotspot code has a notable exception (see findings).

### Crash/kill behavior
If the daemon is killed (SIGKILL), panics, or power is lost, “finally blocks” and `Drop` won’t run. That means **monitor mode and rfkill state can leak across restarts** unless startup includes a recovery pass.

**Recommended architectural posture**
- Treat restore as a **session-scoped state machine** with an explicit “baseline reassertion” step on:
  - job cancel,
  - job failure,
  - daemon startup,
  - interface switch.

---

## 4) Guardrails & UX gates (and where they live)

### Trusted guardrail constraints
- Disruptive operations must be **explicitly confirmed** (root docs, referenced by Architecture Doc 2).
- “Stealth/passive” posture must be truthfully represented: passive mode reduces emissions but is not magic RF invisibility. (trusted note)

### Guardrails that exist in code (implementation evidence)
- **Offensive gating via “review approval”:** `crates/rustyjack-core/src/operations.rs::offensive_review_approved()`
  gates multiple Wi‑Fi actions behind either:
  - `RUSTYJACK_REVIEW_APPROVED=1`, or
  - presence of a `REVIEW_APPROVED.md` sentinel file.
  (This is a good pattern, but see findings about defaults/UX clarity.)
- **Operation-mode gating (UI side):** UI checks whether the current mode allows “active” operations (e.g., stealth mode blocks). This is not a security boundary by itself—daemon must also enforce.
- **Interface isolation preflight:** Wi‑Fi operations frequently call `enforce_single_interface(...)` before touching radio state.

### Misuse prevention (UI/daemon design notes)
Even for legitimate workflows, accidental TX can be disruptive. Prevent it by making the system “fail closed”:
- Default to **passive-only** posture unless user explicitly escalates.
- Require **two independent intentional actions** for any TX-capable operation (e.g., “arm” + “execute”), with a clear on-screen “TX will occur” banner.
- Keep a **persistent “RF state” indicator**: interface name, mode (managed/monitor/AP), channel, and whether rfkill is blocked.
- Add a global **TX watchdog**: if UI disconnects, job times out, or cancel is triggered, immediately tear down TX paths and revert to baseline.

---

## 5) Findings (17)
Format required: **Problem → Why → Where → Fix → Fixed version looks like**.

### 1) `WirelessInterface` does not restore original interface type/channel/MAC
- **Problem:** `WirelessInterface` stores `original_mac` and `original_type`, but restoration only toggles monitor→managed and does not restore channel or MAC.
- **Why:** Leaving an interface in a modified state violates “reversible operations” expectations and can break subsequent workflows or leak user intent (e.g., stuck on a weird channel).
- **Where:** `crates/rustyjack-wireless/src/interface.rs` (struct fields + `Drop` impl; `set_monitor_mode` / `set_managed_mode`)
- **Fix:** Capture a full baseline snapshot on construction:
  - interface type, admin-up state, channel/frequency, MAC, txpower, rfkill soft-block.
  - Restore it via a single `restore_baseline()` called in `Drop` and in explicit cleanup paths.
- **Fixed version looks like:** A `WirelessInterfaceGuard { baseline: BaselineState, iface: WirelessInterface }` where `Drop` calls a best-effort restore and emits one high-signal log line if degraded.

### 2) Monitor mode switching is “best effort” and may not be applied cleanly
- **Problem:** `set_monitor_mode()` notes it “doesn’t bring interface down/up,” but some drivers require down/up or separate flags for effective monitor transition.
- **Why:** Partial mode switch can produce confusing behavior (captures silently empty; injections fail), and can lead to “half-configured” state that is hard to restore.
- **Where:** `crates/rustyjack-wireless/src/interface.rs` (`set_monitor_mode`)
- **Fix:** Perform an atomic mode-switch transaction:
  - bring interface down (if necessary),
  - set type,
  - bring up,
  - verify via nl80211 query.
- **Fixed version looks like:** `set_mode(Monitor)` returns a `ModeReport { requested, actual, verification }` and callers refuse to proceed if verification fails.

### 3) `supports_injection()` is too weak and risks false positives
- **Problem:** `nl80211.rs::supports_injection()` returns `supports_monitor_mode`, not “TX in monitor.”
- **Why:** Some adapters support monitor RX but cannot transmit in monitor; attempting TX will fail unpredictably (and might trigger retries/side effects).
- **Where:** `crates/rustyjack-wireless/src/nl80211.rs::supports_injection`
- **Fix:** Base injection gating on `supports_tx_in_monitor` from phy capabilities; propagate that through `CapabilityReport`.
- **Fixed version looks like:** `supports_injection(caps) = caps.supports_monitor_mode && caps.supports_tx_in_monitor` and every TX-capable workflow checks it *before* mode switching.

### 4) rfkill “unblock all” breaks the isolation invariant
- **Problem:** Hotspot setup calls `rfkill_unblock_all()`.
- **Why:** The isolation invariant wants non-selected radios soft-blocked; unblocking *all* radios can resurrect dormant interfaces and violate “only selected interface up/available.” rfkill also interacts with privacy expectations.
- **Where:** `crates/rustyjack-wireless/src/hotspot.rs` (setup path), `crates/rustyjack-wireless/src/rfkill_helpers.rs`
- **Fix:** Replace “unblock all” with “unblock only the selected interface’s rfkill device,” and re-run isolation enforcement immediately after hotspot setup.
- **Fixed version looks like:** `rfkill_unblock_iface(iface)` + `enforce_single_interface(selected_iface)` after success; on failure, revert.

### 5) Cancellation can’t interrupt a blocking capture read
- **Problem:** `PacketCapture::next_packet()` blocks on `rx.next()`; cancellation checks in callers won’t fire until a packet arrives.
- **Why:** “Stop” may feel broken; also, a cancel requested during a quiet channel can take arbitrarily long.
- **Where:** `crates/rustyjack-wireless/src/capture.rs`
- **Fix:** Make capture cancellable:
  - use non-blocking I/O or a read timeout,
  - poll in a loop that checks cancel tokens,
  - or run capture in a dedicated thread and cancel via fd close.
- **Fixed version looks like:** `next_packet(&CancelToken) -> Result<Option<Packet>, ...>` returning `Ok(None)` on timeout so the caller can check cancel and continue.

### 6) Capture path allocates per packet (avoidable on Pi)
- **Problem:** Each received packet is copied into a new `Vec<u8>` (`to_vec()`).
- **Why:** Sustained capture creates allocator pressure and SD wear if you log too eagerly; the Pi Zero 2 W is resource constrained.
- **Where:** `crates/rustyjack-wireless/src/capture.rs`
- **Fix:** Use a reusable buffer strategy:
  - ring buffer,
  - `Bytes`/`Arc<[u8]>` pooling,
  - or downstream parsing on borrowed slices with short-lived lifetimes.
- **Fixed version looks like:** A `PacketPool` with bounded memory and counters for drops under pressure.

### 7) Radiotap parser ignores extended present bitmaps/alignment
- **Problem:** `RadiotapInfo::parse` assumes a single present word and parses only a subset of fields with simplified alignment.
- **Why:** Radiotap explicitly supports extended present bitmaps and field alignment; ignoring these can mis-locate the 802.11 payload boundary and break parsing.
- **Where:** `crates/rustyjack-wireless/src/radiotap.rs`
- **Fix:** Implement full radiotap walking:
  - iterate present words until “extended” bit is unset,
  - apply per-field alignment,
  - validate `it_len` and never trust malformed length fields.
- **Fixed version looks like:** `RadiotapCursor` that yields `(field_id, field_bytes)` with strict bounds checks + a fuzz harness.

### 8) 802.11 parser assumes simplified header layout
- **Problem:** `Ieee80211Frame::parse` uses a fixed header and doesn’t compute variable header length from frame control bits.
- **Why:** This yields semantic misclassification (e.g., addresses/QoS), which becomes policy risk if filters/UX depend on correct identification.
- **Where:** `crates/rustyjack-wireless/src/frames.rs`
- **Fix:** Compute header length based on:
  - ToDS/FromDS,
  - QoS control present,
  - HT control present.
- **Fixed version looks like:** `fn header_len(fc: FrameControl) -> usize` + parse slices accordingly.

### 9) SSID parsing is lossy and can create collisions
- **Problem:** SSID extraction filters bytes and coerces to `String`.
- **Why:** SSIDs can contain arbitrary bytes; lossy handling can merge distinct networks into one UI label and can break “loot directory” determinism if used downstream.
- **Where:** `crates/rustyjack-wireless/src/frames.rs::extract_ssid`
- **Fix:** Represent SSID as `Vec<u8>` internally; derive a display string separately (escaped/hex as needed).
- **Fixed version looks like:** `struct Ssid { raw: [u8; 32], len: u8, display: String }` (or similar) plus stable hashing for IDs.

### 10) Netlink helpers create a Tokio runtime per call
- **Problem:** Several helper functions build a new `tokio::runtime::Runtime` inside synchronous functions.
- **Why:** Creating nested runtimes can panic or deadlock if called within an existing runtime, and it adds overhead. It also makes cancellation/timeout discipline harder.
- **Where:** `crates/rustyjack-wireless/src/netlink_helpers.rs` and `crates/rustyjack-wireless/src/nl80211.rs::set_mac_address`
- **Fix:** Make these functions async and run them on the daemon’s existing runtime, or create one shared runtime for the crate behind a dedicated worker.
- **Fixed version looks like:** `async fn set_channel_async(...)` and callers use `await` with timeouts and cancellation tokens.

### 11) Channel hopping doesn’t restore prior channel
- **Problem:** Hopping logic sets channels but does not restore the starting channel at the end.
- **Why:** Leaves the interface in a surprising state; can reduce connectivity or confuse subsequent jobs.
- **Where:** `crates/rustyjack-wireless/src/probe.rs` (`sniff_with_hopping`)
- **Fix:** Snapshot starting channel/frequency and restore in `finally`/`Drop`.
- **Fixed version looks like:** `let start = iface.current_channel()?; ... defer { iface.set_channel(start) }`.

### 12) Cleanup relies on “happy path”; crash recovery is not explicit
- **Problem:** Many workflows restore managed mode on normal return/cancel, but there is no explicit “startup recovery sweep” that reasserts baseline after daemon restart.
- **Why:** SIGKILL/power loss skips cleanup; monitor mode/rfkill can leak across boots.
- **Where:** cross-cutting; e.g., `wireless_native.rs`, `interface.rs` (Drop-based restore), daemon startup path
- **Fix:** On daemon startup:
  - enforce isolation invariant,
  - force non-selected wireless to rfkill block,
  - optionally detect and revert monitor-mode interfaces.
- **Fixed version looks like:** `daemon::startup_reassert_network_baseline()` with a one-time, idempotent repair log.

### 13) “Kill interfering processes” is a sharp knife
- **Problem:** `kill_interfering_processes(...)` can terminate processes matching patterns (e.g., “wpa_supplicant”).
- **Why:** Can destabilize connectivity and conflicts with “only selected interface up” policy if you kill something managing a different interface; it’s also a denial-of-service vector if misused.
- **Where:** `crates/rustyjack-wireless/src/nl80211.rs`, `process_helpers.rs`
- **Fix:** Narrow scope:
  - only kill processes proven to be bound to the target interface (via `/proc/<pid>/fd` or netlink),
  - prefer coordinated shutdown via systemd units when present.
- **Fixed version looks like:** “detach interface from wpa control” rather than “kill by name”; or a per-interface pid map.

### 14) Refusal semantics are inconsistent (“warn and continue”)
- **Problem:** Several low-level operations log warnings on failure (e.g., channel set) and continue, even when later steps assume success.
- **Why:** Leads to silent failures and confusing UX; also makes safety validation hard (“did we *really* switch modes?”).
- **Where:** multiple; e.g., `probe.rs` channel hop warnings, mode switch warnings
- **Fix:** Distinguish *policy* from *mechanism*:
  - mechanism returns rich error/report,
  - policy decides whether it’s acceptable to continue.
- **Fixed version looks like:** `Result<VerifiedState, OpError>` with `OpError::Degraded { … }` surfaced to UI.

### 15) Netlink scan parsing should be treated as untrusted input
- **Problem:** nl80211 scan results are parsed from kernel messages and nested attributes; a bug here can panic or mis-parse.
- **Why:** While kernel is “trusted,” malformed/edge-case data from drivers or fuzzed environments can still occur; robust parsing reduces crash risk.
- **Where:** `crates/rustyjack-netlink/src/wireless.rs` (scan result parsing)
- **Fix:** Add exhaustive bounds checks and fuzz harnesses for netlink attribute decoding.
- **Fixed version looks like:** `parse_nested_attrs()` hardened + property tests (“never panic,” “never loop forever,” “reject invalid lengths”).

### 16) pcap writer flushes every packet (performance + wear)
- **Problem:** `PcapWriter::write_packet` calls `flush()` each time.
- **Why:** On SD storage this is slow and increases wear; it also impacts capture throughput.
- **Where:** `crates/rustyjack-wireless/src/pcap.rs`
- **Fix:** Use buffered writes with periodic flush (timer or packet count), and flush on close.
- **Fixed version looks like:** `flush_every_n_packets` + explicit `close()` that flushes once, with `fsync` optional behind a “paranoid mode” toggle.

### 17) TX-risk UX could be clearer at the daemon boundary
- **Problem:** UI gating exists, but daemon APIs may still accept requests that imply TX without a single “this will transmit” flag.
- **Why:** Security boundary is the daemon; relying on UI correctness is risky. Accidental TX is a misuse hazard.
- **Where:** `rustyjack-core` command handling and IPC contract (`rustyjack-ipc` / `rustyjack-commands`)
- **Fix:** Make TX explicit in the request schema:
  - requests that can transmit must carry `tx_ack=true` and a short-lived nonce from a confirmation flow,
  - daemon refuses otherwise.
- **Fixed version looks like:** A “two-phase commit” API: `PrepareTxOp` (returns nonce) → UI shows warning → `ExecuteTxOp { nonce }`.

---

## 6) Test plan

### A) Fuzzing strategy (parser + netlink)
**Tooling:** `cargo-fuzz` (libFuzzer integration) is the standard Rust path.

1) **Radiotap fuzz target**
- Target: `RadiotapInfo::parse(&[u8])`
- Properties:
  - never panic
  - never read out of bounds
  - if it returns `Ok`, `header_len <= input.len()`
- Seed corpus:
  - small real-world radiotap headers
  - synthetic headers with extended present words

2) **802.11 fuzz target**
- Target: `Ieee80211Frame::parse(&[u8])` and `extract_ssid`
- Properties:
  - never panic
  - if `Ok`, parsed addresses are 6 bytes and slices are in-range
  - SSID extraction never allocates beyond length caps

3) **Netlink attribute fuzz target**
- Target: `parse_nested_attrs` + scan result decode path in `crates/rustyjack-netlink/src/wireless.rs`
- Properties:
  - never infinite loop
  - never panic
  - length accounting is monotonic

**CI integration:** add fuzz smoke tests (short runs) in CI and keep longer runs for nightly/on-device lab.

### B) Integration tests with pcap fixtures
Create a `tests/pcap_fixtures/` corpus (checked in) containing:
- radiotap + 802.11 management frames with SSID elements (including non-UTF8 bytes)
- data frames with QoS, null data, and unusual DS bits
- truncated frames and “weird but valid” frames

Tests:
- parse all packets and assert:
  - no panics
  - expected classification for known fixtures
  - malformed fixtures are rejected cleanly

### C) On-device sanity checks (Pi Zero 2 W + USB adapter)
1) **Baseline reassertion**
- Boot device; verify:
  - only selected interface is admin-up
  - non-selected wireless is soft-blocked (where applicable)
2) **Monitor mode session restore**
- Start a monitor-mode workflow, then cancel:
  - verify interface returns to managed mode
  - verify channel restored (after implementing fix)
3) **Crash consistency drill**
- Start a workflow; force-kill daemon; restart:
  - verify startup recovery returns the system to baseline
4) **rfkill truthfulness**
- Hard-block Wi‑Fi via hardware switch (if available) and confirm UX reports inability to unblock (soft vs hard)
5) **Performance sanity**
- Run passive capture for a fixed duration and confirm:
  - CPU stays within expected bounds
  - no unbounded memory growth
  - pcap write throughput acceptable

---

## Appendix: quick “misuse prevention” checklist (daemon/UI)
- TX requires explicit schema-level `tx_ack` + nonce (daemon enforces).
- Stealth mode disables TX-capable endpoints (daemon enforces).
- Global “stop now” cancels blocking reads (capture has timeout/poll).
- Always display RF state: mode, channel, txpower, rfkill, selected iface.
- Startup always reasserts isolation baseline.

## References (external)

- Linux kernel radiotap header documentation (extended present bitmaps, alignment): https://docs.kernel.org/networking/radiotap-headers.html
- Radiotap project (extended presence masks, alignment): https://www.radiotap.org/
- rfkill man page (hard vs soft block behavior): https://www.man7.org/linux/man-pages/man8/rfkill.8.html
- Tokio `spawn_blocking` docs (abort/cancellation semantics): https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- Rust Fuzz Book (`cargo-fuzz`/libFuzzer workflow): https://rust-fuzz.github.io/book/cargo-fuzz.html
- OWASP Log Injection overview: https://owasp.org/www-community/attacks/Log_Injection
- RustSec advisory re: ANSI escape sequence injection via logs (tracing-subscriber): https://rustsec.org/advisories/RUSTSEC-2025-0055
- Linux `packet(7)` man page (AF_PACKET, privilege): https://www.man7.org/linux/man-pages/man7/packet.7.html
- Linux `socket(7)` man page (socket options like SO_BINDTODEVICE): https://www.man7.org/linux/man-pages/man7/socket.7.html
- NIST SP 800-88 Rev.2 (2025) Guidelines for Media Sanitization: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf

