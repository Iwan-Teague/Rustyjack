# Area 6 — DHCP and address management (Architecture Doc 2)
Date: 2026-02-15


> **Read-only report.** No repository files were modified.

## Evidence model and constraints (per Architecture Doc 2)

- Authoritative constraints come from **root docs** and **`logs/done/`** docs.
- Code is treated as “what it does today,” not as a normative source of truth.
- “Home‑grown Rust where possible” is a guiding requirement; any reliance on external DHCP tooling should be called out.

## Scope

- DHCP **client** behavior for uplink acquisition, renew, release
- DHCP **server** behavior used for hotspot / captive portal mode (if applicable)
- Lease storage / persistence, timeouts / retries
- Interaction with interface switching + isolation
- Explicitly call out any risk of:
  - bringing up more than one uplink interface, or
  - leaking DHCP traffic on dormant interfaces

---

## 1) Intended behavior per mode

### 1.1 Uplink: DHCP client (acquire address for selected uplink)

**Intent**
- When an interface is selected as the uplink, the system should:
  1. Bring the interface up (admin UP).
  2. Run DHCP to obtain a lease (IP, subnet mask, gateway/router, DNS, lease time).
  3. Apply the lease to the interface.
  4. Apply routing (default route via gateway) and DNS configuration.
  5. Record enough state to support renew/release and observability.
  6. Ensure only the selected interface participates (no “ghost DHCP” from dormant interfaces).

**Observed current behavior (code)**
- DHCP client implementation: `crates/rustyjack-netlink/src/dhcp.rs`
- DHCP acquisition is invoked by higher layers, typically:
  - `crates/rustyjack-core/src/system/interface_selection.rs`
  - `crates/rustyjack-core/src/system/isolation.rs`
- Applying the lease:
  - Address is applied inside the DHCP client module (flush + add address).
  - Default route and DNS are applied by the caller (selection/isolation), using values in the lease.

**Renew / release**
- Renew exists (`DhcpClient::renew`) but is invoked explicitly (e.g., reconnection flows), not as a continuously scheduled background process.
- Release exists (`DhcpClient::release`) and is used during interface switching; address flushing is handled by switching logic.

### 1.2 AP / hotspot / portal: DHCP server (serve leases on an AP interface)

**Intent**
- When running a hotspot/captive portal:
  1. Assign the AP interface a static IP (the server/gateway address).
  2. Run a DHCP server bound to the AP interface (UDP/67) to hand out leases in a configured pool.
  3. Optionally run DNS (and captive portal logic) pointing clients to the portal.
  4. Ensure DHCP traffic stays on the AP interface only.

**Observed current behavior (code)**
- DHCP server: `crates/rustyjack-netlink/src/dhcp_server.rs`
- Hotspot wiring: `crates/rustyjack-wireless/src/hotspot.rs`
  - Starts `DhcpServer` with a custom `DhcpConfig` (server IP, pool range, lease time, DNS pointing at the gateway).

**Important note**
- DHCP server leases are currently **in-memory only**; restarting the hotspot server forgets prior leases.

---

## 2) Implementation map (paths; state files; timers)

### 2.1 DHCP client

**Primary file**
- `crates/rustyjack-netlink/src/dhcp.rs`

**Entry points**
- `DhcpClient::acquire_report_timeout(iface, timeout)`
  - Tries raw “packet socket” transport first (`DhcpTransport::RawSocket`), then falls back to UDP (`DhcpTransport::UdpSocket`).
  - DHCP flow:
    - Send DISCOVER → wait OFFER (`wait_for_offer`)
    - Send REQUEST → wait ACK (`wait_for_ack`)
- `DhcpClient::renew(iface, current_ip, timeout)`
  - Sends a renewal-style REQUEST, waits for ACK.
- `DhcpClient::release(iface, lease)`
  - Sends DHCPRELEASE; does **not** flush addresses itself.

**Interface configuration**
- `configurefinterface(iface, lease)` in `dhcp.rs`
  - Flushes all addresses on the interface.
  - Adds the leased address + prefix.
  - Does **not** apply default route or DNS (despite the comment implying it does).

**Lease/state storage**
- `crates/rustyjack-core/src/system/mod.rs`
  - `LEASE_RECORD: Mutex<HashMap<String, LeaseInfo>>` (in-memory)
  - Functions: `record_lease()`, `get_lease_record()`, `clear_lease_record()`

**Timers/retries (actual code behavior)**
- Callers usually pass a 30s overall timeout (e.g., interface selection).
- Discover phase:
  - Up to 3 attempts (per acquisition), with a 1s sleep between attempts.
  - Each attempt waits for an OFFER with a receive timeout capped at 5s, but bounded by the overall deadline.
- Request/ACK phase:
  - Within an attempt, waits for ACK up to 5 receive cycles; each cycle’s read timeout is capped at 5s and bounded by the overall deadline.
- There is no randomized exponential backoff; pacing is mostly fixed/capped.

### 2.2 DHCP server (hotspot)

**Primary file**
- `crates/rustyjack-netlink/src/dhcp_server.rs`

**Core behavior**
- `DhcpConfig` default:
  - server IP: `10.20.30.1`
  - pool: `10.20.30.100–10.20.30.200`
  - lease time: `3600s`
  - DNS: `[8.8.8.8, 8.8.4.4]`
- `DhcpServer::start()` spawns a dedicated OS thread which:
  - binds UDP socket to interface with `SO_BINDTODEVICE`,
  - handles: DISCOVER/OFFER, REQUEST/ACK, RELEASE, DECLINE, INFORM,
  - runs a cleanup pass every 5 seconds to remove expired leases.

**Hotspot integration**
- `crates/rustyjack-wireless/src/hotspot.rs`
  - starts DHCP server with:
    - server IP: `192.168.50.1`
    - pool: `192.168.50.100–192.168.50.200`
    - lease time: `3600s`
    - DNS: `[192.168.50.1]` (local gateway/portal DNS)

**State files**
- Hotspot runtime state file:
  - `/tmp/rustyjack-hotspot-state.json` (tracks hotspot servers/ports; not DHCP leases)
- DHCP leases:
  - **not persisted** (held only in `DhcpState` maps in memory).

---

## 3) Failure handling

### 3.1 Timeouts and retries
- Client acquisition is bounded by the caller-provided timeout (commonly 30s).
- On failure to obtain OFFER/ACK within an attempt, client retries (up to 3 attempts).
- If raw transport fails, the client retries raw a small number of times and then falls back to UDP.

### 3.2 Partial/invalid leases
- ACK parsing requires:
  - message type = DHCPACK
  - option 51 (lease time)
  - option 1 (subnet mask)
  - option 3 (router/gateway)
  - option 6 (DNS servers)
- Missing required options causes acquisition to fail.

### 3.3 Link flap / switching mid-lease
- Interface switching logic (uplink changes) actively:
  - releases DHCP on the old interface (best-effort),
  - flushes addresses on non-selected interfaces,
  - ensures default route and DNS point at the newly selected interface.
- Because there is no continuous renewer, link flaps and long runtimes can still produce stale/expired leases unless another reconnection path triggers DHCP again.

### 3.4 Server restart behavior (AP mode)
- DHCP server leases are in-memory.
- Restarting the server forgets leases; clients keep old IPs until they renew, which can create churn and temporary confusion.

---

## 4) Isolation interactions (ensure only selected interface participates)

### 4.1 Socket-level isolation (DHCP traffic stays on one NIC)
- DHCP client UDP sockets are bound to a specific interface using `SO_BINDTODEVICE`.
- DHCP server sockets are also bound using `SO_BINDTODEVICE`.
- This prevents DHCP send/receive from “spilling” across interfaces even if multiple NICs are up.

### 4.2 System-level isolation (admin state + routes + DNS)
- Interface selection/isolation layers aim to enforce:
  - only one uplink interface is active for egress at a time,
  - default route and DNS correspond to the selected interface’s lease,
  - non-selected interfaces are brought down and/or have addresses flushed.

### 4.3 Explicit call-out: risks of “more than one interface up” and DHCP leakage
- Hotspot mode intentionally creates a **two-interface** steady state:
  - uplink (DHCP client),
  - AP interface (DHCP server + DNS).
- The remaining DHCP leakage risks come from:
  - invoking DHCP acquisition on a non-selected interface from ad-hoc operations/feature code,
  - leaving an interface up and configured while switching,
  - or keeping stale default routes/DNS after a partial DHCP failure.

---

## 5) Findings (Problem → Why → Where → Fix → Fixed version looks like)

1. **Blocking UDP I/O inside async DHCP acquisition** → `std::net::UdpSocket::recv_from()` is called from `async fn` code paths; even with short read timeouts it can block Tokio worker threads → `crates/rustyjack-netlink/src/dhcp.rs` (UDP transport receive loops) → Use `tokio::net::UdpSocket` (preferred) or wrap blocking recv/send in `spawn_blocking` → Acquisition/renew no longer blocks runtime threads; concurrency tests show stable latency for unrelated async tasks.

2. **No RFC-style randomized exponential backoff for retransmissions** → DHCP clients are expected to use randomized exponential backoff for retransmissions; fixed pacing can cause synchronization/bursts on congested networks → `crates/rustyjack-netlink/src/dhcp.rs` (fixed retry structure + capped timeouts) → Implement exponential backoff with jitter for DISCOVER/REQUEST retransmits (bounded by overall deadline) → Packet traces show increasing retry spacing with jitter; fewer synchronized “storms” in multi-client tests.

3. **Lease renewal is not automatically scheduled** → Without background renew, leases can expire silently on long-running sessions → `crates/rustyjack-netlink/src/dhcp.rs` provides `renew()`, but higher layers do not schedule it → Add a per-interface renewal task using T1/T2 derived from lease time; cancel/reschedule on interface switch → The selected uplink renews before expiry; multi-hour runs keep connectivity without manual reconnection.

4. **No lease persistence across reboot/restart** → Reboots lose lease info and timing, causing unnecessary churn and slower recovery → `crates/rustyjack-core/src/system/mod.rs` (`LEASE_RECORD` is in-memory) → Persist per-interface lease records to disk (e.g., `/var/lib/rustyjack/dhcp/<iface>.json`) with expiry checks and replay-safe loading → On reboot, system can reuse/renew quickly and restore routing/DNS deterministically.

5. **Lease application is split across layers without a single “apply lease” API** → Address is applied in netlink DHCP client, while route+DNS are applied by callers; this invites drift and inconsistent call sites → `dhcp.rs` vs `interface_selection.rs` / `isolation.rs` → Introduce a single “apply_lease” operation (address + route + DNS) with explicit policy knobs → New call sites can’t accidentally apply only half a lease; code becomes easier to audit.

6. **Misleading comment + misspelling in `configurefinterface`** → Comment implies gateway/DNS are configured but they are not; name misspelling adds friction for maintenance → `crates/rustyjack-netlink/src/dhcp.rs` (`configurefinterface`) → Rename to `configure_interface_address` (or similar) and update comment to match reality (or fold into apply_lease) → Clear intent at call sites; fewer incorrect assumptions.

7. **No duplicate-address defense before applying a lease** → Misconfigured DHCP servers or overlapping pools can hand out an IP already in use; client will configure it and cause confusing failures → `crates/rustyjack-netlink/src/dhcp.rs` (post-ACK apply) → Add ARP-based duplicate address detection; send DHCPDECLINE on conflict and retry → In collision tests, client declines and reacquires; no duplicate-IP config is applied.

8. **DHCPNAK handling is coarse** → NAKs are treated as generic “not a DHCPACK” errors; state-machine behavior is not explicit → `crates/rustyjack-netlink/src/dhcp.rs` (`parse_ack_packet` requires DHCPACK) → Parse DHCPNAK explicitly and restart the state machine immediately (new DISCOVER), clearing any stale lease record for that iface → NAKs produce quick, deterministic recovery without long retry loops.

9. **Hard-fail on missing router/DNS options reduces interoperability** → Some minimal DHCP environments omit option 3 or 6; hard failing prevents getting an address even if that might be acceptable under policy → `crates/rustyjack-netlink/src/dhcp.rs` (`parse_ack_packet` requires gateway + DNS) → Make router/DNS options policy-driven (required vs optional); allow “address-only lease” if the caller permits → Works on minimal servers when allowed; strict mode still rejects incomplete leases when required.

10. **Raw transport permission errors can add latency/noise before UDP fallback** → On systems lacking `CAP_NET_RAW`, raw socket operations will fail; current approach retries raw before falling back → `crates/rustyjack-netlink/src/dhcp.rs` (raw-first + retry loop) → Detect permission errors once and disable raw for the session (or gate by capability check) → Immediate UDP path when raw isn’t available; cleaner logs and faster acquisition.

11. **Server default DNS points to public resolvers** → Defaulting to `8.8.8.8/8.8.4.4` can unintentionally leak DNS traffic; hotspot/portal typically wants local DNS → `crates/rustyjack-netlink/src/dhcp_server.rs` (`DhcpConfig::default`) → Default DNS to `server_ip` (or empty) unless explicitly configured → Default server behavior stays local and predictable; no surprising external DNS.

12. **DHCP server leases are not persisted** → Restarting the server forgets leases, causing churn and potential client confusion → `crates/rustyjack-netlink/src/dhcp_server.rs` (`DhcpState` in-memory) → Persist lease bindings (MAC↔IP↔expiry) or implement deterministic address mapping (MAC hash into pool) → After restart, clients mostly keep the same IP; fewer reconnect glitches.

13. **DHCP server does not probe for address conflicts before offering** → Pool overlap with an existing network device can cause collisions → `crates/rustyjack-netlink/src/dhcp_server.rs` (`allocate_ip` / offer) → Add ARP probe (or a configurable “conflict detection” mode) and skip in-use IPs → Server avoids giving out already-used IPs in overlap tests.

14. **Lease cleanup tick is fixed and scans maps** → Periodic full-map scans every 5 seconds can become inefficient for large client counts → `crates/rustyjack-netlink/src/dhcp_server.rs` (cleanup loop) → Track expiries with a min-heap/priority queue and sleep until next expiration; avoid full scans → CPU stays low even with many clients; cleanup cost scales with expiring leases, not total leases.

15. **Recon code reads external dhclient lease files** → Parsing `/var/lib/dhcp/dhclient.*.leases` couples recon behavior to external DHCP tooling and conflicts with the “home-grown Rust where possible” direction → `crates/rustyjack-wireless/src/recon.rs` (`get_dhcp_server`) → Replace with internal lease record/persistence (preferred), or derive gateway/DHCP server from kernel route + stored lease options → Recon is self-contained and consistent with RustyJack’s own DHCP stack.

16. **Risk: DHCP can be invoked on a non-selected interface in ad-hoc operations** → Interface selection/isolation protect the main path, but direct calls to `ops.acquire_dhcp()` from feature code can still broadcast DHCPDISCOVER on a dormant NIC (even if the socket is bound, the NIC may still be “active” from the kernel’s perspective) → Cross-cutting: `operations.rs` and feature modules → Gate DHCP acquisition behind “selected interface” checks (or an isolation guard), and ensure dormant interfaces are admin-DOWN before running DHCP on the chosen interface → In multi-NIC tests, only the selected interface emits DHCP traffic; no DHCP packets are observed on dormant interfaces.

---

## 6) Test plan

### A. Lease churn
1. Configure a DHCP server with short leases (e.g., 60–120s).
2. Acquire a lease, then verify:
   - address/prefix are correct,
   - default route points to the lease gateway,
   - DNS matches lease configuration.
3. Keep the system running through multiple lease renewals (once scheduled renew exists).
4. Validate:
   - renew happens before expiry,
   - default route/DNS stay consistent,
   - no DHCP traffic appears on non-selected interfaces.

### B. Link flap
1. Acquire a lease on uplink A.
2. Flap link:
   - short flaps (1–3s),
   - longer flaps (15–30s).
3. Validate:
   - DHCP reacquires cleanly on link return,
   - no “half-configured” state persists (address without route, or route without address),
   - no stale default routes remain after reacquire.

### C. Concurrent switch + DHCP
1. Start DHCP acquisition on interface A.
2. Mid-acquisition, trigger a switch to interface B.
3. Validate:
   - A’s acquisition is abandoned/canceled,
   - A gets best-effort RELEASE and address flush,
   - only B ends up with default route + DNS,
   - no duplicate default routes exist.

### D. Reboot persistence
1. Acquire a lease and record it (once lease persistence exists).
2. Reboot service/system.
3. Validate:
   - lease record loads,
   - if still valid: fast path (reuse + verify or immediate renew),
   - if expired: clean reacquire,
   - routes/DNS match the selected interface.

### E. Hotspot DHCP server behavior
1. Start hotspot + DHCP server on AP interface.
2. Connect multiple clients and verify:
   - leases are in pool range,
   - router option points to server IP,
   - DNS points to the configured DNS (often the gateway/portal),
   - expired leases are reclaimed.
3. Restart hotspot/server and evaluate churn:
   - baseline: in-memory lease churn,
   - improved: deterministic or persisted lease behavior (if implemented).

---

## Key risk call-outs (explicit)

- **More than one interface up:** uplink selection aims to keep a single uplink active, but hotspot mode intentionally uses two interfaces (uplink + AP). DHCP roles must remain strictly separated in that state.
- **DHCP leakage on dormant interfaces:** `SO_BINDTODEVICE` provides strong socket-level isolation, but ad-hoc operations and partial switching failures can still produce DHCP traffic on non-selected interfaces if they remain admin-UP.
