# Area 9 — Ethernet operations layer (Architecture Doc 2) — Read‑only review
Date: 2026-02-15


**Repository snapshot:** `watchdog_shallow_20260213-173640.zip` (read-only analysis; no files modified)

**Scope (per request):** Ethernet scanning/recon implementation, raw socket usage, async-vs-blocking boundaries, timeouts, rate limiting, banner parsing, output sanitization, and teardown correctness.

**Constraint model used:** Only **root docs** and **`logs/done`** are treated as constraints; everything else (including this review) is advisory.

---

## 0) What exists today (very short)

The Ethernet “ops layer” is split across:

- **Low-level network logic:** `crates/rustyjack-ethernet/src/lib.rs`
  - ICMP host discovery via **IPv4 raw socket**
  - ARP discovery via **AF_PACKET raw socket** (Linux-only)
  - TCP connect-based port scan + optional banner grab
  - “Inventory” probes (mDNS, NetBIOS, WS-Discovery)
- **Command orchestration + loot/log writing:** `crates/rustyjack-core/src/operations.rs`
- **Daemon job wrapper (async runtime boundary):** `crates/rustyjack-daemon/src/jobs/kinds/*.rs`

---

## 1) Execution model (sync vs async; how daemon avoids blocking)

### Ethernet crate execution style
- The bulk of `rustyjack-ethernet` is **synchronous** (blocking) Rust:
  - `discover_hosts*` (ICMP): tight loops + `std::thread::sleep(...)`
  - `quick_port_scan*`: sequential `TcpStream::connect_timeout(...)`
  - UDP probes (`mDNS` / `NetBIOS` / `WS-Discovery`) use blocking `UdpSocket` with timeouts
- One notable exception: `discover_hosts_arp_cancellable(...)` is **async**, but it immediately offloads the heavy work into `tokio::task::spawn_blocking(...)` and awaits the result.

### Daemon wrapping (critical: tokio current-thread runtime)
The daemon is on a **single-threaded Tokio scheduler** (see `ci/no_blocking_in_async.rs`), so any blocking work must stay out of async tasks.

The daemon achieves this by running core operations in `spawn_blocking(...)`:

- `crates/rustyjack-daemon/src/jobs/kinds/scan.rs` (line ~46): wraps scan work in `tokio::task::spawn_blocking(...)`
- `crates/rustyjack-daemon/src/jobs/kinds/core_command.rs` (line ~34): wraps generic core commands in `spawn_blocking(...)`

This pattern is correct for a current-thread runtime: `spawn_blocking` uses separate OS threads for blocking I/O even when the async runtime is single-threaded.

### Cancellation semantics (important nuance)
`spawn_blocking` tasks **cannot be force-aborted once running**; Tokio explicitly notes that aborting a `spawn_blocking` task usually won’t stop it, and runtime shutdown may wait for them unless a shutdown timeout is used.

So cancellation must be **cooperative** (e.g., your `AtomicBool` checks inside loops) and must be checked frequently enough to bound “time-to-stop”.

**Risk callout:** If future code calls these sync Ethernet routines from async context *without* `spawn_blocking`, the daemon event loop will freeze (UI stalls, watchdog misses timers, etc.).

---

## 2) Safety review (unsafe usage, buffers, parsing untrusted banners)

### Raw socket / packet socket risk profile
- ICMP discovery uses **IPv4 raw sockets**; ARP discovery uses **packet sockets (AF_PACKET)**.
- Packet sockets require elevated privilege (`CAP_NET_RAW`) and receive/send raw frames; they’re powerful and therefore safety-sensitive.
- Linux raw sockets and packet sockets can be bound to a specific device (e.g., `SO_BINDTODEVICE`) to prevent cross-interface leakage.

### `unsafe` inventory (what it is and what could go wrong)
In `crates/rustyjack-ethernet/src/lib.rs`, there are four `unsafe` sites:

1) `std::slice::from_raw_parts(...)` over a `MaybeUninit<[u8; 1500]>` receive buffer
   - Safety depends on using the returned length `n` and not reading beyond it. The code does that, but **header assumptions** can still cause misparsing.
2) Linux ARP plumbing uses libc calls:
   - `if_nametoindex`, `socket(AF_PACKET, SOCK_RAW, ...)`, `bind`, and raw `send`/`recv`
   - Primary hazards are: wrong struct sizes, misaligned casts, and trusting packet structure.

### Parsing untrusted banners and “device strings”
This layer actively ingests strings originating from the network:

- TCP banners (`grab_banner`)
- mDNS records, NetBIOS name tables, WS-Discovery XML-ish blobs
- These are **untrusted** inputs. Two specific risks matter here:

**(a) Log forging / log injection:**
If untrusted data contains newlines, tabs, or crafted prefixes, it can create fake log entries or hide real ones. OWASP explicitly calls this out as Log Injection.

**(b) Terminal escape injection (ANSI control codes):**
Untrusted strings containing escape sequences can manipulate terminal output when viewed (clear screen, hide content, clickable links, etc.). This is not hypothetical; even Rust logging tooling has had real advisories about ANSI escape injection when logging untrusted input.

**Repository-specific observation:** `handle_eth_port_scan(...)` writes banners straight into loot files without neutralization, making it easy to poison stored output for later viewing.

---

## 3) Resource budgeting for Raspberry Pi Zero 2 W

Pi Zero 2 W has a **1GHz quad-core Cortex‑A53** and **512MB SDRAM**.
That’s enough for light recon, but not enough for “spray-and-pray concurrency”.

### Current behavior vs budget
- Port scan is sequential: CPU-light, but time can scale linearly with port list length.
- ICMP discovery can blast packets quickly (no pacing) and keeps an in-flight map; on large CIDRs this becomes both **network-noisy** and **memory-expensive**.
- ARP discovery uses pacing (`rate_limit_pps`) but:
  - currently builds a full `Vec` of targets first (memory spikes on big CIDRs),
  - and send pacing time is not counted against the “timeout”, so wall-clock can exceed what the caller expects.

### Recommended budgets (safe defaults)
These are guardrails aimed at **bounded cost** and **predictable stop time**:

- **CIDR size cap:** refuse (or require explicit “I know what I’m doing” gate) above ~1024 hosts (e.g., larger than /22).
- **ICMP pacing:** token bucket or fixed delay (e.g., 100–200 pps).
- **ARP pps cap:** clamp to a sane max (e.g., 200–500 pps) to avoid `sleep(0)` behavior.
- **Port scan concurrency (if ever added):** 32–64 in-flight connects max; per-host semaphore.
- **String size caps:** banners/records already cap reads, but also cap **stored** and **rendered** sizes (e.g., 256–1024 chars) after sanitization.

---

## 4) Isolation enforcement (only active interface participates)

The repo has a clear “single active interface” concept (`enforce_single_interface(...)` in `rustyjack-core`), and ARP discovery binds the AF_PACKET socket to a specific ifindex.

**But isolation is not consistently enforced at all entry points.**

Two layers matter:

1) **Policy layer:** verify only one interface is active and/or the requested one is active.
2) **Mechanism layer:** bind sockets to an interface (or at least bind source IP) so routing can’t “escape” if policy fails.

Mechanisms you can use safely:
- **Bind-to-device:** `SO_BINDTODEVICE` for raw sockets and UDP sockets (Linux).
- **Bind source IP:** for TCP connect scanning, use `quick_port_scan_with_source(...)` (already exists) and make fallback behavior explicit.

---

## 5) Findings (20)

Format: **Problem → Why → Where → Fix → Fixed version looks like**

### F1 — Port scan does not enforce “single active interface”
- **Problem:** `handle_eth_port_scan` never calls `enforce_single_interface`.
- **Why:** A multi-homed device can route scans over an unintended interface (privacy + correctness).
- **Where:** `crates/rustyjack-core/src/operations.rs` `fn handle_eth_port_scan` (~L516).
- **Fix:** Call `enforce_single_interface(&iface.name)` after `detect_ethernet_interface()`.
- **Fixed version looks like:**
  ```rust
  let interface = detect_ethernet_interface(&root)?;
  enforce_single_interface(&interface.name)?;
  ```

### F2 — Inventory also skips interface enforcement
- **Problem:** `handle_eth_inventory` does not call `enforce_single_interface`.
- **Why:** mDNS/NetBIOS/WS-Discovery probes can leak to other NICs if routing changes.
- **Where:** `crates/rustyjack-core/src/operations.rs` `fn handle_eth_inventory` (~L622–765).
- **Fix:** Same as F1.
- **Fixed version looks like:** identical pattern as F1.

### F3 — Port scan does not bind source (may route off-interface)
- **Problem:** `handle_eth_port_scan` uses `quick_port_scan(...)` (routing-decided).
- **Why:** Routing tables decide egress; if you want “Ethernet-only”, bind to the interface IP.
- **Where:** `handle_eth_port_scan` → `rustyjack_ethernet::quick_port_scan(...)`.
- **Fix:** Use `quick_port_scan_with_source(...)` with `source_ip = interface.ip`.
- **Fixed version looks like:**
  ```rust
  let source_ip = interface.ip;
  let results = rustyjack_ethernet::quick_port_scan_with_source(
      target_ip, &ports, timeout, Some(source_ip)
  )?;
  ```

### F4 — Source-binding fallback silently degrades isolation
- **Problem:** `quick_port_scan_with_source` falls back to non-bound connect if bind fails.
- **Why:** Silent fallback can reintroduce cross-interface leakage.
- **Where:** `crates/rustyjack-ethernet/src/lib.rs` `quick_port_scan_with_source` (~L355+).
- **Fix:** Make fallback opt-in (a flag) and default to “fail closed”.
- **Fixed version looks like:**
  ```rust
  let stream = connect_tcp_with_source(...)?; // no fallback
  ```

### F5 — Loot file writing stores raw banners (control chars / log forging)
- **Problem:** Loot output includes `b.banner` verbatim, which may include `\n`, `\r`, tabs, and escape sequences.
- **Why:** Stored output can poison viewers; classic Log Injection / CWE-117 risk.
- **Where:** `crates/rustyjack-core/src/operations.rs` in `handle_eth_port_scan` loot write loop (~L580–610).
- **Fix:** Sanitize before writing: strip/escape control chars, enforce max length.
- **Fixed version looks like:**
  ```rust
  let banner = sanitize_for_log(&b.banner, 512);
  writeln!(f, "{} [{}]: {}", b.port, b.probe, banner)?;
  ```

### F6 — No sanitization before JSON/IPC emission
- **Problem:** Banners and service fields are returned inside JSON structures without neutralization.
- **Why:** Downstream renderers may display them to terminal/logs; escape injection is a known class.
- **Where:** `handle_eth_port_scan` response construction; inventory response too.
- **Fix:** Sanitize at **two** points:
  1) right after parsing network input (normalize), and
  2) right before display/logging (defense in depth).
- **Fixed version looks like:** `banner: sanitize_for_display(banner)`.

### F7 — `grab_banner` returns raw first line; still allows ANSI/controls
- **Problem:** `grab_banner` uses `from_utf8_lossy` and picks a “first line”, but does not strip control codes.
- **Why:** The first line can still contain `ESC` sequences (terminal manipulation).
- **Where:** `crates/rustyjack-ethernet/src/lib.rs` `fn grab_banner` (~L961+).
- **Fix:** Apply a conservative filter: keep printable + whitespace, map others to `\xNN`.
- **Fixed version looks like:**
  ```rust
  let clean = neutralize_controls(line, 256);
  ```

### F8 — ICMP parsing assumes 20-byte IPv4 header (IHL ignored)
- **Problem:** Code reads `bytes[20..]` as ICMP payload.
- **Why:** IPv4 options can increase header length; misparsing leads to wrong host classification and brittle behavior.
- **Where:** `discover_hosts*` receive loop (~L160–205 and ~L270–320).
- **Fix:** Parse IHL: `ihl = (bytes[0] & 0x0F) * 4`; validate `n >= ihl + 8`.
- **Fixed version looks like:**
  ```rust
  let ihl = ((bytes[0] & 0x0f) as usize) * 4;
  if n < ihl + 8 { continue; }
  let icmp = &bytes[ihl..];
  ```

### F9 — ICMP discovery has no pacing / rate limit
- **Problem:** Sends to all hosts as fast as the loop can run.
- **Why:** Bursty traffic can be noisy and can starve the Pi’s CPU/network stack.
- **Where:** `discover_hosts*` send loop (~L136–159 and ~L235–260).
- **Fix:** Add optional pacing (token bucket) and cap max pps.
- **Fixed version looks like:** `limiter.wait_for_slot(); sock.send_to(...)`.

### F10 — ICMP discovery can go unbounded on large CIDRs
- **Problem:** `inflight` HashMap grows with number of target hosts.
- **Why:** Large CIDRs can blow memory/time and make cancellation sluggish.
- **Where:** `discover_hosts*` uses `Ipv4Net::hosts()` without cap.
- **Fix:** Enforce host-count cap at boundary (core args parsing) and/or in crate.
- **Fixed version looks like:** refuse networks bigger than a configured maximum.

### F11 — ARP discovery allocates `Vec` of all targets
- **Problem:** `targets: Vec<Ipv4Addr> = network.hosts().collect()`.
- **Why:** Memory spike + delay before first packet is sent on large CIDRs.
- **Where:** `discover_hosts_arp_blocking` (~L582–590).
- **Fix:** Stream hosts; don’t collect.
- **Fixed version looks like:**
  ```rust
  for ip in network.hosts() { /* send */ }
  ```

### F12 — ARP “timeout” excludes send pacing time
- **Problem:** `timeout` is used as “receive wait”, but send loop can take seconds (rate limiting).
- **Why:** Callers cannot predict wall-clock duration; cancellation may feel “late”.
- **Where:** `discover_hosts_arp_blocking` send loop + then `sock.set_read_timeout(Some(timeout))`.
- **Fix:** Treat timeout as an overall budget (`deadline = now + timeout`), and compute remaining time during send + receive.
- **Fixed version looks like:** `if Instant::now() >= deadline { break; }` throughout.

### F13 — `rate_limit_pps` can be set to absurd values (sleep(0) behavior)
- **Problem:** Delay is `1_000_000 / pps` microseconds; for large pps it rounds to 0.
- **Why:** Removing pacing can flood the LAN and burn CPU.
- **Where:** ARP discovery delay calculation (~L590–599).
- **Fix:** Clamp pps to a maximum and enforce a minimum sleep (e.g., 1ms).
- **Fixed version looks like:** `let pps = pps.clamp(1, 500);`.

### F14 — mDNS queries don’t pin outgoing interface
- **Problem:** `query_multicast_dns` binds `0.0.0.0:0` and sends multicast; no interface selection.
- **Why:** Multi-homed systems can emit multicast on unintended NICs.
- **Where:** `crates/rustyjack-ethernet/src/lib.rs` `fn query_multicast_dns` (~L1124+).
- **Fix:** Set outgoing interface (Linux `IP_MULTICAST_IF`) or use `SO_BINDTODEVICE`.
- **Fixed version looks like:** platform-gated setsockopt on the underlying fd.

### F15 — NetBIOS and WS-Discovery probes also lack interface pinning
- **Problem:** Similar to mDNS: default routing decides.
- **Why:** Same cross-interface leakage risk.
- **Where:** `query_netbios`, `query_ws_discovery` helpers in ethernet crate.
- **Fix:** Bind-to-device or bind source IP, and ensure core enforces single interface.
- **Fixed version looks like:** `udp.bind((iface.ip, 0))` + `SO_BINDTODEVICE` (Linux).

### F16 — DNS record parser continues after decode failure
- **Problem:** `parse_dns_records` ignores failure to decode answer names (it does `let _ = decode_dns_name(...)`).
- **Why:** Malformed packets can cause garbage parsing and misleading results.
- **Where:** `parse_dns_records` (~L1063+).
- **Fix:** If name decode fails, stop parsing that packet.
- **Fixed version looks like:**
  ```rust
  decode_dns_name(data, &mut offset, 0)?;
  ```

### F17 — WS-Discovery parsing is “stringly-typed” and may be spoofed
- **Problem:** Extracts fields via substring searches rather than real XML parsing.
- **Why:** Attackers can craft responses that trick the parser (e.g., nested tags, encoding).
- **Where:** `query_ws_discovery` and `parse_ws_discovery` in ethernet crate.
- **Fix:** Treat WS-Discovery output as **untrusted hints**, cap lengths, and apply strict allowlists for extracted tokens.
- **Fixed version looks like:** length-limited extraction + validation.

### F18 — Cooperative cancellation exists, but stop latency depends on sleep/read timeouts
- **Problem:** Cancellation checks exist, but loops include sleeps and socket timeouts.
- **Why:** Worst-case stop latency can approach timeout values, and `spawn_blocking` cannot be hard-aborted.
- **Where:** ICMP receive loops sleep 5ms; ARP socket read timeout uses `timeout`.
- **Fix:** Use short polling intervals (e.g., 20–50ms max), and overall deadline logic.
- **Fixed version looks like:** `read_timeout = 50ms; loop until deadline`.

### F19 — No explicit “max output size” for inventory fields
- **Problem:** Inventory strings are limited by read sizes, but combined output can still be large.
- **Why:** Large JSON/loot can cause memory spikes and UI slowdown on Pi.
- **Where:** `build_device_inventory` (~L1376+).
- **Fix:** Cap number of services recorded per host + cap per-field length post-sanitization.
- **Fixed version looks like:** `services.truncate(MAX_SERVICES)`.

### F20 — Missing tests for parsing + isolation + timing regressions
- **Problem:** Parsing and network boundaries are high-risk but currently unguarded by deterministic tests (from what’s visible in repo).
- **Why:** Regressions here become “it worked on my LAN” ghosts; Pi timing makes it worse.
- **Where:** Test coverage gap (no dedicated ethernet ops fixture/harness).
- **Fix:** Add a fixture-based integration harness and fuzz/property tests (see next section).
- **Fixed version looks like:** described below.

---

## 6) Test plan

### A) Simulated LAN fixtures (repeatable, safe)
Goal: test discovery and inventory without touching a real LAN.

- Use a Linux host (or CI runner) with isolated network namespaces + virtual Ethernet pairs (veth).
- Put a “device emulator” namespace that:
  - responds to ARP,
  - listens on a few TCP ports and emits fixed banners,
  - responds to mDNS/NetBIOS/WS-Discovery with deterministic payloads.
- Run the Ethernet ops against that namespace only.

**Guardrail:** keep fixtures local-only; no bridging to the real network.

### B) Deterministic test harness (time + I/O)
Current code uses `std::thread::sleep` and OS socket timeouts, which are hard to make deterministic.

Recommended architecture for tests:
- Factor the ethernet crate’s I/O behind a small trait like `EthernetIo`:
  - `send_icmp`, `recv_icmp`, `send_arp`, `recv_arp`, `tcp_connect`, `udp_query`
- Provide:
  - a real implementation (sockets),
  - a fake implementation (pre-scripted responses),
  - a “clock” abstraction so tests can fast-forward time.

This yields unit tests like:
- “ICMP reply with options header (IHL>5) parses correctly”
- “banner contains ESC and newlines → sanitized output matches snapshot”
- “cancellation stops within <= X ms of check interval”

### C) On-device timing / resource tests (Pi Zero 2 W)
Goal: ensure budgets remain realistic under Pi CPU + scheduler behavior.

On the Pi:
- Run each operation with a fixed fixture (e.g., a small unmanaged switch + one responder device)
- Collect:
  - wall-clock duration,
  - peak RSS (resident memory),
  - CPU utilization,
  - number of packets sent (optional, if measured internally).
- Track against acceptance targets:
  - discovery on /24 completes in N seconds with pps cap,
  - port scan of 100 ports finishes within M seconds,
  - cancellation stops in < 250ms in normal conditions.

---

## Risk summary (what to fix first)

1) **Output neutralization (banners + service strings)** to prevent log/terminal injection and log forging.
2) **Isolation enforcement everywhere** (policy + socket binding).
3) **Bounded work** (CIDR caps, pacing, overall deadlines) for Pi predictability.
4) **Cancellation latency** tuned for `spawn_blocking` semantics.

---

## Appendix: paths reviewed

- `crates/rustyjack-ethernet/src/lib.rs`
- `crates/rustyjack-core/src/operations.rs`
- `crates/rustyjack-core/src/system/mod.rs`
- `crates/rustyjack-daemon/src/jobs/kinds/scan.rs`
- `crates/rustyjack-daemon/src/jobs/kinds/core_command.rs`
- Root docs + `logs/done/*` relevant to Ethernet recon + interface isolation

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

