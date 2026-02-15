# Area 4 — Netlink primitives: link and routing core (rustyjack-netlink)

**Date:** 2026-02-13  
**Repo snapshot:** `watchdog_shallow_20260213-173640.zip` (no `.git` metadata in snapshot)  
**Area:** “Netlink primitives: link and routing core”  
**Scope (this report):** `crates/rustyjack-netlink` link bring-up/down, interface enumeration, address + default route management, netlink message parsing/building, error handling, async safety.

**Method:** Follows the review structure and fix-format required by “Architecture Doc 2” (`rustyjack_architecture_analysis_plan.md`).

---

## 0) Constraints & assumptions

### Authoritative constraints (root docs + `logs/done/`)
- **Target platform:** Raspberry Pi Zero 2 W + Ethernet HAT + Waveshare LCD HAT.  
- **Pure Rust policy:** system/network operations should be implemented natively in Rust (no external binaries for runtime ops).  
- **Interface isolation:** system relies on bringing non-selected interfaces down to avoid leakage and routing conflicts; link-up/down failures on Wi‑Fi shouldn’t abort isolation flows.

These constraints inform the “correctness, safety, robustness, Pi limits” framing of this audit.

### What “could go wrong on a Pi Zero 2 W”
- **RAM is small (512MB)** → extra threads, extra buffers, and repeated allocations show up quickly.
- **SD card IO is slow** → chatty logging can produce latency spikes and wear.
- **CPU is slow-ish** → repeated netlink dumps (O(N) syscalls) and heavy runtime creation can be noticeable in UI responsiveness.

---

## 1) API surface map (public items + who calls them)

### A) Top-level convenience functions (`crates/rustyjack-netlink/src/lib.rs`)
These each construct a manager internally and perform one operation:

- `pub async fn set_interface_up(interface: &str) -> Result<()>`
- `pub async fn set_interface_down(interface: &str) -> Result<()>`
- `pub async fn add_address(interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>`
- `pub async fn delete_address(interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>`
- `pub async fn flush_addresses(interface: &str) -> Result<()>`
- `pub async fn list_interfaces() -> Result<Vec<InterfaceInfo>>`
- `pub async fn add_default_route(gateway: IpAddr, interface: &str) -> Result<()>`
- `pub async fn add_default_route_with_metric(gateway: IpAddr, interface: &str, metric: u32) -> Result<()>`
- `pub async fn replace_default_route(gateway: IpAddr, interface: &str, metric: Option<u32>) -> Result<bool>`
- `pub async fn delete_default_route() -> Result<()>`
- `pub async fn list_routes() -> Result<Vec<RouteInfo>>`

**Observed direct call sites (from this snapshot):**
- `set_interface_up(…)`: **no direct callers found** in this snapshot.
- `set_interface_down(…)`: **no direct callers found** in this snapshot.
- `add_address(…)`: **no direct callers found** in this snapshot.
- `delete_address(…)`: **no direct callers found** in this snapshot.
- `flush_addresses(…)`: **no direct callers found** in this snapshot.
- `list_interfaces(…)`: **no direct callers found** in this snapshot.
- `add_default_route(…)`: **no direct callers found** in this snapshot.
- `add_default_route_with_metric(…)`: **no direct callers found** in this snapshot.
- `replace_default_route(…)`: **no direct callers found** in this snapshot.
- `delete_default_route(…)`: **no direct callers found** in this snapshot.
- `list_routes(…)`: **no direct callers found** in this snapshot.

> Note: Many consumers use `InterfaceManager` / `RouteManager` directly (below) instead of these wrappers.

### B) `InterfaceManager` (`crates/rustyjack-netlink/src/interface.rs`)
`pub struct InterfaceManager { handle: rtnetlink::Handle }`

**Construction**
- `pub fn new() -> Result<Self>`  
  - If in an existing Tokio runtime, spawns the netlink connection as a task.
  - Otherwise spawns a new OS thread and creates a Tokio runtime inside it.

**Public operations**
- Link state / enumeration:
  - `pub async fn set_interface_up(&self, name: &str) -> Result<()>`
  - `pub async fn set_interface_down(&self, name: &str) -> Result<()>`
  - `pub async fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>>`
  - `pub async fn get_interface_info(&self, name: &str) -> Result<InterfaceInfo>`
  - `pub async fn get_interface_index(&self, name: &str) -> Result<u32>`
  - `pub async fn get_mac_address(&self, interface: &str) -> Result<String>`
  - `pub async fn set_mac_address(&self, interface: &str, mac: &str) -> Result<()>`
- Address management:
  - `pub async fn add_address(&self, interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>`
  - `pub async fn delete_address(&self, interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>`
  - `pub async fn flush_addresses(&self, interface: &str) -> Result<()>`
  - `pub async fn get_addresses(&self, interface: &str) -> Result<Vec<AddressInfo>>`
  - `pub async fn get_ipv4_addresses(&self, interface: &str) -> Result<Vec<AddressInfo>>`
- Compatibility aliases:
  - `pub async fn set_link_up(&self, name: &str) -> Result<()>`
  - `pub async fn set_link_down(&self, name: &str) -> Result<()>`

**Observed direct call sites of `InterfaceManager::new()` (from this snapshot):**
- (none found)

### C) `RouteManager` (`crates/rustyjack-netlink/src/route.rs`)
`pub struct RouteManager { handle: rtnetlink::Handle }`

**Construction**
- `pub fn new() -> Result<Self>` (same runtime fallback strategy as `InterfaceManager`)

**Public operations**
- `pub async fn add_default_route(&self, gateway: IpAddr, interface: &str) -> Result<()>`
- `pub async fn add_default_route_with_metric(&self, gateway: IpAddr, interface: &str, metric: u32) -> Result<()>`
- `pub async fn replace_default_route(&self, gateway: IpAddr, interface: &str, metric: Option<u32>) -> Result<bool>`
- `pub async fn delete_default_route(&self) -> Result<()>`
- `pub async fn list_routes(&self) -> Result<Vec<RouteInfo>>`

**Observed direct call sites of `RouteManager::new()` (from this snapshot):**
- (none found)

### Feature flags & fallbacks (that touch this area indirectly)
- **Runtime fallback:** `InterfaceManager::new()` / `RouteManager::new()` will spawn a dedicated thread + Tokio runtime if called outside an existing Tokio runtime.
- **`journald` feature:** switches logging backend; on Pi, journald vs file logging can change IO patterns (SD wear vs RAM pressure).
- **`station_external` + `station_rust_*` features:** affect Wi‑Fi supplicant/control paths; not part of link/route core, but they can change how frequently link/route primitives are exercised during connect/reconnect loops.

---

## 2) Kernel interaction model (NETLINK_ROUTE)

### Which kernel APIs are used
The link/address/route core uses **NETLINK_ROUTE** sockets (via `rtnetlink`) to:
- Set interface up/down (RTM_NEWLINK / setlink)
- Dump links (RTM_GETLINK)
- Add/del/dump addresses (RTM_NEWADDR / RTM_DELADDR / RTM_GETADDR)
- Add/del/dump routes (RTM_NEWROUTE / RTM_DELROUTE / RTM_GETROUTE)

This is the same interface used by `ip link`, `ip addr`, `ip route`, but implemented directly in Rust.

### Error signaling + ACK model
- Netlink failures are signaled via **NLMSG_ERROR** with a negative errno in `nlmsgerr.error`.
- Kernel-to-userspace netlink is **not fully reliable**: if the socket receive buffer overflows, messages can be dropped and userspace must detect `ENOBUFS` from `recvmsg()` and resync.  
  Implication: “dump + act” logic should tolerate transient inconsistencies and should be able to re-dump state when it detects drops.

### Current behavior in this repo
- `InterfaceManager` + `RouteManager` use `rtnetlink::new_connection()` and keep the connection future running in the background.
- Operations are “one-shot” awaits with **no explicit timeouts or retries** (except a special-case for EEXIST in `add_address`).
- Error mapping typically flattens the upstream error into a string (`reason: e.to_string()`), which reduces the ability to branch on errno class in callers.

### Suggested robustness model for Pi deployments
- Apply **bounded timeouts** to each netlink round-trip (avoid UI/daemon hangs).
- Add **tiny retries** for transient errors (`EINTR`, `EAGAIN`, sometimes `EBUSY`), with very small backoff.
- If a netlink dump detects `ENOBUFS` (or library surfaces it), re-dump and re-evaluate (idempotent reconciliation pattern).

---

## 3) Safety audit (unsafe blocks, validation, lifetimes)

### Unsafe code
- **Link + route core (`interface.rs`, `route.rs`):** **no `unsafe` blocks.**
- Other modules in `rustyjack-netlink` do contain `unsafe` (raw sockets, ioctl, FFI). Those are *out of scope for Area 4* but matter for the crate’s overall risk profile.

**Unsafe occurrences elsewhere in `rustyjack-netlink` (out of Area 4 scope, but relevant for overall risk):**

- (Not exhaustive in this section; this is the “highest density” subset.)

### Input validation (core)
Good:
- Interface name empty checks in `set_interface_up/down`, `add/delete/flush_addresses`.
- Prefix length bounds in `add_address` and `delete_address` (IPv4 max 32, IPv6 max 128).
- MAC parsing validates 6 bytes.

Gaps / pitfalls:
- Address listing and deletion uses **IFA_ADDRESS** only; on point-to-point links the local address is typically in **IFA_LOCAL** (see Findings).
- `flush_addresses` ignores deletion failures, which can silently leave addresses behind (safety + correctness issue).
- Error types often store only strings, losing structured error data that could be used for safe branching (permission vs transient vs “not found”).

### Bounds/lifetimes
- Core logic relies on safe Rust types from `netlink-packet-route` and `rtnetlink`, so bounds/lifetimes are managed safely by the libraries.
- The main “safety” concern here is *operational safety* (avoiding accidental network loss, leaks, and hangs), not memory unsafety.

---

## 4) Performance audit (Pi resource limits)

### Hot spots and avoidable costs
1) **Runtime/thread creation in fallback path**
- `InterfaceManager::new()` and `RouteManager::new()` spawn a new OS thread and create a Tokio runtime using `Runtime::new()`, which is typically a **multi-thread runtime**. On a Pi, that can multiply threads and memory.

2) **Per-operation connection setup**
- The top-level convenience functions in `lib.rs` create a fresh manager per call. In a control loop (UI refresh, periodic probes, isolation loops), this can cause repeated socket setup and thread churn.

3) **N+1 netlink dumps in `list_interfaces()`**
- For each interface, `list_interfaces()` calls `get_interface_addresses(index)` which performs a netlink address dump filtered by index. With N interfaces, that is N address dumps.

4) **Allocation patterns**
- Frequent `to_string()` allocations on hot paths (match_name takes an owned `String`; errors convert upstream error into `String`).
- `list_interfaces()` builds vectors and strings that are typically small, but avoidable allocations matter on Pi if called often.

### Blocking in async contexts
- The core managers’ operations are async and rely on `rtnetlink`’s async I/O.
- However, *outside this crate*, `crates/rustyjack-core/src/netlink_helpers.rs` provides sync wrappers that call `tokio::runtime::Handle::block_on` when a runtime is present. This is a known footgun: calling `block_on` from a runtime thread can stall progress and/or panic depending on context. (See Findings.)

---

## 5) Findings (10–25, required format)

> Format: **Problem → Why → Where → Fix → Fixed version looks like**

### 1) Multi-thread Tokio runtime per manager in fallback path
**Problem →** `InterfaceManager::new()` / `RouteManager::new()` create `tokio::runtime::Runtime::new()` inside a spawned thread when no Tokio runtime exists.  
**Why →** `Runtime::new()` typically builds a **multi-thread** runtime with multiple worker threads. If these managers are created repeatedly from sync contexts, this can balloon thread count and memory — especially painful on a Pi Zero 2 W.  
**Where →** `crates/rustyjack-netlink/src/interface.rs:30+`, `crates/rustyjack-netlink/src/route.rs:27+`  
**Fix →** Use a **current-thread** runtime in the fallback thread, or accept an injected runtime/handle.  
**Fixed version looks like →**
```rust
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .map_err(|e| NetlinkError::runtime("tokio runtime", e.to_string()))?;
rt.block_on(connection);
```

### 2) Per-call netlink connection churn via top-level convenience functions
**Problem →** Top-level `lib.rs` helpers construct a new manager per call.  
**Why →** Creating a netlink socket + spawning a connection task per operation increases latency and CPU wakeups; repeated use (UI refresh / isolation loops) can degrade responsiveness.  
**Where →** `crates/rustyjack-netlink/src/lib.rs:151+` (e.g., `set_interface_up`, `list_interfaces`, route helpers)  
**Fix →** Provide a shared, reusable manager (e.g., `OnceLock<Arc<InterfaceManager>>` / `OnceLock<Arc<RouteManager>>`), or make callers pass `&InterfaceManager` / `&RouteManager`.  
**Fixed version looks like →**
```rust
static IF_MGR: std::sync::OnceLock<std::sync::Arc<InterfaceManager>> = std::sync::OnceLock::new();

pub async fn set_interface_up(interface: &str) -> Result<()> {
    let mgr = IF_MGR
        .get_or_init(|| std::sync::Arc::new(InterfaceManager::new().expect("init netlink")))
        .clone();
    mgr.set_interface_up(interface).await
}
```

### 3) N+1 address dumps in `list_interfaces()`
**Problem →** `list_interfaces()` dumps links, then for each link calls `get_interface_addresses(index)` (a per-interface addr dump).  
**Why →** Extra syscalls + message parsing. On Pi, repeated dumps during UI refresh can cause stutter.  
**Where →** `crates/rustyjack-netlink/src/interface.rs:461+`  
**Fix →** Dump **all addresses once**, group by `ifa_index`, then attach to each interface.  
**Fixed version looks like →**
```rust
use std::collections::HashMap;

async fn dump_all_addrs_grouped(handle: &rtnetlink::Handle) -> Result<HashMap<u32, Vec<AddressInfo>>> {
    let mut map: HashMap<u32, Vec<AddressInfo>> = HashMap::new();
    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs.try_next().await.map_err(|e| NetlinkError::ListAddressesError {
        interface: "<all>".into(),
        reason: e.to_string(),
    })? {
        // parse AddressInfo, then:
        map.entry(msg.header.index).or_default().push(parsed);
    }
    Ok(map)
}
```

### 4) Address enumeration uses IFA_ADDRESS only (wrong on point-to-point links)
**Problem →** Address parsing looks only at `AddressAttribute::Address`.  
**Why →** On point-to-point links, **IFA_ADDRESS can represent the peer**, and the local address is **IFA_LOCAL**. Using the wrong attribute breaks “what address do I have?” logic and can cause wrong deletions.  
**Where →** `crates/rustyjack-netlink/src/interface.rs:511+` (`get_interface_addresses`)  
**Fix →** Prefer `AddressAttribute::Local` when present; fall back to `Address`.  
**Fixed version looks like →**
```rust
let mut local: Option<IpAddr> = None;
let mut addr: Option<IpAddr> = None;

for nla in msg.nlas.into_iter() {
    match nla {
        AddressNla::Local(bytes) => local = parse_ip(bytes),
        AddressNla::Address(bytes) => addr = parse_ip(bytes),
        _ => {}
    }
}
let chosen = local.or(addr);
```

### 5) `delete_address()` matching can miss the intended address
**Problem →** `delete_address()` matches only on `AddressAttribute::Address == addr`.  
**Why →** Same IFA_LOCAL vs IFA_ADDRESS issue: it may fail to delete the local address on point-to-point links, leaving stale state and breaking isolation flows.  
**Where →** `crates/rustyjack-netlink/src/interface.rs:308+`  
**Fix →** Match against Local-first semantics and consider prefixlen/ifindex checks robustly.  
**Fixed version looks like →** Apply the same Local-preferred extraction and compare against `addr`.

### 6) `flush_addresses()` silently ignores deletion failures
**Problem →** `flush_addresses()` deletes each address but discards the result (`let _ = ...await`).  
**Why →** Silent failure is dangerous: isolation/recovery can “think” the interface is clean but it isn’t, causing leaks and weird routing.  
**Where →** `crates/rustyjack-netlink/src/interface.rs:406+`  
**Fix →** Return aggregated errors, or explicitly treat specific errors as ignorable (`ENOENT`) and log others.  
**Fixed version looks like →**
```rust
let mut errs = Vec::new();
while let Some(addr) = addrs.try_next().await.map_err(|e| NetlinkError::ListAddressesError {
    interface: interface.to_string(),
    reason: e.to_string(),
})? {
    if let Err(e) = self.handle.address().del(addr).execute().await {
        errs.push(e);
    }
}
if !errs.is_empty() {
    return Err(NetlinkError::OperationFailed(format!("flush_addresses had {} failures", errs.len())));
}
```

### 7) No explicit timeouts on netlink operations
**Problem →** Core operations await indefinitely.  
**Why →** If the connection task stalls or the kernel response path wedges, the daemon/UI can hang. On Pi (slow CPU + IO contention), “slow” can look like “hung.”  
**Where →** All async operations in `interface.rs` and `route.rs`  
**Fix →** Wrap each netlink request in `tokio::time::timeout` and map to `NetlinkError::Timeout`.  
**Fixed version looks like →**
```rust
use std::time::Duration;

tokio::time::timeout(Duration::from_secs(2), self.handle.link().set(index).up().execute())
    .await
    .map_err(|_| NetlinkError::Timeout { operation: "set_link_up".into(), timeout_secs: 2 })?
    .map_err(|e| NetlinkError::SetStateError { /* ... */ })?;
```

### 8) Limited errno-aware handling (only EEXIST in `add_address`)
**Problem →** Only one special-case exists (EEXIST for add_address).  
**Why →** Idempotent reconciliations need to treat some errors as “already good” (EEXIST) and others as “transient” (EINTR/EAGAIN). Without this, isolation flows can fail spuriously.  
**Where →** `interface.rs:add_address` handles EEXIST; other ops don’t.  
**Fix →** Centralize errno classification (helper fn) and apply to common ops (routes, deletes).  
**Fixed version looks like →**
```rust
fn errno_of_rtnetlink(err: &rtnetlink::Error) -> Option<i32> {
    match err {
        rtnetlink::Error::NetlinkError(nle) => nle.to_io().raw_os_error(),
        _ => None,
    }
}
```

### 9) `get_mac_address("")` returns InterfaceNotFound instead of InvalidArgument
**Problem →** Empty string is treated as “not found” instead of invalid input.  
**Why →** Makes debugging harder and leads to inconsistent caller behavior.  
**Where →** `crates/rustyjack-netlink/src/interface.rs:561+`  
**Fix →** Mirror `set_interface_up/down` validation.  
**Fixed version looks like →**
```rust
if interface.is_empty() {
    return Err(NetlinkError::InvalidArgument {
        parameter: "interface name".into(),
        value: "".into(),
        reason: "Interface name cannot be empty".into(),
    });
}
```

### 10) Route replacement only reconciles IPv4 default routes
**Problem →** `replace_default_route()` calls `get(IpVersion::V4)` even if the gateway is IPv6.  
**Why →** In dual-stack environments, an IPv6 default route may remain, causing traffic to leak out the “wrong” interface even after “route ensure.”  
**Where →** `crates/rustyjack-netlink/src/route.rs:163+`  
**Fix →** Select `IpVersion` based on `gateway`, and implement the IPv6 deletion path.  
**Fixed version looks like →**
```rust
let ver = match gateway {
    std::net::IpAddr::V4(_) => rtnetlink::IpVersion::V4,
    std::net::IpAddr::V6(_) => rtnetlink::IpVersion::V6,
};
let mut routes = self.handle.route().get(ver).execute();
```

### 11) `delete_default_route()` deletes only IPv4 defaults
**Problem →** Deletes V4 default routes only.  
**Why →** Same leak risk as #10 (IPv6 default route remains).  
**Where →** `crates/rustyjack-netlink/src/route.rs:194+`  
**Fix →** Delete both IPv4 and IPv6 defaults (or accept an explicit version parameter).  
**Fixed version looks like →**
```rust
for ver in [IpVersion::V4, IpVersion::V6] {
    let mut routes = self.handle.route().get(ver).execute();
    // delete defaults
}
```

### 12) Default route deletion assumes gateway-based defaults
**Problem →** The conflicting-default cleanup deletes any default route that doesn’t match `gateway`/`oif`, including defaults without `RTA_GATEWAY`.  
**Why →** For point-to-point, VPN, or certain DHCP/PPP setups, default routes can exist without a gateway attribute. Deleting them blindly can drop connectivity.  
**Where →** `crates/rustyjack-netlink/src/route.rs:351+`  
**Fix →** Treat “no gateway” routes as a separate class: only delete if the route’s output interface conflicts and the system intends to manage that class.  
**Fixed version looks like →**
```rust
if route_gateway.is_none() {
    // Keep unless explicitly managing dev-only defaults
    continue;
}
```

### 13) Error flattening into `String` loses structured diagnostics
**Problem →** Many `map_err(|e| ... reason: e.to_string())` conversions discard errno / io::ErrorKind.  
**Why →** Callers can’t robustly decide “retry vs fatal vs permission” without parsing strings.  
**Where →** Most operations in `interface.rs` and `route.rs`  
**Fix →** Preserve sources using `#[source]` variants (already present in `NetlinkError::Io`), or create `NetlinkError::Netlink { source: rtnetlink::Error }`.  
**Fixed version looks like →**
```rust
#[derive(thiserror::Error, Debug)]
pub enum NetlinkError {
    #[error("Netlink error during {operation}")]
    Netlink { operation: String, #[source] source: rtnetlink::Error },
    // ...
}
```

### 14) Potential async footgun in core wrappers (`block_on` on current Handle)
**Problem →** `crates/rustyjack-core/src/netlink_helpers.rs` uses `Handle::try_current().map(|h| h.block_on(async { ... }))`.  
**Why →** Blocking a runtime worker thread can stall other tasks; depending on runtime/config, it can panic or deadlock. This matters because link/route ops are called during UI + daemon flows.  
**Where →** `crates/rustyjack-core/src/netlink_helpers.rs:23+`  
**Fix →** Prefer async call paths, or route all sync entrypoints through a dedicated shared runtime thread.  
**Fixed version looks like →**
```rust
// Preferred: make the caller async and await directly.
rustyjack_netlink::set_interface_up(interface).await?;
```

### 15) Logging volume can become SD-card pain during polling
**Problem →** Link state and route operations log `info!` on every call.  
**Why →** If UI refresh/polling triggers these frequently, logs can be noisy and cause SD IO churn on a Pi.  
**Where →** `interface.rs:set_interface_up/down`, `route.rs` deletion loop logs  
**Fix →** Downgrade to `debug!` for high-frequency events, or add rate limiting / “changed state only” logging.  
**Fixed version looks like →**
```rust
tracing::debug!("Interface {} set to UP", name);
```

---

## 6) Test plan (unit tests, netlink mocks, on-device probes)

### Unit tests (no root required)
Focus on pure logic and message parsing:
1) **Address attribute selection**
   - Fixture: a serialized RTM_GETADDR reply containing both IFA_ADDRESS and IFA_LOCAL.
   - Test: parser chooses Local when present; falls back correctly.
2) **Default route detection**
   - Unit tests for `is_default_route(prefix_len, destination)` with destination None vs Some.
3) **RouteInfo extraction**
   - Provide `RouteMessage` fixtures with varying attributes (gateway, oif, priority/metric).
   - Validate `RouteInfo` fields and metric handling.

Implementation hint: keep a `tests/fixtures/` folder with small binary dumps or structured `RouteMessage` constructors using `netlink_packet_route` builders.

### Netlink mock strategy (Rust-only, no external binaries)
The core obstacle is that `rtnetlink::Handle` is concrete and talks to a socket.

Two viable strategies:
1) **Introduce an internal trait (recommended)**
   - Define `trait LinkRouteApi` with only the needed methods (set up/down, dump links, dump addrs, add/del routes).
   - Production impl wraps `rtnetlink::Handle`.
   - Test impl returns deterministic streams built from fixtures.

2) **Record/replay netlink frames**
   - Capture netlink replies on a dev machine once (with a small Rust capture harness) and store as fixtures.
   - Tests feed frames into `netlink_packet_route` decoding and validate higher-level logic.
   - This avoids needing a live kernel in unit tests.

### Integration tests (Linux CI / root required)
Run in an isolated network namespace so failures don’t brick CI machines:
- Use `nix::sched::unshare(CLONE_NEWNET)` (or spawn a child process with `unshare`) to create an ephemeral netns.
- Create a dummy link (e.g., `dummy0`) using `rtnetlink` (Rust-only).
- Exercise:
  - `set_interface_up/down(dummy0)`
  - `add_address/delete_address/flush_addresses(dummy0)`
  - `add_default_route_with_metric()` against a veth pair or dummy gateway (where possible)
- Assert kernel state by dumping via the same API and checking consistency.

### On-device probes (Pi Zero 2 W)
A “do no harm” probe suite that can be run over SSH safely:
1) **Dry-run dumps**
   - Dump interfaces + addresses + routes; verify no timeouts, no panics, and bounded memory usage.
2) **Safe dummy operations**
   - Only operate on a temporary dummy interface (if kernel module available), or a deliberately non-uplink interface.
3) **Stress profile**
   - Call `list_interfaces()` in a tight loop for ~10 seconds and measure:
     - max RSS growth
     - CPU utilization
     - log volume / IO activity
   - This catches thread/connection churn regressions quickly.

---

## References (kernel + netlink behavior)

(Links provided in a code block to keep this report self-contained.)

```text
netlink(7) — Linux man-pages (NLMSG_ERROR, errno, ENOBUFS resync guidance)
https://www.man7.org/linux/man-pages/man7/netlink.7.html

rtnetlink(7) — Linux man-pages (NETLINK_ROUTE: links/addr/routes)
https://www.man7.org/linux/man-pages/man7/rtnetlink.7.html

Linux kernel netlink specs — rt-link (link attributes/ops)
https://docs.kernel.org/next/networking/netlink_spec/rt_link.html

Linux kernel netlink specs — rt-addr (addr attributes incl. ifa-local vs ifa-address)
https://docs.kernel.org/6.8/networking/netlink_spec/rt_addr.html

Linux kernel netlink specs — rt-route (route attributes incl. gateway/oif/priority)
https://docs.kernel.org/6.8/networking/netlink_spec/rt_route.html

Tokio runtime docs (Runtime::new and runtime flavors)
https://docs.rs/tokio/latest/tokio/runtime/struct.Runtime.html
```
