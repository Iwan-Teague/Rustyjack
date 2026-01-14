# RustyJack Wireless Operations (PI0/W2) — Strict Interface Isolation & Unified Pipeline Patch Guide
**Version:** v1.0 (generated 2026-01-14)  
**Audience:** Rust engineers (networking / systems)  
**Scope:** Wireless operations orchestration + isolation enforcement + reliability hardening (Rust-only, no third‑party binaries)

> This guide is an *engineering patch plan* derived from the existing roadmap and the current repository state.
> The non-negotiable invariant is **strict interface isolation**: *only the selected interface(s) may be operational; all others must be DOWN (and wireless rfkill-blocked), continuously enforced.*

---

## 0) Non‑negotiables (read this first)

### 0.1 Hard constraints
- **Rust-only**: do not shell out to `ip`, `iw`, `iptables`, `hostapd`, `dnsmasq`, etc.
- **No third‑party binaries** in any wireless operation pipeline.
- Keep the existing Linux **netlink / nl80211** approach.

### 0.2 Strict isolation invariant (the big one)
For any operation with an *explicit* chosen interface `I`:

- `I` may be UP (operational).
- **Every other interface must be DOWN** (including ethernet ports).
- Any non-selected wireless interface must also be **rfkill-blocked**.
- This must be **ever‑prevalent**:
  - enforced immediately at operation start,
  - and continuously enforced while the operation is running (netlink events and periodic re-assert).
- **Only allowed exception:** operations that *explicitly* require multiple interfaces. In those cases:
  - you must specify an allow‑list `{I1, I2, ...}`,
  - **and every interface not in the allow‑list must still be DOWN**.

**Expected user experience:** switching interfaces will interrupt existing SSH sessions if they were on a now-blocked interface. That’s intended.

---

## 1) Repository reality check (verified from code)

### 1.1 Isolation primitives exist, but strictness + uniform usage is inconsistent
- `rustyjack-core/src/system/mod.rs`
  - `enforce_single_interface(interface: &str)` calls `apply_interface_isolation(&[interface.to_string()])`.
- `apply_interface_isolation_with_ops()` currently **ignores bring_down errors** (and some bring_up errors), which weakens “must be unoperational”.

### 1.2 Isolation is *missing* for at least one wireless op handler
- `rustyjack-core/src/operations.rs`
  - `handle_wifi_karma(...)` does **not** call `enforce_single_interface(...)` before executing.

### 1.3 Hotspot uses a multi-interface allow‑list, but treats isolation as “best effort”
- `rustyjack-core/src/operations.rs`
  - `handle_hotspot_start(...)` builds `allowed_interfaces=[ap, upstream]`, but:
    - applies isolation **after** hotspot starts
    - logs a warning and proceeds if isolation fails

### 1.4 Wireless route ensure calls an external binary
- `rustyjack-core/src/operations.rs`
  - `ensure_route_health_check()` shells out: `Command::new("id").arg("-u")...`
  - violates the “no third‑party binaries” constraint

### 1.5 Packet capture artifacts are written as raw concatenated bytes
- `rustyjack-core/src/wireless_native.rs`
  - capture output is written by concatenating `pkt.raw_data` and saving with `.pcap` extension
  - this is **not a valid PCAP file format** and will break standard tooling

### 1.6 CLI/config fields not wired correctly
- `rustyjack-core/src/wireless_native.rs`
  - CLI includes a `continuous` flag for certain operations, but native config construction does not use it (it always behaves as continuous bursts until duration).

### 1.7 Requirement checks messaging mismatch
- `rustyjack-core/src/operations.rs`
  - handler constructs “apt install …” failure text for a requirements list
- `rustyjack-wireless/src/evil_twin.rs`
  - `check_requirements()` returns empty and explicitly says no external tools are needed

---

## 2) The plan (what we’re changing)

This guide is structured as:

**Problem → Why → Exact architectural/code changes → What “done” looks like**

Each “How to fix” includes:
- concrete files/functions to edit
- suggested refactors
- pseudo-code close to Rust
- tests and verification steps

---

# Problem A — Isolation enforcement is not uniform (and not strict enough)

## A1) Problem
Some operations enforce isolation, others do not (example: `handle_wifi_karma`).  
Additionally, `apply_interface_isolation_with_ops()` can silently fail to bring interfaces DOWN, violating the invariant.

## A2) Why it matters
Strict isolation is the project’s defining safety/security property. If *any* operation bypasses it, the system no longer has a reliable “one-interface-at-a-time” model.

This also affects correctness: results can be contaminated by traffic from unintended interfaces.

## A3) Exact architectural / code changes (How to fix — extremely detailed)

### A3.1 Introduce a single “Strict Isolation Policy” mechanism used everywhere
Right now you have *multiple* overlapping concepts:
- “preferred interface” file (`PreferenceManager`)
- ad-hoc calls to `apply_interface_isolation`
- daemon netlink enforcement (`IsolationEngine::enforce()`)

To make isolation ever‑prevalent and consistent, unify around an explicit **policy**:

#### Add: `IsolationPolicyManager`
Create file:
- `rustyjack-core/src/system/isolation_policy.rs`

Purpose:
- write/read the active isolation allow‑list (single or multi)
- optionally include a TTL / session token so policies can be reverted safely

Suggested policy file location (under root):
- `root/network/isolation_policy.json`

Example JSON:
```json
{
  "version": 1,
  "mode": "allow_list",
  "allowed": ["wlan0"],
  "session": "wifi_deauth_20260114T120102Z_7f3a",
  "expires_at": null
}
```

Minimal Rust model:
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IsolationMode {
    AllowList,
    BlockAll,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IsolationPolicy {
    pub version: u32,
    pub mode: IsolationMode,
    pub allowed: Vec<String>,
    pub session: String,
    pub expires_at: Option<String>, // RFC3339 string (optional)
}
```

APIs:
```rust
pub struct IsolationPolicyManager { path: PathBuf }

impl IsolationPolicyManager {
    pub fn new(root: PathBuf) -> Self;
    pub fn read(&self) -> Result<Option<IsolationPolicy>>;
    pub fn write(&self, policy: &IsolationPolicy) -> Result<()>;
    pub fn clear(&self) -> Result<()>;
}
```

**Why a file?** The daemon already runs independently and needs a durable, simple source of truth.

---

### A3.2 Extend `IsolationEngine` to honor policy allow‑lists (before auto-selection)
Edit:
- `rustyjack-core/src/system/isolation.rs`

At the top of `enforce()`:
1. Try to read `IsolationPolicyManager::read()`
2. If policy exists and `mode=AllowList`, then:
   - treat `allowed = policy.allowed`
   - skip `select_active_interface(...)`
3. If policy exists and `mode=BlockAll`, then:
   - block everything, allow nothing
4. Else fallback to existing behavior (preferred interface / auto-select)

Pseudo-code:
```rust
pub fn enforce(&self) -> Result<IsolationOutcome> {
    let _guard = self.enforcement_lock();

    if let Some(policy) = IsolationPolicyManager::new(self.root.clone()).read()? {
        return self.enforce_explicit_allow_list(&policy.allowed);
    }

    // existing behavior:
    let preferred = self.prefs.get_preferred()?;
    let active = self.select_active_interface(&interfaces, preferred.as_deref())?;
    ...
}
```

Implement:
```rust
fn enforce_explicit_allow_list(&self, allowed: &[String]) -> Result<IsolationOutcome>
```

This method must:
- bring DOWN all non-allowed interfaces
- rfkill-block all non-allowed wireless
- bring UP allowed interfaces (or at least ensure they can be UP)
- **verify** invariants (see A3.4)

---

### A3.3 Make operation entry points set policy *and* enforce immediately
For any wireless operation where the user selects `interface`, add an RAII guard:

Create:
- `rustyjack-core/src/system/isolation_guard.rs`

```rust
pub struct IsolationPolicyGuard {
    prev: Option<IsolationPolicy>,
    mgr: IsolationPolicyManager,
}

impl IsolationPolicyGuard {
    pub fn set_allow_list(root: PathBuf, allowed: Vec<String>, session: String) -> Result<Self> {
        let mgr = IsolationPolicyManager::new(root);
        let prev = mgr.read()?;
        let policy = IsolationPolicy {
            version: 1,
            mode: IsolationMode::AllowList,
            allowed,
            session,
            expires_at: None,
        };
        mgr.write(&policy)?;
        Ok(Self { prev, mgr })
    }
}

impl Drop for IsolationPolicyGuard {
    fn drop(&mut self) {
        // Best practice: attempt revert, but never panic in Drop.
        let _ = match &self.prev {
            Some(p) => self.mgr.write(p),
            None => self.mgr.clear(),
        };
    }
}
```

Then in each handler (short-term, before you unify the pipeline), do:

1) Build session id string  
2) Create guard `IsolationPolicyGuard::set_allow_list(...)`  
3) Call `IsolationEngine::enforce()` (or `apply_interface_isolation_strict`) immediately  
4) Proceed

This gives:
- immediate strict isolation,
- and daemon will continuously re-assert it (because it reads the policy file).

---

### A3.4 Make isolation strict: never ignore bring_down failures
Edit:
- `rustyjack-core/src/system/mod.rs`
  - `apply_interface_isolation_with_ops(...)`

Currently, this ignores bring_down errors:
```rust
let _ = ops.bring_down(&iface_info.name);
```

Change it to:
- record an error entry if bring_down fails
- treat *any* bring_down failure as fatal for strict mode

Recommended refactor: split into two functions

```rust
pub fn apply_interface_isolation_strict(allowed: &[String]) -> Result<()> {
    let outcome = apply_interface_isolation_with_ops_strict(&RealNetOps, allowed)?;
    if !outcome.errors.is_empty() {
        bail!("Interface isolation errors: ...");
    }
    Ok(())
}

pub fn apply_interface_isolation_with_ops_strict(
    ops: &dyn NetOps,
    allowed: &[String],
) -> Result<IsolationOutcome> {
    ...
}
```

Inside strict implementation:
- For each non-allowed interface:
  - `release_dhcp`
  - `flush_addresses`
  - `delete_default_route`
  - `bring_down` **(error if fails)**
  - `wait_for_admin_state(down)`
  - `rfkill_block` (wireless)
- For each allowed interface:
  - `rfkill_unblock`
  - `bring_up` **(error if fails)**
  - `wait_for_admin_state(up)`
- After loop: verify invariants:
  - only allowed are UP (see A3.5)

You already have a stricter sequence in `system/interface_selection.rs` (it flushes, deletes routes, brings down, waits).
You can **reuse** those internal helpers (`wait_for_admin_state`, route manager usage) to keep semantics aligned.

---

### A3.5 Add a verification step that proves the invariant after enforcement
Add a function (can live near `apply_interface_isolation_with_ops_strict`):

```rust
fn verify_only_allow_list_admin_up(
    ops: &dyn NetOps,
    allowed: &HashSet<String>,
) -> Result<()> {
    let ifaces = ops.list_interfaces()?;
    let up: Vec<_> = ifaces.into_iter()
        .filter(|i| ops.admin_is_up(&i.name).unwrap_or(false))
        .map(|i| i.name)
        .collect();

    for name in &up {
        if !allowed.contains(name) {
            bail!("Isolation invariant violated: {} is UP but not allowed", name);
        }
    }
    for name in allowed {
        if !up.contains(name) {
            bail!("Isolation invariant violated: allowed {} is not UP", name);
        }
    }
    Ok(())
}
```

Also verify rfkill for blocked wireless if you can query it through `NetOps` (if not present, add it).

---

### A3.6 Patch Karma: enforce isolation (single allow-list) before execution
Edit:
- `rustyjack-core/src/operations.rs`
  - `fn handle_wifi_karma(root: &Path, args: WifiKarmaArgs)`

Add, immediately after verifying privileges + interface is wireless:

```rust
// STRICT ISOLATION — must happen before any mode changes / wireless actions
let _iso_guard = IsolationPolicyGuard::set_allow_list(
    root.to_path_buf(),
    vec![args.interface.clone()],
    format!("wifi_karma_{}", chrono_like_session_id()),
)?;
IsolationEngine::new(Arc::new(RealNetOps), root.to_path_buf()).enforce()?;
```

If you don’t want to instantiate `IsolationEngine` here, call your new:
`apply_interface_isolation_strict(&[args.interface.clone()])?;`

**Important:** do *not* treat failure as warning. Failure must abort.

---

### A3.7 Patch Hotspot: strict allow-list and enforce before start
Edit:
- `rustyjack-core/src/operations.rs`
  - `fn handle_hotspot_start(root: &Path, args: HotspotStartArgs)`

Current behavior:
- starts hotspot first, then best-effort isolation (warning-only)

Change to:

1) Build allow-list: `[ap_interface, upstream_interface]`
2) Write policy + enforce strict isolation **before** starting hotspot
3) Start hotspot
4) After startup, enforce again (belt and suspenders)
5) If enforce fails at any point: **stop hotspot** and return error

Pseudo-code:
```rust
let allowed = vec![args.ap_interface.clone(), args.upstream_interface.clone()];
let _iso_guard = IsolationPolicyGuard::set_allow_list(root.to_path_buf(), allowed.clone(), session)?;

apply_interface_isolation_strict(&allowed)?;
// or IsolationEngine(...).enforce_explicit_allow_list(&allowed)?

let state = start_hotspot(cfg)?;

// Re-enforce after hotspot touches interfaces/routes
apply_interface_isolation_strict(&allowed)
    .map_err(|e| {
        let _ = stop_hotspot();
        e
    })?;
```

This preserves the exception rule (multi-interface), while keeping strictness.

---

## A4) What “done” looks like
- Every wireless operation either:
  - enforces a **single-interface allow-list**, or
  - enforces an explicit **multi-interface allow-list** (rare)
- No handler can proceed if isolation fails.
- The daemon’s netlink watcher continuously re-asserts the policy.
- A post-enforcement verification proves only the allowed interfaces are UP.

---

# Problem B — “Ever prevalent” enforcement relies too much on netlink events

## B1) Problem
The daemon currently enforces on netlink events. That’s good, but “ever prevalent” benefits from periodic enforcement too.

## B2) Why it matters
If an interface is toggled without generating the expected netlink events (or if events are missed), the invariant could drift.

## B3) Exact architectural / code changes (How to fix)

Edit:
- `rustyjack-daemon/src/netlink_watcher.rs`

Add a periodic tick enforcement loop (low frequency; e.g., every 2–5 seconds):
- It should call the same `IsolationEngine::enforce()` path that event handling uses.
- It should acquire the same `uplink` lock to avoid racing with operations.

Pseudo-code (Tokio):
```rust
let state_clone = Arc::clone(&state);
tokio::spawn(async move {
    loop {
        sleep(Duration::from_secs(3)).await;
        let _lock = state_clone.locks.acquire_uplink().await;
        let root = state_clone.config.root_path.clone();
        tokio::task::spawn_blocking(move || {
            let engine = IsolationEngine::new(Arc::new(RealNetOps), root);
            let _ = engine.enforce();
        }).await.ok();
    }
});
```

**Important:** do not spam logs. Only log when:
- allowed/block list changes, or
- enforcement errors occur.

---

## B4) What “done” looks like
- Even without netlink events, the system reasserts isolation every few seconds.
- Engineers can trust that “non-selected interfaces stay dead.”

---

# Problem C — External binary invocation in Wi‑Fi path

## C1) Problem
`ensure_route_health_check()` shells out to `id -u`.

## C2) Why it matters
Violates “Rust-only / no third-party binaries” and complicates deployment environments.

## C3) Exact architectural / code changes (How to fix)
Edit:
- `rustyjack-core/src/operations.rs`
  - `fn ensure_route_health_check()`

Replace:
```rust
let uid_out = Command::new("id").arg("-u").output();
```

With:
```rust
#[cfg(target_os = "linux")]
{
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("Rustyjack must run as root (uid 0) to manage interfaces and routes");
    }
}
```

Also remove any remaining `Command` usage in the wireless route path.

Verification:
- `grep -R "Command::new\(\"id\"\)" -n rustyjack-core/src` returns nothing.

---

## C4) What “done” looks like
- No Wi‑Fi handler shells out to any external binary.
- Root checks are consistent and cross-platform gated.

---

# Problem D — Capture artifacts labeled “pcap” are not valid PCAP

## D1) Problem
Capture output is created by concatenating raw packet bytes into a `.pcap` file.

## D2) Why it matters
Standard tooling expects PCAP global headers and per-packet record headers. Raw concatenation breaks analysis workflows and long-term reliability.

## D3) Exact architectural / code changes (How to fix — detailed)

### D3.1 Add a minimal internal PCAP writer (no new binaries)
Create:
- `rustyjack-wireless/src/pcap.rs`

Implement classic PCAP (not pcapng) to keep it small.

PCAP global header (little-endian):
- magic: `0xa1b2c3d4`
- version major/minor: `2`, `4`
- thiszone: `0`
- sigfigs: `0`
- snaplen: `65535` (or tighter)
- network: `127` (LINKTYPE_IEEE802_11_RADIOTAP)

Per-packet record header:
- ts_sec (u32)
- ts_usec (u32)
- incl_len (u32)
- orig_len (u32)

Implementation sketch:
```rust
pub struct PcapWriter<W: Write> {
    w: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut w: W) -> io::Result<Self> {
        write_global_header(&mut w)?;
        Ok(Self { w })
    }

    pub fn write_packet(&mut self, ts: SystemTime, data: &[u8]) -> io::Result<()> {
        let (sec, usec) = system_time_to_sec_usec(ts)?;
        write_record_header(&mut self.w, sec, usec, data.len() as u32)?;
        self.w.write_all(data)?;
        Ok(())
    }
}
```

### D3.2 Fix timestamps: `CapturedPacket` uses `Instant` today
`Instant` is monotonic and not convertible to UNIX epoch without a reference. PCAP needs epoch-ish.

Edit:
- `rustyjack-wireless/src/capture.rs`

Change:
```rust
pub timestamp: Instant
```

To:
```rust
pub timestamp: SystemTime,
pub monotonic: Instant, // optional, if you still need elapsed logic
```

And when constructing:
```rust
let now_sys = SystemTime::now();
let now_mono = Instant::now();
CapturedPacket { timestamp: now_sys, monotonic: now_mono, ... }
```

### D3.3 Update core write site to use the PCAP writer
Edit:
- `rustyjack-core/src/wireless_native.rs`

Replace the raw concat write with:
```rust
let f = File::create(&capture_file)?;
let mut w = rustyjack_wireless::pcap::PcapWriter::new(BufWriter::new(f))?;
for pkt in &captured_packets {
    w.write_packet(pkt.timestamp, &pkt.raw_data)?;
}
```

### D3.4 Tests
Add unit test in `rustyjack-wireless`:
- write one packet
- assert:
  - first 4 bytes == PCAP magic in LE
  - record header exists and lengths match
  - total file length == header + record header + packet

---

## D4) What “done” looks like
- Capture files open in Wireshark/tshark.
- The format is standards-compliant and stable.

---

# Problem E — Operation configuration flags not wired correctly

## E1) Problem
CLI includes a `continuous` flag but native config construction ignores it.

## E2) Why it matters
Engineers and users will assume the flag works, but behavior doesn’t match the interface contract.

## E3) Exact architectural / code changes (How to fix)
Edit:
- `rustyjack-core/src/wireless_native.rs`

When building native config, map `continuous` into burst scheduling:

If native attacker loops bursts until duration:
- `continuous=true`: use the provided `burst_interval`
- `continuous=false`: set `burst_interval > duration` so only the first burst executes

Pseudo-code:
```rust
let duration = Duration::from_secs(config.duration as u64);
let burst_interval = if config.continuous {
    Duration::from_secs(config.interval as u64)
} else {
    duration + Duration::from_secs(1)
};
let native_config = NativeDeauthConfig {
    duration,
    burst_interval,
    packets_per_burst: config.packets,
    ...
};
```

Add a small unit test (core or wireless) that:
- constructs config with continuous=false
- asserts computed burst_interval > duration

---

## E4) What “done” looks like
- CLI flags correspond to real behavior.
- Config mapping is documented and tested.

---

# Problem F — Loot/log scoping is inconsistent across operations

## F1) Problem
Some operations write loot into shared directories (collision risk), while logs are scoped differently.

## F2) Why it matters
- Run collisions overwrite artifacts.
- It’s hard to correlate logs with outputs.
- Debugging production runs is harder than it needs to be.

## F3) Exact architectural / code changes (How to fix)
Introduce a canonical “session directory” pattern and migrate offenders first.

### F3.1 Canonical layout
```
loot/Wireless/
  sessions/
    <YYYYMMDD_HHMMSS>_<op>_<iface>_<shortid>/
      artifacts/
      logs/
      report.json
      report.md
```

### F3.2 Add helper builder
Create:
- `rustyjack-core/src/system/loot_session.rs`

```rust
pub struct LootSession {
    pub dir: PathBuf,
    pub artifacts: PathBuf,
    pub logs: Option<PathBuf>,
}

impl LootSession {
    pub fn new(root: &Path, op: &str, iface: &str) -> Result<Self> {
        let id = make_session_id(op, iface);
        let dir = root.join("loot").join("Wireless").join("sessions").join(id);
        let artifacts = dir.join("artifacts");
        let logs = if crate::logs_enabled() { Some(dir.join("logs")) } else { None };
        fs::create_dir_all(&artifacts)?;
        if let Some(ref l) = logs { fs::create_dir_all(l)?; }
        Ok(Self { dir, artifacts, logs })
    }
}
```

### F3.3 Migrate shared-loot operations
- `handle_wifi_probe_sniff`: stop writing to `loot/Wireless/probe_sniff`; instead use `LootSession`.
- `handle_wifi_karma`: stop writing to `loot/Wireless/karma`; instead use `LootSession`.

Minimal change: keep existing internal artifact naming, just change base dir.

---

## F4) What “done” looks like
- Every run produces a unique session directory.
- Logs and artifacts are always colocated.
- Nothing overwrites or merges unintentionally.

---

# Problem G — Misleading requirements messaging (implies binaries)

## G1) Problem
A handler prints “apt install …” guidance even though requirements are Rust-native.

## G2) Why it matters
- Violates the project’s “no binaries” story.
- Confuses operators and maintainers.

## G3) Exact architectural / code changes (How to fix)
Edit:
- `rustyjack-core/src/operations.rs` (where requirements are checked)

Replace “tools required” messaging with “capability required” messaging:
- e.g. AP mode support, monitor mode support, permissions, kernel support

Pseudo-code:
```rust
let missing = EvilTwin::check_requirements()?;
if !missing.is_empty() {
    bail!("Missing required capabilities: {}", missing.join(", "));
}
```

And update `EvilTwin::check_requirements()` (wireless crate) to return capability strings when applicable, not package names.

---

## G4) What “done” looks like
- No `apt install` messaging in wireless paths.
- Requirement checks reflect actual system capabilities.

---

# Problem H — No single enforced wireless operation pipeline (optional but strongly recommended)

## H1) Problem
Operations each implement their own sequencing (preflight → isolate → execute → teardown → logging), which risks drift.

## H2) Why it matters
Any drift risks violating strict isolation, safe teardown, or the “no binaries” rule.

## H3) Exact architectural / code changes (How to fix)
Introduce a unified pipeline in core, but keep execution bodies small.

Create:
- `rustyjack-core/src/wifi/` module tree:
  - `wifi/pipeline.rs`
  - `wifi/context.rs`
  - `wifi/requirements.rs`
  - `wifi/report.rs`

Define:
```rust
pub struct WifiRequirements {
    pub allowed_ifaces: Vec<String>,
    pub needs_monitor: bool,
    pub needs_ap: bool,
    pub needs_route: bool,
}
```

Pipeline steps:
1. Resolve interface(s)
2. Strict isolation (policy + immediate enforce)
3. Preflight capabilities
4. Create LootSession
5. Execute op (existing functions)
6. Write report
7. Drop guards → revert policy

**Important:** Do not expand operation internals here. The goal is sequencing uniformity + policy enforcement.

---

## H4) What “done” looks like
- Every op uses the same isolation/preflight/session/report skeleton.
- Code review can focus on op-specific logic, not repeated boilerplate.

---

## 3) Implementation order (PI0/W2 pragmatic)

1. **Strict isolation policy** (A3.1–A3.5) — foundation
2. Patch missing enforcement in Karma (A3.6)
3. Patch hotspot strict allow-list (A3.7)
4. Add periodic daemon enforcement (B3)
5. Remove external binary call (C3)
6. Fix PCAP writer + timestamps (D3)
7. Wire `continuous` flag (E3)
8. Normalize loot sessions (F3)
9. Clean up requirements messaging (G3)
10. (Optional) unify pipeline (H3)

---

## 4) Verification checklist (engineers can run this)

### 4.1 Static checks
- No external binaries in Wi‑Fi path:
  - `grep -R "Command::new" -n rustyjack-core/src | grep -E "id\(|ip\(|iw\("` → should be empty or justified outside Wi‑Fi
- Isolation strictness:
  - `grep -R "let _ = ops\.bring_down" -n rustyjack-core/src/system` → should be eliminated in strict isolation path

### 4.2 Behavioral checks (on a Linux test host)
- Select interface `wlan0`:
  - confirm `eth0`, `eth1`, etc are DOWN
  - confirm non-selected wireless is rfkill-blocked
- While operation runs, manually bring up another interface:
  - it should be brought down again quickly (event or periodic tick)

### 4.3 Artifact checks
- Capture output opens with Wireshark/tshark.

---

## 5) Notes on safety and invariants
Strict isolation is intentionally disruptive (SSH drop is expected). The design should remain simple and provable:
- One policy source of truth
- One enforcement engine
- No best-effort “continue anyway” when isolation fails

That is how you keep the system honest.
