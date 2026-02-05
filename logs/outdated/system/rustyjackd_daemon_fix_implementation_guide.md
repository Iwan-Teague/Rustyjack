19 Jan 2026
# RustyJack Daemon Hardening — Implementation Guide

This is the implementation-ready follow-up to the security audit. It turns the findings into a concrete set of changes your developers can implement with minimal additional architecture discovery.

**Repo snapshot in scope:** `watchdog_shallow_20260119-230203.zip`.

**Device:** Raspberry Pi Zero 2 W. **Assumption:** `rustyjackd` + companion services are the only workloads on the Pi, so the system is effectively an appliance.

## Non-negotiables

- All fixes are **Rust**.
- No shelling out to third-party binaries (`git`, `cargo`, `systemctl`, `bash`, ...).
- It’s fine to use Linux syscalls, netlink, and D-Bus from Rust.

## What you will implement (in order)

1. **Capability toggles** (“WiFi Ops [ON] / Eth Ops [ON] / …”) and enforce them for every request.
2. Replace endpoint-only auth with **request-aware auth** (SystemCommand variants need different tiers).
3. Disable/compile-gate **CoreDispatch** and dev-only endpoints.
4. Remove shell-out paths reachable from the daemon (reverse execution, on-device build/update, purge tooling).
5. Fix the netlink watcher to be a real event subscription (not a one-shot dump).
6. Replace log tail with a bounded algorithm (no full-file reads).

Everything below is written as a set of patchable steps.
## 1) Ops toggles (“WiFi Ops [ON]”, “Eth Ops [ON]”, ...)

### 1.1 The model you want

The daemon currently has a single global kill-switch (`dangerous_ops_enabled`) that is both (a) too coarse and (b) misaligned with reality (it blocks normal WiFi connect/hotspot operations). Replace that with **explicit capability toggles** that match product intent.

**New toggles (recommended for the Pi networking appliance):**

- `wifi_ops` — WiFi scanning + connect/disconnect.
- `eth_ops` — Ethernet config + interface selection.
- `hotspot_ops` — hotspot start/stop and client listing.
- `portal_ops` — captive portal start/stop/status.
- `storage_ops` — mount/unmount + block device listing + disk usage.
- `system_ops` — reboot/shutdown/sync/hostname.
- `update_ops` — system update mechanism.

**Always-off in the product build (compile-time + runtime):**

- `dev_ops` — CoreDispatch and anything “generic dispatch”/introspection.
- `offensive_ops` — DnsSpoof/MITM/Reverse/ScanRun-style features.
- `loot_ops` — “loot” extraction style endpoints.
- `process_ops` — process manipulation endpoints.

The intent is: the appliance build exposes a *small safe surface* even if the UI is compromised.

### 1.2 Where to implement this in the repo

You will touch three places:

1) `crates/rustyjack-daemon` — **authoritative enforcement**.
2) `crates/rustyjack-ipc` — **reporting** (so UI can render [ON]/[OFF]).
3) `services/rustyjackd.service` — set sane defaults via environment.

### 1.3 Add a new ops configuration type in the daemon

Create a new file:

- `crates/rustyjack-daemon/src/ops.rs`

Implementation (no new dependencies):

```rust
#[derive(Debug, Clone, Copy)]
pub struct OpsConfig {
    pub wifi_ops: bool,
    pub eth_ops: bool,
    pub hotspot_ops: bool,
    pub portal_ops: bool,
    pub storage_ops: bool,
    pub system_ops: bool,
    pub update_ops: bool,

    // always false in product builds
    pub dev_ops: bool,
    pub offensive_ops: bool,
    pub loot_ops: bool,
    pub process_ops: bool,
}

impl OpsConfig {
    pub fn appliance_defaults() -> Self {
        Self {
            wifi_ops: true,
            eth_ops: true,
            hotspot_ops: true,
            portal_ops: true,
            storage_ops: true,   // flip to false if you never mount removable media
            system_ops: false,   // keep lifecycle under systemd unless you need this
            update_ops: true,
            dev_ops: false,
            offensive_ops: false,
            loot_ops: false,
            process_ops: false,
        }
    }
}
```

### 1.4 Define env vars (exact names) and parsing rules

Edit:

- `crates/rustyjack-daemon/src/config.rs`

Add a field to `DaemonConfig`:

```rust
pub ops: OpsConfig,
```

Add env parsing helpers (keep them local in `config.rs`):

```rust
fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(default)
}

fn env_list(key: &str) -> Option<Vec<String>> {
    std::env::var(key).ok().map(|s| {
        s.split(',')
            .map(|x| x.trim().to_ascii_lowercase())
            .filter(|x| !x.is_empty())
            .collect()
    })
}
```

Use these env vars:

- `RUSTYJACKD_OPS_PROFILE` — `appliance` (default), `dev`.
- Individual booleans (UI-friendly):
  - `RUSTYJACKD_OPS_WIFI`
  - `RUSTYJACKD_OPS_ETH`
  - `RUSTYJACKD_OPS_HOTSPOT`
  - `RUSTYJACKD_OPS_PORTAL`
  - `RUSTYJACKD_OPS_STORAGE`
  - `RUSTYJACKD_OPS_SYSTEM`
  - `RUSTYJACKD_OPS_UPDATE`
  - `RUSTYJACKD_OPS_DEV`
  - `RUSTYJACKD_OPS_OFFENSIVE`
  - `RUSTYJACKD_OPS_LOOT`
  - `RUSTYJACKD_OPS_PROCESS`

**Parsing precedence (deterministic):**

1) Start with profile defaults.
2) If `RUSTYJACKD_OPS` is set (comma list), it acts as an **allowlist override**.
3) Then apply individual booleans on top (so operators can flip a single switch without editing a list).

Implement in `DaemonConfig::from_env()`:

```rust
let profile = std::env::var("RUSTYJACKD_OPS_PROFILE").unwrap_or_else(|_| "appliance".into());
let mut ops = match profile.as_str() {
    "dev" => OpsConfig { wifi_ops: true, eth_ops: true, hotspot_ops: true, portal_ops: true,
                         storage_ops: true, system_ops: true, update_ops: true,
                         dev_ops: true, offensive_ops: true, loot_ops: true, process_ops: true },
    _ => OpsConfig::appliance_defaults(),
};

if let Some(list) = env_list("RUSTYJACKD_OPS") {
    // allowlist: everything false, then enable items in list
    ops = OpsConfig { wifi_ops: false, eth_ops: false, hotspot_ops: false, portal_ops: false,
                      storage_ops: false, system_ops: false, update_ops: false,
                      dev_ops: false, offensive_ops: false, loot_ops: false, process_ops: false };

    for item in list {
        match item.as_str() {
            "wifi" => ops.wifi_ops = true,
            "eth" | "ethernet" => ops.eth_ops = true,
            "hotspot" => ops.hotspot_ops = true,
            "portal" => ops.portal_ops = true,
            "storage" | "mount" => ops.storage_ops = true,
            "system" => ops.system_ops = true,
            "update" => ops.update_ops = true,
            "dev" => ops.dev_ops = true,
            "offensive" => ops.offensive_ops = true,
            "loot" => ops.loot_ops = true,
            "process" => ops.process_ops = true,
            _ => {}
        }
    }
}

// individual overrides
ops.wifi_ops = env_bool("RUSTYJACKD_OPS_WIFI", ops.wifi_ops);
ops.eth_ops = env_bool("RUSTYJACKD_OPS_ETH", ops.eth_ops);
ops.hotspot_ops = env_bool("RUSTYJACKD_OPS_HOTSPOT", ops.hotspot_ops);
ops.portal_ops = env_bool("RUSTYJACKD_OPS_PORTAL", ops.portal_ops);
ops.storage_ops = env_bool("RUSTYJACKD_OPS_STORAGE", ops.storage_ops);
ops.system_ops = env_bool("RUSTYJACKD_OPS_SYSTEM", ops.system_ops);
ops.update_ops = env_bool("RUSTYJACKD_OPS_UPDATE", ops.update_ops);
ops.dev_ops = env_bool("RUSTYJACKD_OPS_DEV", ops.dev_ops);
ops.offensive_ops = env_bool("RUSTYJACKD_OPS_OFFENSIVE", ops.offensive_ops);
ops.loot_ops = env_bool("RUSTYJACKD_OPS_LOOT", ops.loot_ops);
ops.process_ops = env_bool("RUSTYJACKD_OPS_PROCESS", ops.process_ops);
```

Finally store in the config struct:

```rust
Self { /* existing fields */, ops, }
```

### 1.5 Expose ops toggles to clients (so UI can show [ON]/[OFF])

Edit:

- `crates/rustyjack-ipc/src/types.rs`

Add a new struct near `StatusResponse`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsStatus {
    pub wifi_ops: bool,
    pub eth_ops: bool,
    pub hotspot_ops: bool,
    pub portal_ops: bool,
    pub storage_ops: bool,
    pub system_ops: bool,
    pub update_ops: bool,

    pub dev_ops: bool,
    pub offensive_ops: bool,
    pub loot_ops: bool,
    pub process_ops: bool,
}
```

Then extend `StatusResponse`:

```rust
pub struct StatusResponse {
    pub uptime_ms: u64,
    pub jobs_active: usize,
    pub jobs_total: usize,

    // NEW
    pub ops: OpsStatus,
}
```

Now edit:

- `crates/rustyjack-daemon/src/dispatch.rs`

In the `RequestBody::Status` handler, fill `ops` from `state.config.ops`:

```rust
let ops = OpsStatus {
    wifi_ops: state.config.ops.wifi_ops,
    eth_ops: state.config.ops.eth_ops,
    hotspot_ops: state.config.ops.hotspot_ops,
    portal_ops: state.config.ops.portal_ops,
    storage_ops: state.config.ops.storage_ops,
    system_ops: state.config.ops.system_ops,
    update_ops: state.config.ops.update_ops,

    dev_ops: state.config.ops.dev_ops,
    offensive_ops: state.config.ops.offensive_ops,
    loot_ops: state.config.ops.loot_ops,
    process_ops: state.config.ops.process_ops,
};

ResponseOk::Status(StatusResponse { uptime_ms, jobs_active, jobs_total, ops })
```

This gives the UI a single stable place (`Status`) to render a panel like:

- WiFi Ops [ON]
- Eth Ops [ON]
- Hotspot Ops [ON]
- Portal Ops [ON]
- Storage Ops [ON]
- System Ops [OFF]
- Update Ops [ON]

…and optionally the dev/offensive toggles (should be OFF in appliance builds).

### 1.6 Enforce ops toggles for every request

You enforce auth today in `server.rs` using:

- `required_tier(request.endpoint)`
- plus a special-case for `JobStart` using `required_tier_for_jobkind(&job.kind)`.

Do the same pattern for ops toggles.

Create in `crates/rustyjack-daemon/src/auth.rs` (or new `gate.rs`) a function:

```rust
use rustyjack_ipc::{Endpoint, RequestBody};
use rustyjack_ipc::job::JobKind;

#[derive(Debug, Clone, Copy)]
pub enum RequiredOps {
    None,
    Wifi,
    Eth,
    Hotspot,
    Portal,
    Storage,
    System,
    Update,
    Dev,
    Offensive,
    Loot,
    Process,
}

pub fn required_ops_for_request(endpoint: Endpoint, body: &RequestBody) -> RequiredOps {
    use Endpoint as E;
    use RequestBody as B;

    // read-only endpoints
    match endpoint {
        E::Health | E::Version | E::Status
        | E::SystemStatusGet | E::SystemLogsGet | E::InterfaceStatusGet
        | E::WifiCapabilitiesGet | E::WifiInterfacesList
        | E::HotspotWarningsGet | E::HotspotDiagnosticsGet | E::HotspotClientsList
        | E::GpioDiagnosticsGet | E::LoggingConfigGet | E::LogTailGet => return RequiredOps::None,
        _ => {}
    }

    // endpoint families
    match endpoint {
        // WiFi
        E::WifiDisconnect | E::WifiScanStart | E::WifiConnectStart
        | E::WifiCommand => RequiredOps::Wifi,

        // Ethernet
        E::EthernetCommand | E::SetActiveInterface | E::ActiveInterfaceClear => RequiredOps::Eth,

        // Hotspot
        E::HotspotStart | E::HotspotStop | E::HotspotCommand => RequiredOps::Hotspot,

        // Portal
        E::PortalStart | E::PortalStop | E::PortalStatus => RequiredOps::Portal,

        // Storage
        E::MountList | E::MountStart | E::UnmountStart | E::BlockDevicesList | E::DiskUsageGet => RequiredOps::Storage,

        // System control
        E::SystemReboot | E::SystemShutdown | E::SystemSync | E::HostnameRandomizeNow => RequiredOps::System,

        // Updates
        E::JobStart => {
            // JobStart is special: map by job kind, not just endpoint
            match body {
                B::JobStart(req) => required_ops_for_jobkind(&req.job.kind),
                _ => RequiredOps::Dev,
            }
        }

        // generic command endpoints
        E::SystemCommand => RequiredOps::System,

        // dev/offensive
        E::CoreDispatch => RequiredOps::Dev,
        E::DnsSpoofCommand | E::MitmCommand | E::ReverseCommand | E::ScanCommand | E::BridgeCommand => RequiredOps::Offensive,
        E::LootCommand => RequiredOps::Loot,
        E::ProcessCommand => RequiredOps::Process,

        // default: treat as dev
        _ => RequiredOps::Dev,
    }
}

pub fn required_ops_for_jobkind(kind: &JobKind) -> RequiredOps {
    match kind {
        JobKind::WifiScan { .. } | JobKind::WifiConnect { .. } => RequiredOps::Wifi,
        JobKind::HotspotStart { .. } => RequiredOps::Hotspot,
        JobKind::PortalStart { .. } => RequiredOps::Portal,
        JobKind::MountStart { .. } | JobKind::UnmountStart { .. } => RequiredOps::Storage,

        // Update job kind is Update
        JobKind::SystemUpdate { .. } => RequiredOps::Update,

        // ScanRun and CoreCommand are dev/offensive depending on your product intent.
        JobKind::ScanRun { .. } => RequiredOps::Offensive,
        JobKind::CoreCommand { .. } => RequiredOps::Dev,

        JobKind::InterfaceSelect { .. } => RequiredOps::Eth,
        JobKind::Noop | JobKind::Sleep { .. } => RequiredOps::None,
    }
}
```

Now create a single enforcement helper (daemon side) that maps `RequiredOps` to `OpsConfig` booleans:

```rust
pub fn ops_allows(cfg: &crate::ops::OpsConfig, required: RequiredOps) -> bool {
    match required {
        RequiredOps::None => true,
        RequiredOps::Wifi => cfg.wifi_ops,
        RequiredOps::Eth => cfg.eth_ops,
        RequiredOps::Hotspot => cfg.hotspot_ops,
        RequiredOps::Portal => cfg.portal_ops,
        RequiredOps::Storage => cfg.storage_ops,
        RequiredOps::System => cfg.system_ops,
        RequiredOps::Update => cfg.update_ops,
        RequiredOps::Dev => cfg.dev_ops,
        RequiredOps::Offensive => cfg.offensive_ops,
        RequiredOps::Loot => cfg.loot_ops,
        RequiredOps::Process => cfg.process_ops,
    }
}
```

Finally, enforce it in `crates/rustyjack-daemon/src/server.rs` **before** `handle_request`:

```rust
let required_ops = required_ops_for_request(request.endpoint, &request.body);
if !ops_allows(&state.config.ops, required_ops) {
    let _ = send_error_timed(
        &mut stream,
        PROTOCOL_VERSION,
        request.request_id,
        DaemonError::new(ErrorCode::Forbidden, "operation disabled by ops config", false),
        state.config.max_frame,
        state.config.write_timeout,
    ).await;
    continue;
}
```

This enforcement lives in the server loop, which guarantees it applies to *every* request path.

### 1.7 Required tier and required ops should be computed together

Once you add per-request tier checks (next section), your gating logic should follow this exact order:

1) **tier** gate (admin/operator/readonly)
2) **ops toggle** gate (WiFi Ops / Eth Ops / ...)
3) request handling

That order is intentional:
- tier prevents “operator does admin things”
- ops prevents “feature is reachable at all”

### 1.8 systemd unit defaults for ops toggles

Edit `services/rustyjackd.service`:

- Remove: `Environment=RUSTYJACKD_ALLOW_CORE_DISPATCH=true`
- Add explicit ops envs (appliance defaults):

```ini
Environment=RUSTYJACKD_OPS_PROFILE=appliance
Environment=RUSTYJACKD_OPS_WIFI=true
Environment=RUSTYJACKD_OPS_ETH=true
Environment=RUSTYJACKD_OPS_HOTSPOT=true
Environment=RUSTYJACKD_OPS_PORTAL=true
Environment=RUSTYJACKD_OPS_STORAGE=true
Environment=RUSTYJACKD_OPS_UPDATE=true
Environment=RUSTYJACKD_OPS_SYSTEM=false

Environment=RUSTYJACKD_OPS_DEV=false
Environment=RUSTYJACKD_OPS_OFFENSIVE=false
Environment=RUSTYJACKD_OPS_LOOT=false
Environment=RUSTYJACKD_OPS_PROCESS=false
```

This makes the “WiFi Ops [ON]” panel truthful: it reflects runtime policy.

## 2) Request-aware authorization (stop endpoint-only tier decisions)

### 2.1 The problem you are fixing

Right now, the daemon checks tier in `server.rs` via:

```rust
let required = required_tier(request.endpoint);
if !tier_allows(authz, required) { ... }
```

That’s too coarse because:
- `Endpoint::SystemCommand` can carry many different `SystemCommand` variants with very different risk.
- `Endpoint::CoreDispatch` is effectively “run arbitrary core command”.

### 2.2 The exact fix

Replace `required_tier(endpoint)` with:

```rust
required_tier_for_request(endpoint, &request.body)
```

Implement in `crates/rustyjack-daemon/src/auth.rs`:

```rust
pub fn required_tier_for_request(endpoint: Endpoint, body: &RequestBody) -> AuthorizationTier {
    use AuthorizationTier as T;
    use Endpoint as E;
    use RequestBody as B;

    // read-only endpoints
    match endpoint {
        E::Health | E::Version | E::Status
        | E::SystemStatusGet | E::SystemLogsGet | E::InterfaceStatusGet
        | E::WifiCapabilitiesGet | E::WifiInterfacesList
        | E::HotspotWarningsGet | E::HotspotDiagnosticsGet | E::HotspotClientsList
        | E::GpioDiagnosticsGet | E::LoggingConfigGet | E::LogTailGet
            => return T::Readonly,
        _ => {}
    }

    // JobStart uses job kind
    if endpoint == E::JobStart {
        if let B::JobStart(req) = body {
            return required_tier_for_jobkind(&req.job.kind);
        }
        return T::Admin;
    }

    // SystemCommand: map by variant (this is the important one)
    if endpoint == E::SystemCommand {
        if let B::SystemCommand(cmd) = body {
            return required_tier_for_system_command(cmd);
        }
        return T::Admin;
    }

    // CoreDispatch is dev-only
    if endpoint == E::CoreDispatch {
        return T::Admin;
    }

    // default endpoint-based mapping for the rest
    required_tier(endpoint)
}

fn required_tier_for_system_command(cmd: &rustyjack_commands::SystemCommand) -> AuthorizationTier {
    use AuthorizationTier as T;
    use rustyjack_commands::SystemCommand as SC;

    match cmd {
        // safe-ish actions you genuinely want operator to do
        SC::Sync | SC::Uptime => T::Operator,

        // everything else: admin
        _ => T::Admin,
    }
}
```

Then in `server.rs` replace:

```rust
let required = required_tier(request.endpoint);
```

with:

```rust
let required = required_tier_for_request(request.endpoint, &request.body);
```

### 2.3 Unit tests for auth mapping

Create:
- `crates/rustyjack-daemon/src/auth_tests.rs` (or `tests/auth.rs`)

Test that:
- `SystemCommand::Update` requires Admin
- `SystemCommand::Reboot` requires Admin
- `SystemCommand::Sync` can be Operator (if you keep it)

These tests should run without needing the Pi hardware.

## 3) Remove / compile-gate CoreDispatch (and other dev-only endpoints)

### 3.1 What to do

You have two layers of defense:

1) **Runtime**: `allow_core_dispatch` stays false unless explicitly enabled.
2) **Compile-time**: appliance build does not include CoreDispatch at all.

### 3.2 Concrete steps

#### Step A — systemd unit
Remove this line from `services/rustyjackd.service`:

```ini
Environment=RUSTYJACKD_ALLOW_CORE_DISPATCH=true
```

#### Step B — daemon config
Keep `allow_core_dispatch` in `DaemonConfig`, but you should only respect it if a compile-time feature is enabled.

In `config.rs`:

```rust
let allow_core_dispatch = cfg!(feature = "core_dispatch")
    && env_bool("RUSTYJACKD_ALLOW_CORE_DISPATCH", false);
```

#### Step C — server-side tier + ops gate
Treat CoreDispatch as:
- required tier: **Admin**
- required ops: **Dev**

This is already covered by the mappings in Sections 1 and 2.

#### Step D — dispatch handler
In `dispatch.rs`, guard the actual match arm:

```rust
#[cfg(feature = "core_dispatch")]
RequestBody::CoreDispatch(req) => { /* existing logic */ }

#[cfg(not(feature = "core_dispatch"))]
RequestBody::CoreDispatch(_) => ResponseBody::Err(DaemonError::new(
    ErrorCode::Forbidden,
    "CoreDispatch disabled in this build",
    false,
)),
```

### 3.3 Do the same for offensive endpoints

Apply the same pattern to:
- `DnsSpoofCommand`
- `MitmCommand`
- `ReverseCommand`
- `ScanCommand` / `ScanRun`
- `BridgeCommand`

In the appliance build:
- compile them out, and
- ensure ops toggles default OFF.

This report deliberately does **not** describe how to implement offensive features; the work item is to remove them from the appliance surface.

## 4) Replace the update pipeline with a Rust-native signed artifact updater (no shell-outs)

### 4.1 Why you must do this

In the current snapshot, the update flow shells out to `git`, `cargo`, and service management commands. That violates your constraints and creates a supply-chain hazard.

### 4.2 Target behaviour

- CI produces a bundle (e.g. `update-<version>.tar.zst`) containing:
  - `manifest.json`
  - `manifest.sig` (Ed25519)
  - binaries: `rustyjackd`, `rustyjack-ui`, `rustyjack-portal`
  - unit files and any static assets
- Device downloads over HTTPS.
- Daemon verifies signature and per-file hashes.
- Daemon stages update under `/var/lib/rustyjack/update/stage/<version>/`.
- Daemon atomically swaps binaries.
- Daemon restarts **without shelling out**:
  - use systemd D-Bus `RestartUnit("rustyjackd.service", "replace")`.

The systemd D-Bus manager interface and RestartUnit signature are documented in the systemd interface docs.

### 4.3 Repo changes (concrete)

#### Step A — new crate
Create a new crate:

- `crates/rustyjack-updater`

Exports a single high-level API:

```rust
pub struct UpdatePolicy {
    pub public_key_ed25519: [u8; 32],
    pub stage_dir: std::path::PathBuf,
    pub install_dir: std::path::PathBuf, // e.g. /usr/local/bin
    pub unit_restart: String,            // rustyjackd.service
}

pub async fn apply_update(policy: &UpdatePolicy, url: &str) -> anyhow::Result<()>;
```

#### Step B — manifest format
Define `manifest.json` exactly:

```json
{
  "version": "2026.01.20-1",
  "files": [
    {"path": "bin/rustyjackd", "sha256": "...", "mode": "0755", "install_to": "/usr/local/bin/rustyjackd"},
    {"path": "bin/rustyjack-ui", "sha256": "...", "mode": "0755", "install_to": "/usr/local/bin/rustyjack-ui"},
    {"path": "bin/rustyjack-portal", "sha256": "...", "mode": "0755", "install_to": "/usr/local/bin/rustyjack-portal"}
  ]
}
```

The signature file `manifest.sig` is the Ed25519 signature over the **bytes of manifest.json**.

#### Step C — implement verification (Rust)
Use `ed25519-dalek` to verify signatures and `sha2` for SHA-256.

Verification flow:
1) read `manifest.json` bytes
2) read `manifest.sig`
3) verify signature against embedded public key
4) for each file, compute sha256 and compare

#### Step D — implement atomic swap
For each file:
- write to `dest.new`
- fsync the file
- rename `dest.new` → `dest`
- optionally keep `dest.prev` for rollback

#### Step E — restart via systemd D-Bus (Rust)
You have two good Rust options:

- `systemd-zbus` (high-level proxies)
- `zbus_systemd` (auto-generated bindings)

Both are pure Rust and talk to systemd via D-Bus. The core method you need is `RestartUnit(name, mode)` on `org.freedesktop.systemd1.Manager`.

Pseudo-code:

```rust
use zbus::Connection;

pub async fn restart_unit(unit: &str) -> anyhow::Result<()> {
    let conn = Connection::system().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    ).await?;

    // RestartUnit(in s name, in s mode, out o job)
    let (_job_path,): (zbus::zvariant::OwnedObjectPath,) = proxy
        .call("RestartUnit", &(unit, "replace"))
        .await?;

    Ok(())
}
```

### 4.4 Hook update into the daemon

You currently start update as a **job**: `JobKind::SystemUpdate { req: UpdateRequestIpc }`.

Keep that shape, but change the job handler to call `rustyjack_updater::apply_update(...)`.

Then gate it behind:
- required tier: **Admin**
- required ops: **Update**

In the appliance unit, keep `update_ops=true` but require an admin client.

## 5) Fix the netlink watcher so it actually watches

### 5.1 The current behaviour

`netlink_watcher` currently iterates a `get()` dump of links. That ends after emitting the current list.

### 5.2 Target behaviour

Subscribe to `NETLINK_ROUTE` multicast groups so the daemon receives:
- interface up/down
- address add/remove

The netlink man page includes an example of binding to `RTMGRP_LINK` and `RTMGRP_IPV4_IFADDR` groups for exactly this purpose.

### 5.3 Implementation plan

Edit:
- `crates/rustyjack-daemon/src/netlink_watcher.rs`

Replace the dump stream with a netlink socket bound to groups:
- `RTMGRP_LINK`
- `RTMGRP_IPV4_IFADDR`
- `RTMGRP_IPV6_IFADDR`

Implementation approach:

1) Create socket: `AF_NETLINK`, protocol `NETLINK_ROUTE`.
2) Bind with `sockaddr_nl { nl_groups = mask }`.
3) Receive messages in a loop.
4) Debounce (e.g., 200–500ms window) and call `state.isolation.enforce_policy("netlink")`.

Make sure the watcher task never exits on EOF; it should only stop on shutdown signal.

## 6) Replace log tail with a bounded tail-from-end algorithm

### 6.1 Requirements

- O(max_bytes_scanned) worst-case cost
- returns last N lines
- works for UTF-8 logs but does not panic on partial codepoints

### 6.2 Implementation

Create:
- `crates/rustyjack-daemon/src/tail.rs`

Implement:

```rust
pub fn tail_lines(path: &Path, max_lines: usize, max_bytes: usize) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut pos = f.seek(SeekFrom::End(0))?;
    let mut buf: Vec<u8> = Vec::new();

    while pos > 0 && buf.len() < max_bytes {
        if count_newlines(&buf) >= max_lines { break; }
        let step = std::cmp::min(4096, pos as usize);
        pos -= step as u64;
        f.seek(SeekFrom::Start(pos))?;
        let mut chunk = vec![0u8; step];
        f.read_exact(&mut chunk)?;
        buf.splice(0..0, chunk);
    }

    Ok(String::from_utf8_lossy(&buf).to_string())
}
```

Then update `dispatch.rs` log tail endpoint to call this function.

## 7) Installation and service configuration (what your install scripts must do)

The uploaded snapshot does not include the 4 install scripts, so this section specifies *exactly* what those scripts must do so the units work.

### 7.1 Users/groups

Create groups:
- `rustyjack` (operator)
- `rustyjack-admin` (admin)

Create users:
- `rustyjack-ui`
- `rustyjack-portal`

Add both service users to the `rustyjack` group so they can access the socket.

### 7.2 Install paths

Binaries:
- `/usr/local/bin/rustyjackd`
- `/usr/local/bin/rustyjack-ui`
- `/usr/local/bin/rustyjack-portal`

Units:
- `/etc/systemd/system/rustyjackd.socket`
- `/etc/systemd/system/rustyjackd.service`
- `/etc/systemd/system/rustyjack-ui.service`
- `/etc/systemd/system/rustyjack-portal.service`

State:
- `/var/lib/rustyjack/` (StateDirectory)
- `/var/lib/rustyjack/logs/`
- `/var/lib/rustyjack/ui/`
- `/var/lib/rustyjack/portal/`

### 7.3 Enable

- `systemctl daemon-reload`
- `systemctl enable --now rustyjackd.socket`
- `systemctl enable --now rustyjack-ui.service`
- `systemctl enable --now rustyjack-portal.service`

### 7.4 Critical unit edits you must apply

- Remove `RUSTYJACKD_ALLOW_CORE_DISPATCH=true`
- Add ops toggle envs (Section 1.8)

## 8) Test plan (so these changes don’t regress)

### 8.1 Unit tests

In `rustyjack-daemon`:
- `required_tier_for_request` mapping tests.
- `required_ops_for_request` mapping tests.
- env parsing tests for ops toggles.

### 8.2 Integration tests

Add a `tests/daemon_socket.rs` integration test that:
- starts the server bound to a temp socket path
- sends a `Status` request and validates the returned `ops` structure
- attempts a disabled operation (e.g. `CoreDispatch`) and expects Forbidden

### 8.3 Property tests (optional but recommended)

For the tail algorithm:
- random text with random line breaks
- ensure tail returns last N lines
- ensure runtime bounded by `max_bytes`

## References

High-quality primary references used for the design choices in this guide:

- systemd D-Bus interface (`org.freedesktop.systemd1.Manager` object model + method signatures such as `RestartUnit(in s name, in s mode, out o job)`):
  https://www.freedesktop.org/software/systemd/man/org.freedesktop.systemd1.html
- `systemd-zbus` crate docs (Rust bindings for systemd D-Bus APIs):
  https://docs.rs/systemd-zbus
- Linux `netlink(7)` man page (example subscribing to `RTMGRP_LINK | RTMGRP_IPV4_IFADDR`):
  https://www.man7.org/linux/man-pages/man7/netlink.7.html
- Linux kernel rtnetlink link family spec (multicast groups + message semantics):
  https://www.kernel.org/doc/html/latest/networking/netlink_spec/rt-link.html
- `ed25519-dalek` crate docs (signature verification API used for the signed update design):
  https://docs.rs/ed25519-dalek/latest/ed25519_dalek/
- zbus client proxy docs (useful if you generate a typed proxy for systemd D-Bus):
  https://elmarco.pages.freedesktop.org/zbus/client.html
