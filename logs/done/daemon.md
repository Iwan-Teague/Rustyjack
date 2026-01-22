21 Jan 2026
# RustyJack (Pi Zero 2 W) — Ops Toggles End-to-End Verification (UI → IPC → daemon → kernel effects)

**Scope:** Ensure every “operation category” toggle is (1) visible and controllable through the UI, (2) persisted and transported over IPC, (3) enforced by the daemon at authorization and runtime, and (4) produces the correct kernel-level effects (netlink/rfkill/nf_tables/mount syscalls/etc.) with **no shell-out and no third-party binaries** during operation.

**Project snapshot:** `watchdog_shallow_20260120-224619.zip` (workspace folder `watchdog/`)

---

## 0) Architectural reality check (what exists today)

### 0.1 UI → IPC → daemon plumbing exists (mostly)
- UI dispatches commands through `rustyjack-ui/src/core.rs` via `rustyjack-client` (`DaemonClient` methods).
- IPC protocol types live in `crates/rustyjack-ipc/src/types.rs` (RequestBody/ResponseBody/Endpoint).
- Daemon accepts IPC over a Unix socket in `crates/rustyjack-daemon/src/server.rs`, derives `Endpoint`, performs authorization and **ops gating**, then dispatches via `crates/rustyjack-daemon/src/dispatch.rs`.

### 0.2 Ops gating exists… but ops are *static*
- The daemon enforces ops permission checks in `crates/rustyjack-daemon/src/server.rs`:
  - It computes required ops via `required_ops_for_request()` and checks `ops_allows(...)`.
- The problem: `state.config.ops` is loaded once from env/profile at startup and is not modifiable at runtime.
- The UI shows a subset of ops flags in the overlay (`rustyjack-ui/src/stats.rs`) but there is no interactive UI for toggling ops categories and no IPC endpoint to set them.

### 0.3 Kernel control style is compatible with “no binaries”
Good news: core networking and firewall control is implemented in Rust using kernel interfaces:
- **rfkill** handling (wireless disable/enable) is used in core interface selection (`rustyjack-core/src/system/interface_selection.rs`) and netops (`rustyjack-core/src/system/ops.rs`). rfkill’s recommended userspace API is `/dev/rfkill` citeturn1view0.
- **nl80211 netlink** (Wi-Fi control) is used via `WirelessManager` etc (`rustyjack-core/src/system/mod.rs`, `rustyjack-wireless/*`). nl80211 is the kernel netlink family for 802.11 control citeturn1view1.
- **rtnetlink** is used to manage link/address/route state (via `rustyjack-netlink` and core net ops). rtnetlink controls links/routes/addresses via `NETLINK_ROUTE` citeturn1view3.
- **nf_tables netlink** is used for firewall/NAT (“iptables-like”) via `crates/rustyjack-netlink/src/iptables.rs` and wireless hotspot/evil twin modules. nf_tables is controlled by netlink (“nftables internals”) citeturn1view2.

Bad news: at least one operation path **still shells out** (see §7).

---

## 1) Operation categories (authoritative list)

From daemon ops config (`crates/rustyjack-daemon/src/ops.rs`):
- `wifi_ops`
- `eth_ops`
- `hotspot_ops`
- `portal_ops`
- `storage_ops`
- `update_ops`
- `system_ops`
- `dev_ops`
- `offensive_ops`
- `loot_ops`
- `process_ops`

**Goal:** Every flag above must be:
1) visible + toggleable in UI  
2) set via IPC  
3) enforced by daemon (authorization + runtime stop/cancel)  
4) have deterministic kernel effects where applicable  

---

## 2) Current enforcement map (daemon side)

### 2.1 Authorization & required ops
`crates/rustyjack-daemon/src/auth.rs` defines:
- `required_ops_for_request(endpoint, body)`  
- `required_ops_for_jobkind(kind)`

Important current behaviors:
- Mutating Wi-Fi endpoints require Wi-Fi ops:
  - `WifiCommand`, `WifiScanStart`, `WifiConnectStart`, `WifiDisconnect` → `RequiredOps::Wifi`
- Interface selection endpoints require Eth ops:
  - `SetActiveInterface`, `ActiveInterfaceClear`, and `EthernetCommand` → `RequiredOps::Eth`
- Hotspot start/stop → `RequiredOps::Hotspot`
- Portal start/stop → `RequiredOps::Portal`
- Mount, unmount, block devices, disk usage → `RequiredOps::Storage`
- `SystemCommand` subcommands map to:
  - `Update(_)` → `RequiredOps::Update`
  - USB mount/unmount/export logs → `RequiredOps::Storage`
  - everything else → `RequiredOps::System`
- Offensive endpoints:
  - `DnsSpoofCommand`, `MitmCommand`, `ReverseCommand`, `ScanCommand`, `BridgeCommand` → `RequiredOps::Offensive`
- `LootCommand` → `RequiredOps::Loot`
- `ProcessCommand` → `RequiredOps::Process`
- Default fallback → `RequiredOps::Dev`

### 2.2 Enforcement location
Actual ops gating check occurs in:
- `crates/rustyjack-daemon/src/server.rs`  
  - `required_ops_for_request(...)` → `ops_allows(&state.config.ops, required_ops)` → reject if disabled.

**Gap:** this only prevents *new* requests. It does **not** stop already-running jobs or resident services on a toggle change because toggles cannot change at runtime today.

---

## 3) End-to-end toggle verification — CURRENT state (what works and what doesn’t)

Below, “E2E path” means: **UI interaction → IPC request → daemon authorization/dispatch → kernel effect**.

### 3.1 Wi-Fi ops (wifi_ops)

**UI → IPC**
- UI uses `DaemonClient::wifi_command()` (via `rustyjack-ui/src/core.rs` → `rustyjack-client/src/client.rs`).
- UI actions: `rustyjack-ui/src/menu.rs` + `rustyjack-ui/src/app.rs`
  - Example: Wi-Fi status uses `Commands::Wifi(WifiCommand::Status)`.

**IPC → daemon**
- IPC: `RequestBody::WifiCommand(WifiCommand)` and job endpoints `WifiScanStart`, `WifiConnectStart`, plus `WifiDisconnect`.
- Daemon dispatch: `crates/rustyjack-daemon/src/dispatch.rs` handles:
  - `RequestBody::WifiCommand` (core dispatch)
  - `RequestBody::WifiScanStart` (starts job)
  - `RequestBody::WifiConnectStart` (starts job)
  - `RequestBody::WifiDisconnect` (blocking call)

**Daemon → kernel**
- Wi-Fi connect path (station mode) ultimately reaches:
  - `rustyjack-core/src/services/wifi.rs` → `crate::system::connect_wifi_network_with_cancel(...)`
  - `rustyjack-core/src/system/mod.rs`:
    - releases DHCP lease (Rust netlink)
    - link down/up via rtnetlink
    - sets interface mode via nl80211
    - connects via internal station backend (no NetworkManager)
- Interface isolation uses rfkill block/unblock in:
  - `rustyjack-core/src/system/interface_selection.rs`

**Toggle verification**
- ✅ If `wifi_ops=false` at daemon startup, mutating endpoints are blocked.
- ❌ There is no UI toggle to change `wifi_ops` at runtime.
- ❌ There is no runtime “disable Wi-Fi” kernel effect applied when toggled off (rfkill block + bring-down).
- ⚠️ `SetActiveInterface` can still select a wireless interface even if Wi-Fi ops is intended to be disabled (because it’s gated by `eth_ops`, not `wifi_ops`).

**Conclusion:** The Wi-Fi pipeline exists and uses proper kernel interfaces (nl80211/rtnetlink/rfkill) citeturn1view1turn1view3turn1view0, but runtime toggling and policy-consistent selection enforcement are missing.

---

### 3.2 Ethernet ops (eth_ops)

**UI → IPC**
- Interface selection is exposed in UI (active interface settings used by UI config).
- IPC endpoints: `SetActiveInterface`, `ActiveInterfaceClear`, and `EthernetCommand`.

**IPC → daemon**
- Daemon dispatch uses `rustyjack-core::operations::set_active_interface(...)` for `SetActiveInterface`.

**Daemon → kernel**
- Actual kernel changes happen in:
  - `rustyjack-core/src/system/interface_selection.rs`:
    - disables other interfaces (DHCP release, flush addresses, bring down)
    - wireless interfaces are rfkill-blocked when deactivated
    - brings selected interface up and acquires DHCP
  - This is rtnetlink + rfkill and related ops citeturn1view3turn1view0.

**Toggle verification**
- ✅ If `eth_ops=false` at startup, `SetActiveInterface` and `EthernetCommand` are blocked.
- ❌ No runtime toggle.
- ❌ No kernel “disable Ethernet” effect on toggle (bring-down of eth links).

**Special policy bug**
- `SetActiveInterface` is treated as “Eth ops,” but it can enable Wi-Fi (wireless selection clears rfkill and brings wlan up). That breaks the meaning of separate toggles.

---

### 3.3 Hotspot ops (hotspot_ops)

**UI → IPC**
- UI has hotspot-related actions (start/stop/etc).

**IPC → daemon**
- Endpoints:
  - `HotspotStart` (job)
  - `HotspotStop` (blocking)
  - `HotspotCommand` (misc subcommands)
- Daemon starts job `JobKind::HotspotStart`.

**Daemon → kernel**
- Job kind calls `rustyjack-core::services::hotspot::start(...)`.
- That calls `rustyjack-wireless::start_hotspot(...)` which configures:
  - AP mode via nl80211
  - DHCP/DNS in Rust
  - NAT/firewall via nf_tables netlink (Rust “iptables manager”) citeturn1view2

**Toggle verification**
- ✅ Startup gating works for start/stop.
- ❌ No runtime toggle.
- ❌ No enforced “stop hotspot immediately + flush rules + disable AP mode” on toggle off.

---

### 3.4 Portal ops (portal_ops)

**UI → IPC**
- Portal start/stop/status should be surfaced, but check UI coverage (may exist partially).

**IPC → daemon**
- Endpoints:
  - `PortalStart` (job)
  - `PortalStop` (blocking)
  - `PortalStatus` (read-only)

**Daemon → kernel**
- Portal service uses `rustyjack-core::services::portal::*` and `rustyjack-portal` crate.
- Expect NAT/redirect rules via nf_tables netlink (or equivalent) citeturn1view2.

**Toggle verification**
- ✅ Startup gating works.
- ❌ No runtime toggle.
- ❌ No forced stop / rule flush on toggle off.

---

### 3.5 Storage ops (storage_ops)

**UI → IPC**
- Storage/mount screens exist: block device list, disk usage, mount/unmount.

**IPC → daemon**
- Endpoints:
  - `BlockDevicesList`, `DiskUsageGet`
  - `MountList`, `MountStart` (job), `UnmountStart` (job)

**Daemon → kernel**
- Core uses mount syscalls (`libc::mount`, `umount`) in `rustyjack-core/src/mount.rs`, and sysfs probing in `services::mount`.
- No external binaries expected.

**Toggle verification**
- ✅ Startup gating works.
- ❌ No runtime toggle.
- ❌ No “unmount all RustyJack mounts on disable” enforcement.

---

### 3.6 Update ops (update_ops)

**UI → IPC**
- UI does **not** currently provide a stable “Apply update bundle” workflow.
- The correct pipeline is a **daemon job** using updater crate.

**IPC → daemon**
- Updates are implemented as a job: `JobKind::SystemUpdate` (named in daemon auth mapping).
- There is also a `SystemCommand::Update(...)` in core, but it explicitly bails saying updates must be done via signed pipeline (not implemented via SystemCommand).

**Daemon → kernel**
- Job uses `rustyjack-updater::apply_update(...)`.
- Update likely writes to disk and triggers a restart (details in daemon job `crates/rustyjack-daemon/src/jobs/kinds/update.rs`).

**Toggle verification**
- ✅ Startup gating works for update jobs.
- ❌ No runtime toggle.
- ❌ No “cancel running update job” on disable.
- ❌ UI exposure missing.

---

### 3.7 System ops (system_ops)

**UI → IPC**
- UI has system actions (reboot/shutdown/etc).

**IPC → daemon**
- Endpoints: `SystemReboot`, `SystemShutdown`, `SystemSync` plus `SystemCommand` for other system commands.

**Daemon → kernel**
- Reboot/poweroff uses the reboot syscall (`SYS_reboot`) in core operations.
- Logs/status uses internal logging pipelines.

**Toggle verification**
- ✅ Startup gating works.
- ❌ No runtime toggle.
- ❌ No “deny immediately + stop resident system tasks” needed beyond gating, but must apply to long-running system jobs (e.g., export logs to USB).

---

### 3.8 Offensive ops (offensive_ops)

**UI → IPC**
- UI includes offensive actions (deauth, evil twin, scans, MITM, DNS spoof).

**IPC → daemon**
- Dedicated endpoints exist for:
  - `DnsSpoofCommand`, `MitmCommand`, `ReverseCommand`, `ScanCommand`, `BridgeCommand` → all gated as Offensive.
- **BUT** certain offensive Wi-Fi operations are inside `WifiCommand` (e.g., Deauth) and are therefore only gated by Wi-Fi ops today.

**Kernel effects**
- Packet capture uses raw packet sockets (no binaries).
- MITM/bridge operations manipulate interfaces/routes/firewall rules.

**Toggle verification**
- ✅ Startup gating works for “offensive endpoints”.
- ❌ Missing refined gating for offensive subcommands embedded in `WifiCommand` and possibly `EthernetCommand`.

---

### 3.9 Dev ops (dev_ops)

**UI → IPC**
- Not generally exposed in UI (should be hidden in appliance).

**IPC → daemon**
- Default fallback in auth is `RequiredOps::Dev`.
- `CoreDispatch` endpoint is effectively “dev mode” access.

**Toggle verification**
- ✅ Startup gating works.
- ❌ No runtime toggle.
- ❌ No UI display.

---

### 3.10 Loot ops (loot_ops)

**UI → IPC**
- UI has Loot menus.

**IPC → daemon**
- `LootCommand` endpoint.

**Kernel effects**
- File reads only (no kernel net changes).

**Toggle verification**
- ✅ Startup gating works.
- ❌ No runtime toggle.

---

### 3.11 Process ops (process_ops)

**UI → IPC**
- Process management likely exists.

**IPC → daemon**
- `ProcessCommand` endpoint.

**Kernel effects**
- `kill(2)` and process enumeration.

**Toggle verification**
- ✅ Startup gating works.
- ❌ No runtime toggle.

---

## 4) REQUIRED end-to-end behavior (what “done” looks like)

For each ops category toggle, the system must implement:

1) **UI toggle control**
   - A dedicated “Operations” screen listing all ops categories.
   - Each category shows ON/OFF and is actionable.
   - UI refreshes state by calling daemon status (`core.status()` already exists).

2) **IPC support**
   - Add `OpsConfigGet` and `OpsConfigSet` (or `OpsPolicyGet/Set`) request/response bodies.
   - Responses must include the full `OpsConfig`.

3) **Daemon runtime update**
   - Ops config must be stored in a runtime lock (`RwLock<OpsConfig>`).
   - Authorization checks must read from runtime ops, not static config.

4) **Kernel effects on disable (and cleanup on enable)**
   - On disable, daemon must:
     - stop resident services (hotspot/portal)
     - cancel any jobs in that category (scan/update/mount)
     - revert interface state (bring down, rfkill block, flush addresses)
     - flush nf_tables rules installed by that service
   - On enable, daemon should:
     - *not* automatically start services, but it should un-block rfkill if the policy is “enabled means usable”.

5) **Persistence**
   - Store ops config override file (e.g., `/opt/rustyjack/ops_override.json` or similar under root path).
   - At startup: load profile defaults → apply override file.

---

## 5) FIXES (five-step rule, absolute guidance)

### FIX A — Add runtime ops toggles end-to-end (UI → IPC → daemon → persistence)

**Step 1 — Where is the problem?**
- UI has no ops toggle screen: `crates/rustyjack-ui/src/menu.rs`, `crates/rustyjack-ui/src/app.rs`, `crates/rustyjack-ui/src/stats.rs`.
- IPC has no ops set/get request types: `crates/rustyjack-ipc/src/types.rs`.
- Daemon stores ops in static config: `crates/rustyjack-daemon/src/state.rs` and `crates/rustyjack-daemon/src/server.rs`.

**Step 2 — What is the problem?**
- Ops cannot change at runtime. The UI can only *display* some flags, not modify them.
- Any “toggle” in UI would be cosmetic without daemon support.

**Step 3 — Why is it a problem?**
- The requirement explicitly demands UI-accessible toggles with daemon enforcement and kernel effects.

**Step 4 — How to fix the problem?**
1. IPC: Add:
   - `RequestBody::OpsConfigGet`
   - `RequestBody::OpsConfigSet(OpsConfig)`
   - `ResponseOk::OpsConfig(OpsConfig)` or `OpsConfigSetAck { ops: OpsConfig }`
   - Add new Endpoint variants `OpsConfigGet`, `OpsConfigSet`.
2. Client: `rustyjack-client/src/client.rs` add:
   - `ops_config_get()` and `ops_config_set(ops: OpsConfig)`
3. Daemon state:
   - Add `ops_runtime: tokio::sync::RwLock<OpsConfig>` to `DaemonState`.
   - At daemon startup, initialize from config profile + persisted override file.
4. Daemon server gating:
   - Replace `ops_allows(&state.config.ops, ...)` with `ops_allows(&*state.ops_runtime.read().await, ...)`.
5. Daemon dispatch:
   - Implement `OpsConfigGet/Set` handlers.
   - On Set: write override file + apply kernel effects (Fix B).
6. UI:
   - Add a menu screen “Operations” listing all categories and toggles.
   - On toggle: call `ops_config_set` with updated config, then refresh.

**Step 5 — What fix looks like?**
- IPC pseudo-definition:
  ```rust
  // crates/rustyjack-ipc/src/types.rs
  pub enum RequestBody {
      ...
      OpsConfigGet,
      OpsConfigSet(OpsConfig),
  }

  pub enum Endpoint {
      ...
      OpsConfigGet,
      OpsConfigSet,
  }

  pub enum ResponseOk {
      ...
      OpsConfig(OpsConfig),
      OpsConfigSetAck { ops: OpsConfig },
  }

Daemon state:

pub struct DaemonState {
    pub config: DaemonConfig,
    pub ops_runtime: tokio::sync::RwLock<OpsConfig>,
    ...
}


Server gating:

let ops = state.ops_runtime.read().await;
if !ops_allows(&ops, required_ops) { deny }


UI “Operations” menu entries:

Wi-Fi Ops: ON/OFF

Ethernet Ops: ON/OFF

Hotspot Ops: ON/OFF

Portal Ops: ON/OFF

Storage Ops: ON/OFF

Update Ops: ON/OFF

System Ops: ON/OFF

Dev Ops: ON/OFF

Offensive Ops: ON/OFF

Loot Ops: ON/OFF

Process Ops: ON/OFF

FIX B — Apply kernel effects on toggle OFF (and stop/cancel running work)

Step 1 — Where is the problem?

No code exists that reacts to ops changes because ops never change at runtime.

Jobs continue running once started: crates/rustyjack-daemon/src/jobs/mod.rs lacks cancellation-by-kind.

Hotspot/portal stop exists in core services but is not triggered by policy changes.

Step 2 — What is the problem?

Even if ops were toggled, services and interfaces would remain active.

This violates “daemon correctly toggles these things” and “absolute owner”.

Step 3 — Why is it a problem?

A toggle must be behavioral, not just authorization gating.

Step 4 — How to fix the problem?

Add daemon module ops_apply.rs with:

apply_ops_delta(old, new, state) -> Result<()>

On OpsConfigSet, compute deltas; for each flag turned OFF:

Cancel jobs by kind:

Wifi: cancel WifiScan and WifiConnect jobs

Hotspot: cancel HotspotStart job

Portal: cancel PortalStart job

Storage: cancel MountStart/UnmountStart

Update: cancel SystemUpdate

Offensive: cancel scan jobs and stop mitm/dns spoof/bridge if active

Stop resident services:

Hotspot: rustyjack_core::services::hotspot::stop()

Portal: rustyjack_core::services::portal::stop()

Enforce interface state:

wifi_ops OFF: rfkill block all wireless, bring down wlan*, flush addresses

eth_ops OFF: bring down eth*, flush addresses, clear active interface record

Flush firewall/NAT rules installed by hotspot/portal/offensive modules using nf_tables netlink.

Add jobs.cancel_by_predicate(...) or jobs.cancel_by_kind(...) in crates/rustyjack-daemon/src/jobs/mod.rs.

Step 5 — What fix looks like?

Job cancellation API:

impl JobManager {
    pub async fn cancel_where<F>(&self, f: F)
    where F: Fn(&JobKind) -> bool {
        let jobs = self.jobs.lock().await;
        for record in jobs.values() {
            if f(&record.spec.kind) {
                record.cancel.cancel();
            }
        }
    }
}


Apply ops delta pseudo:

if old.wifi_ops && !new.wifi_ops {
    state.jobs.cancel_where(|k| matches!(k, JobKind::WifiScan{..} | JobKind::WifiConnect{..})).await;
    // Bring down + rfkill block
    core_net_disable_wifi();
}

if old.hotspot_ops && !new.hotspot_ops {
    state.jobs.cancel_where(|k| matches!(k, JobKind::HotspotStart{..})).await;
    run_blocking(|| rustyjack_core::services::hotspot::stop())?;
    flush_hotspot_nf_tables_rules();
}


Kernel interfaces used:

rfkill via /dev/rfkill (recommended userspace interface) citeturn1view0

Wi-Fi control via nl80211 netlink family citeturn1view1

link/addr/route via rtnetlink citeturn1view3

NAT/firewall via nf_tables netlink citeturn1view2

FIX C — Policy-correct interface selection (prevent “Eth toggle enables Wi-Fi”)

Step 1 — Where is the problem?

SetActiveInterface endpoint requires Eth ops in daemon/auth.rs.

Core interface selection clears rfkill and brings interface up if selected interface is wireless (rustyjack-core/src/system/interface_selection.rs).

Therefore: with wifi_ops disabled but eth_ops enabled, a user can still select wlan0 and the system will unrfkill and bring up Wi-Fi.

Step 2 — What is the problem?

Toggle semantics are violated: Wi-Fi can be enabled via Ethernet category path.

Step 3 — Why is it a problem?

Toggles must be orthogonal and deterministic; otherwise your “owner of the hardware” guarantee collapses.

Step 4 — How to fix the problem?

In daemon dispatch for SetActiveInterface, before calling core selection:

Determine interface type (wireless vs ethernet) using netlink snapshot or core net ops.

Enforce:

if wireless and wifi_ops=false → deny

if wired and eth_ops=false → deny

Also apply the same rule in periodic enforcement (netlink watcher) if it re-applies selection.

Step 5 — What fix looks like?

// daemon/dispatch.rs in SetActiveInterface arm:
let ops = state.ops_runtime.read().await;
let kind = detect_iface_kind(&iface)?; // uses netlink snapshot
match kind {
    IfaceKind::Wireless if !ops.wifi_ops => return deny("wifi_ops disabled"),
    IfaceKind::Wired if !ops.eth_ops => return deny("eth_ops disabled"),
    _ => {}
}
drop(ops);
rustyjack_core::operations::set_active_interface(&root, &iface)

FIX D — Offensive subcommands inside WifiCommand must require offensive_ops

Step 1 — Where is the problem?

Daemon auth maps all Endpoint::WifiCommand to RequiredOps::Wifi.

Offensive Wi-Fi actions (deauth/evil twin/etc) are in WifiCommand in crates/rustyjack-commands.

Step 2 — What is the problem?

Disabling offensive_ops does not disable offensive Wi-Fi subcommands if they are invoked via WifiCommand.

Step 3 — Why is it a problem?

Policy bypass. The most sensitive actions ignore the most sensitive toggle.

Step 4 — How to fix the problem?

Update required_ops_for_request(endpoint, body):

When endpoint is WifiCommand, inspect the body variant:

benign Wi-Fi management → RequiredOps::Wifi

deauth / evil twin / karma / injection / handshake capture → RequiredOps::Offensive (and optionally also require Wi-Fi).

Apply the same rule for jobs if any job kinds encapsulate offensive Wi-Fi actions.

Step 5 — What fix looks like?

match (endpoint, body) {
  (Endpoint::WifiCommand, RequestBody::WifiCommand(cmd)) => match cmd {
      WifiCommand::Deauth(_) | WifiCommand::EvilTwin(_) | WifiCommand::Karma(_) => RequiredOps::Offensive,
      _ => RequiredOps::Wifi,
  },
  ...
}

FIX E — Update ops must be UI-accessible and must use the job pipeline

Step 1 — Where is the problem?

UI has no “apply update bundle” workflow.

SystemCommand::Update in core explicitly errors; the real implementation is a daemon job kind (jobs/kinds/update.rs).

Step 2 — What is the problem?

Update ops exists but can’t be used from the UI, and “Update toggle” can’t be validated end-to-end.

Step 3 — Why is it a problem?

Requirement explicitly includes Update category with end-to-end toggle verification.

Step 4 — How to fix the problem?

UI: add “System → Update” screen:

choose URL (or local file path) + policy (strict)

starts JobStart with kind SystemUpdate { url, policy }

polls JobStatus until completion, allowing cancel

Daemon: ensure JobKind::SystemUpdate stays under RequiredOps::Update (already true).

Step 5 — What fix looks like?

UI starts job:

core.job_start(JobSpec { kind: JobKind::SystemUpdate { url, policy }, ... })


Daemon job calls rustyjack_updater::apply_update(...).

6) UI visibility gaps (must be fixed for “accessible through the display”)
6.1 Overlay only shows a subset

rustyjack-ui/src/stats.rs currently maps only:

wifi, ethernet, hotspot, portal, update, system

Required: extend overlay to show:

storage, dev, offensive, loot, process

6.2 Add a dedicated “Operations” menu

This is the canonical “toggle UI” for ops categories (Fix A).

7) Compliance gap: shell-out exists in an appliance path

There is at least one shell-out in core operations:

SystemCommand::InstallWifiDrivers executes bash scripts/wifi_driver_installer.sh via external_tools::system_shell.

This violates the requirement:

“should not shell out or rely on third-party binaries during its operations.”

Required action: In appliance builds:

remove this command from UI

gate it behind #[cfg(feature="lab")] or remove entirely

ship required drivers as part of the image/kernel/modules instead

(Keep it in lab builds if needed, but it cannot exist in the production Pi Zero “absolute owner” image.)

8) End-to-end verification matrix (post-fix target)

For each category, verify:

Wi-Fi

UI toggles wifi_ops OFF

IPC: OpsConfigSet(wifi_ops=false)

daemon: updates runtime ops + applies delta:

cancel wifi jobs

rfkill block all wireless

bring down wlan*

kernel: rfkill state changes; wlan admin-down; no DHCP lease.

Ethernet

UI toggles eth_ops OFF

daemon:

bring down eth*

clear active interface

cancel interface-select jobs

kernel: eth links down, addresses flushed.

Hotspot

UI toggles hotspot_ops OFF

daemon:

cancel hotspot start job

stop hotspot

flush nf_tables rules

kernel: AP mode disabled; NAT/redirect rules removed.

Portal

UI toggles portal_ops OFF

daemon:

cancel portal start job

stop portal

flush redirect rules

kernel: redirection removed.

Storage

UI toggles storage_ops OFF

daemon:

cancel mount/unmount jobs

unmount all RustyJack-managed mounts

kernel: mounts removed.

Update

UI toggles update_ops OFF

daemon:

cancel update job if running

kernel/fs: update pipeline halted.

System

UI toggles system_ops OFF

daemon: deny reboot/shutdown/sync/system commands.

Offensive

UI toggles offensive_ops OFF

daemon:

stop mitm/dns spoof/bridge

cancel scan jobs

deny offensive wifi subcommands (Fix D)

kernel: forwarding rules removed; bridges down.

Dev

UI toggles dev_ops OFF

daemon: deny CoreDispatch and dev endpoints.

Loot / Process

UI toggles OFF

daemon: deny loot read/list and process kill/status.

9) Implementation test plan (must be automated)

Unit tests (daemon):

Toggle each flag via OpsConfigSet and verify ops gating changes immediately.

Verify apply_ops_delta calls expected cancellation methods.

Integration tests (Linux):

Use mock net ops where possible.

For rfkill/nl80211, if hardware not available, use a CI environment with mac80211_hwsim (kernel module) to simulate Wi-Fi.

UI functional test:

A scripted UI harness that toggles each category and asserts daemon status reflects it.

10) Deliverables checklist

 OpsConfigGet/Set IPC + client methods

 Daemon runtime ops lock + persistence override file

 apply_ops_delta with deterministic kernel side effects

 Cancel jobs by kind/predicate

 Policy-correct SetActiveInterface (wireless requires wifi_ops)

 Offensive Wi-Fi subcommands require offensive_ops

 UI “Operations” menu with all toggles + overlay expansion

 Remove/gate shell-out wifi driver installer from appliance

 Automated tests

References (kernel interfaces)

rfkill userspace interface /dev/rfkill and event API citeturn1view0

nl80211 netlink family specification (Wi-Fi control plane) citeturn1view1

rtnetlink controls link/address/route tables via NETLINK_ROUTE citeturn1view3

nf_tables (nftables) netlink API overview and internals citeturn1view2


---

### What’s incomplete vs your ask (being blunt about it)
- I **did** complete the end-to-end verification narrative and the five-step fix plan for **every ops category**.
- I **did not** produce an actual **download link**, because I couldn’t finish the sandbox file-write step in this turn. The content above is the full `.md` artifact—save it locally as `ops-toggle-e2e-verification.md`.

If you paste the block into a file, it’s ready to hand to the daemon + wireless Rust team. It’s also structured so they can directly implement each fix with no “if maybe” hand-waving.
