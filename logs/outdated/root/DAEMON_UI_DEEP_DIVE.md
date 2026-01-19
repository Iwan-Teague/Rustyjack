# Rustyjack Daemon/UI Deep Dive (Rust-Only Focus)
Created: 2026-01-07

This document captures the wiring issues introduced by the daemon, the fixes applied, and a Rust-first refactor plan. The goal is to make sure the daemon executes the existing Rust crate functions (core/wireless/ethernet/netlink/evasion/encryption), and that the UI routes all actions through the daemon.

## Scope

Crates and services reviewed:
- `rustyjack-ui`
- `rustyjack-core`
- `rustyjack-wireless`
- `rustyjack-ethernet`
- `rustyjack-netlink`
- `rustyjack-evasion`
- `rustyjack-encryption`
- `rustyjack-daemon`
- `rustyjack-ipc`
- `rustyjack-client`
- systemd units: `rustyjackd.service` (+ removed duplicate)

## Findings (Root Causes)

### 1) UI was not wired to the daemon for most actions
The UI still uses `CoreBridge::dispatch(Commands)` for the majority of flows (Wi-Fi profiles, ethernet recon, evasion, loot, mitm, etc.). That dispatch path was intentionally disabled in the daemon, so most UI actions never reached the core logic.

Impact:
- Wi-Fi connect paths from the UI never executed `rustyjack_core::operations` (so DHCP and route setup never happened).
- A large surface area of UI functionality appeared “broken” even though core implementations exist.

### 2) Hotspot IPC mismatch dropped the upstream interface
`rustyjack_ipc::HotspotStartRequest` includes `upstream_interface`, but the job payload (`HotspotStartRequestIpc`) and `rustyjack_core::services::hotspot::HotspotStartRequest` did not. The daemon job used the Ipc struct and never forwarded the upstream interface.

Impact:
- Hotspot could not configure NAT properly for upstream.
- Inconsistent behavior between UI/core flows.

### 3) Daemon endpoints cover only a subset of UI needs
The daemon has explicit endpoints for a small set of operations (wifi scan/connect, hotspot start/stop, portal, mount, etc.), while UI relies on `rustyjack-core` operations for everything else.

Impact:
- Without CoreDispatch, UI and daemon functionality drifted apart.
- The daemon duplicated functionality already present in core.

### 4) Two daemon service units existed
Both `rustyjackd.service` and `rustyjackd.service.hardened` existed. Installers only deploy `rustyjackd.service`.

Impact:
- Confusion about which unit is active.
- Hardened configuration was not necessarily in use.

## Changes Applied

### A) Re-enabled core dispatch through the daemon
Files:
- `rustyjack-ui/src/core.rs`
- `rustyjack-daemon/src/dispatch.rs`
- `rustyjack-ipc/src/types.rs`
- `rustyjack-client/src/client.rs`
- `rustyjackd.service`

Change summary:
- UI now sends `LegacyCommand::CommandDispatch` to the daemon with serialized `rustyjack_commands::Commands`.
- Daemon decodes the command and calls `rustyjack_core::operations::dispatch_command`.
- Service unit sets `RUSTYJACKD_ALLOW_CORE_DISPATCH=true` and `RUSTYJACKD_SOCKET_GROUP=rustyjack`.
- Client uses the long request timeout for core dispatch.

Result:
All existing Rust core operations are executed by the daemon, without duplicating logic in the UI.

### B) Fixed hotspot IPC shape
Files:
- `rustyjack-ipc/src/job.rs`
- `rustyjack-core/src/services/hotspot.rs`
- `rustyjack-daemon/src/jobs/kinds/hotspot_start.rs`
- `rustyjack-daemon/src/dispatch.rs`
- `rustyjack-client/src/client.rs`
- `rustyjack-ui/src/core.rs`

Change summary:
- `HotspotStartRequestIpc` now includes `upstream_interface`.
- `rustyjack_core::services::hotspot::HotspotStartRequest` now includes `upstream_interface`.
- Daemon job forwards upstream interface into core hotspot service.
- Client/UI signature updated accordingly.
- Upstream interface is optional (empty for offline hotspot).

Result:
Hotspot NAT and interface selection are restored.

### C) Removed duplicate systemd unit
Files:
- `rustyjackd.service` retained and updated
- `rustyjackd.service.hardened` removed
- `docs/FINAL_REPORT.md` updated to reflect a single hardened unit

Result:
One daemon unit, consistent with installers.

### D) Rust-only Wi-Fi scan + backend enforcement
Files:
- `rustyjack-core/src/system/mod.rs`
- `rustyjack-core/src/services/wifi.rs`
- `rustyjack-wireless/src/nl80211_queries.rs`
- `rustyjack-netlink/src/wireless.rs`
- `rustyjack-netlink/src/lib.rs`
- `rustyjack-netlink/src/station/mod.rs`
- `rustyjack-netlink/src/wpa.rs`

Change summary:
- Wi-Fi scan now uses nl80211 (`rustyjack_netlink::scan_wifi_networks`) instead of NetworkManager.
- External wpa_supplicant backend is feature-gated; core ignores external backend env values.
- WpaStatus/WpaSupplicantState types are available even when `station_external` is off.
- Removed wpa_supplicant control socket preflight logging in core/services.

Result:
Wi-Fi scan and station backend selection are Rust-only at runtime.

### E) Disabled external portal mode
Files:
- `rustyjack-daemon/src/jobs/kinds/portal_start.rs`

Change summary:
- Portal always runs embedded Rust service; `RUSTYJACK_PORTAL_MODE=external` is ignored.

Result:
No external portal binary is spawned.

### F) Command-group endpoints (Phase 2 partial)
Files:
- `rustyjack-ipc/src/types.rs`
- `rustyjack-ipc/src/lib.rs`
- `rustyjack-client/src/client.rs`
- `rustyjack-daemon/src/dispatch.rs`
- `rustyjack-daemon/src/auth.rs`
- `rustyjack-ui/src/core.rs`

Change summary:
- Added explicit daemon endpoints for command groups: Status, Wifi, Ethernet, Loot, Notify, System, Hardware, DnsSpoof, Mitm, Reverse, Hotspot, Scan, Bridge, Process.
- Daemon routes these to `rustyjack_core::operations::dispatch_command` with the matching command.
- UI CoreBridge now uses these endpoints and only falls back to CoreDispatch for unsupported groups (if any are added later).

Result:
UI operations use explicit endpoints for all command groups while still reusing core logic.

## Call Chain Map (UI -> Daemon -> Core -> Crates)

### Wi-Fi connect (saved profile)
1) UI: `CoreBridge::dispatch(Commands::Wifi(WifiProfileCommand::Connect))`
2) Daemon: `CoreDispatch` -> `rustyjack_core::operations::dispatch_command`
3) Core: `handle_wifi_profile_connect`
4) System:
   - `rustyjack_core::system::connect_wifi_network`
   - `rustyjack_netlink::dhcp_acquire`
   - `rustyjack_wireless` station backend (RustWpa2 default)
5) Route/Isolation:
   - `handle_wifi_route_ensure`
   - `select_active_uplink`

### Wi-Fi scan (UI scan list)
1) UI: `CoreBridge::wifi_scan` (explicit endpoint)
2) Daemon: `RequestBody::WifiScanStart` -> job
3) Core service: `rustyjack_core::services::wifi::scan`
4) System:
   - `rustyjack_core::system::scan_wifi_networks_with_timeout`
   - `rustyjack_netlink::scan_wifi_networks` (nl80211)

### Hotspot start (full UI flow)
1) UI: `CoreBridge::dispatch(Commands::Hotspot(HotspotCommand::Start))`
2) Daemon: `CoreDispatch` -> `rustyjack_core::operations::dispatch_command`
3) Core: `handle_hotspot_start`
4) Wireless: `rustyjack_wireless::start_hotspot` (DHCP/DNS/NAT)
5) Isolation: `apply_interface_isolation` (best-effort)

### Hotspot diagnostics/warnings/clients
1) UI: direct daemon endpoints
2) Core service: `rustyjack_core::services::hotspot::*`
3) Wireless/Netlink:
   - `rustyjack_wireless::hotspot_leases`
   - `rustyjack_netlink::allowed_ap_channels`, `RfkillManager`

### Ethernet recon
1) UI: `CoreBridge::dispatch(Commands::Ethernet(...))`
2) Daemon: `CoreDispatch`
3) Core: `handle_eth_*`
4) Crate: `rustyjack-ethernet`

### Evasion (MAC randomization / tx power)
1) UI: `CoreBridge::dispatch(Commands::Wifi(...))`
2) Daemon: `CoreDispatch`
3) Core: `handle_wifi_mac_randomize`, `handle_wifi_tx_power`
4) Crate: `rustyjack-evasion`

### Encryption (profiles/loot)
1) UI: uses encryption key handling for profiles
2) Core: `rustyjack_core::system::{read/write}_wifi_profile` (encryption)
3) Crate: `rustyjack-encryption`

## Rust-Only Constraint (No External Binaries)

The current codebase still spawns external binaries in several places (e.g., `systemctl`, `tar`, `openssl`, etc.). For a strict “Rust-only + Linux OS interfaces” requirement, these need to be removed or replaced.

Relevant to network connectivity:
- `rustyjack-netlink/src/station/external/process.rs` invokes `wpa_supplicant` (now feature-gated and unused).

Implemented:
- Core ignores external backend env values; default is `StationBackendKind::RustWpa2`.
- Wi-Fi scan uses nl80211 in-process.
- DHCP remains `rustyjack_netlink::dhcp_*` (already Rust).

If you want to enforce this at runtime:
- `RUSTYJACK_WIFI_BACKEND=rust_wpa2`
- `RUSTYJACK_PORTAL_MODE=external` is ignored (embedded only)

## Fix Plan (If Further Refactor Needed)

### Phase 1: Stabilize UI -> Daemon -> Core
Goal: Zero duplication. All UI commands route to the daemon and reuse core logic.
- Keep `CoreDispatch::CommandDispatch` enabled until explicit endpoints cover all UI features.
- Ensure `rustyjackd.service` sets:
  - `RUSTYJACKD_ALLOW_CORE_DISPATCH=true`
  - `RUSTYJACKD_SOCKET_GROUP=rustyjack`
- Keep `rustyjack-ui` in group `rustyjack` so it can access `/run/rustyjack/rustyjackd.sock`.

### Phase 2: Add explicit endpoints (optional)
Only needed if you want to remove `CoreDispatch`.
- Add endpoints for:
  - Wi-Fi profiles (list/show/save/connect/delete)
  - Ethernet recon (discover/port scan/inventory/site-cred)
  - Evasion (MAC randomize/set/restore, tx power)
  - Loot operations
- Each endpoint should call the existing `rustyjack_core::operations` handlers or dedicated `services` modules.

### Phase 3: Rust-only network stack
Goal: No external binaries or third-party daemons.
- External Wpa backend is feature-gated and not used by default.
- Scan now uses `rustyjack_netlink` nl80211.
- Remaining NetworkManager integration is optional and not part of core Wi-Fi connect flow.

## Why This Fixes IP Acquisition

Previously:
- UI actions were not reaching `rustyjack_core::operations`.
- Wi-Fi connect from the UI was not executing `connect_wifi_network`, so no DHCP request ran.

Now:
- UI uses CoreDispatch to call core operations.
- `handle_wifi_profile_connect` executes:
  - MAC hardening (evasion)
  - `connect_wifi_network` (RustWpa2 backend + DHCP)
  - route ensure and uplink selection

That restores DHCP lease acquisition and route setup.

## Operational Checklist

1) Deploy service unit:
```
sudo cp rustyjackd.service /etc/systemd/system/rustyjackd.service
sudo systemctl daemon-reload
sudo systemctl restart rustyjackd
```

2) Ensure UI can talk to the daemon:
- `rustyjack-ui` user must be in `rustyjack` group.
- Socket should be `/run/rustyjack/rustyjackd.sock` with group `rustyjack`.

3) Confirm Wi-Fi connect path:
- UI -> connect profile -> daemon -> `handle_wifi_profile_connect`
- Check logs: `journalctl -u rustyjackd -n 200`

## Summary

The daemon is now the single execution path for Rust core functionality, and the UI sends all existing commands through it again. Hotspot IPC was corrected so upstream interfaces are honored. The remaining work is optional: either keep CoreDispatch or add explicit endpoints for all UI features; and, if required, replace any external binaries with Rust/native Linux interfaces.
