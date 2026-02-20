# Pro Revision Implementation Report

Date: 2026-02-18
Repo: `/Users/iwanteague/Desktop/watchdog`

## Root Cause Summary (before patch)

1. Daemon transport was brittle around `/run/rustyjack/rustyjackd.sock`:
- Runtime dir/socket lifecycle was not consistently enforced across service startup paths.
- Stale socket handling was not strict enough for replace-vs-active detection.
- Test coverage did not assert the invariant: "service active implies socket exists".

2. Interface switching paths were not strict enough for deterministic exclusivity:
- Non-selected interface deactivation and selected interface activation were not enforced through a single serialized path.
- UI flow had escape paths that could leave the screen before exclusivity was achieved.

3. Display wizard persistence allowed completion state to be set too early relative to successful re-init.

## Implemented Changes

### Phase 1: Daemon socket reliability

- Hardened socket bind and stale-socket replacement behavior:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-daemon/src/systemd.rs`
    - Validates existing path is a socket.
    - Detects active-vs-stale sockets (`AddrInUse` for active, remove/rebind for stale).
    - Ensures parent dir exists and sets permissions.
    - Logs explicit bind target: `listening on unix socket: ...`.
    - Added unit tests for stale replacement and active socket refusal.

- Added defensive runtime-dir creation on daemon startup:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-daemon/src/main.rs`

- Added/standardized socket unit:
  - `/Users/iwanteague/Desktop/watchdog/services/rustyjackd.socket`
  - `/Users/iwanteague/Desktop/watchdog/rustyjackd.socket`

- Installer updates to enforce socket activation order and runtime directory semantics:
  - `/Users/iwanteague/Desktop/watchdog/install_rustyjack.sh`
  - `/Users/iwanteague/Desktop/watchdog/install_rustyjack_dev.sh`

- Added service-active/socket-present invariant to comprehensive test harness:
  - `/Users/iwanteague/Desktop/watchdog/scripts/rustyjack_comprehensive_test.sh`
  - Check: `A6b_active_has_socket`.

### Phase 2: Unified Network Isolation Engine behavior

- Strengthened and serialized interface switch pipeline:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-core/src/system/interface_selection.rs`
    - Global single-flight lock (`INTERFACE_SWITCH_LOCK`) around transitions.
    - Explicit phases + progress emission.
    - Non-target deactivation includes DHCP release, address flush, default route delete, link down, and rfkill block for Wi-Fi.
    - Non-target Wi-Fi now attempts wpa_supplicant stop and station disconnect.
    - Target connectivity split by medium (`configure_wireless_target` / `configure_wired_target`).
    - Enforced ordering: non-target uplinks are disabled before target interface bring-up.
    - Added strict verification gate:
      - selected interface admin-UP + IPv4,
      - non-selected all DOWN,
      - non-selected Wi-Fi rfkill-blocked,
      - exactly one default route and it uses selected interface.
    - On verification failure: rollback to safe all-down state.
    - On post-commit failure: rollback restore of previous interface.
    - Added/updated tests around sequencing and exclusivity behavior.

- Added systemd D-Bus service controls used by isolation flow:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-netlink/src/systemd.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-netlink/src/lib.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-core/src/system/mod.rs`

- Interface list/status metadata expanded for UI and policy display:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ipc/src/types.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-daemon/src/dispatch.rs`
    - Includes `kind`, `mac`, `rfkill_blocked`, `eligible`.
    - `InterfacesListGet` now returns full detected interface set (non-loopback), with eligibility flags.

### Phase 3: UI flow hard-gating (`Network Interfaces`)

- Renamed menu entry and preflight messaging from hardware sanity wording to network interfaces:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/menu.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/menu.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/identity.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/hotspot.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/wifi/attacks.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/wifi/pipeline.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/ops/shared/preflight.rs`

- Reworked screen behavior and lockouts:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/iface_select.rs`
    - Immediate interface enumeration.
    - Type/status/rfkill-aware labels.
    - Confirmation dialog: "Are you sure?".
    - Blocking progress while switch job runs.
    - No navigation escape during switch execution.
    - On error: Retry + Reboot, and Back only when safe all-down state.
    - Prevents leaving `Network Interfaces` until exclusivity is achieved.

- Routed legacy `show_hardware_detect` entry to interface selection pipeline:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/settings.rs`

### Phase 4: Display wizard persistence safety

- Added explicit incomplete-state tracking and normalization rules:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/config.rs`
  - New flag: `display_wizard_incomplete`.

- Calibration apply/finalize split with crash-safe semantics:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/display.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/settings.rs`
    - Persist incomplete state first (atomic save), then finalize and persist complete state.
    - On finalize failure, state remains/resets to incomplete so wizard resumes on restart.

## Pi Verification Checklist

Run on Raspberry Pi (as root where noted):

1. Daemon/socket invariants
- `systemctl daemon-reload`
- `systemctl restart rustyjackd.socket rustyjackd.service`
- `systemctl is-active rustyjackd.service`
- `stat /run/rustyjack/rustyjackd.sock`
- Expected:
  - service active,
  - socket exists and type is socket,
  - group/perm compatible with `0660` and `rustyjack` group.

2. RPC reachability
- `python3 /Users/iwanteague/Desktop/watchdog/scripts/rj_rpc_client.py --socket /run/rustyjack/rustyjackd.sock --endpoint Health`
- Expected: valid JSON response, no `FileNotFoundError`.

3. Interface exclusivity enforcement
- Use UI: `Settings -> Network Interfaces`.
- Select target interface and confirm.
- After success, run:
  - `ip -br link`
  - `ip -4 route show default`
  - For non-selected Wi-Fi: `cat /sys/class/rfkill/rfkill*/soft /sys/class/rfkill/rfkill*/hard` (map rfkill index to iface)
- Expected:
  - exactly one selected uplink admin-UP,
  - non-selected uplinks DOWN,
  - non-selected Wi-Fi rfkill blocked,
  - exactly one default route via selected interface.

4. Blocking UI behavior
- Attempt to leave `Network Interfaces` while switch is running or after a failed switch.
- Expected:
  - cannot leave during running switch,
  - on failure, only Retry/Reboot (and Back only if all-down safe state).

5. Display wizard crash/skip behavior
- Start calibration, force restart/crash before finalization.
- Reopen UI.
- Expected:
  - wizard resumes (not marked complete prematurely).

6. Comprehensive harness invariant check
- `bash /Users/iwanteague/Desktop/watchdog/scripts/rustyjack_comprehensive_test.sh`
- Confirm `A6b_active_has_socket` passes when daemon is active.

## Environment Verification Limits

This host is macOS, and Linux-target checks requiring cross C toolchain are blocked (`x86_64-linux-gnu-gcc` missing). Linux-only crates (`rustyjack-core`, `rustyjack-ui`, `rustyjack-daemon`) cannot be fully compiled/executed here end-to-end. Validation done in this environment was limited to static inspection plus partial crate checking (`rustyjack-netlink` passes local `cargo check`).
