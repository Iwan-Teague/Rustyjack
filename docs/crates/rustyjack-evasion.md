# rustyjack-evasion

Evasion utilities: MAC randomization, TX power control, passive/monitor helpers, and state tracking/restoration.

## Responsibilities
- Vendor-aware MAC generation (locally administered, unicast) using CSPRNG; can preserve OUI from the current iface.
- Save/restore original MAC; optional auto-restore on drop.
- TX power management via netlink (`rustyjack-netlink`).
- Passive/monitor mode helpers and state tracking.

## Modules
- `mac`: `MacManager` for randomize/set/restore with state map and auto-restore; validates interface names and permissions.
- `txpower`: TX power reads/writes; stores previous levels for restore.
- `passive`: monitor-mode enable/disable with TX power adjustments and fallbacks (`airmon-ng`) when netlink fails; channel setting.
- `state`: combined state manager for interfaces (MAC, monitor IFs, txpower) with restore.
- `vendor`: OUI/vendor table; vendor-aware generation.
- `config`, `error`: toggles and error types.

## Dependencies/expectations
- Linux netlink for most operations; guarded fallbacks for host builds. Some paths still shell out (`airmon-ng`) if netlink is unavailable.
- Designed to compile on non-Linux with Linux-only sections behind `cfg(target_os = "linux")`.

## Notes for contributors
- Keep Linux guards intact for host development.
- Ensure locally administered bit stays set and multicast bit cleared on generated MACs.
- Preserve and restore interface state when modifying MAC/monitor/txpower; surface permission errors clearly.

## File-by-file breakdown
- `lib.rs`: crate surface; re-exports modules and key types (e.g., `MacManager`, `TxPowerLevel`, `StateManager`), and provides convenience constructors.
- `config.rs`: toggles/configuration structs for evasion behavior (auto-restore, rotation intervals).
- `error.rs`: error enum used across MAC/txpower/passive/state operations.
- `mac.rs`: `MacManager` with state map, auto-restore option, validation of interface names, vendor-aware/random MAC generation, set/restore functions. Uses netlink (Linux) to bring interfaces down/up and set MAC; guarded fallbacks on non-Linux return errors. Ensures locally administered/unicast bits.
- `txpower.rs`: TX power read/set helpers; maps between dBm/mbm and stores original levels for restore. Uses `rustyjack-netlink::WirelessManager`; Linux-gated.
- `passive.rs`: monitor-mode enable/disable with TX power adjustments, channel setting, and `airmon-ng` fallback when netlink fails. Tracks active monitor interfaces to clean up; guarded on non-Linux with explicit errors.
- `state.rs`: `StateManager` for combined interface state (MAC, monitor IFs, tx power). Includes monitor deletion (`rustyjack-netlink` or `airmon-ng` fallback), MAC restore via netlink, tx power restore, auto-restore on drop when enabled; Linux-gated implementations with non-Linux bailouts.
- `vendor.rs`: vendor/OUI table and helpers for vendor-aware MAC generation.
