# Autopilot Feature Removal
Created: 2026-01-07

> Note: Archived doc. Current builds no longer use external tcpdump, ettercap, ncat, arp-scan, or arpspoof/dsniff; references below are historical.


## Summary
Removed the deprecated autopilot feature from Rustyjack. This was an older automated attack orchestration system that relied on third-party tools (nmap, arpspoof, tcpdump, ettercap, php) which we no longer need given our in-house Rust implementations.

## Files Removed
- `rustyjack-core/src/autopilot.rs` - Complete autopilot engine implementation

## Files Modified

### rustyjack-core
- `src/lib.rs` - Removed `pub mod autopilot;`
- `src/cli.rs` - Removed:
  - `AutopilotCommand` enum
  - `AutopilotStartArgs` struct
  - `AutopilotMode` enum
  - `Commands::Autopilot` variant
- `src/operations.rs` - Removed:
  - Import of `AutopilotCommand`, `AutopilotStartArgs`
  - `handle_autopilot_start()` function
  - `handle_autopilot_stop()` function
  - `handle_autopilot_status()` function
  - `Commands::Autopilot` match arm
  - Global `AUTOPILOT` static and `get_autopilot()` helper

### rustyjack-ui
- `src/app.rs` - Removed:
  - Import of `AutopilotCommand`, `AutopilotMode`, `AutopilotStartArgs`
  - `MenuAction::AutopilotStart` match arm
  - `MenuAction::AutopilotStop` match arm
  - `MenuAction::AutopilotStatus` match arm
  - `autopilot_mode_label()` helper function
  - `start_autopilot()` method
  - `stop_autopilot()` method
  - `show_autopilot_status()` method

- `src/menu.rs` - Removed:
  - `MenuAction::AutopilotStart` enum variant
  - `MenuAction::AutopilotStop` enum variant
  - `MenuAction::AutopilotStatus` enum variant
  - `autopilot_menu()` function
  - "Autopilot" submenu entry from ethernet menu
  - "apt" menu node registration
  - "apt" => "Autopilot" title mapping

- `src/display.rs` - Removed:
  - `StatusOverlay.autopilot_running` field
  - `StatusOverlay.autopilot_mode` field
  - Autopilot indicator rendering in toolbar
  - Autopilot status in `draw_toolbar()`

- `src/stats.rs` - Removed:
  - Autopilot status polling logic
  - Setting of `autopilot_running` and `autopilot_mode` fields

## Rationale
The autopilot feature was built for an earlier version of Rustyjack that depended on external tools like nmap, arpspoof, ettercap, and PHP. With our comprehensive in-house Rust implementations via:
- `rustyjack-netlink` (replaces ip, iw, nmcli, rfkill, hostapd, iptables, pgrep/pkill)
- `rustyjack-ethernet` (native ARP, DHCP client/server, DNS server)
- `rustyjack-wireless` (native 802.11 operations)

...we no longer need orchestration wrapper around third-party binaries. Users can compose attacks using the existing menu system and pipeline features, which are cleaner, more maintainable, and don't require external dependencies.

## No Breaking Changes
This removal does not affect:
- Attack pipelines (PipelineType) which remain intact
- Individual attack features (MITM, DNS spoof, etc.)
- Ethernet reconnaissance and offensive capabilities
- Wireless attack workflows

All functionality previously offered by autopilot can be manually triggered or composed via attack pipelines.
