# Wireless Probe Sniff
Created: 2026-01-07

Passive probe request capture with channel hopping. Uses `rustyjack-wireless::probe` and is orchestrated by `rustyjack-core`/UI.

## Flow
1. User selects duration (30/60/300s) and launches probe sniff.
2. Core enforces isolation; wireless module hops channels and collects probe frames.
3. Aggregates total probes, unique clients, unique SSIDs; optional top SSIDs.
4. Returns summary to UI; loot/logs stored under `loot/Wireless/<target>/` or a timestamped folder.

## Dependencies
- Monitor mode + capture via `rustyjack-wireless` (radiotap parsing, channel hopping).
- `rustyjack-netlink` for interface/channel control.
- Root privileges required.

## Notes
- Passive-only (no TX); compatible with Stealth/Passive modes.
- Useful precursor for Karma/Evil Twin target selection.
