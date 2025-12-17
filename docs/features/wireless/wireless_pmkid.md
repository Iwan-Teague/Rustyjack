# Wireless PMKID Capture

Captures PMKIDs from RSN-enabled APs without client interaction. Uses `rustyjack-wireless::pmkid` for active/passive capture and `rustyjack-core` for orchestration.

## Flow
1. UI/CLI sets target (BSSID/SSID/channel) or runs passive harvest.
2. Core enforces interface isolation and sets channel.
3. `rustyjack-wireless::pmkid` listens/sends required frames to elicit PMKID; collects results.
4. Exports PMKID data to loot; returns JSON summary to UI/CLI.

## Dependencies
- nl80211 monitor mode and raw 802.11 frame parsing via `rustyjack-wireless`.
- Channel control via `rustyjack-netlink` helpers.
- External fallbacks minimal; root privileges required.

## Loot/outputs
- PMKID captures and logs under `loot/Wireless/<target>/`.
- Optional bundle for cracking in pipelines.

## Notes
- Works without client deauth; good for stealth pipelines.
- Built-in Pi radio lacks monitor; use external adapter.
