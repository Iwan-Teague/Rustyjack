# Karma Attack
Created: 2026-01-07

Responds to probe requests to impersonate open networks. Implemented in `rustyjack-wireless::karma`; orchestrated by `rustyjack-core`/UI.

## Flow
1. UI sets target/iface; core enforces isolation and creates monitor/AP context.
2. Karma module listens for probes, responds with appropriate frames, optionally runs a lightweight AP for association.
3. Tracks clients, captures frames, and can pair with probe sniffing data.
4. Results/logs returned to UI; loot stored under `loot/Wireless/<target>/`.

## Dependencies
- Monitor/injection via `rustyjack-wireless` (nl80211 + raw frames).
- Interface control via `rustyjack-netlink`.
- Root/CAP_NET_ADMIN/RAW required; external adapter recommended.

## Notes
- Often combined with Evil Twin or probe sniffing; passive/stealth friendly if run without aggressive AP behavior.
