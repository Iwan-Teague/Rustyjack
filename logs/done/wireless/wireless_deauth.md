# Wireless Deauth
Created: 2026-01-07

Deauthentication attack to force clients off an AP, optionally capturing handshakes. Uses `rustyjack-wireless` injection and capture utilities; orchestrated by `rustyjack-core` and triggered from the UI.

## Flow
1. UI selects target (BSSID/SSID/channel) via Scan Networks.
2. `rustyjack-core` validates active interface and enforces isolation.
3. `rustyjack-wireless::deauth` starts burst-based injection on a monitor-capable interface (external adapter required).
4. Optional handshake capture runs alongside (captures EAPOL frames, exports bundle to loot).
5. Results reported to UI/CLI, loot stored under `loot/Wireless/<target>/`.

## Dependencies
- nl80211 monitor/injection via `rustyjack-wireless` (`nl80211` + raw sockets).
- `rustyjack-netlink` for interface control and rfkill helpers.
- Root/CAP_NET_ADMIN/RAW required.

## Loot/outputs
- PCAP/logs and optional handshake export in `loot/Wireless/<target>/`.
- JSON result includes packets sent, bursts, duration, EAPOL count, capture file paths.

## Notes
- Built-in Pi Zero 2 W radio cannot inject; use a compatible USB adapter.
- Error handling surfaces iface/BSSID/channel context; attack is cancellable.
