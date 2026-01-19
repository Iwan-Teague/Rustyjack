# Evil Twin
Created: 2026-01-07

Open AP impersonation of a target network to lure clients. Implemented in `rustyjack-wireless::evil_twin`; orchestrated by `rustyjack-core`/UI.

## Flow
1. User selects target (BSSID/SSID/channel); core enforces isolation and sets channel.
2. Evil Twin module brings up an open AP with the target SSID (on a monitor-capable adapter), optionally uses same channel/BSSID.
3. Captures client associations, handshakes, and credentials if a portal is used; logs connected clients.
4. Loot (PCAP/JSON) stored under `loot/Wireless/<target>/`; UI displays live stats.

## Dependencies
- `rustyjack-wireless` for AP beaconing/injection/capture; `rustyjack-netlink` for interface control.
- Can pair with DNS spoof/captive portal (via core) for credential harvesting.
- Root/CAP_NET_ADMIN/RAW; external adapter recommended.

## Notes
- Built-in Pi radio cannot reliably host Evil Twin; use USB AP-capable adapter.
- Often combined with Karma and DNS spoof for credential capture pipelines.
