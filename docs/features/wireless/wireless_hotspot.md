# Rust Hotspot

Rust-native hotspot using `rustyjack-wireless` + `rustyjack-netlink` (AP + DHCP/DNS). Replaces hostapd/dnsmasq with in-crate servers.

## Current state (from hotspot fixes)
- Reliable start/stop/restart on supported AP interfaces (typically USB Wi‑Fi; built‑in CYW43436 is client-only).
- DHCP/DNS run natively in Rust; NetworkManager is kept from rewriting DNS.
- Device history logged to `loot/Hotspot/device_history.txt`; “Connected Devices” shows active clients only.
- RF‑kill aggressively unblocked before start; AP iface left unmanaged to avoid NM re-blocking.
- wpa_supplicant stopped on AP iface before start to avoid conflicts.

## Flow
1. User selects AP and upstream interfaces in the UI; core verifies capability and upstream IPv4.
2. `rustyjack-wireless::hotspot` starts AP (Rust hostapd logic), then Rust DHCP server, then Rust DNS server.
3. NetworkManager is set to unmanaged on AP iface; rfkill unblocked; upstream NAT rules applied via `rustyjack-netlink::iptables`.
4. Hotspot state persisted; stop cleans up servers, NAT, and leaves interface unmanaged to avoid rfkill re-block.

## Dependencies
- `rustyjack-netlink`: DHCP/DNS servers, iptables, iface control, NetworkManager D-Bus.
- `rustyjack-wireless`: AP start/stop and interface checks.
- Root/CAP_NET_ADMIN/RAW; external AP-capable adapter recommended (built-in CYW43436 client-only).

## Loot/outputs
- Device history logged to `loot/Hotspot/device_history.txt` when DHCP leases are issued.
- Hotspot status available via UI/CLI (SSID/password, running flags).

## Notes
- Relies on Rust DHCP/DNS; no `dnsmasq` hostapd binaries.
- RF-kill and NetworkManager interactions documented in `docs/hotspot.md`.
