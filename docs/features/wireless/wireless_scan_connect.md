# Wireless Scan & Connect

Network discovery and client connectivity. Uses `rustyjack-core` + `rustyjack-netlink` for scanning/association; profiles stored as JSON.

## Flow
1. Hardware Detect sets active interface; UI runs Scan Networks (nl80211 scan) and displays SSID/BSSID/channel/signal.
2. User sets target (SSID/BSSID/channel) for attacks; or selects a saved profile to connect.
3. Profiles (`wifi/profiles/*.json`) are read/written by core; connect uses `rustyjack-netlink`/NetworkManager/WPA control to associate.
4. Interface preference is stored; isolation enforced for Wi‑Fi operations; default route set as needed.

## Dependencies
- `rustyjack-netlink` for scans and connect operations; NetworkManager D-Bus/WPA control.
- Profiles are plaintext JSON; encryption optional via `rustyjack-encryption`.
- Root required; uses rfkill helpers and route management from core/system.

## Notes
- Built-in Pi radio supports managed/AP (limited) but not monitor/injection; attacks need external adapter.
- Targets saved for downstream attacks (deauth/Evil Twin/PMKID).
