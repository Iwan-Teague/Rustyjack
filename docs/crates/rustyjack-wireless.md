# rustyjack-wireless

Native wireless operations (nl80211) for monitor/injection, attacks, hotspot support, and handshake handling. Requires Linux with nl80211; attacks need adapters that support monitor+injection.

## Responsibilities
- Manage wireless interfaces and monitor/VIF lifecycle.
- Inject/capture 802.11 frames for deauth, karma/evil twin, probe sniffing, PMKID, and handshake capture.
- Provide cracking helpers and handshake export/import for the UI/core pipelines.
- Hotspot glue around the Rust DHCP/DNS servers.
- Channel/TX power helpers and capability queries.

## Key modules
- `nl80211.rs`, `nl80211_queries.rs`, `wireless.rs`: low-level nl80211 handling (set mode/channel, tx power, list interfaces/PHY caps, create/delete VIFs).
- `interface.rs`: higher-level interface management.
- `frames.rs`, `radiotap.rs`: frame/radiotap parsing/building.
- `inject.rs`: raw injection support.
- Attack modules: `deauth.rs`, `karma.rs`, `evil_twin.rs`, `probe.rs` (probe sniff), `pmkid.rs`, `recon.rs`, `stealth.rs`.
- Capture/cracking: `handshake.rs` (capture/export), `capture.rs`, `crack.rs`.
- `hotspot.rs`: Rust AP startup + DHCP/DNS integration via `rustyjack-netlink`, interface cleanup, rfkill handling.

## Dependencies/expectations
- Linux + nl80211; some fallbacks to external tools (`airmon-ng`) when netlink operations fail.
- Uses `rustyjack-netlink` for DHCP/DNS servers and some capability checks.

## Notes for contributors
- Keep attack flows cancellable with clear progress/errors (include BSSID/iface/channel context).
- Preserve interface/channel state when creating/deleting monitor interfaces; restore where appropriate.
- Avoid hardcoded interface names; honor selections from UI/core and capability checks.

## File-by-file breakdown
- `lib.rs`: crate surface exporting modules; re-exports key types for consumers.
- `nl80211.rs`: low-level nl80211 interactions (set interface type, create/delete interfaces, set frequency/channel, query info, set tx power); wraps `rustyjack-netlink` and handles errors/context.
- `nl80211_queries.rs`: helper queries for PHY/IF capabilities, channel lists, and interface info via nl80211.
- `interface.rs`: higher-level interface management (set managed/monitor/AP, create monitor, up/down, channel helpers).
- `netlink_helpers.rs`: wrappers around `rustyjack-netlink` wireless/iface ops to keep async/sync boundaries clean.
- `radiotap.rs`: radiotap header parsing/building for capture/injection.
- `frames.rs`: 802.11 frame crafting/parsing utilities used by deauth/karma/evil twin/etc.
- `inject.rs`: raw frame injection routines with rate limiting/burst control.
- `capture.rs`: capture helpers for raw sockets/monitor interfaces; includes filtering and channel handling.
- `handshake.rs`: handshake detection/export logic (EAPOL parsing, export to JSON/bundles) and capture file handling.
- `pmkid.rs`: PMKID capture logic (targeted and passive), channel handling, and result structs.
- `probe.rs`: probe sniffing, channel hopping, aggregation of probes/clients/SSIDs.
- `deauth.rs`: deauthentication attack engine (bursting, optional client targeting, handshake capture integration, stats collection).
- `karma.rs`: probe-response/karma logic with optional fake AP responses; manages interface state and capture.
- `evil_twin.rs`: open AP impersonation (Evil Twin), client tracking, capture/export of handshakes/credentials.
- `recon.rs`: passive/active recon helpers (bandwidth measurements, gateway discovery, mDNS scans, DNS capture).
- `hotspot.rs`: Rust-native AP startup/teardown, DHCP/DNS integration, rfkill handling, interface cleanup, NAT teardown; uses `rustyjack-netlink` servers.
- `crack.rs`: cracking orchestration (uses handshake exports and wordlists), progress reporting.
- `inject.rs`: frame injection (noted above) reused by attacks; ensures radiotap + frame formatting.
- `rfkill_helpers.rs`: rfkill unblock/list wrappers used by hotspot/attack prep.
- `process_helpers.rs`: process killing helpers (pkill patterns) for interfering services (wpa_supplicant/NetworkManager).
- `error.rs`: crate error types used across modules.
