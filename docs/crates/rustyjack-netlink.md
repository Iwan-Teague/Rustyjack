# rustyjack-netlink

Pure-Rust networking stack replacing common external binaries on Linux. Provides netlink/D-Bus/raw-socket wrappers for the rest of the project.

## Responsibilities
- Link/route: `InterfaceManager`, `RouteManager` (up/down, MAC, MTU, addresses, routes) replacing `ip`.
- Wireless/nl80211: `WirelessManager` (mode, channel, tx power, iface creation/deletion, capability queries) replacing `iw`.
- WPA control: `wpa.rs` (control socket client) replacing `wpa_cli` subprocess usage.
- AP: hostapd-equivalent logic in Rust for starting/stopping APs.
- DHCP: `dhcp.rs` (client) replacing `dhclient`; `dhcp_server.rs` replacing `dnsmasq` DHCP.
- DNS: `dns_server.rs` replacing `dnsmasq` DNS (wildcard spoof, exact match, passthrough).
- iptables/netfilter: `iptables.rs` for NAT/forwarding rules.
- NetworkManager D-Bus: `networkmanager.rs` replacing `nmcli` calls.
- rfkill/process helpers; ARP operations; USB detection helpers.

## Modules
- `interface`, `route`, `wireless`, `wpa`, `hostapd`, `rfkill`, `process`.
- Services: `dhcp`, `dhcp_server`, `dns_server`.
- Management: `iptables`, `networkmanager`.
- Utilities: `arp`, `error`.

## Expectations
- Linux-only; relies on netlink, D-Bus, raw sockets; many APIs will `cfg` out on non-Linux.
- Consumed by `rustyjack-core`, `rustyjack-wireless`, `rustyjack-evasion`, `rustyjack-ui`.

## Notes for contributors
- Keep errors context-rich (iface, command, rule) and avoid panics.
- Maintain Linux guards to keep host builds compiling.
- When adding new binary replacements or capabilities, update installers and docs accordingly.

## File-by-file breakdown
- `lib.rs`: crate surface exposing modules and re-exports for consumers (`InterfaceManager`, `WirelessManager`, DHCP/DNS types, etc.); Linux guards applied where appropriate.
- `error.rs`: error enum/types used across modules to provide context-rich failures.
- `interface.rs`: link-layer manager (up/down, MAC set, MTU, add/del addresses, list interfaces, query info). Replaces `ip link/addr` for common operations.
- `route.rs`: route manager for adding/deleting default routes and static routes; replaces `ip route`.
- `wireless.rs`: nl80211 helper functions for wireless interface operations (set type/mode, create/delete VIFs, get interface/phy capabilities, set channel/txpower); core building block for `WirelessManager`.
- `wpa.rs`: control-socket client for `wpa_supplicant` (status, reconnect, disconnect, scan, connect config management) replacing `wpa_cli` subprocesses.
- `hostapd.rs`: Rust AP/hostapd-like logic to start/stop AP mode and manage basic AP config.
- `dhcp.rs`: DHCP client implementation (DISCOVER/OFFER/REQUEST/ACK flow, interface config, DNS writes). Used to replace `dhclient`.
- `dhcp_server.rs`: DHCP server implementation (offer/ack handling, lease tracking, running flag, background serve loop). Replaces dnsmasq DHCP.
- `dns_server.rs`: DNS server implementation with wildcard/exact-match/passthrough, spoofing, and upstream handling. Replaces dnsmasq DNS.
- `iptables.rs`: iptables rule management (NAT/forwarding chains, rule insert/remove); requires root and iptables binary availability.
- `networkmanager.rs`: D-Bus client for NetworkManager (device managed/unmanaged, connect/disconnect/reconnect Wi‑Fi, status queries) replacing `nmcli` subprocess calls.
- `rfkill.rs`: rfkill state/query/block/unblock helpers via sysfs; replaces `rfkill` binary.
- `process.rs`: process listing/pgrep/pkill equivalents and helper utilities.
- `arp.rs`: generic ARP utilities/helpers.
- `arp_scanner.rs`: ARP scan implementation for subnet scans and MAC lookups.
- `arp_spoofer.rs`: ARP spoofing helpers for MITM scenarios.
- `dns_server.rs`: DNS server (detailed above) used by hotspot/captive portal; (note file already listed but kept here for completeness).
- `iptables.rs`: (as above).
