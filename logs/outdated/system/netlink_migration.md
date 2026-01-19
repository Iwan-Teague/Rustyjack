# Pure-Rust Networking Migration
Created: 2026-01-07

Supersedes multiple status/implementation docs:
- `BINARY_DEPENDENCIES_STATUS.md`
- `BINARY_DEPENDENCIES_REFACTORING.md`
- `NETLINK_REFACTOR_STATUS.md`
- `NETWORKMANAGER_IMPLEMENTATION.md`
- `NETWORKMANAGER_RFKILL_FIX.md` (behavior also captured in `hotspot.md`)
- `AP_MODE_DETECTION.md`
- `HOSTAPD_IMPLEMENTATION_COMPLETE.md`
- `IW_IMPLEMENTATION_COMPLETE.md`
- `DHCP_CLIENT_IMPLEMENTATION.md`
- `DHCP_SERVER_IMPLEMENTATION.md`
- `DNS_SERVER_IMPLEMENTATION.md`
- `DNS_SERVER_COMPLETE.md`
- `IPTABLES_IMPLEMENTATION.md`
- `MAC_FIX_SUMMARY.md`
- `AUTOPILOT_REMOVAL.md`
- `PIPELINE_INDEFINITE_MODE_FIX.md`
- `HARDWARE_DETECTION_FEATURE.md`
- `ARP_IMPLEMENTATION_COMPLETE.md`
- `USB_DETECTION_FIX.md`
- `WPA_IMPLEMENTATION_COMPLETE.md`
- `RUSTYJACK_NETLINK_REFERENCE.md` (API reference preserved in code)

## Replaced external tools with `rustyjack-netlink`
- Link/route management → `InterfaceManager` / `RouteManager` (link state, MAC, MTU, addresses, routes via netlink).
- Wireless/nl80211 → `WirelessManager` (AP capability checks, channel/txpower, iface creation).
- WPA control → `wpa.rs` (replaces `wpa_cli` control socket usage).
- Hostapd/AP → `hostapd.rs` equivalent logic in Rust.
- DHCP client/server → `dhcp.rs` / `dhcp_server.rs` (replaces `dhclient`/`dnsmasq` DHCP).
- DNS server → `dns_server.rs` (replaces `dnsmasq` DNS).
- iptables/netfilter → `iptables.rs`.
- NetworkManager D-Bus → `networkmanager.rs` (replaces `nmcli` subprocesses).
- rfkill/process helpers → `rfkill.rs`, `process.rs`.
- ARP operations → `arp.rs` + scanners/spoofer.
- USB detection, hardware detection, autopilot removal, pipeline fixes consolidated into current codebase.

## Status
- All major networking paths are pure Rust; external binaries still required for drivers/firmware and some optional tools in specialized pipelines.
- Linux-only: netlink/D-Bus paths gate on `target_os = "linux"`.
- Hotspot uses Rust DHCP/DNS + AP; NetworkManager/rfkill handling documented in `hotspot.md`.

## Notes for contributors
- When adding new binary calls, update installers and prefer Rust wrappers in `rustyjack-netlink` where possible.
- Keep Linux guards around netlink/D-Bus usage to allow host builds on macOS/Windows.
- API details live in code; see module docs in `rustyjack-netlink/src`.
