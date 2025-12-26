# Pipelines

Prebuilt sequences that chain wireless/ethernet actions. Orchestrated by `rustyjack-core::operations`, surfaced in the UI and autopilot.

## General behavior
- Enforces interface isolation, sets targets/channels, and uses timeouts/cancellation guards.
- Stores pipeline loot under `loot/Wireless/<target>/pipelines/<timestamp>/` for artifacts created after start.
- Blocks active pipelines in Stealth mode except Stealth Recon.

## Wireless pipelines (examples)
- **Get WiFi Password**: Scan → targeted PMKID → deauth/handshake capture → quick crack.
- **Mass Capture**: Dual scans with hopping → PMKID harvest → probe sniff (clients/SSIDs).
- **Stealth Recon**: MAC/hostname randomize + 1 dBm TX + passive sniff (no TX).
- **Credential Harvest**: Probe sniff → Karma → Evil Twin + DNS spoof portal wait.
- **Full Pentest**: MAC randomize + passive recon → scan → PMKID harvest → deauth → Karma → quick crack.

## Ethernet pipelines
- **Site Credential Capture**: Discover “human” devices → ARP poison subset → DNS spoof portal → capture PCAP/visit/credentials; loot under `loot/Ethernet/<target>/`.

## Dependencies
- Wireless: `rustyjack-wireless` (nl80211, injection, capture), `rustyjack-netlink` (iface control, DHCP/DNS), `rustyjack-core` orchestration, optional `rustyjack-encryption` for loot, external adapters for monitor/injection.
- Ethernet: `rustyjack-ethernet` for discovery/port scan/inventory, tcpdump/arp spoof/DNS spoof via core, iptables/NAT via `rustyjack-netlink`.
- External fallbacks: `airmon-ng`, `tcpdump`, `ettercap`, PHP server, depending on pipeline steps.

## Notes
- Each step returns explicit outcomes; timeouts prevent “empty success” behavior.
- Progress is surfaced in UI; pipelines are cancellable when possible.
