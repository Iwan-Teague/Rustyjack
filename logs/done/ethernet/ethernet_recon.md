# Ethernet Recon
Created: 2026-01-07

LAN discovery, port scanning, inventory, and credential capture pipelines for wired interfaces. Orchestrated by `rustyjack-core` using `rustyjack-ethernet`.

## Features
- **Discover Hosts**: ICMP sweep with TTL OS hints; optional ARP sweep (Linux-only) for hosts blocking ICMP.
- **Port Scan**: TCP connect scan on target/gateway with configurable ports/timeouts; banner grabs.
- **Inventory**: Combines discovery, port scan, and multicast probes (mDNS/LLMNR/NetBIOS/WSD) to build `DeviceInfo`.
- **Site Credential Capture pipeline**: Classifies “human” hosts, ARP poisons up to a cap, starts DNS spoof captive portal, captures PCAP/visit/credential logs.

## Dependencies
- `rustyjack-ethernet` for ICMP/ARP discovery, port scan, multicast probes.
- `rustyjack-netlink` for interface control/NAT when needed; Rust PCAP capture/portal server used in pipelines.
- Root/CAP_NET_RAW required for ICMP/ARP.

## Loot/outputs
- Loot under `loot/Ethernet/<target>/` (discover/scan/inventory PCAP/logs, pipeline outputs).
- Reports aggregate Ethernet findings; Discord/USB export available via UI/core.

## Notes
- Interface isolation/enforcement is performed before active ops.
- Credential capture pipeline uses ARP spoof + DNS spoof site templates under `DNSSpoof/sites/`.
