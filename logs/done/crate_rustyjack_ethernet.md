# rustyjack-ethernet
Created: 2026-01-07

LAN discovery and TCP reconnaissance utilities for wired interfaces. Uses raw sockets for ARP and standard sockets for TCP banners.

## Responsibilities
- ICMP/ARP sweeps with basic OS TTL hints.
- TCP connect scans with banner grabbing on common ports.
- Service/device inventory via multicast probes (mDNS/LLMNR/NetBIOS/WSD).
- Loot/result structuring for the UI/core pipelines.

## Main components
- ICMP sweep using raw IPv4 sockets with nonblocking IO and inflight tracking.
- ARP sweep using packet sockets bound to the interface MAC/IP; rate-limited sends, ARP reply parsing.
- TCP port scan with configurable timeouts and banner reads.
- Device inventory data structures (`DiscoveredHost`, `DeviceInfo`, `PortScanResult`, `PortBanner`, etc.).

## Dependencies/expectations
- Linux sockets (raw/packet) for ARP/ICMP; root/CAP_NET_RAW required.
- Integrates with `rustyjack-core` for loot/reporting paths and pipeline orchestration.

## Notes for contributors
- Keep rate limits and timeouts configurable; avoid blocking callers.
- Validate interface/MAC inputs; surface errors with interface context.
- Preserve loot path conventions (`loot/Ethernet/<target>/`).

## File-by-file breakdown
- `lib.rs` (single-module crate):
  - Data structures: `DiscoveryMethod`, `DiscoveredHost`, `LanDiscoveryResult`, `PortScanResult`, `PortBanner`, `ServiceInfo`, `DeviceInfo`.
  - OS fingerprint helpers: `guess_os_from_ttl` and port-based hints.
  - ICMP discovery (`discover_hosts`, `discover_cidr`): raw IPv4 socket echo sweep with inflight tracking, TTL capture, permission-aware error handling.
  - TCP port scan (`quick_port_scan`): connect-based scan with configurable timeout and simple HTTP HEAD banner grab fallback; returns open ports + banners.
  - ARP discovery (`discover_hosts_arp`): Linux-only AF_PACKET raw socket ARP sweep with rate limiting, per-host ARP requests, reply parsing, and details collection; uses netlink to read local IPs, manual MAC parsing from sysfs; non-Linux stub bails.
  - Banner helper: `grab_banner` for basic banner extraction on web ports.
  - Service discovery:
    - Multicast DNS/LLMNR/NetBIOS/WS-Discovery queries (`query_mdns`, `query_llmnr`, `query_netbios`, `query_ws_discovery`) built on UDP sockets with handcrafted DNS/NetBIOS encoding/decoding (`build_dns_query`, `parse_dns_records`, `decode_dns_name`, `encode_netbios_name`, `parse_netbios_names`).
    - Utility to send/receive multicast/broadcast queries with timeouts and aggregate responses by source IP.
  - `build_device_inventory`: combines discovery results, port scans, TTL/port-based OS hints, multicast service names, and banners into `DeviceInfo` entries.
  - Helpers for loot consumers: structures and functions are directly used by `rustyjack-core` pipelines for Ethernet recon, MITM prep, and inventory/report generation.
