# MITM & DNS Spoof

Middle-in-the-man flows for Ethernet targets with optional captive portals. Orchestrated by `rustyjack-core` using netfilter/tcpdump and DNS spoof helpers.

## Flow
1. Core enforces interface isolation and sets active Ethernet iface.
2. ARP poison victims (pair or subset); enable NAT/forwarding via `rustyjack-netlink::iptables`.
3. Start tcpdump capture and optional ettercap DNS rewrite or Rust DNS spoof add-on.
4. Optional PHP captive portal served from `DNSSpoof/sites/<site>`; visits/credentials logged.
5. Stop tears down ARP spoof, DNS spoof, tcpdump, and NAT rules.

## Dependencies
- ARP spoof helpers (core/system) and `rustyjack-netlink` iptables/NAT.
- External tools: `tcpdump`, `ettercap-text-only`, PHP server for sites.
- Loot paths under `loot/Ethernet/<label>/` with PCAP, visit/credential logs, DNS spoof logs.

## Notes
- Victim selection capped by pipeline args (`max_hosts` for “human” classification).
- DNS spoof templates live in `DNSSpoof/sites/`; adjust or add new portals as needed.
- Requires root; runs on Ethernet interfaces with carrier.
