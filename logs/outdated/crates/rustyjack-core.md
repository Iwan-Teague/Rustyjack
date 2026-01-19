# rustyjack-core
Created: 2026-01-07

Coordinator crate for system operations, pipelines, CLI/autopilot commands, and glue between the UI and the lower-level crates. Linux-only (netlink, D-Bus, raw sockets) and expected to run as root on the Pi target.

## Responsibilities
- Command/IPC layer consumed by the LCD UI and autopilot/CLI.
- Wi‑Fi and Ethernet pipelines: scans, PMKID/handshake capture, deauth, evil twin, probe sniff, cracking, MITM, loot/report generation, Discord upload, USB export.
- Hotspot orchestration (AP + DHCP/DNS) via `rustyjack-netlink` helpers.
- System prep and hygiene: interface isolation/enforcement, rfkill control, process killing, MAC/hostname randomization glue, NetworkManager coordination.
- Anti-forensics: purge logs/loot, uninstall helpers.

## Modules
- `cli`: command enums/structs for UI/autopilot IPC.
- `operations`: all pipelines and discrete actions (Wi‑Fi attacks, Ethernet recon, MITM, cracking, reports). Handles orchestration, timeouts, loot paths, and status/results.
- `system`: interface isolation/enforcement, rfkill helpers, DHCP/DNS start/stop, NetworkManager integration, route/default gateway helpers.
- `netlink_helpers`: thin adapters over `rustyjack-netlink` for common patterns (set link up/down, MAC changes, etc.).
- `dhcp_helpers`, `dns_helpers`: convenience wrappers to launch/tear down the Rust servers for hotspot/captive portal flows.
- `evasion`: bridges to `rustyjack-evasion` for MAC/hostname randomization and TX power settings.
- `wireless_native`: shims to native wireless operations.
- `arp_helpers`: ARP-specific utilities used by Ethernet recon/MITM.
- `anti_forensics`: purge/cleanup routines; service removal.
- `physical_access`: USB detection/mounting and loot export.

## Expectations
- Root privileges and Linux kernel facilities (netlink, D-Bus, raw sockets).
- Depends on `rustyjack-netlink`, `rustyjack-wireless`, `rustyjack-ethernet`, `rustyjack-evasion`, `rustyjack-encryption`.
- Some features still shell out to external tools; mirror new binary deps in installers if added.

## Contributor notes
- Keep errors context-rich (interface/BSSID/command) and avoid panics.
- Guard Linux-only code with `#[cfg(target_os = "linux")]` to keep host builds compiling.
- Pipelines should remain cancellable and time-bounded; avoid blocking the UI thread.
- When adding new system requirements, update installers and service setup accordingly.

## File-by-file breakdown
- `lib.rs`: crate surface; exports modules, re-exports `dispatch_command`/`HandlerResult`, evasion log toggles, and crypto facade.
- `main.rs`: CLI entrypoint (clap) that parses commands and routes to `operations::dispatch_command`; handles output formatting.
- `cli.rs`: full command model (Scan, Notify/Discord, Wifi, Mitm, DnsSpoof, Loot, Process, Status, Reverse, System, Bridge, Hardware, Ethernet, Hotspot) with all `Args` structs/enums used by UI/autopilot IPC and the CLI.
- `operations.rs`: command dispatcher and orchestration layer. Implements handlers for Wi‑Fi (scan/status/best/switch/profile connect/save/delete/list, route ensure/metric, deauth, evil twin, PMKID, probe sniff, cracking, karma, recon), Ethernet (discovery, port scan with banners, inventory, site cred capture pipeline), MITM/DNS spoof start-stop, hotspot start-stop-status, loot list/read, Discord uploads/reports, USB export, system update/hostname/FDE prep, hardware detect, bridge start/stop. Manages loot paths, status composition, interface enforcement, Discord webhook posting, timeouts, and JSON results.
- `system.rs`: core system helpers: interface summaries/stats, isolation/enforcement, rfkill block/unblock, route/default gateway handling, interface preference storage, Wi‑Fi profile read/write/connect/disconnect, NetworkManager coordination, DNS rewrites, ping/process helpers, MAC usage logging, routing state backup/restore, git backup/reset, portal/PCAP capture launchers, bridge/NAT setup, interface metrics. Defines structs for Wi‑Fi networks/profiles/link info. Notes plaintext Wi‑Fi password storage and root requirements.
- `netlink_helpers.rs`: synchronous wrappers over `rustyjack-netlink` async APIs (interface up/down/flush/MAC, list interfaces/routes, rfkill/process, NetworkManager). Uses tokio runtime or spins one if absent; Linux-gated.
- `dhcp_helpers.rs`: create/start/stop/fetch leases for Rust DHCP server (`DhcpServer`); Linux-gated with non-Linux bailouts.
- `dns_helpers.rs`: create/start/stop DNS server (`DnsServer`) helpers; Linux-gated.
- `arp_helpers.rs`: thin ARP scan/get_mac/is_alive/spoof wrappers using `rustyjack-netlink::ArpScanner/ArpSpoofer`; bail on non-Linux.
- `evasion.rs`: utility/legacy evasion helpers (MAC randomization/set, TTL/fragmentation/timing toggles, fingerprint spoofing). Uses netlink helpers for MAC changes and interface flaps.
- `wireless_native.rs`: bridges to native `rustyjack-wireless` attacks; provides result structs and wrappers for deauth, PMKID, probe sniff, karma, evil twin, passive capture, capture bundling; guarded by `target_os = "linux"`.
- `anti_forensics.rs`: secure delete (shred/manual), recursive directory wipes, purge logs/loot, anti-forensics config (`AntiForensicsConfig`), options for ram-only mode, swap/LED disable, hostname randomization.
- `physical_access.rs`: wired “physical access” attack flow to extract Wi‑Fi creds from routers: gateway discovery, router fingerprint, DHCP/mDNS/UPnP leaks, web UI default creds, WPS/config backup attempts, known vuln checks; produces `PhysicalAccessReport` and saves it.
