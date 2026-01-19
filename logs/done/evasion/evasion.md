# Evasion & Identity Controls
Created: 2026-01-07

MAC/hostname randomization, TX power, passive mode, and interface state management to reduce fingerprints.

## Features
- **MAC randomize**: vendor-aware, locally administered, unicast MACs; can preserve current OUI. Auto-restore option.
- **Hostname randomize**: `rustyjack-core` generates random hostnames (sets system hostname).
- **TX power**: presets (Stealth/Low/Medium/High/Max) using `rustyjack-evasion` via `rustyjack-netlink`.
- **Passive mode**: toggles preferred passive mode; monitor + low TX power for stealth recon pipelines.
- **State restore**: tracks original MAC/txpower/monitor IFs to restore on drop or on demand.

## Dependencies
- `rustyjack-evasion` for MAC/txpower/passive; `rustyjack-netlink` for iface operations.
- `rustyjack-core` bridges these controls to UI/CLI and enforces them in pipelines.

## Notes
- Built-in Pi radio MAC changes require interface down/up; permissions enforced.
- Locally administered bit is always set; multicast bit cleared.
- Passive mode does not guarantee RF silence if other modules are active; use Stealth operation mode to block active attacks.
