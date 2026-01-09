# CLAUDE.md - RustyJack Project Context

## Project Overview

**RustyJack** is a portable network security toolkit for Raspberry Pi Zero 2 W running Raspberry Pi OS Lite (32-bit Trixie). It combines a native Rust offensive security framework with an embedded LCD UI (Waveshare 1.44" 128x128 ST7735S display).

**Key Principle: Pure Rust with no external binaries.** All system operations are implemented natively - no iptables, wpa_cli, dnsmasq, dhclient, nmcli, or rfkill binaries. Temporary exceptions exist for shell scripts during installation only.

### Target Platform
- **Hardware:** Raspberry Pi Zero 2 W with Ethernet HAT + Waveshare 1.44" LCD HAT
- **OS:** Raspbian 32-bit CLI (Trixie) - tested configuration
- **External Requirements:** USB WiFi adapter with monitor+injection for wireless attacks (built-in BCM43436 cannot monitor/inject)

### License
MIT

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    rustyjack-ui (unprivileged)                  │
│  LCD rendering, button input, menu navigation                   │
│  User: rustyjack-ui | Groups: gpio, spi                        │
└────────────────────────┬────────────────────────────────────────┘
                         │ Unix Domain Socket IPC
                         │ /run/rustyjack/rustyjackd.sock
┌────────────────────────▼────────────────────────────────────────┐
│              rustyjackd (root daemon, hardened)                 │
│  Command dispatch, job execution, system operations             │
│  Capabilities: CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN       │
└─────────────────────────────────────────────────────────────────┘
```

**Design Principles:**
- Privilege separation: UI cannot directly access hardware
- All privileged operations go through daemon IPC
- Job-based architecture for long-running operations with cancellation
- Hardened systemd units with strict sandboxing

---

## Crate Structure (14 crates)

### Core Infrastructure

| Crate | Purpose |
|-------|---------|
| `rustyjack-ipc` | IPC protocol types, endpoints, authorization levels |
| `rustyjack-commands` | CLI/IPC command enums and argument structures |
| `rustyjack-client` | Tokio-based Unix socket client for daemon communication |

### System-Level (Pure Rust Replacements)

| Crate | Purpose | Replaces |
|-------|---------|----------|
| `rustyjack-netlink` | Networking stack: interfaces, routes, DHCP, DNS, ARP, rfkill, nf_tables | iptables, wpa_cli, dnsmasq, dhclient, nmcli, rfkill |
| `rustyjack-evasion` | MAC/hostname randomization, TX power control | macchanger |
| `rustyjack-encryption` | AES-GCM encryption, secure key handling | - |
| `rustyjack-wpa` | WPA/WPA2 handshake processing, PMK/PTK computation | - |

### Feature-Specific

| Crate | Purpose |
|-------|---------|
| `rustyjack-wireless` | 802.11 attacks: deauth, PMKID, Karma, Evil Twin, handshake capture/crack |
| `rustyjack-ethernet` | LAN discovery, port scanning, ARP spoofing, MITM |
| `rustyjack-portal` | Captive portal HTTP server (Axum-based) |

### Orchestration

| Crate | Purpose |
|-------|---------|
| `rustyjack-core` | Command dispatcher, pipelines, loot management, system operations |
| `rustyjack-daemon` | Privileged service: socket server, job lifecycle, authorization |
| `rustyjack-ui` | LCD display, GPIO buttons, menu system, stats overlay |

---

## Key Features

### Wireless (requires external adapter)
- Network scanning with channel hopping
- Deauth attacks with handshake capture
- PMKID capture (targeted/passive)
- Karma attack (probe response spoofing)
- Evil Twin (open AP impersonation)
- Handshake cracking with wordlists

### Ethernet
- LAN discovery (ICMP/ARP sweep)
- Port scanning with banner grabbing
- Device inventory (mDNS/LLMNR/NetBIOS/WSD)
- ARP spoofing and MITM

### Hotspot
- Rust-native AP (no hostapd/dnsmasq)
- Built-in DHCP and DNS servers
- NAT via nf_tables netlink

### Evasion
- MAC randomization (vendor-aware)
- Hostname randomization
- TX power control (1/5/12/18 dBm, max)
- Operation modes: Stealth, Default, Aggressive

### Loot Management
- Organized storage by target
- Automated reports with insights
- Discord webhook uploads
- USB export
- Optional AES-GCM encryption

---

## Build & Deployment

### Building on Windows (Cross-compile for ARM32)
```powershell
cd scripts
./build_arm32.ps1
```
Outputs to `prebuilt/arm32/`

### Building on Pi
```bash
./install_rustyjack.sh        # Full build (~30 min on Pi Zero 2 W)
./install_rustyjack_prebuilt.sh  # Use prebuilt binaries (faster)
```

### Binaries
- `rustyjack-ui` - LCD interface
- `rustyjackd` - Privileged daemon
- `rustyjack-portal` - Captive portal server
- `rustyjack` - CLI tool (feature-gated)

### Runtime Directories
- `/var/lib/rustyjack/` - State, loot, configs (RUSTYJACK_ROOT)
- `/run/rustyjack/` - Socket, temporary files
- `/usr/local/bin/` - Binaries

---

## Configuration

### gui_conf.json (auto-created)
- GPIO pin mappings
- Color palette
- Active interface, target info
- Evasion toggles
- Hotspot settings

### Environment Variables
```bash
RUSTYJACK_ROOT=/var/lib/rustyjack
RUSTYJACKD_SOCKET=/run/rustyjack/rustyjackd.sock
RUSTYJACKD_READ_TIMEOUT_MS=5000
RUSTYJACKD_WRITE_TIMEOUT_MS=5000
```

---

## Development Guidelines

### Adding New Features
1. **No external binaries** - Implement in Rust using netlink/raw sockets
2. **Privilege separation** - UI requests go through daemon IPC
3. **Job pattern** - Long operations should be cancellable jobs
4. **Error propagation** - Use anyhow with context, surface errors to UI

### Code Organization
- Commands defined in `rustyjack-commands`
- IPC types in `rustyjack-ipc`
- Business logic in `rustyjack-core/src/operations.rs`
- Daemon handlers in `rustyjack-daemon/src/dispatch.rs`
- UI menus in `rustyjack-ui/src/app.rs`

### Testing
```bash
# Check compilation
cargo check --workspace

# Run on Pi
systemctl status rustyjackd
systemctl status rustyjack-ui
journalctl -u rustyjackd -f
```

---

## Common Issues

### UI shows "Failed: internal error"
- Check daemon logs: `journalctl -u rustyjackd -n 50`
- Verify socket exists: `ls -l /run/rustyjack/rustyjackd.sock`
- Error details should now show full chain (improved in recent commits)

### Wireless attacks fail
- Built-in WiFi cannot monitor/inject - use external adapter
- Check adapter capabilities: `iw list`
- Verify monitor mode support

### Build fails on Windows
- Use `./scripts/build_arm32.ps1` for Docker cross-compilation
- Requires Docker Desktop with ARM emulation

### No network after interface change
- RustyJack enforces single active interface
- Check interface isolation in Settings → Hardware

---

## File Structure

```
rustyjack/
├── rustyjack-core/        # Operations, pipelines, orchestration
├── rustyjack-daemon/      # Privileged service
├── rustyjack-ui/          # LCD interface
├── rustyjack-client/      # IPC client library
├── rustyjack-ipc/         # Protocol types
├── rustyjack-commands/    # Command definitions
├── rustyjack-netlink/     # Pure Rust networking
├── rustyjack-wireless/    # 802.11 attacks
├── rustyjack-ethernet/    # LAN operations
├── rustyjack-portal/      # Captive portal
├── rustyjack-evasion/     # MAC/hostname randomization
├── rustyjack-encryption/  # Crypto helpers
├── rustyjack-wpa/         # WPA handshake processing
├── scripts/               # Build scripts
├── docker/                # Cross-compilation containers
├── docs/                  # Documentation
└── install_*.sh           # Installation scripts
```

---

## Security Model

- **Daemon runs as root** with capability restrictions
- **UI runs unprivileged** (rustyjack-ui user)
- **IPC authorization** based on UID/group membership
- **Systemd hardening**: ProtectSystem=strict, MemoryDenyWriteExecute, syscall filtering
- **Crypto**: AES-GCM for loot, PBKDF2 for WPA, zeroization of sensitive data

---

## Useful Commands

```bash
# Service management
sudo systemctl restart rustyjackd
sudo systemctl restart rustyjack-ui

# Logs
journalctl -u rustyjackd -f
tail -f /var/lib/rustyjack/logs/rustyjack-ui.log

# Manual daemon test
sudo /usr/local/bin/rustyjackd

# Check interfaces
ip link show
iw dev
```
