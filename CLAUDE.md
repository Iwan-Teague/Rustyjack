# CLAUDE.md - RustyJack Project Context

## Project Overview

**RustyJack** is a portable network security toolkit for Raspberry Pi Zero 2 W running Raspberry Pi OS Lite or Debian (Trixie). It combines a native Rust offensive security framework with an embedded LCD UI (Waveshare 1.44" ST7735S default profile `128x128`, runtime geometry/layout aware).

**Key Principle: Pure Rust with no external binaries.** All system operations are implemented natively - no iptables, wpa_cli, dnsmasq, dhclient, nmcli, or rfkill binaries. Temporary exceptions exist for shell scripts during installation only.

**Reality check (current state):**
- Installers still pull `wpa_supplicant` (and `wpa_cli` as a fallback), `hostapd`, `dnsmasq`, and `isc-dhcp-client` for compatibility. These are not fully eliminated yet.
- `/etc/resolv.conf` is claimed as a symlink to `/var/lib/rustyjack/resolv.conf` (not a plain file).
- 64-bit arm64 deployments on Debian 13 (Trixie) are in active use; 32-bit remains a supported target but should be revalidated when changing low-level networking.

### Target Platform
- **Hardware:** Raspberry Pi Zero 2 W with Ethernet HAT + Waveshare 1.44" LCD HAT
- **Display model:** Runtime capability/layout metrics; default ST7735 profile is `128x128`, larger backends use same 8-button UX model
- **OS:** Debian 13 / Raspberry Pi OS Lite (Trixie); arm64 is supported (preferred for prebuilts), 32-bit remains supported
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
- Network isolation is enforced in the daemon: only one active uplink is allowed, and transitions must pass exclusivity verification.
- `Settings -> Network Interfaces` is a blocking UI workflow: user cannot leave while a switch is in progress. On error, if rollback restores a valid exclusive state, `Select/Right` exits back to menu; otherwise the screen stays blocked until retry/reboot or a safe all-down state allows Back.
- Display startup flow is backend-aware: detect backend, query mode, calibrate if needed, cache effective geometry
- UI layout metrics are runtime-derived (no fixed menu/dialog visible constants in core flow)

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
| `rustyjack-netlink` | Networking stack: interfaces, routes, DHCP, DNS, ARP, rfkill, nf_tables | iptables, dhclient, rfkill (aims to replace wpa_cli/dnsmasq/nmcli; see reality check) |
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
- Rust-native AP (no hostapd/dnsmasq at runtime; installers still include them for compatibility)
- Built-in DHCP and DNS servers
- NAT via nf_tables netlink

### Evasion
- MAC randomization (vendor-aware)
- Hostname randomization
- TX power control (1/5/12/18 dBm, max)
- Operation modes: Stealth, Default, Aggressive

### Loot Management
- Session-based organization by target
- Automated reports with insights and next steps
- Artifact sweep for comprehensive file collection
- Pipeline loot isolation
- Discord webhook uploads
- USB export with mount policy enforcement
- Optional AES-GCM encryption
- Audit logging with operation history

### Anti-Forensics
- Secure file deletion (DoD 5220.22-M standard)
- RAM wipe on secure shutdown
- Log purging with selective artifact removal
- Complete system purge capability
- Sensitive data redaction in logs
- Zeroization of sensitive data structures

### Physical Access
- WiFi credential extraction from routers
- Router fingerprinting and vulnerability detection
- Default credential testing
- USB mounting with read-only/read-write modes
- Mount policy enforcement

### Full Disk Encryption
- USB key preparation for encrypted volumes
- Root filesystem migration to encrypted storage
- LUKS-based encryption support

### Advanced CLI Operations
- DNS spoofing with captive portal templates
- Reverse shell launcher with job tracking
- Transparent network bridging
- Process management and daemon control

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

`install_rustyjack_prebuilt.sh` is the final provisioning blueprint. Source/dev installers compile locally and then delegate to the prebuilt installer path with `PREBUILT_DIR` override so service/runtime setup remains identical.

### Binaries
- `rustyjack-ui` - LCD interface
- `rustyjackd` - Privileged daemon
- `rustyjack-portal` - Captive portal server
- `rustyjack` - CLI tool (feature-gated)

### Runtime Directories
- `/var/lib/rustyjack/` - State, loot, configs (RUSTYJACK_ROOT)
- `/run/rustyjack/` - Socket, temporary files
- `/usr/local/bin/` - Binaries
- `/var/lib/rustyjack/logs/install/` - Installer transcripts (`install_latest.log` + per-installer latest links)

---

## Configuration

### gui_conf.json (auto-created)
- GPIO pin mappings
- Color palette
- Display state (probe/calibration completion flags, calibrated edges, effective geometry cache, profile fingerprint)
- Active interface, target info
- Evasion toggles
- Hotspot settings

### Display Runtime Notes
- `Settings -> Display` exposes manual `Run Display Discovery`, `Run Display Calibration`, `Reset Display Calibration`, `Reset Display Cache`, and diagnostics.
- Calibration captures `LEFT/TOP/RIGHT/BOTTOM` edges with fixed 8-button controls (`LEFT/RIGHT` for vertical edges, `UP/DOWN` for horizontal edges, `Select` to confirm).
- Startup logs/warnings include `DISPLAY_MODE_MISMATCH`, `DISPLAY_UNVERIFIED_GEOMETRY`, and `UNSUPPORTED_DISPLAY_SIZE`.

### Environment Variables
```bash
RUSTYJACK_ROOT=/var/lib/rustyjack
RUSTYJACK_DISPLAY_BACKEND=st7735      # st7735|framebuffer|drm
RUSTYJACK_DISPLAY_ROTATION=landscape  # or portrait
RUSTYJACK_DISPLAY_WIDTH=128           # optional override
RUSTYJACK_DISPLAY_HEIGHT=128          # optional override
RUSTYJACK_DISPLAY_OFFSET_X=0          # optional override
RUSTYJACK_DISPLAY_OFFSET_Y=0          # optional override
RUSTYJACK_LOGS_DISABLED=1             # disables logging when set
RUSTYJACKD_SOCKET=/run/rustyjack/rustyjackd.sock
RUSTYJACKD_READ_TIMEOUT_MS=5000
RUSTYJACKD_WRITE_TIMEOUT_MS=5000
RUSTYJACKD_ALLOW_CORE_DISPATCH=true   # enables IPC dispatch (required)
RUSTYJACKD_DANGEROUS_OPS=true         # enables system updates (commented out by default)
RUSTYJACK_NFTABLES_LOG=1              # logs nf_tables packet matches to journalctl
```

### Systemd Services
- `rustyjackd.service` - Privileged daemon (root) with CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN
- `rustyjack-ui.service` - Unprivileged LCD UI (rustyjack-ui user, groups: gpio, spi, rustyjack)
- `rustyjack-portal.service` - Captive portal server (rustyjack-portal user, port 3000)
- `rustyjack.service` - Alias for rustyjack-ui.service

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

# Run comprehensive test suite (safe mode)
sudo ./scripts/rustyjack_comprehensive_test.sh

# Run with dangerous/disruptive tests (lab devices only)
sudo ./scripts/rustyjack_comprehensive_test.sh --dangerous

# Check services on Pi
systemctl status rustyjackd
systemctl status rustyjack-ui
journalctl -u rustyjackd -f
```

**Test Suite** (`scripts/rustyjack_comprehensive_test.sh`):
- Suite A: Installation & service sanity
- Suite B: Systemd hardening posture
- Suite C: Authorization matrix & tiers
- Suite D: Protocol robustness
- Suite E: Stress testing
- Suite F: Security adversarial probes
- Dangerous mode: WiFi, hotspot, USB mount operations
- `scripts/rj_run_tests.sh` now stages installer logs into each run under `<results_root>/install_logs/` so Discord final artifact uploads and the consolidated ZIP carry install-time diagnostics.

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
- Check interface isolation in `Settings -> Network Interfaces`
- If UI remains blocked on this screen, resolve the reported isolation error (rfkill hard block, missing DHCP/gateway, or route verification failure) and retry

### DNS resolution issues
- Check that `/etc/resolv.conf` is a symlink to `/var/lib/rustyjack/resolv.conf` and is writable by root
- Verify NetworkManager is purged: `dpkg -s network-manager` should show "not installed"
- Installation removes NetworkManager completely via `apt-get purge`

### USB mount failures
- Verify device is writable and has correct filesystem
- Check permissions on `/var/lib/rustyjack/mounts/`
- Ensure correct mount mode selected (ReadOnly/ReadWrite)

### FDE operations
- FDE preparation and migration are **destructive and irreversible**
- Always backup data before running
- Requires USB key and will format target devices

---

## File Structure

```
rustyjack/
├── rustyjack-core/        # Operations, pipelines, orchestration, anti-forensics
│   ├── src/
│   │   ├── operations.rs       # 68 command handlers
│   │   ├── anti_forensics.rs   # Secure delete, RAM wipe, evidence removal
│   │   ├── physical_access.rs  # WiFi credential extraction from routers
│   │   ├── mount.rs            # USB mount operations with policy enforcement
│   │   └── redact.rs           # Sensitive data redaction for logs
├── rustyjack-daemon/      # Privileged service
├── rustyjack-ui/          # LCD interface
├── rustyjack-client/      # IPC client library
├── rustyjack-ipc/         # Protocol types
├── rustyjack-commands/    # Command definitions
├── rustyjack-netlink/     # Pure Rust networking
├── rustyjack-wireless/    # 802.11 attacks (9,688 lines, 18 modules)
├── rustyjack-ethernet/    # LAN operations
├── rustyjack-portal/      # Captive portal (Axum + Tower)
├── rustyjack-evasion/     # MAC/hostname randomization with policy engine
├── rustyjack-encryption/  # AES-GCM crypto helpers
├── rustyjack-wpa/         # WPA handshake processing (PBKDF2, HMAC-SHA1)
├── DNSSpoof/              # Captive portal templates (HTML/JS, not Rust)
├── scripts/               # Build scripts, WiFi drivers, FDE scripts
│   ├── fde_prepare_usb.sh
│   ├── fde_migrate_root.sh
│   └── wifi_driver_installer.sh
├── docker/                # Cross-compilation containers
├── docs/                  # Documentation
└── install_*.sh           # Installation scripts (production/dev/prebuilt)
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
