# Rustyjack

Portable Raspberry Pi Zero 2 W network toolkit with a Waveshare 1.44" LCD + joystick UI. Written in Rust, shipped as an unprivileged UI service backed by a privileged daemon. Additional documentation is in `logs/done/` (current) and `logs/outdated/` (historical).

> Authorized testing and education only. Verify permissions before running any operation.

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Hardware & Wiring](#hardware--wiring)
- [Controls](#controls)
- [Display Backends & Dynamic Resolution](#display-backends--dynamic-resolution)
- [Display Calibration](#display-calibration)
- [UI Features](#ui-features)
- [Installation](#installation)
- [Configuration & Paths](#configuration--paths)
- [Usage Tips](#usage-tips)
- [Troubleshooting](#troubleshooting)
- [Legal](#legal)

## Project Overview

- Linux-only UI (compile guard in `crates/rustyjack-ui/src/main.rs`); designed for a Pi Zero 2 W with an Ethernet HAT.
- Runs as `rustyjack-ui.service` (unprivileged) with `RUSTYJACK_DISPLAY_ROTATION=landscape` by default.
- Status overlay shows CPU temp/load, memory, disk, uptime, target SSID/BSSID/channel, active interface, current/original MAC, and autopilot status if the CLI autopilot is running.
- Firewall/NAT rules are applied via Rust nf_tables netlink (no `iptables` binary dependency).
- Built-in Cypress/Infineon radio cannot monitor/inject; all wireless attacks require an external adapter that supports monitor + injection.
- Network isolation is strict: exactly one uplink interface may be active at a time, and interface switches are validated before the UI unlocks.

## Architecture

```
crates/rustyjack-ui/         LCD UI: menus, rendering, GPIO buttons, dashboards
crates/rustyjack-core/       Orchestrator CLI: Wi-Fi/Ethernet ops, hotspot, MITM, loot, autopilot, system update, anti-forensics
crates/rustyjack-wireless/   Native wireless ops (nl80211 monitor/injection, deauth, PMKID, karma, evil twin, hotspot, cracking helpers)
crates/rustyjack-evasion/    MAC/hostname evasion, vendor-aware MAC generation, TX power/passive helpers
crates/rustyjack-ethernet/   LAN discovery, TCP port scan, banner grabs, inventory helpers
crates/rustyjack-netlink/    Pure Rust networking: interfaces, routes, DHCP, DNS, ARP, rfkill, nf_tables
crates/rustyjack-ipc/        IPC protocol types and endpoints
crates/rustyjack-daemon/     Privileged daemon with IPC dispatch
crates/rustyjack-client/     Unix socket client library
crates/rustyjack-portal/     Captive portal HTTP server (Axum-based)
crates/rustyjack-wpa/        WPA/WPA2 handshake processing (PBKDF2, HMAC-SHA1)
crates/rustyjack-encryption/ AES-GCM encryption for loot
crates/rustyjack-commands/   CLI/IPC command definitions
DNSSpoof/                Captive portal templates (not a Rust crate - HTML/JS templates)
scripts/                 Wi-Fi driver installer, USB hotplug helper, FDE scripts (udev rule included)
wordlists/               Bundled password lists for handshake cracking
img/                     Splash assets for the LCD (`rustyjack.png`)
services/rustyjack-ui.service     Systemd unit (unprivileged UI, sets display backend/rotation and RUSTYJACK_ROOT)
services/rustyjackd.service       Systemd unit (root daemon, privileged operations + IPC)
services/rustyjack-portal.service Systemd unit (captive portal server, unprivileged)
install_rustyjack*.sh    Production/dev/prebuilt installers for Pi OS targets
```

Runtime directories are created by the installers under `/var/lib/rustyjack`:
`loot/` (Wireless, Ethernet, reports), `wifi/profiles/`, `DNSSpoof/captures/`, and `gui_conf.json` (pins, colors, settings).

### System-Level Operations

**Anti-Forensics** (`crates/rustyjack-core/src/anti_forensics.rs`):
- Secure file deletion with configurable overwrite passes (DoD 5220.22-M standard)
- RAM wipe on secure shutdown
- Log purging with selective artifact removal
- Evidence management and cleanup

**Physical Access** (`crates/rustyjack-core/src/physical_access.rs`):
- WiFi credential extraction from routers via wired connection
- Router fingerprinting and vulnerability detection
- Default credential testing

**USB Operations** (`crates/rustyjack-core/src/mount.rs`):
- USB mounting with read-only/read-write mode selection
- Mount policy enforcement (filesystem type filtering, device limits)
- Safe unmount with lock timeout protection

**Full Disk Encryption** (`scripts/fde_*.sh`):
- USB key preparation for encrypted volumes
- Root filesystem migration to encrypted storage
- LUKS-based encryption support

**Process Management**:
- Daemon/service lifecycle control
- IPC-based job dispatch
- Background operation tracking

## Hardware & Wiring

- Target: Raspberry Pi Zero 2 W + Ethernet HAT + Waveshare 1.44" LCD HAT (ST7735S, default 128x128 profile).
- Display rotation: `RUSTYJACK_DISPLAY_ROTATION=landscape` (default); set to `portrait` to rotate back.
- Backlight: BCM24 held high by the UI; you can test with `gpioset gpiochip0 24=1`.
- Buttons are active-low; installers add GPIO pull-ups via `/boot/firmware/config.txt` (or `/boot/config.txt`): `gpio=6,19,5,26,13,21,20,16=pu`.

**Display pins (from `crates/rustyjack-ui/src/display.rs`):**

| Signal | BCM GPIO |          Notes          |
|--------|----------|-------------------------|
| DC     | 25       | Data/command select     |
| RST    | 27       | Reset (active low)      |
| BL     | 24       | Backlight control       |
| SPI    | spidev0.0 (SCLK 11, MOSI 10, CS 8) | 

**Input pins (defaults from `crates/rustyjack-ui/src/config.rs`):**

| Control | BCM GPIO |           Purpose           |
|---------|----------|-----------------------------|
| UP      | 6        | Joystick up                 |
| DOWN    | 19       | Joystick down               |
| LEFT    | 5        | Back                        |
| RIGHT   | 26.      | Select/forward              |
| PRESS   | 13       | Center press (select)       |
| KEY1    | 21       | Refresh/redraw              |
| KEY2    | 20       | Cancel (no-op in menus; cancels dialogs/ops) |
| KEY3    | 16       | Reboot confirmation dialog  |

Pins and colors can be customized in `gui_conf.json`; defaults are created automatically.

## Controls

|        Button        |                     Action in UI                     |
|----------------------|------------------------------------------------------|
| Up / Down            | Move selection                                       |
| Left                 | Back/exit dialog                                     |
| Right / Center press | Select/confirm                                       |
| Key1                 | Refresh current view                                 |
| Key2                 | Cancel (no-op in menus; cancels dialogs/ops)         |
| Key3                 | Open reboot confirmation (requires explicit confirm) |

## Display Backends & Dynamic Resolution

- Runtime flow: `detect backend -> query capabilities -> calibrate only when needed -> cache effective geometry`.
- Supported baseline: `128x128` is the lowest supported layout target.
- Displays smaller than `128x128` are allowed in best-effort mode and emit `UNSUPPORTED_DISPLAY_SIZE` warnings.
- Cached geometry is reused on normal boots when probe/calibration completion flags are set; no automatic recalculation loop.
- Recalculation is manual-only from `Settings -> Display`.
- Effective geometry precedence: `override (env/config) > backend detected mode > backend profile`.

Runtime warnings/events:
- `DISPLAY_MODE_MISMATCH`
- `DISPLAY_UNVERIFIED_GEOMETRY`
- `UNSUPPORTED_DISPLAY_SIZE`

`rustyjack-ui` currently renders through the ST7735 path by default (`RUSTYJACK_DISPLAY_BACKEND=st7735`) and keeps that path fully functional for Pi Zero 2 W + Waveshare HAT.

## Display Calibration

Use `Settings -> Display -> Run Display Calibration`.

Workflow:
1. Calibrate `LEFT`
2. Calibrate `TOP`
3. Calibrate `RIGHT`
4. Calibrate `BOTTOM`

Controls:
- Vertical edges (`LEFT`, `RIGHT`): `LEFT/RIGHT` adjusts by 1 px
- Horizontal edges (`TOP`, `BOTTOM`): `UP/DOWN` adjusts by 1 px
- `Select`: confirm current edge
- `Key1`: reset current edge to profile default
- `Key2`: cancel calibration and keep previous saved values

Saved values include calibrated edges, completion flags, effective geometry, backend/rotation, offsets, and profile fingerprint in `gui_conf.json`.

Deep-dive reference: `docs/display_dynamic_resolution.md`.

## UI Features

### System, modes, and dashboards

- **Operation Mode**: Stealth (blocks active ops, forces MAC/hostname randomization + 1 dBm TX), Default, Aggressive (max TX), Custom (keep manual toggles).
- **Dashboards**: Cycle System Health, Target Status, and MAC Status views from the main menu.
- **Colors**: Pick palette entries directly from the UI.
- **Display settings**: `Settings -> Display` supports manual discovery/calibration reruns, cache/calibration reset, and diagnostics inspection.
- **Logs toggle**: Enables/disables logging by setting/clearing `RUSTYJACK_LOGS_DISABLED`; **Purge Logs** removes log files under loot.
- **System**: Restart, Secure Shutdown (best-effort RAM wipe then poweroff), Complete Purge (removes binaries, services, loot, udev helpers; exits UI), FDE Prepare/Migrate (full-disk encryption setup), USB Mount/Unmount (with read-only/read-write mode selection).
- **Wi-Fi driver installer**: Runs `scripts/wifi_driver_installer.sh`, detecting USB chipsets and installing/compiling drivers; progress is shown in the UI (`/var/log/rustyjack_wifi_driver.log`).
- **Autopilot (main menu)**: Start Standard/Aggressive/Stealth/Harvest runs or stop/view status. Requires an active wired interface with link; blocked when Operation Mode is Stealth unless you choose the Stealth autopilot. Optional DNS spoof site selection when starting. Toolbar shows `AP:<mode>` while running.
- **Wireless menus split**: Main menu → Wireless. Inside: Get Connected (Scan + Recon/Offence folders plus Connect), Post Connection (Recon + Offence items like DNS spoof/reverse shell), and Hotspot. Selecting an active interface in Network Interfaces runs a blocking isolation flow; the user cannot leave until exclusivity is verified or a hard error is acknowledged. Non-selected Wi-Fi adapters are rfkill-blocked and forced down; non-selected wired adapters are forced down with addresses/routes flushed. Hotspot temporarily unblocks/uses its AP + upstream interfaces while running.

### Network Interfaces (blocking)

- Enumerates detected interfaces (`eth*`, `wlan*`, `usb*`, etc.) with type, state, IP, and rfkill status.
- On selection, prompts for confirmation (`Are you sure?`) and then runs a blocking progress screen.
- The user cannot leave this screen until exclusivity is achieved:
  - exactly one selected interface is admin-UP and routed,
  - all non-selected interfaces are DOWN,
  - non-selected Wi-Fi interfaces are rfkill-blocked.
- On failure, the UI remains blocked and shows Retry/Reboot actions; Back is allowed only in a safe all-down state.
- The selected interface is persisted to `gui_conf.json` only after successful transition.

### Wireless Access (external monitor/injection adapter required)

- **Scan Networks**: Shows SSID/BSSID/channel/signal, lets you set the target (SSID/BSSID/channel saved). Hidden SSIDs are not configurable via the UI. Also allows connecting to a saved profile if one matches the SSID.
- **Connect Known Network**: Lists `wifi/profiles/*.json` (connect or delete). The UI does not create new profiles; edit JSON or use the core CLI to add them.
- **Deauth Attack**: 120s run with handshake capture, progress + cancel, writes PCAP/log/JSON to `loot/Wireless/<target>/`.
- **PMKID Capture**: Targeted (if a target is set) or passive capture with durations 30/60s.
- **Probe Sniff**: 30/60/300s channel-hopping probe capture; shows total probes, unique clients/networks, and top SSIDs.
- **Karma Attack**: Responds to probes (2/5/10 minute options) with optional fake AP using the same interface.
- **Evil Twin Attack**: Open AP impersonation of the selected target (5 minutes). Reports connected clients, handshakes, credentials, loot directory, and duration.
- **Crack Handshake**: Uses JSON handshake exports in `loot/Wireless`; dictionaries include quick (common + SSID-derived), SSID patterns only, and bundled `wordlists/wifi_common.txt` + `wordlists/common_top.txt`.
- **Attack Pipelines** (blocked in Stealth except Stealth Recon):
  - *Get WiFi Password*: Scan -> targeted PMKID -> deauth/handshake capture -> quick crack.
  - *Mass Capture*: Scan twice (hop) -> PMKID harvest -> probe sniff for clients.
  - *Stealth Recon*: Randomize MAC -> 1 dBm TX -> passive sniff (no TX).
  - *Credential Harvest*: Probe sniff -> Karma -> Evil Twin open portal -> captive wait.
  - *Full Pentest*: MAC randomize + passive recon -> scan -> PMKID harvest -> deauth -> Karma -> quick crack.
  - Pipeline loot is copied to `loot/Wireless/<target>/pipelines/<timestamp>/` for artifacts created after the start time.
- **Passive Recon**: UI-only informational dialog today (no capture is launched).
- **Hotspot** (Wireless Access menu): Select upstream + AP interfaces from detected hardware, start/stop Rust AP + DHCP/DNS, randomize SSID/password (`rustyjack_wireless::random_*`). Status view shows running SSID/password and lets you turn it off.

### Obfuscation & Identity

- **MAC controls**: Auto MAC toggle, Randomize Now (vendor-aware: reuses interface OUI when possible, sets locally administered bit, renews DHCP via netlink; reconnect is best-effort), Set Vendor MAC (pick from `rustyjack-evasion` vendor table), Restore MAC (uses saved original or hardware address).
- **Hostname**: Auto toggle + Randomize Now (via `SystemCommand::RandomizeHostname`).
- **TX Power**: Stealth 1 dBm, Low 5 dBm, Medium 12 dBm, High 18 dBm, Maximum (via `rustyjack-netlink`).
- **Passive mode toggle**: Stores preference (used for mode presets); Passive Recon action is informational.

### Ethernet Recon (active interface must be wired and have link)

- **LAN Discovery**: ICMP/ARP sweep with TTL OS hints; saves loot path and host list.
- **Port Scan**: TCP connect scan (defaults to gateway if no target) with banner grabs; timeout presets 0.5/1/2/5s per port; saves loot/banners.
- **Device Inventory**: mDNS/LLMNR/NetBIOS/WSD probes + port data; saves inventory JSON/text to loot.
- **MITM Capture**: ARP spoof + Rust PCAP capture under `loot/Ethernet/<label>/`; optional DNS spoof using `DNSSpoof/sites/<site>` templates; shows victim counts/pcap paths. **MITM Status** tracks visit/credential logs for the chosen site; **Stop MITM/DNS** tears down both.
- **Site Credential Capture pipeline**: Classifies "human" hosts, ARP poisons up to the chosen cap, launches DNS spoof site, captures PCAP/visit/credential logs; loot and PCAP paths are reported.

### Loot, reports, and export

- **Loot browser**: Navigate `loot/Wireless` and `loot/Ethernet` targets, drill into folders, and view files with a scrollable viewer.
- **Reports**: Builds combined Ethernet/Wi-Fi report to `loot/reports/<network>/report_<ts>.txt` (summaries, insights, next steps, artifact sweep, MAC usage notes).
- **Discord upload**: Zips `loot/` and `loot/reports/` into a temp archive and posts to the webhook in `discord_webhook.txt`.
- **Transfer to USB**: Copies loot to `Rustyjack_Loot` on the first writable USB block device mount.
- **Logs toggle/purge**: Logging can be disabled globally; Purge Logs removes `.log` files and log-like artifacts under loot.

### CLI-only extras (via `rustyjack-core`)

The following features exist in the core CLI but are not exposed as LCD menu items:

**DNS Spoof** (`DnsSpoofCommand`):
- Site-based DNS spoof with captive portal templates
- Uses templates from `DNSSpoof/sites/`
- Captures visit/credential logs

**Reverse Shell** (`ReverseCommand::Launch`):
- Configurable reverse shell launcher
- Supports custom callback host and port
- Background execution with job tracking

**Transparent Bridge** (`BridgeCommand`):
- Network bridging functionality
- Bridge start/stop operations
- Interface aggregation support

### Anti-Forensics & Evidence Management

**Secure Operations**:
- **Secure Shutdown**: Best-effort RAM wipe before poweroff to clear sensitive data from memory
- **Secure Delete**: Multi-pass file overwrite using DoD 5220.22-M standard (7 passes)
- **Log Purging**: Selective removal of log files and artifacts under loot directories
- **Complete System Purge**: Removes all RustyJack binaries, systemd services, loot, and configuration files

**Loot Management**:
- **Session-Based Organization**: Artifacts organized by target (Wireless/<SSID>, Ethernet/<IP>)
- **Artifact Sweep**: Automatically identifies and collects all related files for a target
- **Pipeline Loot Isolation**: Artifacts created during pipelines are isolated to pipeline-specific directories
- **Audit Logging**: Operation audit trail with timestamps and command history

**Data Protection**:
- **Sensitive Data Redaction**: Automatic redaction of passwords, keys, and credentials in logs
- **Optional Encryption**: AES-GCM encryption for loot storage
- **Zeroization**: Secure clearing of sensitive data structures in memory

## Installation

**Requirements**

- Raspberry Pi OS Lite (32/64-bit) on a Pi Zero 2 W (or Pi 4/5).
- External Wi-Fi adapter with monitor + injection for wireless attacks.
- Root privileges (daemon runs as root; UI runs unprivileged but needs SPI/GPIO access).

**Steps**

1. Flash Raspberry Pi OS Lite and enable SSH if needed.
2. SSH to the Pi, become root: `sudo su -`.
3. Clone the project: `git clone https://github.com/Iwan-Teague/Rusty-Jack.git Rustyjack && cd Rustyjack`.
4. Run the installer: `chmod +x install_rustyjack.sh && ./install_rustyjack.sh`
   - Installs packages: base runtime (`wpa_supplicant`, git, i2c-tools, curl; firmware for Realtek/Atheros/Ralink as available). Prebuilt/USB installs also include `hostapd`, `dnsmasq`, `isc-dhcp-client`, `rfkill`. Source builds add build toolchain (`build-essential`, `pkg-config`, `libssl-dev`, DKMS toolchain) and kernel headers when available.
   - **Removes NetworkManager**: Runs `apt-get purge network-manager` to completely remove NetworkManager from the system (not just disabled).
   - Enables I2C/SPI overlays, `dtoverlay=spi0-2cs`, and GPIO pull-ups for all buttons.
   - Ensures ~2 GB swap for compilation, builds `rustyjack-ui` (release), installs to `/usr/local/bin/`.
   - Creates `/var/lib/rustyjack/loot/{Wireless,Ethernet,reports}`, `/var/lib/rustyjack/wifi/profiles/sample.json`, and keeps WLAN interfaces up.
   - Installs Wi-Fi driver helper scripts + udev rule, sets `RUSTYJACK_ROOT=/var/lib/rustyjack`, installs/enables systemd units (typically `rustyjackd.service` + `rustyjack-ui.service`; prebuilt may use `rustyjackd.socket`), starts services, and reboots unless `SKIP_REBOOT=1` or `NO_REBOOT=1`.
   - **Claims `/etc/resolv.conf`**: Symlinks to `/var/lib/rustyjack/resolv.conf` and disables competing DNS managers (systemd-resolved, dhcpcd, resolvconf if present). NetworkManager is completely removed to prevent DNS conflicts.
   - Remounts `/` read-write if needed on fresh images to allow installs/edits.
5. After reboot, the LCD shows the menu. Service status: `systemctl status rustyjack-ui`.

`install_rustyjack_dev.sh` is available for development setups and follows the same dependency/build steps.

## Configuration & Paths

**Configuration Files**:
- `gui_conf.json` (auto-created): pins, colors, active interface, target SSID/BSSID/channel, MAC/hostname/passive toggles, hotspot credentials, log/Discord toggles.
- `discord_webhook.txt`: webhook URL for Discord uploads.
- `wifi/profiles/*.json`: saved Wi-Fi profiles used by Connect Known Network (sample provided); directory is `770` and files are `660` for UI access.

**Loot Directories**:
- `loot/`: wireless, Ethernet, and scan captures; pipelines are under `loot/Wireless/<target>/pipelines/`; reports live in `loot/reports/`.
- `logs/`: UI/daemon logs under `/var/lib/rustyjack/logs` (owned by `rustyjack-ui:rustyjack`).
- `loot/Scan/`: Rust-native scan reports from `rustyjack-core scan run`.
- `DNSSpoof/sites/`: portal templates for DNS spoof/MITM; captures go to `DNSSpoof/captures/`.

**Environment Variables**:
- `RUSTYJACK_ROOT=/var/lib/rustyjack` - Root directory for all runtime data
- `RUSTYJACK_DISPLAY_BACKEND={st7735|framebuffer|drm}` - Backend preference (default service value: `st7735`)
- `RUSTYJACK_DISPLAY_ROTATION={landscape|portrait}` - LCD display orientation (default: landscape)
- `RUSTYJACK_DISPLAY_WIDTH=<px>` - Optional explicit width override
- `RUSTYJACK_DISPLAY_HEIGHT=<px>` - Optional explicit height override
- `RUSTYJACK_DISPLAY_OFFSET_X=<px>` - Optional panel offset X override
- `RUSTYJACK_DISPLAY_OFFSET_Y=<px>` - Optional panel offset Y override
- `RUSTYJACK_LOGS_DISABLED` - When set, disables logging globally
- `RUSTYJACKD_SOCKET=/run/rustyjack/rustyjackd.sock` - Daemon IPC socket path
- `RUSTYJACKD_ALLOW_CORE_DISPATCH=true` - Enables IPC command dispatch (required)
- `RUSTYJACKD_DANGEROUS_OPS=true` - Enables system update operations (commented out by default)
- `RUSTYJACK_NFTABLES_LOG=1` - Optional flag to log nf_tables packet matches in journalctl with `[NFTABLE]` prefixes

**Systemd Services**:
- `rustyjackd.service` - Privileged daemon (root) with CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN capabilities
- `rustyjackd.socket` - Daemon socket (used for socket activation in some installs)
- `rustyjack-ui.service` - Unprivileged LCD UI service (rustyjack-ui user, supplementary groups: gpio, spi, rustyjack)
- `rustyjack-wpa_supplicant@wlan0.service` - WiFi client authentication service
- `rustyjack-portal.service` - Captive portal HTTP server (rustyjack-portal user, port 3000)
- `rustyjack.service` - Alias for rustyjack-ui.service

**Other Assets**:
- Splash image: `img/rustyjack.png` (shown on boot)
- Audit logs: Operation history with timestamps

## Usage Tips

- Run **Network Interfaces** first and set the active interface (needed for Wi-Fi and Ethernet menus). This flow is intentionally blocking and cannot be bypassed until isolation succeeds.
- Set a target via **Scan Networks** before deauth/evil twin/PMKID/pipelines; BSSID and channel are required for deauth/evil twin.
- Use an external Wi-Fi adapter with monitor/injection for all wireless attacks; the built-in Zero 2 W radio is managed/AP only.
- For Ethernet features, ensure the active interface is wired and has carrier; the UI refuses to run if the link is down.
- Stealth mode blocks active scans/attacks except the Stealth Recon pipeline; switch to Default/Aggressive/Custom to run active modules.
- Autopilot requires a wired interface with link; Stealth operation mode only allows the Stealth autopilot variant.
- MITM + DNS spoof uses templates under `DNSSpoof/sites`; pick a site before launching the DNS spoof add-on.
- Handshake cracking expects JSON exports generated by the native wireless stack (`handshake_export_*.json`).
- Set `RUSTYJACK_NFTABLES_LOG=1` to log nf_tables packet matches to journalctl with a `[NFTABLE]` prefix.
- The toolbar shows autopilot status when running (whether started from the UI or via the CLI).

## Troubleshooting

**Display & Hardware**:
- Blank LCD: confirm `/dev/spidev0.0` exists and `dtparam=spi=on` + `dtoverlay=spi0-2cs` are in `/boot/firmware/config.txt`; reboot after installer changes.
- Buttons not responding: ensure the UI user is in `gpio` and the pull-up line `gpio=6,19,5,26,13,21,20,16=pu` exists in config.txt.

**Wireless Operations**:
- Wireless attacks fail: verify you are using an adapter with monitor/injection; use Settings → WiFi Drivers if a USB chipset needs firmware/DKMS.
- Hotspot: set upstream/AP interfaces when starting; randomize SSID/password from the hotspot menu if conflicts occur.

**Network & DNS**:
- DNS resolution issues: Check that `/etc/resolv.conf` is a symlink to `/var/lib/rustyjack/resolv.conf` and verify NetworkManager is purged with `dpkg -s network-manager` (should show "not installed").
- NetworkManager conflicts: If you see DNS or networking issues after installation, confirm NetworkManager was fully removed: `sudo apt-get purge network-manager && sudo apt-get autoremove`.

**USB & Storage**:
- USB mount failures: Verify the device is writable, check permissions on `/var/lib/rustyjack/mounts/`, and ensure you selected the correct mount mode (ReadOnly/ReadWrite).
- Transfer to USB not working: Ensure USB device is mounted and writable; check for sufficient space.

**FDE Operations**:
- FDE preparation/migration: These operations are **destructive and irreversible**. Always backup data before running. FDE requires a USB key and will format target devices.
- FDE boot issues: Verify the USB key is inserted and LUKS passphrase is correct.

**Service & Logs**:
- Service issues: `journalctl -u rustyjack-ui -f` and `systemctl status rustyjack-ui`.
- Daemon not responding: Check `systemctl status rustyjackd` and verify socket exists: `ls -l /run/rustyjack/rustyjackd.sock`.

## Legal

Use only for authorized testing, research, and education. The authors assume no liability for misuse, damage, or legal consequences. You are responsible for complying with all applicable laws.
