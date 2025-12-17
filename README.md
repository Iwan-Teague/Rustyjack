# Rustyjack

Portable Raspberry Pi Zero 2 W network toolkit with a Waveshare 1.44" LCD + joystick UI. Written in Rust, shipped as a root systemd service for on-device use. Additional documentation is in `docs/`.

> Authorized testing and education only. Verify permissions before running any operation.

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Hardware & Wiring](#hardware--wiring)
- [Controls](#controls)
- [UI Features](#ui-features)
- [Installation](#installation)
- [Configuration & Paths](#configuration--paths)
- [Usage Tips](#usage-tips)
- [Troubleshooting](#troubleshooting)
- [Legal](#legal)

## Project Overview

- Linux-only UI (compile guard in `rustyjack-ui/src/main.rs`); designed for a Pi Zero 2 W with an Ethernet HAT.
- Runs as `rustyjack.service` (root) with `RUSTYJACK_DISPLAY_ROTATION=landscape` by default.
- Status overlay shows CPU temp/load, memory, disk, uptime, target SSID/BSSID/channel, active interface, current/original MAC, and autopilot status if the CLI autopilot is running.
- Built-in Cypress/Infineon radio cannot monitor/inject; all wireless attacks require an external adapter that supports monitor + injection.

## Architecture

```
rustyjack-ui/          LCD UI: menus, rendering, GPIO buttons, dashboards
rustyjack-core/        Orchestrator CLI: Wi-Fi/Ethernet ops, hotspot, MITM, loot, autopilot, system update
rustyjack-wireless/    Native wireless ops (nl80211 monitor/injection, deauth, PMKID, karma, evil twin, hotspot, cracking helpers)
rustyjack-evasion/     MAC/hostname evasion, vendor-aware MAC generation, TX power/passive helpers
rustyjack-ethernet/    LAN discovery, TCP port scan, banner grabs, inventory helpers
DNSSpoof/              Captive portal templates for DNS spoof/MITM pipelines
scripts/               Wi-Fi driver installer + USB hotplug helper (udev rule included)
wordlists/             Bundled password lists for handshake cracking
img/                   Splash assets for the LCD (`rustyjack.png`)
rustyjack.service      Systemd unit (root, sets display rotation and RUSTYJACK_ROOT)
install_rustyjack*.sh  Production/dev installers for Pi OS targets
```

Runtime directories are created by the installers:
`loot/` (Wireless, Ethernet, reports), `wifi/profiles/`, `DNSSpoof/captures/`, and `gui_conf.json` (pins, colors, settings).

## Hardware & Wiring

- Target: Raspberry Pi Zero 2 W + Ethernet HAT + Waveshare 1.44" LCD HAT (ST7735S, 128x128).
- Display rotation: `RUSTYJACK_DISPLAY_ROTATION=landscape` (default); set to `portrait` to rotate back.
- Backlight: BCM24 held high by the UI; you can test with `gpioset gpiochip0 24=1`.
- Buttons are active-low; installers add GPIO pull-ups via `/boot/firmware/config.txt` (or `/boot/config.txt`): `gpio=6,19,5,26,13,21,20,16=pu`.

**Display pins (from `rustyjack-ui/src/display.rs`):**

| Signal | BCM GPIO |          Notes          |
|--------|----------|-------------------------|
| DC     | 25       | Data/command select     |
| RST    | 27       | Reset (active low)      |
| BL     | 24       | Backlight control       |
| SPI    | spidev0.0 (SCLK 11, MOSI 10, CS 8) | 

**Input pins (defaults from `rustyjack-ui/src/config.rs`):**

| Control | BCM GPIO |           Purpose           |
|---------|----------|-----------------------------|
| UP      | 6        | Joystick up                 |
| DOWN    | 19       | Joystick down               |
| LEFT    | 5        | Back                        |
| RIGHT   | 26.      | Select/forward              |
| PRESS   | 13       | Center press (select)       |
| KEY1    | 21       | Refresh/redraw              |
| KEY2    | 20       | Jump to main menu           |
| KEY3    | 16       | Reboot confirmation dialog  |

Pins and colors can be customized in `gui_conf.json`; defaults are created automatically.

## Controls

|        Button        |                     Action in UI                     |
|----------------------|------------------------------------------------------|
| Up / Down            | Move selection                                       |
| Left                 | Back/exit dialog                                     |
| Right / Center press | Select/confirm                                       |
| Key1                 | Refresh current view                                 |
| Key2                 | Jump to main menu                                    |
| Key3                 | Open reboot confirmation (requires explicit confirm) |

## UI Features

### System, modes, and dashboards

- **Operation Mode**: Stealth (blocks active ops, forces MAC/hostname randomization + 1 dBm TX), Default, Aggressive (max TX), Custom (keep manual toggles).
- **Dashboards**: Cycle System Health, Target Status, and MAC Status views from the main menu.
- **Colors**: Pick palette entries directly from the UI.
- **Logs toggle**: Enables/disables logging by setting/clearing `RUSTYJACK_LOGS_DISABLED`; **Purge Logs** removes log files under loot/Responder.
- **System**: Restart, Secure Shutdown (best-effort RAM wipe then poweroff), Complete Purge (removes binaries, service, loot, udev helpers; exits UI).
- **Wi-Fi driver installer**: Runs `scripts/wifi_driver_installer.sh`, detecting USB chipsets and installing/compiling drivers; progress is shown in the UI (`/var/log/rustyjack_wifi_driver.log`).
- **Autopilot (main menu)**: Start Standard/Aggressive/Stealth/Harvest runs or stop/view status. Requires an active wired interface with link; blocked when Operation Mode is Stealth unless you choose the Stealth autopilot. Optional DNS spoof site selection when starting. Toolbar shows `AP:<mode>` while running.
- **Wireless menus split**: Main menu → Wireless. Inside: Get Connected (Scan + Recon/Offence folders plus Connect), Post Connection (Recon + Offence items like Responder/DNS spoof/reverse shell), and Hotspot. Selecting an active interface in Hardware Detect enforces the default route and brings other interfaces down; non-selected Wi-Fi adapters are rfkill-blocked. Hotspot temporarily unblocks/uses its AP + upstream interfaces while running.

### Hardware Detect

- Calls `HardwareCommand::Detect` to list wired and wireless interfaces with state and IP.
- Lets you set the active interface used by Wi-Fi/Ethernet features (saved to `gui_conf.json`).

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
- **Hotspot** (Wireless Access menu): Select upstream + AP interfaces from detected hardware, start/stop hostapd+dnsmasq, randomize SSID/password (`rustyjack_wireless::random_*`). Status view shows running SSID/password and lets you turn it off.

### Obfuscation & Identity

- **MAC controls**: Auto MAC toggle, Randomize Now (vendor-aware: reuses interface OUI when possible, sets locally administered bit, renews DHCP and signals `wpa_cli`/`nmcli`), Set Vendor MAC (pick from `rustyjack-evasion` vendor table), Restore MAC (uses saved original or hardware address).
- **Hostname**: Auto toggle + Randomize Now (via `SystemCommand::RandomizeHostname`).
- **TX Power**: Stealth 1 dBm, Low 5 dBm, Medium 12 dBm, High 18 dBm, Maximum (via `iw`/`iwconfig`).
- **Passive mode toggle**: Stores preference (used for mode presets); Passive Recon action is informational.

### Ethernet Recon (active interface must be wired and have link)

- **LAN Discovery**: ICMP/ARP sweep with TTL OS hints; saves loot path and host list.
- **Port Scan**: TCP connect scan (defaults to gateway if no target) with banner grabs; timeout presets 0.5/1/2/5s per port; saves loot/banners.
- **Device Inventory**: mDNS/LLMNR/NetBIOS/WSD probes + port data; saves inventory JSON/text to loot.
- **MITM Capture**: ARP spoof + tcpdump PCAP under `loot/Ethernet/<label>/`; optional DNS spoof using `DNSSpoof/sites/<site>` templates; shows victim counts/pcap paths. **MITM Status** tracks visit/credential logs for the chosen site; **Stop MITM/DNS** tears down both.
- **Site Credential Capture pipeline**: Classifies "human" hosts, ARP poisons up to the chosen cap, launches DNS spoof site, captures PCAP/visit/credential logs; loot and PCAP paths are reported.

### Loot, reports, and export

- **Loot browser**: Navigate `loot/Wireless` and `loot/Ethernet` targets, drill into folders, and view files with a scrollable viewer.
- **Reports**: Builds combined Ethernet/Wi-Fi report to `loot/reports/<network>/report_<ts>.txt` (summaries, insights, next steps, artifact sweep, MAC usage notes).
- **Discord upload**: Zips `loot/`, `loot/reports/`, and `Responder/logs` into a temp archive and posts to the webhook in `discord_webhook.txt`.
- **Transfer to USB**: Copies loot and Responder logs to `Rustyjack_Loot` on the first writable USB block device mount.
- **Logs toggle/purge**: Logging can be disabled globally; Purge Logs removes `.log` files and log-like artifacts under loot/Responder.

### CLI-only extras (via `rustyjack-core`)

Responder on/off, DNS spoof start/stop, reverse shell launcher, and transparent bridge start/stop exist in the core CLI but are not exposed as LCD menu items.

## Installation

**Requirements**

- Raspberry Pi OS Lite (32/64-bit) on a Pi Zero 2 W (or Pi 4/5).
- External Wi-Fi adapter with monitor + injection for wireless attacks.
- Root privileges (systemd service runs as root; wireless ops need CAP_NET_ADMIN/RAW).

**Steps**

1. Flash Raspberry Pi OS Lite and enable SSH if needed.
2. SSH to the Pi, become root: `sudo su -`.
3. Clone the project: `git clone https://github.com/Iwan-Teague/Rusty-Jack.git Rustyjack && cd Rustyjack`.
4. Run the installer: `chmod +x install_rustyjack.sh && ./install_rustyjack.sh`
   - Installs packages: build-essential, pkg-config, libssl-dev, DKMS toolchain, `nmap`, `ncat`, `tcpdump`, `arp-scan`, `dsniff`, `ettercap-text-only`, `php`, `procps`, `network-manager`, `wireless-tools`, `wpa_supplicant`, firmware for Realtek/Atheros/Ralink, git, i2c-tools, curl.
   - Enables I2C/SPI overlays, `dtoverlay=spi0-2cs`, and GPIO pull-ups for all buttons.
   - Ensures ~2 GB swap for compilation, builds `rustyjack-ui` (release), installs to `/usr/local/bin/`.
   - Creates `loot/{Wireless,Ethernet,reports}`, `wifi/profiles/sample.json`, and keeps WLAN interfaces up.
   - Installs Wi-Fi driver helper scripts + udev rule, sets `RUSTYJACK_ROOT`, installs/enables `rustyjack.service` (root, landscape rotation), starts the service, and reboots unless `SKIP_REBOOT=1` or `NO_REBOOT=1`.
   - Claims `/etc/resolv.conf` for Rustyjack (plain root-owned file), disables competing DNS managers (systemd-resolved, dhcpcd, resolvconf if present), and sets NetworkManager `dns=none` so `nmcli` stays available but does not rewrite `resolv.conf`.
   - Remounts `/` read-write if needed on fresh images to allow installs/edits.
5. After reboot, the LCD shows the menu. Service status: `systemctl status rustyjack`.

`install_rustyjack_dev.sh` is available for development setups and follows the same dependency/build steps.

## Configuration & Paths

- `gui_conf.json` (auto-created): pins, colors, active interface, target SSID/BSSID/channel, MAC/hostname/passive toggles, hotspot credentials, log/Discord toggles.
- `discord_webhook.txt`: webhook URL for Discord uploads.
- `wifi/profiles/*.json`: saved Wi-Fi profiles used by Connect Known Network (sample provided).
- `loot/`: wireless and Ethernet captures; pipelines are under `loot/Wireless/<target>/pipelines/`; reports live in `loot/reports/`.
- `DNSSpoof/sites/`: portal templates for DNS spoof/MITM; captures go to `DNSSpoof/captures/`.
- `Responder/logs/`: Responder output (included in Discord uploads/USB transfer if present).
- Splash image: `img/rustyjack.png` (shown on boot).
- Systemd unit: `rustyjack.service` sets `RUSTYJACK_DISPLAY_ROTATION` and `RUSTYJACK_ROOT`.

## Usage Tips

- Run **Hardware Detect** first and set the active interface (needed for Wi-Fi and Ethernet menus).
- Set a target via **Scan Networks** before deauth/evil twin/PMKID/pipelines; BSSID and channel are required for deauth/evil twin.
- Use an external Wi-Fi adapter with monitor/injection for all wireless attacks; the built-in Zero 2 W radio is managed/AP only.
- For Ethernet features, ensure the active interface is wired and has carrier; the UI refuses to run if the link is down.
- Stealth mode blocks active scans/attacks except the Stealth Recon pipeline; switch to Default/Aggressive/Custom to run active modules.
- Autopilot requires a wired interface with link; Stealth operation mode only allows the Stealth autopilot variant.
- MITM + DNS spoof uses templates under `DNSSpoof/sites`; pick a site before launching the DNS spoof add-on.
- Handshake cracking expects JSON exports generated by the native wireless stack (`handshake_export_*.json`).
- The toolbar shows autopilot status when running (whether started from the UI or via the CLI).

## Troubleshooting

- Blank LCD: confirm `/dev/spidev0.0` exists and `dtparam=spi=on` + `dtoverlay=spi0-2cs` are in `/boot/firmware/config.txt`; reboot after installer changes.
- Buttons not responding: ensure the service runs as root and the pull-up line `gpio=6,19,5,26,13,21,20,16=pu` exists in config.txt.
- Wireless attacks fail: verify you are using an adapter with monitor/injection; use Settings -> WiFi Drivers if a USB chipset needs firmware/DKMS.
- Service issues: `journalctl -u rustyjack -f` and `systemctl status rustyjack`.
- Hotspot: set upstream/AP interfaces when starting; randomize SSID/password from the hotspot menu if conflicts occur.

## Legal

Use only for authorized testing, research, and education. The authors assume no liability for misuse, damage, or legal consequences. You are responsible for complying with all applicable laws.
