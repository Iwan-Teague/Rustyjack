<p align="center">
  <img src="https://img.shields.io/badge/platform-Raspberry%20Pi-red?style=flat-square&logo=raspberry-pi">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square&logo=rust">
  <img src="https://img.shields.io/badge/LCD-ST7735%20128x128-blue?style=flat-square">
  <img src="https://img.shields.io/badge/license-Educational%20Use-green?style=flat-square">
</p>

<div align="center">
  <h1>Rustyjack</h1>

  <img src="img/rustyjack.bmp" alt="Rustyjack Logo" width="300"/>

  <p>
    <strong>Portable Network Offensive Security Toolkit</strong><br>
    100% Rust • LCD Interface • Raspberry Pi<br>
    <em>Pure Rust offensive security toolkit</em>
  </p>

  <p><strong>WARNING: LEGAL DISCLAIMER</strong></p>

  <p>This tool is for <strong>authorized security testing and educational purposes ONLY</strong>.</p>

  <p>Unauthorized access to computer systems is <strong>ILLEGAL</strong> under:</p>
  <p>Computer Fraud and Abuse Act (USA)<br>
  Computer Misuse Act (UK)<br>
  Similar laws worldwide</p>

  <p><strong>Always obtain written permission before testing any network or system.</strong></p>

  <p>The authors accept <strong>NO LIABILITY</strong> for misuse or illegal activities.<br>
  You are <strong>solely responsible</strong> for your actions.</p>

</div>

---

## Table of Contents

- [What is Rustyjack?](#what-is-rustyjack)
- [Features](#features)
- [Hardware Requirements](#hardware-requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Loot & Data](#loot--data)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

---

## What is Rustyjack?

**Rustyjack** is a self-contained offensive security platform that runs on a Raspberry Pi with an LCD screen. It provides penetration testing tools accessible through a simple joystick interface—no keyboard, monitor, or external computer needed.

### What Makes It Special?

- **100% Rust** - Standalone Rust toolkit
- **Standalone** - LCD screen, buttons, all tools built-in
- **Portable** - Pocket-sized, battery-powered option
- **Complete** - Recon, credential capture, phishing, and other integrated tools
- **On-device hotspot** - Start a NATed hotspot with configurable SSID/password

### Architecture

A high-level, current view of the project's structure. Rustyjack is split into two focused components — a compact UI for the on-device display and a separate core that runs orchestration and long-lived tasks.

```
┌────────────────────────────────────────┐
│               Rustyjack                │
├──────────────┬─────────────────────────┤
│ rustyjack-ui │     rustyjack-core      │
│ (LCD + GPIO) │     (Orchestration)     │
│ - Menu / UX  │ - Task runner / CLI     │
│ - Display    │ - Loot management       │
│ - Button I/O │ - System actions        │
└──────────────┴─────────────────────────┘

UI → dispatches commands to → Core → interacts with OS and filesystem

Notes:
- The UI process (`rustyjack-ui`) owns the display, button handling and menu presentation.
- The core process (`rustyjack-core`) executes longer-running actions, maintains loot, and performs system operations. It calls:
  - `rustyjack-wireless` for nl80211/monitor/injection/handshakes
  - `rustyjack-evasion` for MAC randomization and TX power helpers
  - `rustyjack-ethernet` for ICMP sweep + TCP port scan
```

---

## Features


### Loot & Data

**On-device loot viewer:**
- Browse captured output and logs (Wireless and Ethernet)
- View device-generated logs and export files
- Navigate and open files using LCD buttons
- Wireless loot is grouped per target under `loot/Wireless/<target>/` (target = SSID, else BSSID). Files are timestamped and prefixed by type (e.g., `handshake_<target>_<timestamp>.pcap`, `log_deauth_<target>_<timestamp>.txt`).
- Ethernet loot lives under `loot/Ethernet/` (LAN discovery / port scans, timestamped).

**Ethernet recon:**
- LAN discovery on the wired interface (ARP + ICMP, TTL-based OS hints)
- Quick TCP connect port scan (defaults to gateway) with basic banner grabs

**Hotspot:**
- Start/stop a NATed hotspot (hostapd + dnsmasq) from the UI
- Defaults to SSID/password `rustyjack`, with quick randomize buttons
- Choose upstream (internet) interface and AP interface at launch

**Discord integration:**
- Manual upload of ZIP loot archives via the UI when configured
- Formatted embeds for notifications and metadata
- File attachments up to configured size limits


### User Interface

**Interface layout:**
- Single list-based menu with status toolbar (no grid/carousel modes)
- Key1 refreshes the current view, Key2 jumps to the main menu, Key3 opens reboot confirmation

**Customization and system:**
- RGB color themes (background, border, text, selection)
- Save/refresh configuration
- Temperature and CPU overlay on the toolbar
- System menu currently exposes restart

---

## Hardware Requirements

### Required Components

| Item | Specification | Purpose |
|------|---------------|---------|
| **Raspberry Pi** | Zero 2 W (recommended)<br>or Pi 4 / Pi 5 | Main computer |
| **LCD HAT** | Waveshare 1.44" LCD HAT<br>ST7735, 128×128, SPI | Display + buttons |
| **MicroSD Card** | 16GB+ (Class 10) | Operating system |
| **Power Supply** | 5V 2.5A USB-C/Micro-USB | Power |

### Optional Components

| Item | Purpose |
|------|---------|
| **Ethernet HAT** | 3 USB + 1 Ethernet (Pi Zero) |
| **Battery Pack** | Portable power |
| **USB Storage / Drive** | Attach external storage for backup or loot export |

### Pin Configuration

**Waveshare 1.44" LCD HAT Pinout:**

| Component | GPIO Pin | Function |
|-----------|----------|----------|
| LCD Data/Command | GPIO 25 | DC (data/command select) |
| LCD Reset | GPIO 27 | RST (hardware reset) |
| LCD Backlight | GPIO 24 | BL (backlight control) |
| LCD SPI | `/dev/spidev0.0` | Data transfer |
| Joystick Up | GPIO 6 | Button input |
| Joystick Down | GPIO 19 | Button input |
| Joystick Left | GPIO 5 | Button input |
| Joystick Right | GPIO 26 | Button input |
| Joystick Press | GPIO 13 | Center button |
| Key 1 | GPIO 21 | Refresh current view |
| Key 2 | GPIO 20 | Return to main menu |
| Key 3 | GPIO 16 | Reboot confirmation |

**Wireless radios:** The built-in Pi Zero 2 W radio (CYW43436) supports managed/AP only (no monitor/injection). Deauth/handshake/evil twin/Karma require an external USB adapter that supports monitor + injection (e.g., AR9271/ath9k_htc, MT7612U, RTL8812AU with driver).

**All pins configured in:** `/root/Rustyjack/gui_conf.json`

---

## Button controls

The on-HAT buttons and joystick map directly to menu navigation and actions. Below is a concise mapping of logical controls (and the GPIO pins used — see the Pin Configuration table above).

- **Up / Down** (Joystick Up / Down) — Navigate lists and menus.
- **Left** (Joystick Left) — Back / return to previous menu.
- **Right** (Joystick Right) — Select / activate highlighted item.
- **Center press** (Joystick Press) — Confirm / secondary select.
- **Key 1** — Refresh/redraw the current view.
- **Key 2** — Jump directly to the main menu.
- **Key 3** — Open reboot confirmation (requires explicit confirmation).

How these controls behave:
- Short-press Right or Center confirms selections and triggers actions.
- Left always behaves as a 'Back' while on dialogs or submenus.
- Key 1 refreshes the current screen content.
- Key 2 exits to the main menu.
- Key 3 asks for reboot confirmation before proceeding.

> Tip: button behaviour and pin mapping can be customized by editing `gui_conf.json` (see `config` module in the UI source).


---

## Installation

### Part 1: Flash Operating System

**1. Download Raspberry Pi Imager**

Download from: https://www.raspberrypi.com/software/

**2. Configure in Imager**

- **Device:** Raspberry Pi Zero 2 W (or your model)
- **OS:** Raspberry Pi OS Lite (32-bit or 64-bit)
- **Settings:**
  - Enable SSH
  - Set username: `pi` (or your choice)
  - Set password
  - Configure WiFi (optional)
  - Set hostname: `rustyjack` (optional)

**3. Flash to SD Card**

- Insert microSD card
- Select storage device
- Click "Write"
- Wait for completion (~5 minutes)

**4. Boot Raspberry Pi**

- Insert SD card into Pi
- Connect LCD HAT
- Connect power
- Wait for first boot (~2 minutes)

### Part 2: Install Rustyjack

**1. SSH into Raspberry Pi**

```bash
ssh pi@rustyjack.local
# Or use IP address: ssh pi@192.168.1.XXX
```

**2. Switch to Root User**

```bash
sudo su -
```

**3. Clone Repository**

```bash
cd /root
git clone https://github.com/Iwan-Teague/Rusty-Jack.git Rustyjack
cd Rustyjack
```

**4. Run Installation Script**

```bash
chmod +x install_rustyjack.sh
./install_rustyjack.sh
```

**What it does:**
- Installs Rust toolchain (rustup) and required packages (iproute2, dhclient, iw, wireless-tools, hostapd, dnsmasq, etc.)
- Enables SPI/I2C overlays and GPIO pull-ups for the Waveshare buttons in `/boot/firmware/config.txt` (or `/boot/config.txt`)
- Builds and installs the `rustyjack-ui` binary to `/usr/local/bin/` (core/evasion/wireless are linked as libraries)
- Sets up udev rules for USB Wi-Fi hotplug and installs helper scripts
- Creates systemd service `rustyjack.service` (runs as root, sets `RUSTYJACK_DISPLAY_ROTATION=landscape`)
- Creates required directories (loot, wifi profiles) and starts the service

**Time:** ~10-15 minutes (Rust compilation is CPU-intensive)

**5. Reboot**

```bash
reboot
```

**6. Verify Installation**

After reboot, the LCD should display the Rustyjack menu.

Check service status via SSH:

```bash
systemctl status rustyjack
```

Expected output:
```
● rustyjack.service - Rustyjack UI Service (100% Rust)
   Loaded: loaded (/etc/systemd/system/rustyjack.service; enabled)
   Active: active (running)
   Main PID: 456
```

**View logs:**
```bash
journalctl -u rustyjack -f
```

### Part 3: Configure (Optional)

**Discord Webhook Setup:**

1. Create webhook in Discord (Server → Channel → Integrations → Webhooks)
2. Copy webhook URL
3. Edit file:
   ```bash
   nano /root/Rustyjack/discord_webhook.txt
   ```
4. Paste URL, save, exit
5. Restart service:
   ```bash
   systemctl restart rustyjack
   ```

**Network configuration:**

Configure WiFi and network interfaces using the host OS or your preferred tooling (SSH / NetworkManager / wpa_supplicant).

### Updating

```bash
cd /root/Rustyjack
git pull
./install_rustyjack.sh
reboot
```

Backup loot before updating:
```bash
tar -czf ~/loot_backup_$(date +%Y%m%d).tar.gz loot/
```

---

## Usage

### Button Controls

| Button | Action |
|--------|--------|
| **↑ Up** | Scroll up / Previous item |
| **↓ Down** | Scroll down / Next item |
| **→ Right** | Select / Enter submenu / Confirm |
| **← Left** | Back / Cancel / Previous menu |
| **○ Select** | Same as Right (center button) |
| **KEY1** | Refresh / redraw current view |
| **KEY2** | Jump to main menu |
| **KEY3** | Reboot confirmation (requires confirm) |

### Menu Structure (current)

```
Main Menu
│
├─ Hardware Detect
├─ WiFi Attacks
│  ├─ Scan Networks
│  ├─ Attack Pipelines
│  ├─ Deauth Attack
│  ├─ Evil Twin AP
│  ├─ Karma Attack
│  ├─ PMKID Capture
│  ├─ Probe Sniff
│  ├─ Crack Handshake
│  ├─ Connect Network
│  └─ Hotspot (start/stop)
├─ Ethernet Recon
│  ├─ LAN Discovery (ICMP sweep)
│  └─ Port Scan (quick TCP connect)
├─ Obfuscation
│  ├─ MAC randomize toggle / now / restore
│  ├─ Passive mode toggle + Passive Recon
│  └─ TX Power
├─ View Dashboards
├─ Settings
│  ├─ Toggle/Upload Discord
│  ├─ Options (colors, config)
│  ├─ System (restart)
│  └─ WiFi Drivers
└─ Loot
   ├─ Transfer to USB
   ├─ Wireless Captures
   └─ Ethernet Loot
```

Note: Ethernet Recon now runs real scans; LAN Discovery auto-detects the wired interface/CIDR, and Port Scan defaults to the gateway if no target is provided.

### Quick Start Examples

Here are a few things you can do from the device's main menu (keeps the current trimmed feature set in mind):

- Run hardware detection: Main Menu → Hardware Detect
- Scan networks and set targets: Main Menu → WiFi Attacks → Scan Networks
- Launch an attack pipeline: Main Menu → WiFi Attacks → Attack Pipelines
- Deauth/handshake capture: Main Menu → WiFi Attacks → Deauth Attack
- View dashboards for system and attack metrics: Main Menu → View Dashboards
- Browse wireless/ethernet loot or transfer to USB: Main Menu → Loot

---

## Core Capabilities

Rustyjack is now focused on providing a compact UI for the device and a core orchestration process. The following capabilities are maintained in the trimmed-down project:

- UI / LCD-driven menu and controls (`rustyjack-ui`)
- Hardware detection (interface and peripheral detection)
- Wireless attacks: deauth/handshake, PMKID, probe sniff, evil twin, karma, attack pipelines (via `rustyjack-wireless`)
- Evasion: MAC randomization, passive mode toggle, TX power adjust (`rustyjack-evasion`)
- Ethernet recon: wired LAN discovery (ARP+ICMP) and quick port scan with banners (loot saved under `loot/Ethernet`)
- Loot viewer and transfer utilities (wireless and ethernet captures)
- Discord webhook integration for uploading loot and notifications
- System management: restart from the System menu; configuration refresh/save from Options; updates via the installer script

---

## Troubleshooting

### LCD Not Working

**Symptom:** Blank, white, or garbled display

**Checks:**
```bash
# 1. SPI enabled?
ls -l /dev/spidev0.0
# Should exist

# 2. Boot config correct?
grep spi /boot/firmware/config.txt
# Should show: dtparam=spi=on

# 3. Service running?
systemctl status rustyjack
```

**Fix:**
```bash
echo "dtparam=spi=on" >> /boot/firmware/config.txt
echo "dtoverlay=spi0-2cs" >> /boot/firmware/config.txt
reboot
```

### Buttons Not Responding

**Symptom:** Pressing buttons does nothing

**Checks:**
```bash
# GPIO device exists?
ls -l /dev/gpiochip0

# Service running as root?
systemctl status rustyjack | grep User
# Should show: User=root
```

**Fix:** Service must run as root (configured by install script)

### Service Won't Start

**Checks:**
```bash
# View errors
journalctl -u rustyjack -xe

# Test binary manually
sudo /usr/local/bin/rustyjack-ui
```

**Fix:**
```bash
# Rebuild from source
cd /root/Rustyjack/rustyjack-ui
cargo build --release
sudo install target/release/rustyjack-ui /usr/local/bin/
sudo systemctl restart rustyjack
```

### Network Issues

If you encounter networking problems, prefer using the host OS to configure interfaces and routing. The UI focuses on presentation and orchestration — network configuration and advanced wireless tooling should be managed via the OS and CLI tools on the device.

<!-- Removed legacy attack feature references -->

### Out of Disk Space

**Clean up:**
```bash
# Remove old logs
journalctl --vacuum-time=7d

# Clean Rust build cache
cd /root/Rustyjack
cd rustyjack-core && cargo clean
cd ../rustyjack-ui && cargo clean

# Archive loot
tar -czf ~/loot_$(date +%Y%m%d).tar.gz loot/
rm -rf loot/*
mkdir -p loot/Wireless loot/Ethernet
```

---

## Credits

### Original Project

**Rustyjack** - Created by [@Iwan-Teague](https://github.com/Iwan-Teague)  
Repository: https://github.com/Iwan-Teague/Rusty-Jack.git

### Rust Libraries

- **embedded-graphics** - James Waples
- **st7735-lcd** - Various contributors
- **gpio-cdev** - posborne
- **clap** - Kevin K.
- **serde** - David Tolnay

---

## License

**Educational and Authorized Testing Only**

This software is provided for:
- Security education and research
- Authorized penetration testing
- CTF competitions
- Personal lab environments

This software is **NOT** for:
- Unauthorized access
- Malicious activities
- Breaking laws
- Causing harm

**You are solely responsible for your use of this tool.**

**The authors provide NO WARRANTY and accept NO LIABILITY for misuse.**

---

## Legal Warning

```
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   WARNING  UNAUTHORIZED ACCESS IS A FEDERAL CRIME      ║
║                                                       ║
║   Violating computer security laws can result in:    ║
║   • Heavy fines ($100,000+)                          ║
║   • Prison sentences (up to 20 years)                ║
║   • Permanent criminal record                        ║
║   • Civil lawsuits                                   ║
║                                                       ║
║   ALWAYS obtain written permission before testing.   ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
```

---

<div align="center">

**Rustyjack - Portable Offensive Security**

*Built with Rust • Powered by Raspberry Pi • Made for Security Professionals*

</div>
