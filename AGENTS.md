# AGENTS.md

This project targets a Raspberry Pi Zero 2 W equipped with an Ethernet HAT and a Waveshare 128×128 LCD HAT (ST7735S). The UI is rendered in landscape by default via `RUSTYJACK_DISPLAY_ROTATION=landscape` and the installer sets that environment variable for the systemd service.

Hardware specifics drawn from WAVESHARE_PINS.md and WAVESHARE_BUTTONS.md:
- Display pins (BCM): DC=25, RST=27, BL=24; SPI: SCLK=11, MOSI=10, CS=8. Backlight lives on BCM24 and can be toggled with `gpioset gpiochip0 24=1`.
- Input pins (BCM): UP=6, DOWN=19, LEFT=5, RIGHT=26, PRESS=13; KEY1=21, KEY2=20, KEY3=16. Button mapping in the UI: Up/Down move selection, Left is back, Right/Select accepts, Key1 refreshes, Key2 returns to main menu, Key3 opens reboot confirmation.
- GPIO pull-ups are expected in `/boot/firmware/config.txt` (or `/boot/config.txt`), using `gpio=6,19,5,26,13,21,20,16=pu`; the installers write this line and request a reboot so input remains stable.

Software/runtime expectations:
- Built and run on Linux (Pi OS) with root privileges via systemd service, so `CAP_NET_ADMIN` is available.
- Dependencies are installed by `install_rustyjack.sh` and `install_rustyjack_dev.sh`: `iproute2` (`ip`), `isc-dhcp-client` (`dhclient`), `network-manager` (`nmcli`), `wpasupplicant` (`wpa_cli`), `wireless-tools`, `iw`, `hostapd`, `dnsmasq`, `rfkill`, plus build and firmware packages. When adding features that call new system binaries, update both installers accordingly.
- Installers now:
  - Remount `/` read-write if needed (fresh Pi images can boot `ro`).
  - Claim `/etc/resolv.conf` for Rustyjack (plain root-owned file) and reclaim it after apt installs so route/DNS enforcement can write reliably.
  - Disable competing DNS managers (systemd-resolved, dhcpcd, resolvconf if present) and set NetworkManager `dns=none` so `nmcli` remains available but does not rewrite `resolv.conf`. This ensures Rustyjack has sole control of DNS on the dedicated device.

MAC randomization flow:
- UI uses `rustyjack-evasion::MacManager` for secure, locally administered MACs and will prefer vendor-matched OUIs based on the current interface’s OUI. After changing MAC it triggers `dhclient -r && dhclient` and signals reconnect via `wpa_cli reconnect` or `nmcli device reconnect` if present.

Built-in wireless (Raspberry Pi Zero 2 W):
- Chipset: Cypress/Infineon CYW43436 (2.4 GHz 802.11b/g/n, single-stream HT20, ~72 Mbps max link). No 5 GHz support.
- Modes supported by the stock driver: managed (client) and limited AP mode (2.4 GHz, 20 MHz). Suitable for `rustyjack-core` scanning/association and for UI status queries.
- Monitor/sniff/injection: not supported by the stock CYW43436 driver. Deauth, targeted handshake capture, and Evil Twin features require a USB Wi-Fi adapter with monitor+injection (e.g., ath9k/ath9k_htc or rtl8812au with proper driver). Passive probe sniffing with the built-in radio would require Nexmon patches; otherwise use an external adapter.
- Channel coverage: 2.4 GHz only; Rustyjack features that assume 5 GHz (e.g., channel setting beyond 14 or dual-band AP) need an external dual-band adapter.

Project structure (selected):
- `rustyjack-core/` — shared logic, evasion helpers, configs.
- `rustyjack-evasion/` — MAC management, tx power control, passive mode utilities.
- `rustyjack-wireless/` — low-level wireless operations (nl80211, injection, scans).
- `rustyjack-ui/` — embedded display UI for the Waveshare HAT.
- `scripts/` — helper shell scripts (e.g., WiFi driver installer).
- `install_rustyjack.sh`, `install_rustyjack_dev.sh` — production and debug installers that build and deploy the UI service.
- `WAVESHARE_PINS.md`, `WAVESHARE_BUTTONS.md` — validated pinout and button behavior references.
- `rustyjack-ethernet/` — Rust-only Ethernet recon (ICMP sweep + TCP port scan) used by the UI Ethernet menu.
- Loot storage: wireless captures are grouped per target under `loot/Wireless/<target>/` (target = SSID, else BSSID); reuse that when saving handshakes, PMKIDs, logs. Hotspot device connection history is logged to `loot/Hotspot/device_history.txt` with timestamps, MAC, IP, and hostname for every device that obtains a DHCP lease.
- MAC randomization: `rustyjack-evasion::MacManager` sets locally administered, unicast MACs with CSPRNG; vendor-match OUI from the current interface when available.
- UI dialogs/windows must require explicit user confirmation before advancing; do not auto-dismiss after a timeout or hide errors without acknowledgment.

Style guard:
- Don't add any emojis and remove emojis if found in the code.
