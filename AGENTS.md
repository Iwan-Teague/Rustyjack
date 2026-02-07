# AGENTS.md

This project targets a Raspberry Pi Zero 2 W equipped with an Ethernet HAT and a Waveshare LCD HAT (ST7735S profile default `128x128`). The UI renders with runtime display capabilities/layout metrics, keeps the physical control model fixed at exactly 8 buttons, and defaults to landscape via `RUSTYJACK_DISPLAY_ROTATION=landscape` (set by installer service env).

Display support policy:
- Lowest supported layout target is `128x128`.
- Smaller displays are allowed in best-effort mode and should log `UNSUPPORTED_DISPLAY_SIZE` warnings.
- Startup flow is `detect backend -> query capabilities -> calibrate only when needed -> cache effective geometry`.
- Recalculation is manual-only from `Settings -> Display`.

Hardware specifics drawn from waveshare_gpio_pin_mapping.md and waveshare_button_mapping.md:
- Display pins (BCM): DC=25, RST=27, BL=24; SPI: SCLK=11, MOSI=10, CS=8. Backlight lives on BCM24 and can be toggled with `gpioset gpiochip0 24=1`.
- Input pins (BCM): UP=6, DOWN=19, LEFT=5, RIGHT=26, PRESS=13; KEY1=21, KEY2=20, KEY3=16. Button mapping in the UI: Up/Down move selection, Left is back, Right/Select accepts, Key1 refreshes, Key2 cancels (no-op in menus/dashboards; cancels dialogs/ops), Key3 opens reboot confirmation.
- GPIO pull-ups are expected in `/boot/firmware/config.txt` (or `/boot/config.txt`), using `gpio=6,19,5,26,13,21,20,16=pu`; the installers write this line and request a reboot so input remains stable.

Software/runtime expectations:
- Built and run on Linux (Pi OS) with root privileges via systemd service, so `CAP_NET_ADMIN` is available.
- Dependencies are installed by `install_rustyjack.sh`, `install_rustyjack_dev.sh`, and `install_rustyjack_prebuilt.sh`: `wpasupplicant` (for WPA auth + `wpa_cli` fallback), `isc-dhcp-client`, `hostapd`, `dnsmasq`, `rfkill`, `i2c-tools`, `git`, `curl`, plus build/firmware packages (dev/build includes `build-essential`, `pkg-config`, `libssl-dev`, `dkms`, `bc`, `libelf-dev`). When adding features that call new system binaries, update all installers accordingly.
- **IMPORTANT: NetworkManager is REMOVED, not just disabled.** Installers run `apt-get purge network-manager` to completely remove NetworkManager from the system. Do NOT assume `nmcli` is available. All network management is done through pure Rust netlink operations.
- Installers now:
  - Remount `/` read-write if needed (fresh Pi images can boot `ro`).
  - **Purge NetworkManager completely** via `apt-get purge network-manager` and mask the service.
  - Claim `/etc/resolv.conf` for Rustyjack (symlink to `/var/lib/rustyjack/resolv.conf`, root-owned) and reclaim it after apt installs so route/DNS enforcement can write reliably.
  - Disable competing DNS managers (systemd-resolved, dhcpcd, resolvconf if present). This ensures Rustyjack has sole control of DNS on the dedicated device.
  - Ensure `/var/lib/rustyjack/logs` exists and is owned by `rustyjack-ui:rustyjack` so the UI can write logs.

MAC randomization flow:
- UI uses `rustyjack-evasion::MacManager` with vendor-aware policy engine for secure, locally administered MACs. Prefers vendor-matched OUIs based on the current interface's OUI. After changing MAC it triggers DHCP renewal via netlink; reconnect is best-effort and does not rely on `nmcli`.

Built-in wireless (Raspberry Pi Zero 2 W):
- Chipset: Cypress/Infineon CYW43436 (2.4 GHz 802.11b/g/n, single-stream HT20, ~72 Mbps max link). No 5 GHz support.
- Modes supported by the stock driver: managed (client) and limited AP mode (2.4 GHz, 20 MHz). Suitable for `rustyjack-core` scanning/association and for UI status queries.
- Monitor/sniff/injection: not supported by the stock CYW43436 driver. Deauth, targeted handshake capture, and Evil Twin features require a USB Wi-Fi adapter with monitor+injection (e.g., ath9k/ath9k_htc or rtl8812au with proper driver). Passive probe sniffing with the built-in radio would require Nexmon patches; otherwise use an external adapter.
- Channel coverage: 2.4 GHz only; Rustyjack features that assume 5 GHz (e.g., channel setting beyond 14 or dual-band AP) need an external dual-band adapter.

Project structure (14 workspace crates):
- `rustyjack-core/` — Operations orchestration (68 command handlers), anti-forensics, physical access, USB mount operations, loot management, pipelines.
  - `src/anti_forensics.rs` — Secure file deletion (DoD 5220.22-M), RAM wipe, log purging, evidence management.
  - `src/physical_access.rs` — WiFi credential extraction from routers via wired connection, router fingerprinting.
  - `src/mount.rs` — USB mounting with read-only/read-write mode selection and mount policy enforcement.
  - `src/redact.rs` — Sensitive data redaction for logs (passwords, keys, credentials).
- `rustyjack-daemon/` — Privileged root daemon with IPC dispatch and job lifecycle management.
- `rustyjack-ui/` — Embedded display UI for the Waveshare HAT.
- `rustyjack-client/` — Tokio-based Unix socket client for daemon communication.
- `rustyjack-ipc/` — IPC protocol types and endpoints.
- `rustyjack-commands/` — CLI/IPC command enums and argument structures.
- `rustyjack-netlink/` — Pure Rust networking: interfaces, routes, DHCP, DNS, ARP, rfkill, nf_tables (replaces iptables, nmcli, dhclient).
- `rustyjack-wireless/` — 802.11 attacks (9,688 lines, 18 modules): nl80211, monitor/injection, deauth, PMKID, Karma, Evil Twin, hotspot with native DHCP/DNS.
- `rustyjack-ethernet/` — Rust-only Ethernet recon (ICMP/ARP sweep + TCP port scan, banner grabbing, device inventory).
- `rustyjack-portal/` — Captive portal HTTP server (Axum + Tower middleware).
- `rustyjack-evasion/` — MAC randomization with vendor-aware policy engine, hostname randomization, TX power control.
- `rustyjack-encryption/` — AES-GCM encryption for loot, zeroization of sensitive data.
- `rustyjack-wpa/` — WPA/WPA2 handshake processing (PBKDF2, HMAC-SHA1 for PMK/PTK).
- `DNSSpoof/` — Captive portal HTML/JS templates (not a Rust crate).
- `scripts/` — WiFi driver installer (`wifi_driver_installer.sh`), FDE scripts (`fde_prepare_usb.sh`, `fde_migrate_root.sh`), USB hotplug helper.
- `install_rustyjack.sh`, `install_rustyjack_dev.sh`, `install_rustyjack_prebuilt.sh` — Production, debug, and prebuilt installers.
- `waveshare_gpio_pin_mapping.md`, `waveshare_button_mapping.md` — Validated pinout and button behavior references.

Loot storage:
- Wireless captures: `loot/Wireless/<target>/` (target = SSID, else BSSID).
- Ethernet captures: `loot/Ethernet/<IP>/`.
- Pipeline loot isolation: `loot/Wireless/<target>/pipelines/<timestamp>/`.
- Hotspot device history: `loot/Hotspot/device_history.txt` with timestamps, MAC, IP, hostname for DHCP leases.
- Reports: `loot/reports/<network>/report_<timestamp>.txt` with combined insights and next steps.
- Audit logs: Operation history with timestamps and command tracking.

Systemd services (5 + socket):
- `rustyjackd.service` — Privileged daemon (root, CAP_NET_ADMIN/CAP_NET_RAW/CAP_SYS_ADMIN).
- `rustyjackd.socket` — Daemon socket (used by prebuilt/socket activation flows).
- `rustyjack-ui.service` — Unprivileged LCD UI (rustyjack-ui user, supplementary groups: gpio, spi, rustyjack).
- `rustyjack-wpa_supplicant@wlan0.service` — WiFi client authentication service.
- `rustyjack-portal.service` — Captive portal server (rustyjack-portal user, port 3000).
- `rustyjack.service` — Alias for rustyjack-ui.service.

Important implementation notes:
- MAC randomization: `rustyjack-evasion::MacManager` sets locally administered, unicast MACs with CSPRNG; vendor-match OUI from the current interface when available.
- Display runtime: effective geometry is cached in `gui_conf.json` (`display` block). Manual reruns/reset are under `Settings -> Display`.
- Display warnings emitted when applicable: `DISPLAY_MODE_MISMATCH`, `DISPLAY_UNVERIFIED_GEOMETRY`, `UNSUPPORTED_DISPLAY_SIZE`.
- UI dialogs/windows must require explicit user confirmation before advancing; do not auto-dismiss after a timeout or hide errors without acknowledgment.
- Anti-forensics: Secure delete uses 7-pass overwrite (DoD standard), RAM wipe on shutdown, complete system purge removes all binaries/services/loot.
- FDE operations are **destructive and irreversible** — always verify user intent and warn about data loss.

Style guard:
- Don't add any emojis and remove emojis if found in the code.

Reality check / current gaps:
- Goal: Pure Rust networking and tooling (no external binaries). Current state: installers still include `wpa_supplicant`, `hostapd`, `dnsmasq`, and `isc-dhcp-client` for compatibility. Remove these only after confirming Rust-native replacements cover all flows on target hardware.
- Goal: Dedicated-device DNS ownership. Current state: installers claim `/etc/resolv.conf` and disable competing DNS managers; this is correct for a dedicated appliance but may be too aggressive for multi-purpose hosts.
