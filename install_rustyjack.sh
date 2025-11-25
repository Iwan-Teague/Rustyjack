#!/usr/bin/env bash
# Rustyjack installation / bootstrap script
# ------------------------------------------------------------
# * Idempotent   – safe to run multiple times
# * Bookworm‑ready – handles /boot/firmware/config.txt move
# * Enables I²C/SPI, installs all deps, sets up systemd unit
# * Ends with a health‑check (SPI nodes + Rust binary presence)
# * Native Rust wireless support (rustyjack-wireless crate)
# * RUST UI - Phase 3 complete, Python UI removed
# ------------------------------------------------------------
set -euo pipefail

# ───── helpers ───────────────────────────────────────────────
step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }

# ───── 0 ▸ convert CRLF if file came from Windows ────────────
if grep -q $'\r' "$0"; then
  step "Converting CRLF → LF in $0"
  cmd dos2unix || { sudo apt-get update -qq && sudo apt-get install -y dos2unix; }
  dos2unix "$0"
fi

# ───── 1 ▸ locate active config.txt ──────
CFG=/boot/firmware/config.txt; [[ -f $CFG ]] || CFG=/boot/config.txt
info "Using config file: $CFG"
add_dtparam() {
  local param="$1"
  if grep -qE "^#?\s*${param%=*}=on" "$CFG"; then
    sudo sed -Ei "s|^#?\s*${param%=*}=.*|${param%=*}=on|" "$CFG"
  else
    echo "$param" | sudo tee -a "$CFG" >/dev/null
  fi
}

# ───── 2 ▸ install / upgrade required APT packages ───────────
PACKAGES=(
  # ‣ build tools for Rust compilation
  build-essential pkg-config libssl-dev
  # ‣ network / offensive tools
  nmap ncat tcpdump arp-scan dsniff ettercap-text-only php procps
  # ‣ WiFi interface tools (for native Rust wireless operations)
  wireless-tools wpasupplicant iw
  # ‣ USB WiFi dongle support
  firmware-linux-nonfree firmware-realtek firmware-atheros
  # ‣ misc
  git i2c-tools curl
)

step "Updating APT and installing dependencies …"
sudo apt-get update -qq
to_install=($(sudo apt-get -qq --just-print install "${PACKAGES[@]}" 2>/dev/null | awk '/^Inst/ {print $2}'))
if ((${#to_install[@]})); then
  info "Will install/upgrade: ${to_install[*]}"
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}"
else
  info "All packages already installed & up‑to‑date."
fi

# ───── 3 ▸ enable I²C / SPI & kernel modules ────────────────
step "Enabling I²C & SPI …"
add_dtparam dtparam=i2c_arm=on
add_dtparam dtparam=i2c1=on
add_dtparam dtparam=spi=on
add_dtparam dtparam=wifi=on

MODULES=(i2c-bcm2835 i2c-dev spi_bcm2835 spidev)
for m in "${MODULES[@]}"; do
  grep -qxF "$m" /etc/modules || echo "$m" | sudo tee -a /etc/modules >/dev/null
  sudo modprobe "$m" || true
done

# ensure overlay spi0‑2cs
grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG" >/dev/null

# Ensure buttons use internal pull-ups for reliability on various Pi images.
# Some Raspberry Pi images do not enable GPIO pull-ups by default for these
# pins. This line ensures the joystick/buttons are pulled up so pressing a
# button returns a stable 0 value and released state is 1.
if ! grep -q "^gpio=6,19,5,26,13,21,20,16=pu" "$CFG" ; then
  echo 'gpio=6,19,5,26,13,21,20,16=pu' | sudo tee -a "$CFG" >/dev/null
  info "Pinned button GPIOs to pull‑ups in $CFG"
fi
info "Note: pull-up changes require a reboot to take effect. Reboot now or later as needed."

# ───── 3a ▸ ensure sufficient swap space for compilation ─────
step "Checking swap space for Rust compilation …"
CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
MIN_SWAP=1536  # Need at least 1.5GB for Rust compilation

if [ "$CURRENT_SWAP" -lt "$MIN_SWAP" ]; then
  warn "Current swap: ${CURRENT_SWAP}MB (insufficient for compilation)"
  info "Setting up 2GB swap file for Rust compilation …"
  
  # Turn off existing zram swap if present
  if [ -e /dev/zram0 ]; then
    sudo swapoff /dev/zram0 2>/dev/null || true
  fi
  
  # Create or resize swap file
  SWAP_FILE=/var/swap
  if [ -f "$SWAP_FILE" ]; then
    sudo swapoff "$SWAP_FILE" 2>/dev/null || true
  fi
  
  sudo fallocate -l 2G "$SWAP_FILE" 2>/dev/null || sudo dd if=/dev/zero of="$SWAP_FILE" bs=1M count=2048 status=progress
  sudo chmod 600 "$SWAP_FILE"
  sudo mkswap "$SWAP_FILE" >/dev/null
  sudo swapon "$SWAP_FILE"
  
  # Make it permanent
  if ! grep -q "$SWAP_FILE" /etc/fstab 2>/dev/null; then
    echo "$SWAP_FILE none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
  fi
  
  NEW_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
  info "✓ Swap increased to ${NEW_SWAP}MB"
else
  info "✓ Sufficient swap available: ${CURRENT_SWAP}MB"
fi

# ───── 3b ▸ build/install Rust binaries ──────────────────────
step "Ensuring Rust toolchain + building binaries …"
if ! command -v cargo >/dev/null 2>&1; then
  info "cargo missing – installing rustup toolchain"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
else
  source "$HOME/.cargo/env" 2>/dev/null || true
fi

# Determine project root (support both /root/Rustyjack and current directory)
PROJECT_ROOT="${PROJECT_ROOT:-/root/Rustyjack}"
if [ ! -d "$PROJECT_ROOT" ]; then
  PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
fi
info "Using project root: $PROJECT_ROOT"

# Build Rust binaries
info "Building rustyjack-core..."
(cd "$PROJECT_ROOT/rustyjack-core" && cargo build --release) || fail "Failed to build rustyjack-core"
info "Building rustyjack-ui..."
(cd "$PROJECT_ROOT/rustyjack-ui" && cargo build --release) || fail "Failed to build rustyjack-ui"

# Install binaries
sudo install -Dm755 "$PROJECT_ROOT/rustyjack-core/target/release/rustyjack-core" /usr/local/bin/rustyjack-core
sudo install -Dm755 "$PROJECT_ROOT/rustyjack-ui/target/release/rustyjack-ui" /usr/local/bin/rustyjack-ui
info "Installed rustyjack-core and rustyjack-ui to /usr/local/bin/"

# ───── 4 ▸ WiFi attack setup ──────────────────────────────────
step "Setting up WiFi attack environment …"

# Create WiFi profiles directory
sudo mkdir -p "$PROJECT_ROOT/wifi/profiles"
sudo chown root:root "$PROJECT_ROOT/wifi/profiles"
sudo chmod 755 "$PROJECT_ROOT/wifi/profiles"

# Create sample WiFi profile if it doesn't exist
if [ ! -f "$PROJECT_ROOT/wifi/profiles/sample.json" ]; then
  sudo tee "$PROJECT_ROOT/wifi/profiles/sample.json" >/dev/null <<'PROFILE'
{
  "ssid": "YourWiFiNetwork",
  "password": "your_password_here",
  "interface": "auto",
  "priority": 1,
  "auto_connect": true,
  "created": "2024-01-01T12:00:00",
  "last_used": null,
  "notes": "Sample WiFi profile - edit with your network details"
}
PROFILE
  info "Created sample WiFi profile"
fi

# Set up NetworkManager to allow WiFi interface management
if systemctl is-active --quiet NetworkManager; then
  info "NetworkManager is active - configuring for WiFi attacks"
  sudo tee /etc/NetworkManager/conf.d/99-wifi-attacks.conf >/dev/null <<'NM_CONF'
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=true

[keyfile]
unmanaged-devices=interface-name:wlan0mon;interface-name:wlan1mon;interface-name:wlan2mon
NM_CONF
  sudo systemctl restart NetworkManager
else
  warn "NetworkManager not active - WiFi attacks may need manual setup"
fi

# Optionally run the repository's WiFi setup helper automatically.
# To skip automatic invocation set NO_WIFI_SETUP=1 in the environment.
# If WIFI_COUNTRY not set, try to detect user's locale and set it as default
detect_wifi_country() {
  # 1) use explicit env var
  if [ -n "${WIFI_COUNTRY:-}" ]; then
    echo "$WIFI_COUNTRY"
    return 0
  fi

  # 2) try LANG / locale environment (e.g. en_GB.UTF-8)
  local lang="${LANG:-}"
  if [ -z "$lang" ]; then
    lang=$(locale 2>/dev/null | awk -F= '/^LANG=/ {print $2}') || true
  fi
  if [ -n "$lang" ] && echo "$lang" | grep -q "_"; then
    echo "$lang" | awk -F[_.] '{print toupper($2)}'
    return 0
  fi

  # 3) try system timezone -> map using ipinfo as fallback
  if command -v curl >/dev/null 2>&1; then
    # Prefer IP geolocation if network is present
    country=$(curl -fsS --max-time 5 https://ipapi.co/country/ 2>/dev/null || true)
    if [ -n "$country" ]; then
      echo "$country" | tr '[:lower:]' '[:upper:]'
      return 0
    fi
    # fallback to ipinfo
    country=$(curl -fsS --max-time 5 https://ipinfo.io/country 2>/dev/null || true)
    if [ -n "$country" ]; then
      echo "$country" | tr '[:lower:]' '[:upper:]'
      return 0
    fi
  fi

  # 4) last resort: default to US
  echo "US"
}

if [ "${NO_WIFI_SETUP:-0}" != "1" ]; then
  WIFI_HELPER="$PROJECT_ROOT/setup_wifi.sh"
  if [ -f "$WIFI_HELPER" ]; then
    info "Running WiFi setup helper: $WIFI_HELPER"
    sudo chmod +x "$WIFI_HELPER" || true
    # If WIFI_COUNTRY env is set pass it through; otherwise run non-interactively
    # determine country for non-interactive installer if not provided
    if [ -z "${WIFI_COUNTRY:-}" ]; then
      DETECTED_COUNTRY=$(detect_wifi_country)
      info "Detected locale country code: ${DETECTED_COUNTRY}"
      WIFI_COUNTRY="$DETECTED_COUNTRY"
    fi

    # run helper using the resolved WIFI_COUNTRY env
    sudo WIFI_COUNTRY="$WIFI_COUNTRY" "$WIFI_HELPER" -y || warn "WiFi setup helper failed"
  else
    info "No WiFi setup helper found at $WIFI_HELPER — skipping"
  fi
else
  info "NO_WIFI_SETUP=1 set — skipping WiFi automatic setup"
fi

# Create loot directories
sudo mkdir -p "$PROJECT_ROOT/loot"/{Nmap,Responder,DNSSpoof}
sudo chmod -R 755 "$PROJECT_ROOT/loot"

# ───── 5 ▸ systemd service ───────────────────────────────────
SERVICE=/etc/systemd/system/rustyjack.service
step "Installing systemd service $SERVICE …"

sudo tee "$SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack UI Service (100% Rust)
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_ROOT
ExecStart=/usr/local/bin/rustyjack-ui
Environment=RUSTYJACK_DISPLAY_ROTATION=landscape
Restart=on-failure
RestartSec=5
User=root
Environment=RUSTYJACK_ROOT=$PROJECT_ROOT

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable rustyjack.service
info "Rustyjack service enabled - will start on next boot"

# No legacy service migration needed - Rustyjack only

# Start the service now
sudo systemctl start rustyjack.service && info "Rustyjack service started successfully" || warn "Failed to start service - check 'systemctl status rustyjack'"

# ───── 6 ▸ final health‑check ────────────────────────────────
step "Running post install checks …"

# 6‑a SPI device nodes
if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "✓ SPI device found: $(ls /dev/spidev* | xargs)"
else
  warn "✗ SPI device NOT found – a reboot may be required"
fi

# 6‑b Wireless tools check (native rustyjack-wireless is used instead of aircrack-ng)
if cmd iw && cmd iwconfig; then
  info "✓ Wireless interface tools found (iw, iwconfig)"
  info "  Native rustyjack-wireless crate handles all wireless attacks"
else
  warn "✗ Wireless tools missing - install 'iw' and 'wireless-tools'"
fi

# 6‑c USB WiFi dongle detection
if lsusb | grep -q -i "realtek\|ralink\|atheros\|broadcom"; then
  info "✓ USB WiFi dongles detected: $(lsusb | grep -i 'realtek\|ralink\|atheros\|broadcom' | wc -l) devices"
else
  warn "✗ No USB WiFi dongles detected - WiFi attacks require external dongle"
fi

# 6‑d Rust binaries check
if [ -x /usr/local/bin/rustyjack-ui ] && [ -x /usr/local/bin/rustyjack-core ]; then
  info "✓ Rust binaries installed: rustyjack-ui & rustyjack-core"
  /usr/local/bin/rustyjack-core --version 2>/dev/null && info "  rustyjack-core version OK" || warn "  rustyjack-core version check failed"
else
  fail "✗ Rust binaries missing - check build output"
fi

# 6‑e Service status
if systemctl is-active --quiet rustyjack.service; then
  info "✓ Rustyjack service is running"
else
  warn "✗ Rustyjack service is not running - check 'systemctl status rustyjack'"
fi

# ───── completion ────────────────────────────────────────────
echo ""
step "Installation finished successfully!"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "RUST UI ACTIVE"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info ""
info "REBOOT REQUIRED to ensure overlays & services start cleanly — the installer will now reboot the Pi unless explicitly skipped."
info ""
info "After reboot, the LCD will display the Rust-powered menu system."
info ""
info "To skip automatic reboot (advanced users), run the installer with SKIP_REBOOT=1 or NO_REBOOT=1 in the environment."
info ""

# By default we reboot so required changes (kernel config, gpio pulls, overlays)
# are applied immediately. If an env flag is set to skip, we will not reboot.
if [ "${SKIP_REBOOT:-0}" != "1" ] && [ "${NO_REBOOT:-0}" != "1" ]; then
  info "System rebooting in 5 seconds to finish setup — press Ctrl+C to abort."
  sleep 5
  sudo reboot
else
  info "SKIP_REBOOT set — installer finished without reboot. You must reboot manually for some changes to take effect."
fi
info ""
info "For WiFi attacks: Plug in USB WiFi dongle and use WiFi Manager"
info "Manage service: systemctl status/restart rustyjack"
info "View logs: journalctl -u rustyjack -f"
info ""
