#!/usr/bin/env bash
# Rustyjack installation / bootstrap script
# ------------------------------------------------------------
# * Idempotent   – safe to run multiple times
# * Bookworm‑ready – handles /boot/firmware/config.txt move
# * Enables I²C/SPI, installs all deps, sets up systemd unit
# * Ends with a health‑check (SPI nodes + Rust binary presence)
# * WiFi attack support with aircrack-ng and USB dongle tools
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
  # ‣ WiFi attack tools
  aircrack-ng wireless-tools wpasupplicant iw
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

MODULES=(i2c-bcm2835 i2c-dev spi_bcm2835 spidev)
for m in "${MODULES[@]}"; do
  grep -qxF "$m" /etc/modules || echo "$m" | sudo tee -a /etc/modules >/dev/null
  sudo modprobe "$m" || true
done

# ensure overlay spi0‑2cs
grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG" >/dev/null

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

# 6‑b WiFi attack tools check
if cmd aireplay-ng && cmd airodump-ng && cmd airmon-ng; then
  info "✓ WiFi attack tools found: aircrack-ng suite installed"
else
  warn "✗ WiFi attack tools missing - check aircrack-ng installation"
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
info "✅ RUSTYJACK SOFTWARE OPERATIONAL"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info ""
info "The Rustyjack software has been successfully installed and configured."
info ""
info "⚠️  REBOOT REQUIRED to ensure all hardware interfaces are active."
info ""
info "To restart the Raspberry Pi from this terminal, run:"
info "  sudo reboot"
info ""
info "Next Steps:"
info "1. Wait for the device to reboot."
info "2. The LCD screen will initialize and display the main menu."
info "3. Use the buttons to navigate the interface."
info ""
info "🔧 Manage service: systemctl status/restart rustyjack"
info "📋 View logs: journalctl -u rustyjack -f"
info ""
