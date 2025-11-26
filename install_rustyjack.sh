#!/usr/bin/env bash
# Rustyjack installation / bootstrap script
# ------------------------------------------------------------
# * Idempotent   - safe to run multiple times
# * Bookworm-ready - handles /boot/firmware/config.txt move
# * Enables I2C/SPI, installs all deps, sets up systemd unit
# * Ends with a health-check (SPI nodes + Rust binary presence)
# * Native Rust wireless support (rustyjack-wireless crate)
# * RUST UI - Phase 3 complete, Python UI removed
# ------------------------------------------------------------
set -euo pipefail

# ---- helpers ------------------------------------------------
step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }

# ---- 0: convert CRLF if file came from Windows --------------
if grep -q $'\r' "$0"; then
  step "Converting CRLF to LF in $0"
  cmd dos2unix || { sudo apt-get update -qq && sudo apt-get install -y dos2unix; }
  dos2unix "$0"
fi

# ---- 1: locate active config.txt ----------------------------
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

# ---- 2: install / upgrade required APT packages -------------
PACKAGES=(
  # build tools for Rust compilation
  build-essential pkg-config libssl-dev
  # DKMS for WiFi driver compilation
  dkms bc libelf-dev linux-headers-$(uname -r)
  # network / offensive tools
  nmap ncat tcpdump arp-scan dsniff ettercap-text-only php procps
  # WiFi interface tools (for native Rust wireless operations)
  wireless-tools wpasupplicant iw hostapd dnsmasq
  # USB WiFi dongle support
  firmware-linux-nonfree firmware-realtek firmware-atheros firmware-ralink firmware-misc-nonfree
  # misc
  git i2c-tools curl
)

step "Updating APT and installing dependencies..."
sudo apt-get update -qq
to_install=($(sudo apt-get -qq --just-print install "${PACKAGES[@]}" 2>/dev/null | awk '/^Inst/ {print $2}'))
if ((${#to_install[@]})); then
  info "Will install/upgrade: ${to_install[*]}"
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}"
else
  info "All packages already installed and up-to-date."
fi

# ---- 3: enable I2C / SPI & kernel modules -------------------
step "Enabling I2C and SPI..."
add_dtparam dtparam=i2c_arm=on
add_dtparam dtparam=i2c1=on
add_dtparam dtparam=spi=on
add_dtparam dtparam=wifi=on

MODULES=(i2c-bcm2835 i2c-dev spi_bcm2835 spidev)
for m in "${MODULES[@]}"; do
  grep -qxF "$m" /etc/modules || echo "$m" | sudo tee -a /etc/modules >/dev/null
  sudo modprobe "$m" || true
done

# ensure overlay spi0-2cs
grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG" >/dev/null

# Ensure buttons use internal pull-ups for reliability on various Pi images.
if ! grep -q "^gpio=6,19,5,26,13,21,20,16=pu" "$CFG" ; then
  echo 'gpio=6,19,5,26,13,21,20,16=pu' | sudo tee -a "$CFG" >/dev/null
  info "Pinned button GPIOs to pull-ups in $CFG"
fi
info "Note: pull-up changes require a reboot to take effect."

# ---- 3a: ensure sufficient swap space for compilation -------
step "Checking swap space for Rust compilation..."
CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
MIN_SWAP=1536  # Need at least 1.5GB for Rust compilation

if [ "$CURRENT_SWAP" -lt "$MIN_SWAP" ]; then
  warn "Current swap: ${CURRENT_SWAP}MB (insufficient for compilation)"
  info "Setting up 2GB swap file for Rust compilation..."
  
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
  info "[OK] Swap increased to ${NEW_SWAP}MB"
else
  info "[OK] Sufficient swap available: ${CURRENT_SWAP}MB"
fi

# ---- 3b: build/install Rust binaries ------------------------
step "Ensuring Rust toolchain + building binaries..."
if ! command -v cargo >/dev/null 2>&1; then
  info "cargo missing - installing rustup toolchain"
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

# Stop the service before rebuilding to release the binary
info "Stopping rustyjack service for rebuild..."
sudo systemctl stop rustyjack.service 2>/dev/null || true

# Remove old binary to ensure fresh install
# Note: rustyjack-core and rustyjack-evasion are library crates, not binaries
info "Removing old binary..."
sudo rm -f /usr/local/bin/rustyjack-ui

# Clean old build artifacts to force full rebuild
info "Cleaning build cache for fresh compilation..."
(cd "$PROJECT_ROOT" && cargo clean) 2>/dev/null || true

# Build rustyjack-ui from workspace root (all crates share target directory)
info "Building rustyjack-ui (release - this takes a while)..."
(cd "$PROJECT_ROOT" && cargo build --release -p rustyjack-ui) || fail "Failed to build rustyjack-ui"

# Verify the binary exists before installing (workspace builds go to root target/release/)
if [ ! -f "$PROJECT_ROOT/target/release/rustyjack-ui" ]; then
  fail "rustyjack-ui binary not found after build!"
fi

# Install binary
sudo install -Dm755 "$PROJECT_ROOT/target/release/rustyjack-ui" /usr/local/bin/rustyjack-ui

# Verify installation
if [ -x /usr/local/bin/rustyjack-ui ]; then
  info "Installed rustyjack-ui to /usr/local/bin/"
  # Show binary info to confirm it's new
  info "Binary info:"
  ls -la /usr/local/bin/rustyjack-ui
else
  fail "Failed to install binaries to /usr/local/bin/"
fi

# ---- 4: WiFi attack setup -----------------------------------
step "Setting up WiFi attack environment..."

# Create loot directories
sudo mkdir -p "$PROJECT_ROOT/loot"/{Wireless,Nmap,Responder,DNSSpoof}
sudo chmod -R 755 "$PROJECT_ROOT/loot"

# Create WiFi profiles directory
sudo mkdir -p "$PROJECT_ROOT/wifi/profiles"
sudo chown root:root "$PROJECT_ROOT/wifi/profiles"
sudo chmod 755 "$PROJECT_ROOT/wifi/profiles"

# Install WiFi driver scripts
step "Installing WiFi driver auto-install scripts..."
sudo mkdir -p "$PROJECT_ROOT/scripts"
sudo cp -f scripts/wifi_driver_installer.sh "$PROJECT_ROOT/scripts/" 2>/dev/null || true
sudo cp -f scripts/wifi_hotplug.sh "$PROJECT_ROOT/scripts/" 2>/dev/null || true
sudo chmod +x "$PROJECT_ROOT/scripts/"*.sh 2>/dev/null || true

# Install udev rules for USB WiFi auto-detection
if [ -f scripts/99-rustyjack-wifi.rules ]; then
  sudo cp -f scripts/99-rustyjack-wifi.rules /etc/udev/rules.d/
  sudo udevadm control --reload-rules
  sudo udevadm trigger
  info "Installed USB WiFi auto-detection udev rules"
fi

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

# ---- 5: systemd service -------------------------------------
SERVICE=/etc/systemd/system/rustyjack.service
step "Installing systemd service $SERVICE..."

sudo tee "$SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack UI Service (100% Rust)
After=local-fs.target
Wants=local-fs.target

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

# Start the service now
sudo systemctl start rustyjack.service && info "Rustyjack service started successfully" || warn "Failed to start service - check 'systemctl status rustyjack'"

# ---- 6: final health-check ----------------------------------
step "Running post install checks..."

# 6-a SPI device nodes
if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "[OK] SPI device found: $(ls /dev/spidev* | xargs)"
else
  warn "[X] SPI device NOT found - a reboot may be required"
fi

# 6-b Wireless tools check (native rustyjack-wireless is used)
if cmd iw && cmd iwconfig; then
  info "[OK] Wireless interface tools found (iw, iwconfig)"
  info "     Native rustyjack-wireless crate handles all wireless attacks"
else
  warn "[X] Wireless tools missing - install 'iw' and 'wireless-tools'"
fi

# 6-c USB WiFi dongle detection
if lsusb | grep -q -i "realtek\|ralink\|atheros\|broadcom"; then
  info "[OK] USB WiFi dongles detected: $(lsusb | grep -i 'realtek\|ralink\|atheros\|broadcom' | wc -l) devices"
else
  warn "[X] No USB WiFi dongles detected - WiFi attacks require external dongle"
fi

# 6-d Rust binaries check
if [ -x /usr/local/bin/rustyjack-ui ]; then
  info "[OK] Rust binary installed: rustyjack-ui"
  info "     (rustyjack-core, rustyjack-evasion, rustyjack-wireless are library crates)"
else
  fail "[X] Rust binary missing - check build output"
fi

# 6-e Verify library crates were compiled
if [ -f "$PROJECT_ROOT/target/release/librustyjack_core.rlib" ] || [ -f "$PROJECT_ROOT/target/release/librustyjack_core.so" ]; then
  info "[OK] rustyjack-core library compiled"
else
  warn "[X] rustyjack-core library not found in target/release/"
fi

if [ -f "$PROJECT_ROOT/target/release/librustyjack_evasion.rlib" ] || [ -f "$PROJECT_ROOT/target/release/librustyjack_evasion.so" ]; then
  info "[OK] rustyjack-evasion library compiled"
else
  warn "[X] rustyjack-evasion library not found in target/release/"
fi

# 6-f Service status
if systemctl is-active --quiet rustyjack.service; then
  info "[OK] Rustyjack service is running"
else
  warn "[X] Rustyjack service is not running - check 'systemctl status rustyjack'"
fi

# ---- completion ---------------------------------------------
echo ""
step "Installation finished successfully!"
info "=================================================="
info "RUST UI ACTIVE"
info "=================================================="
info ""
info "REBOOT REQUIRED to ensure overlays and services start cleanly."
info ""
info "After reboot, the LCD will display the Rust-powered menu system."
info ""
info "To skip automatic reboot, run with SKIP_REBOOT=1 or NO_REBOOT=1"
info ""

# By default we reboot so required changes are applied immediately.
if [ "${SKIP_REBOOT:-0}" != "1" ] && [ "${NO_REBOOT:-0}" != "1" ]; then
  info "System rebooting in 5 seconds to finish setup - press Ctrl+C to abort."
  sleep 5
  sudo reboot
else
  info "SKIP_REBOOT set - installer finished without reboot."
  info "You must reboot manually for some changes to take effect."
fi
info ""
info "For WiFi attacks: Plug in USB WiFi dongle and use menu"
info "Manage service: systemctl status/restart rustyjack"
info "View logs: journalctl -u rustyjack -f"
info ""
