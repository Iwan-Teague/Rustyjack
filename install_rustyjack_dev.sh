#!/usr/bin/env bash
# Rustyjack DEVELOPMENT installation script
# ------------------------------------------------------------
# Same as install_rustyjack.sh but builds DEBUG binaries
# which compile MUCH faster on Pi Zero W 2
# 
# Use this for development/testing, use install_rustyjack.sh
# for production (release builds are faster at runtime)
# ------------------------------------------------------------
set -euo pipefail

# ---- helpers ------------------------------------------------
step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }
has_crate_artifact() {
  local crate="$1"
  local mode="${2:-debug}"
  local base="$PROJECT_ROOT/target/$mode"
  compgen -G "$base/deps/lib${crate}-*.rlib" >/dev/null || \
  compgen -G "$base/deps/lib${crate}-*.rmeta" >/dev/null || \
  compgen -G "$base/deps/lib${crate}-*.so" >/dev/null
}

check_resolv_conf() {
  local resolv="/etc/resolv.conf"
  info "Checking $resolv writability..."

  if [ -L "$resolv" ]; then
    local target
    target=$(readlink -f "$resolv" 2>/dev/null || true)
    warn "[NOTE] $resolv is a symlink -> ${target:-unknown}. If managed by systemd-resolved/resolvconf, allow Rustyjack to overwrite it for route enforcement."
  fi

  if command -v lsattr >/dev/null 2>&1; then
    if lsattr -d "$resolv" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      warn "[NOTE] $resolv is immutable (chattr +i). Clear with: sudo chattr -i $resolv"
    fi
  fi

  if ! sudo test -w "$resolv"; then
    warn "[NOTE] $resolv is not writable by root. Adjust permissions or disable the managing service before using ensure-route."
  else
    info "[OK] $resolv writable by root"
  fi
}

claim_resolv_conf() {
  local resolv="/etc/resolv.conf"
  info "Claiming $resolv for Rustyjack (dedicated device)..."

  if command -v lsattr >/dev/null 2>&1; then
    if lsattr -d "$resolv" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      sudo chattr -i "$resolv" 2>/dev/null || warn "[WARN] Failed to clear immutable bit on $resolv"
    fi
  fi

  if [ -L "$resolv" ]; then
    local target
    target=$(readlink -f "$resolv" 2>/dev/null || true)
    warn "Replacing symlinked $resolv (was -> ${target:-unknown}) with Rustyjack-managed file"
    sudo rm -f "$resolv"
  else
    if [ -f "$resolv" ]; then
      sudo cp "$resolv" "${resolv}.rustyjack.bak" 2>/dev/null || true
    fi
  fi

  sudo sh -c "printf '# Managed by Rustyjack\n# Updated by ensure-route\n' > $resolv"
  sudo chmod 644 "$resolv"
  sudo chown root:root "$resolv"
  info "[OK] $resolv now owned by Rustyjack (plain file, root-writable)"
}

ensure_rw_root() {
  local root_status
  root_status=$(findmnt -n -o OPTIONS / || true)
  if echo "$root_status" | grep -q '\bro\b'; then
    warn "Root filesystem is read-only; attempting remount rw..."
    if sudo mount -o remount,rw /; then
      info "[OK] Remounted / as read-write"
    else
      fail "Failed to remount / as read-write. Please enable rw and rerun."
    fi
  fi
}
ensure_rw_root

echo ""
info "=========================================="
info "  DEVELOPMENT BUILD (debug mode)"
info "  Faster compile, slower runtime"
info "=========================================="
echo ""

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
  # WiFi interface tools (for native Rust wireless operations)
  wireless-tools wpasupplicant iw iproute2 isc-dhcp-client network-manager rfkill
  # Evil Twin / Karma AP requirements
  hostapd dnsmasq iptables
  # USB WiFi dongle support
  firmware-linux-nonfree firmware-realtek firmware-atheros
  # misc
  git i2c-tools curl
)

step "Updating APT and installing dependencies..."
if ! sudo apt-get update -qq; then
  fail "APT update failed. Check network connectivity/apt sources and rerun."
fi

to_install=()
install_plan=""
if install_plan=$(sudo apt-get -qq --just-print install "${PACKAGES[@]}" 2>/dev/null); then
  to_install=($(echo "$install_plan" | awk '/^Inst/ {print $2}'))
  if ((${#to_install[@]})); then
    info "Will install/upgrade: ${to_install[*]}"
    sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}" || fail "APT install failed. Check output above."
  else
    info "All packages already installed and up-to-date."
  fi
else
  warn "APT dry-run failed (likely missing kernel headers or bad sources); attempting full install..."
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}" || fail "APT install failed. Check output above."
fi

# Re-claim resolv.conf after any package changes (apt may rewrite it)
claim_resolv_conf
check_resolv_conf
configure_dns_control() {
  # Disable competing DNS managers; keep NetworkManager but stop it from touching resolv.conf
  if systemctl list-unit-files | grep -q '^systemd-resolved'; then
    warn "Disabling systemd-resolved to prevent resolv.conf rewrites"
    sudo systemctl disable --now systemd-resolved.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^dhcpcd'; then
    warn "Disabling dhcpcd (Rustyjack uses dhclient)"
    sudo systemctl disable --now dhcpcd.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^resolvconf'; then
    warn "Disabling resolvconf to avoid resolv.conf churn"
    sudo systemctl disable --now resolvconf.service 2>/dev/null || true
  fi

  local nm_conf="/etc/NetworkManager/NetworkManager.conf"
  info "Setting NetworkManager DNS handling to 'none' (preserve Rustyjack resolv.conf)"
  if [ ! -f "$nm_conf" ]; then
    sudo mkdir -p /etc/NetworkManager
    cat <<'EOF' | sudo tee "$nm_conf" >/dev/null
[main]
dns=none
EOF
  else
    if grep -q '^\[main\]' "$nm_conf"; then
      if grep -q '^dns=' "$nm_conf"; then
        sudo sed -i 's/^dns=.*/dns=none/' "$nm_conf"
      else
        sudo sed -i '/^\[main\]/a dns=none' "$nm_conf"
      fi
    else
      printf '\n[main]\ndns=none\n' | sudo tee -a "$nm_conf" >/dev/null
    fi
  fi
  sudo systemctl restart NetworkManager.service 2>/dev/null || true
}
configure_dns_control

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

# Ensure buttons use internal pull-ups
if ! grep -q "^gpio=6,19,5,26,13,21,20,16=pu" "$CFG" ; then
  echo 'gpio=6,19,5,26,13,21,20,16=pu' | sudo tee -a "$CFG" >/dev/null
  info "Pinned button GPIOs to pull-ups in $CFG"
fi

# ---- 3a: ensure sufficient swap space for compilation -------
step "Checking swap space for Rust compilation..."
CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
MIN_SWAP=1024  # Debug builds need less memory

if [ "$CURRENT_SWAP" -lt "$MIN_SWAP" ]; then
  warn "Current swap: ${CURRENT_SWAP}MB (insufficient for compilation)"
  info "Setting up 1.5GB swap file..."
  
  if [ -e /dev/zram0 ]; then
    sudo swapoff /dev/zram0 2>/dev/null || true
  fi
  
  SWAP_FILE=/var/swap
  if [ -f "$SWAP_FILE" ]; then
    sudo swapoff "$SWAP_FILE" 2>/dev/null || true
  fi
  
  sudo fallocate -l 1536M "$SWAP_FILE" 2>/dev/null || sudo dd if=/dev/zero of="$SWAP_FILE" bs=1M count=1536 status=progress
  sudo chmod 600 "$SWAP_FILE"
  sudo mkswap "$SWAP_FILE" >/dev/null
  sudo swapon "$SWAP_FILE"
  
  if ! grep -q "$SWAP_FILE" /etc/fstab 2>/dev/null; then
    echo "$SWAP_FILE none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
  fi
  
  NEW_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
  info "[OK] Swap increased to ${NEW_SWAP}MB"
else
  info "[OK] Sufficient swap available: ${CURRENT_SWAP}MB"
fi

# ---- 3b: build/install Rust binaries (DEBUG) ----------------
step "Building DEBUG binaries (faster compile)..."
if ! cmd curl; then
  warn "curl missing after package install; installing curl..."
  sudo apt-get install -y --no-install-recommends curl || fail "Failed to install curl; check network/apt sources."
fi

if ! command -v cargo >/dev/null 2>&1; then
  info "cargo missing - installing rustup toolchain"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
else
  source "$HOME/.cargo/env" 2>/dev/null || true
fi

# Determine project root
PROJECT_ROOT="${PROJECT_ROOT:-/root/Rustyjack}"
if [ ! -d "$PROJECT_ROOT" ]; then
  PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
fi
info "Using project root: $PROJECT_ROOT"

# Stop the service before rebuilding
info "Stopping rustyjack service for rebuild..."
sudo systemctl stop rustyjack.service 2>/dev/null || true

# Remove old binary (only rustyjack-ui - core and evasion are library crates)
info "Removing old binary..."
sudo rm -f /usr/local/bin/rustyjack-ui

# Ask user about clean build
echo ""
info "=========================================="
info "  BUILD OPTIONS"
info "=========================================="
echo ""
echo "  [1] Incremental build (fast - recompiles only changed files)"
echo "  [2] Clean build (slow - removes all cached artifacts first)"
echo ""
read -p "Select build type [1/2] (default: 1): " BUILD_CHOICE
BUILD_CHOICE="${BUILD_CHOICE:-1}"

if [ "$BUILD_CHOICE" = "2" ]; then
  warn "Performing CLEAN build (cargo clean)..."
  info "This will take longer but ensures a fresh build."
  (cd "$PROJECT_ROOT" && cargo clean) || warn "cargo clean failed"
  info "Cache cleared. Starting fresh compilation..."
else
  info "Performing INCREMENTAL build (faster)..."
fi

# Build rustyjack-ui (this also compiles rustyjack-core library as a dependency)
# Build from workspace root so all crates share the same target directory
info "Building rustyjack-ui (debug)..."
(cd "$PROJECT_ROOT" && cargo build -p rustyjack-ui) || fail "Failed to build rustyjack-ui"

# Verify the binary exists (workspace builds go to root target/debug/)
if [ ! -f "$PROJECT_ROOT/target/debug/rustyjack-ui" ]; then
  fail "rustyjack-ui binary not found after build!"
fi

# Install DEBUG binary
sudo install -Dm755 "$PROJECT_ROOT/target/debug/rustyjack-ui" /usr/local/bin/rustyjack-ui

# Verify installation
if [ -x /usr/local/bin/rustyjack-ui ]; then
  info "Installed DEBUG binary to /usr/local/bin/"
  info "Binary info:"
  ls -la /usr/local/bin/rustyjack-ui
else
  fail "Failed to install binaries to /usr/local/bin/"
fi

# ---- 4: WiFi attack setup -----------------------------------
step "Setting up WiFi attack environment..."

# Create loot directories (only Wireless and Ethernet are used)
sudo mkdir -p "$PROJECT_ROOT/loot"/{Wireless,Ethernet}
sudo chmod -R 755 "$PROJECT_ROOT/loot"

sudo mkdir -p "$PROJECT_ROOT/wifi/profiles"
sudo chown root:root "$PROJECT_ROOT/wifi/profiles"
sudo chmod 755 "$PROJECT_ROOT/wifi/profiles"

# Ensure WLAN interfaces are unblocked and up (avoid default DOWN state)
step "Ensuring WLAN interfaces are unblocked and up"
sudo rfkill unblock all || true
for dev in /sys/class/net/wlan*; do
  [ -e "$dev" ] || continue
  iface=$(basename "$dev")
  sudo ip link set "$iface" up || warn "Could not bring up $iface"
done

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
Description=Rustyjack UI Service (DEBUG BUILD)
After=local-fs.target
Wants=local-fs.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_ROOT
ExecStart=/usr/local/bin/rustyjack-ui
Environment=RUSTYJACK_DISPLAY_ROTATION=landscape
Environment=RUST_BACKTRACE=1
Restart=on-failure
RestartSec=5
User=root
Environment=RUSTYJACK_ROOT=$PROJECT_ROOT

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable rustyjack.service
info "Rustyjack service enabled"

# Start the service now
sudo systemctl start rustyjack.service && info "Rustyjack service started successfully" || warn "Failed to start service - check 'systemctl status rustyjack'"

# ---- 6: final health-check ----------------------------------
step "Running post install checks..."

if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "[OK] SPI device found"
else
  warn "[X] SPI device NOT found - reboot may be required"
fi

if cmd iw && cmd iwconfig; then
  info "[OK] Wireless tools found"
else
  warn "[X] Wireless tools missing"
fi

# MAC randomization runtime deps
if cmd ip; then
  info "[OK] iproute2 present (ip command)"
else
  warn "[X] ip command missing - install iproute2"
fi

if cmd dhclient; then
  info "[OK] dhclient present (DHCP renew for MAC changes)"
else
  warn "[X] dhclient missing - install isc-dhcp-client"
fi

if cmd wpa_cli || cmd nmcli; then
  info "[OK] WiFi control present (wpa_cli/nmcli) for reconnect"
else
  warn "[X] Neither wpa_cli nor nmcli found - WiFi reconnect after MAC change may need manual intervention"
fi

if [ -x /usr/local/bin/rustyjack-ui ]; then
  info "[OK] DEBUG binary installed: rustyjack-ui"
  info "     (rustyjack-core, rustyjack-evasion, rustyjack-wireless are library crates)"
else
  fail "[X] Binary missing"
fi

# Verify library crates were compiled
if has_crate_artifact "rustyjack_core" "debug"; then
  info "[OK] rustyjack-core library compiled"
else
  warn "[X] rustyjack-core library not found in target/debug/deps/ (Cargo hashes file names)"
fi

if has_crate_artifact "rustyjack_evasion" "debug"; then
  info "[OK] rustyjack-evasion library compiled"
else
  warn "[X] rustyjack-evasion library not found in target/debug/deps/ (Cargo hashes file names)"
fi

if systemctl is-active --quiet rustyjack.service; then
  info "[OK] Rustyjack service is running"
else
  warn "[X] Rustyjack service is not running"
fi

# ---- completion ---------------------------------------------
echo ""
step "DEV Installation finished!"
info "=========================================="
info "  DEBUG BUILD INSTALLED"
info "  - Faster compile time"
info "  - Slower runtime (no optimizations)"
info "  - Includes debug symbols"
info "  - RUST_BACKTRACE=1 enabled"
info "=========================================="
echo ""

if [ "${SKIP_REBOOT:-0}" != "1" ] && [ "${NO_REBOOT:-0}" != "1" ]; then
  info "System rebooting in 5 seconds - press Ctrl+C to abort."
  sleep 5
  sudo reboot
else
  info "SKIP_REBOOT set - skipping reboot."
fi
