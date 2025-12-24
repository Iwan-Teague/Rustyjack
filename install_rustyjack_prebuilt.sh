#!/usr/bin/env bash
# Installer that uses prebuilt binaries instead of building on-device
# Usage: sudo PREBUILT_DIR=prebuilt/arm32 ./install_rustyjack_prebuilt.sh
set -euo pipefail

step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }

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

bootstrap_resolvers() {
  local resolv="/etc/resolv.conf"
  local content="# Managed by Rustyjack (bootstrap)\n# Ensures DNS during install\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
  info "Bootstrapping $resolv for installer DNS..."
  if command -v lsattr >/dev/null 2>&1; then
    if lsattr -d "$resolv" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      sudo chattr -i "$resolv" 2>/dev/null || true
    fi
  fi
  if [ -L "$resolv" ]; then
    warn "Replacing symlinked $resolv with static resolver file for install"
    sudo rm -f "$resolv"
  fi
  echo -e "$content" | sudo tee "$resolv" >/dev/null
  sudo chmod 644 "$resolv"
  sudo chown root:root "$resolv"
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
  sudo sh -c "printf '# Managed by Rustyjack\n# Updated by ensure-route\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n' > $resolv"
  sudo chmod 644 "$resolv"
  sudo chown root:root "$resolv"
  info "[OK] $resolv now owned by Rustyjack (plain file, root-writable)"
}

configure_dns_control() {
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

# ---- 1: locate active config.txt ----------------------------
CFG=/boot/firmware/config.txt; [[ -f $CFG ]] || CFG=/boot/config.txt
if [ ! -f "$CFG" ]; then
  sudo mkdir -p "$(dirname "$CFG")"
  echo "# Rustyjack config (created by installer)" | sudo tee "$CFG" >/dev/null
fi
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
  # WiFi interface tools
  # - wireless-tools: legacy WiFi tools (iwconfig, etc.) - needed by some scripts
  # - wpasupplicant: provides wpa_supplicant daemon and wpa_cli for WPA auth fallback
  # - network-manager: provides NetworkManager daemon for D-Bus WiFi management
  wireless-tools wpasupplicant network-manager
  # networking tools
  iproute2 isc-dhcp-client iw hostapd dnsmasq rfkill
  # misc
  git i2c-tools curl
)

# Optional firmware bundles (may require non-free-firmware repo on Debian)
FIRMWARE_PACKAGES=(
  firmware-linux-nonfree firmware-realtek firmware-atheros firmware-ralink firmware-misc-nonfree
)

step "Updating APT and installing dependencies..."
if ! sudo apt-get update -qq; then
  fail "APT update failed. Ensure no other package manager is running and rerun."
fi

INSTALL_PACKAGES=("${PACKAGES[@]}")
available_firmware=()
missing_firmware=()
for pkg in "${FIRMWARE_PACKAGES[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    available_firmware+=("$pkg")
  else
    missing_firmware+=("$pkg")
  fi
done
if ((${#available_firmware[@]})); then
  INSTALL_PACKAGES+=("${available_firmware[@]}")
fi
if ((${#missing_firmware[@]})); then
  warn "Skipping unavailable firmware packages: ${missing_firmware[*]}"
  warn "Enable 'non-free-firmware' in /etc/apt/sources.list on Debian 12+ if needed."
fi

to_install=()
install_plan=""
if install_plan=$(sudo apt-get -qq --just-print install "${INSTALL_PACKAGES[@]}" 2>/dev/null); then
  to_install=($(echo "$install_plan" | awk '/^Inst/ {print $2}'))
  if ((${#to_install[@]})); then
    info "Will install/upgrade: ${to_install[*]}"
    if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
      if ((${#available_firmware[@]})); then
        warn "APT install failed; retrying without firmware bundles"
        INSTALL_PACKAGES=("${PACKAGES[@]}")
        sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}" || fail "APT install failed. Check output above."
      else
        fail "APT install failed. Check output above."
      fi
    fi
  else
    info "All packages already installed and up-to-date."
  fi
else
  warn "APT dry-run failed; attempting full install..."
  if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
    if ((${#available_firmware[@]})); then
      warn "APT install failed; retrying without firmware bundles"
      INSTALL_PACKAGES=("${PACKAGES[@]}")
      sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}" || fail "APT install failed."
    else
      fail "APT install failed. Check output above."
    fi
  fi
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

# Ensure buttons use internal pull-ups
if ! grep -q "^gpio=6,19,5,26,13,21,20,16=pu" "$CFG" ; then
  echo 'gpio=6,19,5,26,13,21,20,16=pu' | sudo tee -a "$CFG" >/dev/null
  info "Pinned button GPIOs to pull-ups in $CFG"
fi

# Start
bootstrap_resolvers

PROJECT_ROOT="${PROJECT_ROOT:-/root/Rustyjack}"
if [ ! -d "$PROJECT_ROOT" ]; then
  PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
fi
info "Using project root: $PROJECT_ROOT"

PREBUILT_DIR="${PREBUILT_DIR:-prebuilt/arm32}"
BINARY_NAME="rustyjack-ui"
PREBUILT_BIN="$PROJECT_ROOT/$PREBUILT_DIR/$BINARY_NAME"

if [ ! -f "$PREBUILT_BIN" ]; then
  fail "Prebuilt binary not found: $PREBUILT_BIN\nPlace your arm32 binary at $PREBUILT_BIN or set PREBUILT_DIR to its location."
fi

# Ensure the prebuilt binary is executable and appears to be a 32-bit ARM ELF
if [ ! -x "$PREBUILT_BIN" ]; then
  info "Making prebuilt binary executable: $PREBUILT_BIN"
  chmod +x "$PREBUILT_BIN" || warn "Failed to chmod +x $PREBUILT_BIN"
fi
if command -v file >/dev/null 2>&1; then
  arch_info=$(file -b "$PREBUILT_BIN" || true)
  if echo "$arch_info" | grep -qiE 'ELF 32-bit.*ARM|ARM, EABI|ARM aarch32'; then
    info "[OK] Prebuilt binary looks like 32-bit ARM: $arch_info"
  else
    warn "Prebuilt binary does not look like 32-bit ARM: $arch_info"
    warn "Proceeding anyway; ensure the binary matches your Pi's userspace (armhf/armv7)."
  fi
fi

step "Stopping existing service (if any)..."
sudo systemctl stop rustyjack.service 2>/dev/null || true

step "Removing old binary (if present)..."
sudo rm -f /usr/local/bin/$BINARY_NAME

step "Installing prebuilt binary to /usr/local/bin/"
sudo install -Dm755 "$PREBUILT_BIN" /usr/local/bin/$BINARY_NAME || fail "Failed to install binary"

# Create necessary directories
step "Creating runtime directories"
sudo mkdir -p "$PROJECT_ROOT/loot"/{Wireless,Ethernet,reports} 2>/dev/null || true
sudo mkdir -p "$PROJECT_ROOT/wifi/profiles"
sudo chown root:root "$PROJECT_ROOT/wifi/profiles" 2>/dev/null || true
sudo chmod 700 "$PROJECT_ROOT/wifi/profiles" 2>/dev/null || true

# Copy helper scripts
step "Installing helper scripts"
sudo mkdir -p "$PROJECT_ROOT/scripts"
sudo cp -f scripts/wifi_driver_installer.sh "$PROJECT_ROOT/scripts/" 2>/dev/null || true
sudo cp -f scripts/wifi_hotplug.sh "$PROJECT_ROOT/scripts/" 2>/dev/null || true
sudo chmod +x "$PROJECT_ROOT/scripts/"*.sh 2>/dev/null || true

if [ -f scripts/99-rustyjack-wifi.rules ]; then
  sudo cp -f scripts/99-rustyjack-wifi.rules /etc/udev/rules.d/
  sudo udevadm control --reload-rules
  sudo udevadm trigger
  info "Installed USB WiFi auto-detection udev rules"
fi

# Sample profile
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
  sudo chmod 600 "$PROJECT_ROOT/wifi/profiles/sample.json" 2>/dev/null || true
  info "Created sample WiFi profile"
fi

# systemd service
SERVICE=/etc/systemd/system/rustyjack.service
step "Installing systemd service $SERVICE..."

sudo tee "$SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack UI Service (prebuilt)
After=local-fs.target
Wants=local-fs.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_ROOT
ExecStart=/usr/local/bin/$BINARY_NAME
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
info "Rustyjack service enabled"

# Start the service now
sudo systemctl start rustyjack.service && info "Rustyjack service started successfully" || warn "Failed to start service - check 'systemctl status rustyjack'"

# Final adjustments
claim_resolv_conf
check_resolv_conf
configure_dns_control

# Health-check: binary
if [ -x /usr/local/bin/$BINARY_NAME ]; then
  info "[OK] Prebuilt Rust binary installed: $BINARY_NAME"
else
  fail "[X] Binary missing or not executable at /usr/local/bin/$BINARY_NAME"
fi

# Health-check: hardware
step "Running post install checks..."

if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "[OK] SPI device found"
else
  warn "[X] SPI device NOT found - reboot may be required"
fi

if cmd iwconfig; then
  info "[OK] Wireless tools found (legacy reference only)"
else
  warn "[X] wireless-tools missing (optional)"
fi

if cmd wpa_cli || cmd nmcli; then
  info "[OK] WiFi control present (wpa_cli/nmcli) for client authentication"
else
  warn "[X] Neither wpa_cli nor nmcli found - WiFi client mode needs one of these"
fi

# rustyjack-netlink provides native implementations
info "[OK] rustyjack-netlink provides native Rust implementations for:"
info "     ip, rfkill, pgrep/pkill, hostapd, dnsmasq, dhclient,"
info "     nf_tables, and ARP operations"

if systemctl is-active --quiet rustyjack.service; then
  info "[OK] Rustyjack service is running"
else
  warn "[X] Rustyjack service is not running"
fi

info "Prebuilt installation finished. Reboot is recommended."
if [ "${SKIP_REBOOT:-0}" != "1" ] && [ "${NO_REBOOT:-0}" != "1" ]; then
  info "Rebooting in 5 seconds..."
  sleep 5
  sudo reboot
else
  info "SKIP_REBOOT set - skipping reboot."
fi
