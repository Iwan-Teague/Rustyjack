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
has_crate_artifact() {
  local crate="$1"
  local mode="${2:-release}"
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

  sudo sh -c "printf '# Managed by Rustyjack\n# Updated by ensure-route\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n' > $resolv"
  sudo chmod 644 "$resolv"
  sudo chown root:root "$resolv"
  info "[OK] $resolv now owned by Rustyjack (plain file, root-writable)"
}

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

# ---- 0: convert CRLF if file came from Windows --------------
if grep -q $'\r' "$0"; then
  step "Converting CRLF to LF in $0"
  cmd dos2unix || { sudo apt-get update -qq && sudo apt-get install -y dos2unix; }
  dos2unix "$0"
fi

# ---- 0.5: ensure working DNS for git/apt --------------------
bootstrap_resolvers

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
  # build tools for Rust compilation
  build-essential pkg-config libssl-dev
  # DKMS for WiFi driver compilation (kernel headers added separately, best-effort)
  dkms bc libelf-dev
  # network / offensive tools (nmap, tcpdump, etc. still useful for advanced operations)
  nmap ncat tcpdump dsniff ettercap-text-only php
  # WiFi interface tools
  # - wireless-tools: legacy WiFi tools (iwconfig, etc.) - needed by some scripts
  # - wpasupplicant: provides wpa_supplicant daemon and wpa_cli for WPA auth fallback
  # - network-manager: provides NetworkManager daemon for D-Bus WiFi management (nmcli not used - we use D-Bus directly)
  wireless-tools wpasupplicant network-manager
  # misc
  git i2c-tools curl
)

# Optional firmware bundles (may require non-free-firmware repo on Debian)
FIRMWARE_PACKAGES=(
  firmware-linux-nonfree firmware-realtek firmware-atheros firmware-ralink firmware-misc-nonfree
)

step "Updating APT and installing dependencies..."
if ! sudo apt-get update -qq; then
  fail "APT update failed. Ensure no other package manager is running (e.g., packagekit) and rerun."
fi

# Only install firmware packages that exist in current apt sources
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
  warn "Enable 'non-free-firmware' in /etc/apt/sources.list on Debian 12+ if you need them."
fi

# Try to pull a kernel headers package (needed only for DKMS WiFi drivers); skip if none available
header_candidates=( "linux-headers-$(uname -r)" "linux-headers-generic" "linux-headers-amd64" "linux-headers-arm64" "raspberrypi-kernel-headers" )
chosen_header=""
for hdr in "${header_candidates[@]}"; do
  if apt-cache show "$hdr" >/dev/null 2>&1; then
    chosen_header="$hdr"
    INSTALL_PACKAGES+=("$hdr")
    break
  fi
done
if [ -z "$chosen_header" ]; then
  warn "No kernel headers package found (needed only if building DKMS WiFi drivers). Skipping."
fi

to_install=()
install_plan=""
if install_plan=$(sudo apt-get -qq --just-print install "${INSTALL_PACKAGES[@]}" 2>/dev/null); then
  to_install=($(echo "$install_plan" | awk '/^Inst/ {print $2}'))
  if ((${#to_install[@]})); then
    info "Will install/upgrade: ${to_install[*]}"
    if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
      if ((${#available_firmware[@]})); then
        warn "APT install failed; retrying without firmware bundles: ${available_firmware[*]}"
        INSTALL_PACKAGES=("${PACKAGES[@]}")
        sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}" || fail "APT install failed even without firmware. Check output above."
      else
        fail "APT install failed. Check output above."
      fi
    fi
  else
    info "All packages already installed and up-to-date."
  fi
else
  warn "APT dry-run failed (likely missing kernel headers or bad sources); attempting full install..."
  if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
    if ((${#available_firmware[@]})); then
      warn "APT install failed; retrying without firmware bundles: ${available_firmware[*]}"
      INSTALL_PACKAGES=("${PACKAGES[@]}")
      sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}" || fail "APT install failed even without firmware. Check output above."
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
sudo mkdir -p "$PROJECT_ROOT/loot"/{Wireless,Ethernet,reports}
sudo chmod -R 755 "$PROJECT_ROOT/loot"

# Create WiFi profiles directory
sudo mkdir -p "$PROJECT_ROOT/wifi/profiles"
sudo chown root:root "$PROJECT_ROOT/wifi/profiles"
sudo chmod 700 "$PROJECT_ROOT/wifi/profiles"

# Note: rfkill unblock and interface up operations now handled by rustyjack-netlink
info "Network interface management delegated to rustyjack-netlink crate"

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
  sudo chmod 600 "$PROJECT_ROOT/wifi/profiles/sample.json"
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

# Claim resolv.conf and adjust DNS control after installs/builds are complete
claim_resolv_conf
check_resolv_conf
# Defer NetworkManager DNS changes until installs/builds are done so apt isn't impacted
configure_dns_control

# ---- 6: final health-check ----------------------------------
step "Running post install checks..."

# 6-a SPI device nodes
if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "[OK] SPI device found: $(ls /dev/spidev* | xargs)"
else
  warn "[X] SPI device NOT found - a reboot may be required"
fi

# 6-b Wireless tools check
if cmd iwconfig; then
  info "[OK] Wireless tools found (iwconfig - legacy reference only)"
else
  warn "[X] wireless-tools missing (optional - used for legacy reference only)"
fi

# 6-b2 WiFi client mode dependencies
if cmd wpa_cli || cmd nmcli; then
  info "[OK] WiFi control present (wpa_cli/nmcli) for client authentication"
else
  warn "[X] Neither wpa_cli nor nmcli found - WiFi client mode needs one of these"
fi

# 6-b3 rustyjack-netlink replaces: ip, rfkill, pgrep/pkill, iw, hostapd, nf_tables, dhclient, dnsmasq
info "[OK] rustyjack-netlink provides native Rust implementations for:"
info "     - ip (network interface management via netlink)"
info "     - rfkill (radio management via /dev/rfkill)"
info "     - pgrep/pkill (process management via /proc)"
info "     - iw (nl80211 wireless operations)"
info "     - hostapd (software AP via nl80211)"
info "     - wpa_supplicant (WPA/WPA2 client authentication)"
info "     - nf_tables (netfilter via nf_tables netlink)"
info "     - dhclient (DHCP client)"
info "     - dnsmasq (DHCP + DNS server)"
info "     - ARP operations (raw sockets)"

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

# 6-e Verify library crates were compiled (Cargo uses hashed filenames under target/*/deps)
if has_crate_artifact "rustyjack_core" "release"; then
  info "[OK] rustyjack-core library compiled"
else
  warn "[X] rustyjack-core library not found in target/release/deps/"
fi

if has_crate_artifact "rustyjack_evasion" "release"; then
  info "[OK] rustyjack-evasion library compiled"
else
  warn "[X] rustyjack-evasion library not found in target/release/deps/"
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
