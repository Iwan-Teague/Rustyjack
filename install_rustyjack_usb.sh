#!/usr/bin/env bash
# Rustyjack USB clone + prebuilt installer (Pi Zero 2 W / arm32)
# - Finds a Rustyjack project on mounted USB storage
# - Copies it to the local PROJECT_ROOT
# - Installs prebuilt arm32 binaries to /usr/local/bin
# - Sets up runtime root, systemd services, and network ownership
#
# Usage:
#   sudo ./install_rustyjack_usb.sh
#
# Environment overrides:
#   SOURCE_ROOT=/path/to/Rustyjack   # explicit USB project root
#   DEST_ROOT=/root/Rustyjack        # where to copy the project locally
#   PREBUILT_DIR=prebuilt/arm32      # relative to project root
#   RUNTIME_ROOT=/var/lib/rustyjack  # runtime root
#   RUSTYJACK_OVERWRITE=1            # overwrite DEST_ROOT if it exists
#   RUSTYJACK_USB_DEBUG=0            # disable verbose RUST_LOG in UI service (default is enabled)
#   SKIP_REBOOT=1                    # do not reboot after install
#   NO_REBOOT=1                      # do not reboot after install
set -euo pipefail
WARN_COUNT=0

# ---- helpers ------------------------------------------------
step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { WARN_COUNT=$((WARN_COUNT + 1)); printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
  fail "This installer must run as root."
fi

export DEBIAN_FRONTEND=noninteractive
if [ -r /etc/os-release ]; then
  . /etc/os-release
  info "OS: ${PRETTY_NAME:-unknown} (${VERSION_CODENAME:-unknown})"
fi

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

bootstrap_resolvers() {
  local resolv="/etc/resolv.conf"
  local content="# Managed by Rustyjack (bootstrap)\n# Ensures DNS during install\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n"
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
  local target="${RUNTIME_ROOT:-/var/lib/rustyjack}/resolv.conf"
  info "Claiming $resolv for Rustyjack (dedicated device)..."
  if command -v lsattr >/dev/null 2>&1; then
    if lsattr -d "$resolv" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      sudo chattr -i "$resolv" 2>/dev/null || warn "[WARN] Failed to clear immutable bit on $resolv"
    fi
  fi
  if [ -L "$resolv" ]; then
    local old_target
    old_target=$(readlink -f "$resolv" 2>/dev/null || true)
    warn "Replacing symlinked $resolv (was -> ${old_target:-unknown}) with Rustyjack-managed symlink"
  elif [ -f "$resolv" ]; then
    sudo cp "$resolv" "${resolv}.rustyjack.bak" 2>/dev/null || true
  fi
  sudo rm -f "$resolv"
  sudo mkdir -p "$(dirname "$target")"
  sudo sh -c "printf '# Managed by Rustyjack\n# Updated by ensure-route\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n' > $target"
  sudo chmod 644 "$target"
  sudo chown root:root "$target"
  sudo ln -sf "$target" "$resolv"
  info "[OK] $resolv now symlinked to $target"
}

validate_network_status() {
  if ! cmd rustyjack; then
    fail "rustyjack CLI not found; cannot validate network status"
  fi

  info "Validating network status via rustyjack..."
  local output=""
  local tries=60
  for _ in $(seq 1 "$tries"); do
    output=$(RUSTYJACK_ROOT="$RUNTIME_ROOT" rustyjack status network --output json 2>/dev/null || true)
    if [ -n "$output" ]; then
      local active=""
      active=$(echo "$output" | sed -n 's/.*"active_uplink":"\\([^"]*\\)".*/\\1/p' | head -n1)
      if [ -z "$active" ]; then
        sleep 1
        continue
      fi
      local route_iface=""
      route_iface=$(echo "$output" | sed -n 's/.*"default_route":{[^}]*"interface":"\\([^"]*\\)".*/\\1/p' | head -n1)
      if [ "$route_iface" != "$active" ]; then
        sleep 1
        continue
      fi
      if echo "$output" | grep -q '"dns_servers":\\[\\]'; then
        sleep 1
        continue
      fi
      if ! echo "$output" | grep -q '"dns_servers":\\['; then
        sleep 1
        continue
      fi
      if ! echo "$output" | grep -Eq "\"name\":\"${active}\"[^}]*\"ip\":\"[^\"]+\"[^}]*\"gateway\":\"[^\"]+\""; then
        sleep 1
        continue
      fi
      info "[OK] Network validation passed"
      return 0
    fi
    sleep 1
  done

  warn "[X] Network validation failed"
  if [ -n "$output" ]; then
    echo "$output"
  fi
  journalctl -u rustyjack-ui.service -n 120 --no-pager 2>/dev/null || true
  return 1
}

preserve_default_route_interface() {
  local iface
  iface=$(awk '$2=="00000000" {print $1; exit}' /proc/net/route 2>/dev/null || true)
  if [ -z "$iface" ]; then
    warn "No default route interface detected; skipping preferred interface update"
    return 0
  fi
  if [ ! -d "/sys/class/net/$iface" ]; then
    warn "Default route interface $iface not found; skipping preferred interface update"
    return 0
  fi

  local pref_dir="$RUNTIME_ROOT/wifi"
  local pref_path="$pref_dir/interface_preferences.json"
  local mac=""
  if [ -r "/sys/class/net/$iface/address" ]; then
    mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null || true)
    mac="${mac//$'\n'/}"
  fi
  local ts
  ts=$(date -Iseconds 2>/dev/null || date)

  info "Preserving default route interface: $iface"
  mkdir -p "$pref_dir"
  cat > "$pref_path" <<EOF
{
  "system_preferred": {
    "interface": "$iface",
    "mac": "${mac}",
    "timestamp": "$ts"
  }
}
EOF
}

purge_network_manager() {
  info "Removing NetworkManager..."
  sudo systemctl stop NetworkManager.service NetworkManager-wait-online.service 2>/dev/null || true
  sudo systemctl disable NetworkManager.service NetworkManager-wait-online.service 2>/dev/null || true
  sudo apt-get -y purge network-manager >/dev/null 2>&1 || true
  sudo apt-get -y autoremove --purge >/dev/null 2>&1 || true
  if dpkg -s network-manager >/dev/null 2>&1; then
    fail "ERROR: network-manager still installed after purge"
  fi
  sudo systemctl mask NetworkManager.service NetworkManager-wait-online.service 2>/dev/null || true
}

disable_conflicting_services() {
  if systemctl list-unit-files | grep -q '^systemd-resolved'; then
    warn "Disabling systemd-resolved to prevent resolv.conf rewrites"
    sudo systemctl disable --now systemd-resolved.service 2>/dev/null || true
    sudo systemctl mask systemd-resolved.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^dhcpcd'; then
    warn "Disabling dhcpcd (Rustyjack owns DHCP)"
    sudo systemctl disable --now dhcpcd.service 2>/dev/null || true
    sudo systemctl mask dhcpcd.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^resolvconf'; then
    warn "Disabling resolvconf to avoid resolv.conf churn"
    sudo systemctl disable --now resolvconf.service 2>/dev/null || true
    sudo systemctl mask resolvconf.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^wpa_supplicant@'; then
    warn "Disabling wpa_supplicant@*.service to avoid competing WiFi ownership"
    for unit in $(systemctl list-units 'wpa_supplicant@*.service' --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
      sudo systemctl disable --now "$unit" 2>/dev/null || true
    done
    sudo systemctl mask wpa_supplicant@.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^wpa_supplicant'; then
    warn "Disabling wpa_supplicant.service to avoid competing WiFi ownership"
    sudo systemctl disable --now wpa_supplicant.service 2>/dev/null || true
    sudo systemctl mask wpa_supplicant.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^systemd-networkd'; then
    warn "Disabling systemd-networkd to avoid competing network ownership"
    sudo systemctl disable --now systemd-networkd.service systemd-networkd-wait-online.service 2>/dev/null || true
    sudo systemctl mask systemd-networkd.service systemd-networkd-wait-online.service 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^systemd-rfkill'; then
    warn "Disabling systemd-rfkill to prevent rfkill state restoration"
    sudo systemctl disable --now systemd-rfkill.service systemd-rfkill.socket 2>/dev/null || true
    sudo systemctl mask systemd-rfkill.service systemd-rfkill.socket 2>/dev/null || true
    sudo rm -f /var/lib/systemd/rfkill/* 2>/dev/null || true
  fi
}

is_rustyjack_root() {
  local root="$1"
  [ -f "$root/Cargo.toml" ] || return 1
  [ -d "$root/prebuilt/arm32" ] || return 1
  [ -f "$root/prebuilt/arm32/rustyjack-ui" ] || return 1
  return 0
}

find_rustyjack_source() {
  if [ -n "${SOURCE_ROOT:-}" ]; then
    if is_rustyjack_root "$SOURCE_ROOT"; then
      echo "$SOURCE_ROOT"
      return 0
    fi
    fail "SOURCE_ROOT does not look like a Rustyjack project: $SOURCE_ROOT"
  fi

  local script_root
  script_root="$(cd "$(dirname "$0")" && pwd)"
  if is_rustyjack_root "$script_root"; then
    echo "$script_root"
    return 0
  fi

  local base
  for base in /media /mnt /run/media; do
    [ -d "$base" ] || continue
    local hit
    hit=$(find "$base" -maxdepth 5 -type f -path "*/prebuilt/arm32/rustyjack-ui" 2>/dev/null | head -n 1 || true)
    if [ -n "$hit" ]; then
      echo "${hit%/prebuilt/arm32/rustyjack-ui}"
      return 0
    fi
  done

  return 1
}

copy_project() {
  local src="$1"
  local dest="$2"

  if [ "$src" = "$dest" ]; then
    info "Source and destination are the same; skipping project copy"
    return 0
  fi

  if [ -e "$dest" ]; then
    if [ "${RUSTYJACK_OVERWRITE:-0}" != "1" ]; then
      warn "Destination already exists: $dest"
      read -r -p "Overwrite $dest with USB contents? [y/N] " answer
      if [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        fail "Aborted by user"
      fi
    fi
    if [ -z "$dest" ] || [ "$dest" = "/" ]; then
      fail "Refusing to overwrite empty or root destination"
    fi
    sudo rm -rf "$dest"
  fi

  sudo mkdir -p "$dest"
  if cmd rsync; then
    sudo rsync -a "$src"/ "$dest"/
  else
    sudo cp -a "$src"/. "$dest"/
  fi
}

ensure_rw_root

bootstrap_resolvers

# ---- 0: convert CRLF if file came from Windows --------------
if grep -q $'\r' "$0"; then
  step "Converting CRLF to LF in $0"
  cmd dos2unix || { sudo apt-get update -qq && sudo apt-get install -y dos2unix; }
  dos2unix "$0"
fi

step "Locating Rustyjack project on mounted storage..."
SOURCE_ROOT="$(find_rustyjack_source || true)"
if [ -z "$SOURCE_ROOT" ]; then
  fail "Rustyjack project not found on mounted USB. Set SOURCE_ROOT=/path/to/Rustyjack."
fi
info "Found Rustyjack source: $SOURCE_ROOT"

DEST_ROOT="${DEST_ROOT:-/root/Rustyjack}"
step "Copying Rustyjack project to $DEST_ROOT..."
copy_project "$SOURCE_ROOT" "$DEST_ROOT"

PROJECT_ROOT="$DEST_ROOT"
RUNTIME_ROOT="${RUNTIME_ROOT:-/var/lib/rustyjack}"
info "Using project root: $PROJECT_ROOT"
info "Using runtime root: $RUNTIME_ROOT"

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
  # build tools (keep parity with dev installer)
  build-essential pkg-config libssl-dev
  # WiFi tools
  wpasupplicant
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
  warn "APT dry-run failed; attempting full install..."
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

# Ensure buttons use internal pull-ups
if ! grep -q "^gpio=6,19,5,26,13,21,20,16=pu" "$CFG" ; then
  echo 'gpio=6,19,5,26,13,21,20,16=pu' | sudo tee -a "$CFG" >/dev/null
  info "Pinned button GPIOs to pull-ups in $CFG"
fi

# ---- 4: install prebuilt binaries ---------------------------
PREBUILT_DIR="${PREBUILT_DIR:-prebuilt/arm32}"
BINARY_NAME="rustyjack-ui"
PREBUILT_BIN="$PROJECT_ROOT/$PREBUILT_DIR/$BINARY_NAME"
CLI_NAME="rustyjack"
PREBUILT_CLI="$PROJECT_ROOT/$PREBUILT_DIR/$CLI_NAME"
DAEMON_NAME="rustyjackd"
PREBUILT_DAEMON="$PROJECT_ROOT/$PREBUILT_DIR/$DAEMON_NAME"
PORTAL_NAME="rustyjack-portal"
PREBUILT_PORTAL="$PROJECT_ROOT/$PREBUILT_DIR/$PORTAL_NAME"

if [ ! -f "$PREBUILT_BIN" ]; then
  fail "Prebuilt binary not found: $PREBUILT_BIN"
fi
if [ ! -f "$PREBUILT_CLI" ]; then
  fail "Prebuilt CLI not found: $PREBUILT_CLI"
fi
if [ ! -f "$PREBUILT_DAEMON" ]; then
  fail "Prebuilt daemon not found: $PREBUILT_DAEMON"
fi
if [ ! -f "$PREBUILT_PORTAL" ]; then
  fail "Prebuilt portal not found: $PREBUILT_PORTAL"
fi

if [ ! -x "$PREBUILT_BIN" ]; then
  chmod +x "$PREBUILT_BIN" || warn "Failed to chmod +x $PREBUILT_BIN"
fi
if [ ! -x "$PREBUILT_DAEMON" ]; then
  chmod +x "$PREBUILT_DAEMON" || warn "Failed to chmod +x $PREBUILT_DAEMON"
fi
if [ ! -x "$PREBUILT_PORTAL" ]; then
  chmod +x "$PREBUILT_PORTAL" || warn "Failed to chmod +x $PREBUILT_PORTAL"
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

step "Stopping existing services..."
sudo systemctl stop rustyjack-ui.service 2>/dev/null || true
sudo systemctl stop rustyjack.service 2>/dev/null || true
sudo systemctl stop rustyjackd.service 2>/dev/null || true
sudo systemctl stop rustyjackd.socket 2>/dev/null || true

step "Removing old binaries..."
sudo rm -f /usr/local/bin/$BINARY_NAME /usr/local/bin/$CLI_NAME /usr/local/bin/$DAEMON_NAME /usr/local/bin/$PORTAL_NAME

step "Installing prebuilt binaries to /usr/local/bin/..."
sudo install -Dm755 "$PREBUILT_BIN" /usr/local/bin/$BINARY_NAME
sudo install -Dm755 "$PREBUILT_CLI" /usr/local/bin/$CLI_NAME
sudo install -Dm755 "$PREBUILT_DAEMON" /usr/local/bin/$DAEMON_NAME
sudo install -Dm755 "$PREBUILT_PORTAL" /usr/local/bin/$PORTAL_NAME

# ---- 5: WiFi attack setup -----------------------------------
step "Setting up WiFi attack environment..."

# Prepare runtime root and static assets
sudo mkdir -p "$RUNTIME_ROOT"
for dir in img scripts wordlists DNSSpoof; do
  if [ -d "$PROJECT_ROOT/$dir" ] && [ ! -d "$RUNTIME_ROOT/$dir" ]; then
    sudo cp -a "$PROJECT_ROOT/$dir" "$RUNTIME_ROOT/"
  fi
done

# Create loot directories
sudo mkdir -p "$RUNTIME_ROOT/loot"/{Wireless,Ethernet,Scan,reports,Hotspot,logs}
sudo chmod -R 755 "$RUNTIME_ROOT/loot"

sudo mkdir -p "$RUNTIME_ROOT/wifi/profiles"
sudo chown root:root "$RUNTIME_ROOT/wifi/profiles"
sudo chmod 700 "$RUNTIME_ROOT/wifi/profiles"

# Create pipelines directory (used by scan pipeline)
sudo mkdir -p "$RUNTIME_ROOT/pipelines"

info "Network interface management delegated to rustyjack-netlink crate"

if [ ! -f "$RUNTIME_ROOT/wifi/profiles/sample.json" ]; then
  sudo tee "$RUNTIME_ROOT/wifi/profiles/sample.json" >/dev/null <<'PROFILE'
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
  sudo chmod 600 "$RUNTIME_ROOT/wifi/profiles/sample.json"
  info "Created sample WiFi profile"
fi

if [ ! -f "$RUNTIME_ROOT/wifi/profiles/rustyjack.json" ]; then
  sudo tee "$RUNTIME_ROOT/wifi/profiles/rustyjack.json" >/dev/null <<'PROFILE'
{
  "ssid": "rustyjack",
  "password": "123456789",
  "interface": "auto",
  "priority": 1,
  "auto_connect": true,
  "created": "2024-01-01T12:00:00",
  "last_used": null,
  "notes": "Preloaded WiFi profile"
}
PROFILE
  sudo chmod 600 "$RUNTIME_ROOT/wifi/profiles/rustyjack.json"
  info "Created default WiFi profile: rustyjack"
fi

if [ ! -f "$RUNTIME_ROOT/wifi/profiles/skyhn7xm.json" ]; then
  sudo tee "$RUNTIME_ROOT/wifi/profiles/skyhn7xm.json" >/dev/null <<'PROFILE'
{
  "ssid": "SKYHN7XM",
  "password": "6HekvGQvxuVV",
  "interface": "auto",
  "priority": 1,
  "auto_connect": true,
  "created": "2024-01-01T12:00:00",
  "last_used": null,
  "notes": "Preloaded WiFi profile"
}
PROFILE
  sudo chmod 600 "$RUNTIME_ROOT/wifi/profiles/skyhn7xm.json"
  info "Created default WiFi profile: SKYHN7XM"
fi

# ---- 6: systemd service -------------------------------------
step "Ensuring rustyjack system users/groups exist..."
if ! getent group rustyjack >/dev/null 2>&1; then
  sudo groupadd --system rustyjack || true
fi
if ! getent group rustyjack-ui >/dev/null 2>&1; then
  sudo groupadd --system rustyjack-ui || true
fi
if ! getent group rustyjack-portal >/dev/null 2>&1; then
  sudo groupadd --system rustyjack-portal || true
fi
if ! id -u rustyjack-ui >/dev/null 2>&1; then
  sudo useradd --system --home /var/lib/rustyjack --shell /usr/sbin/nologin -g rustyjack-ui rustyjack-ui || true
fi
if ! id -u rustyjack-portal >/dev/null 2>&1; then
  sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin -g rustyjack-portal rustyjack-portal || true
fi
for grp in rustyjack gpio spi; do
  if getent group "$grp" >/dev/null 2>&1; then
    sudo usermod -aG "$grp" rustyjack-ui || true
  fi
done

# Create portal directories with proper ownership
sudo mkdir -p "$RUNTIME_ROOT/portal/site"
sudo mkdir -p "$RUNTIME_ROOT/loot/Portal"
sudo chown -R rustyjack-portal:rustyjack-portal "$RUNTIME_ROOT/portal"
sudo chown -R rustyjack-portal:rustyjack-portal "$RUNTIME_ROOT/loot/Portal"
sudo chmod -R 755 "$RUNTIME_ROOT/portal"
sudo chmod -R 755 "$RUNTIME_ROOT/loot/Portal"

sudo chown -R root:rustyjack "$RUNTIME_ROOT"
sudo chmod -R g+rwX "$RUNTIME_ROOT"
sudo find "$RUNTIME_ROOT/wifi/profiles" -type f -exec chmod 660 {} \; 2>/dev/null || true
sudo chmod 770 "$RUNTIME_ROOT/wifi/profiles" 2>/dev/null || true

DAEMON_SOCKET=/etc/systemd/system/rustyjackd.socket
DAEMON_SERVICE=/etc/systemd/system/rustyjackd.service
step "Installing rustyjackd socket/service..."

sudo tee "$DAEMON_SOCKET" >/dev/null <<UNIT
[Unit]
Description=Rustyjack daemon socket

[Socket]
ListenStream=/run/rustyjack/rustyjackd.sock
SocketMode=0660
SocketUser=root
SocketGroup=rustyjack
RemoveOnStop=true

[Install]
WantedBy=sockets.target
UNIT

sudo tee "$DAEMON_SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack privileged daemon
Requires=rustyjackd.socket
After=local-fs.target network.target rustyjackd.socket
Wants=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/rustyjackd
Restart=on-failure
RestartSec=2
RuntimeDirectory=rustyjack
RuntimeDirectoryMode=0770
StateDirectory=rustyjack
StateDirectoryMode=0770
ConfigurationDirectory=rustyjack
ConfigurationDirectoryMode=0770
Group=rustyjack
Environment=RUSTYJACK_ROOT=$RUNTIME_ROOT
Environment=RUSTYJACKD_SOCKET_GROUP=rustyjack
WatchdogSec=20s
NotifyAccess=main
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

SERVICE=/etc/systemd/system/rustyjack-ui.service
step "Installing systemd service $SERVICE..."

RUSTYJACK_USB_DEBUG="${RUSTYJACK_USB_DEBUG:-1}"
UI_ENV_EXTRA=""
if [ "$RUSTYJACK_USB_DEBUG" = "1" ]; then
  UI_ENV_EXTRA=$'Environment=RUST_BACKTRACE=1\nEnvironment="RUST_LOG=rustyjack_hotspot=trace,rustyjack_netlink=trace,rustyjack_wireless=trace,rustyjack_ui=debug"'
else
  UI_ENV_EXTRA="Environment=RUST_BACKTRACE=1"
fi

sudo tee "$SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack UI Service (prebuilt USB clone)
After=local-fs.target network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=$RUNTIME_ROOT
ExecStart=/usr/local/bin/$BINARY_NAME
Environment=RUSTYJACK_DISPLAY_ROTATION=landscape
$UI_ENV_EXTRA
Restart=on-failure
RestartSec=2
User=rustyjack-ui
Group=rustyjack-ui
SupplementaryGroups=rustyjack gpio spi
Environment=RUSTYJACK_ROOT=$RUNTIME_ROOT
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
Alias=rustyjack.service
UNIT

PORTAL_SERVICE=/etc/systemd/system/rustyjack-portal.service
step "Installing portal service $PORTAL_SERVICE..."

sudo tee "$PORTAL_SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack Portal Service (Unprivileged)
After=rustyjackd.service
Requires=rustyjackd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/rustyjack-portal
Restart=on-failure
RestartSec=2
User=rustyjack-portal
Group=rustyjack-portal
SupplementaryGroups=rustyjack
Environment=RUSTYJACK_PORTAL_PORT=3000
Environment=RUSTYJACK_PORTAL_BIND=0.0.0.0
Environment=RUSTYJACK_DAEMON_SOCKET=/run/rustyjack/rustyjackd.sock
Environment=RUSTYJACK_ROOT=$RUNTIME_ROOT
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$RUNTIME_ROOT/portal $RUNTIME_ROOT/loot/Portal $RUNTIME_ROOT/logs
PrivateTmp=true
NoNewPrivileges=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
WorkingDirectory=$RUNTIME_ROOT/portal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rustyjack-portal

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable rustyjackd.socket
sudo systemctl start rustyjackd.socket 2>/dev/null || true
sudo systemctl enable rustyjackd.service
sudo systemctl start rustyjackd.service 2>/dev/null || warn "Failed to start rustyjackd.service - check journalctl -u rustyjackd"
sudo systemctl enable rustyjack-ui.service
sudo systemctl enable rustyjack-portal.service
info "Rustyjack services enabled"

# Finalize network ownership after installs are complete
step "Finalizing network ownership..."
preserve_default_route_interface
purge_network_manager
disable_conflicting_services

# Start the services now
sudo systemctl start rustyjack-ui.service && info "Rustyjack UI service started successfully" || warn "Failed to start UI service - check 'systemctl status rustyjack-ui'"
sudo systemctl start rustyjack-portal.service && info "Rustyjack Portal service started successfully" || warn "Failed to start Portal service - check 'systemctl status rustyjack-portal'"

# Claim resolv.conf after installs are complete
claim_resolv_conf
check_resolv_conf

step "Validating network status..."
validate_network_status || fail "Network validation failed"

# ---- 7: final health-check ----------------------------------
step "Running post install checks..."

if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "[OK] SPI device found"
else
  warn "[X] SPI device NOT found - reboot may be required"
fi

if cmd wpa_cli; then
  info "[OK] WiFi control present (wpa_cli) for client authentication"
else
  warn "[X] wpa_cli not found - WiFi client mode needs wpa_supplicant"
fi

info "[OK] Rustyjack provides native Rust implementations for:"
info "     netlink interface control (native Rust)"
info "     rfkill (radio management via /dev/rfkill)"
info "     process management (pgrep/pkill via /proc)"
info "     hostapd (software AP via nl80211)"
info "     nf_tables (netfilter via nf_tables netlink)"
info "     DHCP + DNS services (native Rust)"
info "     ARP operations (raw sockets)"

if [ -x /usr/local/bin/$BINARY_NAME ]; then
  info "[OK] UI binary installed: $BINARY_NAME"
else
  fail "[X] UI binary missing"
fi

if [ -x /usr/local/bin/$CLI_NAME ]; then
  info "[OK] CLI binary installed: $CLI_NAME"
else
  fail "[X] CLI binary missing"
fi

if [ -x /usr/local/bin/$DAEMON_NAME ]; then
  info "[OK] daemon binary installed: $DAEMON_NAME"
else
  fail "[X] daemon binary missing"
fi

if [ -x /usr/local/bin/$PORTAL_NAME ]; then
  info "[OK] portal binary installed: $PORTAL_NAME"
else
  warn "[X] portal binary missing"
fi

if systemctl is-active --quiet rustyjack-ui.service; then
  info "[OK] Rustyjack service is running"
else
  warn "[X] Rustyjack service is not running"
fi

echo ""
step "USB install finished!"
info "=========================================="
info "  PREBUILT (ARM32) INSTALLED"
info "  - Rustyjack copied from USB to $PROJECT_ROOT"
info "  - Runtime root: $RUNTIME_ROOT"
info "=========================================="
echo ""

if [ "$WARN_COUNT" -gt 0 ]; then
  warn "Warnings detected ($WARN_COUNT). Skipping reboot to allow debugging."
elif [ "${SKIP_REBOOT:-0}" != "1" ] && [ "${NO_REBOOT:-0}" != "1" ]; then
  info "System rebooting in 5 seconds - press Ctrl+C to abort."
  sleep 5
  sudo reboot
else
  info "SKIP_REBOOT set - skipping reboot."
fi
