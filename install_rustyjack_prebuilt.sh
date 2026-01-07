#!/usr/bin/env bash
# Installer that uses prebuilt binaries instead of building on-device
# Usage: sudo PREBUILT_DIR=prebuilt/arm32 ./install_rustyjack_prebuilt.sh
# Environment overrides:
#   PREBUILT_DIR=prebuilt/arm32   # relative to project root or absolute path
#   USB_MOUNT_POINT=/mnt/usb      # where to mount removable media
#   USB_DEVICE=/dev/sda1          # explicit USB block device to mount
set -euo pipefail

step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
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
ensure_rw_root

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
      local route_iface=""
      route_iface=$(echo "$output" | sed -n 's/.*"default_route":{[^}]*"interface":"\\([^"]*\\)".*/\\1/p' | head -n1)
      if [ -z "$active" ]; then
        if [ -n "$route_iface" ] && echo "$output" | grep -Eq "\"name\":\"${route_iface}\"[^}]*\"ip\":\"[^\"]+\"[^}]*\"gateway\":\"[^\"]+\"" && \
           ! echo "$output" | grep -q '"dns_servers":\[\]' && echo "$output" | grep -q '"dns_servers":\['; then
          info "[OK] Default route $route_iface has DNS and gateway; assuming active uplink"
          return 0
        fi
        sleep 1
        continue
      fi
      if [ "$route_iface" != "$active" ]; then
        sleep 1
        continue
      fi
      if echo "$output" | grep -q '"dns_servers":\[\]'; then
        sleep 1
        continue
      fi
      if ! echo "$output" | grep -q '"dns_servers":\['; then
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
  sudo sh -c "printf '# Managed by Rustyjack\n# Updated by ensure-route\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n' > $resolv"
  sudo chmod 644 "$resolv"
  sudo chown root:root "$resolv"
  info "[OK] $resolv now owned by Rustyjack (plain file, root-writable)"
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
}

is_mountpoint() {
  local path="$1"
  if cmd mountpoint; then
    if mountpoint -q "$path"; then
      return 0
    fi
    return 1
  else
    if grep -qs " $path " /proc/mounts; then
      return 0
    fi
    return 1
  fi
}

progress_bar() {
  local current="$1"
  local total="$2"
  local width=10
  if [ "$total" -le 0 ]; then
    return 0
  fi
  local filled=$((current * width / total))
  local empty=$((width - filled))
  local i
  printf "\r["
  for ((i=0;i<filled;i++)); do printf "="; done
  if [ "$filled" -lt "$width" ]; then
    printf ">"
    empty=$((empty - 1))
  fi
  for ((i=0;i<empty;i++)); do printf " "; done
  printf "] %d/%d" "$current" "$total"
}

find_usb_partition() {
  if [ -n "${USB_DEVICE:-}" ]; then
    echo "$USB_DEVICE"
    return 0
  fi
  if cmd lsblk; then
    local dev=""
    dev=$(lsblk -rno NAME,RM,FSTYPE,MOUNTPOINT 2>/dev/null | awk '$2==1 && $3 != "" && $4 == "" {print $1; exit}' || true)
    if [ -n "$dev" ]; then
      echo "/dev/$dev"
      return 0
    fi
  fi
  if [ -d /dev/disk/by-id ]; then
    local byid=""
    byid=$(ls -1 /dev/disk/by-id/usb-*part* 2>/dev/null | head -n 1 || true)
    if [ -n "$byid" ]; then
      local resolved=""
      resolved=$(readlink -f "$byid" 2>/dev/null || true)
      if [ -n "$resolved" ]; then
        echo "$resolved"
        return 0
      fi
    fi
  fi
  return 1
}

mount_usb_if_needed() {
  local mount_point="${USB_MOUNT_POINT:-/mnt/usb}"
  if is_mountpoint "$mount_point"; then
    return 0
  fi
  local dev=""
  dev="$(find_usb_partition || true)"
  if [ -z "$dev" ]; then
    return 1
  fi
  info "Mounting USB device $dev at $mount_point..."
  sudo mkdir -p "$mount_point"
  if sudo mount "$dev" "$mount_point"; then
    return 0
  fi
  warn "Failed to mount $dev at $mount_point"
  return 1
}

find_prebuilt_dir_on_mounts() {
  local base=""
  for base in "${USB_MOUNT_POINT:-/mnt/usb}" /media /mnt /run/media; do
    [ -d "$base" ] || continue
  local candidate=""
  for candidate in \
    "$base"/Rustyjack/Prebuilt/arm32 \
      "$base"/Rustyjack/prebuilt/arm32 \
      "$base"/rustyjack/Prebuilt/arm32 \
      "$base"/rustyjack/prebuilt/arm32; do
      if [ -f "$candidate/$BINARY_NAME" ]; then
        echo "$candidate"
        return 0
      fi
    done

    local hit=""
    hit=$(find "$base" -maxdepth 6 -type f \( -path "*/prebuilt/arm32/$BINARY_NAME" -o -path "*/Prebuilt/arm32/$BINARY_NAME" \) 2>/dev/null | head -n 1 || true)
    if [ -n "$hit" ]; then
      echo "${hit%/$BINARY_NAME}"
      return 0
    fi
  done
  return 1
}

default_route_interface() {
  if ! cmd ip; then
    return 1
  fi
  local dev
  dev=$(ip route show default 2>/dev/null | awk '/default/ {for (i=1; i<=NF; ++i) if ($i=="dev") print $(i+1); exit}')
  if [ -n "$dev" ]; then
    printf "%s" "$dev"
    return 0
  fi
  return 1
}

copy_prebuilt_from_usb() {
  local dest_dir="$PROJECT_ROOT/prebuilt/arm32"
  local src_dir=""

  src_dir="$(find_prebuilt_dir_on_mounts || true)"
  if [ -z "$src_dir" ]; then
    if mount_usb_if_needed; then
      src_dir="$(find_prebuilt_dir_on_mounts || true)"
    fi
  fi
  if [ -z "$src_dir" ]; then
    return 1
  fi

  info "Found prebuilt binaries on USB: $src_dir"
  sudo mkdir -p "$dest_dir"
  info "Copying prebuilt binaries to $dest_dir"

  local copied=0
  local bins=("$BINARY_NAME" "$CLI_NAME" "$DAEMON_NAME" "$PORTAL_NAME")
  local total="${#bins[@]}"
  local current=0
  progress_bar 0 "$total"
  local bin=""
  for bin in "${bins[@]}"; do
    if [ -f "$src_dir/$bin" ]; then
      sudo install -Dm755 "$src_dir/$bin" "$dest_dir/$bin"
      copied=1
    else
      warn "Missing $bin in $src_dir"
    fi
    current=$((current + 1))
    progress_bar "$current" "$total"
  done
  printf "\n"

  if [ "$copied" -eq 1 ]; then
    info "Copied prebuilt binaries into $dest_dir"
    return 0
  fi
  return 1
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
  # - wpasupplicant: provides wpa_supplicant daemon and wpa_cli for WPA auth fallback
  wpasupplicant
  # networking tools
  isc-dhcp-client hostapd dnsmasq rfkill
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
RUNTIME_ROOT="${RUNTIME_ROOT:-/var/lib/rustyjack}"
info "Using runtime root: $RUNTIME_ROOT"

DEFAULT_PREBUILT_DIR="prebuilt/arm32"
PREBUILT_DIR="${PREBUILT_DIR:-$DEFAULT_PREBUILT_DIR}"
BINARY_NAME="rustyjack-ui"
CLI_NAME="rustyjack"
DAEMON_NAME="rustyjackd"
PORTAL_NAME="rustyjack-portal"
resolve_prebuilt_root() {
  local dir="$1"
  case "$dir" in
    /*) printf "%s" "$dir" ;;
    *) printf "%s/%s" "$PROJECT_ROOT" "$dir" ;;
  esac
}
set_prebuilt_paths() {
  PREBUILT_ROOT="$(resolve_prebuilt_root "$PREBUILT_DIR")"
  PREBUILT_BIN="$PREBUILT_ROOT/$BINARY_NAME"
  PREBUILT_CLI="$PREBUILT_ROOT/$CLI_NAME"
  PREBUILT_DAEMON="$PREBUILT_ROOT/$DAEMON_NAME"
  PREBUILT_PORTAL="$PREBUILT_ROOT/$PORTAL_NAME"
}

set_prebuilt_paths

if [ ! -f "$PREBUILT_BIN" ] || [ ! -f "$PREBUILT_CLI" ] || [ ! -f "$PREBUILT_DAEMON" ] || [ ! -f "$PREBUILT_PORTAL" ]; then
  if copy_prebuilt_from_usb; then
    PREBUILT_DIR="$DEFAULT_PREBUILT_DIR"
    set_prebuilt_paths
    info "Using prebuilt binaries from $PREBUILT_ROOT"
  fi
fi

if [ ! -f "$PREBUILT_BIN" ]; then
  fail "Prebuilt binary not found: $PREBUILT_BIN\nPlace your arm32 binary at $PREBUILT_BIN or set PREBUILT_DIR to its location."
fi
if [ ! -f "$PREBUILT_CLI" ]; then
  fail "Prebuilt CLI not found: $PREBUILT_CLI\nPlace your arm32 CLI binary at $PREBUILT_CLI (rustyjack-core) or set PREBUILT_DIR accordingly."
fi
if [ ! -f "$PREBUILT_DAEMON" ]; then
  fail "Prebuilt daemon not found: $PREBUILT_DAEMON\nPlace your arm32 daemon binary at $PREBUILT_DAEMON or set PREBUILT_DIR accordingly."
fi

# Ensure the prebuilt binary is executable and appears to be a 32-bit ARM ELF
if [ ! -x "$PREBUILT_BIN" ]; then
  info "Making prebuilt binary executable: $PREBUILT_BIN"
  chmod +x "$PREBUILT_BIN" || warn "Failed to chmod +x $PREBUILT_BIN"
fi
if [ ! -x "$PREBUILT_DAEMON" ]; then
  info "Making prebuilt daemon executable: $PREBUILT_DAEMON"
  chmod +x "$PREBUILT_DAEMON" || warn "Failed to chmod +x $PREBUILT_DAEMON"
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
sudo systemctl stop rustyjack-ui.service 2>/dev/null || true
sudo systemctl stop rustyjack.service 2>/dev/null || true
sudo systemctl stop rustyjackd.service 2>/dev/null || true
sudo systemctl stop rustyjackd.socket 2>/dev/null || true

step "Removing old binaries (if present)..."
sudo rm -f /usr/local/bin/$BINARY_NAME /usr/local/bin/$CLI_NAME /usr/local/bin/$DAEMON_NAME /usr/local/bin/$PORTAL_NAME

step "Installing prebuilt binaries to /usr/local/bin/"
sudo install -Dm755 "$PREBUILT_BIN" /usr/local/bin/$BINARY_NAME || fail "Failed to install binary"
sudo install -Dm755 "$PREBUILT_CLI" /usr/local/bin/$CLI_NAME || fail "Failed to install CLI binary"
sudo install -Dm755 "$PREBUILT_DAEMON" /usr/local/bin/$DAEMON_NAME || fail "Failed to install daemon binary"
sudo install -Dm755 "$PREBUILT_PORTAL" /usr/local/bin/$PORTAL_NAME || fail "Failed to install portal binary"

# Create necessary directories
step "Creating runtime directories"
sudo mkdir -p "$RUNTIME_ROOT"
for dir in img scripts wordlists DNSSpoof; do
  if [ -d "$PROJECT_ROOT/$dir" ] && [ ! -d "$RUNTIME_ROOT/$dir" ]; then
    sudo cp -a "$PROJECT_ROOT/$dir" "$RUNTIME_ROOT/"
  fi
done
sudo mkdir -p "$RUNTIME_ROOT/loot"/{Wireless,Ethernet,reports,Hotspot,logs} 2>/dev/null || true
sudo mkdir -p "$RUNTIME_ROOT/wifi/profiles"
sudo chown root:root "$RUNTIME_ROOT/wifi/profiles" 2>/dev/null || true
sudo chmod 700 "$RUNTIME_ROOT/wifi/profiles" 2>/dev/null || true
sudo mkdir -p "$RUNTIME_ROOT/pipelines"

# Copy helper scripts
step "Installing helper scripts"
sudo mkdir -p "$RUNTIME_ROOT/scripts"
sudo cp -f scripts/wifi_driver_installer.sh "$RUNTIME_ROOT/scripts/" 2>/dev/null || true
sudo cp -f scripts/wifi_hotplug.sh "$RUNTIME_ROOT/scripts/" 2>/dev/null || true
sudo chmod +x "$RUNTIME_ROOT/scripts/"*.sh 2>/dev/null || true

if [ -f scripts/99-rustyjack-wifi.rules ]; then
  sudo cp -f scripts/99-rustyjack-wifi.rules /etc/udev/rules.d/
  sudo udevadm control --reload-rules
  sudo udevadm trigger
  info "Installed USB WiFi auto-detection udev rules"
fi

# Sample profile
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
  sudo chmod 600 "$RUNTIME_ROOT/wifi/profiles/sample.json" 2>/dev/null || true
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
  sudo chmod 600 "$RUNTIME_ROOT/wifi/profiles/rustyjack.json" 2>/dev/null || true
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
  sudo chmod 600 "$RUNTIME_ROOT/wifi/profiles/skyhn7xm.json" 2>/dev/null || true
  info "Created default WiFi profile: SKYHN7XM"
fi

# systemd service
step "Ensuring rustyjack system users/groups exist..."
if ! getent group rustyjack >/dev/null 2>&1; then
  sudo groupadd --system rustyjack || true
fi
if ! getent group rustyjack-ui >/dev/null 2>&1; then
  sudo groupadd --system rustyjack-ui || true
fi
if ! id -u rustyjack-ui >/dev/null 2>&1; then
  sudo useradd --system --home /var/lib/rustyjack --shell /usr/sbin/nologin -g rustyjack-ui rustyjack-ui || true
fi
for grp in rustyjack gpio spi; do
  if getent group "$grp" >/dev/null 2>&1; then
    sudo usermod -aG "$grp" rustyjack-ui || true
  fi
done

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
After=local-fs.target network.target
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

sudo tee "$SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack UI Service (prebuilt)
After=local-fs.target network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=$RUNTIME_ROOT
ExecStart=/usr/local/bin/$BINARY_NAME
Environment=RUSTYJACK_DISPLAY_ROTATION=landscape
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

sudo systemctl daemon-reload
sudo systemctl enable rustyjackd.socket
sudo systemctl start rustyjackd.socket 2>/dev/null || true
sudo systemctl enable rustyjack-ui.service
info "Rustyjack service enabled"

# Finalize network ownership after installs/builds are complete
step "Finalizing network ownership..."
preserve_default_route_interface
purge_network_manager
disable_conflicting_services

# Start the service now
sudo systemctl start rustyjack-ui.service && info "Rustyjack service started successfully" || warn "Failed to start service - check 'systemctl status rustyjack-ui'"

# Final adjustments
claim_resolv_conf
check_resolv_conf

step "Validating network status..."
if cmd rustyjack; then
  route_iface=$(default_route_interface)
  if [ -n "$route_iface" ]; then
    info "Ensuring active uplink via rustyjack wifi route ensure --interface $route_iface"
  else
    route_iface="eth0"
    warn "Unable to detect default interface; falling back to $route_iface for ensure-route"
  fi
  RUSTYJACK_ROOT="$RUNTIME_ROOT" rustyjack wifi route ensure --interface "$route_iface" >/dev/null 2>&1 || warn "ensure-route failed; continuing to validation"
else
  warn "rustyjack CLI not found; skipping ensure-route"
fi
validate_network_status || fail "Network validation failed"

# Health-check: binary
if [ -x /usr/local/bin/$BINARY_NAME ]; then
  info "[OK] Prebuilt Rust binary installed: $BINARY_NAME"
else
  fail "[X] Binary missing or not executable at /usr/local/bin/$BINARY_NAME"
fi
if [ -x /usr/local/bin/$CLI_NAME ]; then
  info "[OK] Prebuilt CLI binary installed: $CLI_NAME"
else
  fail "[X] CLI binary missing or not executable at /usr/local/bin/$CLI_NAME"
fi
if [ -x /usr/local/bin/$DAEMON_NAME ]; then
  info "[OK] Prebuilt daemon binary installed: $DAEMON_NAME"
else
  fail "[X] Daemon binary missing or not executable at /usr/local/bin/$DAEMON_NAME"
fi
if [ -x /usr/local/bin/$PORTAL_NAME ]; then
  info "[OK] Prebuilt portal binary installed: $PORTAL_NAME"
else
  warn "Portal binary $PORTAL_NAME not executable or missing (optional)."
fi

# Health-check: hardware
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

# Rustyjack replaces core networking binaries with Rust implementations
info "[OK] Rustyjack provides native Rust implementations for:"
info "     netlink interface control (native Rust)"
info "     rfkill (radio management via /dev/rfkill)"
info "     process management (pgrep/pkill via /proc)"
info "     hostapd (software AP via nl80211)"
info "     nf_tables (netfilter via nf_tables netlink)"
info "     DHCP + DNS services (native Rust)"
info "     ARP operations (raw sockets)"

if systemctl is-active --quiet rustyjack-ui.service; then
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
