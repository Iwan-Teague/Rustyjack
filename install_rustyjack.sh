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
WARN_COUNT=0

# ---- helpers ------------------------------------------------
step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { WARN_COUNT=$((WARN_COUNT + 1)); printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }
show_service_logs() {
  local service="$1"
  local lines="${2:-80}"
  local max_lines="${3:-80}"
  warn "Recent logs for $service (deduped, up to $max_lines lines):"
  journalctl -u "$service" -n "$lines" --no-pager 2>/dev/null | awk -v max="$max_lines" '
    $0==prev { next }
    { prev=$0; print; count++ }
    count>=max { exit }
  ' | while IFS= read -r line; do
    warn "  $line"
  done
}
show_apt_logs() {
  warn "Recent APT logs:"
  if [ -f /var/log/apt/term.log ]; then
    tail -n 120 /var/log/apt/term.log 2>/dev/null | awk '$0==prev{next}{prev=$0; print; count++} count>=80{exit}' | while IFS= read -r line; do
      warn "  $line"
    done
  else
    warn "  /var/log/apt/term.log not found"
  fi
  if [ -f /var/log/dpkg.log ]; then
    tail -n 120 /var/log/dpkg.log 2>/dev/null | awk '$0==prev{next}{prev=$0; print; count++} count>=80{exit}' | while IFS= read -r line; do
      warn "  $line"
    done
  else
    warn "  /var/log/dpkg.log not found"
  fi
}
has_crate_artifact() {
  local crate="$1"
  local mode="${2:-release}"
  local base="$PROJECT_ROOT/target/$mode"
  compgen -G "$base/deps/lib${crate}-*.rlib" >/dev/null || \
  compgen -G "$base/deps/lib${crate}-*.rmeta" >/dev/null || \
  compgen -G "$base/deps/lib${crate}-*.so" >/dev/null
}

wpa_supplicant_present() {
  if cmd wpa_supplicant; then
    return 0
  fi
  [ -x /sbin/wpa_supplicant ] || [ -x /usr/sbin/wpa_supplicant ] || [ -x /usr/local/sbin/wpa_supplicant ]
}

ensure_wpa_supplicant() {
  if wpa_supplicant_present; then
    info "[OK] wpa_supplicant present"
    return 0
  fi
  warn "wpa_supplicant not found; attempting to install..."
  if ! sudo apt-get install -y --no-install-recommends wpasupplicant; then
    show_apt_logs
    fail "Failed to install wpa_supplicant"
  fi
  if wpa_supplicant_present; then
    info "[OK] wpa_supplicant installed"
    return 0
  fi
  fail "wpa_supplicant still missing after install"
}

verify_usb_filesystem_support() {
  step "Verifying USB filesystem support..."
  local fs_list
  fs_list=$(awk '{print $NF}' /proc/filesystems 2>/dev/null || true)

  local missing=()
  if ! echo "$fs_list" | grep -qx "vfat"; then
    missing+=("vfat")
  fi
  if ! echo "$fs_list" | grep -qx "exfat"; then
    missing+=("exfat")
  fi
  if ! echo "$fs_list" | grep -qx "ext4"; then
    missing+=("ext4")
  fi

  if ((${#missing[@]})); then
    warn "Missing kernel filesystem support: ${missing[*]}"
    warn "Rustyjack USB mounts require vfat, exfat, and ext4 support (ext4 provides ext2/ext3 compatibility on Pi OS)."
    fail "Kernel filesystem support is incomplete. Install a Pi kernel with vfat/exfat/ext4 enabled and rerun."
  fi

  info "[OK] Kernel filesystem support present: vfat exfat ext4"
}

if [ "$(id -u)" -ne 0 ]; then
  fail "This installer must run as root."
fi
export DEBIAN_FRONTEND=noninteractive
if [ -r /etc/os-release ]; then
  . /etc/os-release
  info "OS: ${PRETTY_NAME:-unknown} (${VERSION_CODENAME:-unknown})"
fi
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

# ---- 0: convert CRLF if file came from Windows --------------
if grep -q $'\r' "$0"; then
  step "Converting CRLF to LF in $0"
if ! cmd dos2unix; then
  if ! sudo apt-get update -qq || ! sudo apt-get install -y dos2unix; then
    show_apt_logs
    fail "Failed to install dos2unix"
  fi
fi
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
  # WiFi interface tools
  # - wpasupplicant: provides wpa_supplicant daemon and wpa_cli for WPA auth fallback
  wpasupplicant
  # USB filesystem support for Rustyjack mount policy (vfat/exfat/ext)
  dosfstools e2fsprogs exfatprogs
  # misc
  git i2c-tools curl usbutils
)

# Optional firmware bundles (may require non-free-firmware repo on Debian)
FIRMWARE_PACKAGES=(
  firmware-linux-nonfree firmware-realtek firmware-atheros firmware-ralink firmware-misc-nonfree
)

step "Updating APT and installing dependencies..."
if ! sudo apt-get update -qq; then
  show_apt_logs
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
        if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
          show_apt_logs
          fail "APT install failed even without firmware. Check output above."
        fi
      else
        show_apt_logs
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
      if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
        show_apt_logs
        fail "APT install failed even without firmware. Check output above."
      fi
    else
      show_apt_logs
      fail "APT install failed. Check output above."
    fi
  fi
fi

# Ensure wpa_supplicant is present even if package installation was skipped
ensure_wpa_supplicant

# ---- 3: enable I2C / SPI & kernel modules -------------------
step "Enabling I2C and SPI..."
add_dtparam dtparam=i2c_arm=on
add_dtparam dtparam=i2c1=on
add_dtparam dtparam=spi=on
add_dtparam dtparam=wifi=on

MODULES=(i2c-bcm2835 i2c-dev spi_bcm2835 spidev vfat exfat ext4)
for m in "${MODULES[@]}"; do
  grep -qxF "$m" /etc/modules || echo "$m" | sudo tee -a /etc/modules >/dev/null
  sudo modprobe "$m" || true
done

verify_usb_filesystem_support

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
  if ! sudo apt-get install -y --no-install-recommends curl; then
    show_apt_logs
    fail "Failed to install curl; check network/apt sources."
  fi
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
RUNTIME_ROOT="${RUNTIME_ROOT:-/var/lib/rustyjack}"
info "Using runtime root: $RUNTIME_ROOT"

# Stop the service before rebuilding to release the binary
info "Stopping rustyjack services for rebuild..."
sudo systemctl stop rustyjack-ui.service 2>/dev/null || true
sudo systemctl stop rustyjack.service 2>/dev/null || true
sudo systemctl stop rustyjackd.service 2>/dev/null || true
sudo systemctl stop rustyjackd.socket 2>/dev/null || true

# Remove old binaries to ensure fresh install
info "Removing old binaries..."
sudo rm -f /usr/local/bin/rustyjack-ui /usr/local/bin/rustyjack /usr/local/bin/rustyjackd

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

# Build rustyjack-core CLI (used for status/validation)
info "Building rustyjack CLI (release with cli feature)..."
(cd "$PROJECT_ROOT" && cargo build --release --bin rustyjack --features rustyjack-core/cli) || fail "Failed to build rustyjack"

if [ ! -f "$PROJECT_ROOT/target/release/rustyjack" ]; then
  fail "rustyjack binary not found after build!"
fi

# Build rustyjackd daemon
info "Building rustyjackd daemon (release)..."
(cd "$PROJECT_ROOT" && cargo build --release -p rustyjack-daemon) || fail "Failed to build rustyjackd"

if [ ! -f "$PROJECT_ROOT/target/release/rustyjackd" ]; then
  fail "rustyjackd binary not found after build!"
fi

# Build rustyjack-portal binary
info "Building rustyjack-portal binary (release)..."
(cd "$PROJECT_ROOT" && cargo build --release -p rustyjack-portal) || fail "Failed to build rustyjack-portal"

if [ ! -f "$PROJECT_ROOT/target/release/rustyjack-portal" ]; then
  fail "rustyjack-portal binary not found after build!"
fi

# Install binaries
sudo install -Dm755 "$PROJECT_ROOT/target/release/rustyjack-ui" /usr/local/bin/rustyjack-ui
sudo install -Dm755 "$PROJECT_ROOT/target/release/rustyjack" /usr/local/bin/rustyjack
sudo install -Dm755 "$PROJECT_ROOT/target/release/rustyjackd" /usr/local/bin/rustyjackd
sudo install -Dm755 "$PROJECT_ROOT/target/release/rustyjack-portal" /usr/local/bin/rustyjack-portal

# Verify installation
if [ -x /usr/local/bin/rustyjack-ui ] && [ -x /usr/local/bin/rustyjack ] && [ -x /usr/local/bin/rustyjackd ] && [ -x /usr/local/bin/rustyjack-portal ]; then
  info "Installed binaries to /usr/local/bin/"
  # Show binary info to confirm it's new
  info "Binary info:"
  ls -la /usr/local/bin/rustyjack-ui
  ls -la /usr/local/bin/rustyjack
  ls -la /usr/local/bin/rustyjackd
  ls -la /usr/local/bin/rustyjack-portal
else
  fail "Failed to install binaries to /usr/local/bin/"
fi

# Configure regdom + forwarding sysctls (Rust-only, no external binaries)
step "Configuring regulatory domain and forwarding sysctls..."
if cmd rustyjack; then
  CONFIG_ARGS=()
  if [ -n "${RUSTYJACK_COUNTRY:-}" ]; then
    CONFIG_ARGS+=(--country "$RUSTYJACK_COUNTRY")
  fi
  if RUSTYJACK_ROOT="$RUNTIME_ROOT" rustyjack system configure-host "${CONFIG_ARGS[@]}"; then
    info "[OK] Host configuration complete"
  else
    warn "[WARN] Host configuration failed; review output above"
  fi
else
  warn "rustyjack CLI not found; skipping regdom/sysctl configuration"
fi

# ---- 4: WiFi attack setup -----------------------------------
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

# Create WiFi profiles directory
sudo mkdir -p "$RUNTIME_ROOT/wifi/profiles"
sudo chown root:root "$RUNTIME_ROOT/wifi/profiles"
sudo chmod 700 "$RUNTIME_ROOT/wifi/profiles"

# Create pipelines directory (used by scan pipeline)
sudo mkdir -p "$RUNTIME_ROOT/pipelines"

# Note: rfkill unblock and interface up operations now handled by rustyjack-netlink
info "Network interface management delegated to rustyjack-netlink crate"

# Install WiFi driver scripts
step "Installing WiFi driver auto-install scripts..."
sudo mkdir -p "$RUNTIME_ROOT/scripts"
sudo cp -f scripts/wifi_driver_installer.sh "$RUNTIME_ROOT/scripts/" 2>/dev/null || true
sudo cp -f scripts/wifi_hotplug.sh "$RUNTIME_ROOT/scripts/" 2>/dev/null || true
sudo chmod +x "$RUNTIME_ROOT/scripts/"*.sh 2>/dev/null || true

# Install udev rules for USB WiFi auto-detection
if [ -f scripts/99-rustyjack-wifi.rules ]; then
  sudo cp -f scripts/99-rustyjack-wifi.rules /etc/udev/rules.d/
  sudo udevadm control --reload-rules
  sudo udevadm trigger
  info "Installed USB WiFi auto-detection udev rules"
fi

# Create sample WiFi profile if it doesn't exist
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

# ---- 5: systemd service -------------------------------------
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
sudo chown -R rustyjack-ui:rustyjack "$RUNTIME_ROOT/logs" 2>/dev/null || true
sudo chmod 2770 "$RUNTIME_ROOT/logs" 2>/dev/null || true
sudo find "$RUNTIME_ROOT/logs" -type f -name "*.log*" -exec chmod g+rw {} + 2>/dev/null || true
sudo find "$RUNTIME_ROOT/wifi/profiles" -type f -exec chmod 660 {} \; 2>/dev/null || true
sudo chmod 770 "$RUNTIME_ROOT/wifi/profiles" 2>/dev/null || true

# Ensure runtime and state directories exist with correct permissions
step "Ensuring runtime and state directories exist..."
sudo mkdir -p /var/lib/rustyjack /run/rustyjack
sudo chown root:rustyjack /var/lib/rustyjack /run/rustyjack
sudo chmod 2770 /var/lib/rustyjack /run/rustyjack

DAEMON_SOCKET=/etc/systemd/system/rustyjackd.socket
DAEMON_SERVICE=/etc/systemd/system/rustyjackd.service
step "Installing rustyjackd socket/service..."

# Socket activation is not used on dedicated devices; ensure any existing socket unit is disabled/masked
sudo systemctl disable --now rustyjackd.socket 2>/dev/null || true
sudo systemctl mask rustyjackd.socket 2>/dev/null || true


sudo tee "$DAEMON_SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack Daemon (Hardened)
Documentation=https://github.com/yourusername/rustyjack
After=local-fs.target network.target
Wants=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/rustyjackd
Restart=on-failure
RestartSec=5

# Environment
Environment=RUSTYJACKD_SOCKET=/run/rustyjack/rustyjackd.sock
Environment=RUSTYJACK_ROOT=$RUNTIME_ROOT
Environment=RUSTYJACK_WIFI_BACKEND=dbus
Environment=RUSTYJACKD_OPS_PROFILE=appliance
Environment=RUSTYJACKD_OPS_WIFI=true
Environment=RUSTYJACKD_OPS_ETH=true
Environment=RUSTYJACKD_OPS_HOTSPOT=true
Environment=RUSTYJACKD_OPS_PORTAL=true
Environment=RUSTYJACKD_OPS_STORAGE=true
Environment=RUSTYJACKD_OPS_POWER=true
Environment=RUSTYJACKD_OPS_UPDATE=true
Environment=RUSTYJACKD_OPS_SYSTEM=true
Environment=RUSTYJACKD_OPS_DEV=false
Environment=RUSTYJACKD_OPS_OFFENSIVE=false
Environment=RUSTYJACKD_OPS_LOOT=false
Environment=RUSTYJACKD_OPS_PROCESS=false
UMask=0007
# Uncomment to enable dangerous operations (system updates)
#Environment=RUSTYJACKD_DANGEROUS_OPS=true

# Privilege and capability management
User=root
# Keep only required capabilities
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_OVERRIDE
# Ambient capabilities for rootless operation where possible
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# Filesystem access restrictions
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/rustyjack /run/rustyjack /tmp/rustyjack /etc/resolv.conf
ReadOnlyPaths=/etc/wpa_supplicant
PrivateTmp=true

# Kernel hardening
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible

# Process restrictions
NoNewPrivileges=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true

# Memory protection
MemoryDenyWriteExecute=true

# Network restrictions (allow all needed for WiFi)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET

# Syscall filtering
SystemCallFilter=@system-service @mount
SystemCallFilter=~@clock @debug @module @mount @obsolete @raw-io @reboot @swap
SystemCallArchitectures=native

# Resource limits
LimitNOFILE=1024
LimitNPROC=64
TasksMax=64
CPUQuota=80%
MemoryMax=256M

# Working directory
WorkingDirectory=$RUNTIME_ROOT

# Security
PrivateDevices=false

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rustyjackd

[Install]
WantedBy=multi-user.target
UNIT

WPA_SERVICE=/etc/systemd/system/rustyjack-wpa_supplicant@.service
WPA_CONF=/etc/rustyjack/wpa_supplicant.conf
step "Installing wpa_supplicant service $WPA_SERVICE..."

sudo tee "$WPA_SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack wpa_supplicant (D-Bus) for %i
After=network.target dbus.service
Wants=dbus.service
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
Type=simple
ExecStart=/sbin/wpa_supplicant -u -s -i %i -D nl80211 -c /etc/rustyjack/wpa_supplicant.conf
Restart=on-failure
RestartSec=3

RuntimeDirectory=wpa_supplicant
RuntimeDirectoryMode=0755

User=root
Group=root

CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run/wpa_supplicant

ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible

RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
MemoryDenyWriteExecute=true

RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET

SystemCallFilter=@system-service
SystemCallFilter=~@clock @debug @module @obsolete @raw-io @reboot @swap

PrivateDevices=false

[Install]
WantedBy=multi-user.target
UNIT

step "Installing wpa_supplicant config $WPA_CONF..."
sudo mkdir -p /etc/rustyjack
sudo tee "$WPA_CONF" >/dev/null <<CONF
ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev
update_config=0
ap_scan=1
country=US
CONF
sudo chmod 600 "$WPA_CONF"
sudo systemctl unmask rustyjack-wpa_supplicant@.service 2>/dev/null || true
step "Installing systemd service $SERVICE..."

sudo tee "$SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack UI Service (100% Rust)
After=local-fs.target network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=$RUNTIME_ROOT
ExecStart=/usr/local/bin/rustyjack-ui
Environment=RUSTYJACK_DISPLAY_ROTATION=landscape
Environment=RUSTYJACK_DISPLAY_BACKEND=st7735
# Optional display overrides:
# Environment=RUSTYJACK_DISPLAY_WIDTH=128
# Environment=RUSTYJACK_DISPLAY_HEIGHT=128
# Environment=RUSTYJACK_DISPLAY_OFFSET_X=0
# Environment=RUSTYJACK_DISPLAY_OFFSET_Y=0
Restart=on-failure
RestartSec=2
User=rustyjack-ui
Group=rustyjack-ui
SupplementaryGroups=rustyjack gpio spi
UMask=0007
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
UMask=0007
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

# Verify the generated daemon unit is valid
if command -v systemd-analyze >/dev/null 2>&1; then
  if systemd-analyze verify /etc/systemd/system/rustyjackd.service >/dev/null 2>&1; then
    info "systemd unit OK: rustyjackd.service"
  else
    warn "systemd-analyze verify reported issues for rustyjackd.service; check 'systemctl status' and 'journalctl -u rustyjackd'"
  fi
fi
# Disable socket activation and prefer always-on service on dedicated devices
sudo systemctl disable --now rustyjackd.socket 2>/dev/null || true
sudo systemctl mask rustyjackd.socket 2>/dev/null || true
if ! sudo systemctl enable --now rustyjackd.service 2>/dev/null; then
  warn "Failed to enable/start rustyjackd.service"
  show_service_logs rustyjackd.service
fi
if ! sudo systemctl enable --now rustyjack-wpa_supplicant@wlan0.service 2>/dev/null; then
  warn "Failed to enable/start rustyjack-wpa_supplicant@wlan0.service"
  show_service_logs rustyjack-wpa_supplicant@wlan0.service
fi
sudo systemctl enable rustyjack-ui.service
sudo systemctl enable rustyjack-portal.service
info "Rustyjack services enabled - will start on next boot"

# Finalize network ownership after installs/builds are complete
step "Finalizing network ownership..."
preserve_default_route_interface
purge_network_manager
disable_conflicting_services

# Start the services now
info "Waiting for daemon socket before starting UI..."
for _ in $(seq 1 10); do
  if systemctl is-active --quiet rustyjackd.service && [ -S /run/rustyjack/rustyjackd.sock ]; then
    break
  fi
  sleep 1
done

if sudo systemctl start rustyjack-ui.service; then
  info "Rustyjack UI service started successfully"
else
  warn "Failed to start UI service - check 'systemctl status rustyjack-ui'"
  show_service_logs rustyjack-ui.service
fi
if sudo systemctl start rustyjack-portal.service; then
  info "Rustyjack Portal service started successfully"
else
  warn "Failed to start Portal service - check 'systemctl status rustyjack-portal'"
  show_service_logs rustyjack-portal.service
fi

# Claim resolv.conf after installs/builds are complete
claim_resolv_conf
check_resolv_conf

step "Validating network status..."
validate_network_status || fail "Network validation failed"

# ---- 6: final health-check ----------------------------------
step "Running post install checks..."

# 6-a SPI device nodes
if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "[OK] SPI device found: $(ls /dev/spidev* | xargs)"
else
  warn "[X] SPI device NOT found - a reboot may be required"
fi

# 6-b WiFi client mode dependencies
if cmd wpa_cli; then
  info "[OK] WiFi control present (wpa_cli) for client authentication"
else
  warn "[X] wpa_cli not found - WiFi client mode needs wpa_supplicant"
fi

if [ -d "$RUNTIME_ROOT/logs" ]; then
  log_owner=$(stat -c "%U" "$RUNTIME_ROOT/logs" 2>/dev/null || echo "?")
  log_group=$(stat -c "%G" "$RUNTIME_ROOT/logs" 2>/dev/null || echo "?")
  if [ "$log_owner" = "rustyjack-ui" ] && [ "$log_group" = "rustyjack" ]; then
    info "[OK] Log directory ownership: $log_owner:$log_group"
  else
    warn "[X] Log directory ownership is $log_owner:$log_group (expected rustyjack-ui:rustyjack)"
  fi
  if sudo -u rustyjack-ui test -w "$RUNTIME_ROOT/logs" 2>/dev/null; then
    info "[OK] UI user can write to log directory"
  else
    warn "[X] UI user cannot write to log directory - check permissions on $RUNTIME_ROOT/logs"
  fi
else
  warn "[X] Log directory missing at $RUNTIME_ROOT/logs"
fi

# 6-b3 Rustyjack replaces core networking binaries with Rust implementations
info "[OK] Rustyjack provides native Rust implementations for:"
info "     - netlink interface control (native Rust)"
info "     - rfkill (radio management via /dev/rfkill)"
info "     - process management (pgrep/pkill via /proc)"
info "     - hostapd (software AP via nl80211)"
info "     - nf_tables (netfilter via nf_tables netlink)"
info "     - DHCP + DNS services (native Rust)"
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
else
  fail "[X] rustyjack-ui binary missing - check build output"
fi

if [ -x /usr/local/bin/rustyjack ]; then
  info "[OK] Rust binary installed: rustyjack"
else
  fail "[X] rustyjack CLI binary missing - check build output"
fi

if [ -x /usr/local/bin/rustyjackd ]; then
  info "[OK] Rust binary installed: rustyjackd"
else
  fail "[X] rustyjackd binary missing - check build output"
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
if systemctl is-active --quiet rustyjackd.service; then
  info "[OK] Daemon service is running"
else
  warn "[X] Daemon service is not running - check 'systemctl status rustyjackd.service'"
  show_service_logs rustyjackd.service 50
fi

if systemctl is-active --quiet rustyjack-wpa_supplicant@wlan0.service; then
  info "[OK] wpa_supplicant service is running"
else
  warn "[X] wpa_supplicant service is not running - check 'systemctl status rustyjack-wpa_supplicant@wlan0.service'"
  show_service_logs rustyjack-wpa_supplicant@wlan0.service 50
fi

if systemctl is-active --quiet rustyjack-ui.service; then
  info "[OK] Rustyjack service is running"
else
  warn "[X] Rustyjack service is not running - check 'systemctl status rustyjack-ui'"
  show_service_logs rustyjack-ui.service 50
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
if [ "$WARN_COUNT" -gt 0 ]; then
  warn "Warnings detected ($WARN_COUNT). Skipping reboot to allow debugging."
  info "You must reboot manually for some changes to take effect."
elif [ "${SKIP_REBOOT:-0}" != "1" ] && [ "${NO_REBOOT:-0}" != "1" ]; then
  info "System rebooting in 5 seconds to finish setup - press Ctrl+C to abort."
  sleep 5
  sudo reboot
else
  info "SKIP_REBOOT set - installer finished without reboot."
  info "You must reboot manually for some changes to take effect."
fi
info ""
info "For WiFi attacks: Plug in USB WiFi dongle and use menu"
info "Manage service: systemctl status/restart rustyjack-ui"
info "View logs: journalctl -u rustyjack-ui -f"
info ""
