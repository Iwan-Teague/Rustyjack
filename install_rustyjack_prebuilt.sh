#!/usr/bin/env bash
# Installer that uses prebuilt binaries instead of building on-device
# Usage: sudo ./install_rustyjack_prebuilt.sh
# Notes:
#   - Auto-selects prebuilt/arm64/<variant> on 64-bit OS when available, otherwise prebuilt/arm32/<variant>
#   - Variants: release or development
# Environment overrides:
#   PREBUILT_DIR=prebuilt/arm64/release   # relative to project root or absolute path
#   USB_MOUNT_POINT=/mnt/usb      # where to mount removable media
#   USB_DEVICE=/dev/sda1          # explicit USB block device to mount
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/rj_shellops.sh
source "$SCRIPT_DIR/scripts/rj_shellops.sh"
WARN_COUNT=0
SKIP_HASH_CHECKS=0
USB_COPY_TO_PREBUILT=0
SPI_REBOOT_REQUIRED=0

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

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-n}"
  local reply=""
  while true; do
    if [ "$default" = "y" ]; then
      if ! read -r -p "$prompt [Y/n]: " reply; then
        reply=""
      fi
      reply="${reply:-y}"
    else
      if ! read -r -p "$prompt [y/N]: " reply; then
        reply=""
      fi
      reply="${reply:-n}"
    fi
    case "$reply" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO) return 1 ;;
    esac
    echo "Please answer y or n."
  done
}

prompt_select_option() {
  local prompt="$1"
  shift
  local options=("$@")
  local reply=""
  while true; do
    echo "$prompt" >&2
    local i=1
    for opt in "${options[@]}"; do
      echo "  $i) $opt" >&2
      i=$((i + 1))
    done
    if ! read -r -p "Choose [1-${#options[@]}]: " reply; then
      reply=""
    fi
    if [[ "$reply" =~ ^[0-9]+$ ]] && [ "$reply" -ge 1 ] && [ "$reply" -le "${#options[@]}" ]; then
      echo "$((reply - 1))"
      return 0
    fi
    echo "Please enter a number between 1 and ${#options[@]}." >&2
  done
}

prompt_install_options() {
  if [ -t 0 ]; then
    step "Installer options"
    if prompt_yes_no "Skip SHA256 integrity checks (faster on slow storage)?" "n"; then
      SKIP_HASH_CHECKS=1
    else
      SKIP_HASH_CHECKS=0
    fi
    if prompt_yes_no "When prebuilts are found on USB, copy them into PREBUILT_DIR (slower but caches locally)?" "n"; then
      USB_COPY_TO_PREBUILT=1
    else
      USB_COPY_TO_PREBUILT=0
    fi
  else
    info "Non-interactive shell detected; using defaults (hash checks enabled, USB copy disabled)."
  fi
}

hash_file() {
  local path="$1"
  if [ "$SKIP_HASH_CHECKS" = "1" ]; then
    echo ""
    return 0
  fi
  if cmd sha256sum; then
    sha256sum "$path" | awk '{print $1}'
    return 0
  fi
  if cmd shasum; then
    shasum -a 256 "$path" | awk '{print $1}'
    return 0
  fi
  echo ""
  return 1
}

detect_arm64_capable() {
  local uname_arch=""
  local long_bits=""
  local dpkg_arch=""
  uname_arch=$(uname -m 2>/dev/null || true)
  long_bits=$(getconf LONG_BIT 2>/dev/null || true)
  if cmd dpkg; then
    dpkg_arch=$(dpkg --print-architecture 2>/dev/null || true)
  fi
  if [ "$uname_arch" != "aarch64" ] && [ "$long_bits" != "64" ] && [ "$dpkg_arch" != "arm64" ]; then
    return 1
  fi
  if [ -e /lib/ld-linux-aarch64.so.1 ] || [ -e /lib64/ld-linux-aarch64.so.1 ]; then
    return 0
  fi
  return 1
}

print_binary_info() {
  local label="$1"
  local path="$2"
  if [ -f "$path" ]; then
    local size=""
    local buildid=""
    local hash=""
    size=$(ls -lh "$path" | awk '{print $5}')
    buildid=$(file "$path" | grep -o "BuildID\\[sha1\\]=[a-f0-9]*" || echo "BuildID not found")
    hash=$(hash_file "$path" || true)
    if [ -n "$hash" ]; then
      info "  ${label}: $size - $buildid - sha256=$hash"
    else
      if [ "$SKIP_HASH_CHECKS" = "1" ]; then
        info "  ${label}: $size - $buildid - sha256=skipped"
      else
        info "  ${label}: $size - $buildid - sha256=unavailable"
      fi
    fi
  else
    warn "  ${label}: NOT FOUND at $path"
  fi
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
  echo -e "$content" | rj_sudo_tee "$resolv" >/dev/null
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
    if cmd ip; then
      local route_line=""
      route_line=$(ip route show default 2>/dev/null | head -n 1 || true)
      if [ -n "$route_line" ]; then
        local route_iface=""
        route_iface=$(echo "$route_line" | awk '{for (i=1; i<=NF; ++i) if ($i=="dev") print $(i+1)}' | head -n1)
        local route_gateway=""
        route_gateway=$(echo "$route_line" | awk '{for (i=1; i<=NF; ++i) if ($i=="via") print $(i+1)}' | head -n1)
        if [ -n "$route_iface" ] && [ -n "$route_gateway" ] && grep -q '^nameserver ' /etc/resolv.conf; then
          info "[OK] Default route $route_iface ($route_gateway) and resolv.conf ready"
          return 0
        fi
      fi
    fi

    output=$(RUSTYJACK_ROOT="$RUNTIME_ROOT" rustyjack status network --output json 2>/dev/null || true)
    if [ -n "$output" ]; then
      info "[OK] Network status returned"
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

purge_network_manager() {
  info "Removing NetworkManager..."
  sudo systemctl stop NetworkManager.service NetworkManager-wait-online.service 2>/dev/null || true
  sudo systemctl disable NetworkManager.service NetworkManager-wait-online.service 2>/dev/null || true
  sudo apt-get -y purge network-manager || true
  sudo apt-get -y autoremove --purge || true
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
  local arch="$1"
  local variant="${2:-}"
  local base=""
  local suffix=""
  if [ -n "$variant" ] && [ "$variant" != "legacy" ]; then
    suffix="$arch/$variant"
  else
    suffix="$arch"
  fi
  local bins=("$BINARY_NAME" "$CLI_NAME" "$DAEMON_NAME" "$PORTAL_NAME" "$HOTPLUG_NAME" "$SHELLOPS_NAME")

  for base in "${USB_MOUNT_POINT:-/mnt/usb}" /media /mnt /run/media; do
    [ -d "$base" ] || continue
    local candidate=""
    for candidate in \
      "$base"/Rustyjack/Prebuilt/"$suffix" \
      "$base"/Rustyjack/prebuilt/"$suffix" \
      "$base"/rustyjack/Prebuilt/"$suffix" \
      "$base"/rustyjack/prebuilt/"$suffix"; do
      local all_found=1
      for bin in "${bins[@]}"; do
        if [ ! -f "$candidate/$bin" ]; then
          all_found=0
          break
        fi
      done
      if [ "$all_found" -eq 1 ]; then
        echo "$candidate"
        return 0
      fi
    done

    local hit=""
    if [ -n "$variant" ] && [ "$variant" != "legacy" ]; then
      hit=$(find "$base" -maxdepth 7 -type f \( -path "*/prebuilt/$arch/$variant/$BINARY_NAME" -o -path "*/Prebuilt/$arch/$variant/$BINARY_NAME" \) 2>/dev/null | head -n 1 || true)
    else
      hit=$(find "$base" -maxdepth 7 -type f \( -path "*/prebuilt/$arch/$BINARY_NAME" -o -path "*/Prebuilt/$arch/$BINARY_NAME" \) 2>/dev/null | head -n 1 || true)
    fi
    if [ -n "$hit" ]; then
      local dir="${hit%/$BINARY_NAME}"
      local all_found=1
      for bin in "${bins[@]}"; do
        if [ ! -f "$dir/$bin" ]; then
          all_found=0
          break
        fi
      done
      if [ "$all_found" -eq 1 ]; then
        echo "$dir"
        return 0
      fi
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
  local arch="$1"
  local variant="${2:-}"
  local src_override="${3:-}"
  local dest_dir=""
  local src_dir=""
  if [ -n "${PREBUILT_DIR:-}" ]; then
    dest_dir="$(resolve_prebuilt_root "$PREBUILT_DIR")"
  else
    if [ -n "$variant" ] && [ "$variant" != "legacy" ]; then
      dest_dir="$PROJECT_ROOT/prebuilt/$arch/$variant"
    else
      dest_dir="$PROJECT_ROOT/prebuilt/$arch"
    fi
  fi

  if [ -n "$variant" ] && [ "$variant" != "legacy" ]; then
    info "Searching for prebuilt binaries on mounted devices (arch=$arch, variant=$variant)..."
  else
    info "Searching for prebuilt binaries on mounted devices (arch=$arch)..."
  fi

  if [ -n "$src_override" ]; then
    src_dir="$src_override"
  else
    # First check if binaries already exist on mounted filesystems
    src_dir="$(find_prebuilt_dir_on_mounts "$arch" "$variant" || true)"
  fi

  if [ -z "$src_dir" ]; then
    info "No binaries found on current mounts, attempting to mount USB..."
    if mount_usb_if_needed; then
      info "USB mount successful, searching again..."
      src_dir="$(find_prebuilt_dir_on_mounts "$arch" "$variant" || true)"
    else
      warn "USB mounting failed or no USB device detected"
    fi
  fi

  if [ -z "$src_dir" ]; then
    warn "=========================================="
    warn "BINARIES NOT FOUND ON USB"
    warn "=========================================="
    warn "Searched locations:"
    warn "  - /mnt/usb/Rustyjack/Prebuilt/$arch/release"
    warn "  - /mnt/usb/Rustyjack/prebuilt/$arch/release"
    warn "  - /mnt/usb/rustyjack/Prebuilt/$arch/release"
    warn "  - /mnt/usb/rustyjack/prebuilt/$arch/release"
    warn "  - /mnt/usb/Rustyjack/Prebuilt/$arch/development"
    warn "  - /mnt/usb/Rustyjack/prebuilt/$arch/development"
    warn "  - /mnt/usb/rustyjack/Prebuilt/$arch/development"
    warn "  - /mnt/usb/rustyjack/prebuilt/$arch/development"
    warn "  - /mnt/usb/Rustyjack/Prebuilt/$arch (legacy)"
    warn "  - /mnt/usb/Rustyjack/prebuilt/$arch (legacy)"
    warn "  - /mnt/usb/rustyjack/Prebuilt/$arch (legacy)"
    warn "  - /mnt/usb/rustyjack/prebuilt/$arch (legacy)"
    warn "  - Deep search in /mnt/usb, /media, /mnt, /run/media"
    warn ""
    warn "Will attempt to use binaries from: $dest_dir"
    warn "If that directory is empty or has old binaries, installation will fail."
    warn "=========================================="
    return 1
  fi

  info "=========================================="
  info "BINARIES FOUND ON USB"
  info "=========================================="
  info "Source directory: $src_dir"
  info ""
  info "Verifying binaries before copy..."

  local bins=("$BINARY_NAME" "$CLI_NAME" "$DAEMON_NAME" "$PORTAL_NAME" "$HOTPLUG_NAME" "$SHELLOPS_NAME")
  local all_found=1
  declare -A src_hashes

  for bin in "${bins[@]}"; do
    if [ -f "$src_dir/$bin" ]; then
      print_binary_info "OK $bin" "$src_dir/$bin"
      if [ "$SKIP_HASH_CHECKS" != "1" ]; then
        src_hashes["$bin"]="$(hash_file "$src_dir/$bin" || true)"
      fi
    else
      warn "  $bin - MISSING"
      all_found=0
    fi
  done

  if [ "$all_found" -eq 0 ]; then
    fail "Not all binaries found in $src_dir"
  fi

  if [ "$USB_COPY_TO_PREBUILT" != "1" ]; then
    local src_real
    src_real=$(readlink -f "$src_dir" 2>/dev/null || echo "$src_dir")
    PREBUILT_DIR="$src_real"
    info ""
    info "Using USB prebuilts directly (skipping copy to $dest_dir)"
    info "PREBUILT_DIR set to: $PREBUILT_DIR"
    return 0
  fi

  info ""
  info "Creating destination directory: $dest_dir"
  sudo mkdir -p "$dest_dir"

  info "Copying binaries from USB to $dest_dir"
  info ""

  local copied=0
  local total="${#bins[@]}"
  local current=0

  for bin in "${bins[@]}"; do
    current=$((current + 1))
    if [ -f "$src_dir/$bin" ]; then
      local fsize
      fsize=$(stat -c%s "$src_dir/$bin" 2>/dev/null || stat -f%z "$src_dir/$bin" 2>/dev/null || echo "0")
      local fsize_mb=$(awk "BEGIN {printf \"%.2f\", $fsize/1024/1024}")
      
      printf "  [$current/$total] $bin ($fsize_mb MB)\n"
      
      if command -v pv >/dev/null 2>&1 && [ "$fsize" -gt 1048576 ]; then
        # Use pv for live progress (stderr goes to terminal, stdout to file)
        pv -p -s "$fsize" "$src_dir/$bin" | sudo tee "$dest_dir/$bin" > /dev/null
        sudo chmod 755 "$dest_dir/$bin"
      else
        # Fallback: manual live progress using dd with status updates
        if [ "$fsize" -gt 1048576 ]; then
          # For files > 1MB, show live progress with dd
          printf "    Progress: "
          (
            sudo dd if="$src_dir/$bin" of="$dest_dir/$bin" bs=1M status=progress 2>&1 | \
            while IFS= read -r line; do
              # Extract bytes copied from dd output
              if echo "$line" | grep -q "bytes"; then
                bytes=$(echo "$line" | awk '{print $1}')
                if [ -n "$bytes" ] && [ "$bytes" != "0" ]; then
                  pct=$(awk "BEGIN {printf \"%.0f\", ($bytes/$fsize)*100}")
                  bars=$(awk "BEGIN {printf \"%.0f\", ($pct/2)}")
                  spaces=$((50 - bars))
                  printf "\r    [%s%s] %d%% " "$(printf '#%.0s' $(seq 1 $bars))" "$(printf ' %.0s' $(seq 1 $spaces))" "$pct"
                fi
              fi
            done
          )
          printf "\n"
          sudo chmod 755 "$dest_dir/$bin"
        else
          # Small files: just copy directly
          sudo install -Dm755 "$src_dir/$bin" "$dest_dir/$bin"
          printf "    [##################################################] 100%\n"
        fi
      fi
      copied=1
    fi
  done
  printf "\n"

  if [ -f "$src_dir/build_info.txt" ]; then
    sudo install -Dm644 "$src_dir/build_info.txt" "$dest_dir/build_info.txt" || true
  fi

  if [ "$copied" -eq 1 ]; then
    info ""
    info "=========================================="
    info "BINARIES COPIED SUCCESSFULLY"
    info "=========================================="
    info "Destination: $dest_dir"
    info ""
    if [ "$SKIP_HASH_CHECKS" != "1" ]; then
      info "Verifying copied binaries..."
      for bin in "${bins[@]}"; do
        if [ -f "$dest_dir/$bin" ]; then
          print_binary_info "OK $bin" "$dest_dir/$bin"
          local src_hash="${src_hashes[$bin]:-}"
          local dest_hash=""
          dest_hash=$(hash_file "$dest_dir/$bin" || true)
          if [ -n "$src_hash" ] && [ -n "$dest_hash" ] && [ "$src_hash" != "$dest_hash" ]; then
            warn "  $bin hash mismatch after copy (src=$src_hash dest=$dest_hash)"
            fail "Binary copy failed integrity check"
          fi
        else
          warn "  $bin - COPY FAILED"
        fi
      done
    else
      info "Skipping copied-binary hash verification (SKIP_HASH_CHECKS=1)"
    fi
    info "=========================================="
    return 0
  fi

  return 1
}

# Prompt for install speed options before making changes.
prompt_install_options

# ---- 1: locate active config.txt ----------------------------
CFG=/boot/firmware/config.txt; [[ -f $CFG ]] || CFG=/boot/config.txt
if [ ! -f "$CFG" ]; then
  sudo mkdir -p "$(dirname "$CFG")"
  echo "# Rustyjack config (created by installer)" | rj_sudo_tee "$CFG" >/dev/null
fi
info "Using config file: $CFG"
add_dtparam() {
  local param="$1"
  if grep -qE "^#?\s*${param%=*}=on" "$CFG"; then
    sudo sed -Ei "s|^#?\s*${param%=*}=.*|${param%=*}=on|" "$CFG"
  else
    echo "$param" | rj_sudo_tee -a "$CFG" >/dev/null
  fi
}

# ---- 2: install / upgrade required APT packages -------------
PACKAGES=(
  # WiFi interface tools
  # - wpasupplicant: provides wpa_supplicant daemon and wpa_cli for WPA auth fallback
  wpasupplicant
  # networking tools
  isc-dhcp-client hostapd dnsmasq rfkill
  # USB filesystem support for Rustyjack mount policy (vfat/exfat/ext)
  dosfstools e2fsprogs exfatprogs
  # misc
  git i2c-tools curl
)

# Optional firmware bundles (may require non-free-firmware repo on Debian)
FIRMWARE_PACKAGES=(
  firmware-linux-nonfree firmware-realtek firmware-atheros firmware-ralink firmware-misc-nonfree
)

step "Updating APT and installing dependencies..."
if ! sudo apt-get update; then
  show_apt_logs
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
        if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
          show_apt_logs
          fail "APT install failed. Check output above."
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
  warn "APT dry-run failed; attempting full install..."
  if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
    if ((${#available_firmware[@]})); then
      warn "APT install failed; retrying without firmware bundles"
      INSTALL_PACKAGES=("${PACKAGES[@]}")
      if ! sudo apt-get install -y --no-install-recommends "${INSTALL_PACKAGES[@]}"; then
        show_apt_logs
        fail "APT install failed."
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
  grep -qxF "$m" /etc/modules || echo "$m" | rj_sudo_tee -a /etc/modules >/dev/null
  sudo modprobe "$m" || true
done

verify_usb_filesystem_support

# ensure overlay spi0-2cs
grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | rj_sudo_tee -a "$CFG" >/dev/null

# Ensure buttons use internal pull-ups
if ! grep -q "^gpio=6,19,5,26,13,21,20,16=pu" "$CFG" ; then
  echo 'gpio=6,19,5,26,13,21,20,16=pu' | rj_sudo_tee -a "$CFG" >/dev/null
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

PREBUILT_DIR_OVERRIDE=0
if [ -n "${PREBUILT_DIR:-}" ]; then
  PREBUILT_DIR_OVERRIDE=1
fi

PREFERRED_ARCH="arm32"
if detect_arm64_capable; then
  PREFERRED_ARCH="arm64"
  info "[OK] Detected 64-bit userspace; arm64 binaries are supported"
else
  info "[OK] Detected 32-bit userspace; arm64 binaries are NOT supported"
fi

BINARY_NAME="rustyjack-ui"
CLI_NAME="rustyjack"
DAEMON_NAME="rustyjackd"
PORTAL_NAME="rustyjack-portal"
HOTPLUG_NAME="rustyjack-hotplugd"
SHELLOPS_NAME="rustyjack-shellops"
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
  PREBUILT_HOTPLUG="$PREBUILT_ROOT/$HOTPLUG_NAME"
  PREBUILT_SHELLOPS="$PREBUILT_ROOT/$SHELLOPS_NAME"
}

prebuilt_has_all_bins() {
  local root="$1"
  local bins=("$BINARY_NAME" "$CLI_NAME" "$DAEMON_NAME" "$PORTAL_NAME" "$HOTPLUG_NAME" "$SHELLOPS_NAME")
  for bin in "${bins[@]}"; do
    if [ ! -f "$root/$bin" ]; then
      return 1
    fi
  done
  return 0
}

read_build_info_file() {
  local dir="$1"
  local file="$dir/build_info.txt"
  BUILD_INFO_EPOCH=""
  BUILD_INFO_ISO=""
  BUILD_INFO_GIT_HASH=""
  BUILD_INFO_GIT_DIRTY=""
  BUILD_INFO_PROFILE=""
  BUILD_INFO_VARIANT=""
  BUILD_INFO_TARGET=""
  BUILD_INFO_ARCH=""
  if [ ! -f "$file" ]; then
    return 1
  fi
  BUILD_INFO_EPOCH="$(grep -E '^build_epoch=' "$file" | head -n 1 | cut -d= -f2-)"
  BUILD_INFO_ISO="$(grep -E '^build_iso=' "$file" | head -n 1 | cut -d= -f2-)"
  BUILD_INFO_GIT_HASH="$(grep -E '^git_hash=' "$file" | head -n 1 | cut -d= -f2-)"
  BUILD_INFO_GIT_DIRTY="$(grep -E '^git_dirty=' "$file" | head -n 1 | cut -d= -f2-)"
  BUILD_INFO_PROFILE="$(grep -E '^build_profile=' "$file" | head -n 1 | cut -d= -f2-)"
  BUILD_INFO_VARIANT="$(grep -E '^build_variant=' "$file" | head -n 1 | cut -d= -f2-)"
  BUILD_INFO_TARGET="$(grep -E '^target=' "$file" | head -n 1 | cut -d= -f2-)"
  BUILD_INFO_ARCH="$(grep -E '^arch=' "$file" | head -n 1 | cut -d= -f2-)"
  return 0
}

stat_epoch() {
  local path="$1"
  if stat -c %Y "$path" >/dev/null 2>&1; then
    stat -c %Y "$path"
    return 0
  fi
  if stat -f %m "$path" >/dev/null 2>&1; then
    stat -f %m "$path"
    return 0
  fi
  echo "0"
  return 1
}

format_epoch_iso() {
  local epoch="$1"
  if [ -z "$epoch" ] || [ "$epoch" -le 0 ] 2>/dev/null; then
    echo "unknown"
    return 0
  fi
  if date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
    date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%SZ"
    return 0
  fi
  if date -u -r "$epoch" +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
    date -u -r "$epoch" +"%Y-%m-%dT%H:%M:%SZ"
    return 0
  fi
  echo "unknown"
}

CAND_COUNT=0
CAND_ARCH=()
CAND_VARIANT=()
CAND_SOURCE=()
CAND_DIR=()
CAND_EPOCH=()
CAND_ISO=()
CAND_GIT=()
CAND_DIRTY=()
CAND_EPOCH_SRC=()
CAND_COMPAT=()

add_candidate() {
  local arch="$1"
  local variant="$2"
  local source="$3"
  local dir="$4"
  local key="$arch/$variant/$source/$dir"
  for existing in "${CAND_DIR[@]}"; do
    if [ "$existing" = "$dir" ]; then
      return 0
    fi
  done

  if ! prebuilt_has_all_bins "$dir"; then
    return 1
  fi

  local epoch=""
  local iso=""
  local git_hash="unknown"
  local git_dirty=""
  local epoch_src="unknown"

  if read_build_info_file "$dir"; then
    epoch="$BUILD_INFO_EPOCH"
    iso="$BUILD_INFO_ISO"
    if [ -z "$iso" ] && [ -n "$epoch" ]; then
      iso="$(format_epoch_iso "$epoch")"
    fi
    git_hash="${BUILD_INFO_GIT_HASH:-unknown}"
    git_dirty="${BUILD_INFO_GIT_DIRTY:-0}"
    epoch_src="build_info"
  else
    epoch="$(stat_epoch "$dir/$BINARY_NAME")"
    iso="$(format_epoch_iso "$epoch")"
    epoch_src="mtime"
  fi

  local compat="1"
  if [ "$arch" = "arm64" ] && ! detect_arm64_capable; then
    compat="0"
  fi

  CAND_ARCH+=("$arch")
  CAND_VARIANT+=("$variant")
  CAND_SOURCE+=("$source")
  CAND_DIR+=("$dir")
  CAND_EPOCH+=("$epoch")
  CAND_ISO+=("$iso")
  CAND_GIT+=("$git_hash")
  CAND_DIRTY+=("$git_dirty")
  CAND_EPOCH_SRC+=("$epoch_src")
  CAND_COMPAT+=("$compat")
  CAND_COUNT=$((CAND_COUNT + 1))
  return 0
}

collect_candidates() {
  local arch=""
  local variant=""

  for arch in arm64 arm32; do
    for variant in release development; do
      local rel="prebuilt/$arch/$variant"
      local abs
      abs="$(resolve_prebuilt_root "$rel")"
      if prebuilt_has_all_bins "$abs"; then
        add_candidate "$arch" "$variant" "local" "$abs"
      fi
    done
    local legacy_rel="prebuilt/$arch"
    local legacy_abs
    legacy_abs="$(resolve_prebuilt_root "$legacy_rel")"
    if prebuilt_has_all_bins "$legacy_abs"; then
      add_candidate "$arch" "legacy" "local" "$legacy_abs"
    fi
  done

  # Search USB if available.
  mount_usb_if_needed || true
  for arch in arm64 arm32; do
    for variant in release development legacy; do
      local usb_dir=""
      usb_dir="$(find_prebuilt_dir_on_mounts "$arch" "$variant" || true)"
      if [ -n "$usb_dir" ]; then
        add_candidate "$arch" "$variant" "usb" "$usb_dir"
      fi
    done
  done
}

print_candidates() {
  local max_epoch_all=0
  local max_epoch_compat=0
  local i=0
  local latest_idx=-1

  for i in "${!CAND_EPOCH[@]}"; do
    local epoch="${CAND_EPOCH[$i]}"
    local compat="${CAND_COMPAT[$i]}"
    if [ -n "$epoch" ] && [ "$epoch" -gt "$max_epoch_all" ] 2>/dev/null; then
      max_epoch_all="$epoch"
    fi
    if [ "$compat" = "1" ] && [ -n "$epoch" ] && [ "$epoch" -gt "$max_epoch_compat" ] 2>/dev/null; then
      max_epoch_compat="$epoch"
    fi
  done

  info "Available prebuilt binaries:"
  for i in "${!CAND_ARCH[@]}"; do
    local arch="${CAND_ARCH[$i]}"
    local variant="${CAND_VARIANT[$i]}"
    local source="${CAND_SOURCE[$i]}"
    local epoch="${CAND_EPOCH[$i]}"
    local iso="${CAND_ISO[$i]}"
    local git_hash="${CAND_GIT[$i]}"
    local git_dirty="${CAND_DIRTY[$i]}"
    local epoch_src="${CAND_EPOCH_SRC[$i]}"
    local compat="${CAND_COMPAT[$i]}"
    local tag="unknown"
    if [ -n "$epoch" ] && [ "$epoch" -gt 0 ] 2>/dev/null; then
      if [ "$epoch" -eq "$max_epoch_all" ] 2>/dev/null; then
        tag="latest"
      elif [ "$compat" = "1" ] && [ "$epoch" -eq "$max_epoch_compat" ] 2>/dev/null; then
        tag="latest compatible"
      else
        tag="outdated"
      fi
    fi

    local dirty_note=""
    if [ "$git_dirty" = "1" ]; then
      dirty_note=" dirty"
    fi

    local compat_note="compatible"
    if [ "$arch" = "arm64" ] && ! detect_arm64_capable; then
      compat_note="incompatible (requires 64-bit OS)"
    elif [ "$arch" = "arm32" ] && detect_arm64_capable; then
      compat_note="compatible (arm32 on 64-bit OS)"
    fi

    local build_note="build ${iso}"
    if [ "$epoch_src" = "mtime" ]; then
      build_note="build ${iso} (mtime)"
    fi

    printf "  %s) %s/%s (%s) - %s - git %s%s - %s - %s\n" \
      "$((i + 1))" "$arch" "$variant" "$source" "$build_note" "$git_hash" "$dirty_note" "$tag" "$compat_note"
  done

  if [ "$max_epoch_all" -gt 0 ] 2>/dev/null; then
    for i in "${!CAND_EPOCH[@]}"; do
      if [ "${CAND_EPOCH[$i]}" = "$max_epoch_all" ]; then
        latest_idx="$i"
        break
      fi
    done
  fi

  if [ "$latest_idx" -ge 0 ]; then
    info "Most recent build: ${CAND_ARCH[$latest_idx]}/${CAND_VARIANT[$latest_idx]} (${CAND_SOURCE[$latest_idx]}) - ${CAND_ISO[$latest_idx]}"
  fi
}

select_candidate() {
  local selected=""
  if [ ! -t 0 ]; then
    local best_idx=-1
    local best_epoch=0
    local i=0
    for i in "${!CAND_EPOCH[@]}"; do
      local compat="${CAND_COMPAT[$i]}"
      local epoch="${CAND_EPOCH[$i]}"
      if [ "$compat" != "1" ]; then
        continue
      fi
      if [ -n "$epoch" ] && [ "$epoch" -gt "$best_epoch" ] 2>/dev/null; then
        best_epoch="$epoch"
        best_idx="$i"
      elif [ "$best_idx" -eq -1 ]; then
        best_idx="$i"
      fi
    done
    if [ "$best_idx" -lt 0 ]; then
      return 1
    fi
    selected="$best_idx"
    info "Non-interactive shell detected; selecting $((selected + 1))"
  else
    while true; do
      if ! read -r -p "Select prebuilt set to install [1-${CAND_COUNT}]: " selected; then
        selected=""
      fi
      if [[ "$selected" =~ ^[0-9]+$ ]] && [ "$selected" -ge 1 ] && [ "$selected" -le "$CAND_COUNT" ]; then
        selected=$((selected - 1))
        if [ "${CAND_COMPAT[$selected]}" != "1" ]; then
          warn "Selection is incompatible with this OS. Choose a compatible build."
          continue
        fi
        break
      fi
      echo "Please enter a number between 1 and ${CAND_COUNT}."
    done
  fi
  SELECTED_INDEX="$selected"
  return 0
}

PREBUILT_ARCH="$PREFERRED_ARCH"
PREBUILT_VARIANT=""
PREBUILT_SOURCE=""

if [ "$PREBUILT_DIR_OVERRIDE" -eq 1 ]; then
  info "PREBUILT_DIR override set: $PREBUILT_DIR"
  case "$PREBUILT_DIR" in
    *arm64*) PREBUILT_ARCH="arm64" ;;
    *arm32*) PREBUILT_ARCH="arm32" ;;
  esac
else
  collect_candidates
  if [ "$CAND_COUNT" -eq 0 ]; then
    fail "No prebuilt binaries found in local directories or USB media"
  fi
  print_candidates
  if ! select_candidate; then
    fail "No compatible prebuilt binaries available"
  fi

  PREBUILT_ARCH="${CAND_ARCH[$SELECTED_INDEX]}"
  PREBUILT_VARIANT="${CAND_VARIANT[$SELECTED_INDEX]}"
  PREBUILT_SOURCE="${CAND_SOURCE[$SELECTED_INDEX]}"
  PREBUILT_DIR="${CAND_DIR[$SELECTED_INDEX]}"

  if [ "$PREBUILT_SOURCE" = "usb" ]; then
    if [ "$USB_COPY_TO_PREBUILT" = "1" ]; then
      if [ "$PREBUILT_VARIANT" = "legacy" ] || [ -z "$PREBUILT_VARIANT" ]; then
        PREBUILT_DIR="prebuilt/$PREBUILT_ARCH"
      else
        PREBUILT_DIR="prebuilt/$PREBUILT_ARCH/$PREBUILT_VARIANT"
      fi
    fi
    copy_prebuilt_from_usb "$PREBUILT_ARCH" "$PREBUILT_VARIANT" "${CAND_DIR[$SELECTED_INDEX]}" || true
  fi
fi

if [ "$PREBUILT_ARCH" = "arm64" ] && ! detect_arm64_capable; then
  fail "arm64 binaries selected but this OS does not appear to support 64-bit execution"
fi

set_prebuilt_paths

if [ -n "$PREBUILT_VARIANT" ] && [ "$PREBUILT_VARIANT" != "legacy" ]; then
  info "Selected prebuilt directory: $PREBUILT_DIR (arch=$PREBUILT_ARCH, variant=$PREBUILT_VARIANT)"
else
  info "Selected prebuilt directory: $PREBUILT_DIR (arch=$PREBUILT_ARCH)"
fi

info "Using prebuilt binaries from $PREBUILT_ROOT"

if [ ! -f "$PREBUILT_BIN" ]; then
  fail "Prebuilt binary not found: $PREBUILT_BIN\nPlace your ${PREBUILT_ARCH} binary at $PREBUILT_BIN or set PREBUILT_DIR to its location."
fi
if [ ! -f "$PREBUILT_CLI" ]; then
  fail "Prebuilt CLI not found: $PREBUILT_CLI\nPlace your ${PREBUILT_ARCH} CLI binary at $PREBUILT_CLI (rustyjack-core) or set PREBUILT_DIR accordingly."
fi
if [ ! -f "$PREBUILT_DAEMON" ]; then
  fail "Prebuilt daemon not found: $PREBUILT_DAEMON\nPlace your ${PREBUILT_ARCH} daemon binary at $PREBUILT_DAEMON or set PREBUILT_DIR accordingly."
fi
if [ ! -f "$PREBUILT_PORTAL" ]; then
  fail "Prebuilt portal not found: $PREBUILT_PORTAL\nPlace your ${PREBUILT_ARCH} portal binary at $PREBUILT_PORTAL or set PREBUILT_DIR accordingly."
fi
if [ ! -f "$PREBUILT_HOTPLUG" ]; then
  fail "Prebuilt hotplug helper not found: $PREBUILT_HOTPLUG\nPlace your ${PREBUILT_ARCH} hotplug binary at $PREBUILT_HOTPLUG or set PREBUILT_DIR accordingly."
fi
if [ ! -f "$PREBUILT_SHELLOPS" ]; then
  fail "Prebuilt shell ops helper not found: $PREBUILT_SHELLOPS\nPlace your ${PREBUILT_ARCH} shell ops binary at $PREBUILT_SHELLOPS or set PREBUILT_DIR accordingly."
fi

# Ensure the prebuilt binaries are executable and appear to match the target arch
if [ ! -x "$PREBUILT_BIN" ]; then
  info "Making prebuilt binary executable: $PREBUILT_BIN"
  chmod +x "$PREBUILT_BIN" || warn "Failed to chmod +x $PREBUILT_BIN"
fi
if [ ! -x "$PREBUILT_CLI" ]; then
  info "Making prebuilt CLI executable: $PREBUILT_CLI"
  chmod +x "$PREBUILT_CLI" || warn "Failed to chmod +x $PREBUILT_CLI"
fi
if [ ! -x "$PREBUILT_DAEMON" ]; then
  info "Making prebuilt daemon executable: $PREBUILT_DAEMON"
  chmod +x "$PREBUILT_DAEMON" || warn "Failed to chmod +x $PREBUILT_DAEMON"
fi
if [ ! -x "$PREBUILT_PORTAL" ]; then
  info "Making prebuilt portal executable: $PREBUILT_PORTAL"
  chmod +x "$PREBUILT_PORTAL" || warn "Failed to chmod +x $PREBUILT_PORTAL"
fi
if [ ! -x "$PREBUILT_HOTPLUG" ]; then
  info "Making prebuilt hotplug helper executable: $PREBUILT_HOTPLUG"
  chmod +x "$PREBUILT_HOTPLUG" || warn "Failed to chmod +x $PREBUILT_HOTPLUG"
fi
if [ ! -x "$PREBUILT_SHELLOPS" ]; then
  info "Making prebuilt shell ops helper executable: $PREBUILT_SHELLOPS"
  chmod +x "$PREBUILT_SHELLOPS" || warn "Failed to chmod +x $PREBUILT_SHELLOPS"
fi
check_binary_arch() {
  local path="$1"
  local arch="$2"
  if ! command -v file >/dev/null 2>&1; then
    return 0
  fi
  local arch_info=""
  arch_info=$(file -b "$path" || true)
  if [ "$arch" = "arm64" ]; then
    if echo "$arch_info" | grep -qiE 'ELF 64-bit.*ARM aarch64|ARM aarch64'; then
      info "[OK] $(basename "$path") looks like 64-bit ARM: $arch_info"
    else
      warn "$(basename "$path") does not look like 64-bit ARM: $arch_info"
      warn "Proceeding anyway; ensure the binary matches your Pi's userspace (arm64)."
    fi
  else
    if echo "$arch_info" | grep -qiE 'ELF 32-bit.*ARM|ARM, EABI|ARM aarch32'; then
      info "[OK] $(basename "$path") looks like 32-bit ARM: $arch_info"
    else
      warn "$(basename "$path") does not look like 32-bit ARM: $arch_info"
      warn "Proceeding anyway; ensure the binary matches your Pi's userspace (armhf/armv7)."
    fi
  fi
}
check_binary_arch "$PREBUILT_BIN" "$PREBUILT_ARCH"
check_binary_arch "$PREBUILT_CLI" "$PREBUILT_ARCH"
check_binary_arch "$PREBUILT_DAEMON" "$PREBUILT_ARCH"
check_binary_arch "$PREBUILT_PORTAL" "$PREBUILT_ARCH"
check_binary_arch "$PREBUILT_HOTPLUG" "$PREBUILT_ARCH"
check_binary_arch "$PREBUILT_SHELLOPS" "$PREBUILT_ARCH"

step "Stopping existing service (if any)..."
sudo systemctl stop rustyjack-ui.service 2>/dev/null || true
sudo systemctl stop rustyjack.service 2>/dev/null || true
sudo systemctl stop rustyjackd.service 2>/dev/null || true
sudo systemctl stop rustyjackd.socket 2>/dev/null || true

step "Removing old binaries (if present)..."
sudo rm -f /usr/local/bin/$BINARY_NAME /usr/local/bin/$CLI_NAME /usr/local/bin/$DAEMON_NAME /usr/local/bin/$PORTAL_NAME /usr/local/bin/$HOTPLUG_NAME /usr/local/bin/$SHELLOPS_NAME

step "Installing prebuilt binaries to /usr/local/bin/"
info "Source binaries:"
for bin_var in PREBUILT_BIN PREBUILT_CLI PREBUILT_DAEMON PREBUILT_PORTAL PREBUILT_HOTPLUG PREBUILT_SHELLOPS; do
  bin_path="${!bin_var}"
  print_binary_info "$(basename "$bin_path")" "$bin_path"
done
info ""

INSTALL_PAIRS=(
  "$PREBUILT_BIN:/usr/local/bin/$BINARY_NAME"
  "$PREBUILT_CLI:/usr/local/bin/$CLI_NAME"
  "$PREBUILT_DAEMON:/usr/local/bin/$DAEMON_NAME"
  "$PREBUILT_PORTAL:/usr/local/bin/$PORTAL_NAME"
  "$PREBUILT_HOTPLUG:/usr/local/bin/$HOTPLUG_NAME"
  "$PREBUILT_SHELLOPS:/usr/local/bin/$SHELLOPS_NAME"
)

INSTALL_CURRENT=0
INSTALL_TOTAL="${#INSTALL_PAIRS[@]}"

for pair in "${INSTALL_PAIRS[@]}"; do
  INSTALL_CURRENT=$((INSTALL_CURRENT + 1))
  inst_src="${pair%%:*}"
  inst_dest="${pair##*:}"
  inst_fname=$(basename "$inst_src")
  inst_fsize=$(stat -c%s "$inst_src" 2>/dev/null || stat -f%z "$inst_src" 2>/dev/null || echo "0")
  inst_fsize_mb=$(awk "BEGIN {printf \"%.2f\", $inst_fsize/1024/1024}")

  printf "  [$INSTALL_CURRENT/$INSTALL_TOTAL] $inst_fname ($inst_fsize_mb MB)\n"

  if command -v pv >/dev/null 2>&1 && [ "$inst_fsize" -gt 1048576 ]; then
    # Use pv for live progress (pipe through tee to avoid sh -c wrapper)
    pv -p -s "$inst_fsize" "$inst_src" | sudo tee "$inst_dest" > /dev/null || fail "Failed to install $inst_fname"
    sudo chmod 755 "$inst_dest"
  else
    # Fallback: manual live progress using dd with status updates
    if [ "$inst_fsize" -gt 1048576 ]; then
      printf "    Progress: "
      (
        sudo dd if="$inst_src" of="$inst_dest" bs=1M status=progress 2>&1 | \
        while IFS= read -r line; do
          # Extract bytes copied from dd output
          if echo "$line" | grep -q "bytes"; then
            bytes=$(echo "$line" | awk '{print $1}')
            if [ -n "$bytes" ] && [ "$bytes" != "0" ]; then
              pct=$(awk "BEGIN {printf \"%.0f\", ($bytes/$inst_fsize)*100}")
              bars=$(awk "BEGIN {printf \"%.0f\", ($pct/2)}")
              spaces=$((50 - bars))
              printf "\r    [%s%s] %d%% " "$(printf '#%.0s' $(seq 1 $bars))" "$(printf ' %.0s' $(seq 1 $spaces))" "$pct"
            fi
          fi
        done
      ) || fail "Failed to install $inst_fname"
      printf "\n"
      sudo chmod 755 "$inst_dest"
    else
      # Small files: just copy directly
      sudo install -Dm755 "$inst_src" "$inst_dest" || fail "Failed to install $inst_fname"
      printf "    [##################################################] 100%%\n"
    fi
  fi
done
info ""

info "Installed binaries to /usr/local/bin:"
for bin_name in $BINARY_NAME $CLI_NAME $DAEMON_NAME $PORTAL_NAME $HOTPLUG_NAME $SHELLOPS_NAME; do
  if [ -f "/usr/local/bin/$bin_name" ]; then
    print_binary_info "OK $bin_name" "/usr/local/bin/$bin_name"
  else
    warn "  $bin_name: INSTALLATION FAILED"
  fi
done
info ""

if [ "$SKIP_HASH_CHECKS" != "1" ]; then
  info "Verifying installed binary hashes..."
  for bin_name in $BINARY_NAME $CLI_NAME $DAEMON_NAME $PORTAL_NAME $HOTPLUG_NAME $SHELLOPS_NAME; do
    src_path="$PREBUILT_ROOT/$bin_name"
    dest_path="/usr/local/bin/$bin_name"
    if [ -f "$src_path" ] && [ -f "$dest_path" ]; then
      src_hash=$(hash_file "$src_path" || true)
      dest_hash=$(hash_file "$dest_path" || true)
      if [ -n "$src_hash" ] && [ -n "$dest_hash" ]; then
        if [ "$src_hash" = "$dest_hash" ]; then
          info "  $bin_name hash match ($src_hash)"
        else
          warn "  $bin_name hash mismatch (src=$src_hash dest=$dest_hash)"
          fail "Binary integrity check failed for $bin_name"
        fi
      else
        warn "  [WARN] $bin_name hash unavailable (missing sha256sum/shasum)"
      fi
    else
      warn "  $bin_name hash check skipped (missing source or destination)"
    fi
  done
  info ""
else
  info "Skipping installed binary hash verification (SKIP_HASH_CHECKS=1)"
  info ""
fi

# Verify binaries can execute (check for missing libraries)
info "Verifying binary compatibility..."
if ldd /usr/local/bin/$DAEMON_NAME 2>&1 | grep -q "not found"; then
  warn "Daemon binary has missing library dependencies:"
  ldd /usr/local/bin/$DAEMON_NAME 2>&1 | grep "not found" | while IFS= read -r line; do
    warn "  $line"
  done
  fail "Cannot proceed with missing libraries"
else
  info "[OK] All daemon binary dependencies satisfied"
fi

# Configure regdom + forwarding sysctls (Rust-only, no external binaries)
step "Configuring regulatory domain and forwarding sysctls..."
if cmd "$CLI_NAME"; then
  CONFIG_ARGS=()
  if [ -n "${RUSTYJACK_COUNTRY:-}" ]; then
    CONFIG_ARGS+=(--country "$RUSTYJACK_COUNTRY")
  fi
  if RUSTYJACK_ROOT="$RUNTIME_ROOT" "$CLI_NAME" system configure-host "${CONFIG_ARGS[@]}"; then
    info "[OK] Host configuration complete"
  else
    warn "[WARN] Host configuration failed; review output above"
  fi
else
  warn "rustyjack CLI not found; skipping regdom/sysctl configuration"
fi

# Create necessary directories
step "Creating runtime directories"
sudo mkdir -p "$RUNTIME_ROOT"
for dir in img scripts wordlists DNSSpoof; do
  if [ -d "$PROJECT_ROOT/$dir" ] && [ ! -d "$RUNTIME_ROOT/$dir" ]; then
    sudo cp -a "$PROJECT_ROOT/$dir" "$RUNTIME_ROOT/"
  fi
done
sudo mkdir -p "$RUNTIME_ROOT/loot"/{Wireless,Ethernet,reports,Hotspot,logs,Portal} 2>/dev/null || true
sudo mkdir -p "$RUNTIME_ROOT/logs" 2>/dev/null || true
sudo mkdir -p "$RUNTIME_ROOT/portal/site" 2>/dev/null || true
if [ ! -f "$RUNTIME_ROOT/portal/site/index.html" ]; then
  if [ -f "$PROJECT_ROOT/DNSSpoof/sites/portal/index.html" ]; then
    sudo cp -a "$PROJECT_ROOT/DNSSpoof/sites/portal/." "$RUNTIME_ROOT/portal/site/" || fail "Failed to install default portal site assets"
    info "Installed default portal site assets to $RUNTIME_ROOT/portal/site"
  else
    warn "[X] Default portal site missing at $PROJECT_ROOT/DNSSpoof/sites/portal"
  fi
fi
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
  rj_sudo_tee "$RUNTIME_ROOT/wifi/profiles/sample.json" >/dev/null <<'PROFILE'
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
  rj_sudo_tee "$RUNTIME_ROOT/wifi/profiles/rustyjack.json" >/dev/null <<'PROFILE'
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
  rj_sudo_tee "$RUNTIME_ROOT/wifi/profiles/skyhn7xm.json" >/dev/null <<'PROFILE'
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
for grp in rustyjack; do
  if getent group "$grp" >/dev/null 2>&1; then
    sudo usermod -aG "$grp" rustyjack-portal || true
  fi
done

sudo chown -R root:rustyjack "$RUNTIME_ROOT"
sudo chmod -R g+rwX "$RUNTIME_ROOT"
sudo chown -R rustyjack-ui:rustyjack "$RUNTIME_ROOT/logs" 2>/dev/null || true
sudo chmod 2770 "$RUNTIME_ROOT/logs" 2>/dev/null || true
sudo find "$RUNTIME_ROOT/logs" -type f -name "*.log*" -exec chmod g+rw {} + 2>/dev/null || true
sudo find "$RUNTIME_ROOT/wifi/profiles" -type f -exec chmod 660 {} \; 2>/dev/null || true
sudo chmod 770 "$RUNTIME_ROOT/wifi/profiles" 2>/dev/null || true
sudo chown -R rustyjack-portal:rustyjack-portal "$RUNTIME_ROOT/portal" "$RUNTIME_ROOT/loot/Portal" 2>/dev/null || true
sudo chmod 770 "$RUNTIME_ROOT/portal" "$RUNTIME_ROOT/loot/Portal" 2>/dev/null || true

DAEMON_SOCKET=/etc/systemd/system/rustyjackd.socket
DAEMON_SERVICE=/etc/systemd/system/rustyjackd.service
step "Installing rustyjackd socket/service..."

# Ensure old units are stopped before re-installing.
sudo systemctl stop rustyjackd.socket rustyjackd.service 2>/dev/null || true
sudo systemctl disable --now rustyjackd.socket rustyjackd.service 2>/dev/null || true
sudo systemctl unmask rustyjackd.socket 2>/dev/null || true
sudo rm -f "$DAEMON_SOCKET" 2>/dev/null || true
sudo rm -f /run/rustyjack/rustyjackd.sock 2>/dev/null || true
sudo systemctl daemon-reload 2>/dev/null || true
sudo systemctl reset-failed rustyjackd.socket rustyjackd.service 2>/dev/null || true

rj_sudo_tee "$DAEMON_SOCKET" >/dev/null <<UNIT
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

rj_sudo_tee "$DAEMON_SERVICE" >/dev/null <<UNIT
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
UMask=0007
Environment=RUST_BACKTRACE=1
Environment=RUSTYJACK_ROOT=${RUNTIME_ROOT}
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
Environment=RUSTYJACKD_OPS_OFFENSIVE=true
Environment=RUSTYJACKD_OPS_LOOT=false
Environment=RUSTYJACKD_OPS_PROCESS=false
Environment=RUSTYJACKD_SOCKET=/run/rustyjack/rustyjackd.sock
Environment=RUSTYJACKD_SOCKET_GROUP=rustyjack
WatchdogSec=20s
NotifyAccess=main
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${RUNTIME_ROOT} /etc/resolv.conf
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

WPA_SERVICE=/etc/systemd/system/rustyjack-wpa_supplicant@.service
WPA_CONF=/etc/rustyjack/wpa_supplicant.conf
step "Installing wpa_supplicant service $WPA_SERVICE..."

rj_sudo_tee "$WPA_SERVICE" >/dev/null <<UNIT
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
rj_sudo_tee "$WPA_CONF" >/dev/null <<CONF
ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev
update_config=0
ap_scan=1
country=US
CONF
sudo chmod 600 "$WPA_CONF"
sudo systemctl unmask rustyjack-wpa_supplicant@.service 2>/dev/null || true

SERVICE=/etc/systemd/system/rustyjack-ui.service
SERVICE_FILE=$SERVICE
step "Installing systemd service $SERVICE..."

rj_sudo_tee "$SERVICE" >/dev/null <<UNIT
[Unit]
Description=Rustyjack UI Service (prebuilt)
After=local-fs.target network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=$RUNTIME_ROOT
ExecStart=/usr/local/bin/$BINARY_NAME
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
PORTAL_SERVICE_FILE=$PORTAL_SERVICE
step "Installing portal service $PORTAL_SERVICE..."

rj_sudo_tee "$PORTAL_SERVICE" >/dev/null <<UNIT
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
Environment=RUSTYJACK_PORTAL_SITE_DIR=$RUNTIME_ROOT/portal/site
Environment=RUSTYJACK_PORTAL_CAPTURE_DIR=$RUNTIME_ROOT/loot/Portal
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

# Verify service file has correct environment variables
info "Verifying service file environment:"
if grep -q "Environment=RUSTYJACK_ROOT=$RUNTIME_ROOT" "$DAEMON_SERVICE"; then
  info "  RUSTYJACK_ROOT is set to: $RUNTIME_ROOT"
else
  warn "  RUSTYJACK_ROOT may not be set correctly in service file"
  grep "RUSTYJACK_ROOT" "$DAEMON_SERVICE" | while IFS= read -r line; do
    warn "  Found: $line"
  done
fi

# Enable socket activation for the daemon.
sudo systemctl daemon-reload 2>/dev/null || true
sudo systemctl reset-failed rustyjackd.socket rustyjackd.service 2>/dev/null || true
sudo systemctl enable rustyjackd.socket
if sudo systemctl start rustyjackd.socket 2>/dev/null; then
  info "Daemon socket started successfully"
else
  warn "Failed to start rustyjackd.socket"
  show_service_logs rustyjackd.socket
  warn "Socket status:"
  systemctl status rustyjackd.socket 2>&1 | head -n 10 | while IFS= read -r line; do
    warn "  $line"
  done
fi

sudo systemctl enable rustyjackd.service
if sudo systemctl start rustyjackd.service 2>/dev/null; then
  info "Daemon service started successfully"
else
  warn "Failed to start rustyjackd.service"
  warn "Service status:"
  systemctl status rustyjackd.service 2>&1 | head -n 10 | while IFS= read -r line; do
    warn "  $line"
  done
  if cmd journalctl; then
    warn "Recent daemon logs:"
    journalctl -u rustyjackd.service -n 30 --no-pager 2>/dev/null | while IFS= read -r line; do
      warn "  $line"
    done
  fi

  warn "Attempting manual daemon test with environment:"
  warn "  RUSTYJACK_ROOT=$RUNTIME_ROOT"
  warn "  (testing for 2 seconds...)"
  timeout 5 sudo RUST_BACKTRACE=1 RUSTYJACK_ROOT="$RUNTIME_ROOT" /usr/local/bin/rustyjackd 2>&1 | head -n 40 | while IFS= read -r line; do
    warn "  $line"
  done || warn "  (manual test timed out or exited)"

  # Fallback: if the prebuilt daemon still panics (common for mismatched prebuilt), try rebuilding from source
  if command -v cargo >/dev/null 2>&1; then
    warn "Prebuilt daemon failed; attempting to rebuild rustyjackd from source as a fallback (this may take a while)..."
    if (cd "$PROJECT_ROOT" && cargo build --release -p rustyjack-daemon); then
      warn "Build succeeded - installing rebuilt daemon binary"
      sudo install -Dm755 "$PROJECT_ROOT/target/release/rustyjackd" /usr/local/bin/rustyjackd || warn "Failed to install rebuilt binary"
      sudo systemctl daemon-reload || true
      if sudo systemctl restart rustyjackd.service 2>/dev/null; then
        info "Rebuilt rustyjackd and restarted service successfully"
      else
        warn "Rebuilt daemon installed but failed to start via systemd; start manually to inspect errors"
      fi
    else
      warn "Rebuild failed - check cargo output above for details"
    fi
  else
    warn "cargo not available; cannot rebuild daemon on-device"
  fi
fi
sudo systemctl enable rustyjack-wpa_supplicant@wlan0.service
if sudo systemctl start rustyjack-wpa_supplicant@wlan0.service 2>/dev/null; then
  info "wpa_supplicant service started successfully"
else
  warn "Failed to start rustyjack-wpa_supplicant@wlan0.service"
  show_service_logs rustyjack-wpa_supplicant@wlan0.service
fi
sudo systemctl enable rustyjack-ui.service
sudo systemctl enable rustyjack-portal.service
info "Rustyjack services enabled"

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
if [ -x /usr/local/bin/$HOTPLUG_NAME ]; then
  info "[OK] Prebuilt hotplug helper binary installed: $HOTPLUG_NAME"
else
  fail "[X] Hotplug helper binary missing or not executable at /usr/local/bin/$HOTPLUG_NAME"
fi
if [ -x /usr/local/bin/$SHELLOPS_NAME ]; then
  info "[OK] Prebuilt shell ops helper binary installed: $SHELLOPS_NAME"
else
  fail "[X] Shell ops helper binary missing or not executable at /usr/local/bin/$SHELLOPS_NAME"
fi

# Health-check: service files
if [ -f "$DAEMON_SOCKET" ]; then
  info "[OK] Socket unit file installed: $DAEMON_SOCKET"
else
  warn "[NOTE] Socket unit file not present; socket activation disabled for always-on service"
fi
if [ -f "$DAEMON_SERVICE" ]; then
  info "[OK] Daemon service file installed: $DAEMON_SERVICE"
else
  fail "[X] Daemon service file missing at $DAEMON_SERVICE"
fi
if [ -f "$SERVICE_FILE" ]; then
  info "[OK] UI service file installed: $SERVICE_FILE"
else
  fail "[X] UI service file missing at $SERVICE_FILE"
fi
if [ -f "$PORTAL_SERVICE_FILE" ]; then
  info "[OK] Portal service file installed: $PORTAL_SERVICE_FILE"
else
  fail "[X] Portal service file missing at $PORTAL_SERVICE_FILE"
fi

# Health-check: groups and directories
if getent group rustyjack >/dev/null 2>&1; then
  info "[OK] System group 'rustyjack' exists"
else
  fail "[X] System group 'rustyjack' does not exist"
fi
if [ -d "$RUNTIME_ROOT" ]; then
  info "[OK] Runtime directory exists: $RUNTIME_ROOT"
else
  fail "[X] Runtime directory missing: $RUNTIME_ROOT"
fi
if [ -d "/run/rustyjack" ]; then
  info "[OK] Socket directory exists: /run/rustyjack"
else
  warn "[NOTE] Socket directory /run/rustyjack will be created by systemd on first start"
fi

# Health-check: hardware
step "Running post install checks..."

if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "[OK] SPI device found"
else
  warn "[X] SPI device NOT found - reboot may be required"
  SPI_REBOOT_REQUIRED=1
fi

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

if [ -f "$RUNTIME_ROOT/portal/site/index.html" ]; then
  info "[OK] Portal site index present: $RUNTIME_ROOT/portal/site/index.html"
else
  warn "[X] Portal site index missing at $RUNTIME_ROOT/portal/site/index.html"
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

# Health-check: service status
if systemctl is-active --quiet rustyjackd.socket; then
  info "[OK] Daemon socket is active"
  if [ -S /run/rustyjack/rustyjackd.sock ]; then
    info "[OK] Socket file exists: /run/rustyjack/rustyjackd.sock"
  else
    warn "[X] Socket file missing at /run/rustyjack/rustyjackd.sock"
  fi
else
  warn "[X] Daemon socket is not active - run: systemctl status rustyjackd.socket"
  show_service_logs rustyjackd.socket 50
fi

if systemctl is-active --quiet rustyjackd.service; then
  info "[OK] Daemon service is running"
else
  warn "[X] Daemon service is not running - run: systemctl status rustyjackd.service"
  warn "    Check logs with: journalctl -u rustyjackd.service -n 50"
  show_service_logs rustyjackd.service 50
fi

if systemctl is-active --quiet rustyjack-ui.service; then
  info "[OK] UI service is running"
else
  warn "[X] UI service is not running - run: systemctl status rustyjack-ui.service"
  show_service_logs rustyjack-ui.service 50
fi

if systemctl is-active --quiet rustyjack-portal.service; then
  info "[OK] Portal service is running"
else
  warn "[NOTE] Portal service is not running (may be optional depending on configuration)"
  show_service_logs rustyjack-portal.service 50
fi

info "Prebuilt installation finished."
if [ "${SKIP_REBOOT:-0}" != "1" ] && [ "${NO_REBOOT:-0}" != "1" ]; then
  if [ "$WARN_COUNT" -gt 0 ]; then
    info "Warnings detected ($WARN_COUNT). Rebooting to apply overlay and service changes."
  fi
  info "Rebooting in 5 seconds..."
  sleep 5
  sudo reboot
else
  info "SKIP_REBOOT set - installer finished without reboot."
  if [ "$SPI_REBOOT_REQUIRED" -eq 1 ]; then
    warn "Manual reboot required for SPI device availability."
  fi
fi
