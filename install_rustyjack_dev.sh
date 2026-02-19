#!/usr/bin/env bash
# Rustyjack source installer (debug build)
#
# This script compiles debug binaries on-device, then delegates all post-build
# installation logic to install_rustyjack_prebuilt.sh so install flow stays
# identical across installers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/rj_shellops.sh
source "$SCRIPT_DIR/scripts/rj_shellops.sh"

WARN_COUNT=0

step()  { printf "\e[1;34m[STEP]\e[0m %s\n" "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n" "$*"; }
warn()  { WARN_COUNT=$((WARN_COUNT + 1)); printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n" "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }

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

setup_install_logging() {
  if [ "${RJ_INSTALL_LOG_DISABLE:-0}" = "1" ]; then
    return 0
  fi

  local script_name log_root log_dir ts log_path latest_any latest_script
  script_name="$(basename "$0" .sh)"
  log_root="${RUNTIME_ROOT:-/var/lib/rustyjack}"
  log_dir="${RJ_INSTALL_LOG_DIR:-${log_root%/}/logs/install}"
  ts="$(date +%Y%m%d-%H%M%S)"
  log_path="${log_dir}/${script_name}_${ts}.log"
  latest_any="${log_dir}/install_latest.log"
  latest_script="${log_dir}/${script_name}_latest.log"

  mkdir -p "$log_dir" || fail "Unable to create installer log directory: $log_dir"
  chmod 750 "$log_dir" 2>/dev/null || true
  touch "$log_path" || fail "Unable to create installer log file: $log_path"
  chmod 640 "$log_path" 2>/dev/null || true

  exec > >(tee -a "$log_path") 2>&1
  export RUSTYJACK_INSTALL_LOG_PATH="$log_path"

  ln -sfn "$log_path" "$latest_any" 2>/dev/null || true
  ln -sfn "$log_path" "$latest_script" 2>/dev/null || true
  info "Installer log: $log_path"
}

ensure_rw_root() {
  local root_status
  root_status=$(findmnt -n -o OPTIONS / || true)
  if echo "$root_status" | grep -q '\\bro\\b'; then
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
  echo -e "$content" | rj_sudo_tee "$resolv" >/dev/null
  sudo chmod 644 "$resolv"
  sudo chown root:root "$resolv"
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

install_build_dependencies() {
  local packages=(
    build-essential pkg-config libssl-dev
    wpasupplicant
    dosfstools e2fsprogs exfatprogs
    git i2c-tools curl
  )
  local firmware_packages=(
    firmware-linux-nonfree firmware-realtek firmware-atheros firmware-ralink firmware-misc-nonfree
  )

  step "Updating APT and installing debug build dependencies..."
  if ! sudo apt-get update; then
    show_apt_logs
    fail "APT update failed. Ensure no other package manager is running and rerun."
  fi

  local install_packages=("${packages[@]}")
  local available_firmware=()
  local missing_firmware=()
  local pkg=""
  for pkg in "${firmware_packages[@]}"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then
      available_firmware+=("$pkg")
    else
      missing_firmware+=("$pkg")
    fi
  done

  if ((${#available_firmware[@]})); then
    install_packages+=("${available_firmware[@]}")
  fi
  if ((${#missing_firmware[@]})); then
    warn "Skipping unavailable firmware packages: ${missing_firmware[*]}"
    warn "Enable 'non-free-firmware' in /etc/apt/sources.list on Debian 12+ if needed."
  fi

  local header_candidates=(
    "linux-headers-$(uname -r)" "linux-headers-generic" "linux-headers-amd64" "linux-headers-arm64" "raspberrypi-kernel-headers"
  )
  local chosen_header=""
  local hdr=""
  for hdr in "${header_candidates[@]}"; do
    if apt-cache show "$hdr" >/dev/null 2>&1; then
      chosen_header="$hdr"
      install_packages+=("$hdr")
      break
    fi
  done
  if [ -z "$chosen_header" ]; then
    warn "No kernel headers package found (needed only for DKMS WiFi drivers). Skipping."
  fi

  if ! sudo apt-get install -y --no-install-recommends "${install_packages[@]}"; then
    if ((${#available_firmware[@]})); then
      warn "APT install failed; retrying without firmware bundles"
      if ! sudo apt-get install -y --no-install-recommends "${packages[@]}"; then
        show_apt_logs
        fail "APT install failed even without firmware packages"
      fi
    else
      show_apt_logs
      fail "APT install failed"
    fi
  fi

  ensure_wpa_supplicant
}

ensure_swap_space() {
  local min_mb="${1:-1024}"
  local target_mb="${2:-1536}"
  local current_swap

  step "Checking swap space for Rust compilation..."
  current_swap=$(free -m | awk '/^Swap:/ {print $2}')

  if [ "${current_swap:-0}" -ge "$min_mb" ]; then
    info "[OK] Sufficient swap available: ${current_swap}MB"
    return 0
  fi

  warn "Current swap: ${current_swap}MB (insufficient for compilation)"
  info "Setting up ${target_mb}MB swap file..."

  if [ -e /dev/zram0 ]; then
    sudo swapoff /dev/zram0 2>/dev/null || true
  fi

  local swap_file="/var/swap"
  if [ -f "$swap_file" ]; then
    sudo swapoff "$swap_file" 2>/dev/null || true
  fi

  sudo fallocate -l "${target_mb}M" "$swap_file" 2>/dev/null || sudo dd if=/dev/zero of="$swap_file" bs=1M count="$target_mb" status=progress
  sudo chmod 600 "$swap_file"
  sudo mkswap "$swap_file" >/dev/null
  sudo swapon "$swap_file"

  if ! grep -q "$swap_file" /etc/fstab 2>/dev/null; then
    echo "$swap_file none swap sw 0 0" | rj_sudo_tee -a /etc/fstab >/dev/null
  fi

  local new_swap
  new_swap=$(free -m | awk '/^Swap:/ {print $2}')
  info "[OK] Swap increased to ${new_swap}MB"
}

ensure_rust_toolchain() {
  step "Ensuring Rust toolchain is installed..."
  if ! cmd curl; then
    warn "curl missing after package install; installing curl..."
    if ! sudo apt-get install -y --no-install-recommends curl; then
      show_apt_logs
      fail "Failed to install curl"
    fi
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    info "cargo missing - installing rustup toolchain"
    curl --proto '=https' --tlsv1.2 --fail --location https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  else
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env" 2>/dev/null || true
  fi
}

build_debug_binaries() {
  step "Building debug binaries from source..."

  PROJECT_ROOT="${PROJECT_ROOT:-/root/Rustyjack}"
  if [ ! -d "$PROJECT_ROOT" ]; then
    PROJECT_ROOT="$SCRIPT_DIR"
  fi
  RUNTIME_ROOT="${RUNTIME_ROOT:-/var/lib/rustyjack}"
  info "Using project root: $PROJECT_ROOT"
  info "Using runtime root: $RUNTIME_ROOT"

  sudo systemctl stop rustyjack-ui.service 2>/dev/null || true
  sudo systemctl stop rustyjack.service 2>/dev/null || true
  sudo systemctl stop rustyjackd.service 2>/dev/null || true
  sudo systemctl stop rustyjackd.socket 2>/dev/null || true

  echo ""
  info "=========================================="
  info "  BUILD OPTIONS"
  info "=========================================="
  echo ""
  echo "  [1] Incremental build (fast - recompiles only changed files)"
  echo "  [2] Clean build (slow - removes cached artifacts first)"
  echo ""
  if [ -t 0 ]; then
    read -r -p "Select build type [1/2] (default: 1): " BUILD_CHOICE
    BUILD_CHOICE="${BUILD_CHOICE:-1}"
  else
    BUILD_CHOICE="1"
    info "Non-interactive shell detected; using incremental build"
  fi

  if [ "$BUILD_CHOICE" = "2" ]; then
    warn "Performing clean build (cargo clean)..."
    (cd "$PROJECT_ROOT" && cargo clean) || warn "cargo clean failed"
  else
    info "Performing incremental build"
  fi

  info "Building rustyjack-ui (debug, journald enabled)..."
  (cd "$PROJECT_ROOT" && cargo build -p rustyjack-ui --features journald) || fail "Failed to build rustyjack-ui"

  info "Building rustyjack CLI (debug with cli feature)..."
  (cd "$PROJECT_ROOT" && cargo build --bin rustyjack --features rustyjack-core/cli) || fail "Failed to build rustyjack"

  info "Building rustyjack daemon helpers (debug)..."
  (cd "$PROJECT_ROOT" && cargo build -p rustyjack-daemon --bin rustyjackd --bin rustyjack-hotplugd --bin rustyjack-shellops) || fail "Failed to build rustyjack daemon components"

  info "Building rustyjack-portal (debug)..."
  (cd "$PROJECT_ROOT" && cargo build -p rustyjack-portal) || fail "Failed to build rustyjack-portal"

  local built_dir="$PROJECT_ROOT/target/debug"
  local required=(rustyjack-ui rustyjack rustyjackd rustyjack-portal rustyjack-hotplugd rustyjack-shellops)
  local bin=""
  for bin in "${required[@]}"; do
    if [ ! -f "$built_dir/$bin" ]; then
      fail "Missing built binary: $built_dir/$bin"
    fi
  done

  PREBUILT_DIR="$built_dir"
  export PROJECT_ROOT RUNTIME_ROOT PREBUILT_DIR
  info "Debug binaries ready at: $PREBUILT_DIR"
}

handoff_to_prebuilt() {
  step "Handing off to install_rustyjack_prebuilt.sh for unified installation flow..."

  if [ "${SKIP_REBOOT:-0}" = "1" ]; then
    export NO_REBOOT=1
  fi

  export RJ_INSTALL_LOG_DISABLE=1
  if ! PREBUILT_DIR="$PREBUILT_DIR" PROJECT_ROOT="$PROJECT_ROOT" RUNTIME_ROOT="$RUNTIME_ROOT" RJ_INSTALL_LOG_DISABLE=1 "$SCRIPT_DIR/install_rustyjack_prebuilt.sh"; then
    fail "install_rustyjack_prebuilt.sh failed after debug source build handoff"
  fi
}

if [ "$(id -u)" -ne 0 ]; then
  fail "This installer must run as root."
fi

setup_install_logging
export DEBIAN_FRONTEND=noninteractive

if [ -r /etc/os-release ]; then
  . /etc/os-release
  info "OS: ${PRETTY_NAME:-unknown} (${VERSION_CODENAME:-unknown})"
fi

ensure_rw_root
bootstrap_resolvers
install_build_dependencies
ensure_swap_space 1024 1536
ensure_rust_toolchain
build_debug_binaries
handoff_to_prebuilt
