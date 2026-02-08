#!/usr/bin/env bash
# Roll back Rustyjack installer changes on Raspberry Pi OS (arm64 or armhf/armv7).
# This script dynamically inspects install_rustyjack*.sh in the repo root to model
# what to undo, then reverts the host back toward stock CLI image defaults.
set -euo pipefail

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "This rollback script requires bash 4.0+." >&2
  exit 2
fi

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0.0"

DRY_RUN=0
ASSUME_YES=0
PURGE_INSTALLER_PACKAGES=1
REBOOT_AFTER=0
RESTORE_NETWORK_MANAGER=1
FORCE_ARCH_MISMATCH=0
EXPECTED_ARCH=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="/var/log/rustyjack"
BACKUP_DIR_BASE="/var/backups/rustyjack-rollback"
LOG_FILE="${LOG_DIR}/rollback_${TIMESTAMP}.log"
BACKUP_DIR="${BACKUP_DIR_BASE}/${TIMESTAMP}"

CFG_FILES=("/boot/firmware/config.txt" "/boot/config.txt")
CMDLINE_FILES=("/boot/firmware/cmdline.txt" "/boot/cmdline.txt")

declare -A SET_RUNTIME_ROOTS=()
declare -A SET_SYSTEMD_UNITS=()
declare -A SET_BINARIES=()
declare -A SET_GROUPS=()
declare -A SET_USERS=()
declare -A SET_PACKAGES=()
declare -A SET_CONFIG_LINES=()
declare -A SET_MODULES=()
declare -A SET_NETWORK_CONFLICT_UNITS=()

declare -a INSTALLER_SCRIPTS=()
declare -a RUNTIME_ROOTS=()
declare -a RUSTYJACK_UNITS=()
declare -a RUSTYJACK_BINARIES=()
declare -a RUSTYJACK_GROUPS=()
declare -a RUSTYJACK_USERS=()
declare -a INSTALLER_PACKAGES=()
declare -a CONFIG_LINES=()
declare -a MODULE_LINES=()
declare -a NETWORK_CONFLICT_UNITS=()

usage() {
  cat <<'USAGE'
Usage:
  sudo ./scripts/rollback_rustyjack.sh [options]

Options:
  --dry-run                    Print actions without making changes.
  --yes                        Skip interactive confirmation.
  --no-package-purge           Keep installer-added packages installed.
  --no-network-manager-restore Do not attempt to reinstall/restore NetworkManager.
  --reboot                     Reboot automatically when rollback finishes.
  --expected-arch <arch>       Require host arch: arm64 or armhf.
  --force-arch                 Ignore --expected-arch mismatch.
  -h, --help                   Show this help.

Examples:
  sudo ./scripts/rollback_rustyjack.sh --yes --reboot
  sudo ./scripts/rollback_rustyjack.sh --dry-run
USAGE
}

info() { printf "[INFO] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*"; }
fail() { printf "[FAIL] %s\n" "$*" >&2; exit 1; }

run_cmd() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf "[DRY-RUN]"
    printf " %q" "$@"
    printf "\n"
    return 0
  fi
  "$@"
}

add_to_set() {
  local set_name="$1"
  shift
  local item
  # shellcheck disable=SC2178
  local -n set_ref="${set_name}"
  for item in "$@"; do
    [ -n "${item}" ] || continue
    set_ref["${item}"]=1
  done
}

set_to_sorted_array() {
  local set_name="$1"
  local out_name="$2"
  # shellcheck disable=SC2178
  local -n set_ref="${set_name}"
  # shellcheck disable=SC2178
  local -n out_ref="${out_name}"
  out_ref=()
  if [ "${#set_ref[@]}" -eq 0 ]; then
    return 0
  fi
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    out_ref+=("${line}")
  done < <(printf "%s\n" "${!set_ref[@]}" | LC_ALL=C sort -u)
}

package_installed() {
  local pkg="$1"
  dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
}

unit_exists() {
  local unit="$1"
  systemctl list-unit-files --all --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "$unit"
}

extract_array_tokens_from_file() {
  local file="$1"
  local var_name="$2"
  awk -v name="$var_name" '
    BEGIN { in_arr=0 }
    $0 ~ "^[[:space:]]*"name"=\\(" { in_arr=1; next }
    in_arr == 1 {
      if ($0 ~ /^[[:space:]]*\\)/) { in_arr=0; next }
      sub(/#.*/, "", $0)
      gsub(/[[:space:]]+/, " ", $0)
      gsub(/^ | $/, "", $0)
      if (length($0) > 0) print $0
    }
  ' "$file" | tr ' ' '\n' | sed '/^$/d'
}

escape_regex() {
  printf "%s" "$1" | sed -e 's/[.[\*^$()+?{}|\\/]/\\&/g'
}

remove_exact_line() {
  local file="$1"
  local line="$2"
  [ -f "$file" ] || return 0
  local esc
  esc="$(escape_regex "$line")"
  run_cmd sed -i -E "/^[[:space:]]*${esc}[[:space:]]*$/d" "$file"
}

backup_path() {
  local src="$1"
  if [ ! -e "$src" ] && [ ! -L "$src" ]; then
    return 0
  fi
  local dst="${BACKUP_DIR}${src}"
  run_cmd mkdir -p "$(dirname "$dst")"
  run_cmd cp -a "$src" "$dst"
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        ;;
      --yes)
        ASSUME_YES=1
        ;;
      --no-package-purge)
        PURGE_INSTALLER_PACKAGES=0
        ;;
      --no-network-manager-restore)
        RESTORE_NETWORK_MANAGER=0
        ;;
      --reboot)
        REBOOT_AFTER=1
        ;;
      --expected-arch)
        shift || fail "Missing value for --expected-arch"
        EXPECTED_ARCH="$1"
        ;;
      --force-arch)
        FORCE_ARCH_MISMATCH=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "Unknown option: $1"
        ;;
    esac
    shift
  done
}

discover_installers() {
  INSTALLER_SCRIPTS=()
  while IFS= read -r -d '' file; do
    INSTALLER_SCRIPTS+=("$file")
  done < <(find "$PROJECT_ROOT" -maxdepth 1 -type f -name 'install_rustyjack*.sh' -print0 | sort -z)

  if [ "${#INSTALLER_SCRIPTS[@]}" -eq 0 ]; then
    warn "No install_rustyjack*.sh scripts found under ${PROJECT_ROOT}. Using fallback rollback model."
  fi
}

apply_fallback_model() {
  add_to_set SET_RUNTIME_ROOTS "/var/lib/rustyjack"
  add_to_set SET_SYSTEMD_UNITS \
    "rustyjackd.socket" \
    "rustyjackd.service" \
    "rustyjack-ui.service" \
    "rustyjack-portal.service" \
    "rustyjack.service" \
    "rustyjack-wpa_supplicant@wlan0.service" \
    "rustyjack-wpa_supplicant@.service"
  add_to_set SET_BINARIES "rustyjack" "rustyjack-ui" "rustyjackd" "rustyjack-portal"
  add_to_set SET_GROUPS "rustyjack" "rustyjack-ui" "rustyjack-portal"
  add_to_set SET_USERS "rustyjack-ui" "rustyjack-portal"
  add_to_set SET_CONFIG_LINES \
    "dtparam=i2c_arm=on" \
    "dtparam=i2c1=on" \
    "dtparam=spi=on" \
    "dtparam=wifi=on" \
    "dtoverlay=spi0-2cs" \
    "gpio=6,19,5,26,13,21,20,16=pu"
  add_to_set SET_MODULES "i2c-bcm2835" "i2c-dev" "spi_bcm2835" "spidev" "vfat" "exfat" "ext4"
  add_to_set SET_NETWORK_CONFLICT_UNITS \
    "NetworkManager.service" \
    "NetworkManager-wait-online.service" \
    "systemd-resolved.service" \
    "dhcpcd.service" \
    "resolvconf.service" \
    "wpa_supplicant.service" \
    "wpa_supplicant@.service" \
    "systemd-networkd.service" \
    "systemd-networkd-wait-online.service" \
    "systemd-rfkill.service" \
    "systemd-rfkill.socket"
  add_to_set SET_PACKAGES \
    "build-essential" "pkg-config" "libssl-dev" "dkms" "bc" "libelf-dev" \
    "wpasupplicant" "isc-dhcp-client" "hostapd" "dnsmasq" "rfkill" \
    "dosfstools" "e2fsprogs" "exfatprogs" "git" "i2c-tools" "curl" "usbutils" \
    "firmware-linux-nonfree" "firmware-realtek" "firmware-atheros" \
    "firmware-ralink" "firmware-misc-nonfree"
}

parse_installers_into_model() {
  local script
  for script in "${INSTALLER_SCRIPTS[@]}"; do
    while IFS= read -r rr; do
      rr="${rr//$'\r'/}"
      [ -n "$rr" ] || continue
      add_to_set SET_RUNTIME_ROOTS "$rr"
    done < <(grep -Eo 'RUNTIME_ROOT="\$\{RUNTIME_ROOT:-[^}]+' "$script" | sed -E 's/.*:-//')

    while IFS= read -r dt; do
      dt="${dt//$'\r'/}"
      [ -n "$dt" ] || continue
      add_to_set SET_CONFIG_LINES "$dt"
    done < <(grep -Eo 'add_dtparam[[:space:]]+dtparam=[^[:space:]]+' "$script" | awk '{print $2}')

    if grep -q "dtoverlay=spi0-2cs" "$script"; then
      add_to_set SET_CONFIG_LINES "dtoverlay=spi0-2cs"
    fi
    if grep -q "gpio=6,19,5,26,13,21,20,16=pu" "$script"; then
      add_to_set SET_CONFIG_LINES "gpio=6,19,5,26,13,21,20,16=pu"
    fi

    while IFS= read -r mods_line; do
      mods_line="${mods_line//$'\r'/}"
      [ -n "$mods_line" ] || continue
      mods_line="$(printf '%s' "$mods_line" | sed -E 's/^[^(]*\(([^)]*)\).*/\1/')"
      while IFS= read -r m; do
        [ -n "$m" ] || continue
        add_to_set SET_MODULES "$m"
      done < <(printf "%s\n" "$mods_line" | tr ' ' '\n' | sed '/^$/d')
    done < <(grep -E '^[[:space:]]*MODULES=\(' "$script" || true)

    while IFS= read -r unit_path; do
      [ -n "$unit_path" ] || continue
      add_to_set SET_SYSTEMD_UNITS "$(basename "$unit_path")"
    done < <(grep -Eo '/etc/systemd/system/[A-Za-z0-9@._-]+' "$script" || true)

    while IFS= read -r bin_path; do
      [ -n "$bin_path" ] || continue
      add_to_set SET_BINARIES "$(basename "$bin_path")"
    done < <(grep -Eo '/usr/local/bin/[A-Za-z0-9._-]+' "$script" || true)

    while IFS= read -r grp; do
      grp="${grp//$'\r'/}"
      [ -n "$grp" ] || continue
      add_to_set SET_GROUPS "$grp"
    done < <(sed -nE 's/.*groupadd --system ([A-Za-z0-9@._-]+).*/\1/p' "$script")

    while IFS= read -r usr; do
      usr="${usr//$'\r'/}"
      [ -n "$usr" ] || continue
      add_to_set SET_USERS "$usr"
    done < <(sed -nE 's/.*useradd --system .* ([A-Za-z0-9@._-]+)([[:space:]]*\|\|.*)?$/\1/p' "$script")

    while IFS= read -r pkg; do
      pkg="${pkg//$'\r'/}"
      [ -n "$pkg" ] || continue
      add_to_set SET_PACKAGES "$pkg"
    done < <(extract_array_tokens_from_file "$script" "PACKAGES")

    while IFS= read -r pkg; do
      pkg="${pkg//$'\r'/}"
      [ -n "$pkg" ] || continue
      add_to_set SET_PACKAGES "$pkg"
    done < <(extract_array_tokens_from_file "$script" "FIRMWARE_PACKAGES")

    while IFS= read -r unit; do
      [ -n "$unit" ] || continue
      case "$unit" in
        NetworkManager*|systemd-resolved*|dhcpcd*|resolvconf*|wpa_supplicant*|systemd-networkd*|systemd-rfkill*)
          add_to_set SET_NETWORK_CONFLICT_UNITS "$unit"
          ;;
      esac
    done < <(grep -Eo '[A-Za-z0-9@._-]+\.(service|socket)' "$script" || true)
  done
}

materialize_model() {
  set_to_sorted_array SET_RUNTIME_ROOTS RUNTIME_ROOTS
  set_to_sorted_array SET_SYSTEMD_UNITS RUSTYJACK_UNITS
  set_to_sorted_array SET_BINARIES RUSTYJACK_BINARIES
  set_to_sorted_array SET_GROUPS RUSTYJACK_GROUPS
  set_to_sorted_array SET_USERS RUSTYJACK_USERS
  set_to_sorted_array SET_PACKAGES INSTALLER_PACKAGES
  set_to_sorted_array SET_CONFIG_LINES CONFIG_LINES
  set_to_sorted_array SET_MODULES MODULE_LINES
  set_to_sorted_array SET_NETWORK_CONFLICT_UNITS NETWORK_CONFLICT_UNITS
}

validate_arch() {
  local dpkg_arch uname_arch
  dpkg_arch="$(dpkg --print-architecture 2>/dev/null || true)"
  uname_arch="$(uname -m 2>/dev/null || true)"
  info "Detected architecture: dpkg=${dpkg_arch:-unknown}, uname=${uname_arch:-unknown}"

  [ -n "${EXPECTED_ARCH}" ] || return 0

  local ok=0
  case "${EXPECTED_ARCH}" in
    arm64)
      if [ "${dpkg_arch}" = "arm64" ] || [ "${uname_arch}" = "aarch64" ]; then
        ok=1
      fi
      ;;
    armhf)
      case "${dpkg_arch}" in
        armhf|armel) ok=1 ;;
      esac
      case "${uname_arch}" in
        armv6l|armv7l|armv8l) ok=1 ;;
      esac
      ;;
    *)
      fail "Unsupported --expected-arch value: ${EXPECTED_ARCH} (use arm64 or armhf)"
      ;;
  esac

  if [ "${ok}" -eq 0 ]; then
    if [ "${FORCE_ARCH_MISMATCH}" -eq 1 ]; then
      warn "Architecture mismatch ignored (--force-arch)."
    else
      fail "Architecture mismatch: expected ${EXPECTED_ARCH}, got dpkg=${dpkg_arch:-unknown}, uname=${uname_arch:-unknown}"
    fi
  fi
}

confirm_plan() {
  info "Rollback model summary:"
  info "  Runtime roots: ${RUNTIME_ROOTS[*]:-none}"
  info "  Rustyjack units discovered: ${#RUSTYJACK_UNITS[@]}"
  info "  Rustyjack binaries discovered: ${#RUSTYJACK_BINARIES[@]}"
  info "  Service users discovered: ${RUSTYJACK_USERS[*]:-none}"
  info "  Service groups discovered: ${RUSTYJACK_GROUPS[*]:-none}"
  info "  Config lines to remove: ${#CONFIG_LINES[@]}"
  info "  Kernel modules to remove from /etc/modules: ${#MODULE_LINES[@]}"
  info "  Installer package candidates: ${#INSTALLER_PACKAGES[@]}"

  if [ "${ASSUME_YES}" -eq 1 ] || [ "${DRY_RUN}" -eq 1 ]; then
    return 0
  fi

  echo
  echo "Type ROLLBACK to continue:"
  read -r answer
  [ "$answer" = "ROLLBACK" ] || fail "Aborted."
}

prepare_logging() {
  if [ "${DRY_RUN}" -eq 0 ]; then
    mkdir -p "${LOG_DIR}"
    mkdir -p "${BACKUP_DIR}"
    exec > >(tee -a "${LOG_FILE}") 2>&1
  fi
  info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
  info "Project root: ${PROJECT_ROOT}"
  if [ "${DRY_RUN}" -eq 1 ]; then
    info "Dry-run mode enabled."
  else
    info "Log file: ${LOG_FILE}"
    info "Backup dir: ${BACKUP_DIR}"
  fi
}

audit_current_state() {
  info "Auditing current Rustyjack footprint..."

  local unit
  for unit in "${RUSTYJACK_UNITS[@]}"; do
    case "$unit" in
      rustyjack*)
        ;;
      *)
        continue
        ;;
    esac
    if unit_exists "$unit"; then
      info "  Unit exists: $unit"
    fi
  done

  local bin
  for bin in "${RUSTYJACK_BINARIES[@]}"; do
    case "$bin" in
      rustyjack* )
        if [ -e "/usr/local/bin/$bin" ]; then
          info "  Binary exists: /usr/local/bin/$bin"
        fi
        ;;
    esac
  done

  local root
  for root in "${RUNTIME_ROOTS[@]}"; do
    [ -n "$root" ] || continue
    if [ -e "$root" ]; then
      info "  Runtime root exists: $root"
    fi
  done

  if [ -e "/etc/systemd/system/rustyjack.service" ]; then
    info "  Alias exists: /etc/systemd/system/rustyjack.service"
  fi
}

backup_pre_rollback_state() {
  info "Backing up key files before rollback..."

  local f
  for f in "${CFG_FILES[@]}" "${CMDLINE_FILES[@]}" "/etc/modules" "/etc/resolv.conf" "/etc/resolv.conf.rustyjack.bak"; do
    backup_path "$f"
  done

  backup_path "/etc/sysctl.d/99-rustyjack.conf"
  backup_path "/etc/modprobe.d/cfg80211.conf"
  backup_path "/etc/udev/rules.d/99-rustyjack-wifi.rules"
  backup_path "/usr/local/bin/rustyjack"
  backup_path "/usr/local/bin/rustyjack-ui"
  backup_path "/usr/local/bin/rustyjackd"
  backup_path "/usr/local/bin/rustyjack-portal"

  if [ -d "/etc/systemd/system" ]; then
    while IFS= read -r -d '' unit_file; do
      backup_path "$unit_file"
    done < <(find /etc/systemd/system -maxdepth 3 \( -name 'rustyjack*.service' -o -name 'rustyjack*.socket' \) -print0 2>/dev/null)
  fi

  if [ "${DRY_RUN}" -eq 0 ]; then
    {
      echo "=== PRE-ROLLBACK STATE ==="
      date -Is
      echo
      echo "--- systemctl --failed ---"
      systemctl --failed --no-pager || true
      echo
      echo "--- rustyjack unit files ---"
      systemctl list-unit-files --all --no-pager | grep -i rustyjack || true
      echo
      echo "--- rustyjack binaries ---"
      ls -l /usr/local/bin/rustyjack* 2>/dev/null || true
      echo
      echo "--- runtime directories ---"
      ls -ld /var/lib/rustyjack /run/rustyjack /etc/rustyjack 2>/dev/null || true
    } > "${BACKUP_DIR}/pre_rollback_state.txt"
  fi
}

rollback_systemd_units() {
  info "Removing Rustyjack systemd units..."

  local unit
  for unit in "${RUSTYJACK_UNITS[@]}"; do
    case "$unit" in
      rustyjack*)
        run_cmd systemctl disable --now "$unit" || true
        run_cmd systemctl stop "$unit" || true
        run_cmd systemctl reset-failed "$unit" || true
        ;;
    esac
  done

  if [ -d "/etc/systemd/system" ]; then
    while IFS= read -r -d '' unit_file; do
      run_cmd rm -f "$unit_file"
    done < <(find /etc/systemd/system -maxdepth 3 \( -name 'rustyjack*.service' -o -name 'rustyjack*.socket' \) -print0 2>/dev/null)
  fi

  run_cmd rm -f \
    "/etc/systemd/system/rustyjack.service" \
    "/etc/systemd/system/multi-user.target.wants/rustyjack.service" \
    "/etc/systemd/system/multi-user.target.wants/rustyjack-ui.service" \
    "/etc/systemd/system/multi-user.target.wants/rustyjack-portal.service" \
    "/etc/systemd/system/multi-user.target.wants/rustyjackd.service" \
    "/etc/systemd/system/sockets.target.wants/rustyjackd.socket" \
    "/etc/systemd/system/multi-user.target.wants/rustyjack-wpa_supplicant@wlan0.service" || true

  run_cmd systemctl daemon-reload
  run_cmd systemctl reset-failed || true
}

rollback_binaries_and_runtime() {
  info "Removing Rustyjack binaries and runtime artifacts..."

  local bin
  for bin in "${RUSTYJACK_BINARIES[@]}"; do
    case "$bin" in
      rustyjack*)
        run_cmd rm -f "/usr/local/bin/${bin}"
        ;;
    esac
  done

  run_cmd rm -f /usr/local/bin/rustyjack /usr/local/bin/rustyjack-ui /usr/local/bin/rustyjackd /usr/local/bin/rustyjack-portal

  local root
  for root in "${RUNTIME_ROOTS[@]}"; do
    [ -n "$root" ] || continue
    [ "$root" = "/" ] && continue
    run_cmd rm -rf "$root"
  done

  run_cmd rm -rf /run/rustyjack /etc/rustyjack
  run_cmd rm -f /etc/udev/rules.d/99-rustyjack-wifi.rules
  run_cmd udevadm control --reload-rules || true
  run_cmd udevadm trigger || true
}

rollback_boot_and_kernel_tuning() {
  info "Reverting boot/config module changes..."

  local cfg line
  for cfg in "${CFG_FILES[@]}"; do
    [ -f "$cfg" ] || continue
    for line in "${CONFIG_LINES[@]}"; do
      [ -n "$line" ] || continue
      remove_exact_line "$cfg" "$line"
    done
  done

  local cmdline
  for cmdline in "${CMDLINE_FILES[@]}"; do
    [ -f "$cmdline" ] || continue
    run_cmd sed -i -E 's/(^|[[:space:]])cfg80211\.ieee80211_regdom=[^[:space:]]+//g; s/[[:space:]]+/ /g; s/^ //; s/ $//' "$cmdline"
  done

  if [ -f /etc/modules ]; then
    for line in "${MODULE_LINES[@]}"; do
      [ -n "$line" ] || continue
      remove_exact_line "/etc/modules" "$line"
    done
  fi

  run_cmd rm -f /etc/sysctl.d/99-rustyjack.conf /etc/modprobe.d/cfg80211.conf
  run_cmd sysctl --system || true
}

restore_resolv_conf() {
  info "Restoring /etc/resolv.conf ownership and target..."

  if [ -e /etc/resolv.conf.rustyjack.bak ]; then
    run_cmd rm -f /etc/resolv.conf
    run_cmd mv /etc/resolv.conf.rustyjack.bak /etc/resolv.conf
  else
    run_cmd rm -f /etc/resolv.conf
    if [ -e /run/systemd/resolve/stub-resolv.conf ]; then
      run_cmd ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    elif [ -e /run/systemd/resolve/resolv.conf ]; then
      run_cmd ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
    elif [ -e /run/NetworkManager/resolv.conf ]; then
      run_cmd ln -s /run/NetworkManager/resolv.conf /etc/resolv.conf
    else
      if [ "${DRY_RUN}" -eq 1 ]; then
        printf "[DRY-RUN] write static /etc/resolv.conf with public resolvers\n"
      else
        cat > /etc/resolv.conf <<'CONF'
nameserver 1.1.1.1
nameserver 9.9.9.9
CONF
      fi
    fi
  fi

  run_cmd chmod 644 /etc/resolv.conf || true
  run_cmd chown root:root /etc/resolv.conf || true
}

network_manager_was_purged() {
  if grep -qs "apt-get -y purge network-manager" /var/log/apt/history.log 2>/dev/null; then
    return 0
  fi

  if command -v zgrep >/dev/null 2>&1; then
    if zgrep -qs "apt-get -y purge network-manager" /var/log/apt/history.log*.gz 2>/dev/null; then
      return 0
    fi
  fi

  return 1
}

restore_network_stack() {
  info "Restoring network service ownership defaults..."

  local unit
  for unit in "${NETWORK_CONFLICT_UNITS[@]}"; do
    [ -n "$unit" ] || continue
    if unit_exists "$unit"; then
      run_cmd systemctl unmask "$unit" || true
      run_cmd systemctl preset "$unit" || true
    fi
  done

  if [ "${RESTORE_NETWORK_MANAGER}" -eq 1 ] && network_manager_was_purged; then
    if ! package_installed "network-manager"; then
      if apt-cache show network-manager >/dev/null 2>&1; then
        info "Reinstalling network-manager (installer previously purged it)..."
        run_cmd apt-get update -qq
        run_cmd apt-get install -y network-manager
      else
        warn "network-manager package not available from current apt sources."
      fi
    fi
  fi

  local default_services=(
    "NetworkManager.service"
    "systemd-resolved.service"
    "dhcpcd.service"
    "wpa_supplicant.service"
    "systemd-networkd.service"
    "systemd-rfkill.socket"
    "systemd-rfkill.service"
  )

  for unit in "${default_services[@]}"; do
    if unit_exists "$unit"; then
      local enabled_state
      enabled_state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
      case "$enabled_state" in
        enabled|enabled-runtime|static)
          run_cmd systemctl start "$unit" || true
          ;;
      esac
    fi
  done
}

purge_packages_installed_by_installers() {
  [ "${PURGE_INSTALLER_PACKAGES}" -eq 1 ] || {
    info "Skipping installer package purge (--no-package-purge)."
    return 0
  }

  info "Purging installer package set (best effort)..."

  declare -A PRESERVE=(
    [wpasupplicant]=1
    [git]=1
    [curl]=1
    [dosfstools]=1
    [e2fsprogs]=1
    [exfatprogs]=1
  )

  local purge_list=()
  local pkg essential
  for pkg in "${INSTALLER_PACKAGES[@]}"; do
    [ -n "$pkg" ] || continue
    if [ "${PRESERVE[$pkg]+x}" = "x" ]; then
      continue
    fi
    if ! package_installed "$pkg"; then
      continue
    fi

    essential="$(dpkg-query -W -f='${Essential}' "$pkg" 2>/dev/null || true)"
    if [ "$essential" = "yes" ]; then
      continue
    fi
    purge_list+=("$pkg")
  done

  if [ "${#purge_list[@]}" -eq 0 ]; then
    info "No removable installer packages detected."
    return 0
  fi

  run_cmd apt-get purge -y "${purge_list[@]}" || true
  run_cmd apt-get autoremove --purge -y || true
}

safe_remove_user() {
  local user="$1"
  id "$user" >/dev/null 2>&1 || return 0

  local uid home shell
  uid="$(id -u "$user" 2>/dev/null || echo "")"
  home="$(getent passwd "$user" | cut -d: -f6)"
  shell="$(getent passwd "$user" | cut -d: -f7)"

  case "$shell" in
    /usr/sbin/nologin|/usr/bin/false|/bin/false) ;;
    *)
      warn "Skipping user ${user}: shell is ${shell} (not a service account shell)."
      return 0
      ;;
  esac

  if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ "$home" != "/var/lib/rustyjack" ] && [ "$home" != "/nonexistent" ]; then
    warn "Skipping user ${user}: uid=${uid}, home=${home} looks interactive."
    return 0
  fi

  run_cmd userdel "$user" || true
}

safe_remove_group() {
  local group="$1"
  getent group "$group" >/dev/null 2>&1 || return 0

  local gid primary_users members
  gid="$(getent group "$group" | cut -d: -f3)"
  primary_users="$(awk -F: -v gid="$gid" '$4 == gid {print $1}' /etc/passwd)"
  members="$(getent group "$group" | cut -d: -f4)"

  if [ -n "$primary_users" ]; then
    warn "Skipping group ${group}: still primary for user(s): ${primary_users//$'\n'/, }"
    return 0
  fi
  if [ -n "$members" ]; then
    warn "Skipping group ${group}: has explicit members: ${members}"
    return 0
  fi

  run_cmd groupdel "$group" || true
}

rollback_users_and_groups() {
  info "Removing Rustyjack service users/groups where safe..."

  local user
  for user in "${RUSTYJACK_USERS[@]}"; do
    case "$user" in
      rustyjack-ui|rustyjack-portal)
        safe_remove_user "$user"
        ;;
      rustyjack*)
        safe_remove_user "$user"
        ;;
    esac
  done

  local group
  for group in "${RUSTYJACK_GROUPS[@]}"; do
    case "$group" in
      rustyjack|rustyjack-ui|rustyjack-portal)
        safe_remove_group "$group"
        ;;
    esac
  done
}

final_report() {
  info "Rollback pass complete."
  info "Post-check summary:"

  local unit
  for unit in "rustyjackd.service" "rustyjackd.socket" "rustyjack-ui.service" "rustyjack-portal.service"; do
    if unit_exists "$unit"; then
      warn "  Unit still present in unit-file registry: $unit"
    else
      info "  Unit removed or not registered: $unit"
    fi
  done

  local bin
  for bin in "rustyjack" "rustyjack-ui" "rustyjackd" "rustyjack-portal"; do
    if [ -e "/usr/local/bin/$bin" ]; then
      warn "  Binary still present: /usr/local/bin/$bin"
    else
      info "  Binary removed: /usr/local/bin/$bin"
    fi
  done

  if [ "${DRY_RUN}" -eq 0 ]; then
    if [ "${REBOOT_AFTER}" -eq 1 ]; then
      warn "Reboot requested. System will reboot in 5 seconds."
      sleep 5
      reboot
    else
      warn "Reboot recommended to fully apply config/module rollback."
    fi
  fi
}

main() {
  parse_args "$@"

  if [ "$(id -u)" -ne 0 ]; then
    fail "Run as root (sudo)."
  fi

  prepare_logging
  discover_installers
  apply_fallback_model
  parse_installers_into_model
  materialize_model
  validate_arch
  audit_current_state
  confirm_plan
  backup_pre_rollback_state

  rollback_systemd_units
  rollback_binaries_and_runtime
  rollback_boot_and_kernel_tuning
  restore_resolv_conf
  restore_network_stack
  purge_packages_installed_by_installers
  rollback_users_and_groups
  final_report
}

main "$@"
