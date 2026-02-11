#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

RUN_WIRELESS=0
RUN_ETHERNET=0
RUN_ENCRYPTION=0
RUN_LOOT=0
RUN_MAC=0
RUN_DAEMON=0
RUN_INSTALLERS=0
RUN_USB=0
RUN_UI_LAYOUT=0
RUN_THEME=0
DANGEROUS=0
RUN_UI=1
OUTROOT="${RJ_OUTROOT:-/var/tmp/rustyjack-tests}"
RUN_ID="${RJ_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
WIFI_IFACE=""
WIFI_IFACES=""
WIFI_ALL_IFACES=0
ETH_IFACE=""
ETH_IFACES=""
ETH_ALL_IFACES=0

chmod +x "$ROOT_DIR"/rj_test_*.sh "$ROOT_DIR"/rustyjack_comprehensive_test.sh 2>/dev/null || true

usage() {
  cat <<'USAGE'
Usage: rj_run_tests.sh [options]

Options:
  --all         Run all test suites
  --wireless    Run wireless tests
  --ethernet    Run ethernet tests
  --encryption  Run encryption tests
  --loot        Run loot tests
  --mac         Run MAC randomization tests
  --daemon      Run daemon/IPC security tests
  --installers  Run installer script tests
  --usb         Run USB mount detect/read/write tests
  --ui-layout   Run dynamic UI layout/resolution tests
  --theme       Run UI theme/palette stabilization tests
  --dangerous   Enable dangerous tests (passed to suites)
  --no-ui       Disable UI automation
  --wifi-interface IFACE   Run wireless suite on a single Wi-Fi interface
  --wifi-interfaces LIST   Comma-separated Wi-Fi interfaces for wireless suite
  --wifi-all-interfaces    Auto-detect all Wi-Fi interfaces for wireless suite
  --eth-interface IFACE    Run ethernet suite on a single ethernet interface
  --eth-interfaces LIST    Comma-separated ethernet interfaces for ethernet suite
  --eth-all-interfaces     Auto-detect all ethernet interfaces for ethernet suite
  --outroot DIR Output root (default: /var/tmp/rustyjack-tests)
  -h, --help    Show help

If no options are provided, a menu will be shown.
USAGE
}

if [[ $# -eq 0 ]]; then
  echo "Select tests:"
  echo "  1) Wireless"
  echo "  2) Ethernet"
  echo "  3) Encryption"
  echo "  4) Loot"
  echo "  5) MAC Randomization"
  echo "  6) Daemon/IPC"
  echo "  7) Installers"
  echo "  8) USB Mount"
  echo "  9) UI Layout/Display"
  echo " 10) Theme/Palette"
  echo "  0) All"
  read -r choice
  case "$choice" in
    0) RUN_WIRELESS=1; RUN_ETHERNET=1; RUN_ENCRYPTION=1; RUN_LOOT=1; RUN_MAC=1; RUN_DAEMON=1; RUN_INSTALLERS=1; RUN_USB=1; RUN_UI_LAYOUT=1; RUN_THEME=1 ;;
    1) RUN_WIRELESS=1 ;;
    2) RUN_ETHERNET=1 ;;
    3) RUN_ENCRYPTION=1 ;;
    4) RUN_LOOT=1 ;;
    5) RUN_MAC=1 ;;
    6) RUN_DAEMON=1 ;;
    7) RUN_INSTALLERS=1 ;;
    8) RUN_USB=1 ;;
    9) RUN_UI_LAYOUT=1 ;;
    10) RUN_THEME=1 ;;
    *) echo "Unknown choice" >&2; exit 2 ;;
  esac
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all) RUN_WIRELESS=1; RUN_ETHERNET=1; RUN_ENCRYPTION=1; RUN_LOOT=1; RUN_MAC=1; RUN_DAEMON=1; RUN_INSTALLERS=1; RUN_USB=1; RUN_UI_LAYOUT=1; RUN_THEME=1; shift ;;
      --wireless) RUN_WIRELESS=1; shift ;;
      --ethernet) RUN_ETHERNET=1; shift ;;
      --encryption) RUN_ENCRYPTION=1; shift ;;
      --loot) RUN_LOOT=1; shift ;;
      --mac) RUN_MAC=1; shift ;;
      --daemon) RUN_DAEMON=1; shift ;;
      --installers) RUN_INSTALLERS=1; shift ;;
      --usb) RUN_USB=1; shift ;;
      --ui-layout) RUN_UI_LAYOUT=1; shift ;;
      --theme) RUN_THEME=1; shift ;;
      --dangerous) DANGEROUS=1; shift ;;
      --no-ui) RUN_UI=0; shift ;;
      --wifi-interface) WIFI_IFACE="$2"; WIFI_ALL_IFACES=0; shift 2 ;;
      --wifi-interfaces) WIFI_IFACES="$2"; WIFI_ALL_IFACES=0; shift 2 ;;
      --wifi-all-interfaces) WIFI_ALL_IFACES=1; shift ;;
      --eth-interface) ETH_IFACE="$2"; ETH_ALL_IFACES=0; shift 2 ;;
      --eth-interfaces) ETH_IFACES="$2"; ETH_ALL_IFACES=0; shift 2 ;;
      --eth-all-interfaces) ETH_ALL_IFACES=1; shift ;;
      --outroot) OUTROOT="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
    esac
  done
fi

export RJ_OUTROOT="$OUTROOT"
export RJ_RUN_ID="$RUN_ID"

COMMON_ARGS=()
if [[ $RUN_UI -eq 0 ]]; then
  COMMON_ARGS+=(--no-ui)
fi
if [[ $DANGEROUS -eq 1 ]]; then
  COMMON_ARGS+=(--dangerous)
fi

WIRELESS_ARGS=()
if [[ $WIFI_ALL_IFACES -eq 1 ]]; then
  WIRELESS_ARGS+=(--all-interfaces)
elif [[ -n "$WIFI_IFACES" ]]; then
  WIRELESS_ARGS+=(--interfaces "$WIFI_IFACES")
elif [[ -n "$WIFI_IFACE" ]]; then
  WIRELESS_ARGS+=(--interface "$WIFI_IFACE")
fi

ETHERNET_ARGS=()
if [[ $ETH_ALL_IFACES -eq 1 ]]; then
  ETHERNET_ARGS+=(--all-interfaces)
elif [[ -n "$ETH_IFACES" ]]; then
  ETHERNET_ARGS+=(--interfaces "$ETH_IFACES")
elif [[ -n "$ETH_IFACE" ]]; then
  ETHERNET_ARGS+=(--interface "$ETH_IFACE")
fi

if [[ $RUN_WIRELESS -eq 0 && $RUN_ETHERNET -eq 0 && $RUN_ENCRYPTION -eq 0 && \
      $RUN_LOOT -eq 0 && $RUN_MAC -eq 0 && $RUN_DAEMON -eq 0 && \
      $RUN_INSTALLERS -eq 0 && $RUN_USB -eq 0 && $RUN_UI_LAYOUT -eq 0 && \
      $RUN_THEME -eq 0 ]]; then
  echo "No test suites selected. Use --all or choose a suite."
  exit 2
fi

SUITES_RUN=0
SUITES_PASS=0
SUITES_FAIL=0
SUITE_RESULTS=()

run_suite() {
  local label="$1"
  local script="$2"
  shift 2

  SUITES_RUN=$((SUITES_RUN + 1))
  echo "================================================================"
  echo "[SUITE] $label"
  echo "[START] $(date -Is) :: $script"

  if "$script" "$@"; then
    SUITES_PASS=$((SUITES_PASS + 1))
    SUITE_RESULTS+=("[PASS] $label")
    echo "[DONE]  $(date -Is) :: $label (pass)"
  else
    local rc=$?
    SUITES_FAIL=$((SUITES_FAIL + 1))
    SUITE_RESULTS+=("[FAIL] $label (rc=$rc)")
    echo "[DONE]  $(date -Is) :: $label (fail rc=$rc)"
  fi
}

echo "Rustyjack test run starting"
echo "Run ID: $RUN_ID"
echo "Results root: $OUTROOT/$RUN_ID"
echo "Common args: ${COMMON_ARGS[*]:-(none)}"
echo "Wireless args: ${WIRELESS_ARGS[*]:-(auto)}"
echo "Ethernet args: ${ETHERNET_ARGS[*]:-(auto)}"

if [[ $RUN_WIRELESS -eq 1 ]]; then
  run_suite "Wireless" "$ROOT_DIR/rj_test_wireless.sh" "${COMMON_ARGS[@]}" "${WIRELESS_ARGS[@]}"
fi
if [[ $RUN_ETHERNET -eq 1 ]]; then
  run_suite "Ethernet" "$ROOT_DIR/rj_test_ethernet.sh" "${COMMON_ARGS[@]}" "${ETHERNET_ARGS[@]}"
fi
if [[ $RUN_ENCRYPTION -eq 1 ]]; then
  run_suite "Encryption" "$ROOT_DIR/rj_test_encryption.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_LOOT -eq 1 ]]; then
  run_suite "Loot" "$ROOT_DIR/rj_test_loot.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_MAC -eq 1 ]]; then
  run_suite "MAC Randomization" "$ROOT_DIR/rj_test_mac_randomization.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_DAEMON -eq 1 ]]; then
  run_suite "Daemon/IPC" "$ROOT_DIR/rj_test_daemon.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_INSTALLERS -eq 1 ]]; then
  run_suite "Installers" "$ROOT_DIR/rj_test_installers.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_USB -eq 1 ]]; then
  run_suite "USB Mount" "$ROOT_DIR/rj_test_usb.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_UI_LAYOUT -eq 1 ]]; then
  run_suite "UI Layout/Display" "$ROOT_DIR/rj_test_ui_layout.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_THEME -eq 1 ]]; then
  run_suite "Theme/Palette" "$ROOT_DIR/rj_test_theme.sh" "${COMMON_ARGS[@]}"
fi

echo "================================================================"
echo "Suite summary:"
for result in "${SUITE_RESULTS[@]}"; do
  echo "  $result"
done
echo "Suites run: $SUITES_RUN"
echo "Suites passed: $SUITES_PASS"
echo "Suites failed: $SUITES_FAIL"
echo "Results root: $OUTROOT/$RUN_ID"

if [[ $SUITES_FAIL -gt 0 ]]; then
  exit 1
fi
