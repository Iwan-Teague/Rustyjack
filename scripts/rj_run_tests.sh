#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

RUN_WIRELESS=0
RUN_ETHERNET=0
RUN_ENCRYPTION=0
RUN_LOOT=0
RUN_MAC=0
RUN_DAEMON=0
RUN_DAEMON_DEEP=0
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
WIRELESS_EXTRA_ARGS=()
ETHERNET_EXTRA_ARGS=()
ENCRYPTION_EXTRA_ARGS=()
LOOT_EXTRA_ARGS=()
MAC_EXTRA_ARGS=()
DAEMON_EXTRA_ARGS=()
INSTALLERS_EXTRA_ARGS=()
USB_EXTRA_ARGS=()
UI_LAYOUT_EXTRA_ARGS=()
THEME_EXTRA_ARGS=()
DAEMON_DEEP_EXTRA_ARGS=()

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
  --daemon-deep Run deep daemon comprehensive diagnostics (longer)
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

hr() {
  printf '%s\n' "================================================================"
}

format_duration() {
  local secs="$1"
  local h=$((secs / 3600))
  local m=$(((secs % 3600) / 60))
  local s=$((secs % 60))
  if [[ $h -gt 0 ]]; then
    printf '%dh%02dm%02ds' "$h" "$m" "$s"
  elif [[ $m -gt 0 ]]; then
    printf '%dm%02ds' "$m" "$s"
  else
    printf '%ss' "$s"
  fi
}

read_report_metric() {
  local report="$1"
  local key="$2"
  if [[ ! -f "$report" ]]; then
    printf '%s' "-"
    return 0
  fi
  awk -F': ' -v k="$key" '$0 ~ "^- " k ":" {print $2; exit}' "$report" 2>/dev/null || printf '%s' "-"
}

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  local reply
  if [[ "$default" == "Y" ]]; then
    read -r -p "$prompt [Y/n]: " reply
    reply="${reply:-y}"
  else
    read -r -p "$prompt [y/N]: " reply
    reply="${reply:-n}"
  fi
  case "$reply" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

add_skip_flag() {
  local -n arr_ref="$1"
  local label="$2"
  local flag="$3"
  if prompt_yes_no "Skip ${label}?" "N"; then
    arr_ref+=("$flag")
  fi
}

interactive_collect_advanced_options() {
  local val
  if ! prompt_yes_no "Configure advanced per-suite options?" "N"; then
    return 0
  fi

  if [[ $RUN_WIRELESS -eq 1 ]]; then
    echo
    echo "Advanced: Wireless"
    add_skip_flag WIRELESS_EXTRA_ARGS "wireless unit tests" "--no-unit"
    add_skip_flag WIRELESS_EXTRA_ARGS "wireless integration tests" "--no-integration"
    add_skip_flag WIRELESS_EXTRA_ARGS "wireless negative tests" "--no-negative"
    add_skip_flag WIRELESS_EXTRA_ARGS "wireless isolation checks" "--no-isolation"
    add_skip_flag WIRELESS_EXTRA_ARGS "wireless compatibility checks" "--no-compat"
    if prompt_yes_no "Enable wireless recon tests?" "N"; then
      WIRELESS_EXTRA_ARGS+=("--recon")
    fi
  fi

  if [[ $RUN_ETHERNET -eq 1 ]]; then
    echo
    echo "Advanced: Ethernet"
    add_skip_flag ETHERNET_EXTRA_ARGS "ethernet unit tests" "--no-unit"
    add_skip_flag ETHERNET_EXTRA_ARGS "ethernet integration tests" "--no-integration"
    add_skip_flag ETHERNET_EXTRA_ARGS "ethernet negative tests" "--no-negative"
    add_skip_flag ETHERNET_EXTRA_ARGS "ethernet isolation checks" "--no-isolation"
    add_skip_flag ETHERNET_EXTRA_ARGS "ethernet compatibility checks" "--no-compat"
    read -r -p "Ethernet target CIDR/IP (blank to skip): " val
    if [[ -n "${val// }" ]]; then
      ETHERNET_EXTRA_ARGS+=(--target "${val// /}")
    fi
    read -r -p "Ethernet ports list (e.g. 22,80,443; blank to skip): " val
    if [[ -n "${val// }" ]]; then
      ETHERNET_EXTRA_ARGS+=(--ports "${val// /}")
    fi
  fi

  if [[ $RUN_ENCRYPTION -eq 1 ]]; then
    echo
    echo "Advanced: Encryption"
    add_skip_flag ENCRYPTION_EXTRA_ARGS "encryption unit tests" "--no-unit"
    add_skip_flag ENCRYPTION_EXTRA_ARGS "encryption integration tests" "--no-integration"
    add_skip_flag ENCRYPTION_EXTRA_ARGS "encryption negative tests" "--no-negative"
    add_skip_flag ENCRYPTION_EXTRA_ARGS "encryption isolation checks" "--no-isolation"
    add_skip_flag ENCRYPTION_EXTRA_ARGS "encryption compatibility checks" "--no-compat"
  fi

  if [[ $RUN_LOOT -eq 1 ]]; then
    echo
    echo "Advanced: Loot"
    add_skip_flag LOOT_EXTRA_ARGS "loot unit tests" "--no-unit"
    add_skip_flag LOOT_EXTRA_ARGS "loot integration tests" "--no-integration"
    add_skip_flag LOOT_EXTRA_ARGS "loot negative tests" "--no-negative"
    add_skip_flag LOOT_EXTRA_ARGS "loot isolation checks" "--no-isolation"
    add_skip_flag LOOT_EXTRA_ARGS "loot compatibility checks" "--no-compat"
  fi

  if [[ $RUN_MAC -eq 1 ]]; then
    echo
    echo "Advanced: MAC Randomization"
    add_skip_flag MAC_EXTRA_ARGS "MAC unit tests" "--no-unit"
    add_skip_flag MAC_EXTRA_ARGS "MAC stress loop" "--no-stress"
    add_skip_flag MAC_EXTRA_ARGS "MAC negative tests" "--no-negative"
    add_skip_flag MAC_EXTRA_ARGS "MAC vendor test" "--no-vendor"
    read -r -p "MAC interface override (blank to keep default): " val
    if [[ -n "${val// }" ]]; then
      MAC_EXTRA_ARGS+=(--interface "${val// /}")
    fi
    read -r -p "MAC vendor name (blank to keep default): " val
    if [[ -n "${val// }" ]]; then
      MAC_EXTRA_ARGS+=(--vendor "$val")
    fi
    read -r -p "MAC stress loop count (blank to keep default): " val
    if [[ -n "${val// }" ]]; then
      MAC_EXTRA_ARGS+=(--loops "${val// /}")
    fi
  fi

  if [[ $RUN_DAEMON -eq 1 ]]; then
    echo
    echo "Advanced: Daemon/IPC"
    add_skip_flag DAEMON_EXTRA_ARGS "daemon auth tests" "--no-auth"
    add_skip_flag DAEMON_EXTRA_ARGS "daemon protocol tests" "--no-protocol"
    add_skip_flag DAEMON_EXTRA_ARGS "daemon unit tests" "--no-unit"
    add_skip_flag DAEMON_EXTRA_ARGS "daemon compatibility checks" "--no-compat"
    add_skip_flag DAEMON_EXTRA_ARGS "daemon isolation checks" "--no-isolation"
    if prompt_yes_no "Skip daemon comprehensive sub-suite?" "N"; then
      DAEMON_EXTRA_ARGS+=("--skip-comprehensive")
    fi
    read -r -p "Daemon socket path (blank for default): " val
    if [[ -n "${val// }" ]]; then
      DAEMON_EXTRA_ARGS+=(--socket "$val")
    fi
    read -r -p "Daemon service unit (blank for default): " val
    if [[ -n "${val// }" ]]; then
      DAEMON_EXTRA_ARGS+=(--service "$val")
    fi
  fi

  if [[ $RUN_DAEMON_DEEP -eq 1 ]]; then
    echo
    echo "Advanced: Daemon Deep Diagnostics"
    read -r -p "Daemon deep socket path (blank for default): " val
    if [[ -n "${val// }" ]]; then
      DAEMON_DEEP_EXTRA_ARGS+=(--socket "$val")
    fi
    read -r -p "Daemon deep service unit (blank for default): " val
    if [[ -n "${val// }" ]]; then
      DAEMON_DEEP_EXTRA_ARGS+=(--service "$val")
    fi
    read -r -p "Daemon deep parallel clients (blank for default): " val
    if [[ -n "${val// }" ]]; then
      DAEMON_DEEP_EXTRA_ARGS+=(--parallel "${val// /}")
    fi
    read -r -p "Daemon deep stress iterations (blank for default): " val
    if [[ -n "${val// }" ]]; then
      DAEMON_DEEP_EXTRA_ARGS+=(--stress "${val// /}")
    fi
    if prompt_yes_no "Enable verbose deep daemon output?" "N"; then
      DAEMON_DEEP_EXTRA_ARGS+=(--verbose)
    fi
  fi

  if [[ $RUN_INSTALLERS -eq 1 ]]; then
    echo
    echo "Advanced: Installers"
    add_skip_flag INSTALLERS_EXTRA_ARGS "shellcheck checks" "--no-shellcheck"
    add_skip_flag INSTALLERS_EXTRA_ARGS "syntax checks" "--no-syntax"
    add_skip_flag INSTALLERS_EXTRA_ARGS "pattern checks" "--no-patterns"
    add_skip_flag INSTALLERS_EXTRA_ARGS "installer isolation checks" "--no-isolation"
  fi

  if [[ $RUN_USB -eq 1 ]]; then
    echo
    echo "Advanced: USB"
    add_skip_flag USB_EXTRA_ARGS "USB compatibility checks" "--no-compat"
    add_skip_flag USB_EXTRA_ARGS "USB integration checks" "--no-integration"
    add_skip_flag USB_EXTRA_ARGS "USB negative checks" "--no-negative"
    add_skip_flag USB_EXTRA_ARGS "USB isolation checks" "--no-isolation"
    read -r -p "USB device path override (blank for auto-detect): " val
    if [[ -n "${val// }" ]]; then
      USB_EXTRA_ARGS+=(--device "${val// /}")
    fi
  fi

  if [[ $RUN_THEME -eq 1 ]]; then
    echo
    echo "Advanced: Theme"
    add_skip_flag THEME_EXTRA_ARGS "theme unit tests" "--no-unit"
    add_skip_flag THEME_EXTRA_ARGS "theme integration checks" "--no-integration"
    add_skip_flag THEME_EXTRA_ARGS "theme source checks" "--no-source"
    add_skip_flag THEME_EXTRA_ARGS "theme compatibility checks" "--no-compat"
    add_skip_flag THEME_EXTRA_ARGS "theme isolation checks" "--no-isolation"
  fi
}

interactive_collect_flags() {
  local mode choice_list single_iface

  if prompt_yes_no "Enable dangerous tests where supported?" "N"; then
    DANGEROUS=1
  fi
  if prompt_yes_no "Enable UI automation?" "Y"; then
    RUN_UI=1
  else
    RUN_UI=0
  fi
  if prompt_yes_no "Run deep daemon diagnostics suite?" "N"; then
    RUN_DAEMON_DEEP=1
  fi

  if [[ $RUN_WIRELESS -eq 1 ]]; then
    echo "Wireless interface mode:"
    echo "  1) Auto-detect (default)"
    echo "  2) Single interface"
    echo "  3) Comma-separated list"
    echo "  4) All interfaces"
    read -r -p "Choose [1-4]: " mode
    mode="${mode:-1}"
    case "$mode" in
      2)
        read -r -p "Enter Wi-Fi interface (e.g. wlan0): " single_iface
        WIFI_IFACE="${single_iface// /}"
        WIFI_IFACES=""
        WIFI_ALL_IFACES=0
        ;;
      3)
        read -r -p "Enter Wi-Fi interfaces (comma-separated): " choice_list
        WIFI_IFACES="${choice_list// /}"
        WIFI_IFACE=""
        WIFI_ALL_IFACES=0
        ;;
      4)
        WIFI_ALL_IFACES=1
        WIFI_IFACE=""
        WIFI_IFACES=""
        ;;
      *)
        WIFI_ALL_IFACES=0
        WIFI_IFACE=""
        WIFI_IFACES=""
        ;;
    esac
  fi

  if [[ $RUN_ETHERNET -eq 1 ]]; then
    echo "Ethernet interface mode:"
    echo "  1) Auto-detect (default)"
    echo "  2) Single interface"
    echo "  3) Comma-separated list"
    echo "  4) All interfaces"
    read -r -p "Choose [1-4]: " mode
    mode="${mode:-1}"
    case "$mode" in
      2)
        read -r -p "Enter Ethernet interface (e.g. eth0): " single_iface
        ETH_IFACE="${single_iface// /}"
        ETH_IFACES=""
        ETH_ALL_IFACES=0
        ;;
      3)
        read -r -p "Enter Ethernet interfaces (comma-separated): " choice_list
        ETH_IFACES="${choice_list// /}"
        ETH_IFACE=""
        ETH_ALL_IFACES=0
        ;;
      4)
        ETH_ALL_IFACES=1
        ETH_IFACE=""
        ETH_IFACES=""
        ;;
      *)
        ETH_ALL_IFACES=0
        ETH_IFACE=""
        ETH_IFACES=""
        ;;
    esac
  fi

  read -r -p "Output root directory [$OUTROOT]: " choice_list
  if [[ -n "${choice_list// }" ]]; then
    OUTROOT="${choice_list%/}"
  fi

  interactive_collect_advanced_options
}

if [[ $# -eq 0 ]]; then
  echo "Select tests:"
  echo "  1) Wireless"
  echo "  2) Ethernet"
  echo "  3) Encryption"
  echo "  4) Loot"
  echo "  5) MAC Randomization"
  echo "  6) Daemon/IPC"
  echo " 11) Daemon Deep Diagnostics"
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
    11) RUN_DAEMON_DEEP=1 ;;
    7) RUN_INSTALLERS=1 ;;
    8) RUN_USB=1 ;;
    9) RUN_UI_LAYOUT=1 ;;
    10) RUN_THEME=1 ;;
    *) echo "Unknown choice" >&2; exit 2 ;;
  esac
  interactive_collect_flags
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
      --daemon-deep) RUN_DAEMON_DEEP=1; shift ;;
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
export RJ_NONINTERACTIVE="${RJ_NONINTERACTIVE:-1}"
export RJ_AUTO_INSTALL="${RJ_AUTO_INSTALL:-0}"

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
      $RUN_DAEMON_DEEP -eq 0 && $RUN_INSTALLERS -eq 0 && $RUN_USB -eq 0 && $RUN_UI_LAYOUT -eq 0 && \
      $RUN_THEME -eq 0 ]]; then
  echo "No test suites selected. Use --all or choose a suite."
  exit 2
fi

SUITES_RUN=0
SUITES_PASS=0
SUITES_FAIL=0
SUITE_RESULTS=()
SUITE_TABLE=()
SUITE_FAILURE_SNIPPETS=()

run_suite() {
  local suite_id="$1"
  local label="$2"
  local script="$3"
  shift 3
  local start_ts end_ts duration rc status
  local suite_dir report_path log_path tests pass fail skip

  start_ts="$(date +%s)"
  SUITES_RUN=$((SUITES_RUN + 1))
  hr
  echo "[SUITE] $label"
  echo "[START] $(date -Is) :: $script"

  if "$script" "$@"; then
    rc=0
    status="PASS"
    SUITES_PASS=$((SUITES_PASS + 1))
    SUITE_RESULTS+=("[PASS] $label")
    echo "[DONE]  $(date -Is) :: $label (pass)"
  else
    rc=$?
    status="FAIL"
    SUITES_FAIL=$((SUITES_FAIL + 1))
    SUITE_RESULTS+=("[FAIL] $label (rc=$rc)")
    echo "[DONE]  $(date -Is) :: $label (fail rc=$rc)"
  fi

  end_ts="$(date +%s)"
  duration=$((end_ts - start_ts))
  suite_dir="$OUTROOT/$RUN_ID/$suite_id"
  report_path="$suite_dir/report.md"
  log_path="$suite_dir/run.log"
  tests="$(read_report_metric "$report_path" "Tests")"
  pass="$(read_report_metric "$report_path" "Passed")"
  fail="$(read_report_metric "$report_path" "Failed")"
  skip="$(read_report_metric "$report_path" "Skipped")"
  SUITE_TABLE+=("${label}|${status}|${rc}|$(format_duration "$duration")|${tests}|${pass}|${fail}|${skip}|${report_path}|${log_path}")

  if [[ "$status" == "FAIL" && -f "$log_path" ]]; then
    local snippet
    snippet="$(grep -F "[FAIL]" "$log_path" | head -n 3 | sed -E 's/^[^[]*\[FAIL\] /[FAIL] /' || true)"
    SUITE_FAILURE_SNIPPETS+=("${label}|${snippet}")
  fi
}

echo "Rustyjack test run starting"
echo "Run ID: $RUN_ID"
echo "Results root: $OUTROOT/$RUN_ID"
echo "Common args: ${COMMON_ARGS[*]:-(none)}"
echo "Wireless args: ${WIRELESS_ARGS[*]:-(auto)}"
echo "Ethernet args: ${ETHERNET_ARGS[*]:-(auto)}"

if [[ $RUN_WIRELESS -eq 1 ]]; then
  run_suite "wireless" "Wireless" "$ROOT_DIR/rj_test_wireless.sh" "${COMMON_ARGS[@]}" "${WIRELESS_ARGS[@]}" "${WIRELESS_EXTRA_ARGS[@]}"
fi
if [[ $RUN_ETHERNET -eq 1 ]]; then
  run_suite "ethernet" "Ethernet" "$ROOT_DIR/rj_test_ethernet.sh" "${COMMON_ARGS[@]}" "${ETHERNET_ARGS[@]}" "${ETHERNET_EXTRA_ARGS[@]}"
fi
if [[ $RUN_ENCRYPTION -eq 1 ]]; then
  run_suite "encryption" "Encryption" "$ROOT_DIR/rj_test_encryption.sh" "${COMMON_ARGS[@]}" "${ENCRYPTION_EXTRA_ARGS[@]}"
fi
if [[ $RUN_LOOT -eq 1 ]]; then
  run_suite "loot" "Loot" "$ROOT_DIR/rj_test_loot.sh" "${COMMON_ARGS[@]}" "${LOOT_EXTRA_ARGS[@]}"
fi
if [[ $RUN_MAC -eq 1 ]]; then
  run_suite "mac_randomization" "MAC Randomization" "$ROOT_DIR/rj_test_mac_randomization.sh" "${COMMON_ARGS[@]}" "${MAC_EXTRA_ARGS[@]}"
fi
if [[ $RUN_DAEMON -eq 1 ]]; then
  run_suite "daemon" "Daemon/IPC" "$ROOT_DIR/rj_test_daemon.sh" "${COMMON_ARGS[@]}" "${DAEMON_EXTRA_ARGS[@]}"
fi
if [[ $RUN_DAEMON_DEEP -eq 1 ]]; then
  run_suite "daemon_deep" "Daemon Deep Diagnostics" "$ROOT_DIR/rustyjack_comprehensive_test.sh" --outroot "$OUTROOT/$RUN_ID/deep_daemon" "${DAEMON_DEEP_EXTRA_ARGS[@]}"
fi
if [[ $RUN_INSTALLERS -eq 1 ]]; then
  run_suite "installers" "Installers" "$ROOT_DIR/rj_test_installers.sh" "${COMMON_ARGS[@]}" "${INSTALLERS_EXTRA_ARGS[@]}"
fi
if [[ $RUN_USB -eq 1 ]]; then
  run_suite "usb_mount" "USB Mount" "$ROOT_DIR/rj_test_usb.sh" "${COMMON_ARGS[@]}" "${USB_EXTRA_ARGS[@]}"
fi
if [[ $RUN_UI_LAYOUT -eq 1 ]]; then
  run_suite "ui_layout" "UI Layout/Display" "$ROOT_DIR/rj_test_ui_layout.sh" "${COMMON_ARGS[@]}" "${UI_LAYOUT_EXTRA_ARGS[@]}"
fi
if [[ $RUN_THEME -eq 1 ]]; then
  run_suite "theme" "Theme/Palette" "$ROOT_DIR/rj_test_theme.sh" "${COMMON_ARGS[@]}" "${THEME_EXTRA_ARGS[@]}"
fi

hr
echo "Suite summary:"
for result in "${SUITE_RESULTS[@]}"; do
  echo "  $result"
done
echo
echo "Detailed summary:"
printf '%-24s %-6s %-3s %-8s %-5s %-5s %-5s %-5s\n' "Suite" "Status" "RC" "Duration" "Tests" "Pass" "Fail" "Skip"
printf '%-24s %-6s %-3s %-8s %-5s %-5s %-5s %-5s\n' "-----" "------" "--" "--------" "-----" "----" "----" "----"
for row in "${SUITE_TABLE[@]}"; do
  IFS='|' read -r label status rc duration tests pass fail skip report_path log_path <<<"$row"
  printf '%-24s %-6s %-3s %-8s %-5s %-5s %-5s %-5s\n' "$label" "$status" "$rc" "$duration" "$tests" "$pass" "$fail" "$skip"
done

if [[ "${#SUITE_FAILURE_SNIPPETS[@]}" -gt 0 ]]; then
  echo
  echo "Top failure snippets:"
  for item in "${SUITE_FAILURE_SNIPPETS[@]}"; do
    IFS='|' read -r label snippet <<<"$item"
    echo "  [$label]"
    if [[ -n "${snippet:-}" ]]; then
      while IFS= read -r line; do
        [[ -n "$line" ]] && echo "    $line"
      done <<<"$snippet"
    else
      echo "    (No [FAIL] lines captured; check suite log.)"
    fi
  done
fi

echo
echo "Artifacts:"
for row in "${SUITE_TABLE[@]}"; do
  IFS='|' read -r label status rc duration tests pass fail skip report_path log_path <<<"$row"
  echo "  - $label report: $report_path"
  echo "    $label log:    $log_path"
done

echo "Suites run: $SUITES_RUN"
echo "Suites passed: $SUITES_PASS"
echo "Suites failed: $SUITES_FAIL"
echo "Results root: $OUTROOT/$RUN_ID"

if [[ $SUITES_FAIL -gt 0 ]]; then
  exit 1
fi
