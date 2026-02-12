#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_shellops.sh
source "$ROOT_DIR/rj_shellops.sh"

RUN_WIRELESS=0
RUN_ETHERNET=0
RUN_IFACE_SELECT=0
RUN_ENCRYPTION=0
RUN_LOOT=0
RUN_MAC=0
RUN_DAEMON=0
RUN_DAEMON_DEEP=0
RUN_INSTALLERS=0
RUN_USB=0
RUN_UI_LAYOUT=0
RUN_THEME=0
RUN_DISCORD=0
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
IFACE_SELECT_EXTRA_ARGS=()
ENCRYPTION_EXTRA_ARGS=()
LOOT_EXTRA_ARGS=()
MAC_EXTRA_ARGS=()
DAEMON_EXTRA_ARGS=()
INSTALLERS_EXTRA_ARGS=()
USB_EXTRA_ARGS=()
UI_LAYOUT_EXTRA_ARGS=()
THEME_EXTRA_ARGS=()
DAEMON_DEEP_EXTRA_ARGS=()
DISCORD_TEST_EXTRA_ARGS=()

DISCORD_WEBHOOK_ENABLED="${RJ_DISCORD_WEBHOOK_ENABLED:-1}"
DISCORD_RUNTIME_ROOT="${RJ_RUNTIME_ROOT:-/var/lib/rustyjack}"
DISCORD_WEBHOOK_PATH_DEFAULT="${DISCORD_RUNTIME_ROOT%/}/discord_webhook.txt"
DISCORD_WEBHOOK_URL_DEFAULT=""
DISCORD_WEBHOOK_URL="${RJ_DISCORD_WEBHOOK_URL:-$DISCORD_WEBHOOK_URL_DEFAULT}"
DISCORD_WEBHOOK_USERNAME="${RJ_DISCORD_WEBHOOK_USERNAME:-RustyJack}"
DISCORD_WEBHOOK_AVATAR_URL="${RJ_DISCORD_WEBHOOK_AVATAR_URL:-}"
DISCORD_WEBHOOK_ATTACH_SUMMARY="${RJ_DISCORD_WEBHOOK_ATTACH_SUMMARY:-1}"
DISCORD_WEBHOOK_MENTION="${RJ_DISCORD_WEBHOOK_MENTION:-}"

MASTER_REPORT_PATH=""
MASTER_JSON_PATH=""
TOTAL_TESTS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

chmod +x "$ROOT_DIR"/rj_test_*.sh "$ROOT_DIR"/rustyjack_comprehensive_test.sh 2>/dev/null || true

usage() {
  cat <<'USAGE'
Usage: rj_run_tests.sh [options]

Options:
  --all         Run all test suites
  --wireless    Run wireless tests
  --ethernet    Run ethernet tests
  --iface-select Run interface selection/set-active tests
  --encryption  Run encryption tests
  --loot        Run loot tests
  --mac         Run MAC randomization tests
  --daemon      Run daemon/IPC security tests
  --daemon-deep Run deep daemon comprehensive diagnostics (longer)
  --discord-test Run Discord webhook connectivity preflight (UI-only)
  --installers  Run installer script tests
  --usb         Run USB mount detect/read/write tests
  --ui-layout   Run dynamic UI layout/resolution tests
  --theme       Run UI theme/palette stabilization tests
  --dangerous   Enable dangerous tests (passed to suites)
  --discord-enable        Enable Discord webhook notification (default: enabled)
  --discord-disable       Disable Discord webhook notification
  --discord-webhook URL   Override Discord webhook URL for this run
  --discord-username STR  Override Discord username for this run
  --discord-mention STR   Prefix Discord message with mention text (e.g. <@123>)
  --discord-no-attach     Do not attach consolidated summary markdown to Discord
  --wifi-interface IFACE   Run wireless suite on a single Wi-Fi interface
  --wifi-interfaces LIST   Comma-separated Wi-Fi interfaces for wireless suite
  --wifi-all-interfaces    Auto-detect all Wi-Fi interfaces for wireless suite
  --eth-interface IFACE    Run ethernet suite on a single ethernet interface
  --eth-interfaces LIST    Comma-separated ethernet interfaces for ethernet suite
  --eth-all-interfaces     Auto-detect all ethernet interfaces for ethernet suite
  --wireless-arg ARG       Append raw argument to rj_test_wireless.sh (repeatable)
  --ethernet-arg ARG       Append raw argument to rj_test_ethernet.sh (repeatable)
  --iface-select-arg ARG   Append raw argument to rj_test_interface_selection.sh (repeatable)
  --encryption-arg ARG     Append raw argument to rj_test_encryption.sh (repeatable)
  --loot-arg ARG           Append raw argument to rj_test_loot.sh (repeatable)
  --mac-arg ARG            Append raw argument to rj_test_mac_randomization.sh (repeatable)
  --daemon-arg ARG         Append raw argument to rj_test_daemon.sh (repeatable)
  --daemon-deep-arg ARG    Append raw argument to rustyjack_comprehensive_test.sh (repeatable)
  --discord-test-arg ARG   Append raw argument to rj_test_discord.sh (repeatable)
  --installers-arg ARG     Append raw argument to rj_test_installers.sh (repeatable)
  --usb-arg ARG            Append raw argument to rj_test_usb.sh (repeatable)
  --ui-layout-arg ARG      Append raw argument to rj_test_ui_layout.sh (repeatable)
  --theme-arg ARG          Append raw argument to rj_test_theme.sh (repeatable)
  --runtime-root DIR       Runtime root used to discover UI webhook (default: /var/lib/rustyjack)
  --outroot DIR Output root (default: /var/tmp/rustyjack-tests)
  -h, --help    Show help

If no options are provided, a menu will be shown.
UI automation is always enabled by policy.
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

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

trim_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

discover_discord_webhook_url() {
  if [[ "$DISCORD_WEBHOOK_ENABLED" != "1" ]]; then
    return 0
  fi
  if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
    return 0
  fi

  local webhook_file="${RJ_DISCORD_WEBHOOK_FILE:-$DISCORD_WEBHOOK_PATH_DEFAULT}"
  if [[ ! -f "$webhook_file" ]]; then
    return 0
  fi

  local candidate
  candidate="$(sed -n '1p' "$webhook_file" 2>/dev/null | tr -d '\r' || true)"
  candidate="$(trim_whitespace "$candidate")"
  if [[ "$candidate" == https://discord.com/api/webhooks/* ]]; then
    DISCORD_WEBHOOK_URL="$candidate"
  fi
}

discord_can_send() {
  if [[ "$DISCORD_WEBHOOK_ENABLED" != "1" ]]; then
    return 1
  fi
  if [[ -z "${DISCORD_WEBHOOK_URL:-}" ]]; then
    return 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

post_discord_payload_json() {
  local payload_json="$1"
  if ! curl -sS -X POST "$DISCORD_WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d "$payload_json" \
    >/dev/null; then
    return 1
  fi
  return 0
}

send_discord_text_message() {
  local content="$1"
  local include_mention="${2:-0}"
  local payload_json

  if ! discord_can_send; then
    return 0
  fi

  if [[ "$include_mention" == "1" && -n "$DISCORD_WEBHOOK_MENTION" ]]; then
    content="${DISCORD_WEBHOOK_MENTION}"$'\n'"${content}"
  fi

  payload_json="{\"content\":\"$(json_escape "$content")\""
  if [[ -n "$DISCORD_WEBHOOK_USERNAME" ]]; then
    payload_json+=",\"username\":\"$(json_escape "$DISCORD_WEBHOOK_USERNAME")\""
  fi
  if [[ -n "$DISCORD_WEBHOOK_AVATAR_URL" ]]; then
    payload_json+=",\"avatar_url\":\"$(json_escape "$DISCORD_WEBHOOK_AVATAR_URL")\""
  fi
  payload_json+="}"

  if ! post_discord_payload_json "$payload_json"; then
    echo "[WARN] Failed to send Discord webhook."
  fi
  return 0
}

calculate_totals() {
  TOTAL_TESTS=0
  TOTAL_PASS=0
  TOTAL_FAIL=0
  TOTAL_SKIP=0

  local tests pass fail skip
  for row in "${SUITE_TABLE[@]}"; do
    IFS='|' read -r _ _ _ _ tests pass fail skip _ _ <<<"$row"
    if is_uint "$tests"; then
      TOTAL_TESTS=$((TOTAL_TESTS + tests))
    fi
    if is_uint "$pass"; then
      TOTAL_PASS=$((TOTAL_PASS + pass))
    fi
    if is_uint "$fail"; then
      TOTAL_FAIL=$((TOTAL_FAIL + fail))
    fi
    if is_uint "$skip"; then
      TOTAL_SKIP=$((TOTAL_SKIP + skip))
    fi
  done
}

write_master_summary() {
  local run_dir="$OUTROOT/$RUN_ID"
  mkdir -p "$run_dir"
  MASTER_REPORT_PATH="$run_dir/run_summary.md"
  MASTER_JSON_PATH="$run_dir/run_summary.json"

  {
    echo "# Rustyjack Test Run Summary"
    echo
    echo "- Run ID: $RUN_ID"
    echo "- Host: $(hostname 2>/dev/null || echo unknown)"
    echo "- Results Root: $run_dir"
    echo "- Suites Run: $SUITES_RUN"
    echo "- Suites Passed: $SUITES_PASS"
    echo "- Suites Failed: $SUITES_FAIL"
    echo "- Tests Total: $TOTAL_TESTS"
    echo "- Tests Passed: $TOTAL_PASS"
    echo "- Tests Failed: $TOTAL_FAIL"
    echo "- Tests Skipped: $TOTAL_SKIP"
    echo
    echo "## Suite Breakdown"
    echo
    echo "| Suite | Status | RC | Duration | Tests | Pass | Fail | Skip |"
    echo "|---|---|---:|---:|---:|---:|---:|---:|"
    for row in "${SUITE_TABLE[@]}"; do
      IFS='|' read -r label status rc duration tests pass fail skip _ _ <<<"$row"
      echo "| $label | $status | $rc | $duration | $tests | $pass | $fail | $skip |"
    done

    if [[ "${#SUITE_FAILURE_SNIPPETS[@]}" -gt 0 ]]; then
      echo
      echo "## Failure Snippets"
      echo
      for item in "${SUITE_FAILURE_SNIPPETS[@]}"; do
        IFS='|' read -r label snippet <<<"$item"
        echo "### $label"
        if [[ -n "${snippet:-}" ]]; then
          while IFS= read -r line; do
            [[ -n "$line" ]] && echo "- $line"
          done <<<"$snippet"
        else
          echo "- No [FAIL] lines captured. Check suite log."
        fi
        echo
      done
    fi
  } >"$MASTER_REPORT_PATH"

  {
    echo "{"
    echo "  \"run_id\": \"$(json_escape "$RUN_ID")\","
    echo "  \"results_root\": \"$(json_escape "$run_dir")\","
    echo "  \"suites\": {"
    echo "    \"run\": $SUITES_RUN,"
    echo "    \"passed\": $SUITES_PASS,"
    echo "    \"failed\": $SUITES_FAIL"
    echo "  },"
    echo "  \"tests\": {"
    echo "    \"total\": $TOTAL_TESTS,"
    echo "    \"passed\": $TOTAL_PASS,"
    echo "    \"failed\": $TOTAL_FAIL,"
    echo "    \"skipped\": $TOTAL_SKIP"
    echo "  }"
    echo "}"
  } >"$MASTER_JSON_PATH"
}

send_discord_summary() {
  if [[ "$DISCORD_WEBHOOK_ENABLED" != "1" ]]; then
    echo "[INFO] Discord webhook notifications disabled."
    return 0
  fi
  if ! discord_can_send; then
    echo "[WARN] Discord webhook not configured or curl missing; skipping notification."
    return 0
  fi

  local run_dir status_word payload_json content host
  run_dir="$OUTROOT/$RUN_ID"
  status_word="PASS"
  if [[ $SUITES_FAIL -gt 0 ]]; then
    status_word="FAIL"
  fi
  host="$(hostname 2>/dev/null || echo unknown)"

  content=""
  if [[ -n "$DISCORD_WEBHOOK_MENTION" ]]; then
    content+="${DISCORD_WEBHOOK_MENTION}"$'\n'
  fi
  content+="Timestamp: $(date -Is)"$'\n'
  content+="Rustyjack test run: ${status_word}"$'\n'
  content+="Host: ${host}"$'\n'
  content+="Run ID: ${RUN_ID}"$'\n'
  content+="Suites: run=${SUITES_RUN}, pass=${SUITES_PASS}, fail=${SUITES_FAIL}"$'\n'
  content+="Tests: total=${TOTAL_TESTS}, pass=${TOTAL_PASS}, fail=${TOTAL_FAIL}, skip=${TOTAL_SKIP}"$'\n'
  content+="Results root: ${run_dir}"$'\n'
  content+="Summary: ${MASTER_REPORT_PATH}"

  payload_json="{\"content\":\"$(json_escape "$content")\""
  if [[ -n "$DISCORD_WEBHOOK_USERNAME" ]]; then
    payload_json+=",\"username\":\"$(json_escape "$DISCORD_WEBHOOK_USERNAME")\""
  fi
  if [[ -n "$DISCORD_WEBHOOK_AVATAR_URL" ]]; then
    payload_json+=",\"avatar_url\":\"$(json_escape "$DISCORD_WEBHOOK_AVATAR_URL")\""
  fi
  payload_json+="}"

  if [[ "$DISCORD_WEBHOOK_ATTACH_SUMMARY" == "1" && -f "$MASTER_REPORT_PATH" ]]; then
    if ! curl -sS -X POST "$DISCORD_WEBHOOK_URL" \
      -F "payload_json=$payload_json" \
      -F "file1=@${MASTER_REPORT_PATH};filename=rustyjack_${RUN_ID}_summary.md" \
      >/dev/null; then
      echo "[WARN] Failed to send Discord webhook with attachment."
      return 0
    fi
  else
    if ! post_discord_payload_json "$payload_json"; then
      echo "[WARN] Failed to send Discord webhook."
      return 0
    fi
  fi

  echo "[INFO] Discord notification sent."
  return 0
}

send_discord_suite_update() {
  local label="$1"
  local status="$2"
  local rc="$3"
  local duration="$4"
  local tests="$5"
  local pass="$6"
  local fail="$7"
  local skip="$8"
  local report_path="$9"
  local host

  host="$(hostname 2>/dev/null || echo unknown)"
  send_discord_text_message \
    "Timestamp: $(date -Is)
Suite: ${label}
Status: ${status} (rc=${rc}, duration=${duration})
Tests: total=${tests}, pass=${pass}, fail=${fail}, skip=${skip}
Host: ${host}
Run ID: ${RUN_ID}
Report: ${report_path}" \
    0
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

  if [[ $RUN_IFACE_SELECT -eq 1 ]]; then
    echo
    echo "Advanced: Interface Selection"
    add_skip_flag IFACE_SELECT_EXTRA_ARGS "interface selection negative tests" "--no-negative"
    add_skip_flag IFACE_SELECT_EXTRA_ARGS "interface selection compatibility checks" "--no-compat"
    add_skip_flag IFACE_SELECT_EXTRA_ARGS "interface selection isolation snapshots" "--no-isolation"
    if prompt_yes_no "Allow remote interface switching (may drop SSH)?" "N"; then
      IFACE_SELECT_EXTRA_ARGS+=(--allow-remote-switch)
    fi
    read -r -p "Recovery interface override (blank for auto): " val
    if [[ -n "${val// }" ]]; then
      IFACE_SELECT_EXTRA_ARGS+=(--recovery-interface "${val// /}")
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

  if [[ $RUN_DISCORD -eq 1 ]]; then
    echo
    echo "Advanced: Discord Webhook Preflight"
    read -r -p "Discord runtime root (blank for default: $DISCORD_RUNTIME_ROOT): " val
    if [[ -n "${val// }" ]]; then
      DISCORD_RUNTIME_ROOT="${val%/}"
      DISCORD_WEBHOOK_PATH_DEFAULT="${DISCORD_RUNTIME_ROOT%/}/discord_webhook.txt"
    fi
    read -r -p "Discord webhook file override (blank for default: $DISCORD_WEBHOOK_PATH_DEFAULT): " val
    if [[ -n "${val// }" ]]; then
      DISCORD_TEST_EXTRA_ARGS+=(--webhook-file "$val")
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
  RUN_UI=1
  echo "UI automation is enforced for all suites."
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
  echo " 12) Interface Selection"
  echo " 13) Discord Webhook Preflight"
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
    0) RUN_WIRELESS=1; RUN_ETHERNET=1; RUN_IFACE_SELECT=1; RUN_ENCRYPTION=1; RUN_LOOT=1; RUN_MAC=1; RUN_DAEMON=1; RUN_INSTALLERS=1; RUN_USB=1; RUN_UI_LAYOUT=1; RUN_THEME=1 ;;
    1) RUN_WIRELESS=1 ;;
    2) RUN_ETHERNET=1 ;;
    12) RUN_IFACE_SELECT=1 ;;
    13) RUN_DISCORD=1 ;;
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
      --all) RUN_WIRELESS=1; RUN_ETHERNET=1; RUN_IFACE_SELECT=1; RUN_ENCRYPTION=1; RUN_LOOT=1; RUN_MAC=1; RUN_DAEMON=1; RUN_INSTALLERS=1; RUN_USB=1; RUN_UI_LAYOUT=1; RUN_THEME=1; shift ;;
      --wireless) RUN_WIRELESS=1; shift ;;
      --ethernet) RUN_ETHERNET=1; shift ;;
      --iface-select) RUN_IFACE_SELECT=1; shift ;;
      --discord-test) RUN_DISCORD=1; shift ;;
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
      --discord-enable) DISCORD_WEBHOOK_ENABLED=1; shift ;;
      --discord-disable) DISCORD_WEBHOOK_ENABLED=0; shift ;;
      --discord-webhook) DISCORD_WEBHOOK_URL="$2"; DISCORD_WEBHOOK_ENABLED=1; shift 2 ;;
      --discord-username) DISCORD_WEBHOOK_USERNAME="$2"; shift 2 ;;
      --discord-mention) DISCORD_WEBHOOK_MENTION="$2"; shift 2 ;;
      --discord-no-attach) DISCORD_WEBHOOK_ATTACH_SUMMARY=0; shift ;;
      --no-ui)
        echo "Error: --no-ui is disabled; UI automation is mandatory." >&2
        exit 2
        ;;
      --wifi-interface) WIFI_IFACE="$2"; WIFI_ALL_IFACES=0; shift 2 ;;
      --wifi-interfaces) WIFI_IFACES="$2"; WIFI_ALL_IFACES=0; shift 2 ;;
      --wifi-all-interfaces) WIFI_ALL_IFACES=1; shift ;;
      --eth-interface) ETH_IFACE="$2"; ETH_ALL_IFACES=0; shift 2 ;;
      --eth-interfaces) ETH_IFACES="$2"; ETH_ALL_IFACES=0; shift 2 ;;
      --eth-all-interfaces) ETH_ALL_IFACES=1; shift ;;
      --wireless-arg) WIRELESS_EXTRA_ARGS+=("$2"); shift 2 ;;
      --ethernet-arg) ETHERNET_EXTRA_ARGS+=("$2"); shift 2 ;;
      --iface-select-arg) IFACE_SELECT_EXTRA_ARGS+=("$2"); shift 2 ;;
      --encryption-arg) ENCRYPTION_EXTRA_ARGS+=("$2"); shift 2 ;;
      --loot-arg) LOOT_EXTRA_ARGS+=("$2"); shift 2 ;;
      --mac-arg) MAC_EXTRA_ARGS+=("$2"); shift 2 ;;
      --daemon-arg) DAEMON_EXTRA_ARGS+=("$2"); shift 2 ;;
      --daemon-deep-arg) DAEMON_DEEP_EXTRA_ARGS+=("$2"); shift 2 ;;
      --discord-test-arg) DISCORD_TEST_EXTRA_ARGS+=("$2"); shift 2 ;;
      --installers-arg) INSTALLERS_EXTRA_ARGS+=("$2"); shift 2 ;;
      --usb-arg) USB_EXTRA_ARGS+=("$2"); shift 2 ;;
      --ui-layout-arg) UI_LAYOUT_EXTRA_ARGS+=("$2"); shift 2 ;;
      --theme-arg) THEME_EXTRA_ARGS+=("$2"); shift 2 ;;
      --runtime-root) DISCORD_RUNTIME_ROOT="${2%/}"; DISCORD_WEBHOOK_PATH_DEFAULT="${DISCORD_RUNTIME_ROOT%/}/discord_webhook.txt"; shift 2 ;;
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

UI_ARGS=(--ui)

DANGEROUS_ARGS=()
if [[ $DANGEROUS -eq 1 ]]; then
  DANGEROUS_ARGS+=(--dangerous)
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

IFACE_SELECT_ARGS=()
if [[ $WIFI_ALL_IFACES -eq 1 ]]; then
  IFACE_SELECT_ARGS+=(--wifi-all-interfaces)
elif [[ -n "$WIFI_IFACES" ]]; then
  IFACE_SELECT_ARGS+=(--wifi-interfaces "$WIFI_IFACES")
elif [[ -n "$WIFI_IFACE" ]]; then
  IFACE_SELECT_ARGS+=(--wifi-interface "$WIFI_IFACE")
fi

if [[ $ETH_ALL_IFACES -eq 1 ]]; then
  IFACE_SELECT_ARGS+=(--eth-all-interfaces)
elif [[ -n "$ETH_IFACES" ]]; then
  IFACE_SELECT_ARGS+=(--eth-interfaces "$ETH_IFACES")
elif [[ -n "$ETH_IFACE" ]]; then
  IFACE_SELECT_ARGS+=(--eth-interface "$ETH_IFACE")
fi

discover_discord_webhook_url

if [[ $RUN_WIRELESS -eq 1 || $RUN_ETHERNET -eq 1 || $RUN_IFACE_SELECT -eq 1 || \
      $RUN_ENCRYPTION -eq 1 || $RUN_LOOT -eq 1 || $RUN_MAC -eq 1 || \
      $RUN_DAEMON -eq 1 || $RUN_DAEMON_DEEP -eq 1 || $RUN_INSTALLERS -eq 1 || \
      $RUN_USB -eq 1 || $RUN_UI_LAYOUT -eq 1 || $RUN_THEME -eq 1 ]]; then
  if [[ "$DISCORD_WEBHOOK_ENABLED" == "1" ]]; then
    RUN_DISCORD=1
  fi
fi

if [[ $RUN_WIRELESS -eq 0 && $RUN_ETHERNET -eq 0 && $RUN_IFACE_SELECT -eq 0 && $RUN_ENCRYPTION -eq 0 && \
      $RUN_LOOT -eq 0 && $RUN_MAC -eq 0 && $RUN_DAEMON -eq 0 && \
      $RUN_DAEMON_DEEP -eq 0 && $RUN_INSTALLERS -eq 0 && $RUN_USB -eq 0 && $RUN_UI_LAYOUT -eq 0 && \
      $RUN_THEME -eq 0 && $RUN_DISCORD -eq 0 ]]; then
  echo "No test suites selected. Use --all or choose a suite."
  exit 2
fi

SUITES_RUN=0
SUITES_PASS=0
SUITES_FAIL=0
SUITE_RESULTS=()
SUITE_TABLE=()
SUITE_FAILURE_SNIPPETS=()
LAST_SUITE_ID=""
LAST_SUITE_STATUS=""
LAST_SUITE_RC=0

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
  LAST_SUITE_ID="$suite_id"
  LAST_SUITE_STATUS="$status"
  LAST_SUITE_RC="$rc"

  if [[ "$status" == "FAIL" && -f "$log_path" ]]; then
    local snippet
    snippet="$(grep -F "[FAIL]" "$log_path" | head -n 3 | sed -E 's/^[^[]*\[FAIL\] /[FAIL] /' || true)"
    SUITE_FAILURE_SNIPPETS+=("${label}|${snippet}")
  fi

  if [[ "$suite_id" != "discord_webhook" ]]; then
    send_discord_suite_update "$label" "$status" "$rc" "$(format_duration "$duration")" "$tests" "$pass" "$fail" "$skip" "$report_path"
  fi
}

echo "Rustyjack test run starting"
echo "Run ID: $RUN_ID"
echo "Results root: $OUTROOT/$RUN_ID"
echo "UI args: ${UI_ARGS[*]:-(none)}"
echo "Dangerous args: ${DANGEROUS_ARGS[*]:-(none)}"
echo "Wireless args: ${WIRELESS_ARGS[*]:-(auto)}"
echo "Ethernet args: ${ETHERNET_ARGS[*]:-(auto)}"
echo "Interface-select args: ${IFACE_SELECT_ARGS[*]:-(auto)}"
echo "Discord webhook: $([[ "$DISCORD_WEBHOOK_ENABLED" == "1" ]] && echo enabled || echo disabled)"
if [[ "$DISCORD_WEBHOOK_ENABLED" == "1" ]]; then
  echo "Discord runtime root: $DISCORD_RUNTIME_ROOT"
  if [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
    echo "Discord endpoint: configured"
  else
    echo "Discord endpoint: not configured (set RJ_DISCORD_WEBHOOK_URL or configure UI webhook)"
  fi
fi

if [[ $RUN_DISCORD -eq 1 ]]; then
  run_suite "discord_webhook" "Discord Webhook" "$ROOT_DIR/rj_test_discord.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    --runtime-root "$DISCORD_RUNTIME_ROOT" \
    ${DISCORD_TEST_EXTRA_ARGS[@]+"${DISCORD_TEST_EXTRA_ARGS[@]}"}

  if [[ "$LAST_SUITE_STATUS" != "PASS" ]]; then
    echo "[WARN] Discord preflight failed; disabling follow-up Discord notifications for this run."
    DISCORD_WEBHOOK_ENABLED=0
  else
    send_discord_text_message \
      "Timestamp: $(date -Is)
Rustyjack test run started after Discord preflight.
Host: $(hostname 2>/dev/null || echo unknown)
Run ID: ${RUN_ID}" \
      1
  fi
fi

if [[ $RUN_WIRELESS -eq 1 ]]; then
  run_suite "wireless" "Wireless" "$ROOT_DIR/rj_test_wireless.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${WIRELESS_ARGS[@]+"${WIRELESS_ARGS[@]}"} \
    ${WIRELESS_EXTRA_ARGS[@]+"${WIRELESS_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_ETHERNET -eq 1 ]]; then
  run_suite "ethernet" "Ethernet" "$ROOT_DIR/rj_test_ethernet.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${ETHERNET_ARGS[@]+"${ETHERNET_ARGS[@]}"} \
    ${ETHERNET_EXTRA_ARGS[@]+"${ETHERNET_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_IFACE_SELECT -eq 1 ]]; then
  run_suite "interface_selection" "Interface Selection" "$ROOT_DIR/rj_test_interface_selection.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${IFACE_SELECT_ARGS[@]+"${IFACE_SELECT_ARGS[@]}"} \
    ${IFACE_SELECT_EXTRA_ARGS[@]+"${IFACE_SELECT_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_ENCRYPTION -eq 1 ]]; then
  run_suite "encryption" "Encryption" "$ROOT_DIR/rj_test_encryption.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${ENCRYPTION_EXTRA_ARGS[@]+"${ENCRYPTION_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_LOOT -eq 1 ]]; then
  run_suite "loot" "Loot" "$ROOT_DIR/rj_test_loot.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${LOOT_EXTRA_ARGS[@]+"${LOOT_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_MAC -eq 1 ]]; then
  run_suite "mac_randomization" "MAC Randomization" "$ROOT_DIR/rj_test_mac_randomization.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${MAC_EXTRA_ARGS[@]+"${MAC_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_DAEMON -eq 1 ]]; then
  run_suite "daemon" "Daemon/IPC" "$ROOT_DIR/rj_test_daemon.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${DAEMON_EXTRA_ARGS[@]+"${DAEMON_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_DAEMON_DEEP -eq 1 ]]; then
  run_suite "daemon_deep" "Daemon Deep Diagnostics" "$ROOT_DIR/rustyjack_comprehensive_test.sh" \
    --outroot "$OUTROOT/$RUN_ID/deep_daemon" \
    ${DAEMON_DEEP_EXTRA_ARGS[@]+"${DAEMON_DEEP_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_INSTALLERS -eq 1 ]]; then
  run_suite "installers" "Installers" "$ROOT_DIR/rj_test_installers.sh" \
    ${INSTALLERS_EXTRA_ARGS[@]+"${INSTALLERS_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_USB -eq 1 ]]; then
  run_suite "usb_mount" "USB Mount" "$ROOT_DIR/rj_test_usb.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${USB_EXTRA_ARGS[@]+"${USB_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_UI_LAYOUT -eq 1 ]]; then
  run_suite "ui_layout" "UI Layout/Display" "$ROOT_DIR/rj_test_ui_layout.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${UI_LAYOUT_EXTRA_ARGS[@]+"${UI_LAYOUT_EXTRA_ARGS[@]}"}
fi
if [[ $RUN_THEME -eq 1 ]]; then
  run_suite "theme" "Theme/Palette" "$ROOT_DIR/rj_test_theme.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${THEME_EXTRA_ARGS[@]+"${THEME_EXTRA_ARGS[@]}"}
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

calculate_totals
write_master_summary

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
echo "Tests total: $TOTAL_TESTS"
echo "Tests passed: $TOTAL_PASS"
echo "Tests failed: $TOTAL_FAIL"
echo "Tests skipped: $TOTAL_SKIP"
echo "Results root: $OUTROOT/$RUN_ID"
echo "Consolidated summary: $MASTER_REPORT_PATH"
echo "Consolidated JSON: $MASTER_JSON_PATH"

send_discord_summary

if [[ $SUITES_FAIL -gt 0 ]]; then
  exit 1
fi
