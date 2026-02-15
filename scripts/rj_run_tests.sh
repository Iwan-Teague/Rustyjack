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
RUN_EVASION=0
RUN_ANTI_FORENSICS=0
RUN_PHYSICAL_ACCESS=0
RUN_HOTSPOT=0
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

DISCORD_WEBHOOK_ENABLED="${RJ_DISCORD_WEBHOOK_ENABLED:-1}"
DISCORD_RUNTIME_ROOT="${RJ_RUNTIME_ROOT:-/var/lib/rustyjack}"
DISCORD_WEBHOOK_PATH_DEFAULT="${DISCORD_RUNTIME_ROOT%/}/discord_webhook.txt"
DISCORD_DEFAULTS_DIR="$ROOT_DIR/defaults"
DISCORD_REPO_DEFAULT_WEBHOOK_FILE="${DISCORD_DEFAULTS_DIR%/}/discord_webhook.txt"
DISCORD_WEBHOOK_URL_DEFAULT=""
DISCORD_WEBHOOK_URL="${RJ_DISCORD_WEBHOOK_URL:-$DISCORD_WEBHOOK_URL_DEFAULT}"
DISCORD_WEBHOOK_USERNAME="${RJ_DISCORD_WEBHOOK_USERNAME:-RustyJack}"
DISCORD_WEBHOOK_AVATAR_URL="${RJ_DISCORD_WEBHOOK_AVATAR_URL:-}"
DISCORD_WEBHOOK_ATTACH_SUMMARY="${RJ_DISCORD_WEBHOOK_ATTACH_SUMMARY:-1}"
DISCORD_WEBHOOK_MENTION="${RJ_DISCORD_WEBHOOK_MENTION:-}"
DISCORD_MAX_CONTENT_LEN=2000
DISCORD_MAX_RETRIES=5
DISCORD_BUNDLE_MAX_BYTES=$((8 * 1024 * 1024))

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

Suite selection:
  --all           Run all core test suites
  --wireless      Run wireless tests
  --ethernet      Run ethernet tests
  --iface-select  Run interface selection/set-active tests
  --encryption    Run encryption tests
  --loot          Run loot tests
  --mac           Run MAC randomization tests
  --evasion       Run evasion tests (MAC, hostname, TX power)
  --anti-forensics Run anti-forensics tests (secure delete, log purge)
  --physical-access Run physical access tests (router credentials)
  --hotspot       Run hotspot/AP tests
  --daemon        Run daemon/IPC security tests
  --daemon-deep   Run deep daemon comprehensive diagnostics (longer)
  --discord-test  Run Discord webhook connectivity preflight (UI-only)
  --installers    Run installer script tests
  --usb           Run USB mount detect/read/write tests
  --ui-layout     Run dynamic UI layout/resolution tests
  --theme         Run UI theme/palette stabilization tests

Test options:
  --dangerous     Enable dangerous tests (passed to suites)

Discord options:
  --discord-enable        Enable Discord webhook notification (default: enabled)
  --discord-disable       Disable Discord webhook notification
  --discord-webhook URL   Override Discord webhook URL for this run
  --discord-username STR  Override Discord username for this run
  --discord-mention STR   Prefix Discord message with mention text (e.g. <@123>)
  --discord-no-attach     Do not attach consolidated summary markdown to Discord

Interface targeting:
  --wifi-interface IFACE   Run wireless suite on a single Wi-Fi interface
  --wifi-interfaces LIST   Comma-separated Wi-Fi interfaces for wireless suite
  --wifi-all-interfaces    Auto-detect all Wi-Fi interfaces for wireless suite
  --eth-interface IFACE    Run ethernet suite on a single ethernet interface
  --eth-interfaces LIST    Comma-separated ethernet interfaces for ethernet suite
  --eth-all-interfaces     Auto-detect all ethernet interfaces for ethernet suite

Other:
  --runtime-root DIR  Runtime root used to discover UI webhook (default: /var/lib/rustyjack)
  --outroot DIR       Output root (default: /var/tmp/rustyjack-tests)
  -h, --help          Show help

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

normalize_discord_webhook_url() {
  local raw="$1"
  raw="$(trim_whitespace "$raw")"
  raw="${raw/https:\/\/discordapp.com\/api\/webhooks\//https:\/\/discord.com\/api\/webhooks\/}"
  printf '%s' "$raw"
}

discord_webhook_url_is_valid() {
  local candidate="$1"
  [[ "$candidate" == https://discord.com/api/webhooks/* ]]
}

stage_discord_webhook_file() {
  local url="$1"
  local webhook_file="${RJ_DISCORD_WEBHOOK_FILE:-$DISCORD_WEBHOOK_PATH_DEFAULT}"
  local webhook_dir
  local tmp_file

  if [[ -z "$url" ]] || ! discord_webhook_url_is_valid "$url"; then
    return 1
  fi

  webhook_dir="$(dirname "$webhook_file")"
  if ! mkdir -p "$webhook_dir" 2>/dev/null; then
    return 1
  fi
  chmod 700 "$webhook_dir" 2>/dev/null || true

  tmp_file="${webhook_file}.tmp.$$"
  if ! printf '%s\n' "$url" >"$tmp_file"; then
    rm -f "$tmp_file" 2>/dev/null || true
    return 1
  fi
  if ! chmod 600 "$tmp_file" 2>/dev/null; then
    rm -f "$tmp_file" 2>/dev/null || true
    return 1
  fi
  if ! mv -f "$tmp_file" "$webhook_file"; then
    rm -f "$tmp_file" 2>/dev/null || true
    return 1
  fi
  chmod 600 "$webhook_file" 2>/dev/null || true
  return 0
}

discover_discord_webhook_url() {
  if [[ "$DISCORD_WEBHOOK_ENABLED" != "1" ]]; then
    return 0
  fi

  DISCORD_WEBHOOK_URL="$(normalize_discord_webhook_url "${DISCORD_WEBHOOK_URL:-}")"
  if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]] && discord_webhook_url_is_valid "$DISCORD_WEBHOOK_URL"; then
    stage_discord_webhook_file "$DISCORD_WEBHOOK_URL" || true
    return 0
  fi

  local webhook_file="${RJ_DISCORD_WEBHOOK_FILE:-$DISCORD_WEBHOOK_PATH_DEFAULT}"
  local candidate=""
  if [[ -f "$webhook_file" ]]; then
    candidate="$(sed -n '1p' "$webhook_file" 2>/dev/null | tr -d '\r' || true)"
    candidate="$(normalize_discord_webhook_url "$candidate")"
    if discord_webhook_url_is_valid "$candidate"; then
      DISCORD_WEBHOOK_URL="$candidate"
      stage_discord_webhook_file "$DISCORD_WEBHOOK_URL" || true
      return 0
    fi
  fi

  if [[ -f "$DISCORD_REPO_DEFAULT_WEBHOOK_FILE" ]]; then
    candidate="$(sed -n '1p' "$DISCORD_REPO_DEFAULT_WEBHOOK_FILE" 2>/dev/null | tr -d '\r' || true)"
    candidate="$(normalize_discord_webhook_url "$candidate")"
    if discord_webhook_url_is_valid "$candidate"; then
      DISCORD_WEBHOOK_URL="$candidate"
      stage_discord_webhook_file "$DISCORD_WEBHOOK_URL" || true
    fi
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

# Truncate content to Discord's 2000 character limit.
discord_truncate_content() {
  local s="$1"
  if [[ ${#s} -gt $DISCORD_MAX_CONTENT_LEN ]]; then
    s="${s:0:$((DISCORD_MAX_CONTENT_LEN - 15))}...[truncated]"
  fi
  printf '%s' "$s"
}

# Build a Discord payload_json string with content, username, and avatar.
discord_build_payload_json() {
  local content="$1"
  content="$(discord_truncate_content "$content")"
  local pj="{\"content\":\"$(json_escape "$content")\""
  if [[ -n "$DISCORD_WEBHOOK_USERNAME" ]]; then
    pj+=",\"username\":\"$(json_escape "$DISCORD_WEBHOOK_USERNAME")\""
  fi
  if [[ -n "$DISCORD_WEBHOOK_AVATAR_URL" ]]; then
    pj+=",\"avatar_url\":\"$(json_escape "$DISCORD_WEBHOOK_AVATAR_URL")\""
  fi
  pj+="}"
  printf '%s' "$pj"
}

# Curl wrapper with Discord 429 rate-limit retry handling.
# Usage: discord_curl_with_retry [curl args...]
# All args are passed directly to curl after the common flags.
# Returns 0 on success (HTTP 2xx), 1 on exhausted retries or error.
discord_curl_with_retry() {
  local max_retries="$DISCORD_MAX_RETRIES"
  local attempt=0
  local http_code
  local tmpfile
  tmpfile="$(mktemp "${TMPDIR:-/tmp}/rj_discord_XXXXXX")"

  while [[ $attempt -lt $max_retries ]]; do
    attempt=$((attempt + 1))
    # Add explicit timeouts: 10s connect, 120s max total (large uploads)
    http_code="$(curl -sS -o "$tmpfile" -w '%{http_code}' \
      --connect-timeout 10 --max-time 120 \
      -X POST "$DISCORD_WEBHOOK_URL" "$@" 2>/dev/null)" || http_code="000"

    if [[ "$http_code" == "429" ]]; then
      # Parse retry_after from JSON response body
      local retry_after=""
      retry_after="$(sed -n 's/.*"retry_after" *: *\([0-9.]*\).*/\1/p' "$tmpfile" 2>/dev/null | head -n1)" || true
      if [[ -z "$retry_after" || "$retry_after" == "0" ]]; then
        retry_after="5"
      fi
      # Convert float to integer ceiling and add jitter
      local wait_int
      wait_int="$(printf '%.0f' "$retry_after" 2>/dev/null || echo "${retry_after%%.*}")" || wait_int=5
      wait_int=$((wait_int + 1))
      echo "[WARN] Discord rate limited (429). Waiting ${wait_int}s before retry ${attempt}/${max_retries}."
      sleep "$wait_int"
      continue
    fi

    if [[ "$http_code" =~ ^2 ]]; then
      rm -f "$tmpfile" 2>/dev/null || true
      return 0
    fi

    echo "[WARN] Discord returned HTTP ${http_code} on attempt ${attempt}/${max_retries}."
    if [[ $attempt -lt $max_retries ]]; then
      sleep 2
    fi
  done

  echo "[WARN] Discord upload failed after ${max_retries} attempts (last HTTP ${http_code})."
  rm -f "$tmpfile" 2>/dev/null || true
  return 1
}

# Post a JSON-only payload to Discord (no file attachment).
post_discord_payload_json() {
  local payload_json="$1"
  discord_curl_with_retry \
    -H "Content-Type: application/json" \
    -d "$payload_json"
}

send_discord_text_message() {
  local content="$1"
  local include_mention="${2:-0}"

  if ! discord_can_send; then
    return 0
  fi

  if [[ "$include_mention" == "1" && -n "$DISCORD_WEBHOOK_MENTION" ]]; then
    content="${DISCORD_WEBHOOK_MENTION}"$'\n'"${content}"
  fi

  local payload_json
  payload_json="$(discord_build_payload_json "$content")"

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

  payload_json="$(discord_build_payload_json "$content")"

  if [[ "$DISCORD_WEBHOOK_ATTACH_SUMMARY" == "1" && -f "$MASTER_REPORT_PATH" ]]; then
    if ! discord_curl_with_retry \
      -F "payload_json=$payload_json" \
      -F "file1=@${MASTER_REPORT_PATH};filename=rustyjack_${RUN_ID}_summary.md"; then
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

# Upload individual critical files from suite to Discord (report, log, summary)
upload_suite_critical_files() {
  local suite_id="$1"
  local suite_label="$2"
  local suite_dir="$3"

  if ! discord_can_send; then
    return 0
  fi

  if [[ ! -d "$suite_dir" ]]; then
    echo "[WARN] Suite directory missing for critical file upload: $suite_dir"
    return 0
  fi

  local report="${suite_dir}/report.md"
  local log="${suite_dir}/run.log"
  local summary="${suite_dir}/summary.jsonl"
  local payload_json
  
  # Upload report.md (always present)
  if [[ -f "$report" ]]; then
    payload_json="$(discord_build_payload_json "Suite report: ${suite_label}")"
    if ! discord_curl_with_retry \
      -F "payload_json=$payload_json" \
      -F "file1=@${report};filename=${suite_id}_report.md"; then
      echo "[WARN] Failed to upload report for ${suite_label}"
    fi
  fi

  # Upload run.log (always present)
  if [[ -f "$log" ]]; then
    payload_json="$(discord_build_payload_json "Suite log: ${suite_label}")"
    if ! discord_curl_with_retry \
      -F "payload_json=$payload_json" \
      -F "file1=@${log};filename=${suite_id}_run.log"; then
      echo "[WARN] Failed to upload log for ${suite_label}"
    fi
  fi

  # Upload summary.jsonl if present
  if [[ -f "$summary" ]]; then
    payload_json="$(discord_build_payload_json "Suite summary: ${suite_label}")"
    if ! discord_curl_with_retry \
      -F "payload_json=$payload_json" \
      -F "file1=@${summary};filename=${suite_id}_summary.jsonl"; then
      echo "[WARN] Failed to upload summary for ${suite_label}"
    fi
  fi

  return 0
}

# Upload per-suite artifacts as a tar.gz bundle to Discord after each suite.
send_discord_suite_artifacts() {
  local suite_id="$1"
  local suite_label="$2"
  local status="$3"
  local rc="$4"
  local duration="$5"
  local suite_dir="$6"

  if ! discord_can_send; then
    return 0
  fi

  if [[ ! -d "$suite_dir" ]]; then
    echo "[WARN] Suite directory missing for artifact upload: $suite_dir"
    return 0
  fi

  local bundle="${suite_dir}/suite_${suite_id}_${RUN_ID}.tar.gz"
  local upload_file=""
  local upload_filename=""

  # Try to create a bundle of the suite directory
  # CRITICAL: Exclude FIFOs to prevent tar from blocking indefinitely
  if command -v tar >/dev/null 2>&1; then
    # Use timeout to prevent tar from hanging on FIFOs or other problematic files
    if timeout 30 tar -C "$suite_dir" -czf "$bundle" \
      --exclude='*.core' --exclude='*.tar.gz' --exclude='*.fifo' \
      --exclude='*ui_input.fifo' --exclude-fifo . 2>/dev/null; then
      local bundle_size=0
      bundle_size="$(stat -c%s "$bundle" 2>/dev/null || stat -f%z "$bundle" 2>/dev/null || echo 0)"
      if [[ "$bundle_size" -gt 0 && "$bundle_size" -le "$DISCORD_BUNDLE_MAX_BYTES" ]]; then
        upload_file="$bundle"
        upload_filename="suite_${suite_id}_${RUN_ID}.tar.gz"
      else
        echo "[WARN] Suite bundle too large (${bundle_size} bytes); skipping bundle upload."
        rm -f "$bundle" 2>/dev/null || true
      fi
    else
      echo "[WARN] Failed to create suite bundle (timeout or error); skipping bundle upload."
    fi
  fi

  # Upload bundle if available
  if [[ -n "$upload_file" && -f "$upload_file" ]]; then
    local content
    content="Suite full artifacts: ${suite_label} [${status}] (rc=${rc}, ${duration})"
    local payload_json
    payload_json="$(discord_build_payload_json "$content")"

    if ! discord_curl_with_retry \
      -F "payload_json=$payload_json" \
      -F "file1=@${upload_file};filename=${upload_filename}"; then
      echo "[WARN] Failed to upload suite bundle for ${suite_label} to Discord."
    fi
  fi

  return 0
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
}

# --- Interactive menu (ordered 1..13, 0=All last) ---

if [[ $# -eq 0 ]]; then
  echo "Select tests:"
  echo "  1) Wireless"
  echo "  2) Ethernet"
  echo "  3) Interface Selection"
  echo "  4) Encryption"
  echo "  5) Loot"
  echo "  6) MAC Randomization"
  echo "  7) Daemon/IPC"
  echo "  8) Daemon Deep Diagnostics"
  echo "  9) Installers"
  echo " 10) USB Mount"
  echo " 11) UI Layout/Display"
  echo " 12) Theme/Palette"
  echo " 13) Discord Webhook Preflight"
  echo "  0) All"
  read -r choice
  case "$choice" in
    0) RUN_WIRELESS=1; RUN_ETHERNET=1; RUN_IFACE_SELECT=1; RUN_ENCRYPTION=1; RUN_LOOT=1; RUN_MAC=1; RUN_DAEMON=1; RUN_INSTALLERS=1; RUN_USB=1; RUN_UI_LAYOUT=1; RUN_THEME=1 ;;
    1) RUN_WIRELESS=1 ;;
    2) RUN_ETHERNET=1 ;;
    3) RUN_IFACE_SELECT=1 ;;
    4) RUN_ENCRYPTION=1 ;;
    5) RUN_LOOT=1 ;;
    6) RUN_MAC=1 ;;
    7) RUN_DAEMON=1 ;;
    8) RUN_DAEMON_DEEP=1 ;;
    9) RUN_INSTALLERS=1 ;;
    10) RUN_USB=1 ;;
    11) RUN_UI_LAYOUT=1 ;;
    12) RUN_THEME=1 ;;
    13) RUN_DISCORD=1 ;;
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
      $RUN_EVASION -eq 1 || $RUN_ANTI_FORENSICS -eq 1 || $RUN_PHYSICAL_ACCESS -eq 1 || \
      $RUN_HOTSPOT -eq 1 || $RUN_DAEMON -eq 1 || $RUN_DAEMON_DEEP -eq 1 || \
      $RUN_INSTALLERS -eq 1 || $RUN_USB -eq 1 || $RUN_UI_LAYOUT -eq 1 || \
      $RUN_THEME -eq 1 ]]; then
  if [[ "$DISCORD_WEBHOOK_ENABLED" == "1" ]]; then
    RUN_DISCORD=1
  fi
fi

if [[ $RUN_WIRELESS -eq 0 && $RUN_ETHERNET -eq 0 && $RUN_IFACE_SELECT -eq 0 && \
      $RUN_ENCRYPTION -eq 0 && $RUN_LOOT -eq 0 && $RUN_MAC -eq 0 && \
      $RUN_EVASION -eq 0 && $RUN_ANTI_FORENSICS -eq 0 && $RUN_PHYSICAL_ACCESS -eq 0 && \
      $RUN_HOTSPOT -eq 0 && $RUN_DAEMON -eq 0 && $RUN_DAEMON_DEEP -eq 0 && \
      $RUN_INSTALLERS -eq 0 && $RUN_USB -eq 0 && $RUN_UI_LAYOUT -eq 0 && \
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
    send_discord_suite_artifacts "$suite_id" "$label" "$status" "$rc" "$(format_duration "$duration")" "$suite_dir"
    upload_suite_critical_files "$suite_id" "$label" "$suite_dir"
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
    --runtime-root "$DISCORD_RUNTIME_ROOT"

  if [[ "$LAST_SUITE_STATUS" != "PASS" ]]; then
    webhook_file="${RJ_DISCORD_WEBHOOK_FILE:-$DISCORD_WEBHOOK_PATH_DEFAULT}"
    if [[ -z "${DISCORD_WEBHOOK_URL:-}" && ! -s "$webhook_file" ]]; then
      echo "[WARN] Discord preflight failed and no endpoint is configured; disabling follow-up Discord notifications for this run."
      DISCORD_WEBHOOK_ENABLED=0
    else
      echo "[WARN] Discord preflight failed, but an endpoint appears configured; keeping follow-up Discord notifications enabled."
    fi
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
    ${WIRELESS_ARGS[@]+"${WIRELESS_ARGS[@]}"}
fi
if [[ $RUN_ETHERNET -eq 1 ]]; then
  run_suite "ethernet" "Ethernet" "$ROOT_DIR/rj_test_ethernet.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${ETHERNET_ARGS[@]+"${ETHERNET_ARGS[@]}"}
fi
if [[ $RUN_IFACE_SELECT -eq 1 ]]; then
  run_suite "interface_selection" "Interface Selection" "$ROOT_DIR/rj_test_interface_selection.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${IFACE_SELECT_ARGS[@]+"${IFACE_SELECT_ARGS[@]}"}
fi
if [[ $RUN_ENCRYPTION -eq 1 ]]; then
  run_suite "encryption" "Encryption" "$ROOT_DIR/rj_test_encryption.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"}
fi
if [[ $RUN_LOOT -eq 1 ]]; then
  run_suite "loot" "Loot" "$ROOT_DIR/rj_test_loot.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"}
fi
if [[ $RUN_MAC -eq 1 ]]; then
  run_suite "mac_randomization" "MAC Randomization" "$ROOT_DIR/rj_test_mac_randomization.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"}
fi
if [[ $RUN_EVASION -eq 1 ]]; then
  run_suite "evasion" "Evasion" "$ROOT_DIR/rj_test_evasion.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"}
fi
if [[ $RUN_ANTI_FORENSICS -eq 1 ]]; then
  run_suite "anti_forensics" "Anti-Forensics" "$ROOT_DIR/rj_test_anti_forensics.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"}
fi
if [[ $RUN_PHYSICAL_ACCESS -eq 1 ]]; then
  run_suite "physical_access" "Physical Access" "$ROOT_DIR/rj_test_physical_access.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"}
fi
if [[ $RUN_HOTSPOT -eq 1 ]]; then
  run_suite "hotspot" "Hotspot" "$ROOT_DIR/rj_test_hotspot.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"} \
    ${WIRELESS_ARGS[@]+"${WIRELESS_ARGS[@]}"}
fi
if [[ $RUN_DAEMON -eq 1 ]]; then
  run_suite "daemon" "Daemon/IPC" "$ROOT_DIR/rj_test_daemon.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"}
fi
if [[ $RUN_DAEMON_DEEP -eq 1 ]]; then
  run_suite "daemon_deep" "Daemon Deep Diagnostics" "$ROOT_DIR/rustyjack_comprehensive_test.sh" \
    --outroot "$OUTROOT/$RUN_ID/deep_daemon"
fi
if [[ $RUN_INSTALLERS -eq 1 ]]; then
  run_suite "installers" "Installers" "$ROOT_DIR/rj_test_installers.sh"
fi
if [[ $RUN_USB -eq 1 ]]; then
  run_suite "usb_mount" "USB Mount" "$ROOT_DIR/rj_test_usb.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"}
fi
if [[ $RUN_UI_LAYOUT -eq 1 ]]; then
  run_suite "ui_layout" "UI Layout/Display" "$ROOT_DIR/rj_test_ui_layout.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"} \
    ${DANGEROUS_ARGS[@]+"${DANGEROUS_ARGS[@]}"}
fi
if [[ $RUN_THEME -eq 1 ]]; then
  run_suite "theme" "Theme/Palette" "$ROOT_DIR/rj_test_theme.sh" \
    ${UI_ARGS[@]+"${UI_ARGS[@]}"}
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

# Send completion message before uploading artifacts
send_discord_text_message \
  "All test suites completed.
Run ID: ${RUN_ID}
Host: $(hostname 2>/dev/null || echo unknown)
Status: $([[ $SUITES_FAIL -eq 0 ]] && echo PASS || echo FAIL)
Uploading final summary..." \
  1

send_discord_summary

echo "[INFO] Test run complete. Exiting with code $([[ $SUITES_FAIL -gt 0 ]] && echo 1 || echo 0)"

if [[ $SUITES_FAIL -gt 0 ]]; then
  exit 1
fi
