#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0
WIFI_IFACE=""

usage() {
  cat <<'USAGE'
Usage: rj_test_hotspot.sh [options]

Tests hotspot/AP capabilities: start, stop, status, client tracking.

Options:
  --ui                    Require UI mode (default)
  --no-ui                 Disable UI mode
  --dangerous             Enable dangerous/disruptive tests (start/stop hotspot)
  --wifi-interface IFACE  Wi-Fi interface to use for hotspot
  --outroot DIR           Output root (default: /var/tmp/rustyjack-tests)
  -h, --help              Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ui) RUN_UI=1; shift ;;
    --no-ui) RUN_UI=0; shift ;;
    --dangerous) DANGEROUS=1; shift ;;
    --wifi-interface) WIFI_IFACE="$2"; shift 2 ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "hotspot"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

# Auto-detect Wi-Fi interface if not provided
if [[ -z "$WIFI_IFACE" ]]; then
  WIFI_IFACE="$(rj_detect_wifi_interface)"
  if [[ -z "$WIFI_IFACE" ]]; then
    rj_fail "wifi_interface_detection"
    rj_write_report
    exit 0
  fi
  rj_ok "wifi_interface_detection ($WIFI_IFACE)"
fi

# Test hotspot status query
rj_run_cmd_capture "hotspot_status" "$OUT/artifacts/hotspot_status.json" \
  rustyjack hotspot status --output json

HOTSPOT_STATUS="$(rj_json_get "$OUT/artifacts/hotspot_status.json" "status" || echo "")"
HOTSPOT_RUNNING="$(rj_json_get "$OUT/artifacts/hotspot_status.json" "data.running" || echo "false")"
if [[ "$HOTSPOT_STATUS" == "ok" ]]; then
  rj_ok "hotspot_status_query"
  rj_log "[INFO] Hotspot running: $HOTSPOT_RUNNING"
else
  rj_fail "hotspot_status_query"
fi

# Test hotspot configuration query
rj_run_cmd_capture "hotspot_config" "$OUT/artifacts/hotspot_config.json" \
  rustyjack hotspot config --output json

HOTSPOT_CONFIG_STATUS="$(rj_json_get "$OUT/artifacts/hotspot_config.json" "status" || echo "")"
if [[ "$HOTSPOT_CONFIG_STATUS" == "ok" ]]; then
  rj_ok "hotspot_config_query"
else
  rj_fail "hotspot_config_query"
fi

# Test device history query
rj_run_cmd_capture "hotspot_device_history" "$OUT/artifacts/hotspot_device_history.json" \
  rustyjack hotspot device-history --output json

HISTORY_STATUS="$(rj_json_get "$OUT/artifacts/hotspot_device_history.json" "status" || echo "")"
if [[ "$HISTORY_STATUS" == "ok" ]]; then
  rj_ok "hotspot_device_history_query"
else
  rj_fail "hotspot_device_history_query"
fi

if [[ $DANGEROUS -eq 1 ]]; then
  rj_log "[WARN] Running dangerous hotspot start test"
  
  # Stop hotspot if running
  if [[ "$HOTSPOT_RUNNING" == "true" ]]; then
    rj_log "[INFO] Stopping existing hotspot"
    rj_run_cmd_capture "hotspot_stop_pre" "$OUT/artifacts/hotspot_stop_pre.json" \
      rustyjack hotspot stop --output json
  fi
  
  # Start hotspot
  rj_run_cmd_capture "hotspot_start" "$OUT/artifacts/hotspot_start.json" \
    rustyjack hotspot start --interface "$WIFI_IFACE" --ssid "RustyJack-Test" --output json
  
  HOTSPOT_START_STATUS="$(rj_json_get "$OUT/artifacts/hotspot_start.json" "status" || echo "")"
  if [[ "$HOTSPOT_START_STATUS" == "ok" ]]; then
    rj_ok "hotspot_start_execution"
    
    # Query status to verify it's running
    sleep 2
    rj_run_cmd_capture "hotspot_status_after_start" "$OUT/artifacts/hotspot_status_after_start.json" \
      rustyjack hotspot status --output json
    
    HOTSPOT_RUNNING_AFTER="$(rj_json_get "$OUT/artifacts/hotspot_status_after_start.json" "data.running" || echo "false")"
    if [[ "$HOTSPOT_RUNNING_AFTER" == "true" ]]; then
      rj_ok "hotspot_running_verification"
    else
      rj_fail "hotspot_running_verification"
    fi
    
    # Stop hotspot
    rj_run_cmd_capture "hotspot_stop" "$OUT/artifacts/hotspot_stop.json" \
      rustyjack hotspot stop --output json
    
    HOTSPOT_STOP_STATUS="$(rj_json_get "$OUT/artifacts/hotspot_stop.json" "status" || echo "")"
    if [[ "$HOTSPOT_STOP_STATUS" == "ok" ]]; then
      rj_ok "hotspot_stop_execution"
    else
      rj_fail "hotspot_stop_execution"
    fi
  else
    rj_fail "hotspot_start_execution"
  fi
else
  rj_skip "Dangerous hotspot tests disabled (use --dangerous)"
fi

rj_write_report
rj_log "Hotspot tests completed. Output: $OUT"
rj_exit_by_fail_count
