#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0

usage() {
  cat <<'USAGE'
Usage: rj_test_evasion.sh [options]

Tests MAC randomization, hostname randomization, and TX power control.

Options:
  --ui                 Require UI mode (default)
  --no-ui              Disable UI mode
  --dangerous          Enable dangerous/disruptive tests (MAC change, hostname change)
  --outroot DIR        Output root (default: /var/tmp/rustyjack-tests)
  -h, --help           Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ui) RUN_UI=1; shift ;;
    --no-ui) RUN_UI=0; shift ;;
    --dangerous) DANGEROUS=1; shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "evasion"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

# Test MAC randomization status
rj_run_cmd_capture "evasion_mac_status" "$OUT/artifacts/mac_status.json" \
  rustyjack evasion mac-status --output json

MAC_CURRENT="$(rj_json_get "$OUT/artifacts/mac_status.json" "data.current" || echo "")"
MAC_RANDOMIZATION="$(rj_json_get "$OUT/artifacts/mac_status.json" "data.randomization_enabled" || echo "")"
if [[ -n "$MAC_CURRENT" ]]; then
  rj_ok "evasion_mac_status_query"
else
  rj_fail "evasion_mac_status_query"
fi

# Test hostname randomization status
rj_run_cmd_capture "evasion_hostname_status" "$OUT/artifacts/hostname_status.json" \
  rustyjack evasion hostname-status --output json

HOSTNAME_CURRENT="$(rj_json_get "$OUT/artifacts/hostname_status.json" "data.current" || echo "")"
HOSTNAME_RANDOMIZATION="$(rj_json_get "$OUT/artifacts/hostname_status.json" "data.randomization_enabled" || echo "")"
if [[ -n "$HOSTNAME_CURRENT" ]]; then
  rj_ok "evasion_hostname_status_query"
else
  rj_fail "evasion_hostname_status_query"
fi

# Test TX power control status
rj_run_cmd_capture "evasion_txpower_status" "$OUT/artifacts/txpower_status.json" \
  rustyjack evasion tx-power-status --output json

TXPOWER_STATUS="$(rj_json_get "$OUT/artifacts/txpower_status.json" "status" || echo "")"
if [[ "$TXPOWER_STATUS" == "ok" ]]; then
  rj_ok "evasion_txpower_status_query"
else
  rj_fail "evasion_txpower_status_query"
fi

# Test evasion mode status
rj_run_cmd_capture "evasion_mode_status" "$OUT/artifacts/mode_status.json" \
  rustyjack evasion mode-status --output json

MODE_CURRENT="$(rj_json_get "$OUT/artifacts/mode_status.json" "data.current" || echo "")"
if [[ -n "$MODE_CURRENT" ]]; then
  rj_ok "evasion_mode_status_query"
  rj_log "[INFO] Current evasion mode: $MODE_CURRENT"
else
  rj_fail "evasion_mode_status_query"
fi

if [[ $DANGEROUS -eq 1 ]]; then
  # Test MAC randomization (dangerous - changes MAC address)
  rj_log "[WARN] Running dangerous MAC randomization test"
  
  rj_run_cmd_capture "evasion_mac_randomize" "$OUT/artifacts/mac_randomize.json" \
    rustyjack evasion randomize-mac --output json
  
  MAC_NEW="$(rj_json_get "$OUT/artifacts/mac_randomize.json" "data.new_mac" || echo "")"
  if [[ -n "$MAC_NEW" && "$MAC_NEW" != "$MAC_CURRENT" ]]; then
    rj_ok "evasion_mac_randomize"
    rj_log "[INFO] MAC changed from $MAC_CURRENT to $MAC_NEW"
  else
    rj_fail "evasion_mac_randomize (MAC did not change)"
  fi
  
  # Test hostname randomization (dangerous - changes hostname)
  rj_log "[WARN] Running dangerous hostname randomization test"
  
  rj_run_cmd_capture "evasion_hostname_randomize" "$OUT/artifacts/hostname_randomize.json" \
    rustyjack evasion randomize-hostname --output json
  
  HOSTNAME_NEW="$(rj_json_get "$OUT/artifacts/hostname_randomize.json" "data.new_hostname" || echo "")"
  if [[ -n "$HOSTNAME_NEW" && "$HOSTNAME_NEW" != "$HOSTNAME_CURRENT" ]]; then
    rj_ok "evasion_hostname_randomize"
    rj_log "[INFO] Hostname changed from $HOSTNAME_CURRENT to $HOSTNAME_NEW"
  else
    rj_fail "evasion_hostname_randomize (hostname did not change)"
  fi
else
  rj_skip "Dangerous evasion tests disabled (use --dangerous to enable)"
fi

rj_write_report
rj_log "Evasion tests completed. Output: $OUT"
rj_exit_by_fail_count
