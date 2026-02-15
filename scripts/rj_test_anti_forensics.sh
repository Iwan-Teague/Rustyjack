#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0

usage() {
  cat <<'USAGE'
Usage: rj_test_anti_forensics.sh [options]

Tests secure deletion, log purging, and evidence management capabilities.

Options:
  --ui                 Require UI mode (default)
  --no-ui              Disable UI mode
  --dangerous          Enable dangerous/disruptive tests (secure wipe, log purge)
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

rj_init "anti_forensics"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

# Test audit log status
rj_run_cmd_capture "audit_log_status" "$OUT/artifacts/audit_log_status.json" \
  rustyjack audit log-status --output json

AUDIT_STATUS="$(rj_json_get "$OUT/artifacts/audit_log_status.json" "status" || echo "")"
if [[ "$AUDIT_STATUS" == "ok" ]]; then
  rj_ok "audit_log_status_query"
else
  rj_fail "audit_log_status_query"
fi

# Test that secure deletion capabilities are available
TEST_FILE="${OUT}/artifacts/test_secure_delete.txt"
echo "Test data for secure deletion" > "$TEST_FILE"
if [[ -f "$TEST_FILE" ]]; then
  rj_ok "test_file_created_for_secure_delete"
  
  if [[ $DANGEROUS -eq 1 ]]; then
    rj_log "[WARN] Running dangerous secure deletion test"
    
    rj_run_cmd_capture "secure_delete_test" "$OUT/artifacts/secure_delete.json" \
      rustyjack anti-forensics secure-delete --target "$TEST_FILE" --output json
    
    if [[ ! -f "$TEST_FILE" ]]; then
      rj_ok "secure_delete_removed_file"
    else
      rj_fail "secure_delete_removed_file (file still exists)"
    fi
  else
    rj_skip "Dangerous secure delete test disabled (use --dangerous)"
    rm -f "$TEST_FILE"
  fi
else
  rj_fail "test_file_created_for_secure_delete"
fi

# Test log purge query (non-destructive)
rj_run_cmd_capture "log_purge_status" "$OUT/artifacts/log_purge_status.json" \
  rustyjack anti-forensics log-status --output json

LOG_STATUS="$(rj_json_get "$OUT/artifacts/log_purge_status.json" "status" || echo "")"
if [[ "$LOG_STATUS" == "ok" ]]; then
  rj_ok "log_purge_status_query"
else
  rj_fail "log_purge_status_query"
fi

# Test artifact sweep capabilities (non-destructive list)
rj_run_cmd_capture "artifact_sweep_list" "$OUT/artifacts/artifact_sweep_list.json" \
  rustyjack loot artifact-sweep --list-only --output json

SWEEP_STATUS="$(rj_json_get "$OUT/artifacts/artifact_sweep_list.json" "status" || echo "")"
if [[ "$SWEEP_STATUS" == "ok" ]]; then
  rj_ok "artifact_sweep_list_query"
else
  rj_fail "artifact_sweep_list_query"
fi

if [[ $DANGEROUS -eq 1 ]]; then
  rj_log "[WARN] Dangerous anti-forensics tests would be destructive"
  rj_log "[WARN] Skipping actual log purge and RAM wipe tests"
  rj_skip "log_purge_execution (too dangerous for automated testing)"
  rj_skip "ram_wipe_execution (too dangerous for automated testing)"
else
  rj_skip "Dangerous anti-forensics tests disabled (use --dangerous)"
fi

rj_write_report
rj_log "Anti-forensics tests completed. Output: $OUT"
rj_exit_by_fail_count
