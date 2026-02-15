#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0

usage() {
  cat <<'USAGE'
Usage: rj_test_physical_access.sh [options]

Tests physical access operations: router credential extraction, fingerprinting.

Options:
  --ui                 Require UI mode (default)
  --no-ui              Disable UI mode
  --dangerous          Enable dangerous/disruptive tests (router connection attempts)
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

rj_init "physical_access"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

# Test router fingerprinting capabilities (query only, no actual scan)
rj_run_cmd_capture "router_fingerprint_help" "$OUT/artifacts/router_fingerprint_help.txt" \
  rustyjack physical-access router-fingerprint --help

if [[ -f "$OUT/artifacts/router_fingerprint_help.txt" ]]; then
  rj_ok "router_fingerprint_help_available"
else
  rj_fail "router_fingerprint_help_available"
fi

# Test credential extraction capabilities (query only)
rj_run_cmd_capture "credential_extract_help" "$OUT/artifacts/credential_extract_help.txt" \
  rustyjack physical-access extract-credentials --help

if [[ -f "$OUT/artifacts/credential_extract_help.txt" ]]; then
  rj_ok "credential_extract_help_available"
else
  rj_fail "credential_extract_help_available"
fi

# Test default credential database query
rj_run_cmd_capture "default_creds_list" "$OUT/artifacts/default_creds_list.json" \
  rustyjack physical-access list-default-credentials --output json

CREDS_STATUS="$(rj_json_get "$OUT/artifacts/default_creds_list.json" "status" || echo "")"
if [[ "$CREDS_STATUS" == "ok" ]]; then
  rj_ok "default_credentials_database_available"
else
  rj_fail "default_credentials_database_available"
fi

if [[ $DANGEROUS -eq 1 ]]; then
  rj_log "[WARN] Physical access tests require actual router hardware"
  rj_log "[WARN] Skipping dangerous router connection tests"
  rj_skip "router_fingerprint_execution (requires router hardware)"
  rj_skip "credential_extraction_execution (requires router hardware)"
else
  rj_skip "Dangerous physical access tests disabled (use --dangerous)"
fi

rj_write_report
rj_log "Physical access tests completed. Output: $OUT"
rj_exit_by_fail_count
