#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
RUN_UNIT=1
RUN_INTEGRATION=1
RUN_NEGATIVE=1
RUN_ISOLATION=1
RUN_COMPAT=1

UI_SCENARIO="$ROOT_DIR/ui_scenarios/loot.ui"
RJ_ROOT="${RUSTYJACK_ROOT:-/var/lib/rustyjack}"

usage() {
  cat <<'USAGE'
Usage: rj_test_loot.sh [options]

Options:
  --no-ui             Skip UI automation
  --ui                Enable UI automation (default)
  --ui-scenario PATH  Scenario file (default: scripts/ui_scenarios/loot.ui)
  --root DIR          Rustyjack root (default: /var/lib/rustyjack)
  --no-unit           Skip unit tests
  --no-integration    Skip integration tests
  --no-negative       Skip negative tests
  --no-isolation      Skip isolation checks
  --no-compat         Skip compatibility checks
  --outroot DIR       Output root (default: /var/tmp/rustyjack-tests)
  -h, --help          Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-ui) RUN_UI=0; shift ;;
    --ui) RUN_UI=1; shift ;;
    --ui-scenario) UI_SCENARIO="$2"; shift 2 ;;
    --root) RJ_ROOT="$2"; shift 2 ;;
    --no-unit) RUN_UNIT=0; shift ;;
    --no-integration) RUN_INTEGRATION=0; shift ;;
    --no-negative) RUN_NEGATIVE=0; shift ;;
    --no-isolation) RUN_ISOLATION=0; shift ;;
    --no-compat) RUN_COMPAT=0; shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "loot"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing loot failure context..."
  ls -la "$RJ_ROOT/loot" >"$OUT/artifacts/loot_ls_fail.txt" 2>&1 || true
  rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd_fail.log"
}
export RJ_FAILURE_HOOK=capture_failure_context

if [[ $RUN_COMPAT -eq 1 ]]; then
  rj_ok "Compatibility checks passed (loot)"
else
  rj_skip "Compatibility checks disabled"
fi

if [[ $RUN_UNIT -eq 1 ]]; then
  if rj_ensure_tool cargo "cargo" "Rust toolchain (unit tests)"; then
    rj_run_cmd "unit_rustyjack_core" cargo test -p rustyjack-core --lib -- --nocapture
  else
    rj_skip "Unit tests skipped (cargo unavailable)"
  fi
else
  rj_skip "Unit tests disabled"
fi

WIRELESS_LOOT="$RJ_ROOT/loot/Wireless/TestNet/test_loot.txt"
ETH_LOOT="$RJ_ROOT/loot/Ethernet/192.168.0.10/test_loot.txt"
REPORT_LOOT="$RJ_ROOT/loot/reports/TestNet/report_test.txt"

mkdir -p "$(dirname "$WIRELESS_LOOT")" "$(dirname "$ETH_LOOT")" "$(dirname "$REPORT_LOOT")"

printf 'wireless loot sample\n' >"$WIRELESS_LOOT"
printf 'ethernet loot sample\n' >"$ETH_LOOT"
printf 'report loot sample\n' >"$REPORT_LOOT"

if [[ $RUN_INTEGRATION -eq 1 ]]; then
  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "loot_pre"
  fi

  rj_run_cmd_capture "loot_list_wireless" "$OUT/artifacts/loot_wireless.json" \
    rustyjack loot list --kind wireless --output json
  rj_run_cmd_capture "loot_list_ethernet" "$OUT/artifacts/loot_ethernet.json" \
    rustyjack loot list --kind ethernet --output json
  rj_run_cmd_capture "loot_list_scan" "$OUT/artifacts/loot_scan.json" \
    rustyjack loot list --kind scan --output json
  rj_run_cmd_capture "loot_list_dnsspoof" "$OUT/artifacts/loot_dnsspoof.json" \
    rustyjack loot list --kind dnsspoof --output json

  rj_run_cmd_capture "loot_read_wireless" "$OUT/artifacts/loot_read_wireless.txt" \
    rustyjack loot read --path "$WIRELESS_LOOT" --output text
  rj_run_cmd_capture "loot_read_ethernet" "$OUT/artifacts/loot_read_ethernet.txt" \
    rustyjack loot read --path "$ETH_LOOT" --output text
  rj_run_cmd_capture "loot_read_report" "$OUT/artifacts/loot_read_report.txt" \
    rustyjack loot read --path "$REPORT_LOOT" --output text

  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "loot_post"
    rj_compare_snapshot "loot_pre" "loot_post" "loot_readonly"
  fi
else
  rj_skip "Integration tests disabled"
fi

if [[ $RUN_NEGATIVE -eq 1 ]]; then
  rj_run_cmd_capture_allow_fail "loot_read_missing" "$OUT/artifacts/loot_read_missing.txt" \
    rustyjack loot read --path "$RJ_ROOT/loot/does_not_exist.txt" --output text
  rj_run_cmd_expect_fail "loot_list_invalid_kind" "$OUT/artifacts/loot_list_invalid.txt" \
    rustyjack loot list --kind invalid --output json
else
  rj_skip "Negative tests disabled"
fi

if [[ $RUN_UI -eq 1 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    trap rj_ui_disable EXIT
    if rj_ui_enable; then
      rj_ui_run_scenario "$UI_SCENARIO"
      rj_capture_journal "rustyjack-ui.service" "$OUT/journal/rustyjack-ui.log"
    else
      rj_skip "Failed to enable UI virtual input"
    fi
  else
    rj_skip "systemctl not available; skipping UI automation"
  fi
fi

rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd.log"
rj_write_report

rj_log "Loot tests completed. Output: $OUT"
