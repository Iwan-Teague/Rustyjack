#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
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

WIRELESS_LOOT="$RJ_ROOT/loot/Wireless/TestNet/test_loot.txt"
ETH_LOOT="$RJ_ROOT/loot/Ethernet/192.168.0.10/test_loot.txt"
REPORT_LOOT="$RJ_ROOT/loot/reports/TestNet/report_test.txt"

mkdir -p "$(dirname "$WIRELESS_LOOT")" "$(dirname "$ETH_LOOT")" "$(dirname "$REPORT_LOOT")"

printf 'wireless loot sample\n' >"$WIRELESS_LOOT"
printf 'ethernet loot sample\n' >"$ETH_LOOT"
printf 'report loot sample\n' >"$REPORT_LOOT"

rj_run_cmd_capture "loot_list_wireless" "$OUT/artifacts/loot_wireless.json" \
  rustyjack loot list --kind wireless --output json
rj_run_cmd_capture "loot_list_ethernet" "$OUT/artifacts/loot_ethernet.json" \
  rustyjack loot list --kind ethernet --output json
rj_run_cmd_capture "loot_read_wireless" "$OUT/artifacts/loot_read_wireless.txt" \
  rustyjack loot read --path "$WIRELESS_LOOT" --output text

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
