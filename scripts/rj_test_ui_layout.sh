#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "UI layout suite requires Linux target for rustyjack-ui crate"
  exit 0
fi

usage() {
  cat <<'USAGE'
Usage: rj_test_ui_layout.sh [--outroot DIR]

Runs dynamic display/layout tests for rustyjack-ui:
- runtime metrics across resolutions
- wrap/ellipsis/pagination bounds
- display config persistence/cache tests
- display menu manual rerun action coverage
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --no-ui|--dangerous) shift ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "ui_layout"

if ! rj_ensure_tool cargo "cargo" "Rust toolchain (UI layout tests)"; then
  rj_skip "UI layout tests skipped (cargo unavailable)"
  rj_write_report
  exit 0
fi

rj_run_cmd "ui_layout_metrics_tests" cargo test -p rustyjack-ui ui::layout::tests -- --nocapture
rj_run_cmd "ui_display_config_tests" cargo test -p rustyjack-ui config::tests -- --nocapture
rj_run_cmd "ui_display_probe_tests" cargo test -p rustyjack-ui display::tests -- --nocapture
rj_run_cmd "ui_display_menu_tests" cargo test -p rustyjack-ui menu::tests -- --nocapture
rj_run_cmd "ui_core_dispatch_guard" cargo test -p rustyjack-ui --test core_dispatch_guard -- --nocapture

rj_write_report
rj_log "UI layout/display tests completed. Output: $OUT"
