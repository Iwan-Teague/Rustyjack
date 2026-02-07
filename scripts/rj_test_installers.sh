#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$ROOT_DIR/.." && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_SHELLCHECK=1
RUN_SYNTAX=1
RUN_PATTERNS=1
RUN_ISOLATION=1

usage() {
  cat <<'USAGE'
Usage: rj_test_installers.sh [options]

Options:
  --no-shellcheck     Skip shellcheck if available
  --no-syntax         Skip bash -n syntax checks
  --no-patterns       Skip installer content checks
  --no-isolation      Skip isolation snapshot checks
  --outroot DIR       Output root (default: /var/tmp/rustyjack-tests)
  -h, --help          Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-shellcheck) RUN_SHELLCHECK=0; shift ;;
    --no-syntax) RUN_SYNTAX=0; shift ;;
    --no-patterns) RUN_PATTERNS=0; shift ;;
    --no-isolation) RUN_ISOLATION=0; shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "installers"

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing installer test failure context..."
  ls -la "$PROJECT_ROOT" >"$OUT/artifacts/project_root_ls.txt" 2>&1 || true
}
export RJ_FAILURE_HOOK=capture_failure_context

INSTALL_SCRIPTS=(
  "$PROJECT_ROOT/install_rustyjack.sh"
  "$PROJECT_ROOT/install_rustyjack_dev.sh"
  "$PROJECT_ROOT/install_rustyjack_prebuilt.sh"
  "$PROJECT_ROOT/install_rustyjack_usb.sh"
)

pattern_match() {
  local pattern="$1" script="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$script"
  else
    grep -nE "$pattern" "$script"
  fi
}

require_pattern() {
  local script="$1" label="$2" pattern="$3"
  if pattern_match "$pattern" "$script" >/dev/null 2>&1; then
    local hit
    hit=$(pattern_match "$pattern" "$script" | head -n 1 | tr -d '\r')
    rj_ok "$label ($hit)"
  else
    rj_fail "$label (pattern not found: $pattern)"
  fi
}

if [[ $RUN_ISOLATION -eq 1 ]]; then
  rj_snapshot_network "installers_pre"
fi

for script in "${INSTALL_SCRIPTS[@]}"; do
  if [[ ! -f "$script" ]]; then
    rj_fail "installer_missing ($script)"
    continue
  fi

  if [[ -x "$script" ]]; then
    rj_ok "installer_executable ($script)"
  else
    rj_fail "installer_not_executable ($script)"
  fi

  if [[ $RUN_SYNTAX -eq 1 ]]; then
    rj_run_cmd "syntax_${script##*/}" bash -n "$script"
  else
    rj_skip "syntax checks disabled"
  fi

  if [[ $RUN_SHELLCHECK -eq 1 ]]; then
    if command -v shellcheck >/dev/null 2>&1; then
      rj_run_cmd "shellcheck_${script##*/}" shellcheck -x -s bash "$script"
    else
      rj_skip "shellcheck not available"
    fi
  else
    rj_skip "shellcheck disabled"
  fi

  if [[ $RUN_PATTERNS -eq 1 ]]; then
    require_pattern "$script" "has_shebang" '^#!.*/(env )?bash'
    require_pattern "$script" "has_set_euo" 'set -euo pipefail'
    require_pattern "$script" "purge_network_manager" 'purge network-manager'
    require_pattern "$script" "disable_conflicting_services" 'disable_conflicting_services\(\)'
    require_pattern "$script" "claim_resolv_conf" 'claim_resolv_conf\(\)'
    require_pattern "$script" "post_install_checks" 'Running post install checks'
    require_pattern "$script" "log_dir_chown" 'chown -R rustyjack-ui:rustyjack .*logs'
    require_pattern "$script" "socket_unit" 'rustyjackd.socket'
    require_pattern "$script" "ui_service" 'rustyjack-ui.service'
  else
    rj_skip "pattern checks disabled"
  fi

done

# USB installer: extra diagnostics for mount/debugging
USB_SCRIPT="$PROJECT_ROOT/install_rustyjack_usb.sh"
if [[ -f "$USB_SCRIPT" && $RUN_PATTERNS -eq 1 ]]; then
  require_pattern "$USB_SCRIPT" "usb_lsblk" 'lsblk'
  require_pattern "$USB_SCRIPT" "usb_lsusb" 'lsusb'
  require_pattern "$USB_SCRIPT" "usb_dmesg" 'dmesg'
fi

if [[ $RUN_ISOLATION -eq 1 ]]; then
  rj_snapshot_network "installers_post"
  rj_compare_snapshot "installers_pre" "installers_post" "installers_readonly"
fi

rj_write_report

rj_log "Installer tests completed. Output: $OUT"
