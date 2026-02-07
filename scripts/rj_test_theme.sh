#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$ROOT_DIR/.." && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
RUN_UNIT=1
RUN_INTEGRATION=1
RUN_SOURCE=1
RUN_COMPAT=1
RUN_ISOLATION=1

RJ_ROOT="${RUSTYJACK_ROOT:-/var/lib/rustyjack}"
UI_SERVICE="${RJ_UI_SERVICE:-rustyjack-ui.service}"
DAEMON_SERVICE="${RJ_DAEMON_SERVICE:-rustyjackd.service}"

GUI_CONF=""
BACKUP_GUI=""
ORIG_GUI_PRESENT=0
NEEDS_RESTORE=0

usage() {
  cat <<'USAGE'
Usage: rj_test_theme.sh [options]

Runs thorough UI theme verification for rustyjack-ui:
- source guard checks for theme architecture and palette usage
- theme-focused unit tests
- UI-driven per-role color edits with immediate persistence checks
- restart persistence checks
- preset apply checks
- invalid gui_conf.json theme repair checks
- removed-field compatibility checks

Options:
  --root DIR          Rustyjack root (default: /var/lib/rustyjack)
  --ui-service UNIT   UI service unit (default: rustyjack-ui.service)
  --daemon-service U  Daemon service unit (default: rustyjackd.service)
  --no-ui             Skip UI automation checks
  --ui                Enable UI automation (default)
  --no-unit           Skip Rust unit tests
  --no-integration    Skip integration checks against gui_conf/service
  --no-source         Skip source/pattern guard checks
  --no-compat         Skip compatibility checks
  --no-isolation      Skip network isolation snapshots
  --dangerous         Ignored (compat with rj_run_tests)
  --outroot DIR       Output root (default: /var/tmp/rustyjack-tests)
  -h, --help          Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) RJ_ROOT="$2"; shift 2 ;;
    --ui-service) UI_SERVICE="$2"; shift 2 ;;
    --daemon-service) DAEMON_SERVICE="$2"; shift 2 ;;
    --no-ui) RUN_UI=0; shift ;;
    --ui) RUN_UI=1; shift ;;
    --no-unit) RUN_UNIT=0; shift ;;
    --no-integration) RUN_INTEGRATION=0; shift ;;
    --no-source) RUN_SOURCE=0; shift ;;
    --no-compat) RUN_COMPAT=0; shift ;;
    --no-isolation) RUN_ISOLATION=0; shift ;;
    --dangerous) shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "theme"
rj_require_root

GUI_CONF="$RJ_ROOT/gui_conf.json"
BACKUP_GUI="$OUT/artifacts/gui_conf.backup.json"

cleanup_theme_suite() {
  if [[ "$NEEDS_RESTORE" -eq 1 && "$ORIG_GUI_PRESENT" -eq 1 && -f "$BACKUP_GUI" ]]; then
    cp "$BACKUP_GUI" "$GUI_CONF" 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart "$UI_SERVICE" >/dev/null 2>&1 || true
    fi
  fi
  rj_ui_disable || true
}
trap cleanup_theme_suite EXIT

FAIL_CONTEXT_CAPTURED=0
UI_LAST_RESTART_OK=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing theme failure context..."

  mkdir -p "$OUT/artifacts" "$OUT/journal" 2>/dev/null || true
  if [[ -f "$GUI_CONF" ]]; then
    cp "$GUI_CONF" "$OUT/artifacts/gui_conf_fail.json" 2>/dev/null || true
    stat "$GUI_CONF" >"$OUT/artifacts/gui_conf_fail.stat.txt" 2>&1 || true
  fi
  ls -la "$RJ_ROOT" >"$OUT/artifacts/rj_root_ls_fail.txt" 2>&1 || true

  if command -v systemctl >/dev/null 2>&1; then
    systemctl status "$UI_SERVICE" >"$OUT/artifacts/${UI_SERVICE}.status.fail.txt" 2>&1 || true
    systemctl status "$DAEMON_SERVICE" >"$OUT/artifacts/${DAEMON_SERVICE}.status.fail.txt" 2>&1 || true
  fi

  rj_capture_journal "$UI_SERVICE" "$OUT/journal/${UI_SERVICE}.fail.log"
  rj_capture_journal "$DAEMON_SERVICE" "$OUT/journal/${DAEMON_SERVICE}.fail.log"

  for jf in "$OUT/journal/${UI_SERVICE}.fail.log" "$OUT/journal/${DAEMON_SERVICE}.fail.log"; do
    if [[ -f "$jf" ]]; then
      rj_log "[TAIL] $(basename "$jf")"
      rj_tail_dedup "$jf" 120 | while IFS= read -r line; do
        rj_log "  $line"
      done
    fi
  done
}
export RJ_FAILURE_HOOK=capture_failure_context

pattern_match() {
  local pattern="$1" file="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$file"
  else
    grep -nE "$pattern" "$file"
  fi
}

require_pattern() {
  local file="$1" label="$2" pattern="$3"
  if pattern_match "$pattern" "$file" >/dev/null 2>&1; then
    local hit
    hit="$(pattern_match "$pattern" "$file" | head -n 1 | tr -d '\r')"
    rj_ok "$label ($hit)"
  else
    rj_fail "$label (pattern not found: $pattern in $file)"
  fi
}

forbid_pattern() {
  local file="$1" label="$2" pattern="$3"
  if pattern_match "$pattern" "$file" >/dev/null 2>&1; then
    local hit
    hit="$(pattern_match "$pattern" "$file" | head -n 1 | tr -d '\r')"
    rj_fail "$label (unexpected pattern: $hit)"
  else
    rj_ok "$label"
  fi
}

file_mtime_epoch() {
  local file="$1"
  stat -c %Y "$file" 2>/dev/null || echo 0
}

expect_color_value() {
  local role="$1"
  local expected="$2"
  local context="$3"
  local actual
  actual="$(rj_json_get "$GUI_CONF" "colors.$role" || true)"
  if [[ "$actual" == "$expected" ]]; then
    rj_ok "$context ($role=$expected)"
  else
    rj_fail "$context ($role expected=$expected actual=${actual:-<missing>})"
    if [[ -f "$GUI_CONF" ]]; then
      cp "$GUI_CONF" "$OUT/artifacts/gui_conf_assert_fail_${role}.json" 2>/dev/null || true
    fi
  fi
}

expect_color_key_present() {
  local role="$1"
  local context="$2"
  local actual
  actual="$(rj_json_get "$GUI_CONF" "colors.$role" || true)"
  if [[ -n "$actual" ]]; then
    rj_ok "$context ($role present: $actual)"
  else
    rj_fail "$context ($role missing)"
  fi
}

expect_color_key_absent() {
  local role="$1"
  local context="$2"
  local actual
  actual="$(rj_json_get "$GUI_CONF" "colors.$role" || true)"
  if [[ -z "$actual" ]]; then
    rj_ok "$context ($role absent)"
  else
    rj_fail "$context ($role unexpectedly present: $actual)"
  fi
}

write_invalid_theme_config() {
  python3 - <<PY
import json
import pathlib
p = pathlib.Path("$GUI_CONF")
if p.exists():
    try:
        data = json.loads(p.read_text())
    except Exception:
        data = {}
else:
    data = {}
colors = data.setdefault("colors", {})
colors["background"] = "  12zz00  "
colors["border"] = "#123"
colors["text"] = "AA00FF"
colors["selected_text"] = " #abcdef "
colors["selected_background"] = " 1122GG "
colors["toolbar"] = "0f0f0f "
colors["gamepad"] = "#440066"
colors["gamepad_fill"] = "#AA00FF"
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(data, indent=2))
PY
}

restart_ui_service() {
  local label="$1"
  local outfile="$OUT/artifacts/${label}.log"
  UI_LAST_RESTART_OK=0
  if ! command -v systemctl >/dev/null 2>&1; then
    rj_skip "$label (systemctl unavailable)"
    return 0
  fi
  rj_run_cmd_capture "$label" "$outfile" systemctl restart "$UI_SERVICE"
  sleep "${RJ_UI_BOOT_WAIT:-4}"
  if systemctl is-active --quiet "$UI_SERVICE"; then
    rj_ok "${label}_active"
    UI_LAST_RESTART_OK=1
    return 0
  fi
  rj_fail "${label}_active (service not active)"
  return 0
}

ui_nav_main_to_colors_menu() {
  # Assumes service has just restarted; selection begins at top-level main menu.
  rj_ui_send down 9
  rj_ui_send select 1
  rj_ui_send down 3
  rj_ui_send select 1
}

ui_set_role_color() {
  local role_key="$1"
  local role_menu_index="$2"
  local color_choice_index="$3"
  local expected_hex="$4"

  restart_ui_service "theme_ui_restart_${role_key}"
  if [[ "$UI_LAST_RESTART_OK" -ne 1 ]]; then
    rj_fail "ui_role_edit_aborted_${role_key} (UI service restart failed)"
    return 0
  fi

  local before_mtime after_mtime
  before_mtime="$(file_mtime_epoch "$GUI_CONF")"

  ui_nav_main_to_colors_menu
  if [[ "$role_menu_index" -gt 0 ]]; then
    rj_ui_send down "$role_menu_index"
  fi
  rj_ui_send select 1
  if [[ "$color_choice_index" -gt 0 ]]; then
    rj_ui_send down "$color_choice_index"
  fi
  rj_ui_send select 1
  rj_ui_send select 1
  sleep 1

  expect_color_value "$role_key" "$expected_hex" "ui_immediate_persist_${role_key}"

  after_mtime="$(file_mtime_epoch "$GUI_CONF")"
  if [[ "$after_mtime" -gt "$before_mtime" ]]; then
    rj_ok "ui_immediate_file_update_${role_key} (mtime ${before_mtime} -> ${after_mtime})"
  else
    rj_fail "ui_immediate_file_update_${role_key} (mtime unchanged: ${before_mtime})"
  fi
}

ui_apply_high_contrast_preset() {
  restart_ui_service "theme_ui_restart_apply_preset"
  if [[ "$UI_LAST_RESTART_OK" -ne 1 ]]; then
    rj_fail "ui_apply_preset_aborted (UI service restart failed)"
    return 0
  fi

  ui_nav_main_to_colors_menu
  rj_ui_send down 6
  rj_ui_send select 1
  rj_ui_send down 2
  rj_ui_send select 1
  rj_ui_send select 1
  sleep 1

  expect_color_value "background" "#000000" "ui_apply_preset_high_contrast"
  expect_color_value "border" "#FFFFFF" "ui_apply_preset_high_contrast"
  expect_color_value "text" "#FFFFFF" "ui_apply_preset_high_contrast"
  expect_color_value "selected_text" "#000000" "ui_apply_preset_high_contrast"
  expect_color_value "selected_background" "#FFFF00" "ui_apply_preset_high_contrast"
  expect_color_value "toolbar" "#000000" "ui_apply_preset_high_contrast"
}

if [[ $RUN_COMPAT -eq 1 ]]; then
  if command -v python3 >/dev/null 2>&1; then
    rj_ok "python3_available"
  else
    rj_fail "python3_missing"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    rj_ok "systemctl_available"
  else
    rj_skip "systemctl unavailable (service-level theme checks limited)"
  fi
else
  rj_skip "Compatibility checks disabled"
fi

if ! rj_ensure_tool python3 "python3" "Python 3 (theme suite JSON checks)"; then
  rj_write_report
  exit 0
fi

if [[ -f "$GUI_CONF" ]]; then
  cp "$GUI_CONF" "$BACKUP_GUI" 2>/dev/null || true
  ORIG_GUI_PRESENT=1
  NEEDS_RESTORE=1
  rj_ok "gui_conf_present ($GUI_CONF)"
else
  rj_fail "gui_conf_present ($GUI_CONF missing)"
fi

if [[ $RUN_SOURCE -eq 1 ]]; then
  CONFIG_RS="$PROJECT_ROOT/crates/rustyjack-ui/src/config.rs"
  DISPLAY_RS="$PROJECT_ROOT/crates/rustyjack-ui/src/display.rs"
  MENU_RS="$PROJECT_ROOT/crates/rustyjack-ui/src/menu.rs"
  SETTINGS_RS="$PROJECT_ROOT/crates/rustyjack-ui/src/app/settings.rs"
  ACTION_MAP="$PROJECT_ROOT/docs/ui_action_map.md"

  require_pattern "$CONFIG_RS" "theme_mutate_helper_present" 'pub fn mutate_theme_and_persist'
  require_pattern "$CONFIG_RS" "theme_normalize_present" 'pub fn normalize\(&mut self\) -> bool'
  require_pattern "$CONFIG_RS" "theme_preset_present" 'pub enum ThemePreset'
  require_pattern "$CONFIG_RS" "theme_contrast_present" 'pub fn contrast_warnings'
  require_pattern "$CONFIG_RS" "theme_atomic_save_temp" 'tmp\.set_file_name'
  require_pattern "$CONFIG_RS" "theme_atomic_save_sync" 'file\.sync_all\(\)'
  require_pattern "$CONFIG_RS" "theme_atomic_save_rename" 'fs::rename\(&tmp, path\)'
  forbid_pattern "$CONFIG_RS" "theme_dead_field_removed_gamepad" 'gamepad'

  require_pattern "$MENU_RS" "theme_color_roles_centralized" 'pub const ALL: \[Self; 6\]'
  require_pattern "$MENU_RS" "theme_colors_menu_data_driven" 'ColorTarget::ALL'
  require_pattern "$MENU_RS" "theme_apply_preset_menu_entry" 'Apply Preset'

  require_pattern "$SETTINGS_RS" "theme_single_mutate_flow" 'fn mutate_theme_config_and_refresh'
  require_pattern "$SETTINGS_RS" "theme_feedback_flow" 'fn show_theme_update_result'
  require_pattern "$SETTINGS_RS" "theme_preset_flow" 'fn apply_theme_preset'
  require_pattern "$SETTINGS_RS" "theme_contrast_warning_text" 'Contrast warning'

  require_pattern "$DISPLAY_RS" "theme_startup_clear_uses_palette" 'with_fill\(palette\.background\)'
  require_pattern "$DISPLAY_RS" "theme_splash_clear_uses_palette" 'with_fill\(self\.palette\.background\)'
  require_pattern "$DISPLAY_RS" "theme_splash_text_uses_palette" 'text_color\(self\.palette\.text\)'
  forbid_pattern "$DISPLAY_RS" "theme_splash_hardcoded_purple_removed" 'text_color\(Rgb565::new\(21, 0, 31\)\)'

  require_pattern "$ACTION_MAP" "theme_action_map_updated" '\| ApplyThemePreset \| `App::apply_theme_preset` \|'
else
  rj_skip "Source guard checks disabled"
fi

if [[ $RUN_UNIT -eq 1 ]]; then
  if rj_ensure_tool cargo "cargo" "Rust toolchain (theme unit tests)"; then
    rj_run_cmd "theme_unit_config_tests" cargo test -p rustyjack-ui config::tests -- --nocapture
    rj_run_cmd "theme_unit_display_tests" cargo test -p rustyjack-ui display::tests -- --nocapture
    rj_run_cmd "theme_unit_menu_tests" cargo test -p rustyjack-ui menu::tests -- --nocapture
  else
    rj_skip "Theme unit tests skipped (cargo unavailable)"
  fi
else
  rj_skip "Theme unit tests disabled"
fi

if [[ $RUN_INTEGRATION -eq 1 ]]; then
  if [[ ! -f "$GUI_CONF" ]]; then
    rj_skip "Theme integration skipped (gui_conf missing)"
  else
    if [[ $RUN_ISOLATION -eq 1 ]]; then
      rj_snapshot_network "theme_pre"
    fi

    # Verify all active roles exist in config.
    expect_color_key_present "background" "theme_role_present"
    expect_color_key_present "border" "theme_role_present"
    expect_color_key_present "text" "theme_role_present"
    expect_color_key_present "selected_text" "theme_role_present"
    expect_color_key_present "selected_background" "theme_role_present"
    expect_color_key_present "toolbar" "theme_role_present"

    if [[ $RUN_UI -eq 1 ]]; then
      if command -v systemctl >/dev/null 2>&1; then
        if rj_ui_enable; then
          ui_set_role_color "background" 0 4 "#0000FF"
          ui_set_role_color "border" 1 3 "#FF0000"
          ui_set_role_color "text" 2 1 "#000000"
          ui_set_role_color "selected_text" 3 0 "#FFFFFF"
          ui_set_role_color "selected_background" 4 6 "#AA00FF"
          ui_set_role_color "toolbar" 5 7 "#FFBF00"

          restart_ui_service "theme_ui_restart_verify_persistence"
          if [[ "$UI_LAST_RESTART_OK" -eq 1 ]]; then
            expect_color_value "background" "#0000FF" "theme_restart_persist"
            expect_color_value "border" "#FF0000" "theme_restart_persist"
            expect_color_value "text" "#000000" "theme_restart_persist"
            expect_color_value "selected_text" "#FFFFFF" "theme_restart_persist"
            expect_color_value "selected_background" "#AA00FF" "theme_restart_persist"
            expect_color_value "toolbar" "#FFBF00" "theme_restart_persist"
          fi

          ui_apply_high_contrast_preset
        else
          rj_skip "Failed to enable UI virtual input; skipping UI theme automation"
        fi
      else
        rj_skip "systemctl unavailable; skipping UI theme automation"
      fi
    else
      rj_skip "UI theme automation disabled"
    fi

    # Invalid config repair check (normalization + removed dead fields).
    before_mtime="$(file_mtime_epoch "$GUI_CONF")"
    rj_run_cmd "theme_write_invalid_config" write_invalid_theme_config
    restart_ui_service "theme_restart_repair_invalid_config"
    if [[ "$UI_LAST_RESTART_OK" -eq 1 ]]; then
      sleep 1
      after_mtime="$(file_mtime_epoch "$GUI_CONF")"
      if [[ "$after_mtime" -gt "$before_mtime" ]]; then
        rj_ok "theme_repair_rewrites_config (mtime ${before_mtime} -> ${after_mtime})"
      else
        rj_fail "theme_repair_rewrites_config (mtime unchanged: ${before_mtime})"
      fi

      expect_color_value "background" "#000000" "theme_invalid_repair"
      expect_color_value "border" "#8800AA" "theme_invalid_repair"
      expect_color_value "text" "#AA00FF" "theme_invalid_repair"
      expect_color_value "selected_text" "#ABCDEF" "theme_invalid_repair"
      expect_color_value "selected_background" "#330055" "theme_invalid_repair"
      expect_color_value "toolbar" "#0F0F0F" "theme_invalid_repair"

      expect_color_key_absent "gamepad" "theme_removed_dead_field"
      expect_color_key_absent "gamepad_fill" "theme_removed_dead_field"
    fi

    if [[ $RUN_ISOLATION -eq 1 ]]; then
      rj_snapshot_network "theme_post"
      rj_compare_snapshot "theme_pre" "theme_post" "theme_readonly"
    fi
  fi
else
  rj_skip "Theme integration checks disabled"
fi

rj_capture_journal "$UI_SERVICE" "$OUT/journal/${UI_SERVICE}.log"
rj_capture_journal "$DAEMON_SERVICE" "$OUT/journal/${DAEMON_SERVICE}.log"
rj_write_report
rj_log "Theme tests completed. Output: $OUT"
