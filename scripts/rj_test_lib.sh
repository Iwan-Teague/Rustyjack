#!/usr/bin/env bash
set -euo pipefail

rj_now() {
  date -Is
}

rj_init() {
  local suite="$1"
  local outroot="${RJ_OUTROOT:-/var/tmp/rustyjack-tests}"
  local run_id="${RJ_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"

  export RJ_OUTROOT="$outroot"
  export RJ_RUN_ID="$run_id"

  OUT="$outroot/$run_id/$suite"
  LOG="$OUT/run.log"
  SUMMARY="$OUT/summary.jsonl"
  REPORT="$OUT/report.md"

  mkdir -p "$OUT" "$OUT/artifacts" "$OUT/journal"

  TESTS_RUN=0
  TESTS_PASS=0
  TESTS_FAIL=0
  TESTS_SKIP=0

  rj_log "Suite: $suite"
  rj_log "Output: $OUT"
}

rj_log() {
  local msg="$*"
  printf '%s %s\n' "$(rj_now)" "$msg" | tee -a "$LOG" >/dev/null
}

rj_ok() {
  rj_log "[PASS] $*"
  TESTS_PASS=$((TESTS_PASS + 1))
}

rj_fail() {
  rj_log "[FAIL] $*"
  TESTS_FAIL=$((TESTS_FAIL + 1))
}

rj_skip() {
  rj_log "[SKIP] $*"
  TESTS_SKIP=$((TESTS_SKIP + 1))
}

rj_summary_event() {
  local status="$1" name="$2" detail="${3:-}"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY >> "$SUMMARY"
import json
print(json.dumps({"ts": "${RJ_NOW:-$(rj_now)}", "status": "$status", "name": "$name", "detail": "$detail"}))
PY
  else
    printf '%s\n' "{\"ts\":\"$(rj_now)\",\"status\":\"$status\",\"name\":\"$name\",\"detail\":\"$detail\"}" >> "$SUMMARY"
  fi
}

rj_run_cmd() {
  local name="$1"; shift
  TESTS_RUN=$((TESTS_RUN + 1))
  rj_log "[CMD] $name :: $*"
  if "$@" >>"$LOG" 2>&1; then
    rj_ok "$name"
    rj_summary_event "pass" "$name" ""
  else
    local rc=$?
    rj_fail "$name (rc=$rc)"
    rj_summary_event "fail" "$name" "rc=$rc"
  fi
  return 0
}

rj_run_cmd_capture() {
  local name="$1"; shift
  local outfile="$1"; shift
  TESTS_RUN=$((TESTS_RUN + 1))
  rj_log "[CMD] $name :: $*"
  if "$@" >"$outfile" 2>>"$LOG"; then
    rj_ok "$name"
    rj_summary_event "pass" "$name" "saved=$outfile"
  else
    local rc=$?
    rj_fail "$name (rc=$rc)"
    rj_summary_event "fail" "$name" "rc=$rc; saved=$outfile"
  fi
  return 0
}

rj_require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Must run as root (sudo required)" >&2
    exit 1
  fi
}

rj_require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    rj_skip "Missing command: $cmd"
    return 1
  fi
  return 0
}

rj_capture_journal() {
  local unit="$1"
  local outfile="$2"
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u "$unit" --no-pager >"$outfile" 2>/dev/null || true
  else
    rj_skip "journalctl not available"
  fi
}

rj_write_report() {
  cat >"$REPORT" <<EOF
# Rustyjack Test Report

- Run: $RJ_RUN_ID
- Output: $OUT
- Tests: $TESTS_RUN
- Passed: $TESTS_PASS
- Failed: $TESTS_FAIL
- Skipped: $TESTS_SKIP

Artifacts:
- $LOG
- $SUMMARY
- $REPORT
EOF
}

rj_ui_enable() {
  local fifo="${RJ_UI_FIFO:-/run/rustyjack/ui_input.fifo}"
  local dropin_dir="/run/systemd/system/rustyjack-ui.service.d"
  local dropin_file="$dropin_dir/50-virtual-input.conf"

  mkdir -p "$(dirname "$fifo")" || true
  if [[ -e "$fifo" && ! -p "$fifo" ]]; then
    rj_fail "UI fifo exists but is not a FIFO: $fifo"
    return 1
  fi
  if [[ ! -p "$fifo" ]]; then
    mkfifo "$fifo"
  fi
  chown root:rustyjack "$fifo" 2>/dev/null || true
  chmod 0660 "$fifo" 2>/dev/null || true

  mkdir -p "$dropin_dir"
  cat >"$dropin_file" <<EOF
[Service]
Environment=RUSTYJACK_UI_VINPUT=$fifo
EOF

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl restart rustyjack-ui.service
  fi

  export RJ_UI_FIFO="$fifo"
  RJ_UI_ENABLED=1
  sleep "${RJ_UI_BOOT_WAIT:-4}"
  return 0
}

rj_ui_disable() {
  local dropin_file="/run/systemd/system/rustyjack-ui.service.d/50-virtual-input.conf"
  if [[ -n "${RJ_UI_ENABLED:-}" ]]; then
    rm -f "$dropin_file" || true
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload
      systemctl restart rustyjack-ui.service
    fi
    if [[ -n "${RJ_UI_FIFO:-}" ]]; then
      rm -f "$RJ_UI_FIFO" || true
    fi
  fi
}

rj_ui_send() {
  local key="$1"
  local count="${2:-1}"
  local delay="${RJ_UI_DELAY:-0.25}"
  local i=0
  while [[ $i -lt $count ]]; do
    printf '%s\n' "$key" >"$RJ_UI_FIFO"
    sleep "$delay"
    i=$((i + 1))
  done
}

rj_ui_run_scenario() {
  local scenario="$1"
  if [[ ! -f "$scenario" ]]; then
    rj_fail "UI scenario missing: $scenario"
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line%%$'\r'}"
    [[ -z "${line// /}" ]] && continue
    set -- $line
    local cmd="${1:-}"
    local arg="${2:-}"
    cmd="$(printf '%s' "$cmd" | tr 'A-Z' 'a-z')"
    case "$cmd" in
      sleep|wait)
        sleep "$arg"
        ;;
      up|down|left|right|select|key1|key2|key3)
        if [[ -n "$arg" ]]; then
          rj_ui_send "$cmd" "$arg"
        else
          rj_ui_send "$cmd" 1
        fi
        ;;
      *)
        rj_log "[WARN] Unknown scenario command: $cmd"
        ;;
    esac
  done <"$scenario"
}
