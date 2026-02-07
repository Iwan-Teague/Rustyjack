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
  export RJ_START_TS="${RJ_START_TS:-$(rj_now)}"

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

rj_slug() {
  echo "$*" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+|_+$//g'
}

rj_log() {
  local msg="$*"
  printf '%s %s\n' "$(rj_now)" "$msg" | tee -a "$LOG" >/dev/null
}

rj_prompt_yesno() {
  local prompt="$1"
  local default="${2:-N}"
  if [[ "${RJ_AUTO_INSTALL:-0}" == "1" ]]; then
    return 0
  fi
  if [[ "${RJ_NONINTERACTIVE:-0}" == "1" ]]; then
    return 1
  fi
  if [[ ! -t 0 ]]; then
    return 1
  fi
  local reply
  if [[ "$default" == "Y" ]]; then
    read -r -p "$prompt [Y/n]: " reply
    reply="${reply:-y}"
  else
    read -r -p "$prompt [y/N]: " reply
    reply="${reply:-n}"
  fi
  case "$reply" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

rj_ensure_tool() {
  local tool="$1"
  local pkgs="$2"
  local desc="${3:-$tool}"
  if command -v "$tool" >/dev/null 2>&1; then
    return 0
  fi

  rj_log "[WARN] Missing required tool: $tool ($desc)"
  if ! rj_prompt_yesno "Install $desc now?"; then
    rj_skip "Skipping tests that require $tool"
    return 1
  fi

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    rj_fail "Cannot install $tool without root privileges"
    return 1
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    rj_fail "apt-get not available to install $tool"
    return 1
  fi

  rj_log "[INFO] Installing $desc via apt-get ($pkgs)"
  if ! apt-get update >>"$LOG" 2>&1; then
    rj_fail "apt-get update failed while installing $tool"
    return 1
  fi
  if ! apt-get install -y --no-install-recommends $pkgs >>"$LOG" 2>&1; then
    rj_fail "apt-get install failed for $tool ($pkgs)"
    return 1
  fi
  if command -v "$tool" >/dev/null 2>&1; then
    rj_log "[INFO] Installed $tool successfully"
    return 0
  fi

  rj_fail "Tool $tool still missing after install"
  return 1
}

rj_ok() {
  rj_log "[PASS] $*"
  TESTS_PASS=$((TESTS_PASS + 1))
}

rj_fail() {
  rj_log "[FAIL] $*"
  TESTS_FAIL=$((TESTS_FAIL + 1))
  if [[ -n "${RJ_FAILURE_HOOK:-}" ]]; then
    if declare -F "$RJ_FAILURE_HOOK" >/dev/null 2>&1; then
      "$RJ_FAILURE_HOOK" "$*" || true
    fi
  fi
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

rj_tail_dedup() {
  local file="$1"
  local lines="${2:-${RJ_LOG_TAIL_LINES:-120}}"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  tail -n "$lines" "$file" 2>/dev/null | awk '
    NR==1 { prev=$0; count=1; next }
    $0==prev { count++; next }
    {
      if (count > 1) {
        printf "%s [repeated %dx]\n", prev, count
      } else {
        print prev
      }
      prev=$0
      count=1
    }
    END {
      if (NR>=1) {
        if (count > 1) {
          printf "%s [repeated %dx]\n", prev, count
        } else {
          print prev
        }
      }
    }
  '
}

rj_run_cmd() {
  local name="$1"; shift
  local safe
  safe="$(rj_slug "$name")"
  local outfile="$OUT/artifacts/${safe}.log"
  TESTS_RUN=$((TESTS_RUN + 1))
  rj_log "[CMD] $name :: $* (output: $outfile)"
  if "$@" >"$outfile" 2>&1; then
    rj_ok "$name"
    rj_summary_event "pass" "$name" ""
  else
    local rc=$?
    rj_fail "$name (rc=$rc)"
    rj_log "[TAIL] $name output (deduped)"
    rj_tail_dedup "$outfile" "${RJ_LOG_TAIL_LINES:-120}" | while IFS= read -r line; do
      rj_log "  $line"
    done
    rj_summary_event "fail" "$name" "rc=$rc"
  fi
  return 0
}

rj_run_cmd_capture() {
  local name="$1"; shift
  local outfile="$1"; shift
  TESTS_RUN=$((TESTS_RUN + 1))
  mkdir -p "$(dirname "$outfile")" 2>/dev/null || true
  rj_log "[CMD] $name :: $* (output: $outfile)"
  if "$@" >"$outfile" 2>&1; then
    rj_ok "$name"
    rj_summary_event "pass" "$name" "saved=$outfile"
  else
    local rc=$?
    rj_fail "$name (rc=$rc)"
    rj_log "[TAIL] $name output (deduped)"
    rj_tail_dedup "$outfile" "${RJ_LOG_TAIL_LINES:-120}" | while IFS= read -r line; do
      rj_log "  $line"
    done
    rj_summary_event "fail" "$name" "rc=$rc; saved=$outfile"
  fi
  return 0
}

rj_run_cmd_expect_fail() {
  local name="$1"; shift
  local outfile="$1"; shift
  TESTS_RUN=$((TESTS_RUN + 1))
  mkdir -p "$(dirname "$outfile")" 2>/dev/null || true
  rj_log "[CMD] $name (expect failure) :: $* (output: $outfile)"
  if "$@" >"$outfile" 2>&1; then
    rj_fail "$name succeeded but expected failure"
    rj_summary_event "fail" "$name" "unexpected success"
  else
    rj_ok "$name failed as expected"
    rj_summary_event "pass" "$name" "expected failure"
  fi
  return 0
}

rj_run_cmd_capture_allow_fail() {
  local name="$1"; shift
  local outfile="$1"; shift
  TESTS_RUN=$((TESTS_RUN + 1))
  mkdir -p "$(dirname "$outfile")" 2>/dev/null || true
  rj_log "[CMD] $name (allow fail) :: $* (output: $outfile)"
  if "$@" >"$outfile" 2>&1; then
    rj_log "[CMD] $name exited 0 (allowed)"
    rj_summary_event "info" "$name" "rc=0"
  else
    local rc=$?
    rj_log "[CMD] $name exited rc=$rc (allowed)"
    rj_summary_event "info" "$name" "rc=$rc"
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
    if [[ -n "${RJ_START_TS:-}" ]]; then
      journalctl -u "$unit" --since "$RJ_START_TS" --no-pager >"$outfile" 2>/dev/null || true
    else
      journalctl -u "$unit" --no-pager >"$outfile" 2>/dev/null || true
    fi
  else
    rj_skip "journalctl not available"
  fi
}

rj_json_get() {
  local file="$1"
  local path="$2"
  if ! command -v python3 >/dev/null 2>&1; then
    echo ""
    return 1
  fi
  python3 - "$file" "$path" <<'PY'
import json, sys
path = sys.argv[2].split(".")
try:
    with open(sys.argv[1], "r") as fh:
        data = json.load(fh)
except Exception:
    print("")
    sys.exit(1)
cur = data
for key in path:
    if not key:
        continue
    if isinstance(cur, dict) and key in cur:
        cur = cur[key]
    else:
        cur = None
        break
if cur is None:
    print("")
elif isinstance(cur, bool):
    print("true" if cur else "false")
else:
    print(cur)
PY
}

rj_snapshot_network() {
  local label="$1"
  local outdir="${2:-$OUT/artifacts}"
  mkdir -p "$outdir" 2>/dev/null || true
  if command -v ip >/dev/null 2>&1; then
    ip -br link show >"$outdir/net_${label}_link.txt" 2>&1 || true
    ip -br addr show >"$outdir/net_${label}_addr.txt" 2>&1 || true
    ip route show >"$outdir/net_${label}_route.txt" 2>&1 || true
    ip rule show >"$outdir/net_${label}_rule.txt" 2>&1 || true
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -tunap >"$outdir/net_${label}_ss.txt" 2>&1 || true
  fi
  if [ -f /etc/resolv.conf ]; then
    cat /etc/resolv.conf >"$outdir/net_${label}_resolv.txt" 2>&1 || true
  fi
}

rj_compare_snapshot() {
  local before="$1"
  local after="$2"
  local label="${3:-network}"
  local outdir="${4:-$OUT/artifacts}"
  local changed=0
  local f
  for f in link addr route rule resolv; do
    local a="$outdir/net_${before}_${f}.txt"
    local b="$outdir/net_${after}_${f}.txt"
    if [[ ! -f "$a" || ! -f "$b" ]]; then
      continue
    fi
    if ! diff -u "$a" "$b" >"$outdir/net_${label}_${f}.diff" 2>/dev/null; then
      rj_fail "Isolation check failed: $label ($f changed)"
      rj_log "[DIFF] $outdir/net_${label}_${f}.diff"
      rj_tail_dedup "$outdir/net_${label}_${f}.diff" 80 | while IFS= read -r line; do
        rj_log "  $line"
      done
      changed=1
    fi
  done
  if [[ "$changed" -eq 0 ]]; then
    rj_ok "Isolation check passed: $label"
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
