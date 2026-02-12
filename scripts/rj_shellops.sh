#!/usr/bin/env bash
set -euo pipefail

if [[ "${RJ_SHELLOPS_LOADED:-0}" == "1" ]]; then
  return 0
fi
RJ_SHELLOPS_LOADED=1

RJ_SHELLOPS_BIN="${RJ_SHELLOPS_BIN:-/usr/local/bin/rustyjack-shellops}"

rj_shellops_has_bin() {
  [[ -x "$RJ_SHELLOPS_BIN" ]]
}

rj_shellops_run() {
  "$RJ_SHELLOPS_BIN" "$@"
}

date() {
  if rj_shellops_has_bin; then
    rj_shellops_run date "$@"
  else
    command date "$@"
  fi
}

sleep() {
  if rj_shellops_has_bin; then
    rj_shellops_run sleep "$@"
  else
    command sleep "$@"
  fi
}

tr() {
  if rj_shellops_has_bin; then
    rj_shellops_run tr "$@"
  else
    command tr "$@"
  fi
}

tee() {
  if rj_shellops_has_bin; then
    rj_shellops_run tee "$@"
  else
    command tee "$@"
  fi
}

timeout() {
  if rj_shellops_has_bin; then
    rj_shellops_run timeout "$@"
  else
    command timeout "$@"
  fi
}

socat() {
  if rj_shellops_has_bin; then
    rj_shellops_run socat "$@"
  else
    command socat "$@"
  fi
}

awk() {
  if rj_shellops_has_bin; then
    rj_shellops_run awk "$@"
  else
    command awk "$@"
  fi
}

rj_sudo_tee() {
  local append=0
  if [[ "${1:-}" == "-a" ]]; then
    append=1
    shift
  fi

  local path="${1:-}"
  if [[ -z "$path" ]]; then
    return 2
  fi

  if [[ "$append" -eq 1 ]]; then
    sudo sh -c "cat >> '$path'"
  else
    sudo sh -c "cat > '$path'"
  fi
}
