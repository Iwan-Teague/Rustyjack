#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

RUN_WIRELESS=0
RUN_ETHERNET=0
RUN_ENCRYPTION=0
RUN_LOOT=0
DANGEROUS=0
RUN_UI=1
OUTROOT="${RJ_OUTROOT:-/var/tmp/rustyjack-tests}"
RUN_ID="${RJ_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"

usage() {
  cat <<'USAGE'
Usage: rj_run_tests.sh [options]

Options:
  --all         Run all test suites
  --wireless    Run wireless tests
  --ethernet    Run ethernet tests
  --encryption  Run encryption tests
  --loot        Run loot tests
  --dangerous   Enable dangerous tests (passed to suites)
  --no-ui       Disable UI automation
  --outroot DIR Output root (default: /var/tmp/rustyjack-tests)
  -h, --help    Show help

If no options are provided, a menu will be shown.
USAGE
}

if [[ $# -eq 0 ]]; then
  echo "Select tests:"
  echo "  1) Wireless"
  echo "  2) Ethernet"
  echo "  3) Encryption"
  echo "  4) Loot"
  echo "  0) All"
  read -r choice
  case "$choice" in
    0) RUN_WIRELESS=1; RUN_ETHERNET=1; RUN_ENCRYPTION=1; RUN_LOOT=1 ;;
    1) RUN_WIRELESS=1 ;;
    2) RUN_ETHERNET=1 ;;
    3) RUN_ENCRYPTION=1 ;;
    4) RUN_LOOT=1 ;;
    *) echo "Unknown choice" >&2; exit 2 ;;
  esac
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all) RUN_WIRELESS=1; RUN_ETHERNET=1; RUN_ENCRYPTION=1; RUN_LOOT=1; shift ;;
      --wireless) RUN_WIRELESS=1; shift ;;
      --ethernet) RUN_ETHERNET=1; shift ;;
      --encryption) RUN_ENCRYPTION=1; shift ;;
      --loot) RUN_LOOT=1; shift ;;
      --dangerous) DANGEROUS=1; shift ;;
      --no-ui) RUN_UI=0; shift ;;
      --outroot) OUTROOT="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
    esac
  done
fi

export RJ_OUTROOT="$OUTROOT"
export RJ_RUN_ID="$RUN_ID"

COMMON_ARGS=()
if [[ $RUN_UI -eq 0 ]]; then
  COMMON_ARGS+=(--no-ui)
fi
if [[ $DANGEROUS -eq 1 ]]; then
  COMMON_ARGS+=(--dangerous)
fi

if [[ $RUN_WIRELESS -eq 1 ]]; then
  "$ROOT_DIR/rj_test_wireless.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_ETHERNET -eq 1 ]]; then
  "$ROOT_DIR/rj_test_ethernet.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_ENCRYPTION -eq 1 ]]; then
  "$ROOT_DIR/rj_test_encryption.sh" "${COMMON_ARGS[@]}"
fi
if [[ $RUN_LOOT -eq 1 ]]; then
  "$ROOT_DIR/rj_test_loot.sh" "${COMMON_ARGS[@]}"
fi

echo "Tests complete. Results in: $OUTROOT/$RUN_ID"
