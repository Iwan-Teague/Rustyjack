#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
RUN_CONNECTIVITY=1
RUNTIME_ROOT="${RUSTYJACK_ROOT:-/var/lib/rustyjack}"
WEBHOOK_FILE=""

usage() {
  cat <<'USAGE'
Usage: rj_test_discord.sh [options]

Options:
  --ui                 Require UI mode (default)
  --no-ui              Disable UI mode (this suite fails when disabled)
  --runtime-root DIR   Runtime root (default: /var/lib/rustyjack)
  --webhook-file PATH  Explicit webhook file path (default: <runtime-root>/discord_webhook.txt)
  --no-connectivity    Skip live webhook send and only validate local config
  --outroot DIR        Output root (default: /var/tmp/rustyjack-tests)
  -h, --help           Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ui) RUN_UI=1; shift ;;
    --no-ui) RUN_UI=0; shift ;;
    --runtime-root) RUNTIME_ROOT="${2%/}"; shift 2 ;;
    --webhook-file) WEBHOOK_FILE="$2"; shift 2 ;;
    --no-connectivity) RUN_CONNECTIVITY=0; shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$WEBHOOK_FILE" ]]; then
  WEBHOOK_FILE="${RUNTIME_ROOT%/}/discord_webhook.txt"
fi

rj_init "discord_webhook"
rj_require_root

if [[ $RUN_UI -ne 1 ]]; then
  rj_fail "discord_webhook_requires_ui (--ui)"
  rj_write_report
  rj_exit_by_fail_count
fi

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

rj_log "[INFO] Runtime root: $RUNTIME_ROOT"
rj_log "[INFO] Webhook file: $WEBHOOK_FILE"

if command -v systemctl >/dev/null 2>&1; then
  rj_run_cmd_capture "ui_service_active" "$OUT/artifacts/ui_service_active.txt" \
    systemctl is-active rustyjack-ui.service
  if grep -qi '^active$' "$OUT/artifacts/ui_service_active.txt"; then
    rj_ok "ui_service_running"
  else
    rj_fail "ui_service_running"
  fi
else
  rj_skip "systemctl not available; cannot verify UI service state"
fi

if [[ ! -f "$WEBHOOK_FILE" ]]; then
  rj_fail "webhook_file_missing ($WEBHOOK_FILE)"
else
  WEBHOOK_LINE="$(sed -n '1p' "$WEBHOOK_FILE" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$WEBHOOK_LINE" == https://discord.com/api/webhooks/* ]]; then
    rj_ok "webhook_file_format_valid"
  else
    rj_fail "webhook_file_format_invalid"
  fi
fi

rj_run_cmd_capture "discord_status" "$OUT/artifacts/discord_status.json" \
  rustyjack notify discord status --output json
DISCORD_STATUS="$(rj_json_get "$OUT/artifacts/discord_status.json" "status" || true)"
DISCORD_CONFIGURED="$(rj_json_get "$OUT/artifacts/discord_status.json" "data.configured" || true)"
if [[ "$DISCORD_STATUS" == "ok" && "$DISCORD_CONFIGURED" == "true" ]]; then
  rj_ok "discord_status_configured"
else
  rj_fail "discord_status_configured"
fi

if [[ $RUN_CONNECTIVITY -eq 1 ]]; then
  TS="$(date -Is)"
  HOST="$(hostname 2>/dev/null || echo unknown)"
  TITLE="Rustyjack Discord Webhook Preflight"
  MESSAGE="Timestamp: ${TS}; Host: ${HOST}; Run: ${RJ_RUN_ID}; Suite: discord_webhook"

  rj_run_cmd_capture "discord_send_test_message" "$OUT/artifacts/discord_send_test_message.json" \
    rustyjack notify discord send --title "$TITLE" --message "$MESSAGE" --output json

  SEND_STATUS="$(rj_json_get "$OUT/artifacts/discord_send_test_message.json" "status" || true)"
  SEND_OK="$(rj_json_get "$OUT/artifacts/discord_send_test_message.json" "data.sent" || true)"
  if [[ "$SEND_STATUS" == "ok" && "$SEND_OK" == "true" ]]; then
    rj_ok "discord_send_succeeded"
  else
    rj_fail "discord_send_succeeded"
  fi
else
  rj_skip "Connectivity send disabled"
fi

rj_write_report
rj_log "Discord webhook tests completed. Output: $OUT"
rj_exit_by_fail_count
