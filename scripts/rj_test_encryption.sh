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

UI_SCENARIO="$ROOT_DIR/ui_scenarios/encryption.ui"
RJ_ROOT="${RUSTYJACK_ROOT:-/var/lib/rustyjack}"
KEY_PATH="${RJ_ENC_KEY_PATH:-$RJ_ROOT/keys/test.key}"

usage() {
  cat <<'USAGE'
Usage: rj_test_encryption.sh [options]

Options:
  --no-ui             Skip UI automation
  --ui                Enable UI automation (default)
  --ui-scenario PATH  Scenario file (default: scripts/ui_scenarios/encryption.ui)
  --root DIR          Rustyjack root (default: /var/lib/rustyjack)
  --key PATH          Test key path (default: /var/lib/rustyjack/keys/test.key)
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
    --key) KEY_PATH="$2"; shift 2 ;;
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

rj_init "encryption"
rj_require_root

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing encryption failure context..."
  ls -la "$RJ_ROOT" >"$OUT/artifacts/root_ls_fail.txt" 2>&1 || true
  ls -la "$RJ_ROOT/loot" >"$OUT/artifacts/loot_ls_fail.txt" 2>&1 || true
  if [ -f "$RJ_ROOT/gui_conf.json" ]; then
    cp "$RJ_ROOT/gui_conf.json" "$OUT/artifacts/gui_conf_fail.json" 2>/dev/null || true
  fi
  rj_capture_journal "rustyjack-ui.service" "$OUT/journal/rustyjack-ui_fail.log"
  rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd_fail.log"
}
export RJ_FAILURE_HOOK=capture_failure_context

if [[ $RUN_COMPAT -eq 1 ]]; then
  if command -v python3 >/dev/null 2>&1; then
    rj_ok "python3 available"
  else
    rj_skip "python3 not available"
  fi
else
  rj_skip "Compatibility checks disabled"
fi

if ! rj_ensure_tool python3 "python3" "Python 3 (encryption tests)"; then
  rj_write_report
  exit 0
fi

if [[ $RUN_UNIT -eq 1 ]]; then
  if rj_ensure_tool cargo "cargo" "Rust toolchain (unit tests)"; then
    rj_run_cmd "unit_rustyjack_encryption" cargo test -p rustyjack-encryption --lib -- --nocapture
  else
    rj_skip "Unit tests skipped (cargo unavailable)"
  fi
else
  rj_skip "Unit tests disabled"
fi

GUI_CONF="$RJ_ROOT/gui_conf.json"
LOOT_FILE="$RJ_ROOT/loot/Wireless/TestNet/test_loot.txt"
WIFI_PROFILE="$RJ_ROOT/wifi/profiles/test_profile.json"

mkdir -p "$(dirname "$KEY_PATH")" "$(dirname "$LOOT_FILE")" "$(dirname "$WIFI_PROFILE")"

if [[ ! -f "$KEY_PATH" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY >"$KEY_PATH"
import os, binascii
print(binascii.hexlify(os.urandom(32)).decode())
PY
    rj_log "Generated test key: $KEY_PATH"
  else
    rj_fail "python3 required to generate test key"
  fi
fi

if [[ ! -f "$LOOT_FILE" ]]; then
  printf 'rustyjack loot encryption test\n' >"$LOOT_FILE"
fi
if [[ ! -f "$WIFI_PROFILE" ]]; then
  cat >"$WIFI_PROFILE" <<'JSON'
{
  "ssid": "TestNet",
  "password": "testpass",
  "interface": "auto",
  "priority": 1,
  "auto_connect": false
}
JSON
fi

if command -v python3 >/dev/null 2>&1; then
  python3 - <<PY
import json, pathlib
cfg_path = pathlib.Path("$GUI_CONF")
key_path = "$KEY_PATH"
if cfg_path.exists():
    data = json.loads(cfg_path.read_text())
else:
    data = {}
settings = data.get("settings", {})
settings["encryption_key_path"] = key_path
if "encryption_enabled" not in settings:
    settings["encryption_enabled"] = False
if "encrypt_loot" not in settings:
    settings["encrypt_loot"] = False
if "encrypt_wifi_profiles" not in settings:
    settings["encrypt_wifi_profiles"] = False
if "encrypt_discord_webhook" not in settings:
    settings["encrypt_discord_webhook"] = False
data["settings"] = settings
cfg_path.parent.mkdir(parents=True, exist_ok=True)
cfg_path.write_text(json.dumps(data, indent=2))
PY
  rj_log "Updated gui_conf.json encryption_key_path"
else
  rj_fail "python3 required to update gui_conf.json"
fi

if [[ $RUN_INTEGRATION -eq 1 ]]; then
  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "enc_pre"
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
  else
    rj_skip "UI automation disabled"
  fi

  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "enc_post"
    rj_compare_snapshot "enc_pre" "enc_post" "encryption_readonly"
  fi
else
  rj_skip "Integration tests disabled"
fi

# Validate post-conditions (plaintext restored)
if [[ -f "$LOOT_FILE" ]]; then
  rj_ok "Loot plaintext present"
else
  rj_fail "Loot plaintext missing"
fi
if [[ -f "${LOOT_FILE}.enc" ]]; then
  rj_fail "Loot encrypted file still present"
fi
if [[ -f "$WIFI_PROFILE" ]]; then
  rj_ok "Wi-Fi profile plaintext present"
else
  rj_fail "Wi-Fi profile plaintext missing"
fi
if [[ -f "${WIFI_PROFILE}.enc" ]]; then
  rj_fail "Wi-Fi profile encrypted file still present"
fi

if command -v python3 >/dev/null 2>&1; then
  KEY_LEN=$(python3 - <<PY
import pathlib
p = pathlib.Path("$KEY_PATH")
try:
    data = p.read_text().strip()
    print(len(data))
except Exception:
    print(0)
PY
  )
  if [[ "$KEY_LEN" -eq 64 ]]; then
    rj_ok "Encryption key length valid (64 hex chars)"
  else
    rj_fail "Encryption key length invalid: $KEY_LEN"
  fi
else
  rj_skip "python3 not available; skipping key length validation"
fi

if [[ $RUN_NEGATIVE -eq 1 ]]; then
  BAD_KEY="$OUT/artifacts/bad_key.txt"
  printf 'not-hex' >"$BAD_KEY"
  if command -v python3 >/dev/null 2>&1; then
    BAD_LEN=$(python3 - <<PY
import pathlib
p = pathlib.Path("$BAD_KEY")
print(len(p.read_text().strip()))
PY
    )
    if [[ "$BAD_LEN" -ne 64 ]]; then
      rj_ok "Bad key length rejected by validation"
    else
      rj_fail "Bad key length unexpectedly valid"
    fi
  else
    rj_skip "python3 not available; skipping negative key validation"
  fi
else
  rj_skip "Negative tests disabled"
fi

if command -v python3 >/dev/null 2>&1 && [[ -f "$GUI_CONF" ]]; then
  ENCRYPT_ENABLED=$(python3 - <<PY
import json, pathlib
p = pathlib.Path("$GUI_CONF")
try:
    data = json.loads(p.read_text())
except Exception:
    data = {}
settings = data.get("settings", {})
print("true" if settings.get("encryption_enabled") else "false")
PY
  )
  if [[ "$ENCRYPT_ENABLED" == "false" ]]; then
    rj_ok "Encryption disabled after scenario"
  else
    rj_fail "Encryption still enabled after scenario"
  fi
fi

rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd.log"
rj_write_report

rj_log "Encryption tests completed. Output: $OUT"
