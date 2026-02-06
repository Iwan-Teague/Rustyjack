#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
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
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "encryption"
rj_require_root

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

rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd.log"
rj_write_report

rj_log "Encryption tests completed. Output: $OUT"
