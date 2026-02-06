#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0
RUN_RECON=0
UI_SCENARIO="$ROOT_DIR/ui_scenarios/wireless.ui"
WIFI_IFACE="${RJ_WIFI_INTERFACE:-wlan0}"

usage() {
  cat <<'USAGE'
Usage: rj_test_wireless.sh [options]

Options:
  --no-ui             Skip UI automation
  --ui                Enable UI automation (default)
  --ui-scenario PATH  Scenario file (default: scripts/ui_scenarios/wireless.ui)
  --interface IFACE   Wi-Fi interface (default: wlan0)
  --recon             Run recon tests (requires connection)
  --dangerous         Enable offensive tests (requires targets)
  --outroot DIR       Output root (default: /var/tmp/rustyjack-tests)
  -h, --help          Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-ui) RUN_UI=0; shift ;;
    --ui) RUN_UI=1; shift ;;
    --ui-scenario) UI_SCENARIO="$2"; shift 2 ;;
    --interface) WIFI_IFACE="$2"; shift 2 ;;
    --recon) RUN_RECON=1; shift ;;
    --dangerous) DANGEROUS=1; shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "wireless"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

rj_run_cmd_capture "status_network" "$OUT/artifacts/status_network.json" \
  rustyjack status network --output json
rj_run_cmd_capture "hardware_detect" "$OUT/artifacts/hardware_detect.json" \
  rustyjack hardware detect --output json
rj_run_cmd_capture "wifi_list" "$OUT/artifacts/wifi_list.json" \
  rustyjack wifi list --output json
rj_run_cmd_capture "wifi_best" "$OUT/artifacts/wifi_best.json" \
  rustyjack wifi best --prefer-wifi --output json
rj_run_cmd_capture "wifi_status" "$OUT/artifacts/wifi_status.json" \
  rustyjack wifi status --interface "$WIFI_IFACE" --output json
rj_run_cmd_capture "wifi_scan" "$OUT/artifacts/wifi_scan.json" \
  rustyjack wifi scan --interface "$WIFI_IFACE" --output json
rj_run_cmd_capture "wifi_profile" "$OUT/artifacts/wifi_profile.json" \
  rustyjack hardware wifi-profile --interface "$WIFI_IFACE" --output json

if [[ $RUN_RECON -eq 1 ]]; then
  rj_run_cmd_capture "wifi_recon_gateway" "$OUT/artifacts/wifi_recon_gateway.json" \
    rustyjack wifi recon gateway --interface "$WIFI_IFACE" --output json
  rj_run_cmd_capture "wifi_recon_arp" "$OUT/artifacts/wifi_recon_arp.json" \
    rustyjack wifi recon arp-scan --interface "$WIFI_IFACE" --output json
  rj_run_cmd_capture "wifi_recon_service" "$OUT/artifacts/wifi_recon_service.json" \
    rustyjack wifi recon service-scan --interface "$WIFI_IFACE" --output json
fi

if [[ $DANGEROUS -eq 1 ]]; then
  TARGET_BSSID="${RJ_WIFI_TARGET_BSSID:-}"
  TARGET_CHANNEL="${RJ_WIFI_TARGET_CHANNEL:-}"
  MON_IFACE="${RJ_WIFI_MONITOR_IFACE:-}"
  if [[ -z "$TARGET_BSSID" || -z "$TARGET_CHANNEL" || -z "$MON_IFACE" ]]; then
    rj_skip "Dangerous Wi-Fi tests require RJ_WIFI_TARGET_BSSID, RJ_WIFI_TARGET_CHANNEL, RJ_WIFI_MONITOR_IFACE"
  else
    rj_run_cmd_capture "wifi_deauth" "$OUT/artifacts/wifi_deauth.json" \
      rustyjack wifi deauth --bssid "$TARGET_BSSID" --channel "$TARGET_CHANNEL" \
      --interface "$MON_IFACE" --duration 20 --output json
  fi
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
fi

rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd.log"
rj_write_report

rj_log "Wireless tests completed. Output: $OUT"
