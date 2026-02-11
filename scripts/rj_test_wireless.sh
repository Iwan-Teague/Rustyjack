#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0
RUN_RECON=0
RUN_UNIT=1
RUN_INTEGRATION=1
RUN_NEGATIVE=1
RUN_ISOLATION=1
RUN_COMPAT=1

UI_SCENARIO="$ROOT_DIR/ui_scenarios/wireless.ui"
WIFI_IFACE="${RJ_WIFI_INTERFACE:-}"
WIFI_IFACES_RAW="${RJ_WIFI_INTERFACES:-}"
RUN_ALL_IFACES=0
PROFILE_SSID="${RJ_WIFI_TEST_SSID:-RJ_TEST_PROFILE}"
PROFILE_PASS="${RJ_WIFI_TEST_PASS:-testpass123}"
TARGET_BSSID="${RJ_WIFI_TARGET_BSSID:-}"
TARGET_CHANNEL="${RJ_WIFI_TARGET_CHANNEL:-}"
MON_IFACE="${RJ_WIFI_MONITOR_IFACE:-}"
WIFI_IFACES=()

usage() {
  cat <<'USAGE'
Usage: rj_test_wireless.sh [options]

Options:
  --no-ui             Skip UI automation
  --ui                Enable UI automation (default)
  --ui-scenario PATH  Scenario file (default: scripts/ui_scenarios/wireless.ui)
  --interface IFACE   Run tests only on a single Wi-Fi interface
  --interfaces LIST   Comma-separated Wi-Fi interfaces (e.g. wlan0,wlan1)
  --all-interfaces    Auto-detect and test all Wi-Fi interfaces (default when no interface is set)
  --recon             Run recon tests (requires connection)
  --dangerous         Enable offensive tests (requires targets)
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
    --interface) WIFI_IFACE="$2"; RUN_ALL_IFACES=0; shift 2 ;;
    --interfaces) WIFI_IFACES_RAW="$2"; RUN_ALL_IFACES=0; shift 2 ;;
    --all-interfaces) RUN_ALL_IFACES=1; shift ;;
    --recon) RUN_RECON=1; shift ;;
    --dangerous) DANGEROUS=1; shift ;;
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

split_iface_list() {
  local raw="$1"
  printf '%s\n' "$raw" | awk -F'[[:space:],]+' '{for (i = 1; i <= NF; i++) if ($i != "") print $i}'
}

detect_wireless_interfaces() {
  local iface
  local found=0

  if [[ -d /sys/class/net ]]; then
    while IFS= read -r iface; do
      [[ -n "$iface" ]] || continue
      if [[ -d "/sys/class/net/$iface/wireless" ]]; then
        printf '%s\n' "$iface"
        found=1
      fi
    done < <(ls -1 /sys/class/net 2>/dev/null || true)
  fi

  if [[ "$found" -eq 0 ]] && command -v iw >/dev/null 2>&1; then
    iw dev 2>/dev/null | awk '/Interface/ {print $2}'
  fi
}

resolve_wireless_interfaces() {
  local detected=()

  if [[ $RUN_ALL_IFACES -eq 1 ]]; then
    mapfile -t detected < <(detect_wireless_interfaces)
  elif [[ -n "$WIFI_IFACES_RAW" ]]; then
    mapfile -t detected < <(split_iface_list "$WIFI_IFACES_RAW")
  elif [[ -n "$WIFI_IFACE" ]]; then
    detected=("$WIFI_IFACE")
  else
    mapfile -t detected < <(detect_wireless_interfaces)
  fi

  if [[ ${#detected[@]} -eq 0 ]]; then
    WIFI_IFACES=()
    return 0
  fi

  mapfile -t WIFI_IFACES < <(printf '%s\n' "${detected[@]}" | awk 'NF && !seen[$0]++')
}

rj_init "wireless"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

resolve_wireless_interfaces
if [[ ${#WIFI_IFACES[@]} -gt 0 ]]; then
  rj_log "[INFO] Wireless interfaces under test: ${WIFI_IFACES[*]}"
else
  rj_log "[WARN] No wireless interfaces detected"
fi

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  local iface iface_slug
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing wireless failure context..."
  if command -v ip >/dev/null 2>&1; then
    ip -br link show >"$OUT/artifacts/ip_link_fail.txt" 2>&1 || true
    ip -br addr show >"$OUT/artifacts/ip_addr_fail.txt" 2>&1 || true
    ip route show >"$OUT/artifacts/ip_route_fail.txt" 2>&1 || true
  fi
  if command -v iw >/dev/null 2>&1; then
    iw dev >"$OUT/artifacts/iw_dev_fail.txt" 2>&1 || true
    iw list >"$OUT/artifacts/iw_list_fail.txt" 2>&1 || true
  fi
  if command -v rfkill >/dev/null 2>&1; then
    rfkill list >"$OUT/artifacts/rfkill_fail.txt" 2>&1 || true
  fi
  rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd_fail.log"
  rj_capture_journal "rustyjack-ui.service" "$OUT/journal/rustyjack-ui_fail.log"
  if [[ ${#WIFI_IFACES[@]} -eq 0 ]]; then
    if [[ -n "$WIFI_IFACE" ]]; then
      rj_capture_journal "rustyjack-wpa_supplicant@${WIFI_IFACE}.service" \
        "$OUT/journal/rustyjack-wpa_supplicant_fail.log"
    fi
  else
    for iface in "${WIFI_IFACES[@]}"; do
      iface_slug="$(rj_slug "$iface")"
      rj_capture_journal "rustyjack-wpa_supplicant@${iface}.service" \
        "$OUT/journal/rustyjack-wpa_supplicant_${iface_slug}_fail.log"
    done
  fi
}
export RJ_FAILURE_HOOK=capture_failure_context

if [[ $RUN_COMPAT -eq 1 ]]; then
  rj_require_cmd ip || true
  rj_run_cmd_capture "ip_link" "$OUT/artifacts/ip_link.txt" ip -br link show
  rj_run_cmd_capture "ip_addr" "$OUT/artifacts/ip_addr.txt" ip -br addr show
  if command -v iw >/dev/null 2>&1; then
    rj_run_cmd_capture "iw_dev" "$OUT/artifacts/iw_dev.txt" iw dev
    rj_run_cmd_capture "iw_list" "$OUT/artifacts/iw_list.txt" iw list
  else
    rj_skip "iw not available"
  fi
  if command -v rfkill >/dev/null 2>&1; then
    rj_run_cmd_capture "rfkill_list" "$OUT/artifacts/rfkill_list.txt" rfkill list
  else
    rj_skip "rfkill not available"
  fi
  if command -v wpa_cli >/dev/null 2>&1; then
    rj_run_cmd_capture "wpa_cli_version" "$OUT/artifacts/wpa_cli_version.txt" wpa_cli -v
  else
    rj_skip "wpa_cli not available"
  fi
else
  rj_skip "Compatibility checks disabled"
fi

if [[ $RUN_UNIT -eq 1 ]]; then
  if rj_ensure_tool cargo "cargo" "Rust toolchain (unit tests)"; then
    rj_run_cmd "unit_rustyjack_wireless" cargo test -p rustyjack-wireless --lib -- --nocapture
    rj_run_cmd "unit_rustyjack_netlink" cargo test -p rustyjack-netlink --lib -- --nocapture
    rj_run_cmd "unit_rustyjack_wpa" cargo test -p rustyjack-wpa --lib -- --nocapture
  else
    rj_skip "Unit tests skipped (cargo unavailable)"
  fi
else
  rj_skip "Unit tests disabled"
fi

rj_run_cmd_capture "status_network" "$OUT/artifacts/status_network.json" \
  rustyjack status network --output json
rj_run_cmd_capture "hardware_detect" "$OUT/artifacts/hardware_detect.json" \
  rustyjack hardware detect --output json

run_wireless_interface_tests() {
  local iface="$1"
  local iface_slug
  local profile_ssid
  local deauth_iface

  iface_slug="$(rj_slug "$iface")"
  profile_ssid="${PROFILE_SSID}_${iface_slug}"
  rj_log "[INFO] Running wireless interface tests for $iface"

  if [[ $RUN_INTEGRATION -eq 1 ]]; then
    if [[ $RUN_ISOLATION -eq 1 ]]; then
      rj_snapshot_network "wifi_${iface_slug}_pre"
    fi

    rj_run_cmd_capture "wifi_list_${iface_slug}" "$OUT/artifacts/wifi_list_${iface_slug}.json" \
      rustyjack wifi list --output json
    rj_run_cmd_capture "wifi_best_${iface_slug}" "$OUT/artifacts/wifi_best_${iface_slug}.json" \
      rustyjack wifi best --prefer-wifi --output json
    rj_run_cmd_capture "wifi_status_${iface_slug}" "$OUT/artifacts/wifi_status_${iface_slug}.json" \
      rustyjack wifi status --interface "$iface" --output json
    rj_run_cmd_capture "wifi_scan_${iface_slug}" "$OUT/artifacts/wifi_scan_${iface_slug}.json" \
      rustyjack wifi scan --interface "$iface" --output json
    rj_run_cmd_capture "wifi_route_status_${iface_slug}" "$OUT/artifacts/wifi_route_status_${iface_slug}.json" \
      rustyjack wifi route status --output json
    rj_run_cmd_capture "wifi_profile_list_${iface_slug}" "$OUT/artifacts/wifi_profile_list_${iface_slug}.json" \
      rustyjack wifi profile list --output json

    if [[ $RUN_ISOLATION -eq 1 ]]; then
      rj_snapshot_network "wifi_${iface_slug}_post"
      rj_compare_snapshot "wifi_${iface_slug}_pre" "wifi_${iface_slug}_post" "wifi_${iface_slug}_readonly"
    fi

    rj_run_cmd_capture "wifi_profile_save_${iface_slug}" "$OUT/artifacts/wifi_profile_save_${iface_slug}.json" \
      rustyjack wifi profile save --ssid "$profile_ssid" --password "$PROFILE_PASS" --interface "$iface" --priority 5 --output json
    rj_run_cmd_capture "wifi_profile_show_${iface_slug}" "$OUT/artifacts/wifi_profile_show_${iface_slug}.json" \
      rustyjack wifi profile show --ssid "$profile_ssid" --output json
    rj_run_cmd_capture "wifi_profile_delete_${iface_slug}" "$OUT/artifacts/wifi_profile_delete_${iface_slug}.json" \
      rustyjack wifi profile delete --ssid "$profile_ssid" --output json

    rj_run_cmd_capture "wifi_status_after_profile_${iface_slug}" "$OUT/artifacts/wifi_status_after_profile_${iface_slug}.json" \
      rustyjack wifi status --interface "$iface" --output json
  else
    rj_skip "Integration tests disabled (interface $iface)"
  fi

  if [[ $RUN_RECON -eq 1 ]]; then
    rj_run_cmd_capture "wifi_recon_gateway_${iface_slug}" "$OUT/artifacts/wifi_recon_gateway_${iface_slug}.json" \
      rustyjack wifi recon gateway --interface "$iface" --output json
    rj_run_cmd_capture "wifi_recon_arp_${iface_slug}" "$OUT/artifacts/wifi_recon_arp_${iface_slug}.json" \
      rustyjack wifi recon arp-scan --interface "$iface" --output json
    rj_run_cmd_capture "wifi_recon_service_${iface_slug}" "$OUT/artifacts/wifi_recon_service_${iface_slug}.json" \
      rustyjack wifi recon service-scan --interface "$iface" --output json
  fi

  if [[ $DANGEROUS -eq 1 ]]; then
    deauth_iface="${MON_IFACE:-$iface}"
    if [[ -z "$TARGET_BSSID" || -z "$TARGET_CHANNEL" ]]; then
      rj_skip "Dangerous Wi-Fi tests require RJ_WIFI_TARGET_BSSID and RJ_WIFI_TARGET_CHANNEL"
    else
      rj_run_cmd_capture "wifi_deauth_${iface_slug}" "$OUT/artifacts/wifi_deauth_${iface_slug}.json" \
        rustyjack wifi deauth --bssid "$TARGET_BSSID" --channel "$TARGET_CHANNEL" \
        --interface "$deauth_iface" --duration 20 --output json
    fi
  fi
}

if [[ ${#WIFI_IFACES[@]} -eq 0 ]]; then
  rj_skip "No wireless interfaces detected; skipping interface-dependent wireless tests"
else
  for iface in "${WIFI_IFACES[@]}"; do
    run_wireless_interface_tests "$iface"
  done
fi

if [[ $RUN_NEGATIVE -eq 1 ]]; then
  BAD_IFACE="${RJ_WIFI_BAD_INTERFACE:-rjbad0}"
  rj_run_cmd_capture_allow_fail "wifi_status_bad_iface" "$OUT/artifacts/wifi_status_bad_iface.json" \
    rustyjack wifi status --interface "$BAD_IFACE" --output json
  if command -v python3 >/dev/null 2>&1; then
    STATUS_BAD="$(rj_json_get "$OUT/artifacts/wifi_status_bad_iface.json" "status" || true)"
    if [[ "$STATUS_BAD" == "ok" || -z "$STATUS_BAD" ]]; then
      rj_fail "Expected wifi status failure for bad interface"
    else
      rj_ok "Bad interface rejected in wifi status"
    fi
  else
    rj_skip "python3 not available; skipping JSON validation for bad interface"
  fi

  rj_run_cmd_capture_allow_fail "wifi_scan_bad_iface" "$OUT/artifacts/wifi_scan_bad_iface.json" \
    rustyjack wifi scan --interface "$BAD_IFACE" --output json
  if command -v python3 >/dev/null 2>&1; then
    STATUS_SCAN_BAD="$(rj_json_get "$OUT/artifacts/wifi_scan_bad_iface.json" "status" || true)"
    if [[ "$STATUS_SCAN_BAD" == "ok" || -z "$STATUS_SCAN_BAD" ]]; then
      rj_fail "Expected wifi scan failure for bad interface"
    else
      rj_ok "Bad interface rejected in wifi scan"
    fi
  else
    rj_skip "python3 not available; skipping JSON validation for bad scan"
  fi

  rj_run_cmd_capture_allow_fail "wifi_profile_show_missing" "$OUT/artifacts/wifi_profile_show_missing.json" \
    rustyjack wifi profile show --ssid "RJ_MISSING_PROFILE" --output json
  if command -v python3 >/dev/null 2>&1; then
    STATUS_PROFILE_BAD="$(rj_json_get "$OUT/artifacts/wifi_profile_show_missing.json" "status" || true)"
    if [[ "$STATUS_PROFILE_BAD" == "ok" || -z "$STATUS_PROFILE_BAD" ]]; then
      rj_fail "Expected wifi profile show failure for missing profile"
    else
      rj_ok "Missing profile correctly rejected"
    fi
  else
    rj_skip "python3 not available; skipping JSON validation for missing profile"
  fi
else
  rj_skip "Negative tests disabled"
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
if [[ ${#WIFI_IFACES[@]} -eq 0 ]]; then
  if [[ -n "$WIFI_IFACE" ]]; then
    rj_capture_journal "rustyjack-wpa_supplicant@${WIFI_IFACE}.service" \
      "$OUT/journal/rustyjack-wpa_supplicant.log"
  fi
else
  for iface in "${WIFI_IFACES[@]}"; do
    iface_slug="$(rj_slug "$iface")"
    rj_capture_journal "rustyjack-wpa_supplicant@${iface}.service" \
      "$OUT/journal/rustyjack-wpa_supplicant_${iface_slug}.log"
  done
fi
rj_write_report

rj_log "Wireless tests completed. Output: $OUT"
