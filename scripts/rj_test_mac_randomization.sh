#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

IFACE="${RJ_WIFI_INTERFACE:-wlan0}"
VENDOR="${RJ_MAC_VENDOR:-Apple}"
LOOPS="${RJ_MAC_LOOPS:-5}"
RUN_UNIT=1
RUN_STRESS=1
RUN_NEGATIVE=1
RUN_VENDOR=1
DANGEROUS=0

usage() {
  cat <<'USAGE'
Usage: rj_test_mac_randomization.sh [options]

Options:
  --interface IFACE   Interface to test (default: wlan0)
  --vendor NAME       Vendor name for vendor-MAC test (default: Apple)
  --loops N           Randomize loops for stress test (default: 5)
  --no-unit           Skip Rust unit tests (if cargo available)
  --no-stress         Skip stress/randomize loop
  --no-negative       Skip negative tests (invalid mac/vendor/interface)
  --no-vendor         Skip vendor-MAC test
  --dangerous         Enable extended stress tests
  --no-ui             Ignored (compat with rj_run_tests)
  --ui                Ignored (compat with rj_run_tests)
  --outroot DIR       Output root (default: /var/tmp/rustyjack-tests)
  -h, --help          Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) IFACE="$2"; shift 2 ;;
    --vendor) VENDOR="$2"; shift 2 ;;
    --loops) LOOPS="$2"; shift 2 ;;
    --no-unit) RUN_UNIT=0; shift ;;
    --no-stress) RUN_STRESS=0; shift ;;
    --no-negative) RUN_NEGATIVE=0; shift ;;
    --no-vendor) RUN_VENDOR=0; shift ;;
    --dangerous) DANGEROUS=1; shift ;;
    --no-ui) shift ;;
    --ui) shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$DANGEROUS" -eq 1 ]]; then
  LOOPS="${RJ_MAC_LOOPS_DANGEROUS:-10}"
fi

rj_init "mac_randomization"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

if ! command -v ip >/dev/null 2>&1; then
  rj_skip "Missing command: ip"
  rj_write_report
  exit 0
fi

if [[ ! -e "/sys/class/net/$IFACE/address" ]]; then
  rj_skip "Interface not found: $IFACE"
  rj_write_report
  exit 0
fi

HAVE_PY=0
if command -v python3 >/dev/null 2>&1; then
  HAVE_PY=1
fi

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing failure context..."
  ip link show "$IFACE" >"$OUT/artifacts/ip_link_fail.txt" 2>&1 || true
  ip addr show "$IFACE" >"$OUT/artifacts/ip_addr_fail.txt" 2>&1 || true
  if command -v iw >/dev/null 2>&1; then
    iw dev >"$OUT/artifacts/iw_dev_fail.txt" 2>&1 || true
  fi
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u rustyjackd.service -n 120 --no-pager >"$OUT/journal/rustyjackd.tail.log" 2>/dev/null || true
    journalctl -u "rustyjack-wpa_supplicant@${IFACE}.service" -n 120 --no-pager \
      >"$OUT/journal/rustyjack-wpa_supplicant.tail.log" 2>/dev/null || true
  fi
}

mac_valid() {
  local mac="$1"
  [[ "$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]
}

mac_first_octet() {
  local mac="$1"
  printf '%s' "${mac%%:*}"
}

mac_is_unicast() {
  local mac="$1"
  local octet
  octet=$((16#$(mac_first_octet "$mac")))
  (( (octet & 1) == 0 ))
}

mac_is_local_admin() {
  local mac="$1"
  local octet
  octet=$((16#$(mac_first_octet "$mac")))
  (( (octet & 2) == 2 ))
}

mac_oui() {
  local mac="$1"
  printf '%s' "$(printf '%s' "$mac" | awk -F: '{print toupper($1":"$2":"$3)}')"
}

normalize_mac() {
  printf '%s' "$1" | tr 'A-F' 'a-f'
}

json_get() {
  local file="$1"
  local path="$2"
  if [[ "$HAVE_PY" -ne 1 ]]; then
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

run_cmd_capture_allow_fail() {
  local name="$1"; shift
  local outfile="$1"; shift
  TESTS_RUN=$((TESTS_RUN + 1))
  rj_log "[CMD] $name :: $*"
  if "$@" >"$outfile" 2>>"$LOG"; then
    rj_log "[CMD] $name completed successfully (expected failure may not have occurred)"
    return 0
  else
    local rc=$?
    rj_log "[CMD] $name failed with rc=$rc (captured)"
    return $rc
  fi
}

ORIG_SYS="$(cat "/sys/class/net/$IFACE/address" 2>/dev/null || true)"
if [[ -z "$ORIG_SYS" ]]; then
  rj_fail "Failed to read original MAC from /sys/class/net/$IFACE/address"
  capture_failure_context
  rj_write_report
  exit 0
fi

if ! mac_valid "$ORIG_SYS"; then
  rj_fail "Invalid baseline MAC format: $ORIG_SYS"
  capture_failure_context
fi

rj_run_cmd_capture "wifi_status_baseline" "$OUT/artifacts/wifi_status_baseline.json" \
  rustyjack wifi status --interface "$IFACE" --output json
ip link show "$IFACE" >"$OUT/artifacts/ip_link_baseline.txt" 2>&1 || true
ip addr show "$IFACE" >"$OUT/artifacts/ip_addr_baseline.txt" 2>&1 || true
if command -v iw >/dev/null 2>&1; then
  iw dev >"$OUT/artifacts/iw_dev_baseline.txt" 2>&1 || true
fi

STATUS_ADDR="$(json_get "$OUT/artifacts/wifi_status_baseline.json" "data.address" || true)"
if [[ -n "$STATUS_ADDR" ]]; then
  if [[ "$(normalize_mac "$STATUS_ADDR")" != "$(normalize_mac "$ORIG_SYS")" ]]; then
    rj_fail "Baseline MAC mismatch: sysfs=$ORIG_SYS status=$STATUS_ADDR"
    capture_failure_context
  else
    rj_ok "Baseline MAC matches status output"
  fi
else
  rj_skip "python3 not available; skipping JSON validation"
fi

if [[ "$RUN_UNIT" -eq 1 ]]; then
  if rj_ensure_tool cargo "cargo" "Rust toolchain (unit tests)"; then
    rj_run_cmd "unit_rustyjack_evasion" cargo test -p rustyjack-evasion --lib -- --nocapture
  else
    rj_skip "Unit tests skipped (cargo unavailable)"
  fi
else
  rj_skip "Unit tests disabled"
fi

# --- Integration: randomize MAC ---
rj_run_cmd_capture "mac_randomize" "$OUT/artifacts/mac_randomize.json" \
  rustyjack wifi mac-randomize --interface "$IFACE" --output json

RAND_STATUS="$(json_get "$OUT/artifacts/mac_randomize.json" "status" || true)"
RAND_NEW="$(json_get "$OUT/artifacts/mac_randomize.json" "data.new_mac" || true)"
RAND_ORIG="$(json_get "$OUT/artifacts/mac_randomize.json" "data.original_mac" || true)"
RAND_VENDOR_REUSED="$(json_get "$OUT/artifacts/mac_randomize.json" "data.vendor_reused" || true)"
RAND_RETRY="$(json_get "$OUT/artifacts/mac_randomize.json" "data.retry_used" || true)"

if [[ "$RAND_STATUS" != "ok" ]]; then
  rj_fail "mac-randomize failed (status=$RAND_STATUS)"
  capture_failure_context
else
  rj_ok "mac-randomize returned ok"
fi

if [[ -n "$RAND_NEW" ]]; then
  if ! mac_valid "$RAND_NEW"; then
    rj_fail "Randomized MAC has invalid format: $RAND_NEW"
    capture_failure_context
  fi
  if [[ "$(normalize_mac "$RAND_NEW")" == "$(normalize_mac "$ORIG_SYS")" ]]; then
    rj_fail "Randomized MAC did not change (still $RAND_NEW)"
    capture_failure_context
  else
    rj_ok "Randomized MAC differs from baseline"
  fi
  if ! mac_is_unicast "$RAND_NEW"; then
    rj_fail "Randomized MAC is not unicast: $RAND_NEW"
    capture_failure_context
  else
    rj_ok "Randomized MAC is unicast"
  fi
  if ! mac_is_local_admin "$RAND_NEW"; then
    rj_fail "Randomized MAC not locally administered: $RAND_NEW"
    capture_failure_context
  else
    rj_ok "Randomized MAC is locally administered"
  fi
else
  rj_fail "Randomized MAC missing in JSON output"
  capture_failure_context
fi

RAND_SYS="$(cat "/sys/class/net/$IFACE/address" 2>/dev/null || true)"
if [[ -n "$RAND_SYS" && -n "$RAND_NEW" ]]; then
  if [[ "$(normalize_mac "$RAND_SYS")" != "$(normalize_mac "$RAND_NEW")" ]]; then
    rj_fail "Sysfs MAC does not match randomized MAC (sysfs=$RAND_SYS new=$RAND_NEW)"
    capture_failure_context
  else
    rj_ok "Sysfs MAC matches randomized MAC"
  fi
fi

if [[ "$RAND_VENDOR_REUSED" == "true" && -n "$RAND_ORIG" && -n "$RAND_NEW" ]]; then
  if [[ "$(mac_oui "$RAND_ORIG")" != "$(mac_oui "$RAND_NEW")" ]]; then
    rj_fail "vendor_reused=true but OUI changed (orig=$(mac_oui "$RAND_ORIG") new=$(mac_oui "$RAND_NEW"))"
    capture_failure_context
  else
    rj_ok "vendor_reused=true and OUI preserved"
  fi
fi

if [[ "$RAND_RETRY" == "true" ]]; then
  rj_log "Note: retry_used=true during MAC randomization (interface busy at first attempt)"
fi

rj_run_cmd_capture "wifi_status_after_randomize" "$OUT/artifacts/wifi_status_randomized.json" \
  rustyjack wifi status --interface "$IFACE" --output json

# --- Vendor MAC set ---
if [[ "$RUN_VENDOR" -eq 1 ]]; then
  rj_run_cmd_capture "mac_set_vendor" "$OUT/artifacts/mac_set_vendor.json" \
    rustyjack wifi mac-set-vendor --interface "$IFACE" --vendor "$VENDOR" --output json
  VSTAT="$(json_get "$OUT/artifacts/mac_set_vendor.json" "status" || true)"
  VNEW="$(json_get "$OUT/artifacts/mac_set_vendor.json" "data.new_mac" || true)"
  if [[ "$VSTAT" != "ok" ]]; then
    rj_fail "mac-set-vendor failed (status=$VSTAT vendor=$VENDOR)"
    capture_failure_context
  else
    rj_ok "mac-set-vendor returned ok"
  fi
  if [[ -n "$VNEW" ]]; then
    if ! mac_valid "$VNEW"; then
      rj_fail "Vendor MAC invalid format: $VNEW"
      capture_failure_context
    fi
    if ! mac_is_unicast "$VNEW" || ! mac_is_local_admin "$VNEW"; then
      rj_fail "Vendor MAC not locally administered/unicast: $VNEW"
      capture_failure_context
    else
      rj_ok "Vendor MAC is locally administered + unicast"
    fi
  fi
else
  rj_skip "Vendor MAC test disabled"
fi

# --- Direct MAC set ---
TARGET_OCTET=$(( (16#$(mac_first_octet "$ORIG_SYS") | 2) & 254 ))
TARGET_MAC=$(printf '%02x:%s' "$TARGET_OCTET" "$(printf '%s' "$ORIG_SYS" | cut -d: -f2-5)" )
TARGET_MAC="${TARGET_MAC}:$(printf '%02x' $(( (16#$(printf '%s' "$ORIG_SYS" | awk -F: '{print $6}') + 1) & 255 )))"

rj_run_cmd_capture "mac_set_direct" "$OUT/artifacts/mac_set_direct.json" \
  rustyjack wifi mac-set --interface "$IFACE" --mac "$TARGET_MAC" --output json
DSTAT="$(json_get "$OUT/artifacts/mac_set_direct.json" "status" || true)"
DNEW="$(json_get "$OUT/artifacts/mac_set_direct.json" "data.new_mac" || true)"
if [[ "$DSTAT" != "ok" ]]; then
  rj_fail "mac-set failed (status=$DSTAT target=$TARGET_MAC)"
  capture_failure_context
else
  rj_ok "mac-set returned ok"
fi
if [[ -n "$DNEW" && "$(normalize_mac "$DNEW")" != "$(normalize_mac "$TARGET_MAC")" ]]; then
  rj_fail "mac-set reported different MAC (reported=$DNEW expected=$TARGET_MAC)"
  capture_failure_context
fi

# --- Restore baseline ---
rj_run_cmd_capture "mac_restore" "$OUT/artifacts/mac_restore.json" \
  rustyjack wifi mac-restore --interface "$IFACE" --original-mac "$ORIG_SYS" --output json
RSTAT="$(json_get "$OUT/artifacts/mac_restore.json" "status" || true)"
RNEW="$(json_get "$OUT/artifacts/mac_restore.json" "data.restored_mac" || true)"
if [[ "$RSTAT" != "ok" ]]; then
  rj_fail "mac-restore failed (status=$RSTAT)"
  capture_failure_context
else
  rj_ok "mac-restore returned ok"
fi
RESTORED_SYS="$(cat "/sys/class/net/$IFACE/address" 2>/dev/null || true)"
if [[ -n "$RESTORED_SYS" && "$(normalize_mac "$RESTORED_SYS")" != "$(normalize_mac "$ORIG_SYS")" ]]; then
  rj_fail "MAC not restored to baseline (baseline=$ORIG_SYS current=$RESTORED_SYS)"
  capture_failure_context
else
  rj_ok "MAC restored to baseline"
fi

# --- Stress/randomize loop ---
if [[ "$RUN_STRESS" -eq 1 ]]; then
  rj_log "Starting stress randomization loop: $LOOPS iterations"
  UNIQUE_MACS=()
  i=0
  while [[ $i -lt $LOOPS ]]; do
    out="$OUT/artifacts/mac_randomize_loop_$i.json"
    rj_run_cmd_capture "mac_randomize_loop_$i" "$out" \
      rustyjack wifi mac-randomize --interface "$IFACE" --output json
    nmac="$(json_get "$out" "data.new_mac" || true)"
    if [[ -n "$nmac" ]]; then
      UNIQUE_MACS+=("$(normalize_mac "$nmac")")
      if ! mac_valid "$nmac"; then
        rj_fail "Loop MAC invalid format: $nmac"
        capture_failure_context
      fi
      if ! mac_is_unicast "$nmac" || ! mac_is_local_admin "$nmac"; then
        rj_fail "Loop MAC not locally administered/unicast: $nmac"
        capture_failure_context
      fi
    fi
    i=$((i + 1))
  done
  if [[ "${#UNIQUE_MACS[@]}" -gt 0 ]]; then
    uniq_count=$(printf '%s\n' "${UNIQUE_MACS[@]}" | sort -u | wc -l | tr -d ' ')
    if [[ "$uniq_count" -lt 2 ]]; then
      rj_fail "Stress loop produced insufficient MAC diversity (unique=$uniq_count)"
      capture_failure_context
    else
      rj_ok "Stress loop produced MAC diversity (unique=$uniq_count)"
    fi
  fi
else
  rj_skip "Stress loop disabled"
fi

# --- Negative tests ---
if [[ "$RUN_NEGATIVE" -eq 1 ]]; then
  run_cmd_capture_allow_fail "mac_set_invalid" "$OUT/artifacts/mac_set_invalid.json" \
    rustyjack wifi mac-set --interface "$IFACE" --mac "zz:zz:zz:zz:zz:zz" --output json
  BAD_STAT="$(json_get "$OUT/artifacts/mac_set_invalid.json" "status" || true)"
  if [[ "$BAD_STAT" == "ok" ]]; then
    rj_fail "Invalid MAC unexpectedly accepted"
    capture_failure_context
  else
    rj_ok "Invalid MAC rejected"
  fi

  run_cmd_capture_allow_fail "mac_set_vendor_invalid" "$OUT/artifacts/mac_set_vendor_invalid.json" \
    rustyjack wifi mac-set-vendor --interface "$IFACE" --vendor "NoSuchVendor" --output json
  BAD_VSTAT="$(json_get "$OUT/artifacts/mac_set_vendor_invalid.json" "status" || true)"
  if [[ "$BAD_VSTAT" == "ok" ]]; then
    rj_fail "Invalid vendor unexpectedly accepted"
    capture_failure_context
  else
    rj_ok "Invalid vendor rejected"
  fi

  BAD_IFACE="${RJ_MAC_BAD_INTERFACE:-rjbad0}"
  run_cmd_capture_allow_fail "mac_randomize_invalid_iface" "$OUT/artifacts/mac_randomize_invalid_iface.json" \
    rustyjack wifi mac-randomize --interface "$BAD_IFACE" --output json
  BAD_ISTAT="$(json_get "$OUT/artifacts/mac_randomize_invalid_iface.json" "status" || true)"
  if [[ "$BAD_ISTAT" == "ok" ]]; then
    rj_fail "Invalid interface unexpectedly accepted"
    capture_failure_context
  else
    rj_ok "Invalid interface rejected"
  fi
else
  rj_skip "Negative tests disabled"
fi

# Final restore attempt (best-effort)
rustyjack wifi mac-restore --interface "$IFACE" --original-mac "$ORIG_SYS" --output json \
  >"$OUT/artifacts/mac_restore_final.json" 2>>"$LOG" || true

ip link show "$IFACE" >"$OUT/artifacts/ip_link_final.txt" 2>&1 || true
ip addr show "$IFACE" >"$OUT/artifacts/ip_addr_final.txt" 2>&1 || true
if command -v iw >/dev/null 2>&1; then
  iw dev >"$OUT/artifacts/iw_dev_final.txt" 2>&1 || true
fi

if command -v journalctl >/dev/null 2>&1; then
  journalctl -u rustyjackd.service -n 300 --no-pager >"$OUT/journal/rustyjackd.log" 2>/dev/null || true
  journalctl -u "rustyjack-wpa_supplicant@${IFACE}.service" -n 300 --no-pager \
    >"$OUT/journal/rustyjack-wpa_supplicant.log" 2>/dev/null || true
fi

rj_write_report
cat >>"$REPORT" <<EOF

## MAC Randomization Summary
- Interface: $IFACE
- Baseline MAC (sysfs): $ORIG_SYS
- Vendor test: $(if [[ "$RUN_VENDOR" -eq 1 ]]; then echo "enabled ($VENDOR)"; else echo "disabled"; fi)
- Stress loops: $(if [[ "$RUN_STRESS" -eq 1 ]]; then echo "$LOOPS"; else echo "disabled"; fi)
- Unit tests: $(if [[ "$RUN_UNIT" -eq 1 ]]; then echo "enabled"; else echo "disabled"; fi)
- Negative tests: $(if [[ "$RUN_NEGATIVE" -eq 1 ]]; then echo "enabled"; else echo "disabled"; fi)
EOF

rj_log "MAC randomization tests completed. Output: $OUT"
