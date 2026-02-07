#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0
RUN_UNIT=1
RUN_INTEGRATION=1
RUN_NEGATIVE=1
RUN_ISOLATION=1
RUN_COMPAT=1

UI_SCENARIO="$ROOT_DIR/ui_scenarios/ethernet.ui"
ETH_IFACE="${RJ_ETH_INTERFACE:-}"
ETH_TARGET="${RJ_ETH_TARGET:-}"
ETH_PORTS="${RJ_ETH_PORTS:-}"

usage() {
  cat <<'USAGE'
Usage: rj_test_ethernet.sh [options]

Options:
  --no-ui             Skip UI automation
  --ui                Enable UI automation (default)
  --ui-scenario PATH  Scenario file (default: scripts/ui_scenarios/ethernet.ui)
  --interface IFACE   Ethernet interface override
  --target CIDR|IP    Target network or host
  --ports PORTS       Port list for scan (comma-separated)
  --dangerous         Enable MITM/site-cred pipeline (requires RJ_ETH_SITE)
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
    --interface) ETH_IFACE="$2"; shift 2 ;;
    --target) ETH_TARGET="$2"; shift 2 ;;
    --ports) ETH_PORTS="$2"; shift 2 ;;
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

rj_init "ethernet"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing ethernet failure context..."
  if command -v ip >/dev/null 2>&1; then
    ip -br link show >"$OUT/artifacts/ip_link_fail.txt" 2>&1 || true
    ip -br addr show >"$OUT/artifacts/ip_addr_fail.txt" 2>&1 || true
    ip route show >"$OUT/artifacts/ip_route_fail.txt" 2>&1 || true
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -tunap >"$OUT/artifacts/ss_fail.txt" 2>&1 || true
  fi
  rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd_fail.log"
  rj_capture_journal "rustyjack-portal.service" "$OUT/journal/rustyjack-portal_fail.log"
}
export RJ_FAILURE_HOOK=capture_failure_context

if [[ $RUN_COMPAT -eq 1 ]]; then
  rj_require_cmd ip || true
  rj_run_cmd_capture "ip_link" "$OUT/artifacts/ip_link.txt" ip -br link show
  rj_run_cmd_capture "ip_addr" "$OUT/artifacts/ip_addr.txt" ip -br addr show
  if command -v ss >/dev/null 2>&1; then
    rj_run_cmd_capture "ss_tunap" "$OUT/artifacts/ss_tunap.txt" ss -tunap
  else
    rj_skip "ss not available"
  fi
else
  rj_skip "Compatibility checks disabled"
fi

if [[ $RUN_UNIT -eq 1 ]]; then
  if command -v cargo >/dev/null 2>&1; then
    rj_run_cmd "unit_rustyjack_ethernet" cargo test -p rustyjack-ethernet --lib -- --nocapture
    rj_run_cmd "unit_rustyjack_netlink" cargo test -p rustyjack-netlink --lib -- --nocapture
  else
    rj_skip "cargo not available; skipping unit tests"
  fi
else
  rj_skip "Unit tests disabled"
fi

cmd_discover=(rustyjack ethernet discover --output json)
cmd_inventory=(rustyjack ethernet inventory --output json)
cmd_portscan=(rustyjack ethernet port-scan --output json)

if [[ -n "$ETH_IFACE" ]]; then
  cmd_discover+=(--interface "$ETH_IFACE")
  cmd_inventory+=(--interface "$ETH_IFACE")
  cmd_portscan+=(--interface "$ETH_IFACE")
fi
if [[ -n "$ETH_TARGET" ]]; then
  cmd_discover+=(--target "$ETH_TARGET")
  cmd_inventory+=(--target "$ETH_TARGET")
  cmd_portscan+=(--target "$ETH_TARGET")
fi
if [[ -n "$ETH_PORTS" ]]; then
  cmd_portscan+=(--ports "$ETH_PORTS")
fi

if [[ $RUN_INTEGRATION -eq 1 ]]; then
  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "eth_pre"
  fi

  rj_run_cmd_capture "eth_discover" "$OUT/artifacts/eth_discover.json" "${cmd_discover[@]}"
  rj_run_cmd_capture "eth_portscan" "$OUT/artifacts/eth_portscan.json" "${cmd_portscan[@]}"
  rj_run_cmd_capture "eth_inventory" "$OUT/artifacts/eth_inventory.json" "${cmd_inventory[@]}"

  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "eth_post"
    rj_compare_snapshot "eth_pre" "eth_post" "ethernet_readonly"
  fi
else
  rj_skip "Integration tests disabled"
fi

if [[ $DANGEROUS -eq 1 ]]; then
  ETH_SITE="${RJ_ETH_SITE:-}"
  if [[ -z "$ETH_SITE" ]]; then
    rj_skip "Dangerous Ethernet tests require RJ_ETH_SITE (DNSSpoof site template)"
  else
    cmd_site=(rustyjack ethernet site-cred-capture --site "$ETH_SITE" --output json)
    if [[ -n "$ETH_IFACE" ]]; then
      cmd_site+=(--interface "$ETH_IFACE")
    fi
    if [[ -n "$ETH_TARGET" ]]; then
      cmd_site+=(--target "$ETH_TARGET")
    fi
    rj_run_cmd_capture "eth_site_cred" "$OUT/artifacts/eth_site_cred.json" "${cmd_site[@]}"
  fi
fi

if [[ $RUN_NEGATIVE -eq 1 ]]; then
  BAD_IFACE="${RJ_ETH_BAD_INTERFACE:-rjbad0}"
  rj_run_cmd_capture_allow_fail "eth_discover_bad_iface" "$OUT/artifacts/eth_discover_bad_iface.json" \
    rustyjack ethernet discover --interface "$BAD_IFACE" --output json
  if command -v python3 >/dev/null 2>&1; then
    STATUS_BAD="$(rj_json_get "$OUT/artifacts/eth_discover_bad_iface.json" "status" || true)"
    if [[ "$STATUS_BAD" == "ok" || -z "$STATUS_BAD" ]]; then
      rj_fail "Expected ethernet discover failure for bad interface"
    else
      rj_ok "Bad interface rejected in ethernet discover"
    fi
  else
    rj_skip "python3 not available; skipping JSON validation for bad interface"
  fi

  rj_run_cmd_capture_allow_fail "eth_portscan_bad_target" "$OUT/artifacts/eth_portscan_bad_target.json" \
    rustyjack ethernet port-scan --target "999.999.999.999" --output json
  if command -v python3 >/dev/null 2>&1; then
    STATUS_BAD_TARGET="$(rj_json_get "$OUT/artifacts/eth_portscan_bad_target.json" "status" || true)"
    if [[ "$STATUS_BAD_TARGET" == "ok" || -z "$STATUS_BAD_TARGET" ]]; then
      rj_fail "Expected ethernet port-scan failure for invalid target"
    else
      rj_ok "Invalid target rejected in port-scan"
    fi
  else
    rj_skip "python3 not available; skipping JSON validation for bad target"
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
rj_write_report

rj_log "Ethernet tests completed. Output: $OUT"
