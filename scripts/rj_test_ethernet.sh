#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
DANGEROUS=0
UI_SCENARIO="$ROOT_DIR/ui_scenarios/ethernet.ui"
ETH_IFACE="${RJ_ETH_INTERFACE:-}"  # optional
ETH_TARGET="${RJ_ETH_TARGET:-}"    # optional CIDR or IP
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

rj_run_cmd_capture "eth_discover" "$OUT/artifacts/eth_discover.json" "${cmd_discover[@]}"
rj_run_cmd_capture "eth_portscan" "$OUT/artifacts/eth_portscan.json" "${cmd_portscan[@]}"
rj_run_cmd_capture "eth_inventory" "$OUT/artifacts/eth_inventory.json" "${cmd_inventory[@]}"

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
