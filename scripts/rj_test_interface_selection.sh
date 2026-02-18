#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_UI=1
RUN_NEGATIVE=1
RUN_COMPAT=1
RUN_ISOLATION=1
ALLOW_REMOTE_SWITCH=0

SOCKET="${RJ_DAEMON_SOCKET:-/run/rustyjack/rustyjackd.sock}"
UI_SCENARIO="$ROOT_DIR/ui_scenarios/interface_selection.ui"

WIFI_IFACE="${RJ_WIFI_INTERFACE:-}"
WIFI_IFACES_RAW="${RJ_WIFI_INTERFACES:-}"
WIFI_ALL_IFACES=0
ETH_IFACE="${RJ_ETH_INTERFACE:-}"
ETH_IFACES_RAW="${RJ_ETH_INTERFACES:-}"
ETH_ALL_IFACES=0
RECOVERY_IFACE="${RJ_TEST_RECOVERY_IFACE:-}"
RPC_USER="${RJ_TEST_INTERFACE_RPC_USER:-}"

WIFI_IFACES=()
ETH_IFACES=()
TARGET_IFACES=()

usage() {
  cat <<'USAGE'
Usage: rj_test_interface_selection.sh [options]

Options:
  --no-ui                    Skip UI automation
  --ui                       Enable UI automation (default)
  --ui-scenario PATH         Scenario file (default: scripts/ui_scenarios/interface_selection.ui)
  --socket PATH              Daemon socket path (default: /run/rustyjack/rustyjackd.sock)
  --allow-remote-switch      Allow switching away from SSH uplink (may drop session)
  --dangerous                Alias of --allow-remote-switch
  --recovery-interface IFACE Interface to restore at end (default: active/SSH/default route)
  --wifi-interface IFACE     Single wireless interface under test
  --wifi-interfaces LIST     Comma-separated wireless interfaces under test
  --wifi-all-interfaces      Auto-detect all wireless interfaces under test
  --eth-interface IFACE      Single ethernet interface under test
  --eth-interfaces LIST      Comma-separated ethernet interfaces under test
  --eth-all-interfaces       Auto-detect all ethernet interfaces under test
  --no-negative              Skip negative interface-selection tests
  --no-compat                Skip compatibility/context checks
  --no-isolation             Skip network snapshots
  --outroot DIR              Output root (default: /var/tmp/rustyjack-tests)
  -h, --help                 Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-ui) RUN_UI=0; shift ;;
    --ui) RUN_UI=1; shift ;;
    --ui-scenario) UI_SCENARIO="$2"; shift 2 ;;
    --socket) SOCKET="$2"; shift 2 ;;
    --allow-remote-switch|--dangerous) ALLOW_REMOTE_SWITCH=1; shift ;;
    --recovery-interface) RECOVERY_IFACE="$2"; shift 2 ;;
    --wifi-interface) WIFI_IFACE="$2"; WIFI_ALL_IFACES=0; shift 2 ;;
    --wifi-interfaces) WIFI_IFACES_RAW="$2"; WIFI_ALL_IFACES=0; shift 2 ;;
    --wifi-all-interfaces) WIFI_ALL_IFACES=1; shift ;;
    --eth-interface) ETH_IFACE="$2"; ETH_ALL_IFACES=0; shift 2 ;;
    --eth-interfaces) ETH_IFACES_RAW="$2"; ETH_ALL_IFACES=0; shift 2 ;;
    --eth-all-interfaces) ETH_ALL_IFACES=1; shift ;;
    --no-negative) RUN_NEGATIVE=0; shift ;;
    --no-compat) RUN_COMPAT=0; shift ;;
    --no-isolation) RUN_ISOLATION=0; shift ;;
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

detect_ethernet_interfaces() {
  local iface type

  if [[ ! -d /sys/class/net ]]; then
    return 0
  fi

  while IFS= read -r iface; do
    [[ -n "$iface" ]] || continue
    [[ "$iface" == "lo" ]] && continue
    [[ -e "/sys/class/net/$iface/device" ]] || continue
    [[ -e "/sys/class/net/$iface/type" ]] || continue
    type="$(cat "/sys/class/net/$iface/type" 2>/dev/null || true)"
    [[ "$type" == "1" ]] || continue
    [[ -d "/sys/class/net/$iface/wireless" ]] && continue
    printf '%s\n' "$iface"
  done < <(ls -1 /sys/class/net 2>/dev/null || true)
}

resolve_interface_targets() {
  local detected=()

  if [[ $WIFI_ALL_IFACES -eq 1 ]]; then
    mapfile -t detected < <(detect_wireless_interfaces)
  elif [[ -n "$WIFI_IFACES_RAW" ]]; then
    mapfile -t detected < <(split_iface_list "$WIFI_IFACES_RAW")
  elif [[ -n "$WIFI_IFACE" ]]; then
    detected=("$WIFI_IFACE")
  else
    mapfile -t detected < <(detect_wireless_interfaces)
  fi
  mapfile -t WIFI_IFACES < <(printf '%s\n' "${detected[@]:-}" | awk 'NF && !seen[$0]++')

  detected=()
  if [[ $ETH_ALL_IFACES -eq 1 ]]; then
    mapfile -t detected < <(detect_ethernet_interfaces)
  elif [[ -n "$ETH_IFACES_RAW" ]]; then
    mapfile -t detected < <(split_iface_list "$ETH_IFACES_RAW")
  elif [[ -n "$ETH_IFACE" ]]; then
    detected=("$ETH_IFACE")
  else
    mapfile -t detected < <(detect_ethernet_interfaces)
  fi
  mapfile -t ETH_IFACES < <(printf '%s\n' "${detected[@]:-}" | awk 'NF && !seen[$0]++')

  mapfile -t TARGET_IFACES < <(printf '%s\n' "${ETH_IFACES[@]:-}" "${WIFI_IFACES[@]:-}" | awk 'NF && !seen[$0]++')
}

rj_init "interface_selection"
rj_require_root

run_as_user() {
  local user="$1"
  shift
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$user" -- "$@"
  else
    su -s /bin/sh -c "$(printf '%q ' "$@")" "$user"
  fi
}

resolve_rpc_user() {
  if [[ -n "$RPC_USER" ]]; then
    return 0
  fi
  if [[ -n "${RUSTYJACKD_UI_CLIENT_USER:-}" ]]; then
    RPC_USER="${RUSTYJACKD_UI_CLIENT_USER}"
  fi
  if [[ -z "$RPC_USER" ]] && command -v systemctl >/dev/null 2>&1; then
    local svc_env token
    svc_env="$(systemctl show -p Environment rustyjackd.service 2>/dev/null | sed 's/^Environment=//' || true)"
    if [[ -n "$svc_env" ]]; then
      for token in $svc_env; do
        case "$token" in
          RUSTYJACKD_UI_CLIENT_USER=*)
            RPC_USER="${token#RUSTYJACKD_UI_CLIENT_USER=}"
            break
            ;;
        esac
      done
    fi
  fi
  if [[ -z "$RPC_USER" ]]; then
    RPC_USER="rustyjack-ui"
  fi
  if ! id "$RPC_USER" >/dev/null 2>&1; then
    rj_log "[WARN] RPC user '$RPC_USER' not found; falling back to root"
    RPC_USER="root"
  fi
}

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

resolve_rpc_user
rj_log "[INFO] Interface-selection RPC user: $RPC_USER"

if [[ ! -S "$SOCKET" ]]; then
  rj_fail "Daemon socket not found: $SOCKET"
  rj_write_report
  rj_exit_by_fail_count
fi

resolve_interface_targets

if [[ ${#WIFI_IFACES[@]} -gt 0 ]]; then
  rj_log "[INFO] Wireless interfaces under test: ${WIFI_IFACES[*]}"
else
  rj_log "[WARN] No wireless interfaces detected for this suite"
fi
if [[ ${#ETH_IFACES[@]} -gt 0 ]]; then
  rj_log "[INFO] Ethernet interfaces under test: ${ETH_IFACES[*]}"
else
  rj_log "[WARN] No ethernet interfaces detected for this suite"
fi
if [[ ${#TARGET_IFACES[@]} -eq 0 ]]; then
  rj_fail "No candidate interfaces found for interface-selection tests"
  rj_write_report
  rj_exit_by_fail_count
fi

PY_HELPER="$OUT/artifacts/rj_iface_rpc.py"

generate_rpc_helper() {
  cat >"$PY_HELPER" <<'PYEOF'
#!/usr/bin/env python3
import json
import re
import socket
import struct
import sys
import time
import traceback

if len(sys.argv) != 4:
    print(json.dumps({"ok": False, "error_type": "usage", "error": "usage: rj_iface_rpc.py <socket> <body_type> <req_json>"}))
    sys.exit(1)

SOCKET_PATH = sys.argv[1]
BODY_TYPE = sys.argv[2]
REQ_PATH = sys.argv[3]
PROTOCOL_VERSION = 1
MAX_FRAME_DEFAULT = 1_048_576


def camel_to_snake(value: str) -> str:
    first = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first).lower()


def encode_frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"unexpected EOF (wanted {n}, got {len(buf)})")
        buf += chunk
    return buf


def read_frame(sock: socket.socket, max_frame: int = MAX_FRAME_DEFAULT) -> bytes:
    header = read_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length <= 0:
        raise ValueError(f"invalid frame length: {length}")
    if length > max_frame:
        raise ValueError(f"frame too large: {length} > {max_frame}")
    return read_exact(sock, length)


def handshake(sock: socket.socket) -> dict:
    hello = {
        "protocol_version": PROTOCOL_VERSION,
        "client_name": "rj-iface-test",
        "client_version": "1.0",
        "supports": [],
    }
    sock.sendall(encode_frame(json.dumps(hello, separators=(",", ":")).encode("utf-8")))
    return json.loads(read_frame(sock).decode("utf-8"))


def main() -> int:
    started = time.time()
    result = {"ok": False, "timing_ms": 0}
    try:
        with open(REQ_PATH, "r", encoding="utf-8") as req_fh:
            req_text = req_fh.read().strip()
        data = None if req_text in ("", "null") else json.loads(req_text)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(SOCKET_PATH)

        ack = handshake(sock)
        request_id = int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF
        envelope = {
            "v": PROTOCOL_VERSION,
            "request_id": request_id,
            "endpoint": camel_to_snake(BODY_TYPE),
            "body": {"type": BODY_TYPE},
        }
        if data is not None:
            envelope["body"]["data"] = data

        sock.sendall(encode_frame(json.dumps(envelope, separators=(",", ":")).encode("utf-8")))
        response = json.loads(read_frame(sock).decode("utf-8"))
        sock.close()

        body = response.get("body", {})
        result.update(
            {
                "ok": body.get("type") == "Ok",
                "request_id": request_id,
                "handshake": ack,
                "response": response,
            }
        )
        if body.get("type") == "Err":
            result["error_type"] = "daemon_error"
            result["daemon_error"] = body.get("data")
            result["timing_ms"] = int((time.time() - started) * 1000)
            print(json.dumps(result))
            return 10

        result["timing_ms"] = int((time.time() - started) * 1000)
        print(json.dumps(result))
        return 0
    except Exception as exc:  # noqa: BLE001
        result["error_type"] = "rpc_exception"
        result["error"] = str(exc)
        result["traceback"] = traceback.format_exc()
        result["timing_ms"] = int((time.time() - started) * 1000)
        print(json.dumps(result))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
PYEOF
  chmod 755 "$PY_HELPER"
}

rpc_payload_field() {
  local file="$1"
  local field="$2"
  python3 - "$file" "$field" <<'PY'
import json
import sys

path = sys.argv[2].split(".")
try:
    obj = json.load(open(sys.argv[1], "r", encoding="utf-8"))
    payload = (
        obj.get("response", {})
        .get("body", {})
        .get("data", {})
        .get("data", {})
    )
    cur = payload
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
except Exception:
    print("")
PY
}

rpc_payload_errors_len() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys
try:
    obj = json.load(open(sys.argv[1], "r", encoding="utf-8"))
    payload = (
        obj.get("response", {})
        .get("body", {})
        .get("data", {})
        .get("data", {})
    )
    errors = payload.get("errors", [])
    print(len(errors) if isinstance(errors, list) else 0)
except Exception:
    print(0)
PY
}

rpc_call_capture() {
  local name="$1"
  local body_type="$2"
  local data_json="$3"
  local allow_fail="${4:-0}"
  local req="$OUT/artifacts/${name}.req.json"
  local resp="$OUT/artifacts/${name}.resp.json"

  RJ_RPC_LAST_RC=0
  TESTS_RUN=$((TESTS_RUN + 1))
  printf '%s\n' "$data_json" >"$req"
  rj_log "[RPC] $name :: $body_type (socket=$SOCKET)"

  if run_as_user "$RPC_USER" python3 "$PY_HELPER" "$SOCKET" "$body_type" "$req" >"$resp" 2>>"$LOG"; then
    if [[ "$allow_fail" == "1" ]]; then
      rj_fail "$name succeeded but failure was expected"
      rj_summary_event "fail" "$name" "unexpected success"
      return 0
    fi
    rj_ok "$name"
    rj_summary_event "pass" "$name" "saved=$resp"
    return 0
  fi

  local rc=$?
  RJ_RPC_LAST_RC="$rc"
  if [[ "$allow_fail" == "1" ]]; then
    rj_ok "$name failed as expected (rc=$rc)"
    rj_summary_event "pass" "$name" "expected failure rc=$rc; saved=$resp"
    return 0
  fi

  rj_fail "$name (rc=$rc)"
  rj_log "[TAIL] $name response"
  rj_tail_dedup "$resp" 80 | while IFS= read -r line; do
    rj_log "  $line"
  done
  rj_summary_event "fail" "$name" "rc=$rc; saved=$resp"
  return 0
}

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  local iface iface_slug
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing interface-selection failure context..."
  if command -v ip >/dev/null 2>&1; then
    ip -br link show >"$OUT/artifacts/ip_link_fail.txt" 2>&1 || true
    ip -br addr show >"$OUT/artifacts/ip_addr_fail.txt" 2>&1 || true
    ip route show >"$OUT/artifacts/ip_route_fail.txt" 2>&1 || true
    ip rule show >"$OUT/artifacts/ip_rule_fail.txt" 2>&1 || true
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
  for iface in "${WIFI_IFACES[@]}"; do
    iface_slug="$(rj_slug "$iface")"
    rj_capture_journal "rustyjack-wpa_supplicant@${iface}.service" \
      "$OUT/journal/rustyjack-wpa_supplicant_${iface_slug}_fail.log"
  done
}
export RJ_FAILURE_HOOK=capture_failure_context

generate_rpc_helper

if [[ $RUN_COMPAT -eq 1 ]]; then
  rj_run_cmd_capture "hardware_detect" "$OUT/artifacts/hardware_detect.json" rustyjack hardware detect --output json
  rj_run_cmd_capture "status_network" "$OUT/artifacts/status_network.json" rustyjack status network --output json
  if command -v iw >/dev/null 2>&1; then
    rj_run_cmd_capture "iw_dev" "$OUT/artifacts/iw_dev.txt" iw dev
  else
    rj_skip "iw not available"
  fi
  if command -v rfkill >/dev/null 2>&1; then
    rj_run_cmd_capture "rfkill_list" "$OUT/artifacts/rfkill_list.txt" rfkill list
  else
    rj_skip "rfkill not available"
  fi
else
  rj_skip "Compatibility checks disabled"
fi

rpc_call_capture "active_before" "ActiveInterfaceGet" "null"

ACTIVE_BEFORE="$(rpc_payload_field "$OUT/artifacts/active_before.resp.json" "interface")"
DEFAULT_ROUTE_IFACE="$(ip route show default 2>/dev/null | awk 'NR==1 {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
SSH_IFACE=""
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  SSH_REMOTE_IP="$(echo "$SSH_CONNECTION" | awk '{print $1}')"
  if [[ -n "$SSH_REMOTE_IP" ]]; then
    SSH_IFACE="$(ip route get "$SSH_REMOTE_IP" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  fi
fi

if [[ -z "$RECOVERY_IFACE" ]]; then
  if [[ -n "$ACTIVE_BEFORE" ]]; then
    RECOVERY_IFACE="$ACTIVE_BEFORE"
  elif [[ -n "$SSH_IFACE" ]]; then
    RECOVERY_IFACE="$SSH_IFACE"
  elif [[ -n "$DEFAULT_ROUTE_IFACE" ]]; then
    RECOVERY_IFACE="$DEFAULT_ROUTE_IFACE"
  fi
fi

rj_log "[INFO] Active interface before tests: ${ACTIVE_BEFORE:-<none>}"
rj_log "[INFO] Default route interface before tests: ${DEFAULT_ROUTE_IFACE:-<none>}"
rj_log "[INFO] SSH route interface: ${SSH_IFACE:-<none>}"
rj_log "[INFO] Recovery interface: ${RECOVERY_IFACE:-<none>}"

if [[ -n "$SSH_IFACE" && "$ALLOW_REMOTE_SWITCH" -eq 0 ]]; then
  rj_log "[WARN] Remote guard enabled: non-SSH interface switches will be skipped to protect session"
fi

switch_and_validate() {
  local target="$1"
  local slug active_after status_up errors_len up_count

  slug="$(rj_slug "$target")"

  if [[ -n "$SSH_IFACE" && "$ALLOW_REMOTE_SWITCH" -eq 0 && "$target" != "$SSH_IFACE" ]]; then
    rj_skip "Skipping $target (remote guard active on SSH interface $SSH_IFACE)"
    return 0
  fi

  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "iface_select_${slug}_pre"
  fi

  rpc_call_capture "iface_status_pre_${slug}" "InterfaceStatusGet" "{\"interface\":\"$target\"}" || true
  rpc_call_capture "set_active_${slug}" "SetActiveInterface" "{\"interface\":\"$target\"}"
  if [[ "${RJ_RPC_LAST_RC:-0}" -ne 0 ]]; then
    rj_log "[WARN] Skipping post-switch assertions for $target because SetActiveInterface failed"
    return 0
  fi
  rpc_call_capture "active_after_${slug}" "ActiveInterfaceGet" "null"
  if [[ "${RJ_RPC_LAST_RC:-0}" -ne 0 ]]; then
    rj_log "[WARN] Skipping post-switch assertions for $target because ActiveInterfaceGet failed"
    return 0
  fi
  rpc_call_capture "iface_status_after_${slug}" "InterfaceStatusGet" "{\"interface\":\"$target\"}" || true

  active_after="$(rpc_payload_field "$OUT/artifacts/active_after_${slug}.resp.json" "interface")"
  if [[ "$active_after" == "$target" ]]; then
    rj_ok "active_interface_set_${slug} (active=$active_after)"
  else
    rj_fail "active_interface_set_${slug} (expected=$target actual=${active_after:-<none>})"
  fi

  errors_len="$(rpc_payload_errors_len "$OUT/artifacts/set_active_${slug}.resp.json")"
  if [[ "${errors_len:-0}" -eq 0 ]]; then
    rj_ok "set_active_errors_${slug} (no daemon-reported errors)"
  else
    rj_fail "set_active_errors_${slug} (daemon reported $errors_len errors)"
  fi

  status_up="$(rpc_payload_field "$OUT/artifacts/iface_status_after_${slug}.resp.json" "is_up")"
  if [[ "$status_up" == "true" ]]; then
    rj_ok "target_admin_up_${slug}"
  else
    rj_fail "target_admin_up_${slug} (is_up=${status_up:-unknown})"
  fi

  up_count="$(ip -br link show up 2>/dev/null | awk '$1 != "lo" {count++} END {print count+0}')"
  if [[ "${up_count:-0}" -ge 1 ]]; then
    rj_ok "nonempty_uplink_set_${slug} (up_non_lo=$up_count)"
  else
    rj_fail "nonempty_uplink_set_${slug} (no non-loopback interface is UP)"
  fi

  if [[ $RUN_ISOLATION -eq 1 ]]; then
    rj_snapshot_network "iface_select_${slug}_post"
  fi

  if [[ -n "$RECOVERY_IFACE" && "$target" != "$RECOVERY_IFACE" ]]; then
    rpc_call_capture "restore_${slug}" "SetActiveInterface" "{\"interface\":\"$RECOVERY_IFACE\"}" || return 0
    rpc_call_capture "active_restore_${slug}" "ActiveInterfaceGet" "null" || return 0
    active_after="$(rpc_payload_field "$OUT/artifacts/active_restore_${slug}.resp.json" "interface")"
    if [[ "$active_after" == "$RECOVERY_IFACE" ]]; then
      rj_ok "restore_interface_${slug} (restored=$RECOVERY_IFACE)"
    else
      rj_fail "restore_interface_${slug} (expected=$RECOVERY_IFACE actual=${active_after:-<none>})"
    fi
  fi
}

for iface in "${TARGET_IFACES[@]}"; do
  switch_and_validate "$iface"
done

if [[ $RUN_NEGATIVE -eq 1 ]]; then
  BAD_IFACE="${RJ_BAD_INTERFACE:-rjbad0}"
  rpc_call_capture "set_active_bad_iface" "SetActiveInterface" "{\"interface\":\"$BAD_IFACE\"}" "1"
else
  rj_skip "Negative tests disabled"
fi

if [[ $RUN_UI -eq 1 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    if [[ -f "$UI_SCENARIO" ]]; then
      trap rj_ui_disable EXIT
      if rj_ui_enable; then
        rj_ui_run_scenario "$UI_SCENARIO"
        rj_capture_journal "rustyjack-ui.service" "$OUT/journal/rustyjack-ui.log"
      else
        rj_skip "Failed to enable UI virtual input"
      fi
    else
      rj_skip "UI scenario missing: $UI_SCENARIO"
    fi
  else
    rj_skip "systemctl not available; skipping UI automation"
  fi
fi

rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd.log"
for iface in "${WIFI_IFACES[@]}"; do
  iface_slug="$(rj_slug "$iface")"
  rj_capture_journal "rustyjack-wpa_supplicant@${iface}.service" \
    "$OUT/journal/rustyjack-wpa_supplicant_${iface_slug}.log"
done

rj_write_report
rj_log "Interface-selection tests completed. Output: $OUT"
rj_exit_by_fail_count
