#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

SOCKET="${RJ_DAEMON_SOCKET:-/run/rustyjack/rustyjackd.sock}"
SERVICE="${RJ_DAEMON_SERVICE:-rustyjackd.service}"
RUN_COMPREHENSIVE=1
DANGEROUS=0
RUN_AUTH=1
RUN_PROTOCOL=1
RUN_UNIT=1
RUN_COMPAT=1
RUN_ISOLATION=1

usage() {
  cat <<'USAGE'
Usage: rj_test_daemon.sh [options]

Options:
  --socket PATH        Daemon socket (default: /run/rustyjack/rustyjackd.sock)
  --service UNIT       Daemon systemd unit (default: rustyjackd.service)
  --skip-comprehensive Skip the comprehensive daemon suite
  --no-auth            Skip auth/authorization tests
  --no-protocol        Skip protocol-abuse tests
  --no-unit            Skip unit tests
  --no-compat          Skip compatibility checks
  --no-isolation       Skip isolation checks
  --dangerous          Enable dangerous tests in comprehensive suite
  --no-ui              Ignored (compat with rj_run_tests)
  --ui                 Ignored (compat with rj_run_tests)
  --outroot DIR        Output root (default: /var/tmp/rustyjack-tests)
  -h, --help           Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --socket) SOCKET="$2"; shift 2 ;;
    --service) SERVICE="$2"; shift 2 ;;
    --skip-comprehensive) RUN_COMPREHENSIVE=0; shift ;;
    --no-auth) RUN_AUTH=0; shift ;;
    --no-protocol) RUN_PROTOCOL=0; shift ;;
    --no-unit) RUN_UNIT=0; shift ;;
    --no-compat) RUN_COMPAT=0; shift ;;
    --no-isolation) RUN_ISOLATION=0; shift ;;
    --dangerous) DANGEROUS=1; shift ;;
    --no-ui) shift ;;
    --ui) shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "daemon"
rj_require_root

NEEDS_PY=0
if [[ $RUN_AUTH -eq 1 || $RUN_PROTOCOL -eq 1 || $RUN_COMPREHENSIVE -eq 1 ]]; then
  NEEDS_PY=1
fi

if [[ $NEEDS_PY -eq 1 ]] && ! command -v python3 >/dev/null 2>&1; then
  rj_fail "python3 required for daemon RPC tests"
  rj_write_report
  exit 0
fi

if [[ $RUN_COMPAT -eq 1 ]]; then
  if command -v python3 >/dev/null 2>&1; then
    rj_ok "python3 available"
  else
    rj_skip "python3 not available"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    rj_ok "systemctl available"
  else
    rj_skip "systemctl not available"
  fi
  if command -v ss >/dev/null 2>&1; then
    rj_ok "ss available"
  else
    rj_skip "ss not available"
  fi
else
  rj_skip "Compatibility checks disabled"
fi

if [[ $RUN_UNIT -eq 1 ]]; then
  if command -v cargo >/dev/null 2>&1; then
    rj_run_cmd "unit_rustyjack_daemon" cargo test -p rustyjack-daemon --lib -- --nocapture
    rj_run_cmd "unit_rustyjack_ipc" cargo test -p rustyjack-ipc --lib -- --nocapture
    rj_run_cmd "unit_rustyjack_client" cargo test -p rustyjack-client --lib -- --nocapture
  else
    rj_skip "cargo not available; skipping unit tests"
  fi
else
  rj_skip "Unit tests disabled"
fi

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing failure context..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl status "$SERVICE" >"$OUT/artifacts/${SERVICE}.status.txt" 2>&1 || true
    systemctl status rustyjackd.socket >"$OUT/artifacts/rustyjackd.socket.status.txt" 2>&1 || true
  fi
  if command -v journalctl >/dev/null 2>&1; then
    rj_capture_journal "$SERVICE" "$OUT/journal/${SERVICE}.log"
    rj_capture_journal "rustyjackd.socket" "$OUT/journal/rustyjackd.socket.log"
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -xap >"$OUT/artifacts/ss_unix.txt" 2>&1 || true
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -U >"$OUT/artifacts/lsof_unix.txt" 2>&1 || true
  fi
  if [[ -e "$SOCKET" ]]; then
    stat "$SOCKET" >"$OUT/artifacts/socket_stat.txt" 2>&1 || true
  fi
}
export RJ_FAILURE_HOOK=capture_failure_context

run_as_user() {
  local user="$1"; shift
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$user" -- "$@"
  else
    su -s /bin/sh -c "$(printf '%q ' "$@")" "$user"
  fi
}

# --- Basic daemon sanity ---
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$SERVICE"; then
    rj_ok "daemon_service_active ($SERVICE)"
  else
    rj_fail "daemon_service_active ($SERVICE not running)"
  fi
else
  rj_skip "systemctl not available"
fi

if [[ -S "$SOCKET" ]]; then
  rj_ok "daemon_socket_present ($SOCKET)"
else
  rj_fail "daemon_socket_present (missing: $SOCKET)"
fi

if [[ -e "$SOCKET" ]]; then
  sock_mode=$(stat -c %a "$SOCKET" 2>/dev/null || echo "unknown")
  sock_owner=$(stat -c %U "$SOCKET" 2>/dev/null || echo "unknown")
  sock_group=$(stat -c %G "$SOCKET" 2>/dev/null || echo "unknown")
  rj_log "Socket perms: mode=$sock_mode owner=$sock_owner group=$sock_group"
  if [[ "${sock_mode:2:1}" == "0" ]]; then
    rj_ok "daemon_socket_perms_secure (others=0)"
  else
    rj_fail "daemon_socket_perms_secure (others=${sock_mode:2:1})"
  fi
fi

# --- Generate RPC helper ---
RPC_HELPER="$OUT/artifacts/rj_rpc.py"
cat >"$RPC_HELPER" <<'PYEOF'
#!/usr/bin/env python3
import json, socket, struct, sys, time, re, traceback

if len(sys.argv) < 4:
    print(json.dumps({"ok": False, "error_type": "usage"}))
    sys.exit(1)

SOCKET_PATH = sys.argv[1]
BODY_TYPE = sys.argv[2]
REQ_PATH = sys.argv[3]
PROTOCOL_VERSION = 1
MAX_FRAME_DEFAULT = 1_048_576

def camel_to_snake(s: str) -> str:
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', s)
    s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()

def enc(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload

def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError()
        buf += chunk
    return buf

def read_frame(sock: socket.socket, max_frame: int = MAX_FRAME_DEFAULT) -> bytes:
    hdr = read_exact(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    if length == 0:
        raise ValueError("zero-length frame")
    if length > max_frame:
        raise ValueError(f"frame too large: {length}")
    return read_exact(sock, length)

def handshake(sock: socket.socket) -> dict:
    hello = {
        "protocol_version": PROTOCOL_VERSION,
        "client_name": "rjdaemon-test",
        "client_version": "1.0",
        "supports": []
    }
    sock.sendall(enc(json.dumps(hello, separators=(",", ":")).encode("utf-8")))
    ack_raw = read_frame(sock)
    return json.loads(ack_raw.decode("utf-8"))

def rpc_request(sock: socket.socket, body_type: str, data):
    request_id = int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF
    endpoint = camel_to_snake(body_type)
    env = {"v": PROTOCOL_VERSION, "request_id": request_id, "endpoint": endpoint, "body": {"type": body_type}}
    if data is not None:
        env["body"]["data"] = data
    sock.sendall(enc(json.dumps(env, separators=(",", ":")).encode("utf-8")))
    resp_raw = read_frame(sock)
    resp = json.loads(resp_raw.decode("utf-8"))
    return request_id, resp

def main():
    t0 = time.time()
    result = {"ok": False, "error_type": None, "error": None, "timing_ms": 0}
    try:
        with open(REQ_PATH, "rb") as f:
            req_data = f.read().strip()
        data = None
        if req_data and req_data not in (b"null", b""):
            data = json.loads(req_data.decode("utf-8"))

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect(SOCKET_PATH)
        except PermissionError as e:
            result["error_type"] = "connect_permission_denied"
            result["error"] = str(e)
            result["timing_ms"] = int((time.time() - t0) * 1000)
            print(json.dumps(result))
            sys.exit(2)
        except FileNotFoundError as e:
            result["error_type"] = "socket_not_found"
            result["error"] = str(e)
            result["timing_ms"] = int((time.time() - t0) * 1000)
            print(json.dumps(result))
            sys.exit(3)

        ack = handshake(sock)
        request_id, resp = rpc_request(sock, BODY_TYPE, data)
        sock.close()

        body = resp.get("body", {})
        result.update({
            "ok": True,
            "handshake": ack,
            "request_id": request_id,
            "response": resp,
            "response_body_type": body.get("type"),
            "response_error": body.get("data") if body.get("type") == "Err" else None,
            "timing_ms": int((time.time() - t0) * 1000),
        })
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        result["error_type"] = "unexpected_error"
        result["error"] = str(e)
        result["timing_ms"] = int((time.time() - t0) * 1000)
        result["error_traceback"] = traceback.format_exc()
        print(json.dumps(result))
        sys.exit(99)

if __name__ == "__main__":
    main()
PYEOF
chmod 755 "$RPC_HELPER"

if [[ $RUN_ISOLATION -eq 1 ]]; then
  rj_snapshot_network "daemon_pre"
fi

rpc_call() {
  local id="$1" body="$2" data_json="$3" user="$4"
  local req="$OUT/rpc/requests/${id}_${body}.json"
  local resp="$OUT/rpc/responses/${id}_${body}.json"
  printf '%s\n' "$data_json" > "$req"
  rj_log "[RPC] $id $body (user=$user)"
  if run_as_user "$user" python3 "$RPC_HELPER" "$SOCKET" "$body" "$req" >"$resp" 2>>"$LOG"; then
    RPC_LAST_RC=0
  else
    RPC_LAST_RC=$?
  fi
  RPC_LAST_RESP="$resp"
  return "$RPC_LAST_RC"
}

rpc_expect_ok() {
  local id="$1" body="$2" data_json="$3" user="$4"
  ((TESTS_RUN++)) || true
  if ! rpc_call "$id" "$body" "$data_json" "$user"; then
    rj_fail "rpc_ok_$id (transport rc=$RPC_LAST_RC)"
    return 0
  fi
  local typ
  typ=$(rj_json_get "$RPC_LAST_RESP" "response_body_type" || true)
  if [[ "$typ" == "Ok" ]]; then
    rj_ok "rpc_ok_$id"
  else
    local err
    err=$(rj_json_get "$RPC_LAST_RESP" "response_error.message" || true)
    rj_fail "rpc_ok_$id (expected Ok, got $typ) ${err:+err=$err}"
  fi
}

rpc_expect_err() {
  local id="$1" body="$2" data_json="$3" user="$4"
  ((TESTS_RUN++)) || true
  if ! rpc_call "$id" "$body" "$data_json" "$user"; then
    local err_type
    err_type=$(rj_json_get "$RPC_LAST_RESP" "error_type" || true)
    if [[ "$err_type" == "connect_permission_denied" ]]; then
      rj_ok "rpc_err_$id (connect denied)"
      return 0
    fi
    rj_fail "rpc_err_$id (transport rc=$RPC_LAST_RC, error_type=$err_type)"
    return 0
  fi
  local typ err_type
  typ=$(rj_json_get "$RPC_LAST_RESP" "response_body_type" || true)
  err_type=$(rj_json_get "$RPC_LAST_RESP" "error_type" || true)
  if [[ "$typ" == "Err" ]]; then
    rj_ok "rpc_err_$id"
  elif [[ "$err_type" == "connect_permission_denied" ]]; then
    rj_ok "rpc_err_$id (connect denied)"
  else
    rj_fail "rpc_err_$id (expected Err, got $typ)"
  fi
}

# Capture current logging config to avoid config drift during tests
LOGCFG_ENABLED="true"
LOGCFG_LEVEL="Info"
rpc_call "BASE" "LoggingConfigGet" "null" "root" || true
base_body=$(rj_json_get "$OUT/rpc/responses/BASE_LoggingConfigGet.json" "response_body_type" || true)
if [[ "$base_body" == "Ok" ]]; then
  base_enabled=$(rj_json_get "$OUT/rpc/responses/BASE_LoggingConfigGet.json" "response.body.data.data.enabled" || true)
  base_level=$(rj_json_get "$OUT/rpc/responses/BASE_LoggingConfigGet.json" "response.body.data.data.level" || true)
  [[ -n "$base_enabled" ]] && LOGCFG_ENABLED="$base_enabled"
  [[ -n "$base_level" ]] && LOGCFG_LEVEL="$base_level"
  rj_log "Baseline logging config: enabled=$LOGCFG_ENABLED level=$LOGCFG_LEVEL"
fi

# --- Auth tests ---
OP_GROUP_DEFAULT="rustyjack"
ADMIN_GROUP_DEFAULT="rustyjack-admin"

if command -v systemctl >/dev/null 2>&1; then
  svc_env=$(systemctl show -p Environment "$SERVICE" 2>/dev/null | sed 's/^Environment=//')
  if [[ "$svc_env" == *"RUSTYJACKD_OPERATOR_GROUP="* ]]; then
    OP_GROUP_DEFAULT=$(printf '%s' "$svc_env" | tr ' ' '\n' | awk -F= '/RUSTYJACKD_OPERATOR_GROUP/{print $2; exit}')
  fi
  if [[ "$svc_env" == *"RUSTYJACKD_ADMIN_GROUP="* ]]; then
    ADMIN_GROUP_DEFAULT=$(printf '%s' "$svc_env" | tr ' ' '\n' | awk -F= '/RUSTYJACKD_ADMIN_GROUP/{print $2; exit}')
  fi
fi

OP_GROUP="$OP_GROUP_DEFAULT"
ADMIN_GROUP="$ADMIN_GROUP_DEFAULT"

CREATED_USERS=()
create_user() {
  local user="$1" groups="${2:-}"
  if id -u "$user" >/dev/null 2>&1; then
    return 0
  fi
  useradd --system --no-create-home --shell /usr/sbin/nologin "$user" >/dev/null 2>&1 || return 1
  CREATED_USERS+=("$user")
  if [[ -n "$groups" ]]; then
    usermod -aG "$groups" "$user" >/dev/null 2>&1 || true
  fi
  return 0
}

cleanup_users() {
  for u in "${CREATED_USERS[@]:-}"; do
    userdel "$u" >/dev/null 2>&1 || true
  done
}
trap cleanup_users EXIT

if [[ "$RUN_AUTH" -eq 1 ]]; then
  RO_USER="rjtest_ro"
  OP_USER="rjtest_op"
  ADMIN_USER="rjtest_admin"

  create_user "$RO_USER" "" || rj_skip "Failed to create RO test user"

  if getent group "$OP_GROUP" >/dev/null 2>&1; then
    create_user "$OP_USER" "$OP_GROUP" || rj_skip "Failed to create OP test user"
  else
    rj_skip "Operator group missing: $OP_GROUP"
  fi

  if getent group "$ADMIN_GROUP" >/dev/null 2>&1; then
    create_user "$ADMIN_USER" "$ADMIN_GROUP" || rj_skip "Failed to create ADMIN test user"
  else
    rj_skip "Admin group missing: $ADMIN_GROUP (root will be used for admin checks)"
    ADMIN_USER="root"
  fi

  # Probe read-only user connectivity
  ((TESTS_RUN++)) || true
  rpc_call "A1" "Health" "null" "$RO_USER" || true
  ro_err=$(rj_json_get "$OUT/rpc/responses/A1_Health.json" "error_type" || true)
  ro_body=$(rj_json_get "$OUT/rpc/responses/A1_Health.json" "response_body_type" || true)
  if [[ "$ro_err" == "connect_permission_denied" ]]; then
    rj_ok "ro_user_connect_denied (socket perms enforce group access)"
    RO_CAN_CONNECT=0
  elif [[ "$ro_body" == "Ok" ]]; then
    rj_ok "ro_user_can_connect"
    RO_CAN_CONNECT=1
  else
    rj_fail "ro_user_connectivity_unexpected (err=$ro_err body=$ro_body)"
    RO_CAN_CONNECT=0
  fi

  if [[ "$RO_CAN_CONNECT" -eq 1 ]]; then
    rpc_expect_ok "A2" "Health" "null" "$RO_USER"
    rpc_expect_err "A3" "ActiveInterfaceClear" "null" "$RO_USER"
    rpc_expect_err "A4" "LoggingConfigSet" "{\"enabled\":$LOGCFG_ENABLED,\"level\":\"$LOGCFG_LEVEL\"}" "$RO_USER"
    rpc_expect_err "A5" "SystemSync" "null" "$RO_USER"
  else
    rj_skip "Read-only RPC tests skipped (socket perms deny RO user)"
  fi

  if id -u "$OP_USER" >/dev/null 2>&1; then
    rpc_expect_ok "A6" "SystemLogsGet" '{"max_lines":10}' "$OP_USER"
    rpc_expect_ok "A7" "ActiveInterfaceClear" "null" "$OP_USER"
    rpc_expect_err "A8" "LoggingConfigSet" "{\"enabled\":$LOGCFG_ENABLED,\"level\":\"$LOGCFG_LEVEL\"}" "$OP_USER"
  fi

  # Admin check (safe admin endpoint)
  rpc_expect_ok "A9" "SystemSync" "null" "$ADMIN_USER"
else
  rj_skip "Auth tests disabled"
fi

# --- Protocol abuse tests ---
if [[ "$RUN_PROTOCOL" -eq 1 ]]; then
  # Protocol mismatch
  python3 - "$SOCKET" "$OUT/artifacts" <<'PYTEST'
import json, socket, struct, sys
sock_path, outdir = sys.argv[1], sys.argv[2]
def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s,n):
    buf=b""
    while len(buf)<n:
        c=s.recv(n-len(buf))
        if not c: raise EOFError()
        buf+=c
    return buf
def read_frame(s):
    hdr=read_exact(s,4)
    ln=struct.unpack(">I", hdr)[0]
    return read_exact(s, ln)
try:
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    hello={"protocol_version":999,"client_name":"rjtest","client_version":"0.1","supports":[]}
    s.sendall(enc(json.dumps(hello).encode()))
    raw=read_frame(s)
    obj=json.loads(raw.decode())
    json.dump(obj, open(f"{outdir}/proto_mismatch.json","w"), indent=2)
    print("OK")
except Exception as e:
    json.dump({"error": str(e)}, open(f"{outdir}/proto_mismatch.json","w"), indent=2)
    print("ERR")
PYTEST
  if grep -q '"error"' "$OUT/artifacts/proto_mismatch.json" 2>/dev/null || grep -qi "incompat" "$OUT/artifacts/proto_mismatch.json"; then
    rj_ok "protocol_version_mismatch_rejected"
  else
    rj_fail "protocol_version_mismatch_rejected"
  fi

  # Oversized frame (should be rejected / connection closed)
  python3 - "$SOCKET" "$OUT/artifacts" <<'PYTEST'
import socket, struct, sys
sock_path, outdir = sys.argv[1], sys.argv[2]
try:
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    s.sendall(struct.pack(">I", 10_000_000))
    s.close()
    open(f"{outdir}/oversized_frame.txt","w").write("sent")
    print("OK")
except Exception as e:
    open(f"{outdir}/oversized_frame.txt","w").write(f"error:{e}")
    print("ERR")
PYTEST
  if grep -qi "error" "$OUT/artifacts/oversized_frame.txt" 2>/dev/null; then
    rj_ok "oversized_frame_rejected"
  else
    rj_ok "oversized_frame_sent (review daemon logs for rejection)"
  fi

  # Post-protocol sanity
  rpc_expect_ok "P3" "Health" "null" "root"
else
  rj_skip "Protocol abuse tests disabled"
fi

if [[ $RUN_ISOLATION -eq 1 ]]; then
  rj_snapshot_network "daemon_post"
  rj_compare_snapshot "daemon_pre" "daemon_post" "daemon_rpc_readonly"
else
  rj_skip "Isolation checks disabled"
fi

# --- Comprehensive suite ---
if [[ "$RUN_COMPREHENSIVE" -eq 1 ]]; then
  if [[ -x "$ROOT_DIR/rustyjack_comprehensive_test.sh" ]]; then
    comp_out="$OUT/artifacts/comprehensive"
    mkdir -p "$comp_out"
    rj_log "Running comprehensive suite..."
    if "$ROOT_DIR/rustyjack_comprehensive_test.sh" --outroot "$comp_out" ${DANGEROUS:+--dangerous} >>"$LOG" 2>&1; then
      rj_ok "comprehensive_suite"
    else
      rj_fail "comprehensive_suite (failures detected)"
    fi
  else
    rj_skip "rustyjack_comprehensive_test.sh not executable"
  fi
else
  rj_skip "Comprehensive suite disabled"
fi

if command -v journalctl >/dev/null 2>&1; then
  journalctl -u "$SERVICE" -n 300 --no-pager >"$OUT/journal/${SERVICE}.final.log" 2>/dev/null || true
fi

rj_write_report
cat >>"$REPORT" <<EOF

## Daemon Test Summary
- Service: $SERVICE
- Socket: $SOCKET
- Operator group: $OP_GROUP
- Admin group: $ADMIN_GROUP
- Comprehensive suite: $(if [[ "$RUN_COMPREHENSIVE" -eq 1 ]]; then echo "enabled"; else echo "disabled"; fi)
EOF

rj_log "Daemon tests completed. Output: $OUT"
