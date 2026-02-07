#!/usr/bin/env bash
# Rustyjackd Comprehensive On-Device Diagnostic Suite
# Implements the full test blueprint for security, correctness, and reliability
# SAFE by default - disruptive tests require --dangerous flag

set -euo pipefail

# =============================
# Configuration & Arguments
# =============================
SOCKET_DEFAULT="/run/rustyjack/rustyjackd.sock"
SERVICE_DEFAULT="rustyjackd.service"
OUTROOT_DEFAULT="/var/tmp/rustyjackd-diag"
DANGEROUS=0
PARALLEL=25
STRESS_ITERATIONS=200
VERBOSE=0

usage() {
  cat <<'USAGE'
RustyJack Comprehensive Diagnostic Test Suite

Usage: rustyjack_comprehensive_test.sh [options]

Options:
  --socket PATH          UDS path (default: /run/rustyjack/rustyjackd.sock)
  --service UNIT         systemd unit name (default: rustyjackd.service)
  --outroot DIR          output root (default: /var/tmp/rustyjackd-diag)
  --dangerous            enable DISRUPTIVE tests (wifi, hotspot, mount, etc.)
  --parallel N           parallel clients for stress (default: 25)
  --stress N             stress test iterations (default: 200)
  --verbose              verbose output
  -h, --help             show this help

Test Suites:
  [A] Installation and service sanity
  [B] Systemd hardening posture (static + live)
  [C] UDS permissions and group boundary checks
  [D] Protocol robustness (negative tests)
  [E] Safe functional smoke tests (read-only)
  [F] Job subsystem reliability
  [G] Logging and observability checks
  [H] Stress and soak (non-destructive)
  [I] Security adversarial tests (privilege escalation probes)
  [J] Disruptive tests (--dangerous only)

Notes:
- Run as root (required): creates test users, reads systemd/journal, checks /proc
- SAFE mode (default): no network modifications, no mount operations
- Results saved to: /var/tmp/rustyjackd-diag/<timestamp>/

USAGE
}

SOCKET="$SOCKET_DEFAULT"
SERVICE="$SERVICE_DEFAULT"
OUTROOT="$OUTROOT_DEFAULT"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --socket) SOCKET="$2"; shift 2 ;;
    --service) SERVICE="$2"; shift 2 ;;
    --outroot) OUTROOT="$2"; shift 2 ;;
    --dangerous) DANGEROUS=1; shift ;;
    --parallel) PARALLEL="$2"; shift 2 ;;
    --stress) STRESS_ITERATIONS="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

# =============================
# Output Setup & Logging
# =============================
RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT="$OUTROOT/$RUN_ID"
mkdir -p "$OUT"/{systemd,rpc/requests,rpc/responses,artifacts,proc,security}

LOG="$OUT/diag.log"
SUMMARY="$OUT/summary.json"
SYSINFO="$OUT/sysinfo.txt"

# Test counters
declare -g TESTS_RUN=0
declare -g TESTS_PASS=0
declare -g TESTS_FAIL=0
declare -g TESTS_SKIP=0

log()  {
  local msg="$*"
  printf '%s %s\n' "$(date -Is)" "$msg" | tee -a "$LOG"
  [[ $VERBOSE -eq 1 ]] && echo "$msg"
}

ok()   {
  log "[PASS] $*"
  ((TESTS_PASS++)) || true
}

bad()  {
  log "[FAIL] $*"
  ((TESTS_FAIL++)) || true
  return 1
}

skip() {
  log "[SKIP] $*"
  ((TESTS_SKIP++)) || true
}

info() {
  log "[INFO] $*"
}

# Machine-readable summary events
summary_event() {
  local status="$1" name="$2" detail="${3:-}"
  local ts="$(date -Is)"
  python3 - <<PY >> "$SUMMARY"
import json, sys
event = {
  "ts": "$ts",
  "status": "$status",
  "name": "$name",
  "detail": """$detail"""
}
print(json.dumps(event))
PY
}

# Run command wrapper with error capture
run_cmd() {
  local name="$1"; shift
  ((TESTS_RUN++)) || true
  log "[CMD] $name :: $*"

  if [[ $VERBOSE -eq 1 ]]; then
    if "$@" 2>&1 | tee -a "$LOG"; then
      ok "$name"
      summary_event "pass" "$name" ""
      return 0
    else
      local rc=$?
      bad "$name (rc=$rc)"
      summary_event "fail" "$name" "rc=$rc; cmd=$*"
      return $rc
    fi
  else
    if "$@" >>"$LOG" 2>&1; then
      ok "$name"
      summary_event "pass" "$name" ""
      return 0
    else
      local rc=$?
      bad "$name (rc=$rc)"
      summary_event "fail" "$name" "rc=$rc; cmd=$*"
      return $rc
    fi
  fi
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Must run as root (sudo required)" >&2
    echo "  - Creates ephemeral test users" >&2
    echo "  - Reads systemd service internals" >&2
    echo "  - Checks /proc/<pid> status" >&2
    exit 1
  fi
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    skip "Tool not found: $tool"
    return 1
  fi
  return 0
}

# =============================
# Test User Management
# =============================
RO_USER="rjdiag_ro"
OP_USER="rjdiag_op"
ADMIN_USER="rjdiag_admin"

cleanup_users() {
  log "Cleaning up test users..."
  for u in "$RO_USER" "$OP_USER" "$ADMIN_USER"; do
    if id "$u" >/dev/null 2>&1; then
      userdel -r "$u" >/dev/null 2>&1 || true
      log "  - Removed user: $u"
    fi
  done
}
trap cleanup_users EXIT

create_test_users() {
  log "Creating ephemeral test users for authorization tests..."

  # Verify required groups exist
  if ! getent group rustyjack >/dev/null; then
    log "[WARN] group 'rustyjack' missing - operator role tests may fail"
  fi
  if ! getent group rustyjack-admin >/dev/null; then
    log "[WARN] group 'rustyjack-admin' missing - admin role tests may fail"
  fi

  # Create system users (no home, no shell)
  for u in "$RO_USER" "$OP_USER" "$ADMIN_USER"; do
    if ! id "$u" >/dev/null 2>&1; then
      useradd -M -r -s /usr/sbin/nologin "$u" 2>/dev/null || {
        log "[WARN] Failed to create user: $u"
        return 1
      }
      log "  - Created user: $u"
    fi
  done

  # Assign group memberships
  usermod -a -G rustyjack "$OP_USER" 2>/dev/null || log "[WARN] Failed to add $OP_USER to rustyjack"
  usermod -a -G rustyjack "$ADMIN_USER" 2>/dev/null || log "[WARN] Failed to add $ADMIN_USER to rustyjack"
  usermod -a -G rustyjack-admin "$ADMIN_USER" 2>/dev/null || log "[WARN] Failed to add $ADMIN_USER to rustyjack-admin"

  log "Test users configured:"
  log "  - $RO_USER: ReadOnly (no groups)"
  log "  - $OP_USER: Operator (rustyjack)"
  log "  - $ADMIN_USER: Admin (rustyjack, rustyjack-admin)"
}

# =============================
# Python RPC Helper
# =============================
PY_HELPER="$OUT/artifacts/rj_rpc.py"

generate_rpc_helper() {
  cat >"$PY_HELPER" <<'PYEOF'
#!/usr/bin/env python3
"""
RustyJack RPC Helper - handles 4-byte length-prefixed JSON framing
Usage: rj_rpc.py <socket_path> <body_type> <req_json_path>
"""
import json, os, socket, struct, sys, time, re, traceback

if len(sys.argv) < 4:
    print(json.dumps({"ok": False, "error": "usage: rj_rpc.py <socket> <body_type> <req_path>"}))
    sys.exit(1)

SOCKET_PATH = sys.argv[1]
BODY_TYPE   = sys.argv[2]
REQ_PATH    = sys.argv[3]
PROTOCOL_VERSION = 1
MAX_FRAME_DEFAULT = 1_048_576

def camel_to_snake(s: str) -> str:
    """Convert CamelCase to snake_case"""
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', s)
    s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()

def encode_frame(payload: bytes) -> bytes:
    """Encode 4-byte big-endian length prefix + payload"""
    return struct.pack(">I", len(payload)) + payload

def read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket"""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"unexpected EOF (wanted {n} bytes, got {len(buf)})")
        buf += chunk
    return buf

def read_frame(sock: socket.socket, max_frame: int = MAX_FRAME_DEFAULT) -> bytes:
    """Read length-prefixed frame"""
    hdr = read_exact(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    if length == 0:
        raise ValueError("zero-length frame")
    if length > max_frame:
        raise ValueError(f"frame too large: {length} > {max_frame}")
    return read_exact(sock, length)

def handshake(sock: socket.socket) -> dict:
    """Perform ClientHello/HelloAck handshake"""
    hello = {
        "protocol_version": PROTOCOL_VERSION,
        "client_name": "rjdiag",
        "client_version": "1.0",
        "supports": []
    }
    sock.sendall(encode_frame(json.dumps(hello, separators=(",", ":")).encode("utf-8")))
    ack_raw = read_frame(sock)
    ack = json.loads(ack_raw.decode("utf-8"))
    return ack

def rpc_request(sock: socket.socket, body_type: str, data) -> tuple:
    """Send RPC request and receive response"""
    request_id = int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF
    endpoint = camel_to_snake(body_type)

    # Build request envelope
    env = {
        "v": PROTOCOL_VERSION,
        "request_id": request_id,
        "endpoint": endpoint,
        "body": {"type": body_type}
    }
    if data is not None:
        env["body"]["data"] = data

    payload = json.dumps(env, separators=(",", ":")).encode("utf-8")
    sock.sendall(encode_frame(payload))

    resp_raw = read_frame(sock)
    resp = json.loads(resp_raw.decode("utf-8"))

    return request_id, resp, resp_raw

def main():
    t0 = time.time()
    result = {
        "ok": False,
        "timing_ms": 0,
        "error_type": None,
        "error": None
    }

    try:
        # Read request data
        with open(REQ_PATH, "rb") as f:
            req_data = f.read().strip()

        data = None
        if req_data and req_data not in (b"null", b""):
            try:
                data = json.loads(req_data.decode("utf-8"))
            except json.JSONDecodeError as e:
                result["error_type"] = "invalid_request_json"
                result["error"] = str(e)
                print(json.dumps(result))
                sys.exit(1)

        # Connect to socket
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
            sys.exit(2)

        # Handshake
        try:
            ack = handshake(sock)
            result["handshake"] = ack
        except socket.timeout:
            result["error_type"] = "handshake_timeout"
            result["error"] = "handshake timeout (2s)"
            result["timing_ms"] = int((time.time() - t0) * 1000)
            print(json.dumps(result))
            sys.exit(3)
        except Exception as e:
            result["error_type"] = "handshake_error"
            result["error"] = str(e)
            result["timing_ms"] = int((time.time() - t0) * 1000)
            print(json.dumps(result))
            sys.exit(3)

        # RPC request
        try:
            request_id, resp, raw = rpc_request(sock, BODY_TYPE, data)
            result["request_id"] = request_id
            result["response"] = resp
        except socket.timeout:
            result["error_type"] = "request_timeout"
            result["error"] = "request timeout (10s)"
            result["timing_ms"] = int((time.time() - t0) * 1000)
            print(json.dumps(result))
            sys.exit(4)
        except Exception as e:
            result["error_type"] = "rpc_error"
            result["error"] = str(e)
            result["error_traceback"] = traceback.format_exc()
            result["timing_ms"] = int((time.time() - t0) * 1000)
            print(json.dumps(result))
            sys.exit(4)

        sock.close()
        result["timing_ms"] = int((time.time() - t0) * 1000)

        # Check if daemon returned error
        body = resp.get("body", {})
        if body.get("type") == "Err":
            result["ok"] = False
            result["error_type"] = "daemon_error"
            result["daemon_error"] = body.get("data", {})
            print(json.dumps(result))
            sys.exit(10)

        # Success
        result["ok"] = True
        print(json.dumps(result))
        sys.exit(0)

    except Exception as e:
        result["error_type"] = "unexpected_error"
        result["error"] = str(e)
        result["error_traceback"] = traceback.format_exc()
        result["timing_ms"] = int((time.time() - t0) * 1000)
        print(json.dumps(result))
        sys.exit(99)

if __name__ == "__main__":
    main()
PYEOF
  chmod 755 "$PY_HELPER"
}

# RPC wrapper that stores request/response artifacts
rj_rpc() {
  local id="$1" body_type="$2" data_json="$3" as_user="${4:-root}"
  local req="$OUT/rpc/requests/${id}_${body_type}.json"
  local resp="$OUT/rpc/responses/${id}_${body_type}.json"

  ((TESTS_RUN++)) || true
  printf '%s\n' "$data_json" > "$req"

  log "[RPC] $id $body_type (user=$as_user)"

  if sudo -u "$as_user" python3 "$PY_HELPER" "$SOCKET" "$body_type" "$req" >"$resp" 2>>"$LOG"; then
    # Check response for ok status
    local is_ok
    is_ok=$(python3 -c "import json; print(json.load(open('$resp')).get('ok', False))" 2>/dev/null || echo "False")

    if [[ "$is_ok" == "True" ]]; then
      ok "RPC $id $body_type"
      summary_event "pass" "rpc:$id:$body_type" ""
      return 0
    else
      local err_type err_msg
      err_type=$(python3 -c "import json; print(json.load(open('$resp')).get('error_type', 'unknown'))" 2>/dev/null || echo "unknown")
      err_msg=$(python3 -c "import json; d=json.load(open('$resp')); print(d.get('error', d.get('daemon_error', {})))" 2>/dev/null || echo "{}")
      bad "RPC $id $body_type (error_type=$err_type)"
      log "  Error: $err_msg"
      summary_event "fail" "rpc:$id:$body_type" "error_type=$err_type"
      return 1
    fi
  else
    local rc=$?
    bad "RPC $id $body_type (python rc=$rc)"
    if [[ -f "$resp" ]]; then
      log "  Response: $(cat "$resp" 2>/dev/null | head -c 500 || true)"
    fi
    summary_event "fail" "rpc:$id:$body_type" "python_rc=$rc"
    return $rc
  fi
}

# Extract JSON field from RPC response
rpc_extract() {
  local resp_file="$1"
  local jq_filter="$2"
  python3 - "$resp_file" "$jq_filter" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    # Simple path extraction (e.g., ".response.body.data.job_id")
    path = sys.argv[2].strip('.').split('.')
    for key in path:
        data = data.get(key, {})
    print(data if isinstance(data, str) else json.dumps(data))
except:
    print("")
PY
}

# =============================
# Suite A: Installation & Service Sanity
# =============================
suite_A_sanity() {
  log ""
  log "========================================"
  log "SUITE A: Installation & Service Sanity"
  log "========================================"

  run_cmd "A1_service_enabled" systemctl is-enabled --quiet "$SERVICE" || true
  run_cmd "A2_service_active" systemctl is-active --quiet "$SERVICE"

  # Capture service properties
  systemctl show "$SERVICE" -p MainPID,ExecStart,User,Group,Environment,Type,Restart > "$OUT/systemd/show.txt" 2>&1 || true
  ok "A3_service_show"

  run_cmd "A4_service_cat" systemctl cat "$SERVICE" > "$OUT/systemd/unit.txt" 2>&1

  # Check runtime directories
  run_cmd "A5_runtime_dirs" bash -c "ls -ld /run/rustyjack /var/lib/rustyjack 2>&1 | tee -a '$LOG'"

  # Socket existence and permissions
  if [[ -e "$SOCKET" ]]; then
    stat "$SOCKET" > "$OUT/systemd/socket_stat.txt" 2>&1
    local sock_type sock_perms
    sock_type=$(stat -c %F "$SOCKET" 2>/dev/null || echo "unknown")
    sock_perms=$(stat -c %a "$SOCKET" 2>/dev/null || echo "unknown")

    if [[ "$sock_type" == "socket" ]]; then
      ok "A6_socket_exists (type=socket, perms=$sock_perms)"
    else
      bad "A6_socket_exists (type=$sock_type, expected socket)"
    fi

    # Check not world-accessible
    if [[ "${sock_perms:2:1}" == "0" ]]; then
      ok "A7_socket_perms_secure (others=0)"
    else
      bad "A7_socket_perms_secure (others=${sock_perms:2:1}, should be 0)"
    fi
  else
    bad "A6_socket_exists (not found: $SOCKET)"
  fi

  # Journal tail
  journalctl -u "$SERVICE" -b --no-pager | tail -n 200 > "$OUT/systemd/journal_tail.txt" 2>&1
  if grep -q "ready\|listening\|started" "$OUT/systemd/journal_tail.txt" 2>/dev/null; then
    ok "A8_journal_ready"
  else
    log "[WARN] A8_journal: did not find 'ready' indicator in recent journal"
  fi

  # Extract MainPID for later /proc checks
  local main_pid
  main_pid=$(systemctl show "$SERVICE" -p MainPID --value 2>/dev/null || echo "0")
  if [[ "$main_pid" -gt 0 ]]; then
    ok "A9_main_pid (pid=$main_pid)"
    echo "$main_pid" > "$OUT/proc/main_pid.txt"
  else
    bad "A9_main_pid (pid=$main_pid, service may not be running)"
  fi
}

# =============================
# Suite B: Systemd Hardening
# =============================
suite_B_hardening() {
  log ""
  log "========================================"
  log "SUITE B: Systemd Hardening Posture"
  log "========================================"

  # systemd-analyze security
  if require_tool systemd-analyze; then
    if systemd-analyze security "$SERVICE" > "$OUT/systemd/security.txt" 2>&1; then
      ok "B1_analyze_security"

      # Extract security score if present
      local score
      score=$(grep -oP 'Overall exposure level: \K[^\s]+' "$OUT/systemd/security.txt" 2>/dev/null || echo "unknown")
      log "  Security exposure: $score"
      summary_event "info" "systemd_security_score" "$score"
    else
      bad "B1_analyze_security (failed to run)"
    fi
  fi

  # Hardening properties
  systemctl show "$SERVICE" \
    -p CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp \
    -p ProtectKernelTunables,ProtectKernelModules,ProtectProc,RestrictAddressFamilies \
    -p SystemCallFilter,MemoryDenyWriteExecute,RestrictNamespaces,LockPersonality \
    > "$OUT/systemd/hardening_props.txt" 2>&1
  ok "B2_hardening_props"

  # Check specific directives
  local no_new_privs protect_system mem_deny
  no_new_privs=$(grep "^NoNewPrivileges=" "$OUT/systemd/hardening_props.txt" 2>/dev/null | cut -d= -f2 || echo "unknown")
  protect_system=$(grep "^ProtectSystem=" "$OUT/systemd/hardening_props.txt" 2>/dev/null | cut -d= -f2 || echo "unknown")
  mem_deny=$(grep "^MemoryDenyWriteExecute=" "$OUT/systemd/hardening_props.txt" 2>/dev/null | cut -d= -f2 || echo "unknown")

  log "  NoNewPrivileges: $no_new_privs"
  log "  ProtectSystem: $protect_system"
  log "  MemoryDenyWriteExecute: $mem_deny"

  # /proc/<pid>/status checks
  if [[ -f "$OUT/proc/main_pid.txt" ]]; then
    local pid
    pid=$(cat "$OUT/proc/main_pid.txt")
    if [[ -f "/proc/$pid/status" ]]; then
      grep -E "^(CapEff|CapBnd|CapInh|NoNewPrivs|Seccomp):" "/proc/$pid/status" > "$OUT/proc/capabilities.txt" 2>&1 || true
      ok "B3_proc_status (pid=$pid)"

      local cap_eff
      cap_eff=$(grep "^CapEff:" "$OUT/proc/capabilities.txt" 2>/dev/null | awk '{print $2}' || echo "unknown")
      log "  CapEff: $cap_eff"
    else
      skip "B3_proc_status (pid=$pid not found)"
    fi
  fi
}

# =============================
# Suite C: Authorization Matrix
# =============================
suite_C_auth_matrix() {
  log ""
  log "========================================"
  log "SUITE C: Authorization Matrix & Tiers"
  log "========================================"

  create_test_users || {
    skip "Suite C (failed to create test users)"
    return 1
  }

  # Test tier detection via handshake
  log "Testing tier assignment..."

  # ReadOnly user
  rj_rpc "C1" "Health" "null" "$RO_USER" || true
  local ro_role
  ro_role=$(rpc_extract "$OUT/rpc/responses/C1_Health.json" ".handshake.authz.role" 2>/dev/null || echo "unknown")
  if [[ "$ro_role" == "ReadOnly" || "$ro_role" == "read_only" ]]; then
    ok "C1_tier_readonly (role=$ro_role)"
  else
    bad "C1_tier_readonly (expected ReadOnly, got $ro_role)"
  fi

  # Operator user
  rj_rpc "C2" "Health" "null" "$OP_USER" || true
  local op_role
  op_role=$(rpc_extract "$OUT/rpc/responses/C2_Health.json" ".handshake.authz.role" 2>/dev/null || echo "unknown")
  if [[ "$op_role" == "Operator" || "$op_role" == "operator" ]]; then
    ok "C2_tier_operator (role=$op_role)"
  else
    bad "C2_tier_operator (expected Operator, got $op_role)"
  fi

  # Admin user
  rj_rpc "C3" "Health" "null" "$ADMIN_USER" || true
  local admin_role
  admin_role=$(rpc_extract "$OUT/rpc/responses/C3_Health.json" ".handshake.authz.role" 2>/dev/null || echo "unknown")
  if [[ "$admin_role" == "Admin" || "$admin_role" == "admin" ]]; then
    ok "C3_tier_admin (role=$admin_role)"
  else
    bad "C3_tier_admin (expected Admin, got $admin_role)"
  fi

  # Endpoint enforcement tests
  log "Testing endpoint tier enforcement..."

  # Admin-only endpoint should fail for Operator
  rj_rpc "C4" "LoggingConfigSet" '{"enabled":true,"level":"info"}' "$OP_USER" && {
    bad "C4_admin_endpoint_op_denied (should have failed)"
  } || {
    ok "C4_admin_endpoint_op_denied (correctly denied)"
  }

  # Operator-only endpoint should fail for ReadOnly
  rj_rpc "C5" "SystemLogsGet" '{"max_lines":50}' "$RO_USER" && {
    bad "C5_operator_endpoint_ro_denied (should have failed)"
  } || {
    ok "C5_operator_endpoint_ro_denied (correctly denied)"
  }

  # Admin endpoint should succeed for Admin
  rj_rpc "C6" "SystemSync" "null" "$ADMIN_USER" || {
    log "[WARN] C6_admin_endpoint_allowed failed (may not be critical)"
  }

  # Test comprehensive endpoint matrix (sample)
  log "Testing authorization matrix samples..."

  # ReadOnly endpoints (should work for all tiers)
  rj_rpc "C7" "Status" "null" "$RO_USER"
  rj_rpc "C8" "Version" "null" "$OP_USER"
  rj_rpc "C9" "BlockDevicesList" "null" "$ADMIN_USER"

  # Operator endpoints (should fail for ReadOnly)
  rj_rpc "C10" "ActiveInterfaceClear" "null" "$RO_USER" && bad "C10_op_endpoint_denied" || ok "C10_op_endpoint_denied"
}

# =============================
# Suite D: Protocol Robustness
# =============================
suite_D_protocol_negative() {
  log ""
  log "========================================"
  log "SUITE D: Protocol Robustness (Negative)"
  log "========================================"

  local testdir="$OUT/artifacts/protocol_negative"
  mkdir -p "$testdir"

  # D1: Protocol version mismatch
  log "D1: Testing protocol version mismatch..."
  python3 - "$SOCKET" "$testdir" <<'PYTEST'
import json, socket, struct, sys
sock_path, outdir = sys.argv[1], sys.argv[2]

def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise EOFError()
        buf += c
    return buf
def read_frame(s):
    hdr = read_exact(s, 4)
    (ln,) = struct.unpack(">I", hdr)
    return read_exact(s, ln)

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    hello = {"protocol_version": 999, "client_name": "rjdiag", "client_version": "0.1", "supports": []}
    s.sendall(enc(json.dumps(hello).encode()))
    raw = read_frame(s)
    obj = json.loads(raw.decode())
    with open(f"{outdir}/D1_incompatible_protocol.json", "w") as f:
        json.dump(obj, f, indent=2)
    print("D1_OK")
except Exception as e:
    with open(f"{outdir}/D1_incompatible_protocol.json", "w") as f:
        json.dump({"error": str(e)}, f, indent=2)
    print(f"D1_ERROR: {e}")
PYTEST

  if [[ -f "$testdir/D1_incompatible_protocol.json" ]]; then
    if grep -q '"code".*1\|incompatible\|version' "$testdir/D1_incompatible_protocol.json" 2>/dev/null; then
      ok "D1_protocol_version_mismatch"
    else
      bad "D1_protocol_version_mismatch (expected error response)"
    fi
  else
    bad "D1_protocol_version_mismatch (no output)"
  fi

  # D2: Oversized frame
  log "D2: Testing oversized frame rejection..."
  python3 - "$SOCKET" "$testdir" <<'PYTEST'
import json, socket, struct, sys
sock_path, outdir = sys.argv[1], sys.argv[2]

def enc(b): return struct.pack(">I", len(b)) + b
def enc_len(n): return struct.pack(">I", n)
def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise EOFError()
        buf += c
    return buf
def read_frame(s):
    hdr = read_exact(s, 4)
    (ln,) = struct.unpack(">I", hdr)
    return read_exact(s, ln)

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    hello = {"protocol_version": 1, "client_name": "rjdiag", "client_version": "0.1", "supports": []}
    s.sendall(enc(json.dumps(hello).encode()))
    ack = json.loads(read_frame(s).decode())
    max_frame = ack.get("max_frame", 1048576)

    # Send oversized frame header
    s.sendall(enc_len(max_frame + 1))
    raw = read_frame(s)
    err = json.loads(raw.decode())

    with open(f"{outdir}/D2_oversize_frame.json", "w") as f:
        json.dump({"ack": ack, "error": err}, f, indent=2)
    print("D2_OK")
except Exception as e:
    with open(f"{outdir}/D2_oversize_frame.json", "w") as f:
        json.dump({"error": str(e)}, f, indent=2)
    print(f"D2_ERROR: {e}")
PYTEST

  if [[ -f "$testdir/D2_oversize_frame.json" ]]; then
    if grep -q '"code".*1002\|protocol.*violation\|too.*large' "$testdir/D2_oversize_frame.json" 2>/dev/null; then
      ok "D2_oversize_frame_rejected"
    else
      bad "D2_oversize_frame_rejected (expected ProtocolViolation)"
    fi
  else
    bad "D2_oversize_frame_rejected (no output)"
  fi

  # D3: Repeated protocol violations
  log "D3: Testing repeated violations disconnect..."
  python3 - "$SOCKET" "$testdir" <<'PYTEST'
import json, socket, struct, sys
sock_path, outdir = sys.argv[1], sys.argv[2]

def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise EOFError()
        buf += c
    return buf
def read_frame(s):
    hdr = read_exact(s, 4)
    (ln,) = struct.unpack(">I", hdr)
    return read_exact(s, ln)

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    hello = {"protocol_version": 1, "client_name": "rjdiag", "client_version": "0.1", "supports": []}
    s.sendall(enc(json.dumps(hello).encode()))
    ack = json.loads(read_frame(s).decode())

    # Send invalid JSON frames 3 times
    violations = []
    for i in range(3):
        s.sendall(enc(b"{not valid json"))
        raw = read_frame(s)
        violations.append(json.loads(raw.decode()))

    # 4th violation should disconnect
    dropped = False
    try:
        s.sendall(enc(b"{not valid json again"))
        raw = read_frame(s)
        violations.append(json.loads(raw.decode()))
    except:
        dropped = True

    with open(f"{outdir}/D3_three_violations.json", "w") as f:
        json.dump({"ack": ack, "violations": violations, "dropped": dropped}, f, indent=2)
    print("D3_OK" if dropped else "D3_FAIL")
except Exception as e:
    with open(f"{outdir}/D3_three_violations.json", "w") as f:
        json.dump({"error": str(e)}, f, indent=2)
    print(f"D3_ERROR: {e}")
PYTEST

  if [[ -f "$testdir/D3_three_violations.json" ]]; then
    if grep -q '"dropped".*true' "$testdir/D3_three_violations.json" 2>/dev/null; then
      ok "D3_repeated_violations_disconnect"
    else
      bad "D3_repeated_violations_disconnect (connection not dropped)"
    fi
  else
    bad "D3_repeated_violations_disconnect (no output)"
  fi

  # D4: Endpoint/body type mismatch
  log "D4: Testing endpoint/body mismatch..."
  rj_rpc "D4" "Health" "null" "root" || true
  # Manually construct a request with wrong endpoint
  python3 - "$SOCKET" "$testdir" <<'PYTEST'
import json, socket, struct, sys, time
sock_path, outdir = sys.argv[1], sys.argv[2]

def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise EOFError()
        buf += c
    return buf
def read_frame(s):
    hdr = read_exact(s, 4)
    (ln,) = struct.unpack(">I", hdr)
    return read_exact(s, ln)

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    hello = {"protocol_version": 1, "client_name": "rjdiag", "client_version": "0.1", "supports": []}
    s.sendall(enc(json.dumps(hello).encode()))
    ack = json.loads(read_frame(s).decode())

    # Send request with mismatched endpoint/body
    req = {
        "v": 1,
        "request_id": int(time.time() * 1000),
        "endpoint": "health",  # wrong endpoint for Version body
        "body": {"type": "Version"}
    }
    s.sendall(enc(json.dumps(req).encode()))
    resp = json.loads(read_frame(s).decode())

    with open(f"{outdir}/D4_endpoint_mismatch.json", "w") as f:
        json.dump({"ack": ack, "response": resp}, f, indent=2)
    print("D4_OK")
except Exception as e:
    with open(f"{outdir}/D4_endpoint_mismatch.json", "w") as f:
        json.dump({"error": str(e)}, f, indent=2)
    print(f"D4_ERROR: {e}")
PYTEST

  if [[ -f "$testdir/D4_endpoint_mismatch.json" ]]; then
    if grep -q '"code".*1001\|bad.*request\|mismatch' "$testdir/D4_endpoint_mismatch.json" 2>/dev/null; then
      ok "D4_endpoint_body_mismatch"
    else
      log "[WARN] D4_endpoint_body_mismatch (unclear if validated)"
    fi
  fi
}

# =============================
# Suite E: Safe Functional Smoke
# =============================
suite_E_safe_smoke() {
  log ""
  log "========================================"
  log "SUITE E: Safe Functional Smoke Tests"
  log "========================================"

  # Core read-only endpoints
  rj_rpc "E1" "Health" "null" "root"
  rj_rpc "E2" "Version" "null" "root"
  rj_rpc "E3" "Status" "null" "root"

  # System status
  rj_rpc "E4" "SystemStatusGet" "null" "root"
  rj_rpc "E5" "DiskUsageGet" '{"path":"/"}' "root"
  rj_rpc "E6" "BlockDevicesList" "null" "root"

  # Interface queries
  rj_rpc "E7" "ActiveInterfaceGet" "null" "root" || true
  rj_rpc "E8" "InterfaceStatusGet" '{"interface":"eth0"}' "root" || true
  rj_rpc "E9" "WifiInterfacesList" "null" "root" || true
  rj_rpc "E10" "WifiCapabilitiesGet" '{"interface":"wlan0"}' "root" || true

  # Portal & mount
  rj_rpc "E11" "PortalStatus" "null" "root" || true
  rj_rpc "E12" "MountList" "null" "root"

  # Logging
  rj_rpc "E13" "LoggingConfigGet" "null" "root"
  rj_rpc "E14" "LogTailGet" '{"component":"rustyjackd","max_lines":200}' "root" || true

  # Timing checks (Health should be fast)
  local e1_timing
  e1_timing=$(rpc_extract "$OUT/rpc/responses/E1_Health.json" ".timing_ms" 2>/dev/null || echo "0")
  if [[ "$e1_timing" -lt 100 ]]; then
    ok "E15_health_latency (${e1_timing}ms < 100ms)"
  else
    log "[WARN] E15_health_latency (${e1_timing}ms, expected <100ms)"
  fi
}

# =============================
# Suite F: Job Subsystem
# =============================
suite_F_jobs() {
  log ""
  log "========================================"
  log "SUITE F: Job Subsystem Reliability"
  log "========================================"

  # F1: Start Noop job
  rj_rpc "F1" "JobStart" '{"job":{"kind":{"type":"Noop"},"requested_by":"diag"}}' "root" || {
    skip "Suite F (JobStart failed)"
    return 1
  }

  local job_id
  job_id=$(python3 - "$OUT/rpc/responses/F1_JobStart.json" <<'PY'
import json, sys
try:
    obj = json.load(open(sys.argv[1]))
    resp = obj.get("response", {})
    body = resp.get("body", {})
    data = body.get("data", {})
    if data.get("type") == "JobStarted":
        print(data.get("data", {}).get("job_id", ""))
    else:
        print("")
except:
    print("")
PY
)

  if [[ -z "$job_id" ]]; then
    bad "F1_jobstart_extract_id (no job_id found)"
    return 1
  fi
  ok "F1_jobstart_extract_id (job_id=$job_id)"

  # F2: Poll job status
  local deadline=$(($(date +%s) + 10))
  local state=""
  while [[ $(date +%s) -lt $deadline ]]; do
    rj_rpc "F2" "JobStatus" "{\"job_id\":\"$job_id\"}" "root" >/dev/null 2>&1 || true
    state=$(python3 - "$OUT/rpc/responses/F2_JobStatus.json" <<'PY'
import json, sys
try:
    obj = json.load(open(sys.argv[1]))
    resp = obj.get("response", {})
    body = resp.get("body", {})
    data = body.get("data", {})
    if data.get("type") == "JobInfo":
        print(data.get("data", {}).get("state", ""))
except:
    print("")
PY
)
    [[ -n "$state" ]] && log "  Job state: $state"
    [[ "$state" == "completed" || "$state" == "failed" || "$state" == "cancelled" ]] && break
    sleep 0.3
  done

  if [[ "$state" == "completed" ]]; then
    ok "F2_job_noop_completed"
  elif [[ "$state" == "failed" ]]; then
    log "[WARN] F2_job_noop_failed (unexpected but not critical)"
  else
    bad "F2_job_noop_timeout (state=$state)"
  fi

  # F3: Start Sleep job and cancel
  rj_rpc "F3" "JobStart" '{"job":{"kind":{"type":"Sleep","ms":5000},"requested_by":"diag"}}' "root" || {
    skip "F3_sleep_job_start"
    return
  }

  local job2
  job2=$(python3 - "$OUT/rpc/responses/F3_JobStart.json" <<'PY'
import json, sys
try:
    obj = json.load(open(sys.argv[1]))
    resp = obj.get("response", {})
    body = resp.get("body", {})
    data = body.get("data", {})
    if data.get("type") == "JobStarted":
        print(data.get("data", {}).get("job_id", ""))
except:
    print("")
PY
)

  if [[ -n "$job2" ]]; then
    sleep 0.5
    rj_rpc "F4" "JobCancel" "{\"job_id\":\"$job2\"}" "root" || true

    # Check if cancelled
    sleep 0.5
    rj_rpc "F5" "JobStatus" "{\"job_id\":\"$job2\"}" "root" >/dev/null 2>&1 || true
    local cancel_state
    cancel_state=$(python3 - "$OUT/rpc/responses/F5_JobStatus.json" <<'PY'
import json, sys
try:
    obj = json.load(open(sys.argv[1]))
    resp = obj.get("response", {})
    body = resp.get("body", {})
    data = body.get("data", {})
    if data.get("type") == "JobInfo":
        print(data.get("data", {}).get("state", ""))
except:
    print("")
PY
)
    if [[ "$cancel_state" == "cancelled" ]]; then
      ok "F5_job_cancel_success"
    else
      log "[WARN] F5_job_cancel (state=$cancel_state, expected cancelled)"
    fi
  fi
}

# =============================
# Suite G: Logging & Observability
# =============================
suite_G_logging() {
  log ""
  log "========================================"
  log "SUITE G: Logging & Observability"
  log "========================================"

  # Capture full journal since boot
  journalctl -u "$SERVICE" -b --no-pager > "$OUT/systemd/journal_full.txt" 2>&1 || true
  ok "G1_journal_capture"

  # LogTailGet RPC
  rj_rpc "G2" "LogTailGet" '{"component":"rustyjackd","max_lines":200}' "root" || true

  # Check log directory permissions
  if [[ -d "/var/lib/rustyjack/logs" ]]; then
    ls -la /var/lib/rustyjack/logs > "$OUT/artifacts/log_dir_perms.txt" 2>&1 || true
    ok "G3_log_dir_perms"
  else
    skip "G3_log_dir_perms (log dir not found)"
  fi

  # Verify logs are not world-readable
  if [[ -d "/var/lib/rustyjack/logs" ]]; then
    local perms
    perms=$(stat -c %a /var/lib/rustyjack/logs 2>/dev/null || echo "000")
    if [[ "${perms:2:1}" == "0" || "${perms:2:1}" == "5" ]]; then
      ok "G4_log_dir_secure (perms=$perms)"
    else
      bad "G4_log_dir_secure (perms=$perms, world-writable)"
    fi
  fi

  # Check error context in logs (improved error reporting)
  if grep -q "error\|Error\|ERROR" "$OUT/systemd/journal_full.txt" 2>/dev/null; then
    log "[INFO] G5_errors_in_journal (found errors, see journal_full.txt)"
    grep -i "error" "$OUT/systemd/journal_full.txt" | tail -20 > "$OUT/artifacts/recent_errors.txt" 2>&1 || true
  fi
}

# =============================
# Suite H: Stress & Soak
# =============================
suite_H_stress() {
  log ""
  log "========================================"
  log "SUITE H: Stress & Soak Tests"
  log "========================================"

  # Capture initial FD count
  local pid
  pid=$(cat "$OUT/proc/main_pid.txt" 2>/dev/null || echo "0")
  local fd_before=0
  if [[ "$pid" -gt 0 && -d "/proc/$pid/fd" ]]; then
    fd_before=$(ls /proc/$pid/fd 2>/dev/null | wc -l || echo "0")
    log "  Initial FD count: $fd_before (pid=$pid)"
  fi

  # H1: Sequential burst (200 requests)
  log "H1: Sequential Health burst ($STRESS_ITERATIONS requests)..."
  local start_time end_time
  start_time=$(date +%s%N)

  local failures=0
  for i in $(seq 1 "$STRESS_ITERATIONS"); do
    if ! rj_rpc "H1_$i" "Health" "null" "root" >/dev/null 2>&1; then
      ((failures++)) || true
    fi
    [[ $((i % 50)) -eq 0 ]] && log "  ... $i/$STRESS_ITERATIONS requests"
  done

  end_time=$(date +%s%N)
  local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
  local rps=$(( STRESS_ITERATIONS * 1000 / elapsed_ms ))

  log "  Completed: ${STRESS_ITERATIONS} requests in ${elapsed_ms}ms (~${rps} req/s)"
  log "  Failures: $failures"

  if [[ $failures -lt $((STRESS_ITERATIONS / 10)) ]]; then
    ok "H1_sequential_burst (failures=$failures/$STRESS_ITERATIONS)"
  else
    bad "H1_sequential_burst (failures=$failures/$STRESS_ITERATIONS, >10% fail rate)"
  fi

  # H2: Connection churn (100 connect/disconnect cycles)
  log "H2: Connection churn (100 cycles)..."
  local churn_failures=0
  for i in $(seq 1 100); do
    if ! rj_rpc "H2_$i" "Version" "null" "root" >/dev/null 2>&1; then
      ((churn_failures++)) || true
    fi
  done

  if [[ $churn_failures -lt 10 ]]; then
    ok "H2_connection_churn (failures=$churn_failures/100)"
  else
    bad "H2_connection_churn (failures=$churn_failures/100)"
  fi

  # H3: FD leak check
  if [[ "$pid" -gt 0 && -d "/proc/$pid/fd" ]]; then
    local fd_after
    fd_after=$(ls /proc/$pid/fd 2>/dev/null | wc -l || echo "0")
    log "  Final FD count: $fd_after (delta: $((fd_after - fd_before)))"

    if [[ $((fd_after - fd_before)) -lt 10 ]]; then
      ok "H3_fd_leak_check (delta=$((fd_after - fd_before)) < 10)"
    else
      bad "H3_fd_leak_check (delta=$((fd_after - fd_before)), possible leak)"
    fi

    # Save FD list for debugging
    ls -l /proc/$pid/fd > "$OUT/proc/fd_after_stress.txt" 2>&1 || true
  else
    skip "H3_fd_leak_check (pid not available)"
  fi

  # H4: Memory check
  if [[ "$pid" -gt 0 && -f "/proc/$pid/status" ]]; then
    local rss_kb
    rss_kb=$(grep "^VmRSS:" /proc/$pid/status 2>/dev/null | awk '{print $2}' || echo "0")
    log "  RSS: ${rss_kb} KB"
    summary_event "info" "memory_rss_kb" "$rss_kb"
    ok "H4_memory_check (rss=${rss_kb}KB)"
  fi
}

# =============================
# Suite I: Security Adversarial
# =============================
suite_I_security() {
  log ""
  log "========================================"
  log "SUITE I: Security Adversarial Tests"
  log "========================================"

  # I1: PID disappears group lookup fallback
  log "I1: Testing PID disappears auth bypass..."

  python3 - "$SOCKET" "$OUT/artifacts" "$RO_USER" <<'PYTEST'
import json, os, socket, struct, sys, time
sock_path, outdir, test_user = sys.argv[1], sys.argv[2], sys.argv[3]

def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise EOFError()
        buf += c
    return buf
def read_frame(s):
    hdr = read_exact(s, 4)
    (ln,) = struct.unpack(">I", hdr)
    return read_exact(s, ln)

result = {"test": "I1_pid_disappears", "success": False}

try:
    # Connect as test_user (ReadOnly)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)

    # Fork before handshake
    pid = os.fork()

    if pid > 0:
        # Parent: exit immediately (causes child's PID to be reparented)
        s.close()
        sys.exit(0)
    else:
        # Child: complete handshake and attempt Operator-only call
        hello = {"protocol_version": 1, "client_name": "rjdiag", "client_version": "0.1", "supports": []}
        s.sendall(enc(json.dumps(hello).encode()))
        ack = json.loads(read_frame(s).decode())
        result["handshake_role"] = ack.get("authz", {}).get("role")

        # Attempt SystemLogsGet (Operator-only)
        req = {
            "v": 1,
            "request_id": int(time.time() * 1000),
            "endpoint": "system_logs_get",
            "body": {"type": "SystemLogsGet", "data": {"max_lines": 50}}
        }
        s.sendall(enc(json.dumps(req).encode()))
        resp = json.loads(read_frame(s).decode())

        result["response"] = resp
        body = resp.get("body", {})

        # If we get Ok, that's a privilege escalation bug!
        if body.get("type") == "Ok":
            result["success"] = False
            result["vulnerability"] = "CRITICAL: Privilege escalation via PID disappearance"
        elif body.get("type") == "Err":
            err_data = body.get("data", {})
            if "Forbidden" in str(err_data) or "forbidden" in str(err_data).lower():
                result["success"] = True
                result["msg"] = "Correctly denied Operator endpoint for ReadOnly user"
            else:
                result["success"] = True
                result["msg"] = f"Denied with: {err_data}"

        with open(f"{outdir}/I1_pid_disappears.json", "w") as f:
            json.dump(result, f, indent=2)

        sys.exit(0 if result["success"] else 1)

except Exception as e:
    result["error"] = str(e)
    with open(f"{outdir}/I1_pid_disappears.json", "w") as f:
        json.dump(result, f, indent=2)
    sys.exit(1)
PYTEST

  sleep 1  # Wait for child process

  if [[ -f "$OUT/artifacts/I1_pid_disappears.json" ]]; then
    if grep -q '"success".*true' "$OUT/artifacts/I1_pid_disappears.json" 2>/dev/null; then
      ok "I1_pid_disappears_auth_secure"
    elif grep -q "vulnerability.*CRITICAL" "$OUT/artifacts/I1_pid_disappears.json" 2>/dev/null; then
      bad "I1_pid_disappears_auth_VULNERABLE (CRITICAL SECURITY BUG!)"
      log "  !!! PRIVILEGE ESCALATION DETECTED !!!"
      summary_event "critical" "I1_privilege_escalation" "PID disappears allows auth bypass"
    else
      bad "I1_pid_disappears_auth_unclear"
    fi
  else
    skip "I1_pid_disappears (no output file)"
  fi

  # I2: Comprehensive tier enforcement matrix
  log "I2: Testing comprehensive tier enforcement..."

  # Test Admin-only endpoints with Operator user (should all fail)
  local admin_endpoints=("SystemReboot" "SystemShutdown" "HostnameRandomizeNow" "LoggingConfigSet")
  local i2_failures=0

  for ep in "${admin_endpoints[@]}"; do
    local test_data='null'
    [[ "$ep" == "LoggingConfigSet" ]] && test_data='{"enabled":true,"level":"info"}'

    if rj_rpc "I2_${ep}" "$ep" "$test_data" "$OP_USER" >/dev/null 2>&1; then
      bad "I2_${ep}_denied (SECURITY: Operator should not access Admin endpoint)"
      ((i2_failures++)) || true
    else
      ok "I2_${ep}_denied"
    fi
  done

  if [[ $i2_failures -eq 0 ]]; then
    ok "I2_tier_enforcement_comprehensive"
  else
    bad "I2_tier_enforcement_comprehensive ($i2_failures endpoints allowed incorrectly)"
  fi

  # I3: Protocol abuse boundaries (repeated oversized frames)
  log "I3: Testing protocol abuse DOS resistance..."

  python3 - "$SOCKET" "$OUT/artifacts" <<'PYTEST'
import json, socket, struct, sys
sock_path, outdir = sys.argv[1], sys.argv[2]

def enc(b): return struct.pack(">I", len(b)) + b
def enc_len(n): return struct.pack(">I", n)
def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise EOFError()
        buf += c
    return buf
def read_frame(s):
    hdr = read_exact(s, 4)
    (ln,) = struct.unpack(">I", hdr)
    if ln > 10*1024*1024:
        raise ValueError(f"refusing to read {ln} bytes")
    return read_exact(s, ln)

result = {"test": "I3_protocol_abuse", "success": True}

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)

    hello = {"protocol_version": 1, "client_name": "rjdiag", "client_version": "0.1", "supports": []}
    s.sendall(enc(json.dumps(hello).encode()))
    ack = json.loads(read_frame(s).decode())

    # Send 10 oversized frame headers rapidly
    for i in range(10):
        s.sendall(enc_len(999999999))
        try:
            resp = read_frame(s)
            result[f"attempt_{i}"] = "got_response"
        except:
            result[f"attempt_{i}"] = "disconnected"
            break

    result["msg"] = "Daemon handled abuse without crash"

    with open(f"{outdir}/I3_protocol_abuse.json", "w") as f:
        json.dump(result, f, indent=2)

except Exception as e:
    result["error"] = str(e)
    result["msg"] = "Daemon disconnected abuser (good)"
    with open(f"{outdir}/I3_protocol_abuse.json", "w") as f:
        json.dump(result, f, indent=2)
PYTEST

  # Verify service still running
  if systemctl is-active --quiet "$SERVICE"; then
    ok "I3_protocol_abuse_dos_resistant (service still active)"
  else
    bad "I3_protocol_abuse_dos_resistant (SERVICE CRASHED!)"
  fi
}

# =============================
# Suite J: Dangerous/Disruptive
# =============================
suite_J_dangerous() {
  if [[ $DANGEROUS -eq 0 ]]; then
    skip "Suite J (requires --dangerous flag)"
    return 0
  fi

  log ""
  log "========================================"
  log "SUITE J: Dangerous/Disruptive Tests"
  log "========================================"
  log "[WARN] Running disruptive tests - network state may change!"

  # J1: WiFi scan (safe-ish but requires hardware)
  rj_rpc "J1" "WifiScanStart" '{"interface":"wlan0"}' "root" || {
    skip "J1_wifi_scan (no wlan0 or failed)"
  }

  # J2: Hotspot start/stop (disruptive!)
  log "J2: Testing hotspot start/stop..."
  local hotspot_if="wlan1"  # Use external adapter

  if rj_rpc "J2a" "HotspotStart" "{\"ssid\":\"RJTest\",\"password\":\"testpass123\",\"interface\":\"$hotspot_if\"}" "root" >/dev/null 2>&1; then
    sleep 2
    rj_rpc "J2b" "HotspotStop" "null" "root" || true
    ok "J2_hotspot_start_stop"
  else
    skip "J2_hotspot_start_stop (failed to start)"
  fi

  # J3: Mount/unmount (requires USB device)
  skip "J3_mount_unmount (requires manual USB device setup)"

  # J4: SystemSync (safe-ish admin operation)
  rj_rpc "J4" "SystemSync" "null" "$ADMIN_USER"

  log "[WARN] Dangerous tests complete - verify network connectivity!"
}

# =============================
# Final Report Generation
# =============================
generate_final_report() {
  log ""
  log "========================================"
  log "DIAGNOSTIC RUN COMPLETE"
  log "========================================"

  local total=$((TESTS_PASS + TESTS_FAIL + TESTS_SKIP))
  local pass_rate=0
  [[ $total -gt 0 ]] && pass_rate=$((TESTS_PASS * 100 / total))

  log "Results Summary:"
  log "  Total Tests: $total"
  log "  Passed:      $TESTS_PASS"
  log "  Failed:      $TESTS_FAIL"
  log "  Skipped:     $TESTS_SKIP"
  log "  Pass Rate:   ${pass_rate}%"
  log ""
  log "Artifacts:"
  log "  Run Directory: $OUT"
  log "  Diagnostic Log: $LOG"
  log "  Summary JSON: $SUMMARY"
  log "  System Info: $SYSINFO"
  log ""

  # Generate final summary JSON
  python3 - "$OUT" "$TESTS_PASS" "$TESTS_FAIL" "$TESTS_SKIP" <<'PYFINAL'
import json, sys
outdir, passed, failed, skipped = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
total = passed + failed + skipped
summary = {
    "run_id": outdir.split("/")[-1],
    "timestamp": outdir.split("/")[-1],
    "totals": {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "pass_rate": round(passed * 100.0 / total, 2) if total > 0 else 0
    }
}
with open(f"{outdir}/final_summary.json", "w") as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
PYFINAL

  if [[ $TESTS_FAIL -eq 0 ]]; then
    log "STATUS: ALL TESTS PASSED"
    return 0
  else
    log "STATUS: FAILURES DETECTED ($TESTS_FAIL failed tests)"
    log "Review: $LOG"
    return 1
  fi
}

# =============================
# Main Execution
# =============================
main() {
  require_root

  log "=========================================="
  log "RustyJack Comprehensive Diagnostic Suite"
  log "=========================================="
  log "Run ID: $RUN_ID"
  log "Socket: $SOCKET"
  log "Service: $SERVICE"
  log "Dangerous Mode: $DANGEROUS"
  log "Output: $OUT"
  log "=========================================="

  # Initialize summary
  echo "[]" > "$SUMMARY"

  # Gather system info
  {
    echo "=== System Information ==="
    uname -a
    echo ""
    echo "=== OS Release ==="
    cat /etc/os-release 2>/dev/null || echo "N/A"
    echo ""
    echo "=== Memory ==="
    free -h
    echo ""
    echo "=== Disk ==="
    df -h
    echo ""
    echo "=== Network Interfaces ==="
    ip link show
    echo ""
    echo "=== Python Version ==="
    python3 --version
  } > "$SYSINFO" 2>&1

  # Generate RPC helper
  generate_rpc_helper

  # Run test suites
  suite_A_sanity || true
  suite_B_hardening || true
  suite_C_auth_matrix || true
  suite_D_protocol_negative || true
  suite_E_safe_smoke || true
  suite_F_jobs || true
  suite_G_logging || true
  suite_H_stress || true
  suite_I_security || true
  suite_J_dangerous || true

  # Final report
  generate_final_report
}

# Execute
main "$@"
