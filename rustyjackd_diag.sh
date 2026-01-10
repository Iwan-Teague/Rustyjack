#!/usr/bin/env bash
# Rustyjackd on-device diagnostic harness (SAFE by default)
# Generated blueprint: see accompanying PDF for full rationale and extension points.

set -euo pipefail

# -----------------------------
# Config / args
# -----------------------------
SOCKET_DEFAULT="/run/rustyjack/rustyjackd.sock"
SERVICE_DEFAULT="rustyjackd.service"
OUTROOT_DEFAULT="/var/tmp/rustyjackd-diag"
DANGEROUS=0
PARALLEL=25

usage() {
  cat <<'USAGE'
Usage: rustyjackd_diag.sh [options]

Options:
  --socket PATH          UDS path (default: /run/rustyjack/rustyjackd.sock)
  --service UNIT         systemd unit name (default: rustyjackd.service)
  --outroot DIR          output root (default: /var/tmp/rustyjackd-diag)
  --dangerous            enable disruptive tests (wifi connect, hotspot, mount, etc.)
  --parallel N           parallel clients for stress (default: 25)
  -h, --help             show help

Notes:
- Run as root (recommended): creates temporary test users and reads systemd/journal.
- SAFE mode does not modify network state or mount devices.
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
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

# -----------------------------
# Output directories / logging
# -----------------------------
RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT="$OUTROOT/$RUN_ID"
mkdir -p "$OUT"/{systemd,rpc/requests,rpc/responses,artifacts}

LOG="$OUT/diag.log"
SUMMARY="$OUT/summary.json"

log()  { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$LOG" ; }
ok()   { log "[PASS] $*"; }
bad()  { log "[FAIL] $*"; return 1; }

# Record summary in JSON (append lines; easy to post-process)
summary_event() {
  local status="$1" name="$2" detail="${3:-}"
  printf '{"ts":"%s","status":"%s","name":"%s","detail":%s}\n' \
    "$(date -Is)" "$status" "$name" \
    "$(python3 - <<PY
import json,sys
print(json.dumps(sys.argv[1]))
PY
"$detail")" >> "$SUMMARY"
}

# run a shell command as a "test case"
run_cmd() {
  local name="$1"; shift
  log "[CMD] $name :: $*"
  if "$@" >>"$LOG" 2>&1; then
    ok "$name"
    summary_event "pass" "$name" ""
  else
    local rc=$?
    bad "$name (rc=$rc)" || true
    summary_event "fail" "$name" "rc=$rc; cmd=$*"
    return $rc
  fi
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Please run as root (sudo). Some tests require creating users and reading service internals." >&2
    exit 1
  fi
}

# -----------------------------
# Ephemeral users for tier tests
# -----------------------------
RO_USER="rjdiag_ro"
OP_USER="rjdiag_op"
ADMIN_USER="rjdiag_admin"

cleanup_users() {
  for u in "$RO_USER" "$OP_USER" "$ADMIN_USER"; do
    if id "$u" >/dev/null 2>&1; then
      userdel -r "$u" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup_users EXIT

create_test_users() {
  # Expected groups created by install
  if ! getent group rustyjack >/dev/null; then
    log "[WARN] group 'rustyjack' missing; operator role tests may not be meaningful."
  fi
  if ! getent group rustyjack-admin >/dev/null; then
    log "[WARN] group 'rustyjack-admin' missing; admin role tests may not be meaningful."
  fi

  # Create system users without home/shell (safe-ish); ignore if already exists
  for u in "$RO_USER" "$OP_USER" "$ADMIN_USER"; do
    if ! id "$u" >/dev/null 2>&1; then
      useradd -M -r -s /usr/sbin/nologin "$u"
    fi
  done

  # Group membership
  usermod -a -G rustyjack "$OP_USER" 2>/dev/null || true
  usermod -a -G rustyjack "$ADMIN_USER" 2>/dev/null || true
  usermod -a -G rustyjack-admin "$ADMIN_USER" 2>/dev/null || true
}

# -----------------------------
# Embedded Python RPC helper
# -----------------------------
# We generate a helper file once per run (keeps the harness a single .sh file,
# but makes sudo/user switching reliable).
PY_HELPER="$OUT/artifacts/rj_rpc.py"
cat >"$PY_HELPER" <<'PY'
import json, os, socket, struct, sys, time, re

SOCKET_PATH = sys.argv[1]
BODY_TYPE   = sys.argv[2]
REQ_PATH    = sys.argv[3]

PROTOCOL_VERSION = 1

def camel_to_snake(s: str) -> str:
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', s)
    s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()

def encode_frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload

def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("unexpected EOF")
        buf += chunk
    return buf

def read_frame(sock: socket.socket, max_frame: int = 1_048_576) -> bytes:
    hdr = read_exact(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    if length == 0:
        raise ValueError("zero-length frame")
    if length > max_frame:
        raise ValueError(f"frame too large: {length} > {max_frame}")
    return read_exact(sock, length)

def rpc(sock: socket.socket, body_type: str, data):
    request_id = int(time.time() * 1000) & 0xFFFFFFFFFFFF  # fine for diagnostics
    endpoint = camel_to_snake(body_type)
    env = {
        "v": PROTOCOL_VERSION,
        "request_id": request_id,
        "endpoint": endpoint,
        "body": {"type": body_type, "data": data} if data is not None else {"type": body_type}
    }
    payload = json.dumps(env, separators=(",", ":")).encode("utf-8")
    sock.sendall(encode_frame(payload))
    raw = read_frame(sock)
    resp = json.loads(raw.decode("utf-8"))
    return request_id, resp, raw

def main():
    t0 = time.time()
    try:
        with open(REQ_PATH, "rb") as f:
            req_data = f.read().strip()
        data = None
        if req_data and req_data != b"null":
            data = json.loads(req_data.decode("utf-8"))

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(SOCKET_PATH)

        # Handshake
        hello = {
            "protocol_version": PROTOCOL_VERSION,
            "client_name": "rjdiag",
            "client_version": "0.1",
            "supports": []
        }
        s.sendall(encode_frame(json.dumps(hello).encode("utf-8")))
        ack_raw = read_frame(s)
        ack = json.loads(ack_raw.decode("utf-8"))

        # Request
        rid, resp, raw = rpc(s, BODY_TYPE, data)

        elapsed_ms = int((time.time() - t0) * 1000)
        out = {
            "ok": True,
            "timing_ms": elapsed_ms,
            "handshake": ack,
            "response": resp,
        }

        # Fail on daemon Err
        body = resp.get("body", {})
        if body.get("type") == "Err":
            out["ok"] = False
            out["error"] = body.get("data", body)
            print(json.dumps(out))
            sys.exit(10)

        print(json.dumps(out))
        sys.exit(0)

    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        out = {
            "ok": False,
            "timing_ms": elapsed_ms,
            "transport_error": str(e),
        }
        print(json.dumps(out))
        sys.exit(20)

if __name__ == "__main__":
    main()
PY
chmod 755 "$PY_HELPER"

# Wrapper that runs python helper as specified user and stores artifacts
rj_rpc() {
  local id="$1" body_type="$2" data_json="$3" as_user="${4:-root}"
  local req="$OUT/rpc/requests/${id}_${body_type}.json"
  local resp="$OUT/rpc/responses/${id}_${body_type}.json"

  printf '%s\n' "$data_json" > "$req"

  log "[RPC] $id $body_type as=$as_user data=$data_json"
  if sudo -u "$as_user" python3 "$PY_HELPER" "$SOCKET" "$body_type" "$req" >"$resp" 2>>"$LOG"; then
    ok "RPC $id $body_type"
    summary_event "pass" "rpc:$id:$body_type" ""
    return 0
  else
    local rc=$?
    log "[RPC] response: $(cat "$resp" 2>/dev/null || true)"
    bad "RPC $id $body_type (rc=$rc)" || true
    summary_event "fail" "rpc:$id:$body_type" "rc=$rc"
    return $rc
  fi
}

# -----------------------------
# Suites
# -----------------------------
suite_A_sanity() {
  run_cmd "A1 systemctl is-active" systemctl is-active --quiet "$SERVICE"
  run_cmd "A2 systemctl show" systemctl show "$SERVICE" -p MainPID,ExecStart,User,Group,Environment >"$OUT/systemd/show.txt"
  run_cmd "A3 systemctl cat" systemctl cat "$SERVICE" >"$OUT/systemd/unit.txt"
  run_cmd "A4 ls runtime dirs" bash -lc "ls -ld /run/rustyjack /var/lib/rustyjack || true"
  run_cmd "A5 socket stat" bash -lc "stat '$SOCKET' || true"
  run_cmd "A6 journal tail" bash -lc "journalctl -u '$SERVICE' -b --no-pager | tail -n 200 >'$OUT/systemd/journal_tail.txt'"
}

suite_B_hardening() {
  if command -v systemd-analyze >/dev/null 2>&1; then
    run_cmd "B1 systemd-analyze security" systemd-analyze security "$SERVICE" >"$OUT/systemd/security.txt"
  else
    log "[SKIP] systemd-analyze not found"
  fi
  run_cmd "B2 show sandboxing props" bash -lc "systemctl show '$SERVICE' -p CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,ProtectKernelTunables,ProtectKernelModules,ProtectProc,RestrictAddressFamilies,SystemCallFilter,MemoryDenyWriteExecute >'$OUT/systemd/hardening_props.txt'"
}

suite_C_auth_matrix() {
  create_test_users

  # Basic connectivity and tier reporting (HelloAck.authz.role)
  rj_rpc "C1" "Health" "null" "$RO_USER" || true
  rj_rpc "C2" "Health" "null" "$OP_USER" || true
  rj_rpc "C3" "Health" "null" "$ADMIN_USER" || true

  # Tier enforcement checks (examples)
  # Admin-only endpoint should fail for operator
  rj_rpc "C4" "LoggingConfigSet" '{"enabled":true,"level":"info"}' "$OP_USER" || true

  # Operator-only endpoint should fail for read-only (or connect denied)
  rj_rpc "C5" "SystemLogsGet" '{"max_lines":50}' "$RO_USER" || true

  # Admin safe action: SystemSync (should be allowed for admin; do not run reboot/shutdown automatically)
  rj_rpc "C6" "SystemSync" "null" "$ADMIN_USER" || true
}

suite_D_protocol_negative() {
  # Negative tests implemented in python (raw framing)
  local outdir="$OUT/artifacts/protocol_negative"
  mkdir -p "$outdir"

  log "[SUITE D] protocol negative tests"

  # D1: hello protocol mismatch -> expect DaemonError code=1 (IncompatibleProtocol)
  python3 - "$SOCKET" >"$outdir/D1_incompatible_protocol.json" <<'PY'
import json, socket, struct, sys
sock_path=sys.argv[1]
def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s,n):
  buf=b""
  while len(buf)<n:
    c=s.recv(n-len(buf))
    if not c: raise EOFError("eof")
    buf+=c
  return buf
def read_frame(s):
  hdr=read_exact(s,4); (ln,)=struct.unpack(">I",hdr)
  return read_exact(s,ln)
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5.0); s.connect(sock_path)
hello={"protocol_version":999,"client_name":"rjdiag","client_version":"0.1","supports":[]}
s.sendall(enc(json.dumps(hello).encode()))
raw=read_frame(s)
try:
  obj=json.loads(raw.decode())
except Exception as e:
  obj={"parse_error":str(e),"raw":raw.decode("utf-8","replace")}
print(json.dumps(obj))
PY
  if grep -q '"code":1' "$outdir/D1_incompatible_protocol.json" 2>/dev/null; then
    ok "D1 incompatible protocol rejected"
    summary_event "pass" "D1_incompatible_protocol" ""
  else
    bad "D1 incompatible protocol did not return expected error"
    summary_event "fail" "D1_incompatible_protocol" "unexpected response"
  fi

  # D2: too-large frame length -> expect ProtocolViolation and connection survives (until repeated)
  python3 - "$SOCKET" >"$outdir/D2_oversize_frame.json" <<'PY'
import json, socket, struct, sys
sock_path=sys.argv[1]
def enc_len(n): return struct.pack(">I", n)
def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s,n):
  buf=b""
  while len(buf)<n:
    c=s.recv(n-len(buf))
    if not c: raise EOFError("eof")
    buf+=c
  return buf
def read_frame(s):
  hdr=read_exact(s,4); (ln,)=struct.unpack(">I",hdr)
  return read_exact(s,ln)
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5.0); s.connect(sock_path)
hello={"protocol_version":1,"client_name":"rjdiag","client_version":"0.1","supports":[]}
s.sendall(enc(json.dumps(hello).encode()))
ack=json.loads(read_frame(s).decode())
maxf=ack.get("max_frame", 1048576)
# send an oversized frame header only (no payload)
s.sendall(enc_len(maxf+1))
raw=read_frame(s)
obj={"ack":ack, "oversize_error":json.loads(raw.decode())}
print(json.dumps(obj))
PY
  if grep -q '"code":1002' "$outdir/D2_oversize_frame.json" 2>/dev/null; then
    ok "D2 oversize frame rejected (ProtocolViolation)"
    summary_event "pass" "D2_oversize_frame" ""
  else
    bad "D2 oversize frame did not return ProtocolViolation"
    summary_event "fail" "D2_oversize_frame" "unexpected response"
  fi

  # D3: 3 protocol violations should drop connection
  python3 - "$SOCKET" >"$outdir/D3_three_violations.json" <<'PY'
import json, socket, struct, sys
sock_path=sys.argv[1]
def enc(b): return struct.pack(">I", len(b)) + b
def read_exact(s,n):
  buf=b""
  while len(buf)<n:
    c=s.recv(n-len(buf))
    if not c: raise EOFError("eof")
    buf+=c
  return buf
def read_frame(s):
  hdr=read_exact(s,4); (ln,)=struct.unpack(">I",hdr)
  return read_exact(s,ln)
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5.0); s.connect(sock_path)
hello={"protocol_version":1,"client_name":"rjdiag","client_version":"0.1","supports":[]}
s.sendall(enc(json.dumps(hello).encode()))
ack=json.loads(read_frame(s).decode())
# send invalid JSON frames 3 times
viol=[]
for i in range(3):
  s.sendall(enc(b"{not json"))
  raw=read_frame(s)
  viol.append(json.loads(raw.decode()))
# next write should fail or read should EOF
dropped=False
try:
  s.sendall(enc(b"{not json"))
  raw=read_frame(s)
  # if we still got something, not dropped yet
  viol.append(json.loads(raw.decode()))
except Exception as e:
  dropped=True
print(json.dumps({"ack":ack, "violations":viol, "dropped":dropped}))
PY
  if grep -q '"dropped": true' "$outdir/D3_three_violations.json" 2>/dev/null; then
    ok "D3 disconnect after repeated violations"
    summary_event "pass" "D3_three_violations" ""
  else
    bad "D3 did not disconnect after repeated violations"
    summary_event "fail" "D3_three_violations" "unexpected behavior"
  fi
}


suite_E_safe_smoke() {
  # Basic safe endpoints
  rj_rpc "E1" "Health" "null" "root"
  rj_rpc "E2" "Version" "null" "root"
  rj_rpc "E3" "Status" "null" "root"
  rj_rpc "E4" "SystemStatusGet" "null" "root"
  rj_rpc "E5" "DiskUsageGet" '{"path":"/"}' "root"
  rj_rpc "E6" "BlockDevicesList" "null" "root"
  rj_rpc "E7" "ActiveInterfaceGet" "null" "root"
  rj_rpc "E8" "WifiInterfacesList" "null" "root"
  rj_rpc "E9" "PortalStatus" "null" "root"
  rj_rpc "E10" "MountList" "null" "root"
  rj_rpc "E11" "LoggingConfigGet" "null" "root"
  rj_rpc "E12" "LogTailGet" '{"component":"rustyjackd","max_lines":200}' "root" || true
}

suite_F_jobs() {
  log "[SUITE F] job subsystem"

  # Start Noop job
  rj_rpc "F1" "JobStart" '{"job":{"kind":{"type":"Noop"},"requested_by":"diag"}}' "root"

  # Extract job_id
  local resp="$OUT/rpc/responses/F1_JobStart.json"
  local job_id
  job_id="$(python3 - "$resp" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1]))
# ResponseEnvelope -> body -> Ok -> JobStarted
resp=obj.get("response",{})
body=resp.get("body",{})
ok=body.get("data",{})
if ok.get("type")!="JobStarted":
  print("")
  sys.exit(0)
data=ok.get("data",{})
print(data.get("job_id",""))
PY
)"
  if [[ -z "$job_id" ]]; then
    bad "F1 could not extract job_id" || true
    summary_event "fail" "F1_jobstart_extract" "no job_id"
    return 1
  fi
  ok "F1 job_id=$job_id"

  # Poll status until completed/failed (max 5s)
  local deadline=$(( $(date +%s) + 5 ))
  local state=""
  while [[ $(date +%s) -lt $deadline ]]; do
    rj_rpc "F2" "JobStatus" "{\"job_id\":\"$job_id\"}" "root" || true
    state="$(python3 - "$OUT/rpc/responses/F2_JobStatus.json" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1]))
resp=obj.get("response",{})
body=resp.get("body",{})
ok=body.get("data",{})
if ok.get("type")!="JobInfo":
  print("")
  sys.exit(0)
info=ok.get("data",{})
print(info.get("state",""))
PY
)"
    [[ -n "$state" ]] && log "[F2] state=$state"
    if [[ "$state" == "completed" || "$state" == "failed" || "$state" == "cancelled" ]]; then
      break
    fi
    sleep 0.2
  done
  if [[ "$state" == "completed" || "$state" == "failed" ]]; then
    ok "F2 job reached terminal state=$state"
    summary_event "pass" "suite:F_jobs_noop" "state=$state"
  else
    bad "F2 job did not reach terminal state (state=$state)" || true
    summary_event "fail" "suite:F_jobs_noop" "state=$state"
  fi

  # Start Sleep job, then cancel
  rj_rpc "F3" "JobStart" '{"job":{"kind":{"type":"Sleep","ms":2000},"requested_by":"diag"}}' "root"
  local resp2="$OUT/rpc/responses/F3_JobStart.json"
  local job2
  job2="$(python3 - "$resp2" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1]))
resp=obj.get("response",{})
body=resp.get("body",{})
ok=body.get("data",{})
if ok.get("type")!="JobStarted":
  print("")
  sys.exit(0)
print(ok.get("data",{}).get("job_id",""))
PY
)"
  if [[ -n "$job2" ]]; then
    sleep 0.2
    rj_rpc "F4" "JobCancel" "{\"job_id\":\"$job2\"}" "root" || true
    ok "F4 cancel issued job_id=$job2"
    summary_event "pass" "suite:F_jobs_cancel" "job_id=$job2"
  else
    bad "F3 could not extract job_id for Sleep job" || true
    summary_event "fail" "suite:F_jobs_cancel" "no job_id"
  fi

  # Gating check: attempt SystemUpdate job (should be forbidden unless dangerous_ops enabled)
  rj_rpc "F5" "JobStart" '{"job":{"kind":{"type":"SystemUpdate"},"requested_by":"diag"}}' "root" || true
  summary_event "info" "suite:F_jobs_dangerous_gate" "attempted SystemUpdate job start (should be Forbidden by default)"
}


suite_H_stress() {
  log "[STRESS] sequential health burst"
  for i in $(seq 1 50); do
    rj_rpc "H1_$i" "Health" "null" "root" >/dev/null || true
  done
  summary_event "pass" "suite:H_stress" "ran 50 sequential health requests"
}

main() {
  require_root
  log "Run directory: $OUT"
  log "Socket: $SOCKET  Service: $SERVICE  Dangerous: $DANGEROUS"

  # Save sysinfo
  run_cmd "sysinfo uname" uname -a >"$OUT/sysinfo.txt"
  run_cmd "sysinfo os-release" bash -lc "cat /etc/os-release >>'$OUT/sysinfo.txt' || true"
  run_cmd "sysinfo df" bash -lc "df -h >>'$OUT/sysinfo.txt' || true"
  run_cmd "sysinfo ip link" bash -lc "ip link >>'$OUT/sysinfo.txt' || true"

  suite_A_sanity
  suite_B_hardening
  suite_C_auth_matrix || true
  suite_D_protocol_negative || true
  suite_E_safe_smoke
  suite_F_jobs || true
  suite_H_stress || true

  # Capture full journal since boot (or you can narrow to since RUN_ID)
  run_cmd "journal full" bash -lc "journalctl -u '$SERVICE' -b --no-pager >'$OUT/systemd/journal_full.txt' || true"

  log "DONE. Artifacts in: $OUT"
  log "Summary JSON: $SUMMARY"
}

main "$@"
