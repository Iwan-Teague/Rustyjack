# RustyJack Comprehensive Testing Suite

## Overview

This document describes the comprehensive diagnostic test suite for RustyJack, implemented as a single bash script that validates security, correctness, and reliability on the Raspberry Pi.

## Files

- **`scripts/rustyjack_comprehensive_test.sh`** - Main comprehensive test script (NEW)
- **`rustyjackd_diag.sh`** - Original diagnostic script (baseline)
- **`rustyjackd_pi_diagnostic_blueprint.pdf`** - Detailed test specification

## Quick Start

### Running Tests (Safe Mode - Default)

```bash
# Run as root (required for user creation, systemd inspection, /proc access)
sudo ./scripts/rustyjack_comprehensive_test.sh
```

This runs **all non-disruptive tests** including:
- Service health checks
- Security hardening validation
- Authorization tier enforcement
- Protocol robustness testing
- Stress testing
- Security adversarial probes

### Running Tests (Dangerous Mode)

```bash
# Enable disruptive tests (WiFi, hotspot, mount operations)
sudo ./scripts/rustyjack_comprehensive_test.sh --dangerous
```

⚠️ **Warning**: Dangerous mode may:
- Modify network state (WiFi connect/disconnect)
- Start/stop hotspot (disrupts connectivity)
- Mount/unmount USB devices
- **Use only on lab/test devices!**

### Custom Options

```bash
# Verbose output
sudo ./scripts/rustyjack_comprehensive_test.sh --verbose

# Custom socket path
sudo ./scripts/rustyjack_comprehensive_test.sh --socket /custom/path/rustyjackd.sock

# Custom stress iterations
sudo ./scripts/rustyjack_comprehensive_test.sh --stress 500

# Parallel stress clients
sudo ./scripts/rustyjack_comprehensive_test.sh --parallel 50
```

## Test Suites

### Suite A: Installation & Service Sanity
**Purpose**: Verify daemon binary, systemd unit, runtime directories, and socket configuration.

**Tests**:
- `A1` - Service enabled check
- `A2` - Service active check
- `A3-A4` - Service properties and unit file capture
- `A5` - Runtime directory existence and permissions
- `A6-A7` - Socket existence, type, and permission security
- `A8` - Journal "ready" indicator check
- `A9` - MainPID extraction for /proc inspection

**Pass Criteria**:
- Service is active with valid MainPID
- Socket exists as Unix socket with secure permissions (not world-accessible)
- Journal shows startup without crash loops

---

### Suite B: Systemd Hardening Posture
**Purpose**: Validate sandboxing directives and security hardening score.

**Tests**:
- `B1` - `systemd-analyze security` posture score
- `B2` - Hardening properties extraction (CapabilityBoundingSet, NoNewPrivileges, ProtectSystem, MemoryDenyWriteExecute, etc.)
- `B3` - Live capability check via `/proc/<MainPID>/status`

**Pass Criteria**:
- systemd security score captured for regression tracking
- NoNewPrivileges enabled
- CapEff does not contain unexpected capabilities
- ProtectSystem=strict with explicit ReadWritePaths

**Output**: `systemd/security.txt`, `systemd/hardening_props.txt`, `proc/capabilities.txt`

---

### Suite C: Authorization Matrix & Tiers
**Purpose**: Verify OS-level and daemon-level authorization boundaries.

**Tests**:
- `C1-C3` - Tier detection via handshake (ReadOnly, Operator, Admin)
- `C4-C6` - Tier enforcement (Admin endpoints denied to Operator, Operator endpoints denied to ReadOnly)
- `C7-C10` - Authorization matrix samples across all tiers

**Test Users** (ephemeral, auto-cleanup):
- `rjdiag_ro` - ReadOnly (no groups)
- `rjdiag_op` - Operator (group: rustyjack)
- `rjdiag_admin` - Admin (groups: rustyjack, rustyjack-admin)

**Pass Criteria**:
- Handshake correctly reports tier based on group membership
- Admin-only endpoints return Forbidden for Operator/ReadOnly
- Operator-only endpoints return Forbidden for ReadOnly

**Critical Security Checks**:
- SO_PEERCRED credentials verified
- Group membership correctly determines authorization tier
- No privilege escalation via tier bypass

---

### Suite D: Protocol Robustness
**Purpose**: Ensure daemon rejects malformed frames/JSON, enforces size limits, and disconnects on repeated violations.

**Tests**:
- `D1` - Protocol version mismatch rejection (expect IncompatibleProtocol error)
- `D2` - Oversized frame rejection (expect ProtocolViolation)
- `D3` - 3 protocol violations → disconnect enforcement
- `D4` - Endpoint/body type mismatch detection

**Pass Criteria**:
- Daemon returns structured error responses (not crashes)
- After 3 protocol violations, connection is dropped
- Service remains active (no crash or file descriptor leak)

**Output**: `artifacts/protocol_negative/D*.json`

---

### Suite E: Safe Functional Smoke Tests
**Purpose**: Exercise minimum set of read-only, non-disruptive endpoints.

**Endpoints Tested**:
- Core: Health, Version, Status
- System: SystemStatusGet, DiskUsageGet, BlockDevicesList
- Interfaces: ActiveInterfaceGet, InterfaceStatusGet, WifiInterfacesList, WifiCapabilitiesGet
- Services: PortalStatus, MountList
- Logging: LoggingConfigGet, LogTailGet

**Pass Criteria**:
- All endpoints return ResponseOk with expected fields
- No Internal errors under normal conditions
- Latency: Health/Version < 100ms

**Output**: `rpc/responses/E*.json`

---

### Suite F: Job Subsystem Reliability
**Purpose**: Validate job start/status/cancel flows and state transitions.

**Tests**:
- `F1-F2` - Start Noop job, poll until completed/failed
- `F3-F5` - Start Sleep job, cancel mid-execution, verify cancelled state

**Pass Criteria**:
- JobStart returns job_id
- JobStatus returns coherent JobInfo with monotonic state transitions
- Cancelled jobs do not continue running

**Tested Job Kinds**:
- Noop (instant completion)
- Sleep (cancellable long-running operation)

---

### Suite G: Logging & Observability
**Purpose**: Verify diagnostic data availability when failures occur.

**Tests**:
- `G1` - Full journal capture since boot
- `G2` - LogTailGet RPC (200 lines)
- `G3-G4` - Log directory permissions (not world-writable)
- `G5` - Recent error extraction from journal

**Pass Criteria**:
- LogTailGet returns lines with correct truncation flag
- Log directory permissions secure (others=0 or 5)
- On failures, request_id and log context available for debugging

**Output**: `systemd/journal_full.txt`, `artifacts/recent_errors.txt`

---

### Suite H: Stress & Soak
**Purpose**: Detect race conditions, timeouts, memory leaks, and file descriptor leaks under load.

**Tests**:
- `H1` - Sequential burst (default: 200 Health requests)
- `H2` - Connection churn (100 connect/disconnect cycles)
- `H3` - File descriptor leak detection (compare FD count before/after)
- `H4` - Memory footprint (RSS) check

**Pass Criteria**:
- Error rate < 10% under configured load
- FD count delta < 10 after stress
- No crash or service restart
- RSS stable (no unbounded growth trend)

**Output**: `proc/fd_after_stress.txt`, memory_rss_kb in summary

---

### Suite I: Security Adversarial Tests
**Purpose**: Probe for privilege escalation and authorization weaknesses.

**Tests**:
- `I1` - **PID disappears group lookup fallback**
  - Parent process connects, forks, then exits
  - Child process (now orphaned) attempts Operator-only endpoint as ReadOnly user
  - **CRITICAL**: If successful, this is a privilege escalation vulnerability

- `I2` - Comprehensive tier enforcement matrix
  - Test all Admin-only endpoints (SystemReboot, SystemShutdown, HostnameRandomizeNow, LoggingConfigSet) with Operator credentials
  - All should return Forbidden

- `I3` - Protocol abuse DOS resistance
  - Rapid oversized frame headers (10 attempts)
  - Daemon should disconnect abuser without crashing

**Pass Criteria**:
- **I1 MUST NOT allow privilege escalation** (if it does, treat as CRITICAL vulnerability)
- All Admin endpoints correctly denied to non-Admin users
- Service remains active after abuse attempts

**Output**: `artifacts/I*.json`

⚠️ **Security Note**: Failure of I1 indicates a critical security vulnerability in SO_PEERCRED handling or group lookup fallback logic.

---

### Suite J: Dangerous/Disruptive Tests (--dangerous flag required)
**Purpose**: Validate state-changing operations on lab devices.

**Tests** (examples, gated behind `--dangerous`):
- `J1` - WiFi scan start
- `J2` - Hotspot start/stop
- `J3` - Mount/unmount USB devices (requires manual setup)
- `J4` - SystemSync

**Requirements**:
- Explicit `--dangerous` flag
- Lab/test device (not production)
- Manual verification of network state after tests

**Pass Criteria**:
- Operations complete without daemon crash
- State changes reversible
- No unexpected side effects

---

## Output Structure

After a test run, artifacts are organized under `/var/tmp/rustyjackd-diag/<timestamp>/`:

```
<timestamp>/
├── diag.log                     # Human-readable log with timestamps
├── summary.json                 # Machine-readable events (one JSON object per line)
├── final_summary.json           # Aggregate pass/fail/skip counts
├── sysinfo.txt                  # uname, os-release, memory, disk, network
├── systemd/
│   ├── unit.txt                 # systemctl cat rustyjackd.service
│   ├── show.txt                 # systemctl show properties
│   ├── security.txt             # systemd-analyze security score
│   ├── hardening_props.txt      # Sandboxing directives
│   ├── journal_tail.txt         # Recent journal (200 lines)
│   ├── journal_full.txt         # Full journal since boot
│   └── socket_stat.txt          # stat output for UDS
├── proc/
│   ├── main_pid.txt             # Daemon MainPID
│   ├── capabilities.txt         # CapEff, CapBnd from /proc/<pid>/status
│   └── fd_after_stress.txt      # FD list after stress tests
├── rpc/
│   ├── requests/                # JSON request payloads
│   │   ├── E1_Health.json
│   │   └── ...
│   └── responses/               # JSON response envelopes
│       ├── E1_Health.json
│       └── ...
├── artifacts/
│   ├── rj_rpc.py                # Generated Python RPC helper
│   ├── protocol_negative/       # Protocol robustness test outputs
│   │   ├── D1_incompatible_protocol.json
│   │   ├── D2_oversize_frame.json
│   │   └── D3_three_violations.json
│   ├── I1_pid_disappears.json   # Security test: PID auth bypass
│   ├── I3_protocol_abuse.json   # DOS resistance test
│   ├── log_dir_perms.txt        # /var/lib/rustyjack/logs permissions
│   └── recent_errors.txt        # Extracted errors from journal
└── security/                    # (reserved for future security-specific artifacts)
```

## Interpreting Results

### Exit Codes
- `0` - All tests passed
- `1` - One or more tests failed
- `2` - Invalid arguments

### Log Format
```
2026-01-10T14:32:15+00:00 [PASS] A1_service_enabled
2026-01-10T14:32:15+00:00 [FAIL] C4_admin_endpoint_op_denied (error_type=daemon_error)
2026-01-10T14:32:16+00:00 [SKIP] J1_wifi_scan (requires --dangerous flag)
2026-01-10T14:32:17+00:00 [INFO] Security exposure: 8.2 UNSAFE
```

### Critical Failures

**Immediate Action Required**:
- `I1_pid_disappears_auth_VULNERABLE` → **Privilege escalation vulnerability** (file bug immediately)
- Service crash during stress tests → Stability issue
- FD leak > 50 after stress → Resource leak

**Review Recommended**:
- Security exposure score degradation (compare across runs)
- Admin endpoint accessible to Operator (authorization bypass)
- >10% request failure rate under stress

### Performance Baselines

Typical values on Raspberry Pi Zero 2 W:
- **Health latency**: 10-50ms
- **Sequential burst throughput**: 20-100 req/s
- **FD delta after stress**: 0-5
- **RSS**: 10-30 MB (varies with workload)

## Comparison with Original Script

### Enhanced Features

| Feature | Original (`rustyjackd_diag.sh`) | Comprehensive (`scripts/rustyjack_comprehensive_test.sh`) |
|---------|----------------------------------|---------------------------------------------------|
| Test Suites | A, B, C (partial), D (partial), E, F, H (basic) | **All suites: A-J** |
| Suite G (Logging) | ❌ Not implemented | ✅ Full journal capture, log permissions |
| Suite I (Security) | ❌ Not implemented | ✅ **PID auth bypass, tier enforcement matrix, DOS resistance** |
| Suite J (Dangerous) | ❌ Flag exists but no tests | ✅ WiFi/hotspot/mount tests (gated) |
| Error Reporting | Basic | **Enhanced with error_type classification** |
| FD Leak Detection | ❌ | ✅ Before/after FD count comparison |
| Memory Monitoring | ❌ | ✅ RSS capture and reporting |
| Test Counters | ❌ | ✅ Pass/Fail/Skip totals with pass rate |
| Final Summary | ❌ | ✅ Machine-readable JSON summary |
| /proc Inspection | ❌ | ✅ Capabilities, FD list |
| Comprehensive Auth Matrix | ❌ | ✅ All endpoint tiers tested |

### Migration Guide

**Keep using original script if**:
- Quick smoke test needed
- Running on production device (safer defaults)

**Use comprehensive script for**:
- Full validation after code changes
- Security audit
- Pre-release testing
- Regression detection
- Performance baselining

## Troubleshooting

### "Must run as root"
**Cause**: Script requires root to create test users, read systemd internals, access /proc.

**Solution**:
```bash
sudo ./scripts/rustyjack_comprehensive_test.sh
```

### "Service not active"
**Cause**: rustyjackd.service is not running.

**Solution**:
```bash
sudo systemctl start rustyjackd
sudo systemctl status rustyjackd
```

### Test users not cleaned up
**Cause**: Script interrupted before trap cleanup.

**Solution**:
```bash
sudo userdel -r rjdiag_ro rjdiag_op rjdiag_admin
```

### Python module import errors
**Cause**: Missing Python 3 (unlikely on Raspberry Pi OS).

**Solution**:
```bash
sudo apt-get install python3
```

### Permission denied on socket
**Cause**: User lacks permission to access `/run/rustyjack/rustyjackd.sock`.

**Expected**: ReadOnly test users (`rjdiag_ro`) may fail to connect - this validates filesystem permissions.

### High failure rate in Suite H (Stress)
**Possible causes**:
- Raspberry Pi Zero 2 W under heavy load (thermal throttling)
- Network instability
- Insufficient resources

**Debug**:
1. Check `journalctl -u rustyjackd -f` during stress test
2. Monitor `top` / `htop` for CPU/memory
3. Reduce `--stress` iterations
4. Reduce `--parallel` clients

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: RustyJack Diagnostic Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: self-hosted  # Raspberry Pi runner
    steps:
      - uses: actions/checkout@v3
      - name: Run comprehensive tests
        run: sudo ./scripts/rustyjack_comprehensive_test.sh
      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: diagnostic-results
          path: /var/tmp/rustyjackd-diag/*/
```

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit
if [[ "$(git diff --cached --name-only | grep -E 'rustyjack-daemon|rustyjack-ipc')" ]]; then
    echo "Daemon code changed - running quick diagnostic..."
    sudo ./scripts/rustyjack_comprehensive_test.sh --stress 50
fi
```

## Extending the Test Suite

### Adding New Tests

1. **Create new suite function**:
```bash
suite_K_my_feature() {
  log ""
  log "========================================"
  log "SUITE K: My Feature Tests"
  log "========================================"

  rj_rpc "K1" "MyEndpoint" '{"param":"value"}' "root"
  # ... more tests
}
```

2. **Call in main()**:
```bash
main() {
  # ... existing suites
  suite_K_my_feature || true
  # ...
}
```

3. **Document in TESTING.md** (this file)

### Adding New RPC Endpoints to Test

Edit the `rj_rpc` calls in Suite E or Suite C:
```bash
rj_rpc "E99" "NewEndpoint" '{"arg1":"val1"}' "root"
```

The Python RPC helper (`rj_rpc.py`) automatically handles CamelCase→snake_case endpoint conversion.

## References

- **Blueprint**: `rustyjackd_pi_diagnostic_blueprint.pdf`
- **IPC Protocol**: `rustyjack-ipc/src/wire.rs`, `rustyjack-daemon/src/server.rs`
- **Authorization**: `rustyjack-daemon/src/auth.rs::required_tier()`
- **Endpoint Matrix**: See blueprint PDF page 5-6

## License

MIT (same as RustyJack project)

---

**Generated**: 2026-01-10
**Script Version**: 1.0
**Maintainer**: RustyJack Project
