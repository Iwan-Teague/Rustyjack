# Security Fixes Quick Reference

## Summary
This implementation addresses critical security vulnerabilities identified in the Rustyjack security review, focusing on daemon boundary enforcement and input validation.

## Files Changed (7 total)

### rustyjack-daemon/ (5 files)
1. **src/validation.rs** - Added 9 validation functions, extended constants
2. **src/auth.rs** - Added per-job authorization tier function
3. **src/dispatch.rs** - Enforced validation in JobStart, stricter mount checks
4. **src/server.rs** - Added per-job tier enforcement at connection level
5. **src/jobs/mod.rs** - Fixed retention to never evict active jobs

### rustyjack-core/ (2 files)
6. **Cargo.toml** - Feature-gated CLI binary (security hardening)
7. **src/services/logs.rs** - Added size limits to prevent IPC overflow

## Critical Bugs Fixed

### 1. JobStart Validation Bypass (High Severity)
**Problem:** Generic JobStart endpoint could bypass validation performed by specialized endpoints.
**Fix:** Added `validate_job_kind()` called before any job starts.
**Files:** rustyjack-daemon/src/validation.rs, src/dispatch.rs

### 2. Privilege Escalation via JobStart (High Severity)
**Problem:** Operator-tier clients could start Admin-tier jobs (SystemUpdate).
**Fix:** Added per-job authorization tier check in server connection handler.
**Files:** rustyjack-daemon/src/auth.rs, src/server.rs

### 3. Mount Internal Storage (Medium Severity)
**Problem:** Daemon allowed mounting mmcblk (SD card) and loop devices.
**Fix:** Added `validate_mount_device_hint()` rejecting internal devices.
**Files:** rustyjack-daemon/src/validation.rs, src/dispatch.rs

### 4. IPC Frame Overflow Prevention (MEDIUM - Fixed Phase 2)
**Problem:** SystemLogsGet could generate response exceeding 1MB limit, causing silent failures.
**Fix:** Added size caps and truncation with clear markers.
**Files:** rustyjack-core/src/services/logs.rs

### 5. Mount Shell Command Injection Risk (MEDIUM - Fixed Phase 2)
**Problem:** Mount operations used shell commands, susceptible to injection and less controlled.
**Fix:** Replaced with policy-based syscalls using libc mount directly.
**Files:** rustyjack-core/src/services/mount.rs

### 5. Active Job Eviction (Medium Severity - Fixed Phase 3)
**Problem:** Job retention could evict running jobs, breaking status queries.
**Fix:** Modified retention to only evict finished jobs.
**Files:** rustyjack-daemon/src/jobs/mod.rs

### 6. CLI Backdoor (Low Severity - Defense in Depth - Fixed Phase 5)
**Problem:** Privileged CLI binary installed on production devices bypassed daemon boundary.
**Fix:** Made CLI opt-in via Cargo feature flag.
**Files:** rustyjack-core/Cargo.toml

## Validation Rules Added

### Job Parameters
- **Sleep:** Max 24 hours
- **ScanRun:** Max 256 char target, max 128 ports, mode-specific port validation
- **SystemUpdate:** Service allowlist (rustyjack/rustyjack-ui/rustyjackd), git remote validation, backup dir confinement
- **WiFi ops:** Interface name validation, SSID/PSK length checks
- **Mount ops:** /dev/ prefix required, mmcblk/loop rejected, filesystem allowlist

### String Sanitization
- Control characters rejected (prevents log injection)
- Path traversal patterns rejected (`..`)
- Git-unsafe characters rejected in refs
- Length limits enforced on all user inputs

### Authorization Tiers (Per Job Kind)
- **ReadOnly:** Noop, Sleep
- **Operator:** WifiScan, WifiConnect, HotspotStart, PortalStart, MountStart, UnmountStart, ScanRun
- **Admin:** SystemUpdate

## Constants Added

### rustyjack-daemon/src/validation.rs
```rust
MAX_SLEEP_SECONDS: 86400        // 24 hours
MAX_SCAN_TARGET_LEN: 256
MAX_SCAN_PORTS: 128
MAX_SERVICE_NAME_LEN: 64
MAX_GIT_REMOTE_LEN: 512
MAX_GIT_REF_LEN: 128
MAX_BACKUP_DIR_LEN: 256
```

### rustyjack-core/src/services/logs.rs
```rust
MAX_LOG_BUNDLE_BYTES: 900_000    // Safely under 1MB IPC limit
MAX_SECTION_BYTES: 200_000
MAX_CMD_OUTPUT_BYTES: 100_000
```

## API Changes (Client Impact)

### Breaking Changes
None. All changes are backward-compatible enforcement of existing intent.

### New Validation Failures (Clients will receive BadRequest)
- JobStart with invalid job parameters
- MountStart/UnmountStart with mmcblk or loop devices
- SystemUpdate with non-allowlisted service or invalid git params
- ScanRun with > 128 ports or mismatched mode/ports

### New Authorization Failures (Clients will receive Forbidden)
- Non-root clients attempting SystemUpdate via JobStart

### Behavioral Changes
- SystemLogsGet may include truncation markers if logs exceed limits
- Job retention never evicts active jobs (may temporarily exceed configured retention)

## Build Commands

### Production (No CLI)
```bash
cargo build --release
# Output: rustyjackd, rustyjack-ui (NO rustyjack binary)
```

### Development (With CLI)
```bash
cargo build --release --features cli -p rustyjack-core
# Output: rustyjack binary enabled
```

## Testing Priorities

### Must Test
1. Non-root user cannot start SystemUpdate via JobStart
2. Mount operations reject /dev/mmcblk* and /dev/loop*
3. JobStart validates parameters (same as specialized endpoints)
4. SystemLogsGet response < 1MB even with large journals
5. Active jobs survive retention enforcement

### Should Test
6. All validation functions reject malformed inputs
7. Git parameters are sanitized
8. Control characters rejected in scan targets
9. Job retention only removes finished jobs
10. CLI binary not built without feature flag

### Nice to Test
11. Large log bundles have clear truncation markers
12. Error messages are descriptive and safe
13. Authorization tier mapping is correct for all job kinds

## Rollback Plan

If issues arise, revert these commits in order:

1. Revert rustyjack-core/Cargo.toml (CLI feature-gating)
2. Revert rustyjack-core/src/services/logs.rs (log size limits)
3. Revert rustyjack-daemon/src/jobs/mod.rs (retention fix)
4. Revert rustyjack-daemon/src/server.rs (per-job tier check)
5. Revert rustyjack-daemon/src/dispatch.rs (JobStart validation)
6. Revert rustyjack-daemon/src/auth.rs (per-job tier function)
7. Revert rustyjack-daemon/src/validation.rs (new validators)

Rebuild and redeploy daemon.

## Known Limitations

### Not Implemented (Future Work)
- ~~Mount operations still use shell commands~~ **FIXED - Now using policy-based syscalls**
- Blocking operations can stall single-thread runtime
- No structured logging (tracing + JSON)
- No group-based authorization (only uid-based)
- Portal not isolated to separate process
- No systemd hardening (CapabilityBoundingSet, etc.)

### Technical Debt
- Validation is string-level only at daemon boundary (sysfs checks happen in spawn_blocking)
- Job cancellation is best-effort (doesn't abort spawn_blocking)
- Error messages could be more specific (generic "BadRequest")

## Documentation

See also:
- **SECURITY_FIXES_IMPLEMENTED.md** - Detailed implementation notes
- **SECURITY_FIXES_TESTING.md** - Comprehensive test plan
- **rustyjack_security_review.txt** - Original security audit
- **rustyjack_security_fix_implementation_roadmap.txt** - Implementation roadmap

## Sign-Off

**Implementation Complete:** 2026-01-03
**Tested On:** Windows (syntax check only - requires Linux for runtime testing)
**Ready For:** Code review, Linux build, integration testing
**Priority:** P0 (Critical security fixes)
