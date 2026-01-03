# Security Fixes Testing Plan

This document outlines how to test the security fixes implemented for Rustyjack.

## Prerequisites

- Linux environment (Raspberry Pi OS or compatible)
- Root access or ability to run daemon as root
- Rust toolchain installed
- All project dependencies installed

## Build and Deploy

### 1. Build without CLI (Production Mode)

```bash
cd /path/to/Rustyjack
cargo build --release
ls -la target/release/rustyjack  # Should NOT exist
ls -la target/release/rustyjackd  # Should exist
ls -la target/release/rustyjack-ui  # Should exist
```

**Expected:** No `rustyjack` binary, only `rustyjackd` and `rustyjack-ui`.

### 2. Build with CLI (Development Mode)

```bash
cd /path/to/Rustyjack
cargo build --release --features cli -p rustyjack-core
ls -la target/release/rustyjack  # Should exist
```

**Expected:** `rustyjack` binary is built.

### 3. Deploy Daemon

```bash
sudo systemctl stop rustyjackd
sudo cp target/release/rustyjackd /usr/local/bin/
sudo systemctl start rustyjackd
sudo systemctl status rustyjackd
```

---

## Test Suite

### Test 1: Job Validation - JobStart Bypass Prevention

**Objective:** Verify that JobStart cannot bypass validation.

**Test 1.1: Invalid sleep duration**
```bash
# Send JobStart with Sleep exceeding 24 hours
# Expected: BadRequest error
```

Create test client script:
```rust
let job = JobSpec {
    kind: JobKind::Sleep { seconds: 100000 },  // > 24 hours
    requested_by: Some("test".to_string()),
};
// Send via JobStart endpoint
// Expected: Error with code BadRequest, message about sleep duration
```

**Test 1.2: Invalid scan target**
```bash
# Send JobStart with scan target containing control characters
let job = JobSpec {
    kind: JobKind::ScanRun {
        req: ScanRequestIpc {
            target: "192.168.1.1\r\n".to_string(),  // Control chars
            mode: ScanModeIpc::DiscoveryOnly,
            ports: None,
            timeout_ms: 30000,
        },
    },
    requested_by: Some("test".to_string()),
};
// Expected: BadRequest error about control characters
```

**Test 1.3: Invalid mount device**
```bash
# Try to mount mmcblk device via JobStart
let job = JobSpec {
    kind: JobKind::MountStart {
        req: MountStartRequestIpc {
            device: "/dev/mmcblk0p1".to_string(),  // Internal storage
            filesystem: Some("ext4".to_string()),
        },
    },
    requested_by: Some("test".to_string()),
};
// Expected: BadRequest error about mmcblk not allowed
```

**Test 1.4: Invalid git remote**
```bash
# Try SystemUpdate with invalid remote
let job = JobSpec {
    kind: JobKind::SystemUpdate {
        req: UpdateRequestIpc {
            service: "rustyjack".to_string(),
            remote: "malicious-remote".to_string(),  // Not origin/https/git@
            branch: "main".to_string(),
            backup_dir: None,
        },
    },
    requested_by: Some("test".to_string()),
};
// Expected: BadRequest error about git remote format
```

---

### Test 2: Per-Job Authorization - Privilege Escalation Prevention

**Objective:** Verify that Operator clients cannot start Admin-only jobs.

**Setup:**
```bash
# Create non-root test user
sudo useradd -m testuser
sudo usermod -aG rustyjack testuser  # Add to operator group (if using group-based auth)
```

**Test 2.1: Operator tries SystemUpdate**
```bash
# As non-root user, try to start SystemUpdate job
su - testuser
# Run test client that attempts:
let job = JobSpec {
    kind: JobKind::SystemUpdate {
        req: UpdateRequestIpc {
            service: "rustyjack".to_string(),
            remote: "origin".to_string(),
            branch: "main".to_string(),
            backup_dir: None,
        },
    },
    requested_by: Some("testuser".to_string()),
};
// Send via JobStart
// Expected: Forbidden error - "insufficient privileges for this job type"
```

**Test 2.2: Root can SystemUpdate**
```bash
# As root, same SystemUpdate request should succeed
sudo su
# Expected: JobStarted response with job_id
```

**Test 2.3: Operator can start WifiScan**
```bash
# As non-root user, start WifiScan
let job = JobSpec {
    kind: JobKind::WifiScan {
        req: WifiScanRequestIpc {
            interface: "wlan0".to_string(),
            timeout_ms: 30000,
        },
    },
    requested_by: Some("testuser".to_string()),
};
// Expected: JobStarted response (Operator tier sufficient)
```

---

### Test 3: Mount Device Validation

**Objective:** Verify mount/unmount operations are restricted.

**Test 3.1: Mount mmcblk via MountStart endpoint**
```bash
# Try via specialized MountStart endpoint
# Expected: BadRequest about mmcblk not allowed
```

**Test 3.2: Mount loop device**
```bash
# Try /dev/loop0
# Expected: BadRequest about loop device not allowed
```

**Test 3.3: Mount valid USB device**
```bash
# Insert USB drive (e.g., /dev/sda1)
# Expected: Success (if device is removable USB)
```

**Test 3.4: Unmount with non-device path**
```bash
# Try to unmount /boot or /home directly
# Expected: BadRequest (path doesn't start with /dev/)
```

---

### Test 4: Log Bundle Size Limiting

**Objective:** Verify SystemLogsGet doesn't exceed IPC max_frame.

**Test 4.1: Normal log bundle**
```bash
# Request logs via SystemLogsGet endpoint
# Expected: Response < 1MB, valid JSON
```

**Test 4.2: Large journal scenario**
```bash
# Generate large amount of logs
for i in {1..10000}; do
    logger -t rustyjack-test "Test message $i with some padding data to increase size"
done

# Request logs
# Expected: Response capped at ~900KB with truncation marker
# Expected: No daemon error about frame size exceeded
```

**Test 4.3: Verify truncation markers**
```bash
# Check response for truncation markers:
# "--- TRUNCATED: exceeded MAX_LOG_BUNDLE_BYTES ---"
# "[truncated stdout]"
# "[truncated file]"
```

---

### Test 5: Job Retention - Active Jobs Protected

**Objective:** Verify active jobs are never evicted.

**Setup:**
```bash
# Configure low retention (e.g., 5 jobs)
export RUSTYJACKD_JOB_RETENTION=5
sudo systemctl restart rustyjackd
```

**Test 5.1: Fill retention with completed jobs**
```bash
# Start 10 short jobs (Sleep 1 second each)
for i in {1..10}; do
    # Submit Sleep job via API
    # Wait for completion
done

# Check job list
# Expected: Only 5 most recent completed jobs remain
```

**Test 5.2: Active jobs survive retention**
```bash
# Start 3 long-running jobs (Sleep 60 seconds)
# Start 10 short jobs (Sleep 1 second) that complete
# Verify:
#   - 3 active jobs still present
#   - Oldest completed jobs evicted
#   - Active jobs queryable via JobStatus

# Wait for active jobs to complete
# Verify they remain until next retention cycle
```

**Test 5.3: Cancellation of retained active job**
```bash
# Start long job
job_id = <from JobStarted response>
# Fill retention with completed jobs
# Cancel the active job
# Expected: Job still exists, state changes to Cancelled
```

---

### Test 6: Scan Parameter Validation

**Objective:** Verify scan request validation.

**Test 6.1: DiscoveryOnly with ports**
```bash
let job = JobSpec {
    kind: JobKind::ScanRun {
        req: ScanRequestIpc {
            target: "192.168.1.0/24".to_string(),
            mode: ScanModeIpc::DiscoveryOnly,
            ports: Some(vec![80, 443]),  // Should be empty for DiscoveryOnly
            timeout_ms: 30000,
        },
    },
    requested_by: Some("test".to_string()),
};
// Expected: BadRequest - "ports must be empty for DiscoveryOnly mode"
```

**Test 6.2: DiscoveryAndPorts without ports**
```bash
mode: ScanModeIpc::DiscoveryAndPorts,
ports: None,
// Expected: BadRequest - "ports required for DiscoveryAndPorts mode"
```

**Test 6.3: Too many ports**
```bash
ports: Some((1..=200).collect()),  // 200 ports, > MAX_SCAN_PORTS (128)
// Expected: BadRequest - "too many ports"
```

**Test 6.4: Privileged port in scan**
```bash
ports: Some(vec![22, 80, 443]),  // 80 is privileged (<1024)
// Expected: BadRequest - "privileged ports (<1024) not allowed"
```

---

### Test 7: Update Service Validation

**Objective:** Verify system update parameters are validated.

**Test 7.1: Invalid service name**
```bash
service: "arbitrary-service".to_string(),
// Expected: BadRequest - "unsupported service name"
```

**Test 7.2: Service name with path separator**
```bash
service: "../../../etc/passwd".to_string(),
// Expected: BadRequest - "service name contains invalid characters"
```

**Test 7.3: Backup dir outside allowed paths**
```bash
backup_dir: Some("/tmp/evil".to_string()),
// Expected: BadRequest - "backup dir must be under /var/lib/rustyjack/backups or /tmp/rustyjack/backups"
```

**Test 7.4: Backup dir with traversal**
```bash
backup_dir: Some("/var/lib/rustyjack/backups/../../etc".to_string()),
// Expected: BadRequest - "backup dir contains directory traversal"
```

---

### Test 8: Git Parameter Validation

**Objective:** Verify git refs and remotes are validated.

**Test 8.1: Git ref with invalid characters**
```bash
branch: "main~1".to_string(),
// Expected: BadRequest - "git ref contains invalid characters"
```

**Test 8.2: Git ref with directory traversal**
```bash
branch: "../../etc/passwd".to_string(),
// Expected: BadRequest - "git ref contains directory traversal"
```

**Test 8.3: Valid origin remote**
```bash
remote: "origin".to_string(),
// Expected: Success (if other params valid)
```

**Test 8.4: Valid https remote**
```bash
remote: "https://github.com/user/repo.git".to_string(),
// Expected: Success (if other params valid)
```

**Test 8.5: Invalid remote format**
```bash
remote: "file:///etc/passwd".to_string(),
// Expected: BadRequest - "git remote must be 'origin' or start with https:// or git@"
```

---

## Integration Tests

### Full Workflow Test

```bash
# 1. Start daemon as root
sudo systemctl start rustyjackd

# 2. As root, perform privileged operations
sudo /usr/local/bin/rustyjack-client job-start '{"type":"SystemUpdate",...}'
# Expected: Success

# 3. As non-root, try privileged operation
su - testuser
/usr/local/bin/rustyjack-client job-start '{"type":"SystemUpdate",...}'
# Expected: Forbidden

# 4. As non-root, perform operator operation
/usr/local/bin/rustyjack-client job-start '{"type":"WifiScan",...}'
# Expected: Success

# 5. Fill job retention
for i in {1..20}; do
    /usr/local/bin/rustyjack-client job-start '{"type":"Sleep","data":{"seconds":1}}'
done

# 6. Start long job
/usr/local/bin/rustyjack-client job-start '{"type":"Sleep","data":{"seconds":60}}'
# Get job_id

# 7. Verify long job still queryable after retention
sleep 10
/usr/local/bin/rustyjack-client job-status $job_id
# Expected: Job found, state Running

# 8. Request large log bundle
/usr/local/bin/rustyjack-client system-logs
# Expected: Response < 1MB, possibly with truncation markers

# 9. Try invalid mount
/usr/local/bin/rustyjack-client mount-start /dev/mmcblk0p1 ext4
# Expected: BadRequest

# 10. Try valid mount (if USB available)
/usr/local/bin/rustyjack-client mount-start /dev/sda1 vfat
# Expected: Success
```

---

## Regression Tests

Ensure existing functionality still works:

1. **UI Operations:**
   - Navigate UI menus
   - Scan for WiFi networks
   - Connect to WiFi
   - View system status
   - Access Ethernet menu

2. **Basic IPC:**
   - Health check
   - Version query
   - Status query
   - Job status for valid job_id
   - Job cancellation

3. **Specialized Endpoints:**
   - WifiScanStart (with validation)
   - WifiConnectStart (with validation)
   - HotspotStart (with validation)
   - PortalStart (with validation)
   - MountStart (with stricter validation)
   - UnmountStart (with stricter validation)

---

## Performance Tests

Verify no significant performance regressions:

1. **Validation overhead:**
   - Time 1000 JobStart requests with valid params
   - Compare with baseline (if available)
   - Expected: < 1ms overhead per validation

2. **Log bundle generation:**
   - Time SystemLogsGet with capped output
   - Expected: < 2 seconds on Pi Zero 2 W

3. **Job retention:**
   - Start 100 jobs rapidly
   - Measure retention enforcement time
   - Expected: < 100ms per retention check

---

## Security Audit Checklist

After testing, verify:

- [ ] JobStart validation prevents all bypass attempts
- [ ] SystemUpdate requires root/admin authorization
- [ ] Mount operations reject internal devices (mmcblk, loop)
- [ ] Git parameters are sanitized (no injection)
- [ ] Scan parameters are bounded (port count, target length)
- [ ] Log bundles never exceed IPC max_frame
- [ ] Active jobs never evicted from retention
- [ ] CLI binary not built without explicit feature flag
- [ ] All error messages are safe (no secret leakage)
- [ ] Path traversal patterns rejected in all inputs

---

## Troubleshooting

### Build Issues

**Problem:** Build fails with systemd-journal-logger errors
**Cause:** Building on Windows (project requires Linux)
**Solution:** Use Linux VM or WSL2 for building

**Problem:** CLI binary not building
**Cause:** `cli` feature not enabled
**Solution:** Add `--features cli` to build command

### Runtime Issues

**Problem:** Validation rejecting legitimate inputs
**Cause:** Overly strict validation rules
**Solution:** Review constants in validation.rs, adjust if needed

**Problem:** Job retention evicting active jobs
**Cause:** Regression or misunderstanding of state
**Solution:** Check JobState values, ensure Queued/Running treated as active

**Problem:** Log bundle still exceeding max_frame
**Cause:** Section limits too high
**Solution:** Reduce MAX_SECTION_BYTES or MAX_CMD_OUTPUT_BYTES

---

**Test Plan Version:** 1.0
**Date:** 2026-01-03
**Compatible With:** Security fixes implementation in SECURITY_FIXES_IMPLEMENTED.md
