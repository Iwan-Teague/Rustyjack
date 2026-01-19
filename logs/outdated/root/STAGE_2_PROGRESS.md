# Stage 2 Progress Report
Created: 2026-01-07

## Goals
- Implement `run_blocking_cancellable` helper
- Refactor job kinds to use cancellable blocking
- Add cancellable subprocess runner
- Thread cancellation into core operations

## Work Completed

### 1. Cancellable Blocking Helper ✅

**File:** `rustyjack-daemon/src/jobs/blocking.rs` (new)

Created two helper functions for cancellable blocking operations:

```rust
pub async fn run_blocking_cancellable<F, T>(
    cancel: &CancellationToken,
    f: F,
) -> Result<T, DaemonError>

pub async fn run_blocking_cancellable_with_progress<F, T>(
    cancel: &CancellationToken,
    f: F,
    mut on_progress: impl FnMut(u8, String) + Send,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<(u8, String)>,
) -> Result<T, DaemonError>
```

**Benefits:**
- Centralizes cancellation logic
- Prevents code duplication across job kinds
- Provides immediate response when cancellation token fires
- Aborts the `spawn_blocking` task to free thread pool resources

**Limitations (documented in code):**
- `JoinHandle::abort()` does NOT kill child processes
- For jobs spawning subprocesses, core services need cancellation support

### 2. Current Cancellation Status by Job Kind

#### ✅ Already correct: Sleep
**File:** `rustyjack-daemon/src/jobs/kinds/sleep.rs`
- Uses async `tokio::time::sleep` with `tokio::select!`
- Cancellation is immediate and clean
- No blocking work, no subprocess

#### ⚠️ Partial cancellation: Mount/Unmount
**Files:** `mount_start.rs`, `unmount_start.rs`
- Currently: `handle.abort()` on cancel
- Issue: `mount`/`umount` syscalls in `rustyjack-core` are not cancellable mid-flight
- Impact: Low (mount operations are typically fast <1s)
- Future: Could add timeout wrapper in core mount service

#### ⚠️ Partial cancellation: WiFi Connect
**File:** `wifi_connect.rs`  
- Currently: `handle.abort()` + disconnect on cancel
- Issue: NetworkManager/wpa_cli calls are not cancellable
- Mitigation: Calls `disconnect()` to tear down connection
- Impact: Medium (connection attempts can take 10-30s)
- Future: Core wifi service needs cancellation token threading

#### ⚠️ Partial cancellation: WiFi Scan
**File:** `wifi_scan.rs`
- Currently: `handle.abort()` on cancel
- Issue: Scan via nl80211 is not cancellable
- Impact: Low (scans typically complete in 2-5s)

#### ⚠️ Partial cancellation: Hotspot/Portal Start
**Files:** `hotspot_start.rs`, `portal_start.rs`
- Currently: `handle.abort()` + cleanup call on cancel
- Mitigation: Calls `stop()` to tear down service
- Issue: If blocking in setup phase, cleanup may be incomplete
- Impact: Medium (leaves network config partially configured)
- Future: Core services need atomic rollback on cancel

#### ❌ No real cancellation: Scan (Ethernet)
**File:** `scan.rs`
- Currently: `handle.abort()` on cancel
- Issue: ICMP sweep + TCP port scan loops are not cancellable
- Impact: High (full subnet scan can take minutes)
- **Priority:** This needs refactoring in `rustyjack-ethernet` or `rustyjack-core`

#### ❌ No real cancellation: System Update
**File:** `update.rs`
- Currently: `handle.abort()` on cancel  
- Issue: Git clone/pull subprocesses are not killed
- Impact: **Critical** (git operations can take minutes, consume bandwidth)
- **Priority:** This is the highest-impact cancellation gap

## Work Remaining

### Step 1: Refactor existing job kinds to use helpers (Low priority)

Most jobs already have the `handle.abort()` pattern. The new helpers don't significantly improve behavior until core services support cancellation.

**Recommendation:** Defer until Step 2 is complete.

### Step 2: Thread cancellation into core services ⏳

This is the real work. Each core service that does blocking I/O needs:

#### A) Scan service (`rustyjack-ethernet` or `rustyjack-core`)
**Location:** `rustyjack-ethernet/src/lib.rs` or `rustyjack-core/src/services/scan.rs`

Changes needed:
- Accept cancellation signal (e.g., `Arc<AtomicBool>`)
- Check signal in discovery loop (between hosts)
- Check signal in port scan loop (between ports)
- Return early with partial results on cancel

Example:
```rust
pub fn run_scan<F>(
    req: ScanRequest,
    cancel: &AtomicBool,  // New parameter
    on_progress: F,
) -> Result<Value> {
    for host in targets {
        if cancel.load(Ordering::Relaxed) {
            return Ok(partial_results);
        }
        // ... scan host
    }
}
```

#### B) Update service subprocess management ⏳
**Location:** `rustyjack-core/src/operations.rs` (likely `run_system_update_with_progress`)

Changes needed:
- Replace `Command::output()` with `Command::spawn()`
- Poll `child.try_wait()` in a loop
- Check cancellation signal in poll loop
- On cancel: `child.kill()` then `child.wait()`

Example:
```rust
let mut child = Command::new("git")
    .args(&["clone", remote, path])
    .spawn()?;

loop {
    if cancel.load(Ordering::Relaxed) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(anyhow!("cancelled"));
    }
    
    match child.try_wait()? {
        Some(status) => break,
        None => std::thread::sleep(Duration::from_millis(100)),
    }
}
```

#### C) WiFi service operations (Lower priority)
**Location:** `rustyjack-core/src/services/wifi.rs`

Most WiFi operations are fast enough that cancellation is less critical. Consider:
- Adding timeout wrappers (easier than full cancellation)
- Ensuring cleanup always runs (finally-style)

### Step 3: Subprocess utilities module (Optional)

Create `rustyjack-daemon/src/jobs/subprocess.rs` with:
```rust
pub struct CancellableCommand {
    child: Child,
    cancel: Arc<AtomicBool>,
}

impl CancellableCommand {
    pub fn wait_with_cancel(&mut self) -> Result<ExitStatus> {
        // Poll loop with cancellation checking
    }
}
```

This centralizes the subprocess cancellation pattern.

## Testing Recommendations

### Test 1: Sleep cancellation (already works)
```bash
# Start sleep job
job_id=$(rustyjack job-start sleep --seconds 60)
# Cancel immediately  
rustyjack job-cancel $job_id
# Check status - should be Cancelled within 1s
rustyjack job-status $job_id
```

### Test 2: Scan cancellation (needs Step 2A)
```bash
# Start full subnet scan
job_id=$(rustyjack job-start scan --target 192.168.1.0/24 --mode ports --ports 1-1000)
sleep 2
rustyjack job-cancel $job_id
# Currently: may continue scanning for minutes
# After fix: should cancel within 1-2s
```

### Test 3: Update cancellation (needs Step 2B)
```bash
# Start update (large git clone)
job_id=$(rustyjack job-start system-update --service rustyjack --remote https://github.com/large/repo)
sleep 5
rustyjack job-cancel $job_id
# Currently: git clone continues
# After fix: git process killed, job cancelled
ps aux | grep git  # Should show no git processes
```

## Acceptance Criteria Status

- ✅ `run_blocking_cancellable` helper created
- ⏳ Job kinds refactored (deferred until core services support cancellation)
- ⏳ Cancellable subprocess runner (needs design in core services)
- ⏳ Cancellation threaded into core ops (scan and update are priorities)

## Risk Assessment

**Current state:** Cancellation works at the daemon layer (job state transitions to Cancelled) but blocking work continues in the background.

**Security impact:** Low (DoS risk remains - cancelling doesn't free resources)

**UX impact:** Medium (users cancel jobs but work continues, wastes battery/bandwidth)

**Complexity:** High (requires refactoring synchronous core services to check cancellation)

## Recommendation

Given the complexity and the fact that the current daemon correctly tracks cancellation in job state, recommend splitting Stage 2:

**Stage 2A (Complete):** Daemon-level cancellation infrastructure ✅
- Cancellation token flows to all jobs ✅
- Job state transitions to Cancelled ✅  
- Helper utilities created ✅

**Stage 2B (Future work):** Core service cancellation 🔲
- Scan service loop cancellation
- Update subprocess kill on cancel  
- WiFi operation timeouts/cleanup

This allows progress on Stage 3 (authorization) and Stage 4 (observability) while Stage 2B is completed separately.

## Next Stage

Proceed to **Stage 3**: Authorization model upgrade (group-based roles + UI usability)
