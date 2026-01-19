# Stage 2B Implementation: Real Cancellation - Core Integration
Created: 2026-01-07

## Status: In Progress

### Phase 1: Ethernet Module ✅ COMPLETE

**Changes Made:**
1. Added `std::sync::atomic::{AtomicBool, Ordering}` and `Arc` imports
2. Created cancellation-aware scan functions:
   - `quick_port_scan_cancellable()` - TCP port scan with cancel checks
   - `quick_port_scan_with_source_cancellable()` - Source-bound scan with cancel checks
   - `discover_hosts_cancellable()` - ICMP discovery with cancel checks
   - `discover_hosts_arp_cancellable()` - ARP discovery with cancel checks (Linux only)

**Implementation Details:**
- All cancellable functions accept `&Arc<AtomicBool>` as last parameter
- Cancel checks use `Ordering::Relaxed` (performance optimization)
- Functions return `Err(anyhow!("...cancelled"))` when cancelled
- Cancel checks placed strategically:
  - Before each port in port scans
  - Before each ICMP probe send
  - In ICMP/ARP receive loops
  - Before each ARP probe send

**Files Modified:**
- `rustyjack-ethernet/Cargo.toml` - Added tokio dev-dependency
- `rustyjack-ethernet/src/lib.rs` - Added 4 cancellable functions (~250 lines)

**Backward Compatibility:**
- Original functions unchanged
- New functions have `_cancellable` suffix
- Existing code continues to work

---

### Phase 2: Core Integration (In Progress)

**Approach:**

Since `rustyjack-core` uses `rustyjack-ethernet` through `run_scan_with_progress`, and the daemon uses `tokio_util::sync::CancellationToken`, we need a bridge:

```rust
// In rustyjack-core or daemon
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn create_cancel_flag(token: &CancellationToken) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = flag.clone();
    let token_clone = token.clone();
    
    tokio::spawn(async move {
        token_clone.cancelled().await;
        flag_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    
    flag
}
```

**Problem:** This requires tokio runtime context, which may not be available in blocking code.

**Better Approach:** Pass cancellation flag directly through the call chain:

1. Daemon scan job creates `Arc<AtomicBool>`
2. Spawns task to monitor `CancellationToken` and set flag
3. Passes flag to core scan function
4. Core scan passes flag to ethernet scan functions

---

### Phase 3: System Update Subprocess Management (Planned)

**Current State:**
- SystemUpdate job calls `rustyjack-core::services::update::run_update()`
- Core uses `std::process::Command` to spawn git subprocess
- No handle tracking or kill-on-cancel

**Implementation Plan:**

```rust
// In rustyjack-daemon/src/jobs/kinds/update.rs

use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

pub async fn run<F, Fut>(
    req: UpdateRequestIpc,
    cancel: &CancellationToken,
    progress: &mut F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // Shared child process handle
    let child_handle: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let child_handle_clone = child_handle.clone();
    
    // Spawn kill task
    let kill_task = tokio::spawn(async move {
        cancel.cancelled().await;
        if let Some(mut child) = child_handle_clone.lock().unwrap().take() {
            let _ = child.kill();
            log::info!("Killed git subprocess due to cancellation");
        }
    });
    
    // Run update in blocking task
    let result = tokio::task::spawn_blocking(move || {
        run_update_tracked(root, request, child_handle, |percent, msg| {
            // progress callback
        })
    }).await;
    
    kill_task.abort();
    result
}

// In rustyjack-core
fn run_update_tracked(
    root: &Path,
    request: UpdateRequest,
    child_handle: Arc<Mutex<Option<Child>>>,
    on_progress: impl FnMut(u8, &str),
) -> Result<Value> {
    // When spawning git:
    let mut child = Command::new("git")
        .args(&["pull", "origin", &request.branch])
        .spawn()?;
    
    // Store handle
    *child_handle.lock().unwrap() = Some(child);
    
    // Wait for completion
    let status = child.wait()?;
    
    // Clear handle
    *child_handle.lock().unwrap() = None;
    
    // Check status...
}
```

---

### Phase 4: WiFi Operation Timeouts (Alternative)

**Current State:**
- WiFi operations use NetworkManager or wpa_supplicant
- Calls are blocking with no timeout
- Job abort kills thread but subprocess may continue

**Options:**

**Option A:** Add timeouts to WiFi operations
```rust
// In rustyjack-core/src/services/wifi.rs
pub fn connect_with_timeout(
    ssid: &str,
    psk: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    
    // Start connection
    start_connect(ssid, psk)?;
    
    // Poll status with timeout
    while start.elapsed() < timeout {
        if is_connected()? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    
    Err(anyhow!("Connection timeout"))
}
```

**Option B:** Use existing timeout in request
- WiFi connect already has `timeout_ms` parameter
- Implementation may already respect it
- Need to verify and document

**Recommendation:** Option B - verify existing timeout works, document behavior.

---

## Current Status Summary

### Completed ✅
1. ✅ Ethernet module cancellation support (4 functions)
2. ✅ Backward compatibility maintained
3. ✅ Documentation of approach

### In Progress 🔄
4. 🔄 Core integration (bridge CancellationToken to AtomicBool)
5. 🔄 Update daemon scan job to use cancellable functions

### Remaining 🔲
6. 🔲 SystemUpdate subprocess tracking and kill-on-cancel
7. 🔲 WiFi timeout verification/implementation
8. 🔲 Testing on actual device
9. 🔲 Integration tests

---

## Testing Plan

### Unit Tests
- Test cancellation of port scan (interrupt mid-scan)
- Test cancellation of ICMP discovery (interrupt during send/receive)
- Test cancellation of ARP discovery (interrupt during send/receive)

### Integration Tests
- Start scan job, cancel after 2 seconds, verify early return
- Start SystemUpdate, cancel during git pull, verify subprocess killed
- Start WiFi connect, cancel during connection, verify cleanup

### Manual Tests
```bash
# Test scan cancellation
rustyjack-client job-start scan --target 192.168.1.0/24 &
JOB_ID=$!
sleep 2
rustyjack-client job-cancel $JOB_ID
# Verify: scan stops immediately, partial results returned

# Test update cancellation
rustyjack-client job-start update --service rustyjack &
JOB_ID=$!
sleep 1
rustyjack-client job-cancel $JOB_ID
# Verify: git process killed, no partial update
```

---

## Next Steps

1. **Complete core integration** (30 min)
   - Add bridge helper in daemon
   - Update scan job to create cancel flag
   - Pass flag through to ethernet functions

2. **Implement SystemUpdate kill-on-cancel** (1-2 hours)
   - Track child process handle
   - Kill on cancellation
   - Clean up partial updates

3. **Verify WiFi timeouts** (30 min)
   - Review existing timeout implementation
   - Document behavior
   - Add timeout if missing

4. **Testing** (2-3 hours)
   - Unit tests for cancellation
   - Manual testing on device
   - Integration test suite

**Total remaining effort:** 4-6 hours

---

## Files Modified So Far

1. `rustyjack-ethernet/Cargo.toml` - Added tokio dev-dependency
2. `rustyjack-ethernet/src/lib.rs` - Added cancellable scan functions
3. `docs/STAGE_2B_IMPLEMENTATION.md` - This document

**Files to modify:**
4. `rustyjack-daemon/src/jobs/kinds/scan.rs` - Use cancellable functions
5. `rustyjack-daemon/src/jobs/kinds/update.rs` - Subprocess tracking
6. `rustyjack-core/src/services/update.rs` - Accept child handle
7. `rustyjack-core/src/services/wifi.rs` - Verify/add timeouts

---

## Design Decisions

### Why AtomicBool instead of CancellationToken in ethernet module?

**Rationale:**
1. **No tokio dependency** - Keeps ethernet module lightweight, std-only
2. **Synchronous context** - Scan functions are blocking, don't need async
3. **Performance** - AtomicBool is cheaper than async cancellation checks
4. **Flexibility** - Can be used from any context (tokio, async-std, sync)

### Why not refactor to async?

**Rationale:**
1. **Large change** - Would require rewriting entire scan logic
2. **Blocking I/O** - Raw sockets are inherently blocking
3. **Compatibility** - Existing code expects synchronous scan functions
4. **Diminishing returns** - Cancellation achieved with minimal changes

### Why track child process handle in Arc<Mutex<Option<Child>>>?

**Rationale:**
1. **Shared ownership** - Both update task and kill task need access
2. **Mutation** - Need to take() child to kill it
3. **Thread safety** - Mutex ensures no data races
4. **Option** - Allows taking ownership to kill, then setting to None

---

## Performance Impact

### Cancellation Checks
- **Overhead:** ~5ns per check (AtomicBool load with Relaxed ordering)
- **Frequency:** Once per port (port scan), once per host (discovery)
- **Impact:** Negligible (<0.1% for typical scans)

### Memory
- **AtomicBool:** 1 byte per scan
- **Arc overhead:** ~16 bytes (pointer + ref counts)
- **Total:** ~17 bytes per cancellable operation

### Worst Case
- Scanning /16 network (65,536 hosts)
- Check every host: 65,536 * 5ns = 328μs overhead
- **Conclusion:** Completely negligible

---

## Backward Compatibility

### API Compatibility ✅
- All original functions unchanged
- New functions have distinct names (`_cancellable` suffix)
- Existing callers unaffected

### Behavior Compatibility ✅
- Original functions have identical behavior
- No performance regression for non-cancellable paths
- Return types unchanged

### Migration Path
- Gradual migration possible
- Can mix cancellable and non-cancellable calls
- No forced updates required

---

## Documentation Updates Needed

1. Update `rustyjack-ethernet/README.md` with cancellation examples
2. Document cancellation behavior in function docstrings
3. Add cancellation section to daemon job documentation
4. Update troubleshooting guide with cancellation scenarios

---

## Known Limitations

1. **Granularity:** Cancellation checked per-host/per-port, not mid-operation
2. **Cleanup:** Partial results may exist when cancelled (expected behavior)
3. **Subprocess:** SystemUpdate subprocess may complete before kill signal arrives
4. **WiFi:** NetworkManager operations may not respect cancellation immediately

**These are acceptable tradeoffs for the cancellation model.**
