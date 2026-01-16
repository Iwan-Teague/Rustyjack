# RustyJack Required Fixes

## Critical Issues Identified

### 1. **Active Interface Not Being Applied (CRITICAL BUG)**
**Problem**: Interface switch is saved to config but daemon NEVER applies it

**Evidence from logs**:

**Config file (captured at 01:06:45)**:
```json
"active_network_interface": "eth0"
```

**Daemon logs (01:04:47 - 01:06:00, user was switching and attacking during this time)**:
```
Jan 16 01:04:47 Selected active interface: eth0
Jan 16 01:04:51 Selected active interface: eth0
Jan 16 01:04:55 Selected active interface: eth0
Jan 16 01:04:59 Selected active interface: eth0
Jan 16 01:05:00 Selected active interface: eth0
```

**What's MISSING from logs**:
- ❌ ZERO occurrences of `"Selected active interface: wlan0"`
- ❌ ZERO occurrences of `"Selected active interface: wlan1"`
- ❌ NO logs showing daemon reading config file
- ❌ NO logs showing daemon receiving interface switch command via IPC

**Grep confirms this**:
```bash
journalctl -u rustyjackd --since "00:41:00" --until "00:43:00" | grep -E "Selected active|wlan"
# Returned: NOTHING (no logs at all during critical window)

# In the 2-minute capture (01:04-01:06):
# Every single "Selected active interface" = eth0
```

**Root Cause**:
- UI saves selection to config: ✅ WORKS (field is `active_network_interface`)
- Daemon reads from config on startup: ❓ UNKNOWN
- **Daemon NEVER switches when config changes**: ❌ **BUG HERE**

The isolation enforcement runs every 4 seconds and ALWAYS selects eth0, ignoring any interface changes made through the UI.

**Required Fix**:
1. Find where daemon reads `active_network_interface` from config
2. Make isolation enforcement respect the config setting
3. Add IPC command to notify daemon when interface changes (instead of relying on file polling)
4. OR: Make daemon watch config file for changes and reload active interface

---

### 2. **RF-Kill Soft Blocking Wireless Interfaces**
**Problem**: Both wireless interfaces are soft-blocked by rfkill

**Evidence from logs**:

**rfkill status (captured at 01:06:45)**:
```
root@rustyjack:~# sudo rfkill list
1: phy0: Wireless LAN
        Soft blocked: yes  ← BLOCKING wlan0
2: phy1: Wireless LAN
        Soft blocked: yes  ← BLOCKING wlan1
```

**Daemon logs showing continuous blocking (wifi.log from 00:43 onwards)**:
```
2026-01-16T00:43:09 rfkill_device_state idx=1 state="blocked" idx=1 block=true
2026-01-16T00:43:09 rfkill_device_state idx=2 state="blocked" idx=2 block=true
2026-01-16T00:43:13 rfkill_device_state idx=1 state="blocked" idx=1 block=true
2026-01-16T00:43:13 rfkill_device_state idx=2 state="blocked" idx=2 block=true
... (repeats every 4 seconds for 20+ minutes)
```

**Daemon logs showing blocking in enforcement pipeline (01:04:47)**:
```
Jan 16 01:04:47 Interface wlan0 set to DOWN
Jan 16 01:04:47 set_state: wifi:422: rfkill_device_state idx=1 state="blocked" idx=1 block=true
Jan 16 01:04:47 Interface wlan0 fully blocked (DOWN, no routes)
Jan 16 01:04:47 Interface wlan1 set to DOWN
Jan 16 01:04:47 set_state: wifi:422: rfkill_device_state idx=2 state="blocked" idx=2 block=true
Jan 16 01:04:47 Interface wlan1 fully blocked (DOWN, no routes)
```

**What's MISSING from logs**:
- ❌ ZERO occurrences of `rfkill_device_state ... block=false`
- ❌ NO logs showing rfkill unblock operations
- ❌ NO logs in activation pipeline like `"[Step 2/6] Unblocking wireless radio"`

**Current Behavior**:
- Soft-blocked interfaces CANNOT be used for wireless operations
- RF-kill error: "Operation not possible due to RF-kill (os error 132)"
- This is why Evil Twin, Karma, and other wireless attacks fail

**Required Fix**:
- When a wireless interface is selected as active, the daemon MUST unblock rfkill for that interface
- The `rustyjack-netlink` rfkill implementation should call rfkill unblock when activating wireless interfaces
- Add verification step: after setting interface UP, check rfkill status and unblock if needed

**Expected Behavior After Fix**:
```
1: phy0: Wireless LAN
        Soft blocked: no   ← UNBLOCKED when wlan0 is active
2: phy1: Wireless LAN
        Soft blocked: no   ← UNBLOCKED when wlan1 is active
```

---

### 3. **Interface State Inconsistency**

**Evidence from logs**:

**Interface status (captured at 01:06:45)**:
```bash
root@rustyjack:~# ip link show | grep -E "wlan|eth"
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ... state UP ...
3: wlan0: <BROADCAST,MULTICAST> ... state DOWN ...
4: wlan1: <BROADCAST,MULTICAST> ... state DOWN ...
```

**Daemon logs showing enforcement cycle (01:04:47)**:
```
Jan 16 01:04:47 Selected active interface: eth0
Jan 16 01:04:47 Deleted default route via Some(192.168.18.1) on interface Some(2)
Jan 16 01:04:47 Flushed all addresses from wlan0
Jan 16 01:04:47 Interface wlan0 set to DOWN
Jan 16 01:04:47 Flushed all addresses from wlan1
Jan 16 01:04:47 Interface wlan1 set to DOWN
Jan 16 01:04:47 === ACTIVATION PIPELINE START: eth0 (Connectivity) ===
Jan 16 01:04:47 [Step 2/6] SKIPPED: Not a wireless interface
Jan 16 01:04:47 [Step 3/6] SKIPPED: Not a wireless interface
Jan 16 01:04:47 Interface eth0 set to UP
Jan 16 01:04:48 Interface eth0 fully activated with connectivity
Jan 16 01:04:48 Enforcement complete: allowed=["eth0"], blocked=["wlan0", "wlan1"], errors=0
```

This cycle repeats **every 4 seconds** (at 01:04:47, 01:04:51, 01:04:55, 01:04:59, etc.)

**What's MISSING from logs**:
- ❌ NO activation pipeline ever starts with `"ACTIVATION PIPELINE START: wlan0"`
- ❌ NO activation pipeline ever starts with `"ACTIVATION PIPELINE START: wlan1"`
- ❌ NO logs showing Steps 2/3 executing (would be rfkill unblock for wireless)
- ❌ NO logs showing `"Interface wlan0 fully activated"`

**Current State Summary**:
```
eth0: state UP     ← Active and working (gets DHCP, default route, DNS)
wlan0: state DOWN  ← Blocked and unusable (forced DOWN every 4s)
wlan1: state DOWN  ← Blocked and unusable (forced DOWN every 4s)
```

**Problem**:
- Even when user selects wlan0/wlan1 as active, they remain DOWN
- Isolation enforcement immediately forces them back DOWN
- Interface never actually becomes usable for operations

**Required Fix**:
- Fix the activation pipeline in `rustyjack-core/src/system/isolation.rs`
- When wireless interface is active:
  1. Unblock rfkill FIRST (before bringing UP)
  2. Set interface UP
  3. Verify interface is UP and rfkill is unblocked
  4. Keep enforcement from immediately forcing it DOWN again

---

### 4. **Job Cancellation Failure - Zombie Attack Jobs (CRITICAL)**
**Problem**: Multiple Evil Twin jobs running simultaneously, never terminating when user exits attack

**Evidence from logs**:

**Daemon logs showing THREE concurrent Evil Twin jobs (01:04-01:06)**:
```
Jan 16 01:04:45 ThreadId(913)  Evil Twin 'Three_20B33A' running for 1360.310561696s...
Jan 16 01:04:46 ThreadId(1055) Evil Twin 'Three_20B33A' running for 1330.131350525s...
Jan 16 01:04:54 ThreadId(5677) Evil Twin 'Three_20B33A' running for 140.01185277s...
Jan 16 01:04:55 ThreadId(913)  Evil Twin 'Three_20B33A' running for 1370.311280186s...
Jan 16 01:04:56 ThreadId(1055) Evil Twin 'Three_20B33A' running for 1340.132142888s...
```

**Job runtime analysis**:
- ThreadId(913): **1370 seconds = ~23 minutes** (created ~00:42:05)
- ThreadId(1055): **1340 seconds = ~22 minutes** (created ~00:42:36)
- ThreadId(5677): **140 seconds = ~2.3 minutes** (created ~01:03)

All three jobs targeting the **same network** ('Three_20B33A'), all running **concurrently**.

**User-reported timeline matches UI error logs**:
```
Jan 16 00:42:05 ERROR rustyjack-ui: Menu action failed:
  Evil Twin attack failed: Operation not possible due to RF-kill (os error 132)

Jan 16 00:42:36 ERROR rustyjack-ui: Menu action failed:
  Evil Twin attack failed: Failed to set wlan1 to AP mode: Device or resource busy (os error 16)

Jan 16 00:42:45 ERROR rustyjack-ui: Menu action failed: Karma attack failed
```

User saw errors and assumed attacks stopped, but **jobs kept running in background**.

**What's MISSING from logs**:
- ❌ NO logs showing `"Job cancelled"` or `"Job terminated"` for these job IDs
- ❌ NO logs showing `"Received JobCancel command"` from UI
- ❌ NO logs showing cleanup when user exited attacks
- ❌ Jobs just keep printing status updates forever

User reports exiting attacks multiple times, but jobs never terminated.

**Why This Happens - Root Cause Analysis**:

#### A. Job Cancellation Mechanism Broken
When user exits an attack in the UI:
1. UI should send IPC command: `JobCancel { job_id }`
2. Daemon should set cancellation flag on that job
3. Job's main loop should check flag and exit gracefully
4. Job should clean up resources (interfaces, sockets, threads)

**What's actually happening**:
- ❌ UI may not be sending cancel command
- ❌ Daemon may not be processing cancel command
- ❌ Job loop may not be checking cancellation flag
- ❌ Job may be stuck waiting on operations that can't complete

#### B. Interface Blocking Prevents Job Cleanup
The jobs are stuck because:

1. **Job starts on wlan0/wlan1** → begins Evil Twin attack
2. **User switches interface or isolation runs** → interface gets blocked
3. **Job can't complete operations** → socket operations timeout/fail
4. **Job enters error state** → but doesn't terminate, just keeps retrying
5. **Job prints "running for X seconds"** → status update still works
6. **Job never checks "should I stop?"** → continues indefinitely

Example scenario:
```rust
// Pseudocode of what's likely happening in Evil Twin job
loop {
    // This check is MISSING or not being honored:
    // if cancellation_requested() { break; }

    // Job tries to send beacon frames
    match send_beacon_on_interface(wlan0) {
        Ok(_) => continue,
        Err(e) => {
            // Interface is blocked! Operation fails
            // But job just logs error and continues looping
            log::error!("Send failed: {}", e);
            sleep(1);
            // Should check cancellation here but doesn't
            continue;
        }
    }
}
```

#### C. Multiple Jobs Created Due to Retry Logic
Possible sequence of events:

**00:42:05** - User starts Evil Twin on wlan0
- Creates job (ThreadId 913)
- Job fails immediately due to RF-kill error
- UI shows error, user thinks job stopped
- **Job actually keeps running in background**

**00:42:36** - User starts Evil Twin on wlan1
- Creates job (ThreadId 1055)
- Job fails with "Device busy" error
- UI shows error, user thinks job stopped
- **Job actually keeps running in background**
- **First job (913) STILL running**

**~01:03** - User tries again
- Creates job (ThreadId 5677)
- Same pattern repeats
- **Now THREE jobs running concurrently**

**Why jobs survive errors**:
- Initial errors (RF-kill, device busy) happen during **setup phase**
- Setup fails, but job thread doesn't exit
- Job enters retry loop waiting for conditions to improve
- No cancellation check in retry loop
- Jobs accumulate over time

#### D. Resource Leaks and System Impact
Each zombie job consumes:
- ✗ 1 thread (stays blocked/sleeping)
- ✗ Memory for job state
- ✗ Open file descriptors for sockets
- ✗ CPU cycles checking interface state
- ✗ Log spam every 10 seconds

After hours of usage with multiple failed attacks:
- Could have dozens of zombie jobs
- System slowdown
- Resource exhaustion
- Unclear UI state (which job is "real"?)

**Required Fix - Multi-Part Solution**:

**1. Add Cancellation Checks Everywhere**
```rust
// In every job's main loop and retry logic
if job.is_cancelled() {
    cleanup_resources();
    return Ok(());
}
```

**2. Add Timeout and Auto-Cleanup**
```rust
// If job fails repeatedly for N attempts or M seconds, auto-terminate
if consecutive_errors > MAX_RETRIES || runtime > MAX_RUNTIME {
    log::error!("Job failed, auto-terminating");
    return Err(JobError::MaxRetriesExceeded);
}
```

**3. Ensure UI Always Sends Cancel on Exit**
```rust
// When user presses Back/Exit during attack
if let Some(job_id) = self.active_job {
    self.core.dispatch(Commands::JobCancel { job_id })?;
    self.active_job = None;
}
```

**4. Add Job Cleanup on Interface Change**
```rust
// When isolation blocks an interface, kill jobs using it
fn block_interface(iface: &str) {
    // Cancel all jobs bound to this interface
    for job in jobs.iter() {
        if job.interface == iface {
            job.cancel();
        }
    }
}
```

**5. Add Job Status Monitoring in UI**
```rust
// Show user which jobs are actually running
// Allow manual termination: "Kill all jobs"
Menu::JobManager {
    jobs: vec![
        "Evil Twin (wlan0) - 23m - ZOMBIE",
        "Karma (wlan1) - 5m - ACTIVE",
    ]
}
```

**6. Fail Fast on Fatal Errors**
```rust
// Don't retry these errors - immediately terminate job
match setup_interface(iface) {
    Err(Error::RfKillBlocked) => return Err(e), // Don't retry
    Err(Error::DeviceBusy) => return Err(e),    // Don't retry
    Err(Error::Timeout) => retry(),              // Can retry
}
```

---

### 5. **Missing Daemon Logs During Critical Window**
**Problem**: No daemon logs exist from 00:41:00 to 00:43:00 when attacks were attempted

**Evidence from logs**:

**Attempted grep query for critical time window**:
```bash
journalctl -u rustyjackd --since "00:41:00" --until "00:43:00" | grep -E "Selected active|isolation|wlan"
# Result: (empty - no output)
```

**Attempted grep query without filter**:
```bash
journalctl -u rustyjackd --since "00:41:00" --until "00:43:00"
# Result: (empty - no logs at all)
```

**User-reported timeline**:
```
00:42:05 - First Evil Twin attempt → RF-kill error
00:42:36 - Second Evil Twin attempt → Device busy error
00:42:45 - Karma attack attempt → Generic failure
```

**What's PRESENT in UI logs for this time (rustyjack-ui.log)**:
```
Jan 16 00:42:05 ERROR rustyjack-ui: Menu action failed:
  Evil Twin attack failed: Operation not possible due to RF-kill (os error 132)

Jan 16 00:42:36 ERROR rustyjack-ui: Menu action failed:
  Evil Twin attack failed: Failed to set wlan1 to AP mode: Device or resource busy (os error 16)

Jan 16 00:42:45 ERROR rustyjack-ui: Menu action failed: Karma attack failed
```

**What's MISSING from daemon logs**:
- ❌ NO logs showing `"Received command: StartEvilTwin"` from UI
- ❌ NO logs showing `"Job created: Evil Twin"`
- ❌ NO logs showing `"Selected active interface"` entries (should appear every 4s)
- ❌ NO isolation enforcement logs (should appear every 4s)
- ❌ NO error logs explaining why jobs failed
- ❌ NO logs of ANY kind from rustyjackd during this 2-minute window

**What this tells us**:

**Hypothesis 1 - Daemon Crash/Restart**:
If daemon crashed at 00:41 and restarted at 00:43:
- Would explain complete absence of logs
- Journal logs would show systemd restart messages
- But user didn't report checking `systemctl status rustyjackd` for restarts

**Hypothesis 2 - Log Rotation Issue**:
If logs rotated at midnight (00:00):
- Old logs would be in `rustyjackd.log.2026-01-15`
- New logs would be in `rustyjackd.log.2026-01-16`
- User may have only checked one file
- But `journalctl -u rustyjackd` should show both

**Hypothesis 3 - Daemon Hung/Deadlocked**:
If daemon's main thread blocked:
- IPC commands from UI would queue up
- No logs would be written (blocked thread can't log)
- Would eventually timeout and continue, or user restarted daemon
- But later logs (01:04-01:06) show daemon working

**Most Likely Explanation**:
Comparing the fact that we DO have logs starting at 01:04:
```
Jan 16 01:04:45 ThreadId(913)  Evil Twin 'Three_20B33A' running for 1360s...
Jan 16 01:04:47 Selected active interface: eth0
```

The ThreadId(913) job started ~1360 seconds earlier = **00:42:05** (matches first error!)

This means:
1. ✓ Daemon WAS running at 00:42 (it created the job)
2. ✓ Jobs WERE created (they show up later in logs)
3. ✗ But NO daemon logs from that period exist in journal

**Conclusion**: Either:
- Logging was completely broken during this time
- Logs were lost/rotated/deleted
- User extracted logs from wrong source
- systemd journal buffer filled up and dropped logs

**Required Fix**:
1. Verify daemon logging configuration is robust
2. Check systemd journal size limits and retention
3. Add critical log entries at WARN/ERROR level to ensure they're never dropped
4. Add startup log: "Daemon started, PID=X, version=Y"
5. Add shutdown log: "Daemon shutting down gracefully" vs crash detection
6. Monitor for gaps in "isolation enforcement" logs (should be every 4s)

---

---

## Error Chain Analysis - How Everything Breaks Together

This section explains how all the bugs interact to create a cascade of failures.

### The Complete Failure Sequence

#### Timeline of a Failed Attack Attempt

**User Action**: Selects wlan0 in UI → Starts Evil Twin attack

**What SHOULD happen**:
```
1. UI saves "active_network_interface": "wlan0" to config ✓
2. UI sends IPC: SetActiveInterface { interface: "wlan0" } ✗ (MISSING)
3. Daemon reads command, updates isolation logic ✗ (NOT IMPLEMENTED)
4. Isolation enforcement runs:
   a. Blocks eth0, wlan1 ✗
   b. Unblocks wlan0 rfkill ✗ (MISSING)
   c. Brings wlan0 UP ✗
   d. Keeps wlan0 UP ✗
5. UI sends: StartEvilTwin { interface: "wlan0", target: "Three_20B33A" } ✓
6. Daemon creates job, job starts successfully ✗
7. Job runs attack until user cancels ✗
8. User clicks Exit, UI sends JobCancel ✗ (MAYBE MISSING)
9. Job cleans up and terminates ✗
```

**What ACTUALLY happens**:
```
1. UI saves "active_network_interface": "wlan0" to config ✓ (BUT NOT USED)
2. Daemon NEVER SEES THIS CHANGE (no IPC, no file watch)
3. Isolation keeps running every 4 seconds, ALWAYS selecting eth0
4. Isolation enforcement runs:
   a. Blocks wlan0 with rfkill ✗ WRONG
   b. Blocks wlan1 with rfkill ✗ WRONG
   c. Sets wlan0 DOWN ✗ WRONG
   d. Sets wlan1 DOWN ✗ WRONG
   e. Brings eth0 UP ✗ WRONG (user wants wlan0)
5. UI sends: StartEvilTwin { interface: "wlan0", target: "Three_20B33A" } ✓
6. Daemon creates job (ThreadId 913)
7. Job tries to set wlan0 UP → FAILS (rfkill blocked) → ERROR 132
8. Job DOESN'T EXIT, enters retry loop waiting for interface
9. UI shows error to user, user thinks job stopped
10. Job KEEPS RUNNING in background, printing status every 10s
11. User tries again on wlan1 → Creates SECOND job (ThreadId 1055)
12. Same failure pattern → Now TWO zombie jobs running
13. Isolation CONTINUES blocking wlan0/wlan1 every 4 seconds
14. Jobs CONTINUE trying to use blocked interfaces forever
15. User clicks Exit → UI MAY NOT send cancel → Jobs still running
16. 20 minutes later: THREE jobs all stuck in retry loops
```

### Why Each Error Occurs

#### Error 1: "Operation not possible due to RF-kill (os error 132)"
**When**: Evil Twin job tries to bring wlan0 UP

**Why**:
1. Isolation enforcement set wlan0 rfkill to BLOCKED
2. Linux kernel refuses to activate blocked radio
3. Job gets EPERM (132) error

**Root cause**: Daemon never unblocked rfkill because it thinks eth0 is active

**Fix needed**: Unblock rfkill in isolation's wireless interface activation pipeline

---

#### Error 2: "Device or resource busy (os error 16)"
**When**: Evil Twin job tries to set wlan1 to AP mode via nl80211

**Why**:
1. Isolation just set wlan1 DOWN 100ms ago
2. Interface not fully shut down yet (driver still cleaning up)
3. Job immediately tries to reconfigure → Gets EBUSY (16)
4. Could also mean: previous job (ThreadId 913) still has sockets open on wlan1

**Root cause**:
- Race condition between isolation blocking and job starting
- No coordination between isolation and job lifecycle
- Previous jobs not cleaned up, holding interface resources

**Fix needed**:
- Add delays or retries when interface just changed state
- Cancel jobs before blocking their interface
- Better resource cleanup when jobs fail

---

#### Error 3: "Karma attack failed"
**When**: User tries Karma attack (probably on wlan0 or wlan1)

**Why**: Same as above - interface is rfkill blocked and/or DOWN

**Additional issue**: Error message too vague, doesn't say WHY it failed

**Fix needed**: Include actual error in user-facing message

---

#### Error 4: Multiple Jobs Running Simultaneously
**When**: Throughout entire session (20+ minutes)

**Why - The Complete Picture**:

**Symptom**: 3 jobs all attacking same target, all "running" for 10-20+ minutes

**Root Cause Chain**:
```
Job Start → Setup Phase → Error Occurs → What Should Happen vs Reality

START EVIL TWIN
└─> spawn_blocking(evil_twin_task)
    └─> evil_twin_task() {
        ├─> set_interface_up(wlan0)
        │   └─> FAILS: RF-kill blocked
        │       ├─> SHOULD: return Err → job exits
        │       └─> ACTUALLY: logs error, continues to retry phase
        │
        ├─> create_raw_socket(wlan0)
        │   └─> FAILS: Interface is DOWN
        │       ├─> SHOULD: return Err → job exits
        │       └─> ACTUALLY: logs error, continues to retry phase
        │
        └─> loop {
            ├─> send_beacon(wlan0) → FAILS (interface blocked)
            ├─> sleep(100ms)
            ├─> if should_cancel() → FALSE (cancellation not set/checked)
            │   └─> SHOULD: break and exit
            │   └─> ACTUALLY: check doesn't exist or returns false
            └─> continue forever...
        }
    }
```

**Why Job Doesn't Exit After Error**:

Looking at likely code structure in `rustyjack-wireless` or `rustyjack-core`:
```rust
// Hypothetical current implementation
pub fn evil_twin_attack(params: EvilTwinParams) -> Result<()> {
    // Setup phase
    match setup_interface(&params.interface) {
        Ok(_) => {},
        Err(e) => {
            log::error!("Setup failed: {}", e);
            // BUG: Should return here, but doesn't!
            // Falls through to main loop
        }
    }

    // Main attack loop
    loop {
        // BUG: No cancellation check!
        // BUG: Continues even though setup failed!

        match send_beacon(&params.interface) {
            Ok(_) => {
                // Successfully sent beacon
            },
            Err(e) => {
                // Beacon failed (interface blocked)
                log::error!("Beacon failed: {}", e);
                // BUG: Just logs and continues!
                // Should check: if errors > threshold, exit
                std::thread::sleep(Duration::from_secs(1));
                continue; // Try again forever
            }
        }

        print_status(); // This is why we see "running for Xs" in logs
    }

    // Never reaches cleanup code
}
```

**Why Multiple Jobs Accumulate**:
1. User starts attack → Job created (doesn't exit on error)
2. UI shows error, user thinks attack stopped
3. User tries again → Second job created (first still running)
4. Repeat → N zombie jobs all stuck in error loops

**System Impact Over Time**:
```
After 1 hour of failed attempts:
- 10-15 zombie jobs running
- 10-15 threads consuming 10-15 MB memory
- 10-15 raw sockets (may be leaked)
- Log spam: 10-15 status updates per 10 seconds = 90-135 log lines/minute
- CPU: Multiple threads all checking interface state, sleeping, retrying

After 8 hours:
- 50-100 zombie jobs
- 50-100 MB memory leaked
- Potential socket exhaustion
- Log file size: hundreds of MB
- System might become unstable
```

---

#### Error 5: Captive Portal Keeps Restarting
**When**: Throughout the session (visible in portal.log)

**Why**:
1. Portal configured to bind to wlan0 interface
2. Isolation keeps setting wlan0 DOWN every 4 seconds
3. Portal can't bind to DOWN interface
4. Portal crashes or exits
5. systemd auto-restarts portal service
6. Portal tries to bind to wlan0 again → still DOWN
7. Repeat every few seconds

**Log evidence** (portal.log):
```
00:48:52 - Portal starting, bind to 0.0.0.0:3000 on wlan0
00:48:55 - Portal starting, bind to 0.0.0.0:3000 on wlan0
00:48:57 - Portal starting, bind to 0.0.0.0:3000 on wlan0
00:49:00 - Portal starting, bind to 0.0.0.0:3000 on wlan0
... ~20 restarts in 2 minutes
```

**Root cause**: Portal needs active interface, but wlan0 is blocked

**Fix needed**: Portal should only run when its configured interface is active

---

### The Interconnected Nature of These Bugs

```
         ┌─────────────────────────────────────┐
         │  BUG #1: Interface Switch Ignored   │
         │  (daemon always picks eth0)         │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────────┐
         │  BUG #2: RF-kill Never Unblocked     │
         │  (wireless interfaces stay blocked)  │
         └──────────────┬───────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────────┐
         │  BUG #3: Jobs Fail to Start          │
         │  (RF-kill error, device busy error)  │
         └──────────────┬───────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────────┐
         │  BUG #4: Jobs Don't Exit on Error    │
         │  (enter infinite retry loops)        │
         └──────────────┬───────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────────┐
         │  BUG #5: Cancellation Doesn't Work   │
         │  (user exits, job keeps running)     │
         └──────────────┬───────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────────┐
         │  RESULT: Zombie Jobs Accumulate      │
         │  + Resource leaks                    │
         │  + System degradation over time      │
         └──────────────────────────────────────┘
```

**Fix ONE bug → Partially fixes others**:
- Fix #1 (interface switching) → #2 becomes visible, #3 becomes fixable
- Fix #2 (rfkill unblocking) → Jobs can start, #4 becomes main issue
- Fix #4 (fail fast on errors) → Fewer zombie jobs, #5 less critical
- Fix #5 (cancellation) → User has control, can manually clean up

**Must fix ALL to fully resolve the issues**.

---

## Implementation Priority

1. **CRITICAL**: Fix interface switching (Bug #1) - Without this, nothing works
2. **CRITICAL**: Add fail-fast on fatal errors (Bug #4) - Prevents zombie accumulation
3. **HIGH**: Fix rfkill unblocking (Bug #2) - Allows wireless to actually work
4. **HIGH**: Fix job cancellation (Bug #5) - Gives user control
5. **MEDIUM**: Add job status UI and manual kill - User workaround until fixed
6. **MEDIUM**: Add verification that active wireless interface stays UP
7. **LOW**: Investigate missing logs issue
8. **LOW**: Fix portal restart loop (symptom of #1)

---

## Testing Verification

After fixes, this sequence should work:

```bash
# 1. Select wlan0 as active interface in UI

# 2. Verify state
sudo rfkill list
# Should show: phy0 Soft blocked: no

ip link show wlan0
# Should show: state UP

# 3. Attempt wireless operation
# Evil Twin, Karma, etc. should now work

# 4. Check daemon logs
journalctl -u rustyjackd -n 50
# Should show: "Selected active interface: wlan0"
# Should show: "Interface wlan0 fully activated"
```

---

## What The Latest Logs Show (01:04-01:06)

### The Smoking Gun
You switched interfaces and tried attacks, but:

1. **Config file still shows**: `"active_network_interface": "eth0"`
2. **Every daemon log entry shows**: `"Selected active interface: eth0"`
3. **No logs showing**: `"Selected active interface: wlan0"` or `"...wlan1"`
4. **RFKILL remains blocked** for both wlan0 and wlan1
5. **Isolation runs every 4 seconds** and ALWAYS blocks wlan0/wlan1, activates eth0

### Unexpected Finding: Background Evil Twin Jobs
There are **multiple Evil Twin jobs running in the background**:
- ThreadId(913): Running for ~23 minutes
- ThreadId(5677): Running for ~2.3 minutes
- ThreadId(1055): Running for ~22 minutes

These jobs are somehow persisting even though their interfaces keep getting blocked by isolation enforcement. This suggests:
- Previous attack attempts created jobs that never properly terminated
- Jobs are running but unable to function because interfaces are blocked
- Possible job cleanup issue

### Conclusion
When you clicked to switch interfaces in the UI:
1. ❌ The daemon did NOT receive the switch command, OR
2. ❌ The daemon received it but immediately reverted to eth0

Either way, the daemon **never actually switched** from eth0 during your entire attack attempt.

---

## Root Cause Summary

**Primary Bug**: The daemon's isolation enforcement doesn't read or respect the `active_network_interface` setting from `gui_conf.json`. It always defaults to eth0, ignoring UI changes.

**Secondary Issue**: RustyJack's isolation enforcement is correctly designed to block non-active interfaces, but it's **not properly activating wireless interfaces** when they're selected. The rfkill soft-block is never being removed, so wireless operations fail with "Operation not possible due to RF-kill".

**Tertiary Issue**: Attack jobs may not be properly cleaned up when their interfaces are forcibly blocked, leading to zombie jobs running in the background.
