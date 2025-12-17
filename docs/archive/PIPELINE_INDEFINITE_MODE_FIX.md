# Pipeline Indefinite Mode Fix

## Problem Analysis

The "Get WiFi Password" pipeline had a critical bug in **Indefinite Mode** that caused it to:
1. Launch each attack step
2. Immediately fail/progress even if no results were captured
3. Display "WiFi sca...anning" truncated text
4. Complete the entire pipeline in seconds without actually capturing anything

## Root Cause

### Issue 1: Fall-through Logic Bug
In `execute_get_password_step()` (and other pipeline step functions), when `dispatch_cancellable()` returned `None` (cancelled or timeout), the function would fall through to:

```rust
Ok(StepOutcome::Completed(None))  // Line 7672
```

This told the pipeline "step completed successfully with no specific results".

### Issue 2: Indefinite Mode Mishandled Empty Results
In `execute_pipeline_steps()` at line 7476:

```rust
StepOutcome::Completed(None) => {
    step_successful = true; // No specific requirement
}
```

This made the pipeline immediately progress to the next step even though **nothing was captured**, defeating the entire purpose of "indefinite mode" (which should retry until results are obtained).

## The Fix

### Fix 1: Explicit Return Values
Changed every step function to **always return explicit results**:

```rust
// OLD CODE (BUGGY):
if let Some((_, data)) = self.dispatch_cancellable("Scanning", cmd, 20)? {
    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
}
// Falls through to Ok(StepOutcome::Completed(None)) ❌

// NEW CODE (FIXED):
if let Some((_, data)) = self.dispatch_cancellable("Scanning", cmd, 20)? {
    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
}
// Explicitly return zero results if cancelled
return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0)))); ✅
```

Now every step **explicitly returns** `(pmkids, handshakes, password, networks, clients)` counts, even if they're all zero.

### Fix 2: Handle Empty Results in Indefinite Mode
Changed the indefinite mode logic to treat `None` as "retry needed":

```rust
StepOutcome::Completed(None) => {
    // This shouldn't happen with our fixed code, but handle it anyway
    if indefinite_mode {
        step_successful = false; // In indefinite mode, no results = retry
    } else {
        step_successful = true; // Standard mode progresses anyway
    }
}
```

### Fix 3: Better Retry Messaging
Added clear logging about what each step is waiting for:

```rust
if !step_successful {
    let waiting_for = match i {
        0 => "networks to be found",
        1 => "PMKID to be captured",
        2 | 3 => "handshake to be captured",
        4 => "password to be cracked",
        _ => "results",
    };
    eprintln!("[PIPELINE] Step {} incomplete: waiting for {}", i + 1, waiting_for);
}
```

And improved max-retry failure messages:

```rust
let waiting_for = match i {
    0 => "No networks found",
    1 => "No PMKIDs captured",
    2 | 3 => "No handshakes captured",
    4 => "Password not cracked",
    _ => "No results obtained",
};
self.show_message(
    "Pipeline stopped",
    [
        &format!("Step {} failed", i + 1),
        "",
        waiting_for,
        &format!("{} retries exhausted", MAX_RETRIES),
    ],
)?;
```

## How It Works Now

### Standard Mode
- Each step runs **once** with its timeout
- Pipeline progresses to next step regardless of results
- Quick execution (sum of all step timeouts)

### Indefinite Mode ✅ (FIXED)
1. **Step 1: Scan networks**
   - Runs 20-second scan
   - If 0 networks found → **RETRY** (up to 10 times)
   - If networks found → Progress to step 2

2. **Step 2: PMKID capture**
   - Runs 30-second PMKID capture
   - If 0 PMKIDs captured → **RETRY**
   - If PMKIDs captured → Progress to step 3

3. **Step 3: Deauth attack**
   - Runs 30-second deauth with handshake capture
   - If 0 handshakes captured → **RETRY**
   - If handshake captured → Progress to step 4

4. **Step 4: Handshake capture**
   - Runs 60-second extended capture
   - If 0 handshakes captured → **RETRY**
   - If handshake captured → Progress to step 5

5. **Step 5: Quick crack**
   - Attempts to crack the captured handshake
   - If password not found → **RETRY** (up to 10 times total)
   - If password found → **PIPELINE COMPLETE** ✅

## Safety Mechanisms

1. **Max Retries**: 10 retries per step (prevents infinite loops)
2. **Cancel Checking**: User can press LEFT button to cancel at any time
3. **Explicit Failure Messages**: Clear indication of what step failed and why
4. **2-Second Pause**: Brief pause between retries to prevent hammering

## Testing Recommendations

Test indefinite mode in these scenarios:

1. ✅ **No networks in range** → Should retry scan up to 10 times, then fail with clear message
2. ✅ **Target has no clients** → Should retry deauth/capture steps until handshake obtained
3. ✅ **Weak password** → Should successfully crack after handshake captured
4. ✅ **User cancellation** → Should cleanly exit at any step when LEFT button pressed
5. ✅ **Standard mode** → Should still run through all steps once regardless of results

## Files Modified

- `rustyjack-ui/src/app.rs`
  - `execute_get_password_step()` - Fixed return values for all 5 steps
  - `execute_pipeline_steps()` - Fixed indefinite mode retry logic and messaging

## Related Issues Fixed

- ❌ "WiFi sca...anning" truncated display (caused by immediate failure)
- ❌ Pipeline completing in <5 seconds (was skipping steps)
- ❌ Indefinite mode not retrying (was treating no-results as success)
- ❌ Unclear failure messages (now shows exactly what's missing)

## Deploy & Test

```bash
cd ~/Rustyjack
cargo build --release
sudo cp target/release/rustyjack-ui /usr/local/bin/
sudo systemctl restart rustyjack
```

Then test:
1. Go to **Wireless → Get Connected → Pipelines → Get WiFi Password**
2. Select **Indefinite Mode**
3. Pick a target network with clients connected
4. Watch it properly retry each step until results are obtained
5. Verify it progresses through all 5 steps correctly
