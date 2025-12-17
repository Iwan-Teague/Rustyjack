# Error Handling Guidelines for Rustyjack

## Current Status: ✅ EXCELLENT

Your error handling is **production-ready** with proper Result types, descriptive messages, and context throughout.

## Audit Results (2025-12-14)

### ✅ What's Good:
- **rustyjack-netlink**: Zero `.unwrap()` or `.expect()` in production code
- All errors use `Result<T>` with proper error types
- Context is provided in error messages (interface names, operations)
- No panics on user input or external data
- Proper error propagation with `?` operator

### ⚠️ Minor Issues Found:

1. **Mutex Locks** (LOW severity)
   - **Files**: `hotspot.rs:88`, `karma.rs` (multiple)
   - **Issue**: `.lock().unwrap()` panics if mutex poisoned
   - **Status**: Fixed in hotspot.rs, kept `.expect()` in karma.rs (internal only)
   - **Rationale**: Poisoned mutex only happens if thread panics while holding lock

2. **Crypto Operations** (ACCEPTABLE)
   - **Files**: `crack.rs:440, 470`
   - **Issue**: `.expect("HMAC key size")`
   - **Status**: Acceptable - keys are hardcoded correct sizes
   - **Rationale**: These are internal crypto operations, keys are always valid

3. **Test Code** (ACCEPTABLE)
   - Multiple `.unwrap()` calls in `#[test]` functions
   - **Status**: This is fine - tests are allowed to panic

## Error Message Quality Checklist

### ✅ Good Examples in Your Code:

```rust
// GOOD: Includes interface name and operation
.map_err(|e| WirelessError::Interface(format!(
    "Failed to set {} down: {}",
    interface, e
)))

// GOOD: Includes file path and reason
.map_err(|e| WirelessError::System(format!(
    "Failed to write hostapd config to {}: {}",
    path, e
)))

// GOOD: Includes pattern and why it failed
.map_err(|e| anyhow::anyhow!(
    "Failed to kill processes matching '{}': {}",
    pattern, e
))
```

### 🎯 Best Practices (Already Following):

1. **Include Context**
   - ✅ Interface/device names
   - ✅ File paths
   - ✅ Operation being performed
   - ✅ Expected vs actual values

2. **Use Specific Error Types**
   - ✅ `WirelessError::Interface`
   - ✅ `WirelessError::Channel`
   - ✅ `ProcessError::NotFound`
   - ✅ `RfkillError::DeviceOpen`

3. **Chain Errors Properly**
   - ✅ Use `.map_err()` to add context
   - ✅ Propagate with `?` operator
   - ✅ Convert between error types explicitly

4. **Avoid Silent Failures**
   - ✅ Log errors before ignoring with `let _ =`
   - ✅ Return errors instead of None when possible

## Error Types Overview

### rustyjack-netlink

**NetlinkError** variants:
- `Runtime` - General netlink operations
- `InterfaceIndexError` - Interface not found
- `SetStateError` - Failed to up/down interface
- `AddAddressError` - Failed to add IP
- `DeleteAddressError` - Failed to delete IP
- `AddRouteError` - Failed to add route
- `DeleteRouteError` - Failed to delete route
- `ListLinksError` - Failed to enumerate interfaces

**ProcessError** variants:
- `ProcRead` - Failed to read /proc
- `ParseError` - Failed to parse process info
- `SignalError` - Failed to signal process
- `NotFound` - Process not found
- `Io` - IO error (#[from] std::io::Error)

**RfkillError** variants:
- `DeviceOpen` - Failed to open /dev/rfkill
- `ReadEvent` - Failed to read rfkill event
- `WriteEvent` - Failed to write rfkill event
- `InvalidType` - Invalid rfkill device type
- `DeviceNotFound` - Specific device not found
- `InvalidState` - Invalid rfkill state

### rustyjack-wireless

**WirelessError** variants:
- `System` - System-level errors (commands, files)
- `Interface` - Interface-specific errors
- `Channel` - Channel configuration errors
- `Injection` - Packet injection failures
- `Capture` - Packet capture failures
- `Parse` - Frame/packet parsing errors
- `Io` - IO errors

## When to Use Each Pattern

### Pattern 1: Direct Error (Most Common)
```rust
pub fn do_thing(interface: &str) -> Result<()> {
    some_operation()
        .map_err(|e| WirelessError::System(format!(
            "Failed to do thing on {}: {}",
            interface, e
        )))?;
    Ok(())
}
```

### Pattern 2: Context Wrapper
```rust
use anyhow::Context;

pub fn complex_operation() -> Result<()> {
    do_step_one()
        .with_context(|| "Step 1 failed")?;
    
    do_step_two()
        .with_context(|| format!("Step 2 failed for {}", name))?;
    
    Ok(())
}
```

### Pattern 3: Custom Error Conversion
```rust
impl From<std::io::Error> for WirelessError {
    fn from(e: std::io::Error) -> Self {
        WirelessError::Io(e)
    }
}
```

### Pattern 4: Optional Logging Before Propagation
```rust
pub fn important_operation() -> Result<()> {
    match risky_operation() {
        Ok(val) => Ok(val),
        Err(e) => {
            log::error!("Risky operation failed: {}", e);
            Err(e)
        }
    }
}
```

## User-Facing Error Messages

### ✅ Good Error Messages (What You Already Have):

```
"Interface wlan0 not found"
"Failed to set wlan0 down: Device busy"
"iw scan failed: Operation not permitted (add sudo)"
"Failed to kill processes matching 'hostapd': Permission denied"
```

### Features to Consider Adding (Optional):

1. **Error Codes** (for programmatic handling)
```rust
pub enum ErrorCode {
    PermissionDenied,
    DeviceNotFound,
    DeviceBusy,
    // ...
}
```

2. **Recovery Suggestions** (for UI)
```rust
pub struct DetailedError {
    message: String,
    suggestion: Option<String>,
    code: ErrorCode,
}
```

3. **Severity Levels** (for logging)
```rust
pub enum ErrorSeverity {
    Info,    // Recoverable, expected
    Warning, // Unexpected but not critical
    Error,   // Operation failed
    Fatal,   // Unrecoverable
}
```

## Testing Error Paths

Your error handling is solid, but consider adding tests for:

1. **Permission Errors**
   - Test what happens when user is not root
   - Verify error messages are helpful

2. **Device Not Found**
   - Test with non-existent interface names
   - Verify proper "not found" vs "permission" distinction

3. **Race Conditions**
   - Test what happens if device unplugged mid-operation
   - Verify clean error propagation

4. **Invalid Input**
   - Test with malformed MAC addresses
   - Test with invalid channel numbers
   - Verify validation errors are clear

## Summary

Your error handling is **already excellent**. The improvements made today:

1. ✅ Fixed mutex unwrap in hotspot.rs (added proper error)
2. ✅ Documented why some `.expect()` calls are acceptable
3. ✅ Confirmed all production code has proper error handling

**No critical issues found.** Your code is production-ready!

## Recommendations (Optional Future Enhancements)

Priority: **LOW** (these are nice-to-haves, not requirements)

1. Add structured error codes for programmatic handling
2. Add user-facing suggestions to error messages ("Try running with sudo")
3. Add error context chain for debugging (keep full error history)
4. Add integration tests for error paths
5. Add error recovery mechanisms (retry with backoff, fallbacks)

But honestly, your current error handling is **very good as-is**. Focus on features, not error handling polish.
