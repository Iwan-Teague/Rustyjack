# Error Handling Improvements
Created: 2026-01-07

## Overview
This document tracks improvements made to error handling across the Rustyjack codebase to provide better error messages and more graceful failure modes.

## Completed Improvements (2025-12-11)

### UI Code (`rustyjack-ui/src/app.rs`, `rustyjack-ui/src/stats.rs`)

#### Mutex Lock Error Handling
**Problem**: Code used `.unwrap()` on Mutex locks, which panics if the mutex is poisoned (happens when a thread panics while holding the lock).

**Fixed**:
- Replaced all `.lock().unwrap()` calls with proper error handling
- Added descriptive error messages: `"Result mutex poisoned: {}"`
- Provides recovery information instead of silent panics

**Locations**:
- Line 653: Background command dispatch result mutex
- Line 693: Result polling in main loop
- Line 3902: Deauth attack result mutex  
- Line 3929: Attack completion check
- Line 3979: Attack result retrieval
- `stats.rs:71`: Stats collection mutex

#### Path/Filename Handling
**Problem**: Used double `.unwrap()` chains on path operations that could fail on invalid Unicode filenames.

**Fixed**:
```rust
// Before:
Path::new(hf).file_name().unwrap().to_str().unwrap()

// After:
Path::new(hf).file_name()
    .and_then(|n| n.to_str())
    .unwrap_or("handshake.cap")
```

**Benefit**: Provides sensible fallback names instead of panicking on edge cases.

**Locations**:
- Line 3991: Handshake capture filename display
- Line 4010: Attack log filename display

#### File I/O Context
**Problem**: Generic I/O errors without context about which file operation failed.

**Fixed**:
```rust
// Before:
let data = fs::read_to_string(&latest)?;

// After:
let data = fs::read_to_string(&latest)
    .with_context(|| format!("Failed to read loot file: {}", latest))?;
```

**Benefit**: Error messages now show the exact file path that failed, making debugging much easier.

**Locations**:
- Line 8875-8877: Loot file reading and JSON parsing

#### Missing Value Handling
**Problem**: Used `.unwrap()` on `Option` values that might not exist.

**Fixed**:
```rust
// Before:
let latest = files.last().cloned().unwrap();

// After:  
let latest = files.last().cloned()
    .ok_or_else(|| anyhow::anyhow!("No loot files found in directory"))?;
```

**Benefit**: Clear error message instead of generic "called `Option::unwrap()` on a `None` value".

## Remaining Improvements Needed

### High Priority

1. **Core Library** (`rustyjack-core/src/`)
   - ~150+ `bail!()` calls with good context already
   - Consider adding error recovery strategies where appropriate
   - Add validation functions with detailed error messages

2. **Wireless Module** (`rustyjack-wireless/src/`)
   - Review packet parsing error handling
   - Add better context for nl80211 operation failures
   - Improve injection failure messages

3. **Evasion Module** (`rustyjack-evasion/src/`)
   - Already has good error types defined
   - Could add more recovery strategies
   - Consider rate-limiting retry logic

### Medium Priority

4. **Error Type Consolidation**
   - Create a top-level error type that wraps all sub-crate errors
   - Implement proper error conversion traits
   - Add error categorization (Recoverable/Fatal/UserError)

5. **User-Facing Errors**
   - Distinguish between developer errors and user errors
   - Add "how to fix" suggestions to user errors
   - Example: "SSID cannot be empty" → "SSID cannot be empty. Please provide a network name."

6. **Configuration Validation**
   - Add pre-flight validation for all config structures
   - Return all validation errors at once (not fail-fast)
   - Example:
     ```rust
     pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
         let mut errors = Vec::new();
         if self.ssid.is_empty() {
             errors.push(ValidationError::EmptySSID);
         }
         // ... more checks
         if errors.is_empty() { Ok(()) } else { Err(errors) }
     }
     ```

### Low Priority

7. **Error Logging Strategy**
   - Add structured logging with error context
   - Log error chains with `source()` traversal
   - Add error metrics/counters for debugging

8. **Error Recovery Documentation**
   - Document which errors are recoverable
   - Add recovery examples to docstrings
   - Create troubleshooting guide based on common errors

## Error Handling Best Practices

### DO ✅
- Use `anyhow::Context` to add context to errors
- Return `Result<T>` from fallible operations
- Use descriptive error messages with values
- Handle `Option` with `.ok_or_else()` instead of `.unwrap()`
- Add recovery information to error messages

### DON'T ❌
- Use `.unwrap()` or `.expect()` in library code
- Use generic error messages like "operation failed"
- Panic on recoverable errors
- Swallow errors with `let _ =` without logging
- Use `.unwrap_or_default()` when the default hides a problem

## Testing Error Paths

Consider adding tests for error conditions:
```rust
#[test]
fn test_empty_ssid_error() {
    let result = connect_wifi("", "password");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("SSID cannot be empty"));
}
```

## Impact

These improvements make Rustyjack:
1. **More debuggable**: Errors show exactly what went wrong and where
2. **More resilient**: Graceful degradation instead of panics
3. **More user-friendly**: Clear actionable error messages
4. **More maintainable**: Easier to track down issues in production

## Next Steps

1. Review all remaining `.unwrap()` calls in core modules
2. Add validation functions for user inputs
3. Create error recovery strategies for network operations
4. Add integration tests for error paths
