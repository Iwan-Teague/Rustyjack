# Build Fixes - Stage 0 Corrections
Created: 2026-01-07

## Issues
During Stage 0 cleanup, several constants and variables were incorrectly removed or renamed, causing build errors.

## Errors Fixed

### 1. HANDSHAKE_TIMEOUT (rustyjack-client)
**Error:**
```
error[E0425]: cannot find value `HANDSHAKE_TIMEOUT` in this scope
   --> rustyjack-client/src/client.rs:137:33
```

**Fix:** Restored constant
```rust
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
```

### 2. DEFAULT_ARP_PPS (rustyjack-ethernet)
**Error:**
```
error[E0425]: cannot find value `DEFAULT_ARP_PPS` in this scope
error[E0308]: mismatched types (expected u32, found u64)
   --> rustyjack-ethernet/src/lib.rs:386:68
```

**Fix:** Restored constant with correct type
```rust
const DEFAULT_ARP_PPS: u32 = 100;  // u32, not u64
```

### 3. Portal Server Visibility (rustyjack-portal)
**Error:**
```
error[E0364]: `build_router` is only public within the crate
error[E0364]: `run_server` is only public within the crate
```

**Fix:** Changed visibility from `pub(crate)` to `pub`
```rust
pub fn build_router(cfg: &PortalConfig, state: PortalState) -> Router
pub async fn run_server(...)
```

### 4. Unused Parameter Warnings (rustyjack-evasion)
**Error:**
```
error[E0425]: cannot find value `interface` in this scope
error[E0425]: cannot find value `dbm` in this scope
```

**Fix:** 
- Changed `_interface` back to `interface` (it IS used in conditional code)
- Added `let dbm = level.to_dbm();` before the log statement

## Root Cause

Stage 0 was too aggressive in "fixing" compiler warnings:

1. **Constants flagged as unused** were actually used in specific code paths
2. **Parameters with leading underscore** were actually used in conditional compilation blocks
3. **Variables** were removed but still referenced in log statements

## Corrected Stage 0 Summary

**Actually removed (correctly):**
- None - all "unused" items were false positives from conditional compilation

**Fixed (warnings about unused variables):**
- None - the warnings were legitimate but the variables were still needed

**Result:** Stage 0 cleanup was rolled back entirely. All constants and parameters restored.

## Lesson Learned

**Do not blindly fix compiler warnings without understanding the code context:**
1. Check for conditional compilation (`#[cfg(...)]`)
2. Search for all references across the entire file
3. Understand why the compiler thinks it's unused
4. Test build after every change
5. For platform-specific code on Windows, cross-check Linux compilation

## Final Status

✅ **All build errors fixed**  
✅ **All constants restored**  
✅ **All parameters correct**  
✅ **Portal visibility fixed**  
✅ **Ready for Linux build**

## Impact

**None** - This was a complete rollback of Stage 0's overzealous cleanup. The codebase warnings remain as they were, but they are false positives due to conditional compilation and platform-specific code.

**New Stage 0 Summary:**
- ❌ Did NOT remove unused code (false positives)
- ✅ Verified documentation accuracy
- ✅ Verified wifi_connect bug already fixed
- ✅ Established baseline for Stages 1-5
