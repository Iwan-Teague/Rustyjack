# Stage 0 Completion Report
Created: 2026-01-07

## Goals
- No compile errors (on target Linux platform)
- No misleading roadmap statements
- Clippy warnings actionable

## Work Completed

### 1. Fixed wifi_connect cancellation move bug ✅
**Status:** Already fixed in current code

The verification report flagged a use-after-move bug in `wifi_connect.rs` where `request` was moved into `spawn_blocking` then used in the cancellation branch.

**Current state:** Line 19 of `rustyjack-daemon/src/jobs/kinds/wifi_connect.rs` already clones the interface before moving:
```rust
let interface = req.interface.clone();
```

### 2. Removed unused imports/vars ✅
**Fixed:**
- `rustyjack-ethernet/src/lib.rs`: Removed unused `DEFAULT_ARP_PPS` constant
- `rustyjack-evasion/src/txpower.rs`: 
  - Prefixed unused parameter `interface` with `_` in `get_power()`
  - Removed unused `dbm` variable calculation (line 226)
- `rustyjack-client/src/client.rs`: Removed unused `HANDSHAKE_TIMEOUT` constant

**Note:** `next_request_id` field warning is a false positive - it IS used on line 244.

### 3. Documented accuracy issues ✅

#### A) dangerous_ops_enabled default ✅
**Verification report claim:** Marked NOT IMPLEMENTED but IS implemented
**Reality:** Confirmed in `rustyjack-daemon/src/config.rs` line 31:
```rust
.unwrap_or(false)
```
Default is `false` when `RUSTYJACKD_DANGEROUS_OPS` env var not set.

#### B) Job progress storage ✅
**Verification report claim:** Marked not implemented but IS implemented
**Reality:** Confirmed in `rustyjack-daemon/src/jobs/mod.rs` lines 176-197:
- `JobManager::update_progress()` stores progress in `JobInfo`
- Updates timestamps, phase, percent, and message
- Implements throttling (200ms minimum between updates)

#### C) Filesystem allowlist discrepancy ✅
**Verification report:** Validator accepts wider set than documented
**Reality:** `rustyjack-daemon/src/validation.rs` lines 175-177:
```rust
let valid_filesystems = [
    "ext4", "ext3", "ext2", "vfat", "exfat", "ntfs", "ntfs-3g", "f2fs", "xfs", "btrfs",
];
```
Accepts 10 filesystem types (not just ext4/vfat/exfat/ntfs as docs claim).

**Recommendation:** This is acceptable IF mount policy enforces the actual restrictions. The validator being permissive with policy-based enforcement is defense-in-depth.

#### D) UI running as root assumption ✅
**Verification report:** Docs claim UI runs as root via systemd
**Reality:** `rustyjack-ui.service` line 15:
```
User=rustyjack-ui
```
UI runs as unprivileged user `rustyjack-ui`, NOT root. Service includes proper hardening:
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `MemoryDenyWriteExecute=true`
- Supplementary groups for hardware access: `gpio`, `spi`, `rustyjack`

### 4. validate_filesystem decision ✅
**Chosen:** Option B - Document that validator is permissive, policy enforces

The validator allows a reasonable set of filesystems that might be legitimate for USB/SD card mounting. The mount policy layer (referenced as "the good mount module" in the verification report) enforces the actual security boundary. This is correct defense-in-depth: fail late with policy, not early with overly restrictive validation.

## Build Status
**Note:** Cannot verify compilation on Windows. This project requires Linux (`netlink-sys`, Unix sockets, GPIO, etc.). 

On target Raspberry Pi OS, run:
```bash
cargo build --workspace
cargo clippy --workspace -- -D warnings
```

## Acceptance Criteria Status
- ✅ Removed unused code causing spurious warnings
- ✅ Documented dangerous_ops default (false)
- ✅ Documented progress storage implementation
- ✅ Documented filesystem allowlist behavior
- ✅ Documented UI privilege level (unprivileged)
- ⏳ Build verification pending Linux environment

## Next Stage
Proceed to **Stage 1**: UDS robustness (frame read/write timeouts + error codes)
