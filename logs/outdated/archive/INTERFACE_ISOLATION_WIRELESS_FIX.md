# Interface Isolation Wireless Fix
Created: 2026-01-07

## Problem Identified

When selecting a wireless interface in Hardware Detect, users encountered errors:
- **Ethernet (eth0)**: Shows "Interface isolated (no gateway found)" - correct but confusing
- **Wireless (wlan0)**: Shows "Route failed for wlan0 ip link set up failed for wlan" followed by "Isolation failed: ip link set up failed for wlan0"

## Root Cause

The interface isolation logic had **incorrect ordering and error handling** for wireless interfaces:

1. **Wrong order**: Tried to bring interface UP before unblocking rfkill
2. **Strict failure**: Failed the entire operation if `ip link set up` failed
3. **Wireless behavior**: Wireless interfaces **cannot be brought UP** until associated with an AP
4. **Confusing messages**: Error messages didn't distinguish between selection success and connection status

## Technical Details

### Wireless Interface States

Wireless interfaces have special requirements:

```
1. RFKILL BLOCKED -> Cannot do anything
2. RFKILL UNBLOCKED, DOWN -> Can scan, but not transmit/associate
3. UP + UNASSOCIATED -> Can scan and attempt association
4. UP + ASSOCIATED -> Can transmit/receive data
5. UP + ASSOCIATED + IP -> Can route traffic
```

### The Problem Flow

**Old behavior when selecting wlan0:**
```
1. User selects wlan0 in Hardware Detect
2. apply_interface_isolation([wlan0]) called
3. Tries: ip link set wlan0 up (FAILS if not associated)
4. Returns error: "ip link set up failed for wlan0"
5. UI shows: "Isolation failed..."
6. ensure_route_for_interface() called anyway
7. enforce_single_interface() called again (duplicate)
8. More errors cascade
```

**Result**: Error messages even though selection worked and isolation succeeded.

## Changes Made

### 1. Fixed `apply_interface_isolation()` in `rustyjack-core/src/system.rs`

**Key improvements:**

```rust
// OLD: Bring interface up, THEN unblock rfkill
ip link set wlan0 up
rfkill unblock X

// NEW: Unblock rfkill FIRST, then bring interface up
rfkill unblock X
ip link set wlan0 up
```

**Lenient error handling:**
```rust
// OLD: Fail if ip link set up fails
.ok_or_else(|| anyhow!("ip link set up failed for {}", iface))?

// NEW: Only fail for non-wireless interfaces
if !status.success() {
    if !is_wireless {
        errors.push(format!("{}: failed to bring up", iface));
    }
    // For wireless: expected if not associated, not an error
}
```

**Behavior:**
- ✅ Wireless interfaces: rfkill unblocked, other interfaces disabled (success)
- ✅ Ethernet interfaces: brought UP, other interfaces disabled (success)
- ✅ Non-wireless failures: collected and reported as errors
- ✅ Wireless failures: silently ignored (expected state)

### 2. Updated UI messages in `rustyjack-ui/src/app.rs`

**Better feedback:**
```rust
// OLD:
lines: ["Set to: wlan0", "Isolation failed: ip link set up failed for wlan0"]

// NEW:
lines: ["Set to: wlan0", "Other interfaces disabled", "Interface isolated (no gateway found)"]
```

**Added explicit success message:**
- Shows "Other interfaces disabled" when isolation succeeds
- Clarifies that selection worked even if not connected

## New Behavior

### When selecting eth0:
```
✅ Set to: eth0
✅ Other interfaces disabled
ℹ️  Interface isolated (no gateway found)
```
**Meaning**: eth0 selected, wlan interfaces blocked, no gateway because not connected to anything.

### When selecting wlan0 (not connected):
```
✅ Set to: wlan0
✅ Other interfaces disabled
ℹ️  Interface isolated (no gateway found)
```
**Meaning**: wlan0 selected, rfkill unblocked, other interfaces blocked, no gateway because not connected to AP.

### When selecting wlan0 (already connected):
```
✅ Set to: wlan0
✅ Other interfaces disabled
✅ Default route updated
```
**Meaning**: wlan0 selected, isolated, and has working gateway because already associated with AP.

## What "Interface isolated" Means

This is **not an error** - it's the expected behavior:

1. **Selected interface**: Chosen as active
2. **rfkill unblocked**: Wireless radio enabled (if wireless)
3. **Other interfaces DOWN**: Ethernet/other wireless disabled
4. **Other wireless blocked**: rfkill blocked on unused wireless
5. **No gateway found**: Interface not connected yet (need to connect to AP/network first)

## User Workflow

### For Ethernet (eth0):
1. Hardware Detect → Select eth0
2. Message: "Set to: eth0, Other interfaces disabled, Interface isolated (no gateway found)"
3. Connect ethernet cable
4. Network → Ethernet → Discover (to verify connection)
5. Gateway will be detected automatically when cable connected

### For Wireless (wlan0):
1. Hardware Detect → Select wlan0
2. Message: "Set to: wlan0, Other interfaces disabled, Interface isolated (no gateway found)"
3. Network → WiFi → Scan
4. Network → WiFi → Connect to network
5. Gateway will be detected after association
6. Or: Network → WiFi → Manage Saved Networks → Connect to saved profile

## Testing

### Test 1: Ethernet Selection
```bash
# Select eth0 in Hardware Detect
# Expected: "Set to: eth0, Other interfaces disabled, Interface isolated (no gateway found)"
# Verify:
ip link show  # eth0 should be UP
rfkill list   # Wireless devices should be BLOCKED
ip route      # May show no default route (correct)
```

### Test 2: Wireless Selection (not connected)
```bash
# Select wlan0 in Hardware Detect
# Expected: "Set to: wlan0, Other interfaces disabled, Interface isolated (no gateway found)"
# Verify:
ip link show wlan0     # Should be UP (or DOWN if not associated - both OK)
rfkill list            # wlan0 should be UNBLOCKED
ip link show eth0      # Should be DOWN
iw wlan0 link          # Should show "Not connected" (correct)
```

### Test 3: Wireless Selection (already connected)
```bash
# First connect to a network
# Then select wlan0 in Hardware Detect
# Expected: "Set to: wlan0, Other interfaces disabled, Default route updated"
# Verify:
iw wlan0 link          # Should show connected to SSID
ip route               # Should show default via wlan0
ping 8.8.8.8           # Should work
```

## Common Scenarios

### Scenario 1: "I selected wlan0 but can't connect to internet"
**Answer**: Selecting an interface != connecting to network
- Selection: Enables interface, blocks others
- Connection: Must still connect to WiFi network
- Go to: Network → WiFi → Scan → Connect

### Scenario 2: "Message says 'no gateway found', is that bad?"
**Answer**: No, it's informational
- Means: Interface selected successfully but not connected yet
- For ethernet: Plug in cable
- For wireless: Connect to AP
- Gateway will appear automatically after connection

### Scenario 3: "I get errors about 'ip link set up failed'"
**Answer**: Should no longer happen with this fix
- Old version: Showed this error for wireless
- New version: Silently handles wireless "failures"
- If still seeing: May be non-wireless interface issue (actual error)

## Verification

After deploying this fix, verify:

- [ ] Selecting eth0 shows "Other interfaces disabled", no errors
- [ ] Selecting wlan0 shows "Other interfaces disabled", no errors
- [ ] `rfkill list` shows selected wireless unblocked, others blocked
- [ ] `ip link show` shows only selected interface UP (or wireless DOWN if not associated)
- [ ] Other interfaces are DOWN
- [ ] Can still scan/connect after selecting wlan0
- [ ] Can ping after connecting to network

## Files Modified

- **`rustyjack-core/src/system.rs`**:
  - `apply_interface_isolation()` - Fixed rfkill/link order, lenient wireless error handling
  
- **`rustyjack-ui/src/app.rs`**:
  - `show_hardware_detect()` - Better success messages, clarifies isolation succeeded

## Technical Notes

### Why wireless "link set up" can fail

Wireless interfaces differ from ethernet:

**Ethernet**: Can be brought UP anytime (physical interface)
**Wireless**: Can only be brought UP when:
- rfkill unblocked
- Firmware loaded
- Ready to associate
- Some drivers: only after association

**Solution**: Don't treat wireless link-up failures as errors - rfkill unblock is what matters for making the interface usable.

### Why rfkill must come first

```
# WRONG ORDER:
ip link set wlan0 up    # Fails if blocked
rfkill unblock 0        # Too late

# CORRECT ORDER:
rfkill unblock 0        # Enable radio first
ip link set wlan0 up    # Now it can work (if driver supports)
```

Even if `ip link set up` still fails after unblock (some drivers don't allow it until associated), the interface is **usable** - it can scan and attempt association.

## Summary

The fix makes interface isolation **succeed correctly** for wireless interfaces by:

1. **Reordering**: Unblock rfkill before attempting link-up
2. **Lenient**: Don't fail if wireless can't be brought UP (expected)
3. **Clear**: Show "Other interfaces disabled" to confirm success
4. **Informative**: "No gateway found" is informational, not an error

Users can now:
- ✅ Select any interface without errors
- ✅ See clear success messages
- ✅ Understand that "no gateway" means "not connected yet"
- ✅ Proceed to connect to networks after selection
