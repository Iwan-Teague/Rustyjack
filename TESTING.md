# Interface Selection Verification (Pi Zero 2 W)

## Preconditions
- Hardware: Raspberry Pi Zero 2 W with Ethernet HAT and Waveshare LCD HAT.
- Services running: `rustyjackd.service`, `rustyjack-ui.service`.
- Device reachable over SSH (preferably via ethernet for recovery validation).

## Build / Deploy
1. Build and install the updated workspace artifacts.
2. Reboot Pi.
3. Confirm daemon + UI start cleanly.

## Manual Verification Checklist

### 1. Truthful interface list
1. Open `Settings -> Active Interface -> View Status`.
2. Confirm both wired and wireless uplinks are listed (`eth0`/`enx...` and `wlan0`).
3. Confirm each row shows admin UP/DOWN, carrier, and IP (if assigned).

### 2. Ethernet steady-state selection
1. From `Switch Interface`, select ethernet uplink.
2. Observe progress phases (`Phase A`, `Phase B`, `Verifying`).
3. Confirm success message appears only after post-check verifies admin-UP.
4. Confirm non-selected uplink(s) are admin-DOWN at steady state.

### 3. Wireless steady-state selection
1. From `Switch Interface`, select `wlan0`.
2. Confirm switch completes without leaving both uplinks DOWN.
3. If not associated, UI may show warning (admin-UP required, link/connectivity optional).

### 4. Cable unplug scenario
1. Unplug ethernet cable.
2. Switch to ethernet uplink.
3. Confirm result shows admin-UP with carrier false (and DHCP skipped/failed warning if applicable).

### 5. rfkill degraded scenario
1. Simulate rfkill access problem (or soft-block not clearable).
2. Switch to wireless target.
3. Confirm switch does not hard-fail pre-commit unless hard-blocked.
4. Confirm warnings are shown in UI and system remains recoverable.

### 6. DHCP failure scenario
1. Connect ethernet to network with no DHCP response.
2. Switch to ethernet.
3. Confirm interface becomes admin-UP and isolation invariant remains enforced.
4. Confirm DHCP/route failure appears as warning, not false success about connectivity.

### 7. Rollback safety
1. Force a post-isolation failure condition (e.g., injected failure during commit).
2. Run interface switch.
3. Confirm failure message reports rollback status.
4. Confirm previous uplink is restored admin-UP when possible.

## Acceptance Criteria
- Interface list is truthful and includes both wired and wireless uplinks.
- At steady state, exactly one uplink is admin-UP (`lo` excluded).
- Switching is transactional: commit failures after isolation trigger rollback.
- UI never claims success before verification of selected interface admin-UP.
- Background watcher enforcement does not race/fight switch jobs.
