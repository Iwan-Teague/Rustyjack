# Hotspot Device History Feature
Created: 2026-01-07

## Overview
The "Connected Devices" menu in the hotspot now displays only **currently connected devices** instead of all devices that have ever connected. Historical device information is now stored in the loot directory.

## Changes Made

### 1. Current Connection Detection
- Uses `ip neigh show dev <ap_iface>` to query the ARP table for active devices
- Only devices with ARP state `REACHABLE`, `STALE`, or `DELAY` are considered currently connected
- Filters out expired DHCP leases from the display

### 2. Device History Logging
- All devices that receive a DHCP lease are logged to `loot/Hotspot/device_history.txt`
- Each entry contains:
  - First seen timestamp (when first logged by Rustyjack)
  - MAC address
  - IP address
  - Hostname (or "Unknown")
  - DHCP lease timestamp
- Duplicate entries are prevented: each MAC is logged only once

### 3. Loot Directory Structure
```
loot/
└── Hotspot/
    └── device_history.txt    # Historical record of all devices
```

## Example History Entry
```
2024-01-15 14:32:10 | MAC: a1:b2:c3:d4:e5:f6 | IP: 10.20.30.15 | Hostname: iPhone-XR | Lease Timestamp: 1705328930
2024-01-15 14:35:22 | MAC: 11:22:33:44:55:66 | IP: 10.20.30.16 | Hostname: Unknown | Lease Timestamp: 1705329122
```

## User Experience
- When hotspot is running, select "Connected Devices" from the hotspot menu
- Only devices **currently connected at that moment** are displayed
- Message shows "No devices currently connected" if no active connections
- Device history is automatically maintained in the background
- Historical data can be reviewed by examining `loot/Hotspot/device_history.txt`

## Technical Details
- **ARP states used**: REACHABLE (recently communicated), STALE (not recently confirmed), DELAY (waiting for reachability)
- **History deduplication**: On each view, the existing history file is parsed to avoid duplicate entries
- **Blacklist integration**: Blacklisted devices are excluded from the display but still logged to history
- **Error handling**: Gracefully handles missing ARP entries, empty lease files, and file I/O errors

## Files Modified
- `rustyjack-ui/src/app.rs`: Updated `show_hotspot_connected_devices()` method
- `AGENTS.md`: Documented new loot directory structure
