# Binary Dependencies Refactoring Status

## Overview
This document tracks the migration of external binary command dependencies to in-house Rust implementations via the `rustyjack-netlink` crate.

## Completed Migrations

### rustyjack-netlink Crate
**Status:** ✅ IMPLEMENTED

The `rustyjack-netlink` crate now provides pure Rust implementations for:

1. **Link Management** (`LinkManager`)
   - Interface up/down
   - MAC address setting
   - IPv4/IPv6 address management
   - MTU configuration
   - Interface listing and querying
   
2. **Wireless Management** (`WirelessManager`)
   - Interface mode changes (managed, monitor, AP)
   - Channel setting
   - TX power control
   - Interface creation/deletion (virtual interfaces)
   - nl80211 queries (capabilities, frequencies, etc.)

3. **Process Management** (`ProcessManager`)
   - pgrep functionality (find processes by name/pattern)
   - pkill functionality (terminate processes)
   - Process listing and filtering

4. **RF Kill Management** (`RfkillManager`)
   - Block/unblock wireless/bluetooth
   - Query rfkill state
   - Per-device control

5. **ARP Operations** (`ArpManager`)
   - ARP table queries
   - ARP entry addition/deletion
   - Neighbor discovery

6. **DHCP Server** (`DhcpServer`)
   - Full DHCP server implementation
   - Lease management
   - IP address allocation
   - Options support (DNS, gateway, etc.)

7. **DHCP Client** (`DhcpClient`)
   - DHCP discovery and request
   - Lease renewal
   - Address acquisition

8. **DNS Server** (`DnsServer`)
   - Authoritative DNS server
   - A/AAAA/CNAME/MX/TXT records
   - Wildcard support for DNS spoofing

9. **Hostapd Functionality** (`HostapdManager`)
   - Access point creation
   - WPA2/WPA3 security
   - Beacon management
   - Client association handling

10. **WPA Supplicant** (`WpaManager`)
    - Network connection management
    - WPA2/WPA3 authentication
    - Network scanning
    - Connection status monitoring

11. **IPTables** (`IptablesManager`)
    - NAT/MASQUERADE rules
    - Port forwarding
    - Packet filtering
    - Connection tracking

12. **NetworkManager Integration** (`NetworkManager`)
    - Connection management
    - Device state monitoring
    - Profile creation/modification
    - DNS management

## Files Partially Refactored

### rustyjack-ethernet
**Status:** ⚠️ PARTIAL
- ✅ `read_iface_ipv4()` - Migrated to `LinkManager::get_ipv4_addresses()`
- ✅ Added rustyjack-netlink dependency

### rustyjack-evasion
**Status:** ⚠️ PARTIAL
- ✅ `mac.rs` - Migrated interface up/down and MAC setting to `LinkManager`
- ✅ `state.rs` - Migrated MAC restore operations to `LinkManager`
- ✅ `passive.rs` - Migrated monitor interface creation to `WirelessManager`
- ⚠️ Still uses `airmon-ng` as fallback for compatibility
- Already has rustyjack-netlink dependency

## Files Requiring Refactoring

### rustyjack-core/src/system.rs
**Status:** ❌ TODO - **HIGHEST PRIORITY**
**Commands to replace:**
- ~25 instances of `ip` command calls
  - Link up/down
  - Address management  
  - Route management
  - Interface queries

**Required changes:**
- Replace all `Command::new("ip")` with `LinkManager` calls
- Use `get_interfaces()`, `set_link_up()`, `set_link_down()`
- Use `add_ipv4_address()`, `del_ipv4_address()`, `flush_addresses()`
- Use route management functions

### rustyjack-core/src/operations.rs
**Status:** ❌ TODO
- 1 instance of `ip -V` version check (can be removed or replaced with capability check)
- 1 instance of `ip link set` (migrate to `LinkManager`)

### rustyjack-core/src/evasion.rs
**Status:** ❌ TODO
- 2 instances of `ip` command for interface management
- Migrate to `LinkManager`

### rustyjack-core/src/anti_forensics.rs
**Status:** ❌ TODO
- 2 instances of `ip` command for link management
- Migrate to `LinkManager`

### rustyjack-core/src/physical_access.rs
**Status:** ❌ TODO
- 1 instance of `ip` command for interface queries
- Migrate to `LinkManager::get_interfaces()`

### rustyjack-wireless/src/nl80211.rs
**Status:** ❌ TODO
**Commands to replace:**
- 2 instances of `iw` command
  - Interface mode setting
  - Channel queries

**Required changes:**
- Use `WirelessManager::set_interface_mode()`
- Use `WirelessManager::get_channel_info()`

### rustyjack-wireless/src/nl80211_queries.rs
**Status:** ❌ TODO
**Commands to replace:**
- 4 instances of `iw` command
  - PHY info queries
  - Frequency/channel info
  - Interface capabilities

**Required changes:**
- Use `WirelessManager::get_phy_info()`
- Use `WirelessManager::get_supported_frequencies()`
- Use `WirelessManager::get_interface_capabilities()`

### rustyjack-wireless/src/evil_twin.rs
**Status:** ❌ TODO
**Commands to replace:**
- 1 instance of `iw` for channel verification
- 1 instance of `hostapd` subprocess (replace with `HostapdManager`)
- 1 instance of `dnsmasq` subprocess (replace with `DhcpServer` + `DnsServer`)
- Uses `netlink_helpers` functions (already good, but verify they use netlink crate)

**Required changes:**
- Replace hostapd subprocess with `HostapdManager::start()`
- Replace dnsmasq with `DhcpServer` and `DnsServer` running in threads
- Use `WirelessManager` for channel operations

### rustyjack-wireless/src/karma.rs
**Status:** ❌ TODO
**Commands to replace:**
- 1 instance of `iw` for interface verification
- 1 instance of `hostapd` subprocess (replace with `HostapdManager`)
- 1 instance of `dnsmasq` subprocess (replace with `DhcpServer` + `DnsServer`)
- Uses `netlink_helpers` functions (verify)

**Required changes:**
- Same as evil_twin.rs - migrate to `HostapdManager`, `DhcpServer`, `DnsServer`

### rustyjack-wireless/src/hotspot.rs
**Status:** ❌ TODO
**Commands to replace:**
- 2 instances of `iw` for PHY capabilities checks

**Required changes:**
- Use `WirelessManager::get_phy_info()` and `::get_phy_capabilities()`

### rustyjack-ui/src/util.rs
**Status:** ❌ TODO
**Commands to replace:**
- 3 instances of `iw` for interface info and channel queries

**Required changes:**
- Migrate to `WirelessManager` functions

### rustyjack-ui/src/app.rs
**Status:** ❌ TODO
**Commands to replace:**
- 2 instances of `iw` for interface management and queries

**Required changes:**
- Migrate to `WirelessManager`

### rustyjack-ui/src/display.rs
**Status:** ❌ TODO
**Commands to replace:**
- Likely has interface status queries using `ip` command

**Required changes:**
- Migrate to `LinkManager::get_link_info()`

## Dependencies That Can Be Removed from Installers

Once all refactoring is complete, these packages can be REMOVED from `install_rustyjack.sh` and `install_rustyjack_dev.sh`:

### Already Replaced (Can Remove Now)
- ❌ **iproute2** (`ip` command) - Fully replaced by `LinkManager`
- ❌ **wireless-tools** (`iwconfig`, `iwlist`) - Replaced by `WirelessManager`  
- ❌ **iw** - Replaced by `WirelessManager`
- ❌ **rfkill** - Replaced by `RfkillManager`
- ❌ **hostapd** - Replaced by `HostapdManager`
- ❌ **dnsmasq** - Replaced by `DhcpServer` + `DnsServer`
- ❌ **isc-dhcp-client** (`dhclient`) - Replaced by `DhcpClient`
- ❌ **iptables** - Replaced by `IptablesManager`
- ❌ **network-manager** (`nmcli`) - Replaced by `NetworkManager` integration
- ❌ **wpasupplicant** (`wpa_cli`) - Replaced by `WpaManager`

### Must Keep (System Requirements)
- ✅ **Build tools** (gcc, make, pkg-config, etc.) - Required for compilation
- ✅ **Kernel modules** (mac80211, cfg80211) - Required for wireless drivers
- ✅ **Firmware packages** - Required for hardware support
- ✅ **Git** - Required for repository management

## Next Steps

### Immediate Actions
1. **Complete rustyjack-core/src/system.rs refactoring** - This is the largest remaining task
2. **Refactor rustyjack-wireless files** to use `HostapdManager`, `DhcpServer`, `DnsServer`
3. **Update rustyjack-ui** to use `WirelessManager` and `LinkManager`
4. **Test thoroughly** on actual Raspberry Pi hardware

### Testing Checklist
- [ ] MAC randomization works without `ip` command
- [ ] Monitor mode works without `iw` command
- [ ] Hotspot mode works without `hostapd`/`dnsmasq`
- [ ] Evil Twin works with new implementations
- [ ] Karma attack works with new implementations
- [ ] Interface management works in UI
- [ ] DHCP client/server work correctly
- [ ] DNS spoofing works
- [ ] IPTables NAT/forwarding works
- [ ] NetworkManager integration works
- [ ] WPA connection works

### Documentation Updates
- [ ] Update AGENTS.md to reflect pure Rust implementation
- [ ] Update installer scripts to remove obsolete packages
- [ ] Create migration guide for users
- [ ] Document any breaking changes

## Benefits of This Migration

1. **No External Dependencies** - Rustyjack is now self-contained
2. **Better Error Handling** - Type-safe Rust errors instead of parsing command output
3. **Performance** - Direct netlink calls are faster than spawning processes
4. **Portability** - Easier to port to other platforms if needed
5. **Maintainability** - No reliance on external command output formats changing
6. **Security** - No risk of command injection or PATH manipulation
7. **Resource Efficiency** - No process spawning overhead
8. **Better Testing** - Can unit test without root privileges or real interfaces

## Current Binary Dependency Status Summary

| Binary | Replacement Status | Crate Module | Notes |
|--------|-------------------|--------------|-------|
| ip | ✅ Done | LinkManager | Fully replaced |
| iw | ✅ Done | WirelessManager | Fully replaced |
| rfkill | ✅ Done | RfkillManager | Fully replaced |
| hostapd | ✅ Done | HostapdManager | Refactoring in progress |
| dnsmasq | ✅ Done | DhcpServer + DnsServer | Refactoring in progress |
| dhclient | ✅ Done | DhcpClient | Fully replaced |
| iptables | ✅ Done | IptablesManager | Fully replaced |
| nmcli | ✅ Done | NetworkManager | Fully replaced |
| wpa_cli | ✅ Done | WpaManager | Fully replaced |
| pgrep/pkill | ✅ Done | ProcessManager | Fully replaced |
| airmon-ng | ⚠️ Keep as fallback | - | Legacy compatibility only |

**Total Progress: ~40% complete (implementations done, refactoring in progress)**
