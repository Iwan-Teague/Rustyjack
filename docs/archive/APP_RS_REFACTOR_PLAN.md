# app.rs Refactoring Plan

## Current State
- **Total Lines**: 9,303 lines
- **Location**: `rustyjack-ui/src/app.rs`
- **Problem**: Monolithic file containing all UI logic

## Analysis of Functions (by Category)

### 1. **WiFi Operations** (~1500 lines estimated)
Functions that handle WiFi scanning, connecting, profiles:
- `show_wifi_status()` - Display WiFi connection status
- `disconnect_wifi()` - Disconnect from WiFi
- `fetch_wifi_scan()` - Get WiFi scan results
- `fetch_wifi_profiles()` - Get saved profiles
- `fetch_wifi_interfaces()` - List wireless interfaces
- `fetch_wifi_status()` - Get detailed WiFi status
- `connect_profile_by_ssid()` - Connect to saved profile
- `connect_named_profile()` - Connect to network by name
- `delete_profile()` - Remove saved profile
- `scan_wifi_networks()` - Scan for networks
- `connect_known_network()` - Connect to known network
- `handle_network_selection()` - Handle user selecting a network
- `handle_profile_selection()` - Handle user selecting a profile
- `require_connected_wireless()` - Ensure WiFi is connected
- `choose_wifi_interface()` - Let user pick WiFi interface

**Recommendation**: Move to `rustyjack-ui/src/wifi_ui.rs`

### 2. **Wireless Attacks** (~2000 lines estimated)
Functions for deauth, Evil Twin, PMKID, handshake cracking:
- `launch_deauth_attack()` - Start deauth attack
- `launch_evil_twin()` - Start Evil Twin AP
- `launch_probe_sniff()` - Sniff probe requests
- `launch_pmkid_capture()` - Capture PMKID
- `launch_crack_handshake()` - Crack WPA handshakes
- `load_handshake_bundle()` - Load handshake for cracking
- `load_wordlist()` - Load password dictionary
- `count_wordlist()` - Count words in dictionary
- `available_dictionaries()` - List available wordlists
- `crack_handshake_with_progress()` - Crack with progress display
- Plus: Pipeline execution logic (multi-step attacks)

**Recommendation**: Move to `rustyjack-ui/src/wireless_attacks.rs`

### 3. **Ethernet/Network Operations** (~800 lines estimated)
Functions for LAN reconnaissance:
- `recon_gateway()` - Identify gateway
- `recon_arp_scan()` - ARP scan LAN
- `recon_service_scan()` - Port scan services
- `recon_mdns_scan()` - Discover mDNS devices
- `recon_bandwidth()` - Monitor bandwidth
- `recon_dns_capture()` - Capture DNS queries

**Recommendation**: Move to `rustyjack-ui/src/ethernet_ui.rs`

### 4. **MITM & DNS Spoof** (~600 lines estimated)
Functions for man-in-the-middle attacks:
- `start_dns_spoof()` - Start DNS spoofing
- `stop_dns_spoof()` - Stop DNS spoofing
- `start_responder()` - Start Responder
- `stop_responder()` - Stop Responder
- `launch_reverse_shell()` - Launch reverse shell
- MITM session management

**Recommendation**: Move to `rustyjack-ui/src/mitm_ui.rs`

### 5. **Autopilot** (~400 lines estimated)
Functions for automated attack sequences:
- `start_autopilot()` - Start autopilot mode
- `stop_autopilot()` - Stop autopilot
- `show_autopilot_status()` - Show status
- `autopilot_mode_label()` - Format mode name

**Recommendation**: Move to `rustyjack-ui/src/autopilot_ui.rs`

### 6. **Loot Management** (~600 lines estimated)
Functions for viewing/exporting captured data:
- `show_loot()` - Browse loot by section
- `show_network_loot()` - View network-specific loot
- `browse_loot_dir()` - Browse loot directory
- `view_loot_file()` - View individual loot file
- `scrollable_text_viewer()` - Paginated text viewer
- `discord_upload()` - Upload to Discord
- `transfer_to_usb()` - Export to USB drive
- `find_usb_mount()` - Find USB mount point
- `build_loot_archive()` - Create ZIP archive
- `add_directory_to_zip()` - Add files to ZIP

**Recommendation**: Move to `rustyjack-ui/src/loot_ui.rs`

### 7. **Hardware/Interface Management** (~500 lines estimated)
Functions for hardware detection and interface control:
- `show_hardware_detect()` - Hardware detection UI
- `choose_interface_name()` - Let user pick interface
- `choose_interface_prompt()` - Prompt for interface
- `ensure_route()` - Ensure default route
- `ensure_route_for_interface()` - Set route for specific interface
- `apply_interface_isolation()` - Isolate interfaces
- `is_ethernet_interface()` - Check if Ethernet
- `interface_has_carrier()` - Check link status
- `read_interface_mac()` - Read MAC address
- `fetch_route_snapshot()` - Get routing info

**Recommendation**: Move to `rustyjack-ui/src/hardware_ui.rs`

### 8. **System Operations** (~400 lines estimated)
Functions for system-level operations:
- `restart_system()` - Reboot device
- `secure_shutdown()` - Secure shutdown with RAM wipe
- `best_effort_ram_wipe()` - Wipe RAM
- `confirm_reboot()` - Reboot confirmation dialog
- Complete purge logic

**Recommendation**: Move to `rustyjack-ui/src/system_ui.rs`

### 9. **Configuration** (~300 lines estimated)
Functions for settings management:
- `reload_config()` - Reload configuration
- `save_config()` - Save configuration
- `pick_color()` - Color picker
- `apply_color()` - Apply color selection
- `toggle_logs()` - Enable/disable logging
- `apply_log_setting()` - Apply logging config
- `toggle_discord()` - Enable/disable Discord
- `tx_power_label()` - Format TX power
- MAC randomization settings

**Recommendation**: Move to `rustyjack-ui/src/settings_ui.rs`

### 10. **UI Primitives** (~400 lines estimated)
Generic UI helper functions:
- `show_message()` - Show message dialog
- `show_progress()` - Show progress indicator
- `execute_with_progress()` - Run operation with progress
- `choose_from_list()` - Generic list chooser
- `choose_from_menu()` - Generic menu chooser
- `prompt_octet()` - Input single byte
- `check_attack_cancel()` - Check if attack cancelled
- `confirm_cancel_attack()` - Cancel confirmation
- `dispatch_cancellable()` - Cancellable command dispatch

**Recommendation**: Move to `rustyjack-ui/src/dialogs.rs`

### 11. **Core App Structure** (~500 lines estimated)
Main app loop and state management:
- `App::new()` - Constructor
- `App::run()` - Main event loop
- `render_menu()` - Render current menu
- `execute_action()` - Execute menu action
- `status_overlay()` - Build status overlay
- `MenuState` impl (navigation)
- Button mapping
- Dashboard management

**Recommendation**: Keep in `app.rs` (reduced to ~800 lines)

### 12. **Response Types & Data Structures** (~200 lines)
Serde response types:
- `WifiNetworkEntry`
- `WifiScanResponse`
- `WifiProfileSummary`
- `WifiStatusOverview`
- `RouteSnapshot`
- `PipelineResult`
- `MitmSession`
- etc.

**Recommendation**: Move to `rustyjack-ui/src/types.rs`

### 13. **Helper Functions** (~300 lines)
Utility functions:
- `count_lines()` - Count file lines
- `renew_dhcp_and_reconnect()` - DHCP renewal
- `generate_vendor_aware_mac()` - Generate MAC
- `randomize_mac_with_reconnect()` - Randomize MAC
- `interface_has_ip()` - Check IP assigned
- `dir_has_files()` - Check directory not empty
- `shorten_for_display()` - Truncate strings
- `port_role()` - Get port description
- `port_weakness()` - Get port vulnerability info
- `interface_wiphy()` - Get wireless PHY
- `check_monitor_mode_support()` - Check monitor capability

**Recommendation**: Move to `rustyjack-ui/src/util.rs`

## Proposed New Structure

```
rustyjack-ui/src/
├── app.rs                    (~800 lines)  - Main app loop, menu rendering, state
├── types.rs                  (~200 lines)  - Response types, data structures
├── dialogs.rs                (~400 lines)  - Generic UI primitives
├── util.rs                   (~300 lines)  - Helper functions
├── settings_ui.rs            (~300 lines)  - Configuration/settings
├── system_ui.rs              (~400 lines)  - System operations
├── hardware_ui.rs            (~500 lines)  - Hardware/interface management
├── wifi_ui.rs                (~1500 lines) - WiFi operations
├── wireless_attacks.rs       (~2000 lines) - Wireless attacks & cracking
├── ethernet_ui.rs            (~800 lines)  - Ethernet/LAN recon
├── mitm_ui.rs                (~600 lines)  - MITM attacks
├── autopilot_ui.rs           (~400 lines)  - Autopilot mode
├── loot_ui.rs                (~600 lines)  - Loot viewing/export
├── display.rs                (existing)     - Display driver
├── menu.rs                   (existing)     - Menu definitions
├── config.rs                 (existing)     - Config types
├── stats.rs                  (existing)     - Stats collection
├── input.rs                  (existing)     - Input handling
├── core.rs                   (existing)     - Core bridge
└── main.rs                   (existing)     - Entry point
```

## Benefits

1. **Maintainability**: Each file has a single, clear purpose
2. **Navigation**: Easy to find where functionality lives
3. **Testability**: Smaller modules are easier to test
4. **Parallel Development**: Multiple developers can work simultaneously
5. **Compilation Speed**: Changes to one module don't recompile everything
6. **Code Reuse**: Helper functions centralized in `util.rs`

## Implementation Strategy

### Phase 1: Extract Helpers & Types (Low Risk)
1. Create `types.rs` - Move all response/data structs
2. Create `util.rs` - Move standalone helper functions
3. Update imports in `app.rs`
4. Test compilation

### Phase 2: Extract UI Primitives (Medium Risk)
1. Create `dialogs.rs` - Move generic UI functions
2. Update `app.rs` to use `dialogs::*`
3. Test all dialog flows

### Phase 3: Extract Feature Modules (Higher Risk, High Value)
1. Start with smallest: `autopilot_ui.rs`
2. Then: `settings_ui.rs`, `system_ui.rs`
3. Then: `hardware_ui.rs`, `loot_ui.rs`
4. Then: `mitm_ui.rs`, `ethernet_ui.rs`
5. Then: `wifi_ui.rs`, `wireless_attacks.rs` (largest)

### Phase 4: Final Cleanup
1. Review `app.rs` - should be ~800 lines
2. Add module documentation
3. Update AGENTS.md with new structure

## Safety Considerations

- Each extraction step should compile successfully
- Use `pub(crate)` instead of `pub` for internal APIs
- Keep `App` struct methods that need access to multiple subsystems
- Methods can be split: high-level logic in module, state access in App
- Use `impl App` blocks in separate files via `mod` if needed

## Estimated Impact

- **Before**: 9,303 lines in one file
- **After**: ~800 lines in app.rs + 13 focused modules
- **Largest Module**: wireless_attacks.rs (~2000 lines) - still 4.6x smaller than current
- **Average Module**: ~500 lines

## Open Questions

1. Should MAC randomization helpers move to `rustyjack-evasion` instead?
2. Should interface detection move to `rustyjack-core`?
3. Do we need a `hotspot_ui.rs` module? (Currently small, could be part of wifi_ui)
4. Should pipeline logic be in its own module? (Complex multi-step attack orchestration)
