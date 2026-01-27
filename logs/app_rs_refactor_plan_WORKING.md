# Refactor Plan: Decompose `src/app.rs` (rustyjack-ui)

**Target file:** `watchdog/crates/rustyjack-ui/src/app.rs`  
**Current size:** ~13,489 LOC (single-file “god module”)

This document is a *step-by-step refactor spec* for splitting `app.rs` into coherent Rust modules without changing runtime behavior.

## Non‑negotiable constraints

- **Rust-only.** No new shell scripts, `std::process::Command`, or “just call out to X”.
- **Refactor, not redesign.** Preserve behavior; changes should be structural and mechanical first.
- **Keep security posture at least as good.** Avoid accidental logging of secrets, keep `Zeroize` usage, etc.
- **Maintain Linux-only assumptions** as-is (UI is Linux-only already).

## Why we’re doing this

### Problem
`app.rs` currently mixes:
- UI event loop + rendering
- input mapping and dialog flows
- config persistence and feature toggles
- Wi-Fi profiles + attacks + pipelines + cracking UI
- USB mounting + archiving + log export
- encryption key management + FDE flows
- recon, ethernet ops, hotspot management
- report generation + file traversal
- error classification / preflight checks

### Where
Everything is in `src/app.rs` (~13,489 lines).

### Why it’s a problem
- **Cognitive load:** impossible to review safely; small edits risk collateral damage.
- **Unclear ownership:** unrelated changes collide in the same file.
- **Harder correctness:** borrow/lifetime issues get “solved” with bigger scopes and more shared mutable state.
- **Harder testing:** no obvious seam to unit test e.g. report generation vs USB mounting.

### How we fix it (high-level)
Split by responsibility into modules and files, re-export a stable surface from the module root.

### What “fixed” looks like
- `app.rs` becomes a thin module root (declarations + the public `App` surface).
- Each subsystem sits in its own file (or submodule tree) with small `impl App` blocks.
- Call sites and signatures remain stable; behavior is unchanged.
- Navigation: a developer can jump to `app/wifi.rs` for Wi-Fi, `app/usb.rs` for USB, etc.

---

# Target module layout

Keep `src/app.rs` as the module root and create a `src/app/` directory for submodules.

Proposed file tree:

```text
src/
  app.rs                 # thin root: mod declarations + pub re-exports
  app/
    state.rs             # App struct + shared enums/structs
    menu.rs              # render_menu + action dispatch
    dialogs.rs           # confirm/show/progress/choose UI flows
    settings.rs          # config + toggles (logs/discord/modes/tx-power label helpers)
    system.rs            # reboot/update/shutdown/ram-wipe
    loot.rs              # loot browser + viewer
    usb.rs               # USB listing/mounting + archive/log export
    encryption.rs        # key mgmt + encryption toggles + FDE flows
    recon.rs             # recon + dns spoof helpers
    ethernet.rs          # ethernet launch + mitm session helpers
    hotspot.rs           # hotspot management UI
    report.rs            # network report generation + summarizers
    iface_select.rs      # interface selection job + isolation flows
    error.rs             # errno parsing + AP error classification + hints
    preflight.rs         # preflight checks used by attacks/pipelines
    identity.rs          # MAC/hostname/modes/tx-power
    wifi.rs              # module root for wifi-related UI (profiles + attacks + pipeline + cracking)
    wifi/
      profiles.rs
      attacks.rs
      pipeline.rs
      crack.rs
```

---

# Refactor process (safe, incremental)

## Phase 0 — Guardrails (no code movement yet)

**Problem:** moving code around without a baseline invites accidental behavior changes.  
**Fix:** lock in a baseline.

- Run `cargo fmt`, `cargo clippy -p rustyjack-ui`, `cargo check -p rustyjack-ui` (and tests if any).
- Ensure `main.rs` only uses the public `App` surface (it does).
- Keep commits small: “move only” first.

**Fixed looks like:** baseline build is green; no behavior changes.

## Phase 1 — Extract shared types into `app/state.rs`

### Problem
Top-level type definitions and UI state live in the same file as 100+ methods.

### Where
- `INDEFINITE_SECS` (const, L73–L74)
- `App` (struct, L75–L89)
- `CancelDecision` (enum, L90–L95)
- `ConfirmChoice` (enum, L96–L103)
- `PipelineResult` (struct, L104–L113)
- `StepOutcome` (enum, L114–L119)
- `MitmSession` (struct, L120–L843)
- `MenuState` (struct, L844–L921)
- `ButtonAction` (enum, L922–L932)
- `UsbDevice` (struct, L933–L943)
- `UsbAccessRequirement` (enum, L944–L962)
- `MountEntry` (struct, L963–L12930)
- `StartApErrorHint` (struct, L12931–L13489)

### Why it’s a problem
Cross-cutting definitions buried alongside unrelated features makes it hard to:
- reason about invariants (`App` fields, menu selection rules)
- reuse helper structs across modules cleanly
- avoid circular imports later

### How to fix
1. Create `src/app/state.rs`.
2. Move the shared types/constants there.
3. In `src/app.rs`, add `mod state;` and `pub use state::App;`.
4. Tighten visibility: prefer `pub(crate)` unless it truly must be public.

### Fixed looks like
- `src/app.rs` contains mostly `mod` declarations + re-exports.
- Submodules can do `use super::state::*;`.

---

# Subsystem refactors (problem → where → why → how → fixed)

## 1) Core event loop + menu dispatch (`app/menu.rs`)

### Where (functions)
- `map_button` (L129–L142), `go_home` (L143–L159), `save_config_file` (L160–L165), `save_config_warn` (L166–L171), `confirm_yes_no` (L172–L212)
- `confirm_yes_no_bool` (L213–L223), `confirm_cancel` (L224–L235), `check_cancel_request` (L236–L246), `show_error_dialog` (L247–L259), `try_load_saved_key` (L260–L288)
- `ensure_saved_key_loaded` (L289–L310), `show_wifi_status` (L311–L361), `disconnect_wifi` (L362–L379), `ensure_route` (L380–L392), `require_connected_wireless` (L393–L447)
- `ensure_route_for_interface` (L448–L475), `status_overlay` (L476–L504), `ops_category_label` (L505–L520), `ops_enabled_in_overlay` (L521–L536), `ops_enabled_in_config` (L537–L552)
- `set_ops_config_value` (L553–L568), `read_interface_mac` (L569–L578), `interface_oper_state` (L579–L589), `interface_admin_up` (L590–L606), `interface_is_up` (L607–L610)
- `wait_for_interface_up` (L611–L621), `wait_for_interface_up_with_ip` (L622–L651), `interface_has_carrier` (L652–L664), `confirm_reboot` (L665–L706), `dispatch_cancellable` (L707–L851)
- `new` (L971–L1007), `current_id` (L859–L862), `path` (L863–L866), `enter` (L867–L872), `back` (L873–L880)
- `move_up` (L881–L898), `move_down` (L899–L912), `home` (L913–L949), `mount_mode` (L950–L955), `needs_write` (L956–L970)
- `new` (L971–L1007), `run` (L1008–L1067), `render_menu` (L1068–L1238), `execute_action` (L1239–L1327), `run_operation` (L1328–L1346)
- `simple_command` (L1347–L1354), `show_message` (L1355–L1413), `show_progress` (L1414–L1428), `execute_with_progress` (L1429–L1436)

### How to fix
Create `src/app/menu.rs` and move:
- `App::run` loop logic
- `render_menu`
- `execute_action`

Keep domain behavior in domain modules; `execute_action` dispatches.

### Fixed looks like
Menu UI logic is isolated; feature modules own their own flows.

---

## 2) Dialogs, prompts, progress UI (`app/dialogs.rs`)

### Where
Mostly in these spans:
- prompts: - `choose_from_list` (L2118–L2124), `choose_from_menu` (L2125–L2175), `prompt_octet` (L2176–L2203)
- plus scattered dialog helpers in the core span.

### How to fix
Create `src/app/dialogs.rs` and move all modal helpers:
- confirm / cancel dialogs
- selection prompts
- progress and scrolling viewers

### Fixed looks like
All modal UI patterns are consistent and centralized.

---

## 3) Settings & feature toggles (`app/settings.rs`)

### Where (functions)
- `reload_config` (L1437–L1442), `save_config` (L1443–L1447), `pick_color` (L1448–L1469), `apply_color` (L1470–L1483), `apply_log_setting` (L1484–L1491)
- `sync_log_env` (L1492–L1499), `toggle_logs` (L1500–L1512), `tx_power_label` (L1513–L1522)

### How to fix
Move config reload/save and all toggles here (logs, colors, env sync, etc.).

### Fixed looks like
Config changes are centralized, easy to audit.

---

## 4) Loot browsing & viewing (`app/loot.rs`)

### Where (functions)
- `show_loot` (L1523–L1629), `show_network_loot` (L1630–L1639), `browse_loot_dir` (L1640–L1699), `view_loot_file` (L1700–L1802), `scrollable_text_viewer` (L1803–L1879)

### How to fix
Move loot browsing + file viewing here. Keep traversal helpers loot-scoped.

### Fixed looks like
Loot UX is isolated, and file IO doesn’t leak into unrelated features.

---

## 5) System power/update flows (`app/system.rs`)

### Where (functions)
- `restart_system` (L1880–L1889), `system_update` (L1890–L1949), `run_update_job` (L1950–L2040), `secure_shutdown` (L2041–L2079), `best_effort_ram_wipe` (L2080–L2117)

### How to fix
Move reboot/update/shutdown/ram-wipe flows here. Use dialogs from `dialogs.rs`.

### Fixed looks like
High-impact actions live in one module for careful review.

---

## 6) Wi‑Fi profiles + import (`app/wifi/profiles.rs`)

### Where (functions)
Wi-Fi profile region:
- `handle_network_selection` (L2204–L2293), `handle_profile_selection` (L2294–L2310), `fetch_wifi_scan` (L2311–L2325), `fetch_wifi_profiles` (L2326–L2343), `manage_saved_networks` (L2344–L2386)
- `view_profile_password` (L2387–L2426), `read_webhook_url` (L2427–L2466), `webhook_encryption_active` (L2467–L2470), `loot_encryption_active` (L2471–L2474), `wifi_encryption_active` (L2475–L2480)
- `ensure_wifi_key_loaded` (L2481–L2489), `attempt_profile_connection` (L2490–L2552), `fetch_wifi_interfaces` (L2553–L2557), `fetch_route_snapshot` (L2558–L2565), `fetch_wifi_status` (L2566–L2576)
- `connect_profile_by_ssid` (L2577–L2584), `connect_named_profile` (L2585–L2626), `delete_profile` (L2627–L2655), `import_wifi_from_usb` (L2656–L2729)

Discord/webhook import region:
- `discord_upload` (L2730–L2782), `import_webhook_from_usb` (L2783–L2873)

### How to fix
Create `src/app/wifi.rs` + `src/app/wifi/profiles.rs` and move:
- scan/profile selection/connect/delete
- password viewing
- import-from-USB for wifi configs

Webhook/discord flows should move to `settings.rs` or a new `discord.rs` if they keep growing.

### Fixed looks like
Wi‑Fi profile UX is cohesive; discord/webhook logic doesn’t pollute Wi‑Fi state machines.

---

## 7) Wi‑Fi attacks, pipelines, cracking UI (`app/wifi/attacks.rs`, `pipeline.rs`, `crack.rs`)

### Where (functions)
- `scan_wifi_networks` (L5394–L5512), `launch_deauth_attack` (L5513–L5651), `connect_known_network` (L5652–L5714), `launch_evil_twin` (L5715–L5872), `launch_probe_sniff` (L5873–L5967)
- `launch_pmkid_capture` (L5968–L6073), `launch_crack_handshake` (L6074–L6105), `scan_dir` (L6106–L6201), `load_handshake_bundle` (L6202–L6210), `load_wordlist` (L6211–L6226)
- `count_wordlist` (L6227–L6243), `available_dictionaries` (L6244–L6273), `crack_handshake_with_progress` (L6274–L6441), `draw_crack_progress` (L6442–L6468), `install_wifi_drivers` (L6469–L6589)
- `launch_karma_attack` (L6590–L6716), `launch_attack_pipeline` (L6717–L6959), `prepare_pipeline_loot_dir` (L6960–L6973), `pipeline_target_dir` (L6974–L6986), `sanitize_target_name` (L6987–L7003)
- `capture_pipeline_loot` (L7004–L7063), `execute_pipeline_steps` (L7064–L7256), `execute_get_password_step` (L7257–L7423), `execute_mass_capture_step` (L7424–L7512), `execute_stealth_recon_step` (L7513–L7604)
- `execute_credential_harvest_step` (L7605–L7708), `execute_full_pentest_step` (L7709–L7899)

### How to fix
Split into:
- `wifi/attacks.rs`: scan + attack launchers
- `wifi/pipeline.rs`: pipeline orchestration + step executors
- `wifi/crack.rs`: cracking UX + wordlists + progress render

### Rust-only constraint note
`install_wifi_drivers` references `scripts/wifi_driver_installer.sh` and uses `SystemCommand::InstallWifiDrivers`.
For the refactor: move unchanged into `wifi/attacks.rs`.
After the move: replace with a Rust-native approach (or remove the action) to meet “no shell / no third-party binaries”.

### Fixed looks like
Attacks, pipeline orchestration, and cracking each have a single owner module.

---

## 8) Identity hardening / MAC & hostname / modes (`app/identity.rs`)

### Where (functions)
- `toggle_mac_randomization` (L7929–L7967), `toggle_per_network_mac` (L7968–L8010), `toggle_hostname_randomization` (L8011–L8052), `randomize_hostname_now` (L8053–L8077), `select_operation_mode` (L8078–L8130)
- `apply_operation_mode` (L8131–L8176), `mode_display_name` (L8177–L8180), `mode_display` (L8181–L8190), `mode_allows_active` (L8191–L8206), `bump_to_custom` (L8207–L8215)
- `apply_identity_hardening` (L8216–L8265), `apply_per_network_mac` (L8266–L8410), `toggle_passive_mode` (L8411–L8451), `toggle_ops` (L8452–L8482), `launch_passive_recon` (L8483–L8555)
- `randomize_mac_now` (L8556–L8705), `set_vendor_mac` (L8706–L8807), `restore_mac` (L8808–L8893), `set_tx_power` (L8894–L8964)

### How to fix
Move MAC randomization, hostname randomization, op mode selection, tx-power into `identity.rs`.

### Fixed looks like
Identity behavior is reviewable as a coherent unit.

---

## 9) Recon + DNS spoof control (`app/recon.rs`)

### Where (functions)
- `toggle_dns_spoof` (L4613–L4623), `recon_gateway` (L4624–L4711), `recon_arp_scan` (L4712–L4822), `recon_service_scan` (L4823–L4931), `recon_mdns_scan` (L4932–L5032)
- `recon_bandwidth` (L5033–L5136), `recon_dns_capture` (L5137–L5246), `start_dns_spoof` (L5247–L5308), `stop_dns_spoof` (L5309–L5318), `launch_reverse_shell` (L5319–L5393)

### How to fix
Move recon helpers + DNS spoof start/stop here.

### Fixed looks like
Recon flows are centralized.

---

## 10) Ethernet ops + MITM session (`app/ethernet.rs`)

### Where (functions)
- `launch_ethernet_discovery` (L8965–L9088), `launch_ethernet_port_scan` (L9089–L9235), `launch_ethernet_inventory` (L9236–L9310), `launch_ethernet_mitm` (L9311–L9514), `stop_ethernet_mitm` (L9515–L9539)
- `launch_ethernet_site_cred_capture` (L9540–L9722), `list_dnsspoof_sites` (L9723–L9739), `begin_mitm_session` (L9740–L9757), `show_mitm_status` (L9758–L9833), `build_network_report` (L9834–L9875)

### How to fix
Move ethernet discovery/scans/mitm session helpers into `ethernet.rs`.

### Fixed looks like
Ethernet UX is isolated and doesn’t collide with reporting.

---

## 11) Report generation (`app/report.rs`)

### Where (functions)
- `collect_network_names` (L9876–L9894), `format_system_time` (L9895–L9899), `format_size_short` (L9900–L9909), `safe_count_lines_limited` (L9910–L9919), `summarize_json_file` (L9920–L9952)
- `classify_artifact_kind` (L9953–L9986), `extract_pipeline_run` (L9987–L10001), `build_artifact_item` (L10002–L10073), `summarize_counts` (L10074–L10084), `format_pipeline_lines` (L10085–L10125)
- `format_artifact_details` (L10126–L10171), `traverse_loot_dir` (L10172–L10218), `service_risk_notes` (L10219–L10268), `append_artifact_section` (L10269–L10322), `generate_network_report` (L10323–L10393)
- `append_eth_report` (L10394–L10505), `append_wifi_report` (L10506–L10578), `append_mac_usage` (L10579–L10599), `append_combined_impact` (L10600–L10723), `summarize_payload_activity` (L10724–L10751)
- `count_bridge_pcaps` (L10752–L10783), `summarize_mac_usage` (L10784–L10817), `mac_usage_count` (L10818–L10835), `read_inventory_summary` (L10836–L10897), `summarize_port_scans` (L10898–L10952)
- `parse_portscan_file` (L10953–L10983), `collect_portscan_candidates` (L10984–L11015), `summarize_discovery` (L11016–L11060), `count_discovery_hosts` (L11061–L11086), `summarize_mitm` (L11087–L11131)
- `summarize_credentials` (L11132–L11235), `count_handshake_files` (L11236–L11256), `choose_dnsspoof_site` (L11257–L11272), `browse_inventory` (L11273–L11355)

### How to fix
Move report building/traversal/summarization into `report.rs`.
Recommended: internally split into `model/collect/render` submodules to keep pure functions testable.

### Fixed looks like
Report code can be unit-tested with fixture dirs; App just calls it.

---

## 12) USB device flows + archiving (`app/usb.rs`)

### Where (functions)
- `export_logs_to_usb` (L3795–L3853), `select_usb_partition` (L3854–L3894), `transfer_to_usb` (L3895–L3967), `browse_usb_for_file` (L3968–L4098), `select_usb_mount` (L4099–L4119)
- `find_mount_for_device` (L4120–L4142), `mount_usb_device` (L4143–L4212), `read_mount_points` (L4213–L4235), `decode_proc_mount` (L4236–L4243), `mount_entry_for` (L4244–L4250)
- `mount_options_for` (L4251–L4255), `is_readable_mount` (L4256–L4264), `mount_access_ok` (L4265–L4271), `is_writable_mount` (L4272–L4277), `build_loot_archive` (L4278–L4299)
- `add_directory_to_zip` (L4300–L4340)

### How to fix
Move USB discovery/mount/transfer/zip building helpers into `usb.rs`.

### Fixed looks like
USB mounting and archiving is isolated and safer to audit.

---

## 13) Encryption & key management (`app/encryption.rs`)

### Where (functions)
- `parse_key_file` (L2874–L2903), `load_encryption_key_from_usb` (L2904–L2939), `encrypt_loot_file_in_place` (L2940–L2965), `generate_encryption_key_on_usb` (L2966–L3028), `toggle_encryption_master` (L3029–L3087)
- `ensure_keyfile_available` (L3088–L3141), `list_usb_devices` (L3142–L3170), `list_usb_partitions` (L3171–L3178), `list_usb_disks` (L3179–L3188), `disable_all_encryptions` (L3189–L3263)
- `toggle_encrypt_wifi_profiles` (L3264–L3267), `set_wifi_encryption` (L3268–L3402), `toggle_encrypt_loot` (L3403–L3406), `set_loot_encryption` (L3407–L3574), `toggle_encrypt_webhook` (L3575–L3580)
- `start_full_disk_encryption_flow` (L3581–L3643), `start_fde_migration` (L3644–L3655), `run_usb_prepare` (L3656–L3692), `run_fde_migrate` (L3693–L3733), `set_webhook_encryption` (L3734–L3794)

### How to fix
Move all encryption toggles, key parsing, key load/generate, and FDE flows into `encryption.rs`.
Audit for secret leakage during the move (avoid accidental `Debug` prints of keys, preserve `Zeroize`).

### Fixed looks like
Secrets-handling logic is localized and reviewable.

---

## 14) Hotspot management + purge (`app/hotspot.rs` + `app/purge.rs` or `system.rs`)

### Where (functions)
- `complete_purge` (L11356–L11440), `purge_logs` (L11441–L11489), `is_log_file` (L11490–L11505), `is_log_basename` (L11506–L11527), `manage_hotspot` (L11528–L12011)
- `list_wifi_interfaces` (L12012–L12025), `interface_has_ip` (L12026–L12031), `monitor_mode_supported` (L12032–L12046), `resolve_hotspot_interface` (L12047–L12070), `select_hotspot_channel` (L12071–L12118)
- `show_hotspot_diagnostics` (L12119–L12205), `show_hotspot_network_info` (L12206–L12240), `show_hotspot_connected_devices` (L12241–L12424), `show_hotspot_network_speed` (L12425–L12513), `manage_hotspot_blacklist` (L12514–L12562)
- `add_to_hotspot_blacklist` (L12563–L12609), `remove_from_hotspot_blacklist` (L12610–L12632), `disconnect_hotspot_client` (L12633–L12653), `apply_hotspot_blacklist` (L12654–L12672)

### How to fix
Move hotspot UX into `hotspot.rs`.
Move destructive purge flows into `system.rs` or a new `purge.rs` so they’re not buried.

### Fixed looks like
Hotspot UX and purge actions are clearly separated.

---

## 15) Interface selection & isolation job (`app/iface_select.rs`)

### Where (functions)
- `run_interface_selection_job` (L12673–L12780), `render_interface_selection_success` (L12781–L12821), `select_active_interface` (L12822–L12893), `view_interface_status` (L12894–L12917)

### How to fix
Move job polling/cancel/selection helpers into `iface_select.rs`.

### Fixed looks like
Isolation flows are owned in one place; cancellation logic is easy to audit.

---

## 16) Error helpers + preflight checks (`app/error.rs`, `app/preflight.rs`)

### Where (functions)
- `format_bytes_per_sec` (L12918–L12934), `extract_errno` (L12935–L12954), `classify_start_ap_error` (L12955–L13008), `mac_error_hint` (L13009–L13027), `preflight_wireless_scan` (L13028–L13058)
- `preflight_deauth_attack` (L13059–L13107), `preflight_evil_twin` (L13108–L13162), `preflight_hotspot` (L13163–L13244), `preflight_karma` (L13245–L13287), `preflight_handshake_capture` (L13288–L13336)
- `preflight_pmkid_capture` (L13337–L13360), `preflight_probe_sniff` (L13361–L13396), `preflight_ethernet_operation` (L13397–L13436), `preflight_mitm` (L13437–L13474), `show_preflight_error` (L13475–L13480)
- `preflight_or_skip` (L13481–L13489)

### How to fix
Move:
- errno/AP hint helpers into `error.rs`
- all `preflight_*` and UI wrappers into `preflight.rs`

### Fixed looks like
Preflight is single-source-of-truth and consistently applied.

---

# Cross-cutting refactors after the move (expected)

- **Imports & visibility:** narrow imports in each module; keep helpers `pub(crate)` unless needed.
- **Avoid circular deps:** if a helper is used everywhere, it belongs in `state.rs` or `dialogs.rs`, or a small pure helper module.
- **Borrow pressure:** splitting files often reveals long-lived borrows; shorten borrow scopes, use owned values, or small context structs.
- **Behavior stability:** do not change command payloads or message strings during the mechanical move.

---

# Appendix: Minimal `src/app.rs` after refactor (shape)

```rust
// src/app.rs
pub mod app {
    pub mod state;
    pub mod menu;
    pub mod dialogs;
    pub mod settings;
    pub mod system;
    pub mod loot;
    pub mod usb;
    pub mod encryption;
    pub mod recon;
    pub mod ethernet;
    pub mod hotspot;
    pub mod report;
    pub mod iface_select;
    pub mod error;
    pub mod preflight;
    pub mod identity;
    pub mod wifi;

    pub use state::App;
}
```

(Practically: declare modules directly in `src/app.rs`, then `pub use state::App;`.)

---

Make the split painless by keeping commits mechanical:
**create module → move code → fix imports → `cargo check` → next chunk**.
