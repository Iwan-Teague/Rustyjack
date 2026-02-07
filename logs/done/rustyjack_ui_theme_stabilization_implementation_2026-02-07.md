# RustyJack UI Theme Stabilization Implementation
Date: 2026-02-07
Scope: Implement fixes from `logs/rustyjack_ui_theme_deep_dive_2026-02-07.md`

## Baseline (before changes)
- `Settings -> Colors` updated runtime palette but did not persist immediately to `gui_conf.json`.
- Theme roles exposed in menu were incomplete (`Border` used by rendering but not editable).
- Startup/splash rendering used hard-coded colors (`Rgb565::BLACK`, hard-coded purple fallback text), bypassing configured theme.
- `GuiConfig::load` did not normalize color values, so invalid/dirty hex values silently fell back in rendering paths.
- `ColorScheme` contained unused fields (`gamepad`, `gamepad_fill`) with no runtime usage.

## Baseline test execution
- Command: `cargo test -p rustyjack-ui`
- Result: failed due offline/network index resolution (`index.crates.io` unavailable in sandbox).
- Command: `cargo test -p rustyjack-ui --offline`
- Result: failed due missing cached crates (`tar` not found in local offline index).

## Problem-to-Implementation Checklist

### Problem 1: Persistence and save reliability
- Files/functions:
  - `crates/rustyjack-ui/src/config.rs`
    - `GuiConfig::save` (atomic temp-write + fsync + rename)
    - `GuiConfig::mutate_theme_and_persist` (shared mutate+normalize+persist helper)
  - `crates/rustyjack-ui/src/app/settings.rs`
    - `mutate_theme_config_and_refresh`
    - `show_theme_update_result`
    - `pick_color`
- Expected behavior:
  - Color updates persist immediately.
  - Save path is crash/corruption-resistant.
  - UI reports `Saved` or `Save failed` explicitly.
- Risks/edges:
  - Save failure still leaves in-memory palette changed for current session.
- Tests:
  - `config.rs`: `mutate_theme_and_persist_saves_normalized_colors`.

### Problem 3: Remove theme bypass in rendering
- Files/functions:
  - `crates/rustyjack-ui/src/display.rs`
    - `Display::new` (theme background used for initial clear)
    - `Display::show_splash_screen` (theme background + theme text fallback)
- Expected behavior:
  - No startup/splash hard-coded black/purple for themed UI paths.
- Risks/edges:
  - Diagnostic rendering paths intentionally retain hard-coded colors.
- Tests:
  - Manual verification checklist item added.

### Problem 2: Coverage completion + dead fields
- Files/functions:
  - `crates/rustyjack-ui/src/menu.rs`
    - `ColorTarget` centralized mapping (`ALL`, `label`, `get`, `set`)
    - `colors_menu` data-driven entries + `Apply Preset`
  - `crates/rustyjack-ui/src/config.rs`
    - Removed unused `ColorScheme` fields: `gamepad`, `gamepad_fill`
- Expected behavior:
  - All active palette roles are editable through one shared flow.
  - No dead color fields in persisted schema.
- Risks/edges:
  - Old `gui_conf.json` may still contain removed keys; serde ignores unknown fields safely.
- Tests:
  - `menu.rs`: `colors_menu_exposes_all_theme_roles_and_preset_entry`.

### Problem 4: Normalize/validate colors on load
- Files/functions:
  - `crates/rustyjack-ui/src/config.rs`
    - `ColorScheme::normalize`
    - `normalize_hex`, `normalize_hex_field`
    - `GuiConfig::load` uses shared mutate helper for load-time repair save
  - `crates/rustyjack-ui/src/app/menu.rs`
    - startup one-time message if theme config repaired
  - `crates/rustyjack-ui/src/app/settings.rs`
    - reload message includes repair notice
- Expected behavior:
  - Invalid/dirty values are repaired to safe defaults, normalized to `#RRGGBB` uppercase.
  - Repairs are persisted.
  - User is informed once on startup/reload.
- Risks/edges:
  - Strict hex enforcement rejects non-6-digit forms by design.
- Tests:
  - `config.rs`: `color_scheme_normalize_repairs_invalid_values`.

### Problem 5: Presets + contrast guardrails
- Files/functions:
  - `crates/rustyjack-ui/src/config.rs`
    - `ThemePreset` enum + `apply`
    - contrast math (`contrast_ratio_hex`, luminance helpers)
    - `ColorScheme::contrast_warnings`
  - `crates/rustyjack-ui/src/app/settings.rs`
    - `apply_theme_preset`
    - contrast warnings in shared post-update message flow
  - `crates/rustyjack-ui/src/menu.rs`
    - `MenuAction::ApplyThemePreset`, Colors menu entry
  - `docs/ui_action_map.md`
    - Added `ApplyThemePreset` routing
- Expected behavior:
  - User can apply coherent presets and still override per-role colors.
  - Low contrast combinations are warned (non-blocking).
- Risks/edges:
  - WCAG-style contrast warning threshold may be conservative for tiny LCD use-cases.
- Tests:
  - `config.rs`: `contrast_ratio_hex_reports_expected_ordering`.

## Files changed
- `crates/rustyjack-ui/src/config.rs`
- `crates/rustyjack-ui/src/display.rs`
- `crates/rustyjack-ui/src/menu.rs`
- `crates/rustyjack-ui/src/app/settings.rs`
- `crates/rustyjack-ui/src/app/menu.rs`
- `docs/ui_action_map.md`

## Post-change test execution
- Command: `cargo test -p rustyjack-ui`
  - Failed: crates index unreachable (`index.crates.io` DNS resolution in sandbox).
- Command: `cargo test -p rustyjack-ui --offline`
  - Failed: required crate cache unavailable (`tar` missing).

## Manual verification checklist
- [ ] Change `Background/Text/Border/Selected Text/Selected BG/Toolbar` under `Settings -> Colors` and confirm immediate redraw.
- [ ] Confirm each color edit shows explicit save status (`Saved` or `Save failed`).
- [ ] Reboot/restart UI and verify selected colors persist.
- [ ] Verify splash startup clear and text fallback respect configured theme colors.
- [ ] Inject invalid values into `gui_conf.json` colors, restart UI, verify automatic repair + warning message.
- [ ] Apply each preset and verify resulting palette is coherent.
- [ ] Confirm contrast warnings appear for intentionally low-contrast combinations.
- [ ] Confirm no remaining unused color fields in active schema (`gamepad*` removed).

## Migration note (`gui_conf.json`)
- Removed color fields: `colors.gamepad`, `colors.gamepad_fill`.
- Backward compatibility:
  - Old configs containing these keys still load (unknown keys ignored by serde).
  - Newly saved configs omit these removed keys.
- Color normalization now enforces uppercase `#RRGGBB`; malformed values are repaired to defaults.
