# Dynamic Display Resolution Blueprint (RustyJack UI)

## Objective
Enable `rustyjack-ui` to use the full available display area at runtime across supported screens (from 128x128 ST7735 up to larger Pi-attached displays, e.g. <= 480p) without hardcoded pixel assumptions.

The 8-button hardware input model remains fixed and mandatory.

Support policy:
- `128x128` is the baseline and lowest **supported** layout target.
- Displays smaller than `128x128` are allowed to run in best-effort mode (no startup block), but are explicitly unsupported.
- Unsupported-size runs should emit a clear warning in logs/UI diagnostics.

## Current State (What Blocks Dynamic Resolution)

Hardcoded layout/geometry is spread across the UI:

- Fixed panel dimensions in `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/display.rs`
  - `LCD_WIDTH`, `LCD_HEIGHT`
  - Many fixed `Point::new(x, y)` and `Size::new(w, h)` values
- Fixed visible line counts in:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/display.rs` (`DIALOG_VISIBLE_LINES`)
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/ui/layout.rs` (`MENU_VISIBLE_ITEMS`)
- Multiple modules depend on those fixed constants for pagination and scrolling:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/menu.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/state.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/ui/screens/mod.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/settings.rs`

Input path is already fixed to exactly eight buttons in `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/input.rs`, which is good and should stay fixed.

## Target Architecture

## 1) Add Runtime Display Capabilities
Create a runtime `DisplayCapabilities` struct and propagate it through rendering/layout.

Suggested fields:
- `width_px: u32`
- `height_px: u32`
- `orientation: Landscape|Portrait`
- `backend: st7735|framebuffer|drm` (or equivalent)
- `safe_padding_px: u32` (for edge clipping tolerance)

Startup flow rule (single generic path):
1. Detect backend.
2. Query capabilities from backend.
3. If geometry is unverified for that backend, run calibration fallback.
4. Cache resulting effective geometry and reuse it on subsequent boots.

## 2) Add a Layout Engine (No UI Constants for Geometry)
Replace fixed geometry constants with computed layout metrics based on capabilities.

Create e.g. `UiLayoutMetrics`:
- `header_height`
- `content_top`
- `content_bottom`
- `line_height`
- `menu_visible_items`
- `dialog_visible_lines`
- `footer_y`
- `text_max_chars`

All draw functions and pagination logic consume this struct instead of constants.

## 2.1) Text Fit, Wrap, and Cutoff Rules (Required)
The dynamic layout must include a text measurement/wrapping policy so content never renders outside visible bounds.

Implementation requirements:
- Compute `chars_per_line` from runtime content width and active font metrics (do not hardcode 18/20/21-char limits).
- Use word-wrap by default; hard-wrap long tokens that exceed line width.
- For single-line labels (menu rows, toolbar title), ellipsize with `...` when needed.
- For multi-line regions (dialogs, dashboards, file viewer), paginate using runtime `visible_lines` from `UiLayoutMetrics`.
- Clip all draw calls to content rectangles so no glyphs bleed into footer/header or off-screen.
- Keep current semantics for navigation hints, but place them using runtime footer geometry.

Affected code paths include:
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/display.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/util.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/loot.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/menu.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/ui/screens/mod.rs`

## 3) Separate Rendering Backend from Layout
Refactor `Display` to support backend-specific device initialization while keeping shared drawing/layout logic.

Recommended split:
- `display/mod.rs`: high-level API + shared drawing methods
- `display/backend/st7735.rs`: SPI ST7735 init + offset handling
- `display/backend/fbdev.rs` (or DRM): runtime mode query for larger screens

Notes:
- ST7735 does not truly self-report visible geometry reliably via current crate flow; keep explicit defaults + config override.
- fbdev/DRM backends can query runtime resolution directly.

## 3.1) Resolution Discovery and Verification Strategy
Use backend-specific detection rules instead of assuming all displays are queryable the same way.

ST7735 SPI backend:
- Geometry is often board/profile-driven (visible window + offsets), not reliably discoverable from controller reads alone.
- If hardware routing supports `MISO` readback, use it for verification signals (controller identity/config/orientation checks), not as sole source of visible-size truth.
- Keep profile defaults + user calibration + overrides as the authoritative geometry path.

Larger display backend (Pi 5 candidate, HDMI/DSI/DRM/fb):
- Query active mode (`width/height`) from DRM/fb at runtime.
- Verify active mode after init and on mode changes.
- If backend-reported mode conflicts with explicit override, log warning and apply precedence rules.

Verification requirements:
- On startup, log: backend, detected mode, effective mode, offsets, calibration state.
- Add explicit warning classes:
  - `DISPLAY_MODE_MISMATCH`
  - `DISPLAY_UNVERIFIED_GEOMETRY`
  - `UNSUPPORTED_DISPLAY_SIZE`

Boot behavior requirement:
- Do not rerun full discovery/calibration flows every boot once they are marked complete.
- Use cached effective geometry unless user explicitly triggers re-run from Settings > Display.

## 4) Add Explicit Resolution Overrides
Support config/env overrides for edge cases:
- `RUSTYJACK_DISPLAY_WIDTH`
- `RUSTYJACK_DISPLAY_HEIGHT`
- Existing: `RUSTYJACK_DISPLAY_ROTATION`
- Existing/added offset tuning: `RUSTYJACK_DISPLAY_OFFSET_X`, `RUSTYJACK_DISPLAY_OFFSET_Y`

Precedence:
1. Explicit env/config override
2. Backend-detected mode
3. Backend default profile

## 4.1) Display Calibration Workflow (User-Driven Edge Capture)
Add a guided calibration mode to capture true visible borders and eliminate cutoff/wasted area.

Calibration model:
- Calibrate four edges in sequence: `LEFT`, `TOP`, `RIGHT`, `BOTTOM`.
- For each edge, render a high-contrast reference line and dim overlay outside the candidate boundary.
- User adjusts line position with DPAD and confirms with Select.

Suggested controls (keeps 8-button model unchanged):
- Vertical edge steps (`LEFT`, `RIGHT` calibration):
  - `LEFT/RIGHT`: nudge boundary by 1 px
- Horizontal edge steps (`TOP`, `BOTTOM` calibration):
  - `UP/DOWN`: nudge boundary by 1 px
- `SELECT` (center press): confirm current edge and move to next edge
- `KEY2` or `LEFT` from prompt screen: cancel calibration and keep previous values
- `KEY1`: reset current edge to default profile value

Edge-specific behavior:
- `LEFT` step: use only `LEFT/RIGHT` to move vertical line until it sits exactly on visible left edge.
- `TOP` step: use only `UP/DOWN` to move horizontal line until it sits exactly on visible top edge.
- `RIGHT` step: use only `LEFT/RIGHT` to move vertical line for right edge.
- `BOTTOM` step: use only `UP/DOWN` to move horizontal line for bottom edge.

Persisted output (e.g. in `gui_conf.json` display section):
- `calibrated_left`
- `calibrated_top`
- `calibrated_right`
- `calibrated_bottom`
- `calibration_version`
- `last_calibrated_at`
- `display_probe_completed` (bool)
- `display_calibration_completed` (bool)
- `display_geometry_source` (`override|detected|calibrated`)
- `effective_width`
- `effective_height`
- `effective_offset_x`
- `effective_offset_y`
- `effective_backend`
- `effective_rotation`
- `display_profile_fingerprint` (string; backend + mode + key params)
- `display_tests_version` (schema/version of discovery+calibration logic)

Derived effective geometry:
- `effective_width = calibrated_right - calibrated_left + 1`
- `effective_height = calibrated_bottom - calibrated_top + 1`
- Runtime layout must use effective geometry, not raw panel defaults.

Persistence and rerun policy:
- On first run:
  - Run backend detection/query.
  - Run calibration only if backend geometry is unverified.
  - Persist effective values and set completion flags.
- On normal boot:
  - If `display_probe_completed=true` and `display_calibration_completed=true` (when required), skip recalculation.
  - Load cached effective values directly.
- Recalculation triggers (manual only):
  - User selects `Run Display Discovery` or `Run Display Calibration` in Settings > Display.
  - User selects `Reset Display Calibration/Display Cache`.
- Optional safety behavior:
  - If current backend/mode fingerprint differs from `display_profile_fingerprint`, warn and offer re-run, but do not force recalculation.

## 5) Keep 8 Buttons Constant (Hard Requirement)
No change to button count or semantics.

Enforce with:
- `const BUTTON_COUNT: usize = 8` in input layer
- Startup invariant check: all 8 pins configured and readable
- Fail fast with clear error if any button mapping is missing

Buttons remain:
- Up, Down, Left, Right, Select, Key1, Key2, Key3

## Project-Wide Implementation Tasks

## A) `rustyjack-ui` code changes

### Core rendering/layout
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/display.rs`
  - Remove fixed geometry assumptions
  - Replace hardcoded y-positions with metrics-based placement
  - Convert fixed truncation heuristics to width-aware truncation (`chars_per_line` from layout)

- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/ui/layout.rs`
  - Replace `MENU_VISIBLE_ITEMS` constant with runtime calculation
  - Add helper functions to calculate visible rows/line wrapping from capabilities

### App/UI logic consumers
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/menu.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/state.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/dialogs.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/ui/screens/mod.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/ui/screens/picker.rs`
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/settings.rs`

Update all pagination/offset logic to use runtime `menu_visible_items` and `dialog_visible_lines`.

### Config
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/config.rs`
  - Add optional display config block:
    - backend preference
    - width/height override
    - offsets
    - safe padding
    - calibration edges (left/top/right/bottom + metadata)

### Settings UI (reconfiguration path)
- Add `Display` submenu under settings in:
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/menu.rs`
  - `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/app/settings.rs`

Suggested entries:
- `Display Backend`
- `Rotation`
- `Resolution Override`
- `Offsets`
- `Run Display Discovery`
- `Run Display Calibration`
- `Reset Display Calibration`
- `Reset Display Cache`
- `Show Display Diagnostics`

Behavior:
- User can re-run calibration at any time from Settings > Display.
- New calibration applies immediately (preview) and persists only after explicit confirm.
- If calibration results are invalid (zero/negative area, out of bounds), reject and keep prior config.
- `Run Display Discovery` and `Run Display Calibration` are explicit user actions; boot path must use cached values when completion flags are set.

### Input (unchanged behavior, stronger invariants)
- `/Users/iwanteague/Desktop/watchdog/crates/rustyjack-ui/src/input.rs`
  - Keep exactly 8 buttons
  - Add invariant/assertion and better startup diagnostics

## B) Service/Installer integration

Update service env in installer-generated units to include optional display backend/settings:
- `/Users/iwanteague/Desktop/watchdog/install_rustyjack.sh`
- `/Users/iwanteague/Desktop/watchdog/install_rustyjack_dev.sh`
- `/Users/iwanteague/Desktop/watchdog/install_rustyjack_prebuilt.sh`
- `/Users/iwanteague/Desktop/watchdog/install_rustyjack_usb.sh`

Possible additions:
- `RUSTYJACK_DISPLAY_BACKEND=st7735` (default for current hardware)
- Optional overrides for width/height/offsets

## C) Testing additions

Add and integrate UI layout/resolution tests:
- New suite idea: `/Users/iwanteague/Desktop/watchdog/scripts/rj_test_ui_layout.sh`
- Add into `/Users/iwanteague/Desktop/watchdog/scripts/rj_run_tests.sh`

Coverage should include:
- Unit tests for metrics calculation (128x128, 240x240, 320x240, 480x320)
- Property tests: no text draw call beyond bounds
- Text-layout tests: wrap/ellipsis/pagination behavior at multiple resolutions
- Snapshot-like rendering checks for key screens (menu/dialog/dashboard/file viewer)
- Rotation checks (portrait/landscape)
- Regression test for bottom-row clipping
- Calibration tests:
  - edge adjustment correctness for LEFT/TOP/RIGHT/BOTTOM
  - persisted config round-trip
  - reject invalid calibrations
  - reconfiguration via Settings > Display path

## Migration Plan (Phased)

## Phase 1: Metrics + De-hardcode
- Introduce `DisplayCapabilities` and `UiLayoutMetrics`
- Replace all fixed `MENU_VISIBLE_ITEMS`/`DIALOG_VISIBLE_LINES` usage
- Keep ST7735 backend only

Acceptance:
- 128x128 behavior matches or improves current UX
- No clipping at bottom/right edges

## Phase 2: Backend abstraction
- Split backend init from renderer
- Add runtime mode detection path for non-ST7735 displays

Acceptance:
- Runs unchanged on current Pi Zero 2 W + Waveshare HAT
- Can launch on larger display backend without layout waste

## Phase 3: Installer/docs/test hardening
- Service env and config wiring
- Add dedicated layout/resolution test suite
- Update docs and troubleshooting

Acceptance:
- New display settings documented and test-covered

## Documentation Updates Required

Update these files to reflect dynamic resolution support while preserving 8-button design:

- `/Users/iwanteague/Desktop/watchdog/README.md`
  - Add "Display Backends & Dynamic Resolution" section
  - Add "Display Calibration" section (edge capture workflow + controls)
  - Document env/config precedence and supported ranges
  - Keep 8-button behavior table unchanged

- `/Users/iwanteague/Desktop/watchdog/AGENTS.md`
  - Replace single fixed-size assumption with "default target 128x128; runtime dynamic supported"
  - Explicitly state button model is fixed at 8 inputs

- `/Users/iwanteague/Desktop/watchdog/CLAUDE.md`
  - Add architecture note about layout engine + backend capability detection
  - Add note on calibration flow and verification logs
  - Note that larger displays are supported with same button controls

- `/Users/iwanteague/Desktop/watchdog/services/rustyjack-ui.service` (template/content generated by installers)
  - Document optional display env vars

- Optional new doc:
  - `/Users/iwanteague/Desktop/watchdog/docs/display_dynamic_resolution.md`
    - Deep-dive for porting to new panels/backends
    - Includes calibration UX and backend verification model

## Key Risks and Pitfalls

- ST7735 detection is not fully auto-discoverable with current driver path; must keep sane defaults + overrides.
- MISO-based ST7735 readback may be unavailable on some HAT routing or insufficient to infer visible geometry.
- Hardcoded truncation lengths (`shorten_for_display(..., 18/20/etc)`) may underutilize larger screens until converted to layout-aware values.
- Different font metrics may require adaptive line-height (not just proportional scaling).
- Large-screen rendering frequency could increase CPU use; maintain capped redraw rates.

## Recommended Defaults

- Keep default backend as ST7735 for current hardware.
- Keep default resolution 128x128 when backend cannot query mode.
- Allow up to 480p-equivalent modes for bigger panels.
- If detected resolution is below 128x128, continue startup in best-effort mode and log `UNSUPPORTED_DISPLAY_SIZE`.
- Prefer calibrated edges over raw defaults when calibration exists and passes validation.
- Keep button input as fixed 8 physical controls with unchanged semantics.

## Definition of Done

- UI fills usable screen area on all supported display modes with no permanent unused strip.
- Menu/dialog/dashboard/file-viewer paging is runtime-derived and resolution-aware.
- Text wrapping/ellipsis/pagination is runtime-derived and prevents cutoff/overflow.
- `128x128` remains the lowest supported size; smaller displays are not blocked but clearly marked unsupported.
- Settings > Display can re-run calibration and persist verified boundaries.
- 8-button control model is unchanged and validated at startup.
- Installer/service/docs/test suite all reflect dynamic resolution behavior.
