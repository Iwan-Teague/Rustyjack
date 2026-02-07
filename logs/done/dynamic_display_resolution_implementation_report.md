# Dynamic Display Resolution Implementation Report

Date: 2026-02-07
Workspace: `/Users/iwanteague/Desktop/watchdog`

## 1) Concise Implementation Summary

Implemented end-to-end dynamic display handling in `rustyjack-ui` with runtime capability-driven layout, persistent probe/calibration state, manual display reconfiguration flows, and updated docs/scripts/service env wiring.

Delivered runtime flow:
1. Detect backend
2. Query capabilities
3. Calibrate only when needed
4. Cache effective geometry and reuse on startup

Key hard requirements addressed:
- No fixed 7-line/7-item constants in core runtime flow
- Recalculation is manual via `Settings -> Display`
- 8-button model remains fixed and now has startup invariant checks
- `<128x128` is warned as unsupported (`UNSUPPORTED_DISPLAY_SIZE`) but not blocked
- Runtime layout-aware wrap/ellipsis/pagination integrated into menu/dialog/viewer flows

## 2) File-by-File Change List

### Core UI Runtime / Display
- `crates/rustyjack-ui/src/display.rs`
  - Added runtime display model:
    - `DisplayCapabilities`
    - `DisplayDiagnostics`
    - `DisplayWarning`
    - `CalibrationEdge`
  - Added backend/query/override/cache probe logic (`resolve_runtime_probe`) with precedence and fingerprinting.
  - Added warning classes/events:
    - `DISPLAY_MODE_MISMATCH`
    - `DISPLAY_UNVERIFIED_GEOMETRY`
    - `UNSUPPORTED_DISPLAY_SIZE`
  - Added runtime metrics integration (`UiLayoutMetrics`) across draw paths.
  - Removed fixed geometry assumptions from core draw/menu/dialog/dashboard/file-view code.
  - Added calibration support methods:
    - validation
    - apply/reset calibration
    - reset cache
    - calibration step rendering
  - Added startup cache reuse + probe dirty tracking.

- `crates/rustyjack-ui/src/ui/layout.rs`
  - Replaced fixed constants with runtime metrics engine (`UiLayoutMetrics`).
  - Added runtime text helpers:
    - `wrap_text`
    - `ellipsize`
    - `chars_that_fit`
    - `max_scroll_offset`
  - Added tests for multiple resolutions and bounds safety.

### App Flow / Pagination / Settings Integration
- `crates/rustyjack-ui/src/app/menu.rs`
  - Updated to runtime menu/dialog metrics (no fixed visible constants).
  - `Display::new` updated to pass mutable display config.
  - Startup:
    - persist probe cache when dirty
    - run startup calibration if required
  - Added action routing/execution for new display settings actions.

- `crates/rustyjack-ui/src/app/state.rs`
  - Menu movement now takes runtime `visible_items`.

- `crates/rustyjack-ui/src/app/dialogs.rs`
  - Selector pagination now runtime `menu_visible_items`.

- `crates/rustyjack-ui/src/ui/screens/picker.rs`
  - Runtime menu window sizing.

- `crates/rustyjack-ui/src/ui/screens/mod.rs`
  - Runtime dialog wrapping/pagination (`chars_per_line`, `dialog_visible_lines`).

- `crates/rustyjack-ui/src/app/loot.rs`
  - Runtime file viewer paging and title truncation.

- `crates/rustyjack-ui/src/app/preflight.rs`
  - Preflight error wrapping now runtime-width aware.

- `crates/rustyjack-ui/src/app/settings.rs`
  - Added `Settings -> Display` action handlers:
    - Show backend
    - Show rotation
    - Show resolution override/effective mode
    - Show offsets
    - Run Display Discovery
    - Run Display Calibration
    - Reset Display Calibration
    - Reset Display Cache
    - Show Display Diagnostics
  - Implemented guided calibration edge workflow with required controls.

- `crates/rustyjack-ui/src/menu.rs`
  - Added display submenu (`asdp`) and display actions.
  - Added test to verify manual rerun actions exist in Settings > Display.

### Config / Persistence / Invariants
- `crates/rustyjack-ui/src/config.rs`
  - Added `DisplayConfig` with persistent state:
    - backend/rotation/overrides/offsets/safe padding
    - calibrated edges + metadata
    - completion flags
    - effective geometry cache + backend/rotation/fingerprint
    - version fields
  - Added normalization and cache/calibration reset helpers.
  - Added tests for calibration/cache persistence behavior.

- `crates/rustyjack-ui/src/input.rs`
  - Added `BUTTON_COUNT: usize = 8` invariant.
  - Added startup validation for 8-button mapping consistency:
    - expected count
    - missing mapping
    - duplicate pins
    - readable GPIO lines

### Installer / Service / Test Runner / Docs
- `services/rustyjack-ui.service`
  - Added `RUSTYJACK_DISPLAY_BACKEND=st7735` and optional display override env docs.

- `install_rustyjack.sh`
- `install_rustyjack_dev.sh`
- `install_rustyjack_prebuilt.sh`
- `install_rustyjack_usb.sh`
  - Updated generated UI service env block with backend default and optional override env docs.

- `scripts/rj_run_tests.sh`
  - Added `--ui-layout` suite integration.

- `scripts/rj_test_ui_layout.sh` (new)
  - Added dedicated dynamic display/layout test suite runner.

- `README.md`
  - Added `Display Backends & Dynamic Resolution` section.
  - Added `Display Calibration` section with controls/workflow.
  - Updated env var documentation for display backend/overrides.

- `AGENTS.md`
  - Updated assumptions from fixed-size display to runtime dynamic geometry model.
  - Explicit support policy for `128x128` minimum supported target.

- `CLAUDE.md`
  - Added architecture/runtime notes for layout engine + backend capability detection + calibration warnings.
  - Updated environment variable documentation.

- `docs/display_dynamic_resolution.md` (new)
  - Added deep-dive display dynamic resolution documentation.

## 3) Why Major Design Choices Match the Blueprint

- Runtime capabilities + metrics model:
  - Implemented and propagated (`DisplayCapabilities`, `UiLayoutMetrics`) to replace fixed geometry constants in core flow.

- Required startup flow:
  - Implemented as detection/query -> conditional calibration -> cached effective geometry.

- No repeated recalculation on boot:
  - Startup reuses cached effective geometry when probe cache is complete and versioned.

- Manual-only recalculation:
  - Reconfiguration paths are explicit menu actions under `Settings -> Display`.

- 8-button hard constraint:
  - Input layer now enforces exactly 8 controls with startup invariants.

- Unsupported small displays:
  - `<128x128` generates warnings but does not block startup.

- Runtime text safety:
  - Wrap/ellipsis/pagination now uses runtime-derived width/visible-line metrics, reducing clip/overflow risk.

- ST7735 preservation:
  - Default backend remains ST7735 and installer/service env keeps this default.

## 4) Test Results and Remaining Risks

### Executed checks
- `rustfmt` on all modified Rust files: pass
- `bash -n`:
  - `scripts/rj_run_tests.sh`: pass
  - `scripts/rj_test_ui_layout.sh`: pass
  - `install_rustyjack*.sh`: pass
- `scripts/rj_test_ui_layout.sh --outroot /tmp/rj-tests` on macOS host: skipped with Linux-only notice (expected)

### Blockers encountered
- Full `cargo check` / `cargo test` for Linux target was blocked by restricted network access to crates.io index in this environment.
  - Example failure: unresolved download for crates index/dependencies.

### Remaining risks
- Full compile/test validation on a Linux Pi environment is still required.
- Non-ST7735 backend rendering remains constrained by current rendering path; detection/configuration is backend-aware, while ST7735 remains the production rendering path.
- Calibrated geometry behavior should be verified on physical panel variants (offset-sensitive modules).

### Recommended next action
1. Run `scripts/rj_test_ui_layout.sh` and `cargo test -p rustyjack-ui` on the target Linux/Pi environment with dependency access.
2. Verify first-boot calibration UX and cached-boot reuse on hardware.
3. Validate diagnostics warnings on mode override/mismatch scenarios.
