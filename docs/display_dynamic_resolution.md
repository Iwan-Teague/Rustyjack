# Dynamic Display Resolution

## Summary

`rustyjack-ui` now uses runtime display capabilities and layout metrics instead of fixed `128x128` geometry constants in core menu/dialog/file-view pagination logic.

Runtime flow:
1. Detect backend.
2. Query backend capabilities.
3. Run calibration only when geometry is unverified.
4. Cache effective geometry and reuse it on normal boots.

Calibration timing:
- Calibration is **not performed inside installer scripts** (`install_rustyjack*.sh`).
- It runs from the UI startup path (`rustyjack-ui` service) when needed.
- After completion flags are set in `gui_conf.json`, startup uses cached geometry and skips recalculation.

## Support Policy

- Lowest supported layout target: `128x128`.
- Smaller displays are allowed in best-effort mode and emit `UNSUPPORTED_DISPLAY_SIZE` warnings.
- Button model remains fixed to exactly 8 controls: `Up, Down, Left, Right, Select, Key1, Key2, Key3`.

## Backends and Detection

Backends:
- `st7735` (default for Pi Zero 2 W + Waveshare HAT)
- `framebuffer`
- `drm`

Environment/config precedence:
1. Explicit overrides (`RUSTYJACK_DISPLAY_*` / config override fields)
2. Backend-detected mode
3. Backend profile default

Warnings/events:
- `DISPLAY_MODE_MISMATCH`
- `DISPLAY_UNVERIFIED_GEOMETRY`
- `UNSUPPORTED_DISPLAY_SIZE`

## Calibration

Menu path: `Settings -> Display -> Run Display Calibration`

Edge order:
1. `LEFT`
2. `TOP`
3. `RIGHT`
4. `BOTTOM`

Controls:
- Vertical edges (`LEFT`, `RIGHT`): `LEFT/RIGHT` adjust by 1 px
- Horizontal edges (`TOP`, `BOTTOM`): `UP/DOWN` adjust by 1 px
- `Select`: confirm edge
- `Key1`: reset current edge to profile default
- `Key2`: cancel and keep previous values

Validation rejects non-positive or out-of-bounds geometries.

## Persisted State (`gui_conf.json`)

Stored in `display` block:
- Backend preference, rotation, width/height overrides, offsets, safe padding
- Calibrated edges (`left/top/right/bottom`)
- `display_probe_completed`
- `display_calibration_completed`
- `display_geometry_source`
- Effective geometry (`width/height/offset_x/offset_y`)
- `effective_backend`, `effective_rotation`
- `display_profile_fingerprint`
- Version fields for calibration/probe logic

## Manual Recalculation

Manual-only operations are exposed under `Settings -> Display`:
- `Run Display Discovery`
- `Run Display Calibration`
- `Reset Display Calibration`
- `Reset Display Cache`
- `Show Display Diagnostics`

Normal boots reuse cached effective geometry when completion flags indicate prior completion.

## Testing

Added/updated coverage includes:
- Runtime metrics and text fit behavior across multiple resolutions
- Wrap/ellipsis/pagination bounds safety
- Display config cache/calibration persistence tests
- Startup cache reuse and warning behavior tests
- Display settings menu action availability tests

Test runner integration:
- `scripts/rj_test_ui_layout.sh`
- `scripts/rj_run_tests.sh --ui-layout`
