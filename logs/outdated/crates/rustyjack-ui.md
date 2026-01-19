# rustyjack-ui
Created: 2026-01-07

Embedded LCD UI for the Waveshare 1.44" HAT (ST7735S) on Pi Zero 2 W. Renders menus/dashboards, handles GPIO buttons, and dispatches actions to `rustyjack-core`.

## Responsibilities
- Menu system and dialogs for Wi‑Fi/Ethernet actions, hotspot, pipelines, and system controls.
- Status overlays (CPU/RAM/disk/uptime/target/MAC/toolbar).
- Loot browsing with scrollable viewer; reports/Discord upload/USB export triggers.
- Hotspot controls (upstream/AP selection, start/stop, SSID/password randomize).
- Autopilot status display; operation mode toggles (Stealth/Default/Aggressive/Custom).
- GPIO button input and SPI display rendering (landscape default via `RUSTYJACK_DISPLAY_ROTATION`).

## Key files
- `main.rs`: Linux guard and entrypoint.
- `display.rs`: ST7735S driver, drawing primitives, colors; backlight control.
- `config.rs`: pins, colors, defaults, and persistence (`gui_conf.json`); button mapping.
- `app.rs`: main UI state machine, menu flow, action dispatch to core, dialog logic.
- `menu.rs`: menu definitions/enums; wiring to `app.rs`.
- `input.rs`: GPIO/button handling, debounce, mapping to actions.
- `stats.rs`: system stats collection for overlays.
- `core.rs`, `types.rs`, `util.rs`: IPC helpers, data types, and utilities.

## Expectations
- Runs as root on Linux (systemd service); uses `RUSTYJACK_DISPLAY_ROTATION` and `RUSTYJACK_ROOT`.
- Communicates with `rustyjack-core` for operations; consumes other crates indirectly via core.

## Notes for contributors
- Keep dialogs requiring explicit user dismissal (no auto timeouts for errors).
- Maintain consistent button mapping (Up/Down/Left/Right, Key1 refresh, Key2 main menu, Key3 reboot confirm).
- Avoid blocking the UI thread; long-running actions should show progress and remain cancellable when possible.
- Preserve small-display readability (concise text, clear hints).

## File-by-file breakdown
- `main.rs`: Linux guard and entrypoint; initializes logging, reads config, and starts the app event loop.
- `app.rs`: core UI state machine. Manages menus/dialogs, dispatches actions to `rustyjack-core`, tracks operation mode, target selection, hotspot controls, loot browsing, reports/Discord/USB export, autopilot status, and pipeline flows. Handles per-action progress/cancel logic and collects results to display.
- `menu.rs`: menu/enum definitions and helpers that map user actions to `app.rs` handlers. Defines the navigation structure for Wireless/Ethernet/Hotspot/System/etc.
- `config.rs`: pin assignments, button mapping, color palette, defaults, and persistence to `gui_conf.json` (including active interface, target SSID/BSSID/channel, toggles). Provides getters/setters and validation for config values.
- `display.rs`: ST7735S LCD driver and rendering: initializes SPI, controls backlight, draws text/bars/dialogs/status overlays, and handles landscape rotation. Includes font rendering and primitives tailored to 128×128 display.
- `input.rs`: GPIO/button handling for the joystick + Key1/Key2/Key3; debouncing and mapping to UI events per config; uses active-low inputs with pull-ups.
- `stats.rs`: collects system stats (CPU temp/load, memory, disk, uptime, interface stats) for status overlays/dashboards.
- `core.rs`: IPC bridge to `rustyjack-core` commands; wraps command invocation, handles serialization/deserialization of responses, and error mapping for the UI.
- `types.rs`: shared UI types/enums/structs for state, results, and command payloads.
- `util.rs`: UI utilities (text formatting, truncation, layout helpers, file/path helpers) used by `app.rs` and rendering.
