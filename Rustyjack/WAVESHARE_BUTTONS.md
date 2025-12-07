# WAVESHARE_BUTTONS.md

Summary of button mapping and UI behaviour changes

Date: 2025-11-24
Branch: test

Goals
- Make error / info dialog screens require explicit user dismissal (no automatic timeouts) so a user can take as long as needed to read the text.
- Make button behaviour uniform across the UI:
  - Up / Down — move selection
  - Left — go back / previous menu
  - Right / Select / centre press — accept / select
  - Key1 (button on the HAT) — refresh view
  - Key2 — return to main menu
  - Key3 — reboot (requires confirmation)

What I changed
- All calls to `show_message(...)` now wait for the user to explicitly dismiss the dialog (SELECT/RIGHT or LEFT) instead of sleeping for a short timeout.
- Global, unified mapping for buttons is implemented in `rustyjack-ui/src/app.rs`:
  - `map_button()` converts raw `Button` values into `ButtonAction` (Up/Down/Back/Select/Refresh/MainMenu/Reboot).
  - `confirm_reboot()` shows a confirmation dialog and calls `systemctl reboot` if the user confirms.
- Replaced existing ad-hoc uses of `Button::Key3` as a "cancel" with the new behaviour — `Key3` now triggers a reboot confirmation.
- Replaced ad-hoc uses of `Key1` and `Key2` as ad-hoc control keys where appropriate, and standardized Key1 to be `Refresh` and Key2 to `MainMenu` across UI flows (prompt and selection screens will treat Key2 as "return to main menu," and pressing Key1 will trigger a redraw/refresh of the current view).

Files changed
- `rustyjack-ui/src/app.rs` — added `ButtonAction` mapping, `MenuState::home()`, `map_button()`, `confirm_reboot()`, turned `show_message()` into a manual-dismiss dialog, and updated the main loop & a few controls to use the unified mapping.

Notes — why I chose this mapping
- Waveshare HATs (1.44" / 1.8" and similar) expose:
  - KEY1, KEY2, KEY3 pins and a small joystick (UP/DOWN/LEFT/RIGHT + press) connected to GPIO pins on the Pi (e.g. KEY1 -> P21, KEY2 -> P20, KEY3 -> P16, Joystick: P6,P19,P5,P26,P13).
  - The Waveshare wiki documents the pins and recommends enabling pull-ups in `/boot/config.txt` (see example config line `gpio=6,19,5,26,13,21,20,16=pu`).

References
- Waveshare 1.44-inch LCD HAT (button pinouts and key usage): https://www.waveshare.com/wiki/1.44inch_LCD_HAT
- Example HAT manual (button notes): https://www.waveshare.com/wiki/1.44inch_LCD_manual
- Raspberry Pi GPIO / pull-up advice (mentioned above) — Waveshare recommends enabling pull-ups in `/boot/config.txt` when using the demo code.

Testing notes
- Behaviours you can check on a running device:
  - Error dialogs or any `show_message` call will now wait for a SELECT/RIGHT press to dismiss (or LEFT to go back). Key2 should send you to the main menu, Key1 will try to refresh/redraw the view, and Key3 will open the reboot confirmation dialog.
  - The reboot confirmation screen requires pressing SELECT/RIGHT to perform the reboot.

If you want stricter behaviour (for example, treat Key3 as "cancel" inside specific dialogs instead of reboot) I can add per-dialog overrides — but right now the mapping is global and consistent across the UI.
