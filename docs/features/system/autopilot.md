# Autopilot

Automated run modes that sequence Rustyjack pipelines with minimal user input. Managed by `rustyjack-core::operations` and surfaced in the UI toolbar/status.

## Modes
- Standard, Aggressive, Stealth, Harvest (names may vary by UI version). Each selects a preset pipeline and toggles (e.g., MAC randomize, TX power, passive vs active attacks).

## Behavior
- Requires wired interface with link (unless in Stealth variant).
- Blocks in Stealth operation mode except for the Stealth autopilot.
- Uses the same pipeline engine as manual runs; reports status/progress via IPC to the UI.

## Dependencies
- Underlying pipelines (wireless or Ethernet) as described in `pipelines.md`.
- Interface isolation and evasion toggles applied before start.

## Notes
- Toolbar shows autopilot status when running.
- Cancellable via UI; respects operation mode restrictions.
