# Interface Isolation
Created: 2026-01-07

Ensures only selected interfaces are active to prevent leaks and conflicts.

Supersedes:
- `INTERFACE_ISOLATION_IMPLEMENTATION.md`
- `INTERFACE_ISOLATION_WIRELESS_FIX.md`
- `INTERFACE_ISOLATION_VERIFICATION.md`

## Behavior
- `apply_interface_isolation(allowed)`: iterates `/sys/class/net`, skips `lo`, brings allowed interfaces up (and unblocks rfkill if wireless), brings others down and rfkill-blocks wireless.
- `enforce_single_interface(iface)`: convenience to allow only one interface (used before attacks/pipelines).
- Wireless fixes: rfkill is unblocked before link-up attempts; wireless UP failures on unassociated IFs no longer abort isolation.

## Dependencies
- `rustyjack-core::system` and `netlink_helpers` using `rustyjack-netlink` for link state/rfkill; uses sysfs for rfkill indices.
- Root required; Linux-only.

## Notes
- Active interface preferences are stored/read by core; UI exposes Hardware Detect and “Route ensure” flows to set the active interface.
- Isolation is applied automatically in pipelines and many operations to avoid multi-interface routing conflicts.
