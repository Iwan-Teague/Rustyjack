# Logging Report Progress

Source: Rustyjack_Logging_Report.md
Last updated: 2026-01-07

Status legend:
- [ ] Not started
- [~] In progress
- [x] Done
- [!] Blocked

## Phase 1 - Fix logging correctness (unify in-process)
- [x] Add `tracing-log` bridge in daemon (`LogTracer::init`) so `log::` events emit.
- [x] Convert daemon-owned logs to `tracing` (e.g., jobs lifecycle).
- [x] Initialize logging in `rustyjack-ui` (env_logger or tracing subscriber).
- [x] Replace raw `println!/eprintln!` in hotspot/netlink with `tracing` macros.
- [x] Convert remaining `log::` usage across core/UI/portal/evasion/WPA/daemon to `tracing::`.

## Phase 2 - Add Rust-managed log store
- [x] Create `/var/lib/rustyjack/logs` and file rotation via `tracing-appender` (daemon/UI/portal).
- [ ] Add component identity spans (`component=...`) in each process.
- [ ] Decide stdout + file layering (text vs JSON) per component.

## Phase 3 - Replace `journalctl` log export with Rust-only
- [ ] Tail Rustyjack log files in `rustyjack-core/src/services/logs.rs`.
- [ ] Add kernel log tail capture (e.g., `/dev/kmsg` ring buffer).
- [ ] Replace GPIO diagnostics shell-outs with Rust (`gpiod` + `/proc`).

## Phase 4 - UI log access via daemon
- [ ] Add daemon endpoints for log tail and export bundle.
- [ ] Update UI to fetch logs from daemon instead of local files.

## Phase 5 - Optional systemd reduction
- [ ] Add Rust supervisor service to manage Rustyjack processes.
- [ ] Evaluate init replacement scope (likely defer).

## Cross-cutting fixes from the report
- [ ] Fix logs toggle propagation (daemon IPC + config).
- [ ] Add audit trail for privileged operations and auth decisions.
- [ ] Define logging policy boundaries (operational vs audit vs loot vs trace).
- [ ] Add redaction helpers and `#[instrument(skip(...))]` patterns.

## Completed items
- Log-to-tracing bridge added in `rustyjack-daemon`.
- Job lifecycle logging moved to `tracing` in the daemon.
- UI log backend initialized in `rustyjack-ui` (tracing subscriber).
- Hotspot `println!/eprintln!` converted to `tracing` in `rustyjack-wireless`.
- Netlink `println!/eprintln!` converted to `tracing` in `rustyjack-netlink`.
- `rustyjack-wireless` and `rustyjack-netlink` migrated from `log::` to `tracing::`.
- `rustyjack-core`, `rustyjack-ui`, `rustyjack-portal`, `rustyjack-evasion`, `rustyjack-wpa`, and `rustyjack-daemon` migrated from `log::` to `tracing::`.
