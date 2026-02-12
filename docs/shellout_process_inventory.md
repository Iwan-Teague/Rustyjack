# Runtime Binary Inventory

This document now tracks binaries used during deployed runtime only.

- Included: binaries started by Rustyjack systemd services, runtime helper hooks, and runtime daemon shellout paths.
- Excluded: installer, rollback, build, and test-only tooling unless explicitly marked as non-runtime.

## 1) Core runtime processes (systemd-managed)

| Binary | Runtime class | Where |
|---|---|---|
| `/usr/local/bin/rustyjackd` | Runtime (core) | `services/rustyjackd.service` (`ExecStart`) |
| `/usr/local/bin/rustyjack-ui` | Runtime (core) | `services/rustyjack-ui.service` (`ExecStart`) |
| `/usr/local/bin/rustyjack-portal` | Runtime (core) | `services/rustyjack-portal.service` (`ExecStart`) |
| `/usr/local/bin/rustyjack-hotplugd` | Runtime (helper core) | `scripts/99-rustyjack-wifi.rules` (`RUN+=`) |
| `/sbin/wpa_supplicant` | Runtime (external dependency) | `services/rustyjack-wpa_supplicant@.service` (`ExecStart`) |

Notes:
- The first three are Rustyjack project binaries.
- `wpa_supplicant` is an external system binary used at runtime for client authentication.

## 2) Runtime shellouts from Rust code

| Binary | Runtime class | Where |
|---|---|---|
| `bash` | Runtime (optional, UI-triggered test job) | `crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs` (`Command::new("bash")`) |

Notes:
- This path is used when UI/daemon test jobs are launched.
- It is not required for normal network/control runtime flows.

## 3) Runtime helper hook binaries (event-driven)

The hotplug handler is now Rust-native (`rustyjack-hotplugd`), so shell helper dependencies (`date`, `sleep`, `tr`, `tee`, `timeout`) are removed from runtime.

## 4) Explicitly non-runtime (excluded)

The following are intentionally excluded from runtime counts:

- Installer/setup commands from `install_rustyjack*.sh` (apt, user/group setup, file install/copy, reboot, etc.).
- Build/export tooling (`cargo` in build scripts, `zip`, `rsync`, packaging helpers).
- Rollback commands (`scripts/rollback_rustyjack.sh`).
- Test-suite tooling in `scripts/rj_test_*.sh` and `scripts/rustyjack_comprehensive_test.sh` (except the optional UI test launcher shellout above, marked separately).

## Runtime summary

- Core runtime service/helper binaries: **5**
- External runtime dependency binaries (core): **1** (`wpa_supplicant`)
- Optional runtime helper binaries: **0** (hotplug path migrated to Rust binary)
- Optional runtime test launcher shellout: **1** (`bash`)
