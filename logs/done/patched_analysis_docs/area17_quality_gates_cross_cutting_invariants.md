# Area 17 — Quality Gates + Cross‑Cutting Invariants

_Read‑only maintainer report for `watchdog (Rustyjack)`. Generated 2026-02-14._

## Non-negotiables this report assumes

- **No repo edits were made.** This document is descriptive + prescriptive only.

- **Authoritative constraints live in root docs and `logs/done/`.** Everything else (code, scripts, CI config) is treated as _enforcement evidence_.

- This playbook focuses on preventing regressions (quality gates), not on operational usage.

## The invariants we must not regress

These are the cross-cutting rules that shape every “quality gate” decision:

1. **Interface isolation invariant**: exactly one operational interface is allowed at a time; selecting a new one must de-isolate the previous one and re-apply isolation deterministically.

2. **Home‑grown Rust where possible / avoid external binaries at runtime**: prefer native Rust implementations over shelling out; if an external binary remains (transitional/compat), it must be explicitly surfaced and fenced.

3. **Privilege separation boundaries**: UI and user-facing services are unprivileged; privileged actions live behind a narrow IPC boundary and are mediated by the daemon.

4. **Pi constraints (RAM/CPU/SD wear)**: stay inside tight budgets; avoid unnecessary processes, blocking in async contexts, and excessive disk churn.

5. **No emojis / control characters in code & logs**: follow the repo’s style constraints (as documented in `AGENTS.md`); avoid emojis and unescaped control characters in scripts and log output.

## 1) Inventory of existing quality gates

### 1.1 GitHub Actions CI (current)

CI is defined in `.github/workflows/ci.yml` and runs four checks:

- **Forbid spawning external commands** via `ci/forbid_command_new.rs`.

  - **Prevents**: new runtime dependencies on `bash`, `iptables`, etc; reduces attack surface and Pi overhead.

  - **How**: static scan for `Command::new` or `std::process::Command` in `.rs` files (with a small directory skip list). The allowlist is currently empty.

- **No new `unwrap()` / `expect()`** via `ci/no_new_unwrap_expect.rs` + `ci/unwrap_expect_baseline.txt`.

  - **Prevents**: creeping panics in production paths; enforces paying down panic debt over time.

  - **How**: counts raw substring occurrences across `.rs` files (excluding `tests/` and `benches/`) and fails if the count exceeds the baseline.

- **No blocking inside async contexts** via `ci/no_blocking_in_async.rs` + `ci/async_blocking_allowlist.txt`.

  - **Prevents**: deadlocks/jank on single-thread runtimes; hidden latency spikes; watchdog stalls.

  - **How**: heuristic scan for blocking patterns (std fs/net, `thread::sleep`, etc.) inside detected `async fn` bodies, with explicit carve‑outs:

    - allowlisted paths: `crates/rustyjack-ui/`, `crates/rustyjack-core/src/external_tools/`, `tests/`, `build.rs`, `ci/`.

    - allowlisted files: from `ci/async_blocking_allowlist.txt`.

    - “blocking-safe contexts”: `spawn_blocking(...)`, `run_blocking(...)`, `block_on(...)`.

- **Release feature guard**: CI runs `cargo check -p rustyjack-core --release --features lab` and expects it to fail.

  - **Prevents**: accidentally shipping lab/dev-only code paths.

  - **How**: compile-time `compile_error!` guard in `crates/rustyjack-core/src/lib.rs` that rejects forbidden feature sets in release builds.

### 1.2 Compile-time / build-time gates (Rust)

- **Release build feature fences**: `crates/rustyjack-core/src/lib.rs` hard-fails `--release` builds when `lab` or `tools` features are enabled.

- **Platform guardrails**: the UI binary contains a Linux-only compile guard (mentioned in root docs).

- **Lint posture (partial)**: multiple crates use `#![deny(unsafe_op_in_unsafe_fn)]`, but there is no workspace-wide lint policy (e.g., deny warnings, forbid unwrap) enforced in CI.

### 1.3 System-level gates (systemd hardening + budgets)

Service units in `services/` and socket activation via `rustyjackd.socket` implement real boundary enforcement:

- **Privilege split**:

  - `services/rustyjack-ui.service` runs as `User=rustyjack-ui` with `RestrictAddressFamilies=AF_UNIX` and `NoNewPrivileges=true`.

  - `services/rustyjackd.service` runs as `User=root` but with a bounded capability set and syscall filtering.

  - The daemon’s socket is `/run/rustyjack/rustyjackd.sock` with `SocketMode=0660`, `SocketUser=root`, `SocketGroup=rustyjack`.

- **Resource budgets** (Pi reality):

  - `rustyjackd.service`: `MemoryMax=256M`, `CPUQuota=80%`, `TasksMax=64`.

  - `rustyjack-ui.service`: `MemoryMax=128M`, `TasksMax=32`.

  - `rustyjack-portal.service`: `MemoryMax=64M`, `CPUQuota=20%`, `TasksMax=32`.

- **Sandboxing**: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, and syscall filters across services.

### 1.4 Test scripts / harnesses (manual + on-device)

The repo ships a cohesive bash-driven acceptance harness under `scripts/`:

- `scripts/rj_run_tests.sh` orchestrates the suite.

- Test entrypoints include `rj_test_all.sh`, `rj_test_daemon.sh`, `rj_test_interface_selection.sh`, `rj_test_ui_layout.sh`, etc.

- `TESTING.md` documents “safe-by-default” testing patterns and how to run fast vs full suites.


**Important:** These scripts are valuable gates, but they are _not enforced_ by CI today.

## 2) Gaps & bypass risks

These are the main ways a regression can slip through despite existing gates:

1. **CI is almost entirely “static text scans”**. It does not run `cargo test`, `cargo fmt`, or `cargo clippy`.

2. **Allowlist drift**:

   - `ci/forbid_command_new.rs` has an empty allowlist (so any exception becomes “edit the checker” pressure).

   - `ci/no_blocking_in_async.rs` allowlists entire directories (`crates/rustyjack-ui/`, `external_tools/`, `/tests/`), making it easy to “move code to bypass the gate.”

3. **Baseline-based gates can be bypassed by moving the baseline** (`unwrap_expect_baseline.txt`). Baselines are useful debt trackers, but they need review discipline.

4. **Command spawning can evade string-based detection** (e.g., aliasing `Command` or using lower-level exec APIs). A pure substring scan is not a complete ban.

5. **Privilege separation is only enforced under systemd**. A developer running binaries manually (or a misconfigured installer) can bypass service sandboxing and resource limits.

6. **Interface isolation depends on call-site discipline**. A new operation that forgets to call `enforce_single_interface(...)` can violate the invariant without tripping CI.

7. **Pi resource budgets are declared (systemd) but not continuously measured**. Without a budget regression test, memory/CPU creep is stealthy.

8. **Style constraints are not enforced by CI**. Example: `AGENTS.md` says to avoid emojis; the repo currently contains an emoji in `scripts/wifi_driver_installer.sh`. A tiny grep gate can prevent accidental spread.

## 3) Cross-cutting invariant map (compliance map)

### 3.1 Interface isolation invariant

- **Enforcement points (today)**

  - Runtime: `crates/rustyjack-core/src/system/mod.rs` (`apply_interface_isolation*`, `enforce_single_interface`).

  - Call sites: multiple operations in `crates/rustyjack-core/src/operations.rs`.

  - Daemon monitoring: `crates/rustyjack-daemon/src/netlink_watcher.rs` triggers isolation on link events.

  - Manual acceptance: `scripts/rj_test_interface_selection.sh` + guidance in `TESTING.md`.

- **Missing enforcement**

  - No CI test ensures all operations that take an `interface` argument call `enforce_single_interface`.

  - No “type-level” guard that forces isolation before privileged ops (it’s a convention, not a capability).

- **Proposed tests/gates**

  - Unit tests with a mocked `NetOps` to ensure isolation is applied/removed in the correct order.

  - Static gate: grep/AST check that every IPC-exposed operation accepting an interface calls `enforce_single_interface`.

  - On-device acceptance: create two dummy interfaces and verify isolation transitions without breaking the admin uplink.

### 3.2 Home-grown Rust / avoid external binaries at runtime

- **Enforcement points (today)**

  - CI: `ci/forbid_command_new.rs`.

  - Compile-time: release feature guard in `crates/rustyjack-core/src/lib.rs` (forbids `lab`/`tools`).

  - Runtime packaging: systemd unit file allowlists (what can run and with what permissions).

- **Missing enforcement**

  - No explicit “runtime external binary allowlist” for transitional dependencies.

  - No gate for non-`Command::new` execution routes (`execve`, `posix_spawn`, etc.).

  - No “process inventory” regression test on-device.

- **Proposed tests/gates**

  - Expand the command-spawn checker to catch common exec APIs and alias patterns.

  - Add an allowlisted-exceptions file (reviewed) that requires any shell-out to be (a) documented and (b) feature-gated.

  - On-device: verify that only expected processes exist while services are idle + during a smoke job.

### 3.3 Privilege separation boundaries

- **Enforcement points (today)**

  - systemd hardening in `services/` and socket activation via `rustyjackd.socket`.

  - IPC surface: `crates/rustyjack-ipc/` types + daemon dispatch (`crates/rustyjack-daemon/src/dispatch.rs`).

- **Missing enforcement**

  - No CI check that unit files retain required hardening settings.

  - No automated test that the UI cannot perform privileged syscalls or access restricted files.

- **Proposed tests/gates**

  - Static unit-file policy tests (parse service units; assert presence of hardening + absence of new capabilities).

  - Integration test: run UI as its service user; attempt privileged actions via IPC only; ensure direct access fails.

### 3.4 Pi resource constraints (RAM/CPU/SD)

- **Enforcement points (today)**

  - systemd budgets: `MemoryMax`, `CPUQuota`, `TasksMax`.

  - CI: `no_blocking_in_async` reduces single-thread stalls.

- **Missing enforcement**

  - No regression thresholds for:

    - binary size (storage + update time)

    - idle RSS/CPU (real RAM budget)

    - write amplification (SD wear)

- **Proposed tests/gates**

  - CI: size check for release artifacts (per-binary max bytes).

  - On-device: “idle budget” test that measures RSS, CPU, open FDs, log write rate over 60s.

## 4) Findings (maintainer-facing)

Format: **Problem → Why → Where → Fix → Fixed version looks like**

### Finding 1

- **Problem:** CI: Command spawning ban currently trips on a real `Command::new` use

- **Why:** Violates the “no external binaries at runtime” rule and opens a backdoor for future shell-outs.

- **Where:** `crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs` (spawns `bash`).

- **Fix:** Move this job behind a non-release feature (e.g., `lab`), or replace it with an internal Rust test runner. If an exception remains, require it to be explicitly allowlisted + feature-gated.

- **Fixed version looks like:** Default build contains **zero** `Command::new` usages; the test job is compiled only with a lab/dev feature and CI verifies the gating.

### Finding 2

- **Problem:** CI: “no blocking in async” checker flags blocking std-fs in async job handler

- **Why:** Blocking std I/O inside async can stall the executor and degrade responsiveness on Pi hardware.

- **Where:** `crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs` (`std::fs::read_to_string`, `File::create` in an `async fn`).

- **Fix:** Use `tokio::fs` equivalents, or wrap blocking file I/O in `spawn_blocking` with a small, auditable closure.

- **Fixed version looks like:** The async job handler does not call std-fs directly; all blocking I/O is done via `tokio::fs` or `spawn_blocking`.

### Finding 3

- **Problem:** CI: unwrap/expect baseline appears stale vs current codebase

- **Why:** The “no new panics” gate is only useful if the baseline reflects current reality; otherwise it becomes permanently red or silently ignored.

- **Where:** `ci/unwrap_expect_baseline.txt` baseline=167; current scan finds 219 occurrences (notably in core system code).

- **Fix:** Decide on policy: (A) update baseline as a one-time sync + start paying down; or (B) tighten by forbidding unwrap/expect in production crates (allow in tests).

- **Fixed version looks like:** CI either passes with an updated baseline **and** a debt paydown plan, or fails whenever unwrap/expect grows outside explicitly-allowed contexts.

### Finding 4

- **Problem:** Two competing approaches for `Command::new` exist; only one is active

- **Why:** Repo contains both a hard ban (`forbid_command_new.rs`) and a baseline tracker (`no_new_command_new.rs` + `command_new_baseline.txt`). Mixed strategies confuse maintainers and reviewers.

- **Where:** `ci/forbid_command_new.rs` (active) vs `ci/no_new_command_new.rs` + `ci/command_new_baseline.txt` (inactive).

- **Fix:** Pick a single policy: either a strict ban with a small reviewed allowlist, or a baseline+paydown approach with explicit deadlines.

- **Fixed version looks like:** There is exactly one source of truth for shell-out policy; CI messages match the chosen policy and point to the exception list.

### Finding 5

- **Problem:** CI does not run compilation for the full workspace

- **Why:** Static scans can pass even while the workspace fails to compile (feature interactions, platform cfg, missing deps).

- **Where:** `.github/workflows/ci.yml` only checks one `cargo check` for core with a forbidden feature set, but not normal builds.

- **Fix:** Add `cargo check` for the default feature set(s) and for the daemon/UI binaries, ideally with a small feature matrix.

- **Fixed version looks like:** CI always proves the repo builds in its supported configurations before merge.

### Finding 6

- **Problem:** CI does not run unit/integration tests

- **Why:** Existing `#[test]` coverage is unused in the main gate, so logical regressions can ship.

- **Where:** Workspace tests exist across crates, but CI doesn’t execute `cargo test`.

- **Fix:** Add `cargo test` (with sensible feature sets); keep device-only tests in scripts.

- **Fixed version looks like:** CI runs fast unit tests on every PR; device tests run on a schedule or a self-hosted runner.

### Finding 7

- **Problem:** No formatting gate

- **Why:** Inconsistent formatting increases diff noise and review cost; also correlates with missed issues in critical code.

- **Where:** No `cargo fmt --check` in CI.

- **Fix:** Add a formatting job or step (`cargo fmt --all -- --check`).

- **Fixed version looks like:** Any formatting drift is caught before merge.

### Finding 8

- **Problem:** No clippy/lint gate

- **Why:** Rust’s strongest quality gate is linting; without it, footguns (e.g., needless clones, panic patterns, suspicious casts) creep in quietly.

- **Where:** No `cargo clippy` step in CI, and no workspace-wide lint policy.

- **Fix:** Add `cargo clippy --all-targets` (curated feature matrix) with `-D warnings` and targeted denies (unwrap/expect, panic in prod paths).

- **Fixed version looks like:** Lint regressions fail fast; exceptions are explicit and rare.

### Finding 9

- **Problem:** Substring-based command ban can be evaded

- **Why:** Aliases or exec APIs could bypass a raw string scan; this is a classic “policy bypass by refactor.”

- **Where:** `ci/forbid_command_new.rs` only matches `Command::new` / `std::process::Command` strings.

- **Fix:** Upgrade to an AST-aware check (rust-analyzer JSON, `syn` parser, or a dedicated lint) and add additional patterns (`execve`, `posix_spawn`).

- **Fixed version looks like:** Spawning processes is blocked even when the code is refactored/aliased.

### Finding 10

- **Problem:** Directory-level allowlists create “move-to-bypass” incentives

- **Why:** If a directory is globally exempt (e.g., tests, UI), code can be moved there to dodge blocking-in-async checks.

- **Where:** `ci/no_blocking_in_async.rs` allowlists `crates/rustyjack-ui/` and `/tests/` wholesale.

- **Fix:** Replace broad directory allowlists with a narrower allowlist file + targeted exceptions; enforce “why” comments for each exception.

- **Fixed version looks like:** Exceptions are precise, reviewed, and do not become a hiding place for core logic.

### Finding 11

- **Problem:** Release feature guard checks only one forbidden feature set

- **Why:** Today’s CI only asserts `--features lab` fails. Other forbidden combinations (e.g., `tools`) may not be continuously tested.

- **Where:** CI step: `cargo check -p rustyjack-core --release --features lab` expecting failure; compile_error also mentions `tools`.

- **Fix:** Expand the guard to check every forbidden feature set and also prove the intended production feature set compiles in release mode.

- **Fixed version looks like:** CI covers the entire feature fence: forbidden sets fail; allowed sets build.

### Finding 12

- **Problem:** Privilege boundaries rely on systemd unit files, but they aren’t tested

- **Why:** A future unit-file edit could accidentally add capabilities, widen address families, or relax filesystem protections.

- **Where:** `services/*.service` and `rustyjackd.socket` are the boundary; no gate asserts their invariants.

- **Fix:** Add a CI check that parses units and asserts required hardening keys remain present (and that capability sets don’t expand without review).

- **Fixed version looks like:** Unit file hardening is treated like API surface: changes are detected and reviewed intentionally.

### Finding 13

- **Problem:** Daemon capabilities include `CAP_SYS_ADMIN` (very broad)

- **Why:** On Linux, `CAP_SYS_ADMIN` is effectively “god-mode.” It may be necessary, but it deserves extra scrutiny and minimization.

- **Where:** `services/rustyjackd.service`: `CapabilityBoundingSet` includes `CAP_SYS_ADMIN`.

- **Fix:** Audit which operations truly require it; try to split into narrower capabilities or separate helper services if feasible.

- **Fixed version looks like:** The daemon runs with the minimum capabilities required; any remaining broad capability is documented with justification.

### Finding 14

- **Problem:** Socket group membership is a security boundary but is not guarded

- **Why:** Anyone added to the `rustyjack` group can talk to the daemon socket. That’s correct-by-design, but it must be deliberate and auditable.

- **Where:** `rustyjackd.socket`: `SocketMode=0660`, `SocketGroup=rustyjack`; UI and portal are in/with that group.

- **Fix:** Document group membership policy in a root doc and add an installer check that enforces expected users/groups and permissions.

- **Fixed version looks like:** Daemon socket access is explicitly controlled; accidental group membership doesn’t silently expand authority.

### Finding 15

- **Problem:** Interface isolation enforcement is mostly by convention (call-sites)

- **Why:** If a new operation takes an interface parameter and forgets `enforce_single_interface`, isolation can silently break.

- **Where:** Many calls exist in `crates/rustyjack-core/src/operations.rs`, but there is no hard rule that all must follow.

- **Fix:** Introduce a type-level token (e.g., `IsolatedInterface`) created only by isolation functions, required by privileged ops that depend on interface state.

- **Fixed version looks like:** Operations that need interface state cannot compile unless isolation was applied first.

### Finding 16

- **Problem:** Unsafe usage is widespread but unmanaged

- **Why:** `unsafe` may be required for low-level Pi operations, but without inventory + justification it becomes unreviewable.

- **Where:** Multiple crates contain `unsafe { ... }`, without an automated inventory gate.

- **Fix:** Add an “unsafe inventory” report in CI: list files/lines, require `// SAFETY:` comments, and fail on new unsafe without justification.

- **Fixed version looks like:** Every unsafe block has a localized safety contract and CI prevents silent growth of unsafe surface.

### Finding 17

- **Problem:** Pi budgets are declared, but no measurement prevents drift

- **Why:** Systemd limits stop catastrophic blow-ups, but they do not prevent gradual performance regressions and UX jank.

- **Where:** Resource limits exist in `services/*.service`; no acceptance test measures idle + load budgets.

- **Fix:** Add a lightweight on-device acceptance: measure RSS/CPU/FDs and log write rate for 60s idle + one smoke job; compare to thresholds.

- **Fixed version looks like:** Budget regressions are caught early; “it still works” does not hide “it’s now slow/unreliable.”

### Finding 18

- **Problem:** CI does not validate cross-compilation / target compatibility

- **Why:** Pi targets (arm64/armv7) can break without being noticed when CI only builds on x86_64.

- **Where:** No CI build step exercises ARM targets.

- **Fix:** Add cross-build checks (e.g., `cargo check --target aarch64-unknown-linux-gnu` and/or `armv7-unknown-linux-gnueabihf`) for key crates.

- **Fixed version looks like:** Target regressions are caught on PRs instead of on-device after a deploy.

### Finding 19

- **Problem:** Test harness is bash-heavy, which can mask Rust-level invariant regressions

- **Why:** Bash tests are useful, but they can accidentally rely on external tools and can drift from the Rust implementation reality.

- **Where:** `scripts/rj_run_tests.sh` drives most acceptance coverage.

- **Fix:** Gradually migrate the “must never regress” checks (interface isolation, IPC health, resource budgets) into a small Rust acceptance binary that can run on device and in CI (namespaces/mocks).

- **Fixed version looks like:** Critical invariants are tested using the same Rust primitives the product uses, reducing “script vs product” drift.

## 5) Next gate proposals (additions to CI / tests)

These are concrete, high-leverage gates to add next (9 proposals):

1. **`cargo fmt --check`** (workspace) — blocks style drift.

2. **`cargo clippy -D warnings`** (curated feature matrix) — blocks common Rust footguns.

3. **`cargo test`** for fast unit tests (no device dependencies).

4. **Build matrix for targets**: at least `x86_64-unknown-linux-gnu` + `aarch64-unknown-linux-gnu` for core/daemon/UI.

5. **Feature fence matrix**: assert forbidden feature sets fail in `--release`, and allowed production sets succeed.

6. **AST-aware “no process spawn” gate**: catch aliases and lower-level exec APIs (not just `Command::new`).

7. **Unsafe inventory gate**: list `unsafe` blocks; require `// SAFETY:`; fail on new unsafe without justification.

8. **Systemd unit policy gate**: parse `services/*.service` + `rustyjackd.socket`; assert required hardening keys; fail if capabilities widen.

9. **On-device smoke suite** (self-hosted runner or manual artifact): service health + IPC + interface isolation + budget snapshot.

## 6) On-device acceptance suite design (fast, repeatable, safe)

Goal: a suite you can run on a Pi in <2 minutes that answers: “Did we break the invariants?” without causing collateral damage.


### 6.1 Design principles

- **Safe-by-default**: never assume you can disrupt the active uplink; prefer dummy/netns-based tests.

- **Deterministic**: fixed timeouts, bounded retries, stable output.

- **Observable**: emit a single JSON/line-oriented summary plus per-check logs.

- **No new runtime dependencies**: prefer running checks using existing Rust binaries/libraries (netlink, IPC client).


### 6.2 Proposed suite layout

**A. Service + IPC health (10–20s)**

- Verify `rustyjackd` socket is listening and permissions match expectations.

- Perform a minimal IPC handshake (version/ping) from the UI service user.

- Ensure daemon rejects malformed/unauthorized requests cleanly (error, not panic).


**B. Privilege boundary checks (10–20s)**

- Run as `rustyjack-ui` user: confirm direct access to privileged paths fails.

- Confirm UI process cannot open AF_INET sockets (per `RestrictAddressFamilies`), while daemon can.


**C. Interface isolation transitions (30–45s)**

- Create two dummy interfaces via netlink (preferred) or a controlled test fixture.

- Select interface A → assert only A is “allowed” and others are isolated.

- Switch to interface B → assert A is de-isolated then isolated; B becomes sole allowed interface.

- Cleanup: remove dummy interfaces and restore original state.


**D. Resource budgets snapshot (30–60s)**

- Measure per-service RSS/CPU for 30s idle.

- Validate open FD counts remain below limits.

- Sample log write rate (bytes/min) while idle.

- Fail with actionable output if budgets regress beyond thresholds.


**E. Regression sentinels (10–20s)**

- Assert no unexpected external processes are running (allowlist-based).

- Assert no `Command::new` usage exists in shipped binaries (optional: strings scan of release artifacts).


### 6.3 How to operationalize it

- Provide a single entrypoint: a thin wrapper script or a dedicated Rust binary `rustyjack-acceptance`.

- Keep it runnable in three modes:

  - `--quick`: A+B+D+E (no interface mutation)

  - `--full`: includes interface isolation transitions (C)

  - `--ci-sim`: uses mocks/netns where possible for CI runners


### 6.4 Safety notes

- Never run disruptive checks unless the suite can prove it is operating on dummy/test interfaces.

- Always restore original DNS/routes/interfaces even if a check fails (best-effort cleanup).


---

## Appendix: Current gate status snapshot (from repo scan)

- `Command::new` occurrences in Rust sources (excluding `ci/`): **1** (in `crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs`).

- Blocking-in-async hits per the CI checker heuristics: **2** (both in `crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs`).

- `unwrap(` + `expect(` occurrences counted by CI script: **219** (baseline is **167**).

- Feature fence exists: core forbids `lab`/`tools` in `--release` builds.
