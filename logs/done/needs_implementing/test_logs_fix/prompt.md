# ONE-SHOT AGENT PROMPT — Fix failing Pi Zero 2 W test logs using /test logs fix/ docs

You are an autonomous Rust engineer operating **inside this repository**. Your mission is to **implement real fixes** (not stubs, not TODOs) so that the existing test harness passes on Raspberry Pi Zero 2 W.

## Ground rules (hard constraints)
1) **Rust-first:** implement fixes in Rust.  
2) **No shelling out for core features:** do not add new dependencies on external system binaries (no `nmcli`, `iptables`, `dhclient`, etc.). Existing test scripts may call utilities, but **core Rust code must stay native**.  
3) **Single-interface networking must be preserved:** all network interactions must respect the system’s “single active interface” model. Enforcing single-interface **must not** destroy the allowed interface’s IP/route state. Block/disable *other* interfaces without breaking the active one.  
4) **Do not weaken production security permanently:** if tests need relaxed daemon authorization, use **test-only systemd drop-ins under `/run/systemd/system/...`** invoked by scripts, not permanent unit-file changes.

## Inputs you MUST use
All reference docs are located in: `./test logs fix/` (note the spaces; quote this path in commands).

You MUST read and use:
- `./test logs fix/RUSTYJACK_TEST_FIX_IMPLEMENTATION_PROMPT.md` (the primary plan)
- `./test logs fix/deep-research-report.md`
- `./test logs fix/deep-research-report (1).md`
- `./test logs fix/AI_AGENT_FIX_EXECUTION_PROMPT.md`

Also use the ground truth failing logs in:
- `./test_logs/` (and any nested `*_run.log` files)

Treat the test logs as the source of truth. If a doc contradicts observed failures, prioritize the logs, then reconcile the docs.

---

## Deliverables (you MUST produce all of these)
1) Code changes that **make the failing suites pass** (no placeholders).
2) A running progress ledger file: `./test logs fix/FIX_PROGRESS.md` updated throughout execution.
3) A final summary appended to `FIX_PROGRESS.md` listing:
   - which suites were failing initially,
   - what fixes were applied,
   - what commands were run to verify,
   - and final pass status.

---

## Progress tracking (do this continuously)
Create/maintain `./test logs fix/FIX_PROGRESS.md` with the following structure and update it after each meaningful step:

### Template you must follow
- **Baseline**
  - Date/time, git commit hash (start)
  - Command(s) used to reproduce failures
  - List of failing suites and failure signatures (copied from logs)
- **Fix Iterations**
  - Iteration N: (short title)
    - Problem (exact log signature + file path)
    - Root cause (code pointers: file + function)
    - Fix implemented (what you changed, where)
    - Verification (commands run + which suites now pass/fail)
- **Final Status**
  - `PASS:` suites list
  - `REMAINING:` (must be empty at the end)
  - Notes on constraints compliance (single-interface preserved, no new external binaries used)

This file is how you keep yourself honest and avoid “we think it’s fixed” vibes.

---

## Execution plan (must be done in one continuous run)
You must carry out the fixes end-to-end, iterating until the suite is clean.

### Step 1 — Read and extract constraints + tasks
1) Read all docs in `./test logs fix/`.
2) Extract constraints into a short bullet list at the top of `FIX_PROGRESS.md`.
3) Extract the required fix list (from the implementation prompt doc) into an ordered checklist.

### Step 2 — Establish a baseline from logs and reproduce locally
1) Parse `./test_logs/*_run.log` and list failures in `FIX_PROGRESS.md` (suite name → key error lines).
2) Re-run the failing tests using the repo’s scripts (prefer `./scripts/rj_run_tests.sh --all` if available).
3) Confirm the failures match the stored logs (or note any drift).

### Step 3 — Implement fixes in the prescribed priority order
You MUST implement the fixes described in `RUSTYJACK_TEST_FIX_IMPLEMENTATION_PROMPT.md` (and validated against the logs). In particular, the following issues are expected and must be actually fixed:

#### A) Tokio runtime panics (“no reactor running”)
- Ensure the CLI enters a Tokio runtime before calling code that uses tokio-backed netlink.
- No “async rewrite of everything”; use the existing runtime helper if present.

#### B) Single-interface enforcement breaking routes (“route changed / isolation check failed”)
- Fix strict isolation logic so that it does **NOT** flush IPs or delete default routes for the *allowed* interface.
- Enforce single-interface by disabling/blocking non-allowed interfaces **without** breaking the selected active interface.
- Add/adjust any tests or internal checks as needed, but do not change the harness expectations unless the docs explicitly authorize it.

#### C) Daemon UI-only gate blocking tests
- Do NOT permanently weaken daemon auth.
- Implement a **test-mode systemd drop-in** created by scripts under `/run/systemd/system/rustyjackd.service.d/` setting `RUSTYJACKD_UI_ONLY_OPERATIONS=false` (or the appropriate env flag already supported).
- Update the test scripts to enable/disable this mode with safe teardown (trap).

#### D) IPC schema mismatch: missing `timeout_ms` for WifiScanStart
- Update the script to send `timeout_ms`.
- Make the Rust IPC struct backward compatible via serde default (so older clients won’t break).

#### E) Missing CLI commands referenced by tests
Implement working, non-stub CLI subcommands that the scripts call, returning JSON in the project’s convention:
- `rustyjack evasion ...` (status + required fields)
- `rustyjack physical-access ...`
- `rustyjack anti-forensics ...`
- `rustyjack audit log-status ...`
- `rustyjack loot artifact-sweep ...`
If the test expects a file to be deleted (secure delete), it must actually delete it safely (no symlink tricks, no directory deletion).

#### F) USB mount filesystem detection (vfat)
- Improve FAT/vfat detection robustly (boot sector signature + BPB plausibility) so valid FAT volumes don’t get rejected.
- Keep it pure Rust.

### Step 4 — Verify after each fix and keep tightening
After each fix:
1) Run the smallest relevant test suite(s) first (the scripts that failed).
2) Then periodically run `--all` to ensure no regressions.
3) Update `FIX_PROGRESS.md` with exact commands and results.

You are not done until:
- All previously failing suites now pass, and
- No new failures are introduced.

### Step 5 — Final pass and handoff summary
1) Run the full test command that the harness uses (document exact command).
2) Confirm `FIX_PROGRESS.md` shows **REMAINING: empty**.
3) Add a final “constraint compliance” paragraph:
   - single-interface model preserved,
   - no new external binaries introduced in core Rust code,
   - test-only relaxations implemented via `/run/systemd/system` drop-ins with teardown.

---

## Quality bar (do not negotiate with yourself)
- No boilerplate “placeholder” implementations.
- No “returns ok but does nothing” just to satisfy scripts unless the script explicitly only checks exit code/help output (and you must document that).
- Fixes must be robust and align with the security + appliance constraints.
- Keep changes minimal but correct; prefer leveraging existing crates/modules already in the repo.

---

## Start now
Begin by creating `./test logs fix/FIX_PROGRESS.md`, then follow the plan above until the full suite passes.
