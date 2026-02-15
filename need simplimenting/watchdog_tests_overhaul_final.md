# Watchdog (Pi Zero 2 W) Test Suite Overhaul + Discord Artifacts Upload
**Audience:** engineers maintaining the Pi test system (SSH runner + Rust UI/daemon).  
**Goal:** deterministic, maintainable tests on Pi hardware + reliable Discord reporting that includes the *actual* artifacts needed to debug failures.

**Repo snapshot reviewed:** `watchdog_shallow_20260215-105501.zip` (unpacked as `watchdog_repo/` during review).  
**This doc consolidates:** current verified behavior *and* the recommended edits to implement the requested UX + Discord uploads.

Legend:
- ✅ **Verified**: confirmed in the repo snapshot.
- 🧪 **Proposed**: not implemented yet; includes concrete file/function targets.

---

## 0) Non-negotiables (system behavior we want)
1) **SSH runner and UI must run the same suites with the same semantics.**  
2) **Suite selection only**: users choose *suites*, not internal subtest toggles.
3) **Tests must be reproducible**: explicit timeouts, retries only where justified, and clear `PASS/FAIL/SKIP`.
4) **Pi realities**: slow CPU, limited RAM, flaky Wi‑Fi, `systemd`/`journald` timing quirks, occasional SD card hiccups.
5) **Discord is an observability sink, not a “nice to have”**: after each suite, ship enough artifacts to debug without SSH’ing into the device.

---

## 1) Current reality (verified)

### 1.1 Where things live (✅)
- Suite scripts: `watchdog/scripts/rj_test_*.sh`
- Deep daemon diagnostics: `watchdog/scripts/rustyjack_comprehensive_test.sh`
- Shared harness: `watchdog/scripts/rj_test_lib.sh`
- SSH runner: `watchdog/scripts/rj_run_tests.sh`
- UI “Tests” flows: `watchdog/crates/rustyjack-ui/src/app/tests.rs`
- Daemon job that spawns the runner: `watchdog/crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs`
- UI puppeting scenarios: `watchdog/scripts/ui_scenarios/*.ui`

### 1.2 Artifacts layout (✅)
`scripts/rj_test_lib.sh` provides `rj_init <suite>` and creates per-suite output under:
- `$RJ_OUTROOT/$RJ_RUN_ID/<suite>/`
  - `run.log`
  - `summary.jsonl`
  - `report.md`
  - `artifacts/`
  - `journal/`

The SSH runner (`rj_run_tests.sh`) writes a *run-level* summary:
- `$OUTROOT/$RUN_ID/run_summary.md`
- `$OUTROOT/$RUN_ID/run_summary.json`

Defaults:
- SSH runner default outroot: `/var/tmp/rustyjack-tests`
- UI/daemon runs typically use: `/var/lib/rustyjack/tests`

### 1.3 UI automation / puppeting mechanism (✅)
`rj_test_lib.sh` implements UI puppeting by:
- Creating FIFO: `/run/rustyjack/ui_input.fifo`
- Writing systemd drop-in: `/run/systemd/system/rustyjack-ui.service.d/50-virtual-input.conf`
  - sets `Environment=RUSTYJACK_UI_VINPUT=/run/rustyjack/ui_input.fifo`
- Restarting `rustyjack-ui.service` to pick up the env var
- Playing scenario files via `rj_ui_run_scenario <file>` which writes `up/down/select/back` commands into the FIFO.

### 1.4 Suites that currently puppet the UI (✅)
**Scenario-driven (`rj_ui_run_scenario`):**
- Wireless → `scripts/ui_scenarios/wireless.ui`
- Ethernet → `scripts/ui_scenarios/ethernet.ui`
- Interface selection → `scripts/ui_scenarios/interface_selection.ui`
- Encryption → `scripts/ui_scenarios/encryption.ui`
- Loot → `scripts/ui_scenarios/loot.ui`

**Direct key injection (`rj_ui_send`):**
- Theme → scripted key presses (no `.ui` scenario file)

**No UI puppeting today:**
- Installers, USB, UI layout/display, MAC randomization, daemon/IPC, Discord test, daemon deep

### 1.5 Discord notifications (current behavior) (✅)
The **runner** `scripts/rj_run_tests.sh` already:
- Discovers/stages a webhook URL:
  - `--discord-webhook URL`
  - runtime file: `${RJ_RUNTIME_ROOT:-/var/lib/rustyjack}/discord_webhook.txt`
  - repo default: `scripts/defaults/discord_webhook.txt`
- Posts:
  - per-suite status updates (`send_discord_suite_update`)
  - a final run summary (`send_discord_summary`)
    - can attach the run summary markdown via `-F file1=@...` when enabled (`RJ_DISCORD_WEBHOOK_ATTACH_SUMMARY=1`)

**What it does *not* do today (and you want it to):**
- upload the per-suite artifacts (`run.log`, `report.md`, `summary.jsonl`, plus useful diagnostics).

---

## 2) Must-fix issues (these will cost money when tests lie)

### 2.1 Menu ordering bug in SSH interactive menu (✅ broken, 🧪 fix)
The printed menu in `scripts/rj_run_tests.sh` is hardcoded and currently displays in this order:
`1, 2, 12, 13, 3, 4, 5, 6, 11, 7, 8, 9, 10, 0`

**Required behavior:**
- show `1..N` in numeric order
- show `0) All` last
- `0) All` should actually mean “all the things we consider part of All”

### 2.2 “Suite-level only” is not implemented yet (✅ still exposed, 🧪 remove)
Both paths still expose per-subtest variability:

**SSH runner (`scripts/rj_run_tests.sh`)**
- Interactive advanced prompt: `interactive_collect_advanced_options()`
- Raw passthrough flags:
  - `--wireless-arg`, `--ethernet-arg`, `--iface-select-arg`, … (repeatable)
  - these can skip internal subtests and mutate meaning of a “suite”

**UI Configure+Run (`crates/rustyjack-ui/src/app/tests.rs`)**
- Prompts: “Advanced opts”
- If enabled, collects per-suite advanced args and forwards them to `rj_run_tests.sh`.

This makes results non-comparable across devices and runs.

### 2.3 Discord posting lacks per-suite artifacts (✅ missing, 🧪 add)
Right now, Discord tells you “suite failed” but not “here’s the stuff you need to debug it.”

---

## 3) Implementation plan (proposed edits)

### 3.1 Fix SSH menu ordering and “All” semantics
**File:** `watchdog/scripts/rj_run_tests.sh`

**🧪 Plan (simple, robust, no external sort needed):**
1) Replace the menu `echo` block with a declarative table:
   - `SUITES_MENU=( "1|Wireless|--wireless" "2|Ethernet|--ethernet" ... )`
2) Print by iterating the list in numeric order (because the array is already ordered).
3) Print `0) All` last.
4) In `case 0)`, set the exact suite flags that define “All”.

**Decision needed (define “All”):**
- Option A: includes everything including `--discord-test` and `--daemon-deep`
- Option B: includes all *core* suites, but keeps preflight/deep as opt-in prompts

**Recommendation:** Option B (core suites only) *unless* you are using All as a CI gate.
- Keep `--discord-test` separate (it’s a connectivity preflight, not a suite of behavior).
- Keep daemon deep behind a prompt (UI already asks whether to run it).

### 3.2 Remove per-subtest prompts from SSH runner (suite-level only)
**File:** `watchdog/scripts/rj_run_tests.sh`

**🧪 Required changes:**
- Delete (or disable) `interactive_collect_advanced_options()`.
- Remove `--*-arg` passthrough flags from CLI parsing + usage text.
- Remove `*_EXTRA_ARGS` arrays and any logic that forwards them into suite invocations.

**Keep allowed:**
- “Dangerous tests” as a single gated boolean (`--dangerous`) because it changes safety, not meaning.
- Interface selection controls:
  - `--wifi-interface`, `--wifi-interfaces`, `--wifi-all-interfaces`
  - `--eth-interface`, `--eth-interfaces`, `--eth-all-interfaces`
  These are about *which hardware* to target, not which subtests to skip.

### 3.3 Remove per-subtest prompts from UI (Configure+Run flow)
**File:** `watchdog/crates/rustyjack-ui/src/app/tests.rs`

**🧪 Required changes:**
- Remove the “Advanced opts” toggle prompt.
- Remove the call to `collect_advanced_suite_args(...)` and the function itself (or make it unreachable).
- Ensure the args emitted by the UI are:
  - suite flags (`--wireless`, `--ethernet`, … or `--all`)
  - `--dangerous` (only if user explicitly enables)
  - `--ui` (already forced)
  - interface targeting args (wifi/eth selection)

**Guardrail (recommended):**
- Add a run header file in the run root with:
  - runner argv
  - suite list
  - host info (`uname -a`, `rustyjack --version`)
  - interface mode chosen
This makes runs comparable and auditable.

### 3.4 Discord: upload per-suite artifacts after completion

#### 3.4.1 What “upload artifacts” means
For each suite directory (e.g. `$OUTROOT/$RUN_ID/wireless/`), upload at least:
- `run.log`
- `report.md`
- `summary.jsonl`

**Bonus (high value, low risk):**
- `journal/*.log` (or bundle)
- `artifacts/` (bundle)

#### 3.4.2 Recommended payload strategy: one attachment per suite (fast + reliable)
Discord file size limits vary by server settings. Logs can be large. Also, sending 3–10 files per suite increases rate-limit risk.

**Recommendation (preferred):**
- Create a single bundle per suite:
  - `suite_<suite>_<run_id>.tar.gz`
  - contains the entire suite directory (excluding giant core dumps if any)
- Post one Discord message per suite with that bundle attached + a short status text.

This avoids multi-file semantics and minimizes rate limiting.

#### 3.4.3 Where to implement
Implement in the runner, because it already:
- knows the suite label/status/RC/duration
- owns Discord config + webhook discovery
- already sends suite updates

**File:** `watchdog/scripts/rj_run_tests.sh`  
**Hook point:** inside `run_suite()` after the suite completes (where `report_path` and suite dir are known).

**🧪 New function:** `send_discord_suite_artifacts()`
Inputs:
- suite id (directory name)
- suite label
- status/rc/duration
- suite_dir path

Behavior:
1) If Discord disabled or webhook missing → no-op.
2) Create bundle:
   - `bundle="${suite_dir%/}/suite_${suite_id}_${RUN_ID}.tar.gz"`
   - `tar -C "$suite_dir" -czf "$bundle" .`
3) Post message with attachment using multipart form:
   - include `payload_json` (content) and `file1=@${bundle};filename=...`
4) If bundling fails or file too large:
   - fall back to uploading *just* `report.md` (typically small)
   - and include “bundle skipped” in message.

#### 3.4.4 Rate limiting and retries (important)
Discord uses dynamic rate limits and returns HTTP 429 with `Retry-After` header and/or JSON `retry_after`.
You must respect those to avoid blackholing notifications.

**🧪 Minimal implementation in bash without new dependencies:**
- Update `post_discord_payload_json()` and the “attachment curl” to:
  - capture HTTP status code and response body
  - if status == 429:
    - parse `retry_after` from JSON body via `grep/sed` (or read `Retry-After` header)
    - `sleep` for that duration + small jitter (e.g., +0.2s)
    - retry up to N times (e.g., 5)

(If you later migrate Discord posting into Rust `reqwest`, do it there; the runner can call `rustyjack notify discord ...` instead of curl.)

#### 3.4.5 Discord formatting constraints you must follow
- Message content is limited to 2000 characters.
- File uploads must use `multipart/form-data` and send JSON as `payload_json` when uploading a file.

(See Discord API docs references at end of this document.)

---

## 4) UI puppeting additions (suite-by-suite recommendations)

### 4.1 General rules for UI puppeting
- Puppeting must produce **assertions**, not “no crash”.
- Every UI automation step must have:
  - a clear start state (UI on home screen or known menu)
  - a bounded timeout
  - a post-condition check (log marker, IPC state, config file diff)

### 4.2 Suites that already puppet the UI (keep, but strengthen assertions)
- Wireless / Ethernet / Interface Selection / Encryption / Loot / Theme

**🧪 Improvements (recommended):**
- For scenario-driven suites:
  - ensure scenario begins with “go home” normalization (e.g., repeated `back`)
  - capture UI journal log around the scenario
- For Theme:
  - convert ad-hoc `rj_ui_send` sequences into a `.ui` scenario file
  - assert config diff or UI log line about applied theme

### 4.3 Suites currently without UI puppeting
**USB**
- Likely has UI flows (export logs, export loot).
- Add a scenario that navigates to export action.
- Assertions:
  - detect mountpoint
  - exported bundle exists
  - UI log includes success marker

**UI Layout**
- If UI exposes a layout / display config menu:
  - scenario: open layout, toggle setting, apply, return
  - assert config changed (hash before/after) and/or daemon event logged

**MAC Randomization**
- Only puppet if UI has a dedicated MAC action.
- Assertions:
  - MAC changes on interface and then restores
  - interface remains up (avoid bricking connectivity)

**Daemon / IPC**
- Usually better as non-UI validation.
- If there is a “daemon status” screen:
  - puppet open status
  - assert that daemon replies with expected state (via IPC log markers)

---

## 5) Test thoroughness and determinism (suite-by-suite guidance)

> This section focuses on *value* and *Pi reliability*. The goal is not “more tests”; it’s “more signal per minute.”

### 5.1 Wireless
**Watch-outs:** flaky Wi‑Fi, scan variability, RF environment noise.
**Recommended deterministic checks:**
- interface exists + is up
- wpa_supplicant / NetworkManager status (whichever is used)
- local-only checks (no internet dependency) by default
- if internet checks exist: gate behind explicit env/flag and report as SKIP when unavailable

### 5.2 Ethernet
**Watch-outs:** USB Ethernet adapters, link negotiation delays.
**Recommended deterministic checks:**
- carrier state + link speed if available
- DHCP lease acquisition bounded by timeout
- avoid external ping; prefer gateway ARP presence / local ping only

### 5.3 Interface Selection
**Risks:** switching default interface can strand remote access.
**Required isolation:**
- always record “previous active interface”
- always restore on exit (trap)
- avoid restarting network stack without an escape hatch (timeout + restore)

### 5.4 Encryption
**High flake risk (today):**
- timing of key generation and UI acceptance can race
- ensure tests don’t permanently lock out access

**Recommended changes:**
- explicit timeouts
- confirm state transitions from durable state (config file or daemon state), not just command exit code

### 5.5 Loot
**Determinism:**
- avoid reliance on device-specific state; use temporary fixtures when possible
- ensure cleanup so repeated runs don’t compound

### 5.6 MAC Randomization
**Risks:** can drop connectivity or confuse DHCP.
**Required:**
- pre/post MAC captured
- bounded wait for link to recover
- restore MAC in `trap` even on failure

### 5.7 Daemon + Deep Daemon
**Recommendation:**
- Keep “deep” behind explicit opt-in (it’s long and noisy)
- Assert:
  - daemon is running under systemd
  - IPC responds
  - permissions and socket ownership correct
- Capture `journalctl -u rustyjack-daemon` consistently.

### 5.8 Installers
**Goal:** catch regressions without actually reinstalling the world.
**Recommended:**
- lint shell scripts
- verify expected files exist after install (in a sandbox / temp root if supported)
- avoid network fetches unless gated

### 5.9 USB
**Determinism:**
- tests should SKIP if no USB device mounted
- do not auto-mount unknown devices without explicit user opt-in
- verify read/write with a small file and checksum

### 5.10 UI Layout + Theme
**Goal:** “UI doesn’t go weird on small screens.”
**Deterministic assertions:**
- config file diffs
- ensure UI can render and respond to input after change
- capture UI logs

---

## 6) Shell correctness + robustness checklist (apply as you touch scripts)
- Keep `set -euo pipefail` (already present in runner).
- Quote everything (`"$var"`) unless you truly want word splitting.
- Use `trap` for:
  - restoring interfaces
  - disabling UI vinput
  - cleaning temporary files
- Use explicit timeouts for anything that could hang:
  - `systemctl restart ...`
  - network operations
  - long-running daemon diagnostics
- When a dependency is missing, prefer **SKIP** with a clear reason over FAIL.

---

## 7) Verification steps (concrete commands)

### 7.1 Validate ordering + selection
SSH:
```bash
cd watchdog/scripts
./rj_run_tests.sh
# visually confirm: 1..N then 0=All last
```

CLI parity:
```bash
./rj_run_tests.sh --wireless --ethernet --ui
./rj_run_tests.sh --all --ui
```

UI parity:
- Main Menu → Tests → Configure + Run → select Wireless/Ethernet → run
- Confirm the emitted suite list matches the CLI behavior.

### 7.2 Validate “suite-level only”
- SSH runner:
  - `./rj_run_tests.sh --help` should show no `--*-arg` options
  - interactive should not ask about “advanced opts”
- UI:
  - Configure + Run should not prompt “Advanced opts”
  - runs should not include passthrough flags

### 7.3 Validate UI puppeting
Run a suite that uses scenarios:
```bash
RJ_OUTROOT=/var/tmp/rustyjack-tests RJ_RUN_ID=devtest ./rj_run_tests.sh --wireless --ui
```
Confirm:
- UI service gets restarted and vinput FIFO exists
- suite artifacts include logs showing scenario playback

### 7.4 Validate Discord suite artifact upload
Set a webhook URL:
```bash
export RJ_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/...."
```

Run a single suite:
```bash
./rj_run_tests.sh --wireless --ui --discord-enable
```

Confirm in Discord:
- suite update message arrives
- suite artifacts attachment arrives (bundle or individual files)
- attachment filename includes suite + run id
- message content stays under 2000 chars

### 7.5 Validate rate limit behavior (synthetic)
- Temporarily point webhook to a local HTTP server that returns 429 with a `retry_after` payload and ensure the sender sleeps + retries and eventually succeeds (or gives a clear warning).

---

## 8) References (Discord API docs)
These are the authoritative behaviors you must match.

```text
Webhook “Execute Webhook” (multipart + payload_json + content<=2000):
https://raw.githubusercontent.com/discord/discord-api-docs/34eee1887e3eba1c23ba0a3fccb7c119f05ea7cb/docs/resources/Webhook.md

Rate limits (HTTP 429, Retry-After header, retry_after field):
https://raw.githubusercontent.com/discord/discord-api-docs/294b3ec67334b2e9a8a0e5e3113f8828605ed288/docs/topics/Rate_Limits.md
```
