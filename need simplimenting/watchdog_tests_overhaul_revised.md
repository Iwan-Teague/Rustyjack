# Watchdog (Pi Zero 2 W) Test Suite Overhaul + Discord Artifacts Upload

**Audience:** engineers maintaining the Pi test system (SSH runner + Rust UI/daemon).
**Goal:** deterministic, maintainable tests on Pi hardware + reliable Discord reporting that includes the *actual* artifacts needed to debug failures.

**Repo reviewed:** RustyJack `main` branch, commit `2a543de` (2026-02-15).
**This doc consolidates:** current verified behavior *and* the recommended edits to implement the requested UX + Discord uploads.

Legend:
- ✅ **Verified**: confirmed against repo code with file:line citations.
- 🧪 **Proposed**: not implemented yet; includes concrete file/function targets and implementation guidance.

---

## 0) Non-negotiables (system behavior we want)
1) **SSH runner and UI must run the same suites with the same semantics.**
2) **Suite selection only**: users choose *suites*, not internal subtest toggles.
3) **Tests must be reproducible**: explicit timeouts, retries only where justified, and clear `PASS/FAIL/SKIP`.
4) **Pi realities**: slow CPU, limited RAM, flaky Wi‑Fi, `systemd`/`journald` timing quirks, occasional SD card hiccups.
5) **Discord is an observability sink, not a "nice to have"**: after each suite, ship enough artifacts to debug without SSH'ing into the device.

---

## 1) Current reality (verified)

### 1.1 Where things live (✅)
| What | Path |
|------|------|
| Suite scripts | `scripts/rj_test_*.sh` |
| Deep daemon diagnostics | `scripts/rustyjack_comprehensive_test.sh` |
| Shared harness | `scripts/rj_test_lib.sh` |
| SSH runner | `scripts/rj_run_tests.sh` |
| UI "Tests" flows | `crates/rustyjack-ui/src/app/tests.rs` |
| Daemon job that spawns the runner | `crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs` |
| UI puppeting scenarios | `scripts/ui_scenarios/*.ui` |
| "Run all" wrapper | `scripts/rj_test_all.sh` (exec's `rj_run_tests.sh --all`) |

### 1.2 Artifacts layout (✅)
`scripts/rj_test_lib.sh` provides `rj_init <suite>` (`rj_test_lib.sh:12-35`) and creates per-suite output under:
- `$RJ_OUTROOT/$RJ_RUN_ID/<suite>/`
  - `run.log`
  - `summary.jsonl`
  - `report.md`
  - `artifacts/`
  - `journal/`

The SSH runner (`rj_run_tests.sh`) writes a *run-level* summary:
- `$OUTROOT/$RUN_ID/run_summary.md` (`rj_run_tests.sh:326`)
- `$OUTROOT/$RUN_ID/run_summary.json` (`rj_run_tests.sh:327`)

Defaults:
- SSH runner default outroot: `/var/tmp/rustyjack-tests` (`rj_run_tests.sh:23`)
- UI/daemon runs typically use: `/var/lib/rustyjack/tests` (`tests.rs:95`, `ui_test_run.rs:103`)

### 1.3 UI automation / puppeting mechanism (✅)
`rj_test_lib.sh` implements UI puppeting by:
- Creating FIFO: `/run/rustyjack/ui_input.fifo` (`rj_test_lib.sh:463`)
- Writing systemd drop-in: `/run/systemd/system/rustyjack-ui.service.d/50-virtual-input.conf` (`rj_test_lib.sh:464-482`)
  - sets `Environment=RUSTYJACK_UI_VINPUT=$fifo`
- Restarting `rustyjack-ui.service` to pick up the env var (`rj_test_lib.sh:484-487`)
- Playing scenario files via `rj_ui_run_scenario <file>` which writes `up/down/left/right/select/key1/key2/key3` commands into the FIFO (`rj_test_lib.sh:521-551`).

**Note:** The spec previously claimed `back` was a recognized FIFO command. This is incorrect — the recognized commands are: `sleep/wait`, `up/down/left/right/select/key1/key2/key3`. Scenarios use `left` to navigate back.

### 1.4 Suites that currently puppet the UI (✅)
**Scenario-driven (`rj_ui_run_scenario`):**
- Wireless → `scripts/ui_scenarios/wireless.ui` (`rj_test_wireless.sh:344`)
- Ethernet → `scripts/ui_scenarios/ethernet.ui` (`rj_test_ethernet.sh:297`)
- Interface selection → `scripts/ui_scenarios/interface_selection.ui` (`rj_test_interface_selection.sh:573`)
- Encryption → `scripts/ui_scenarios/encryption.ui` (`rj_test_encryption.sh:174`)
- Loot → `scripts/ui_scenarios/loot.ui` (`rj_test_loot.sh:144`)

**Direct key injection (`rj_ui_send`):**
- Theme → `rj_test_theme.sh:249-304` (scripted key presses, no `.ui` scenario file)

**No UI puppeting today:**
- Installers, USB, UI layout/display, MAC randomization, Daemon/IPC, Discord test, Daemon deep

### 1.5 Discord notifications (current behavior) (✅)
The **runner** `scripts/rj_run_tests.sh` already:
- Discovers/stages a webhook URL via three sources (`rj_run_tests.sh:214-245`):
  - `--discord-webhook URL` CLI flag
  - Runtime file: `${RJ_RUNTIME_ROOT:-/var/lib/rustyjack}/discord_webhook.txt`
  - Repo default: `scripts/defaults/discord_webhook.txt`
- Posts:
  - Per-suite text status updates via `send_discord_suite_update()` (`rj_run_tests.sh:449-471`)
  - A final run summary via `send_discord_summary()` (`rj_run_tests.sh:390-447`)
    - Attaches `run_summary.md` via multipart/form-data when `RJ_DISCORD_WEBHOOK_ATTACH_SUMMARY=1` (default)
    - Uses `payload_json` + `file1=@...` correctly for multipart uploads

**What it does *not* do today (and you want it to):**
- Upload per-suite artifacts (`run.log`, `report.md`, `summary.jsonl`, plus diagnostics) — text-only update sent instead.
- Check or enforce 2000-character content limit on messages.
- Handle HTTP 429 rate-limit responses (retry_after / Retry-After).

---

## 2) Must-fix issues (these will cost money when tests lie)

### 2.1 Menu ordering bug in SSH interactive menu (✅ broken, 🧪 fix)
The printed menu in `scripts/rj_run_tests.sh:773-787` is hardcoded and currently displays:
```
  1) Wireless
  2) Ethernet
 12) Interface Selection
 13) Discord Webhook Preflight
  3) Encryption
  4) Loot
  5) MAC Randomization
  6) Daemon/IPC
 11) Daemon Deep Diagnostics
  7) Installers
  8) USB Mount
  9) UI Layout/Display
 10) Theme/Palette
  0) All
```

The numbers jump: 1, 2, 12, 13, 3, 4, 5, 6, 11, 7, 8, 9, 10, 0.

**Required behavior:**
- Show `1..N` in numeric order
- Show `0) All` last
- `0) All` should include core suites only (see §3.1)

### 2.2 "Suite-level only" is not implemented yet (✅ still exposed, 🧪 remove)
Both paths still expose per-subtest variability:

**SSH runner (`scripts/rj_run_tests.sh`)**
- Interactive advanced prompt: `interactive_collect_advanced_options()` (`rj_run_tests.sh:499-682`, ~180 lines)
- Raw passthrough flags (`rj_run_tests.sh:98-110` in usage, `rj_run_tests.sh:841-853` in parser):
  - `--wireless-arg`, `--ethernet-arg`, `--iface-select-arg`, `--encryption-arg`, `--loot-arg`, `--mac-arg`, `--daemon-arg`, `--daemon-deep-arg`, `--discord-test-arg`, `--installers-arg`, `--usb-arg`, `--ui-layout-arg`, `--theme-arg` (repeatable)
  - These can skip internal subtests and mutate meaning of a "suite"
- `*_EXTRA_ARGS` arrays: `rj_run_tests.sh:31-43` — 13 arrays declared and forwarded at suite invocation sites

**UI Configure+Run (`crates/rustyjack-ui/src/app/tests.rs`)**
- "Advanced opts" toggle prompt: `tests.rs:209-215`
- `collect_advanced_suite_args()`: `tests.rs:545-728` — full per-suite subtest toggle UI
- `collect_skip_group()`: `tests.rs:730-747` — helper that builds `--*-arg` passthrough flags

This makes results non-comparable across devices and runs.

### 2.3 Discord posting lacks per-suite artifacts (✅ missing, 🧪 add)
`send_discord_suite_update()` (`rj_run_tests.sh:449-471`) sends a text-only message. No bundle, no files attached. The spec's primary deliverable — per-suite artifact upload — is not implemented.

### 2.4 No 429 rate-limit handling (✅ missing, 🧪 add)
All Discord curl calls discard HTTP status codes:
- `post_discord_payload_json()` (`rj_run_tests.sh:262-265`): pipes to `/dev/null`
- `send_discord_summary()` (`rj_run_tests.sh:431-434`): pipes to `/dev/null`

A 429 response from curl returns exit code 0, so `if ! curl` won't detect it. Messages silently vanish.

### 2.5 No content-length enforcement (✅ missing, 🧪 add)
No function checks that Discord `content` stays under 2000 characters. Long report paths or mention strings can easily overflow. Discord will reject with HTTP 400.

---

## 3) Implementation plan (proposed edits)

### 3.1 Fix SSH menu ordering and "All" semantics
**File:** `scripts/rj_run_tests.sh`

**🧪 Plan:**
1. Replace the menu `echo` block (lines 773-787) with a declarative table:
   ```bash
   SUITES_MENU=(
     "1|Wireless|--wireless"
     "2|Ethernet|--ethernet"
     "3|Interface Selection|--iface-select"
     "4|Encryption|--encryption"
     "5|Loot|--loot"
     "6|MAC Randomization|--mac"
     "7|Daemon/IPC|--daemon"
     "8|Daemon Deep Diagnostics|--daemon-deep"
     "9|Installers|--installers"
     "10|USB Mount|--usb"
     "11|UI Layout/Display|--ui-layout"
     "12|Theme/Palette|--theme"
     "13|Discord Webhook Preflight|--discord-test"
   )
   ```
2. Print by iterating the list in array order (already numeric).
3. Print `0) All` last.
4. In `case 0)`, set the core suites (current behavior is correct — all except DaemonDeep and DiscordTest).

**"All" definition (verified — matches Option B):**
- ✅ Already includes: Wireless, Ethernet, InterfaceSelect, Encryption, Loot, Mac, Daemon, Installers, USB, UiLayout, Theme
- ✅ Already excludes: DaemonDeep (opt-in via prompt), DiscordTest (auto-enabled as preflight when webhook configured, lines 911-918)
- No change needed to "All" semantics, just menu presentation.

### 3.2 Remove per-subtest prompts from SSH runner (suite-level only)
**File:** `scripts/rj_run_tests.sh`

**🧪 Required changes:**
1. **Delete** `interactive_collect_advanced_options()` (lines 499-682)
2. **Delete** `*_EXTRA_ARGS` array declarations (lines 31-43)
3. **Delete** `--*-arg` flags from:
   - `usage()` text (lines 98-110)
   - CLI parser `case` block (lines 841-853)
4. **Delete** `*_EXTRA_ARGS` forwarding from all `run_suite` invocations (lines 1033-1101)
5. **Delete** the call to `interactive_collect_advanced_options` (line 769)

**Keep allowed:**
- `--dangerous` (safety gate, not subtest selector)
- Interface selection controls: `--wifi-interface`, `--wifi-interfaces`, `--wifi-all-interfaces`, `--eth-interface`, `--eth-interfaces`, `--eth-all-interfaces`
- Individual suite scripts MAY still accept developer flags (e.g., `--no-unit`) for direct invocation, but the runner and UI do not surface them.

### 3.3 Remove per-subtest prompts from UI (Configure+Run flow)
**File:** `crates/rustyjack-ui/src/app/tests.rs`

**🧪 Required changes:**
1. **Delete** the "Advanced opts" toggle block (lines 209-218)
2. **Delete** `collect_advanced_suite_args()` (lines 545-728)
3. **Delete** `collect_skip_group()` (lines 730-747)
4. Ensure the args emitted by the UI are limited to:
   - Suite flags (`--wireless`, `--ethernet`, … or `--all`)
   - `--dangerous` (only if user explicitly enables)
   - `--ui` (already forced, line 184)
   - Interface targeting args (wifi/eth selection)
   - `--daemon-deep` (if user opts in, lines 186-199)

**🧪 Guardrail (recommended):**
Add a run header file in the run root with:
- runner argv
- suite list
- host info (`uname -a`, `rustyjack --version`)
- interface mode chosen

This makes runs comparable and auditable.

### 3.4 Discord: upload per-suite artifacts after completion

#### 3.4.1 What "upload artifacts" means
For each suite directory (e.g., `$OUTROOT/$RUN_ID/wireless/`), upload at least:
- `run.log`
- `report.md`
- `summary.jsonl`

**Bonus (high value, low risk):**
- `journal/*.log` (or bundle)
- `artifacts/` (bundle)

#### 3.4.2 Recommended payload strategy: one bundle per suite
Discord file size limits vary by server settings. Logs can be large. Sending 3–10 files per suite increases rate-limit risk.

**Recommendation:**
- Create a single bundle per suite:
  - `suite_<suite_id>_<run_id>.tar.gz`
  - Contains the entire suite directory (excluding core dumps >10MB)
- Post one Discord message per suite with that bundle attached + a short status text.

#### 3.4.3 Where to implement
**File:** `scripts/rj_run_tests.sh`
**Hook point:** Inside `run_suite()` after line 988 (after `send_discord_suite_update()`).

**🧪 New function: `send_discord_suite_artifacts()`**

Inputs:
- `suite_id` (directory name)
- `suite_label`
- `status/rc/duration`
- `suite_dir` path

Behavior:
1. If Discord disabled or webhook missing → no-op (use `discord_can_send`).
2. Create bundle:
   ```bash
   bundle="${suite_dir}/suite_${suite_id}_${RUN_ID}.tar.gz"
   tar -C "$suite_dir" -czf "$bundle" \
     --exclude='*.core' --exclude='*.tar.gz' .
   ```
3. Check bundle size. If >8MB (Discord default limit):
   - Fall back to uploading just `report.md`
   - Include "bundle too large, uploading report only" in message
4. Post message with attachment using `discord_curl_with_retry`:
   ```bash
   local content
   content="Suite: ${suite_label} [${status}] (rc=${rc}, ${duration})"
   content="$(discord_truncate_content "$content")"
   local pj
   pj="{\"content\":\"$(json_escape "$content")\""
   [[ -n "$DISCORD_WEBHOOK_USERNAME" ]] && \
     pj+=",\"username\":\"$(json_escape "$DISCORD_WEBHOOK_USERNAME")\""
   pj+="}"
   discord_curl_with_retry \
     -F "payload_json=$pj" \
     -F "file1=@${bundle};filename=suite_${suite_id}_${RUN_ID}.tar.gz"
   ```
5. If bundling fails: fall back to text-only with warning.

#### 3.4.4 Rate limiting and retries (MUST implement)

**🧪 New function: `discord_curl_with_retry()`**

```bash
discord_curl_with_retry() {
  local max_retries=5
  local attempt=0
  local http_code body tmpfile

  tmpfile="$(mktemp)"
  trap "rm -f '$tmpfile'" RETURN

  while [[ $attempt -lt $max_retries ]]; do
    attempt=$((attempt + 1))
    http_code="$(curl -sS -o "$tmpfile" -w '%{http_code}' \
      -X POST "$DISCORD_WEBHOOK_URL" "$@")"

    if [[ "$http_code" == "429" ]]; then
      local retry_after
      # Try JSON body first (more precise, float value)
      retry_after="$(grep -oP '"retry_after"\s*:\s*\K[0-9.]+' "$tmpfile" 2>/dev/null || true)"
      # Fall back to Retry-After header (not available with -o, use header capture if needed)
      if [[ -z "$retry_after" ]]; then
        retry_after="5"  # conservative default
      fi
      # Add jitter
      local wait_secs
      wait_secs="$(printf '%.0f' "$(echo "$retry_after + 0.5" | bc 2>/dev/null || echo "$((${retry_after%.*} + 1))")")"
      echo "[WARN] Discord rate limited (429). Waiting ${wait_secs}s before retry ${attempt}/${max_retries}."
      sleep "$wait_secs"
      continue
    fi

    if [[ "$http_code" =~ ^2 ]]; then
      return 0
    fi

    echo "[WARN] Discord returned HTTP ${http_code} on attempt ${attempt}/${max_retries}."
    if [[ $attempt -lt $max_retries ]]; then
      sleep 2
    fi
  done

  echo "[WARN] Discord upload failed after ${max_retries} attempts."
  return 1
}
```

**Also update:** `post_discord_payload_json()` and `send_discord_summary()` to use `discord_curl_with_retry` instead of raw curl calls.

#### 3.4.5 Content-length enforcement (MUST implement)

**🧪 New helper: `discord_truncate_content()`**

```bash
discord_truncate_content() {
  local s="$1"
  if [[ ${#s} -gt 2000 ]]; then
    s="${s:0:1985}…[truncated]"
  fi
  printf '%s' "$s"
}
```

Call this on all `content` strings before JSON encoding.

#### 3.4.6 Discord formatting constraints
- Message content limited to **2000 characters** (Discord Webhook.md).
- File uploads **MUST** use `multipart/form-data` with `payload_json` for the JSON body (Discord Webhook.md).
- Text-only messages MAY use `Content-Type: application/json` (current behavior is correct).
- Rate-limited responses return HTTP 429 with `Retry-After` header and/or `retry_after` JSON field (Discord Rate_Limits.md).
- Upload failures MUST NOT mark test suites as PASS (current behavior is correct — Discord is fire-and-forget).

---

## 4) UI puppeting additions (suite-by-suite recommendations)

### 4.1 General rules for UI puppeting
- Puppeting must produce **assertions**, not "no crash."
- Every UI automation step must have:
  - A clear start state (UI on home screen or known menu)
  - A bounded timeout
  - A post-condition check (log marker, IPC state, config file diff)

### 4.2 Suites that already puppet the UI (keep, but strengthen assertions)
- Wireless / Ethernet / Interface Selection / Encryption / Loot / Theme

**🧪 Improvements (recommended):**
- For all scenario-driven suites: prepend "go home" normalization to each `.ui` file:
  ```
  # Normalize: return to main menu
  left 5
  sleep 0.3
  ```
  This prevents cascading failures when the previous test leaves the UI in an unexpected state.
- For each scenario: capture UI journal log around the scenario and check for error markers.
- For Theme (`rj_test_theme.sh`): convert ad-hoc `rj_ui_send` sequences (lines 249-304) into a `scripts/ui_scenarios/theme.ui` scenario file and call via `rj_ui_run_scenario`. Assert config diff or UI log line about applied theme.

### 4.3 Suites currently without UI puppeting
**USB**
- Add a scenario that navigates to export action.
- Assertions: detect mountpoint, exported bundle exists, UI log includes success marker.

**UI Layout**
- If UI exposes a layout/display config menu: scenario opens it, toggles a setting, applies, returns.
- Assert config changed (hash before/after) and/or daemon event logged.

**MAC Randomization**
- Only puppet if UI has a dedicated MAC action.
- Assertions: MAC changes on interface and then restores, interface remains up.

**Daemon / IPC**
- Usually better as non-UI validation.
- If there is a "daemon status" screen: puppet open status, assert daemon replies.

---

## 5) Test thoroughness and determinism (suite-by-suite guidance)

> Goal: "more signal per minute," not "more tests."

### 5.1 Wireless
**Watch-outs:** flaky Wi‑Fi, scan variability, RF environment noise.
**Recommended deterministic checks:**
- Interface exists + is up
- wpa_supplicant / NetworkManager status
- Local-only checks (no internet dependency) by default
- If internet checks exist: gate behind explicit env/flag, report as SKIP when unavailable

### 5.2 Ethernet
**Watch-outs:** USB Ethernet adapters, link negotiation delays.
**Recommended deterministic checks:**
- Carrier state + link speed if available
- DHCP lease acquisition bounded by timeout
- Avoid external ping; prefer gateway ARP presence / local ping

### 5.3 Interface Selection
**Risks:** switching default interface can strand remote access.
**Required isolation:**
- Always record "previous active interface"
- Always restore on exit (trap)
- Avoid restarting network stack without escape hatch (timeout + restore)

### 5.4 Encryption
**High flake risk:**
- Timing of key generation and UI acceptance can race
- Ensure tests don't permanently lock out access
**Recommended:** Explicit timeouts, confirm state transitions from config file or daemon state, not just command exit code.

### 5.5 Loot
**Determinism:** Use temporary fixtures, ensure cleanup so repeated runs don't compound.

### 5.6 MAC Randomization
**Risks:** Can drop connectivity or confuse DHCP.
**Required:** pre/post MAC captured, bounded wait for link recovery, restore MAC in `trap`.

### 5.7 Daemon + Deep Daemon
- Keep "deep" behind explicit opt-in (already the case)
- Assert: daemon running under systemd, IPC responds, permissions/socket ownership correct
- Capture `journalctl -u rustyjackd` consistently

### 5.8 Installers
- Lint shell scripts, verify expected files exist, avoid network fetches unless gated.

### 5.9 USB
- SKIP if no USB device mounted, do not auto-mount unknown devices.
- Verify read/write with small file + checksum.

### 5.10 UI Layout + Theme
- Config file diffs, ensure UI can render and respond to input after change, capture UI logs.

---

## 6) Shell correctness + robustness checklist

These apply to all scripts in `scripts/rj_test_*.sh` and `scripts/rj_run_tests.sh`:

- ✅ `set -euo pipefail` present in runner and all test scripts (verified)
- Quote all variables (`"$var"`) unless word splitting is intentional
- Use `trap` for: restoring interfaces, disabling UI vinput, cleaning temporary files
- Use explicit timeouts for anything that could hang (`systemctl restart`, network operations)
- Missing dependency → **SKIP** with clear reason, not FAIL
- 🧪 Fix: `rj_summary_event()` (`rj_test_lib.sh:206`) — fallback JSON path doesn't escape special characters. Add escape or always require python3.

---

## 7) Verification steps (concrete commands)

### 7.1 Validate ordering + selection
SSH (after implementing §3.1):
```bash
cd scripts
./rj_run_tests.sh
# Verify: menu shows 1..13 in numeric order, then 0=All last
```

CLI parity:
```bash
./rj_run_tests.sh --wireless --ethernet --ui
./rj_run_tests.sh --all --ui
```

UI parity:
- Main Menu → Tests → Configure + Run → select Wireless/Ethernet → run
- Confirm the emitted suite list matches the CLI behavior.

### 7.2 Validate "suite-level only"
After implementing §3.2 and §3.3:

SSH runner:
```bash
./rj_run_tests.sh --help
# Verify: no --*-arg options shown
# Verify: --dangerous, --wifi-interface, --eth-interface etc. are still present
```
```bash
./rj_run_tests.sh --wireless-arg foo 2>&1
# Verify: "Unknown arg: --wireless-arg" error
```

Interactive:
```bash
./rj_run_tests.sh
# Select wireless (1), verify NO "advanced per-suite options" prompt appears
```

UI:
- Configure + Run → select any suite
- Verify: no "Advanced opts" prompt appears
- Verify: emitted args contain only suite flags + --dangerous + --ui + interface targeting

### 7.3 Validate UI puppeting
Run a suite that uses scenarios:
```bash
RJ_OUTROOT=/var/tmp/rustyjack-tests RJ_RUN_ID=devtest ./rj_run_tests.sh --wireless --ui
```
Confirm:
- UI service gets restarted and vinput FIFO exists (`ls -la /run/rustyjack/ui_input.fifo`)
- Suite artifacts include logs showing scenario playback
- UI returned to home screen after scenario (check journal)

### 7.4 Validate Discord suite artifact upload
After implementing §3.4:

Set a webhook URL:
```bash
export RJ_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```

Run a single suite:
```bash
./rj_run_tests.sh --wireless --ui --discord-enable
```

Confirm in Discord:
- Suite text status message arrives
- Suite artifact bundle attachment arrives (`suite_wireless_<run_id>.tar.gz`)
- Final run summary with `run_summary.md` attachment arrives
- All message `content` fields are ≤2000 characters
- Attachment filename includes suite ID + run ID

Confirm locally:
```bash
ls -la /var/tmp/rustyjack-tests/*/wireless/suite_wireless_*.tar.gz
# Bundle exists and is non-empty
tar tzf /var/tmp/rustyjack-tests/*/wireless/suite_wireless_*.tar.gz
# Contains: run.log, report.md, summary.jsonl, artifacts/, journal/
```

### 7.5 Validate rate-limit behavior (synthetic)
After implementing §3.4.4:

Start a local HTTP server that returns 429:
```bash
# In one terminal:
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class Handler(BaseHTTPRequestHandler):
    count = 0
    def do_POST(self):
        Handler.count += 1
        if Handler.count <= 2:
            body = json.dumps({'message': 'rate limited', 'retry_after': 1.5, 'global': False})
            self.send_response(429)
            self.send_header('Retry-After', '2')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(204)
            self.end_headers()
    def log_message(self, *args): pass

HTTPServer(('127.0.0.1', 9999), Handler).serve_forever()
"
```

```bash
# In another terminal:
RJ_DISCORD_WEBHOOK_URL="http://127.0.0.1:9999/test" ./rj_run_tests.sh --installers --discord-enable 2>&1 | grep -i discord
# Verify: "[WARN] Discord rate limited (429). Waiting 2s" appears twice
# Verify: upload eventually succeeds on third attempt
# Verify: suite status is not affected by Discord retry behavior
```

### 7.6 Validate content truncation
```bash
# Create a webhook test with a very long mention string
RJ_DISCORD_WEBHOOK_MENTION="$(python3 -c 'print("@" * 2100)')" \
  ./rj_run_tests.sh --installers --discord-enable 2>&1
# Verify: no HTTP 400 errors from Discord
# Verify: message arrives truncated but readable
```

---

## 8) References (Discord API docs)
These are the authoritative behaviors your implementation must match.

- **Execute Webhook** (multipart + payload_json + content≤2000):
  https://raw.githubusercontent.com/discord/discord-api-docs/34eee1887e3eba1c23ba0a3fccb7c119f05ea7cb/docs/resources/Webhook.md

- **Rate Limits** (HTTP 429, Retry-After header, retry_after field):
  https://raw.githubusercontent.com/discord/discord-api-docs/294b3ec67334b2e9a8a0e5e3113f8828605ed288/docs/topics/Rate_Limits.md

Key requirements extracted:
| Rule | Source |
|------|--------|
| `content` ≤ 2000 characters | Webhook.md |
| File uploads require `multipart/form-data` | Webhook.md |
| Use `payload_json` for JSON body when uploading files | Webhook.md |
| On 429: read `Retry-After` header OR `retry_after` JSON field | Rate_Limits.md |
| `retry_after` is a float (seconds) | Rate_Limits.md |
| Never hard-code rate limits | Rate_Limits.md |
| Excessive invalid requests may trigger IP-level restrictions | Rate_Limits.md |
