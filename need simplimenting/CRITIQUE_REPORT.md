# Critique Report: watchdog_tests_overhaul_final.md

**Reviewer:** Claude Opus 4.6 expert review
**Date:** 2026-02-15
**Repo:** RustyJack (commit 2a543de, branch main)
**Spec reviewed:** `need simplimenting/watchdog_tests_overhaul_final.md`

---

## A) High-Risk Issues (Must-Fix)

### H1. No Discord 429 Rate-Limit Handling Anywhere

**Severity:** HIGH — will blackhole notifications on busy webhooks or multi-suite runs.

**Code:**
- `scripts/rj_run_tests.sh:260-269` — `post_discord_payload_json()` fires curl and discards the HTTP status code entirely:
  ```bash
  if ! curl -sS -X POST "$DISCORD_WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d "$payload_json" \
    >/dev/null; then
    return 1
  fi
  ```
- `scripts/rj_run_tests.sh:431-434` — `send_discord_summary()` attachment upload also discards response.
- `scripts/rj_run_tests.sh:462` — `send_discord_suite_update()` calls `send_discord_text_message()` which calls `post_discord_payload_json()`.

**Discord requirement (per Rate_Limits.md):**
> "Your application should rely on the `Retry-After` header or `retry_after` field to determine when to retry the request."

A 429 response from curl will return HTTP 429 (success from curl's perspective, exit code 0), so the current `if ! curl` check won't even detect it. Messages will silently vanish.

**Fix:** Replace `post_discord_payload_json()` and all curl-based Discord calls with a wrapper that:
1. Captures HTTP status via `curl -w '%{http_code}'`
2. On 429: parses `retry_after` from JSON body (or `Retry-After` header via `-D`)
3. Sleeps for `retry_after + 0.5s` jitter
4. Retries up to 5 times
5. Logs a clear warning on exhaustion

---

### H2. No Content-Length Check (2000-char Discord limit)

**Severity:** HIGH — oversized messages will be rejected by Discord API (HTTP 400).

**Code:** All message-building functions (`send_discord_text_message`, `send_discord_suite_update`, `send_discord_summary`) construct `content` strings with no length check.

In `send_discord_suite_update()` (line 463-470), the content includes host, run ID, timestamps, report paths. If report paths are long or mention text is large, this easily exceeds 2000 chars.

**Discord requirement (per Webhook.md):**
> content: "the message contents (up to 2000 characters)"

**Fix:** Before JSON-encoding `content`, truncate to 2000 chars with an ellipsis marker. Add a helper:
```bash
discord_truncate_content() {
  local s="$1"
  if [[ ${#s} -gt 2000 ]]; then
    s="${s:0:1990}…[truncated]"
  fi
  printf '%s' "$s"
}
```

---

### H3. Per-Suite Artifact Upload Missing

**Severity:** HIGH — the primary deliverable of this spec is not implemented.

**Spec claim (§3.4):** "🧪 New function: `send_discord_suite_artifacts()`"
**Code reality:** No such function exists. `run_suite()` (line 938-989) calls `send_discord_suite_update()` which sends a text-only message with no file attachment.

**Fix:** Implement `send_discord_suite_artifacts()` as described in the spec, called from `run_suite()` after line 988. Must:
1. Create `tar.gz` bundle of suite directory
2. Upload via multipart/form-data with `payload_json` + `file1=@bundle`
3. Handle rate limits (see H1)
4. Fall back to `report.md`-only upload if bundle is too large

---

### H4. Menu Ordering Bug Confirmed, Not Fixed

**Severity:** HIGH — confusing UX, spec says "must-fix" but code is unchanged.

**Code:** `scripts/rj_run_tests.sh:773-804` — hardcoded echo block:
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

Numbers are not sequential (1, 2, 12, 13, 3, 4, ...). This is exactly the bug described in spec §2.1 but not yet fixed.

**Fix:** Replace with declarative `SUITES_MENU` array as spec recommends. Renumber 1..13 sequentially, 0=All last.

---

### H5. Per-Subtest Prompts Still Fully Exposed

**Severity:** HIGH — spec §2.2 says "must-fix", code is unchanged.

**SSH runner:**
- `interactive_collect_advanced_options()` at line 499-682 — fully intact, ~180 lines of per-suite subtest skip prompts
- `--*-arg` passthrough flags: lines 98-110 (usage) and 841-853 (parser) — all 13 `--*-arg` flags present
- `*_EXTRA_ARGS` arrays: lines 31-43 — all 13 arrays declared and forwarded (lines 1033-1101)

**UI:**
- "Advanced opts" toggle: `tests.rs:209-218` — still prompts user
- `collect_advanced_suite_args()`: `tests.rs:545-728` — fully intact, ~180 lines of per-suite UI prompts
- `collect_skip_group()`: `tests.rs:730-747` — helper still present

**Fix per spec §3.2 / §3.3:**
- SSH runner: Delete `interactive_collect_advanced_options()`, remove `--*-arg` flags from usage/parser/case, remove `*_EXTRA_ARGS` arrays and forwarding
- UI: Remove "Advanced opts" toggle, delete `collect_advanced_suite_args()` and `collect_skip_group()`

---

## B) Medium-Risk Issues (Should-Fix)

### M1. Discord Text-Only Posts Use `application/json`, Not `multipart/form-data`

**Code:** `post_discord_payload_json()` (line 262-265) uses `-H "Content-Type: application/json"`.

Per Discord docs, text-only webhook messages CAN use JSON content type. This is technically correct. However, for consistency and to enable future file attachment support, consider a unified multipart approach.

**Verdict:** Technically correct for text-only. Keep as-is but ensure the new `send_discord_suite_artifacts()` function uses multipart correctly.

---

### M2. `send_discord_summary()` Attachment Uses Correct Multipart but No 429 Handling

**Code:** Lines 431-434:
```bash
curl -sS -X POST "$DISCORD_WEBHOOK_URL" \
  -F "payload_json=$payload_json" \
  -F "file1=@${MASTER_REPORT_PATH};filename=rustyjack_${RUN_ID}_summary.md" \
  >/dev/null
```

This correctly uses `-F` (multipart/form-data) with `payload_json`. File naming includes run ID. But no 429 handling.

**Fix:** Route through the new rate-limit-aware wrapper.

---

### M3. UI Puppeting Scenarios Lack "Go Home" Normalization

**Code:** All `.ui` scenario files start with `sleep 1` then jump directly to navigation:
- `wireless.ui`: `down 4` → `select` (assumes cursor at main menu item 0)
- `ethernet.ui`: `down 5` → `select`
- `loot.ui`: `down 8` → `select`
- `encryption.ui`: `down 7` → `select`
- `interface_selection.ui`: just `key1`

If the UI is not at the home screen when the scenario starts (e.g., previous test left it in a submenu), all navigation offsets will be wrong.

**Fix:** Prepend each scenario with a normalization block:
```
# Go home — repeated back presses to ensure we're at main menu
left 5
sleep 0.3
```

---

### M4. Theme Suite Uses Ad-Hoc `rj_ui_send` Instead of Scenario File

**Code:** `rj_test_theme.sh:249-304` — uses ~20 inline `rj_ui_send` calls for menu navigation.

**Risk:** Navigation offsets hardcoded in the script will break silently if menu order changes. A `.ui` scenario file would be easier to audit and update.

**Fix (recommended by spec §4.2):** Extract to `scripts/ui_scenarios/theme.ui` and call via `rj_ui_run_scenario`.

---

### M5. "All" in CLI `--all` Excludes Discord Test, but Interactive `0)` Auto-Enables It

**Code:**
- Interactive `0)` at line 790: sets core suites only, does NOT set `RUN_DISCORD=1`
- BUT lines 911-918 auto-enable `RUN_DISCORD=1` if any suite is selected AND Discord is enabled
- CLI `--all` at line 810: same behavior

So effectively, "All" always includes discord preflight when webhook is configured. This is **correct behavior** per spec Option B, but the spec itself is ambiguous about whether `--discord-test` is auto-included or excluded. The current behavior is: discord test is auto-included as a preflight, not as a user-selectable suite within "All". This is fine but should be documented clearly.

---

### M6. `--ui` / `--no-ui` Handling Inconsistency

**Code:**
- `rj_run_tests.sh:831-833`: `--no-ui` causes immediate `exit 2` ("UI automation is mandatory")
- `rj_run_tests.sh:22`: `RUN_UI=1` hardcoded default
- But `UI_ARGS=(--ui)` at line 867 is always set
- Individual suites still accept `--no-ui` (e.g., `rj_test_wireless.sh:53`)

**Risk:** If a suite script is called directly with `--no-ui`, it will skip UI automation, but the runner always forces `--ui`. The daemon also forces UI mode (`tests.rs:184`). This is consistent for normal paths but the individual suites' `--no-ui` flags create a maintenance hazard.

**Recommendation:** Low priority. Document that `--no-ui` on individual suites is for developer use only.

---

### M7. `rj_summary_event()` JSON Injection Risk

**Code:** `rj_test_lib.sh:200-208` — the python3 fallback path at line 206:
```bash
printf '%s\n' "{\"ts\":\"$(rj_now)\",\"status\":\"$status\",\"name\":\"$name\",\"detail\":\"$detail\"}" >> "$SUMMARY"
```

If `$name` or `$detail` contain quotes or backslashes, the JSON will be malformed. The python3 path handles this correctly via `json.dumps()`, but the fallback does not.

**Fix:** Use `json_escape` (from rj_run_tests.sh) or implement a minimal escape in rj_test_lib.sh for the fallback path.

---

## C) Low-Risk Improvements (Nice-to-Have)

### L1. `rj_test_lib.sh` Uses `set -- $line` Without Quoting (Line 531)

In `rj_ui_run_scenario()`:
```bash
set -- $line
```
This performs word splitting. If a scenario file ever contains a command argument with spaces, it will break. Currently all commands are single-word, so this is safe, but defensive quoting would be better.

---

### L2. `rj_capture_journal()` Unbounded Without `--lines` Limit

**Code:** `rj_test_lib.sh:352-353`:
```bash
journalctl -u "$unit" --since "$RJ_START_TS" --no-pager >"$outfile"
```

On a long test run, this can capture megabytes of journal output. Add `--lines 5000` or similar bound.

---

### L3. Scenario Files Don't Have Assertions

Wireless, ethernet, loot, interface_selection scenarios navigate menus but don't assert anything. The assertions come from the surrounding test script, but if a scenario silently fails (e.g., FIFO write blocked), the test may still pass.

**Recommendation:** Add post-scenario log marker checks in the calling scripts.

---

### L4. Spec Uses `watchdog/` Path Prefix Throughout

The spec references `watchdog/scripts/...` and `watchdog/crates/...` but the actual repo root is just `scripts/` and `crates/`. The `watchdog/` prefix comes from the reviewer's unzipped snapshot directory name.

**Fix:** Remove `watchdog/` prefix from all paths in the spec.

---

### L5. `--discord-test` Not in CLI Menu But Is in `case` Parser

Discord Webhook Preflight appears as menu option `13)` in the interactive menu, and as `--discord-test` in CLI. This works but since discord is auto-enabled as a preflight (M5), having it as a separate menu option is redundant. Consider documenting this as a standalone connectivity check.

---

## D) Doc-vs-Code Mismatches

### D1. Path Prefix

| Spec snippet | Actual path |
|---|---|
| `watchdog/scripts/rj_test_*.sh` | `scripts/rj_test_*.sh` |
| `watchdog/scripts/rj_run_tests.sh` | `scripts/rj_run_tests.sh` |
| `watchdog/scripts/rj_test_lib.sh` | `scripts/rj_test_lib.sh` |
| `watchdog/crates/rustyjack-ui/src/app/tests.rs` | `crates/rustyjack-ui/src/app/tests.rs` |
| `watchdog/crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs` | `crates/rustyjack-daemon/src/jobs/kinds/ui_test_run.rs` |
| `watchdog/scripts/ui_scenarios/*.ui` | `scripts/ui_scenarios/*.ui` |

### D2. Spec §1.3 Claims "back" Command in FIFO

> "writes `up/down/select/back` commands into the FIFO"

**Code reality:** `rj_ui_run_scenario()` (rj_test_lib.sh:535-545) recognizes: `sleep/wait`, `up/down/left/right/select/key1/key2/key3`. There is NO `back` command. All scenarios use `left` to go back. The spec should say `left` not `back`.

### D3. Spec §1.4 Claims Theme Uses Direct Key Injection

> "Theme → scripted key presses (no `.ui` scenario file)"

**Verified correct.** `rj_test_theme.sh:249-304` uses inline `rj_ui_send` calls, no `.ui` file.

### D4. Spec §1.5 Webhook Discovery

> "`--discord-webhook URL`"

**Verified correct.** Line 827: `--discord-webhook) DISCORD_WEBHOOK_URL="$2"; DISCORD_WEBHOOK_ENABLED=1; shift 2 ;;`

> "runtime file: `${RJ_RUNTIME_ROOT:-/var/lib/rustyjack}/discord_webhook.txt`"

**Verified correct.** Lines 46-48.

> "repo default: `scripts/defaults/discord_webhook.txt`"

**Verified correct.** Lines 48-49.

### D5. Spec §1.5 Claims `RJ_DISCORD_WEBHOOK_ATTACH_SUMMARY=1`

**Verified correct.** Line 54: `DISCORD_WEBHOOK_ATTACH_SUMMARY="${RJ_DISCORD_WEBHOOK_ATTACH_SUMMARY:-1}"` (defaults to 1, enabled).

### D6. Spec §1.2 Artifacts Layout

> "$RJ_OUTROOT/$RJ_RUN_ID/<suite>/" with run.log, summary.jsonl, report.md, artifacts/, journal/

**Verified correct.** `rj_test_lib.sh:21-26`:
```bash
OUT="$outroot/$run_id/$suite"
LOG="$OUT/run.log"
SUMMARY="$OUT/summary.jsonl"
REPORT="$OUT/report.md"
mkdir -p "$OUT" "$OUT/artifacts" "$OUT/journal"
```

### D7. Spec §2.1 Menu Numbers

> "currently displays in this order: 1, 2, 12, 13, 3, 4, 5, 6, 11, 7, 8, 9, 10, 0"

**Verified correct.** Lines 773-787 match exactly.

### D8. "All" Semantics — Spec vs Code

Spec §3.1: "Decision needed — Option A vs Option B"
Code (line 790, 810): "All" = Wireless + Ethernet + IfaceSelect + Encryption + Loot + Mac + Daemon + Installers + USB + UiLayout + Theme. Excludes DaemonDeep and DiscordTest.

This matches Option B recommendation. Discord is auto-enabled as preflight (lines 911-918) but not part of the "All" flag set.

---

## E) Discord Compliance Summary

| Requirement | Status | Location | Notes |
|---|---|---|---|
| Text-only: JSON body | ✅ Correct | `post_discord_payload_json()` line 262 | |
| File upload: multipart/form-data | ✅ Correct | `send_discord_summary()` line 431 | Only for final summary |
| File upload: `payload_json` field | ✅ Correct | `send_discord_summary()` line 432 | |
| Content ≤ 2000 chars | ❌ NOT CHECKED | All message functions | No truncation/validation |
| Per-suite artifact upload | ❌ NOT IMPLEMENTED | `run_suite()` | Spec §3.4 not done |
| 429 detection | ❌ NOT IMPLEMENTED | All curl calls | Status code discarded |
| 429 `Retry-After` header | ❌ NOT IMPLEMENTED | — | |
| 429 `retry_after` JSON field | ❌ NOT IMPLEMENTED | — | |
| Bounded retries | ❌ NOT IMPLEMENTED | — | |
| Upload failure ≠ suite PASS | ✅ Correct | `send_discord_suite_update` line 986 | Upload is fire-and-forget, doesn't affect suite status |

---

## F) Specific Implementation Targets

### Files to modify:

1. **`scripts/rj_run_tests.sh`**
   - Lines 773-804: Replace menu echo block with ordered array
   - Lines 31-43: Delete `*_EXTRA_ARGS` arrays
   - Lines 98-110: Delete `--*-arg` from usage
   - Lines 499-682: Delete `interactive_collect_advanced_options()`
   - Lines 769: Remove call to `interactive_collect_advanced_options`
   - Lines 841-853: Delete `--*-arg` from case parser
   - Lines 1033-1101: Remove `${*_EXTRA_ARGS[@]+"${*_EXTRA_ARGS[@]}"}` from all `run_suite` calls
   - Lines 260-269: Rewrite `post_discord_payload_json()` with 429 handling
   - Add new function `send_discord_suite_artifacts()` after `send_discord_suite_update()`
   - Call it from `run_suite()` after line 988
   - Add `discord_truncate_content()` helper
   - Add `discord_curl_with_retry()` wrapper

2. **`crates/rustyjack-ui/src/app/tests.rs`**
   - Lines 209-218: Delete "Advanced opts" toggle block
   - Lines 545-728: Delete `collect_advanced_suite_args()`
   - Lines 730-747: Delete `collect_skip_group()`

3. **`scripts/ui_scenarios/*.ui`** (all 5 files)
   - Prepend "go home" normalization block

4. **`scripts/rj_test_lib.sh`**
   - Line 206: Fix JSON injection in fallback path of `rj_summary_event()`
