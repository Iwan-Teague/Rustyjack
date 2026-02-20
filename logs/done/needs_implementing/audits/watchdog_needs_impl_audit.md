# Implementation Audit (needs implimenting)

Repo snapshot: `watchdog_shallow_20260217-225646.zip`  
Audit date: 2026-02-17

This audit reads every document under:

- `needs implimenting/test logs to webhook/`
- `needs implimenting/test logs fix/`

…and checks the current repository for the behaviors/patches those docs describe.

---

## Documents reviewed

### test logs to webhook
- `chat prompt.md`
- `rustyjack_discord_artifacts_fix.md`
- `rustyjack_discord_artifacts_fix_critique.md`

### test logs fix
- `AI_AGENT_FIX_EXECUTION_PROMPT.md`
- `RUSTYJACK_TEST_FIX_IMPLEMENTATION_PROMPT.md`
- `TEST_LOG_FIX_REPORT.md`
- `deep-research-report.md`
- `deep-research-report-latest.md`
- `prompt.md`

---

# 1) test logs to webhook — Status: **IMPLEMENTED (core fix present)**

The core issue these docs target is Discord webhook uploads failing because the multipart file field name was wrong (`file1`, `file`, etc.), plus a pile of reliability/diagnostic problems (zip self-inclusion, retry policy, size gating, etc.).

## 1.1 Multipart field naming (Discord expects `files[0]`, …) — ✅ Present

### Bash sender (rj_run_tests.sh)
Verified in `scripts/rj_run_tests.sh`:

- Single-file upload uses `files[0]=@…` and always includes `payload_json=` in the same multipart post.  
  Evidence: `scripts/rj_run_tests.sh` lines **553–567** and **586–599**.

### Rust sender (reqwest multipart)
Verified in `crates/rustyjack-core/src/system/mod.rs`:

- Files are attached as `files[<idx>]` and `payload_json` is always present.  
  Evidence: `system/mod.rs` lines **856–872**.

## 1.2 ZIP self-inclusion fix — ✅ Present

The bash “consolidated zip” creation now creates the zip in `/tmp` (via `mktemp`) and zips the run directory by relative path from its parent, excluding `*.zip` patterns.

Evidence: `scripts/rj_run_tests.sh` lines **738–755** and **760–763**.

## 1.3 Size gating before upload — ✅ Present

- `RJ_DISCORD_MAX_FILE_BYTES` enforced before upload, with fallback to text-only message if the zip is too large.  
  Evidence: `scripts/rj_run_tests.sh` lines **742–749**.

The Rust path also supports size limits (`--max-file-bytes`) in the `send-test-artifacts` command.
Evidence: `crates/rustyjack-commands/src/lib.rs` lines **301–323**.

## 1.4 Retry policy + observability — ✅ Present

### Bash retry/diagnostics
- Captures headers, prints status + body snippet, saves `discord_error_<ts>.json`, and:
  - fail-fast on `400/401/403/404/413`
  - retry on `429` with `Retry-After` support
  - retry on `5xx` with bounded backoff

Evidence: `scripts/rj_run_tests.sh` lines **270–404**.

### Rust retry/diagnostics
- Has bounded retries with:
  - `Retry-After` parsing from header or JSON body
  - fail-fast status set
  - backoff for 5xx

Evidence: `system/mod.rs` (discord retry helpers) and unit tests in `system/mod.rs` lines **4423–4510**.

## 1.5 “Prefer Rust for artifacts” wiring — ✅ Present

The main run wrapper prefers the Rust subcommand first, then falls back:

1) `rustyjack notify discord send-test-artifacts`  
2) bash consolidated zip upload  
3) text-only message

Evidence: `scripts/rj_run_tests.sh` lines **1334–1360**.

## 1.6 Artifact strategy (plaintext + zip) — ✅ Present

A Rust artifact builder exists:

- Plaintext bundle builder: `build_plaintext_logs()`  
  Evidence: `crates/rustyjack-core/src/test_artifacts.rs` lines **33–127**.
- Chunking if oversized: `chunk_file()`  
  Evidence: `test_artifacts.rs` lines **171–243**.
- Zip packager (no system `zip` dependency): `build_results_zip()`  
  Evidence: `test_artifacts.rs` lines **289–379**.

## 1.7 Requirements that are *not* fully met from `chat prompt.md` — ⚠️ Partial

The chat prompt doc asks for “proof” items beyond implementation (mock server tests for 429 sleeps, multipart structure validation, etc.). The repo **does** include unit tests for:
- retry-after parsing and fatal status classification
- `files[n]` field-name format sanity
- artifact builder behavior

…but **does not** include a local HTTP mock server integration test that proves end-to-end 429 sleep behavior, nor a test that inspects the generated multipart body to assert `payload_json` exists as a multipart field.

If you meant those proofs as hard requirements (not just suggested validation), they’re still outstanding.

**What’s left (only if you care about the proof-level requirements):**
- Add an integration test (dev-dep like `wiremock`) that:
  - runs a local server returning 429 with `Retry-After`
  - asserts the retry loop sleeps (use a time abstraction or tokio time pause)
  - asserts `payload_json` and `files[0]` show up in the multipart request

---

# 2) test logs fix — Status: **PARTIALLY IMPLEMENTED (several fixes still missing)**

This folder targets multiple test failures and harness bugs.

Below is a checklist of the concrete fixes those docs describe, and whether they exist in the current repo.

## 2.1 Tokio “no reactor running” panics (wifi scan / netlink) — ✅ Implemented by an equivalent fix

Docs propose wrapping the CLI main entrypoint in a Tokio runtime. That exact patch is **not** present in:
- `crates/rustyjack-core/src/main.rs` (still sync `main()`).

However, the underlying failure mode is addressed another way:

- Netlink operations are routed through helpers that:
  - use `tokio::runtime::Handle::try_current()`, and
  - fall back to a shared runtime via `shared_runtime().block_on(...)`.

Evidence: `crates/rustyjack-core/src/netlink_helpers.rs` lines **35–116**.

So: **the *intent* of the docs is satisfied** (netlink calls won’t panic when no runtime exists), even though the proposed `main.rs` patch is not applied.

## 2.2 “Strict isolation destroys routes / read-only tests fail” — ✅ Likely addressed in isolation implementation

Several docs claim strict isolation:
- flushes addresses / deletes default routes on the active interface, and
- doesn’t restore them, causing route diffs.

Current implementation **does not** touch the allowed interface(s); it only releases DHCP / flushes / deletes routes on **blocked** interfaces.

Evidence: `crates/rustyjack-core/src/system/mod.rs` lines **2530–2549**.

Caveat: if your test environment has multiple active interfaces with routes you expect to remain unchanged, strict isolation still *will* change those blocked interfaces (by design). Whether that’s acceptable depends on the test harness expectation.

## 2.3 Daemon UI-only operations gate blocks interface-selection RPCs — ❌ NOT IMPLEMENTED

Docs explicitly call out that daemon RPCs like:
- `active_interface_clear` (A7),
- `system_sync` (A9),
- `job_start` (F1),
are rejected when `ui_only_operations=true` unless the peer uid matches `ui_client_user`.

Current state:
- Default remains `ui_only_operations=true`.  
  Evidence: `crates/rustyjack-daemon/src/config.rs` line **14**.
- `services/rustyjackd.service` does **not** set `RUSTYJACKD_UI_ONLY_OPERATIONS=false`.  
  Evidence: `services/rustyjackd.service` lines **1–13**.
- `scripts/rj_test_interface_selection.sh` does not run the RPC peer as the UI user, nor does it set `ui_only_operations=false`.

**Result:** the behavior described in the docs is still present; this fix is missing.

### What to implement
One of these:
1) **Test-only systemd drop-in**: add a `.d/override.conf` for the test environment setting `Environment="RUSTYJACKD_UI_ONLY_OPERATIONS=false"`.
2) **Adjust test scripts** to run RPC helper under `rustyjack-ui` (or whatever `ui_client_user` is), using `sudo -u`.
3) Decide the gate is wrong and change the daemon policy defaults (higher impact).

## 2.4 VFAT detection for USB mount (fails on FAT32 devices) — ❌ NOT IMPLEMENTED

Docs ask for a more robust FAT/VFAT detection heuristic (not just exact “FAT16   /FAT32   ” signature strings), e.g. checking BPB fields + 0x55AA footer.

Current code still only checks for exact ASCII signatures in the boot sector:
- `b"FAT16   "`, `b"FAT32   "`, `b"MSDOS5.0"`, `b"MSWIN4.1"`, `b"MSWIN4.0"`.

Evidence: `crates/rustyjack-core/src/mount.rs` lines **626–648**.

### What to implement
Replace/augment `is_vfat()` with a heuristic like the docs describe:
- accept 0x55AA signature
- check BPB plausibility (bytes/sector, sectors/cluster, reserved sectors, num_fats, root_entries, etc.)
- accept FAT32 if the FAT32 EBPB signature matches

## 2.5 Test harness bug: comprehensive suite G4 log-dir secure check — ❌ NOT FIXED

Docs identify the script is reading the *wrong* permission digit for “others”:

Current code:
- uses `others="${perms:2:1}"` (this is the **group** digit in a 4-digit mode like `2770`), then labels it “world”.

Evidence: `scripts/rustyjack_comprehensive_test.sh` lines **1151–1164**.

### What to implement
Use `others="${perms:3:1}"`, and keep the check/message consistent (world-writable vs world-readable).

## 2.6 Test harness bug: suite I “pid disappears auth” runs as root, not the RO user — ❌ NOT FIXED

Docs require running the RPC as the read-only user (`RO_USER`) so you actually test RO behavior.

Current code runs python directly (no `sudo -u "$RO_USER"`), so it tests root instead.

Evidence: `scripts/rustyjack_comprehensive_test.sh` lines **1290–1315**.

### What to implement
Reuse `rj_rpc` (which already supports `as_user`) or add `sudo -u "$RO_USER"` around the python invocation.

## 2.7 Test harness bug: suite J1 wifi scan request missing `timeout_ms` — ❌ NOT FIXED

Daemon validates `timeout_ms` and rejects zero/missing.

- Daemon requires `timeout_ms` (validation runs before job creation).  
  Evidence: `crates/rustyjack-daemon/src/dispatch.rs` and `validation.rs`.
- Comprehensive test sends `timeout_ms` **missing**.  
  Evidence: `scripts/rustyjack_comprehensive_test.sh` lines **1479–1488**.

### What to implement
Add `timeout_ms` in the J1 request JSON (e.g. 10_000).

## 2.8 “Missing offensive subcommands” — ✅ Implemented (but note the policy tension)

Docs note test scripts fail if `rustyjack evasion`, `physical_access`, `anti_forensics` subcommands don’t exist.

Current repo **does** define those command groups, and the scripts call them.

Evidence:
- Commands exist: `crates/rustyjack-commands/src/lib.rs` (Evasion / PhysicalAccess / AntiForensics sections).
- Scripts call them: `scripts/rj_test_evasion.sh`, `scripts/rj_test_physical_access.sh`, `scripts/rj_test_anti_forensics.sh`.

One doc also warns not to add/expand offensive capabilities; another doc demands the command surfaces exist for the test suite. The repo currently follows the latter requirement.

---

# 3) Bottom line

## Is the “Discord artifacts / test logs to webhook” fix in the project?
**Yes.** The multipart field naming bug, zip self-inclusion, retry policy/diagnostics, and Rust-first artifact sending path are implemented.

## Is everything in “test logs fix” implemented?
**No.** The repo still misses at least these high-signal items:

1) Disable/override daemon `ui_only_operations` for tests (or run test RPC as the UI user)
2) Robust VFAT detection heuristic in `mount.rs`
3) Fix comprehensive script:
   - G4 world-perms digit
   - I1 run as RO user
   - J1 include `timeout_ms`

---

## Appendix: quick pointers (most useful files)

- `scripts/rj_run_tests.sh` — Discord uploading + retry/diagnostics + Rust CLI wiring
- `crates/rustyjack-core/src/system/mod.rs` — Rust Discord sender + tests
- `crates/rustyjack-core/src/test_artifacts.rs` — artifact builders (plaintext + zip)
- `crates/rustyjack-daemon/src/config.rs` — defaults for `ui_only_operations`
- `services/rustyjackd.service` — (missing) env override for tests
- `crates/rustyjack-core/src/mount.rs` — VFAT detection (too strict today)
- `scripts/rustyjack_comprehensive_test.sh` — G4/I1/J1 harness bugs
