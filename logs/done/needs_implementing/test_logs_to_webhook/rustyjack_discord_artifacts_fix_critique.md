# Critique: `rustyjack_discord_artifacts_fix.md`

This report is a direct, repo-verified critique of the design note. It focuses on correctness of Discord webhook uploads, completeness, constraint alignment (Rust-first; no new third‑party system binaries), and operational robustness on low-resource devices (Pi Zero 2 W).

---

## 1. Executive summary

- ✅ **Strong diagnosis:** The note correctly suspects a multipart *file field name mismatch* (`file1` vs Discord’s documented `files[n]`) as a likely cause of webhook upload failures.
- ✅ **Correct focus on visibility:** Calling out missing HTTP status + response-body logging is dead-on; the current script captures body but never prints it.
- ⚠️ **Big missing root cause:** `upload_consolidated_results_zip()` creates the ZIP **inside** the directory being zipped and zips the **entire absolute run dir**. That can self-include the `.tmp` output and balloon size or fail unexpectedly. This is a much more immediate “why does the ZIP blow up / fail” candidate than size alone.
- ⚠️ **The Rust sender is also non-compliant:** `send_discord_payload()` uploads as multipart field `"file"`, not `files[0]`. Any future migration to Rust will reproduce the same bug unless fixed.
- ⚠️ **Rate limit handling is incomplete:** Bash handles 429 via body parsing only; it ignores the `Retry-After` header and retries *all* non-2xx codes equally (including 400/413), which is a bad failure mode.
- ⚠️ **“One message with both artifacts” is optimistic:** It’s brittle against file size limits and will create more rate-limiting pressure. The doc should specify when to split into multiple webhook posts and how to name parts.
- ✅ **Good direction (Rust-first):** Moving network I/O (Discord posts) to Rust is aligned with `rustyjack-core` being built for “appliance forbids external process spawning.”
- ⚠️ **Needs acceptance criteria that match reality:** The repo already uploads `run_summary.md`, per-suite tarballs (size-gated), and “critical files.” The note proposes an “all logs amalgamation” without showing why existing signals aren’t enough, and without defining an exact chunk/split policy.

---

## 2. Incorrect / unverified claims

Each item is a claim made in `rustyjack_discord_artifacts_fix.md`, marked Verified / Unverified, and corrected where needed.

### Discord upload mechanics

1) **Claim:** “The script uses curl form fields like `file1=@...`.”
- **Verified.**
  - `scripts/rj_run_tests.sh:488–492` uploads the master summary with `-F "file1=@..."`.
  - `scripts/rj_run_tests.sh:562–567`, `572–576`, `632–636`, `690–695` upload suite log/summary/tarball and consolidated zip with `file1`.
- **Edit:** Replace all `file1` uses with `files[0]` for single-file posts, or `files[i]` for multi-file.

2) **Claim:** “Discord requires parts named `files[n]`.”
- **Verified (Discord docs).**
- **Edit:** The doc should quote the exact contract: `files[n]` are the form fields, and `payload_json` is required for non-file params on multipart requests.

3) **Claim:** “This can yield HTTP 400 ‘Invalid Form Body’ failures.”
- **Plausible, but unverified in this repo snapshot** (no captured webhook response logs).
- **Fix to doc:** Add a “how to confirm” procedure that prints status + truncated response JSON when any non-2xx occurs.

### File size + artifact behavior

4) **Claim:** “The consolidated ZIP can exceed Discord’s per-file limit.”
- **Plausible and likely**, but the doc currently doesn’t quantify or cite the limit and doesn’t mention that the repo already uses an 8 MiB cap for per-suite tar bundles.
- **Verified repo behavior:** `DISCORD_BUNDLE_MAX_BYTES=$((8 * 1024 * 1024))` in `scripts/rj_run_tests.sh:50`, applied to suite tarballs (`scripts/rj_run_tests.sh:611–619`), **not** applied to the consolidated ZIP (`scripts/rj_run_tests.sh:642–699`).

5) **Claim:** “The script checks size for suite bundles, but not for the consolidated ZIP.”
- **Verified.**
  - Size gate exists for per-suite tarball.
  - No size gate for consolidated ZIP; it uploads regardless.

6) **Missing in the doc (important):** ZIP creation avoids recursion issues by zipping “from parent directory.”
- **Incorrect as implemented.**
  - Comment: `scripts/rj_run_tests.sh:661` claims “from parent directory to avoid recursion issues.”
  - Reality: It runs `zip -r "$temp_zip" "$run_dir"` with `temp_zip` located *inside* `$run_dir` (`scripts/rj_run_tests.sh:656–663`).
- **Corrective edit:** The ZIP should be written outside `$run_dir` and built from the parent directory with a relative path, or exclude the output path explicitly.

### Error visibility + retries

7) **Claim:** “`discord_curl_with_retry` stores the response body in a temp file but does not print it when non-2xx codes happen.”
- **Verified.**
  - Captures body to tmpfile (`scripts/rj_run_tests.sh:292–300`).
  - On non-2xx, only prints code (`scripts/rj_run_tests.sh:323–331`), discarding body content.

8) **Claim:** “Existing Rust Discord sender attaches file under name (`file`) and supports only one file.”
- **Verified.**
  - `crates/rustyjack-core/src/system/mod.rs:638–642` uses `.file("file", file_path)`.
- **Doc correction:** Make explicit that this is **also** not aligned with Discord’s `files[n]` contract and must be fixed before reusing it for artifacts.

---

## 3. Key risks and edge cases (prioritized)

1) **ZIP self-inclusion / recursion / runaway size**
- Current ZIP output (`*.tmp`) lives inside the directory being zipped (`scripts/rj_run_tests.sh:656–663`), so the archive can include its own output mid-write or at least pick up extra artifacts unexpectedly.
- This can cause oversized artifacts and upload failures that look like “Discord broke” but are actually “zip creation is wrong.”

2) **Wrong multipart field name**
- Discord docs specify `files[n]` for file parts.
- Using `file1` and `file` is not reliable. It may fail with 400 or behave inconsistently.

3) **“Retry on everything” is dangerous**
- The current retry loop treats all non-2xx statuses the same except 429. A persistent 400/413 will trigger repeated posts, increasing the chance of IP-level protections and wasting time on the Pi.

4) **No response-body diagnostics**
- Without logging the JSON error body, you can’t distinguish:
  - invalid form body (400),
  - payload too large (413),
  - rate limit (429),
  - transient upstream errors (5xx),
  - TLS/DNS issues.
- On Pi, this becomes “mysterious flakiness.”

5) **Timeouts and memory pressure**
- ZIP in Rust (or `zip -r`) can be CPU heavy; on Pi Zero 2 W, a “zip everything” strategy can make the system look wedged.
- Any “all logs amalgamation” must stream I/O; never read all logs into RAM.

6) **Webhook “wait” behavior**
- Discord’s Execute Webhook supports `wait` query param; without it you may not get a helpful response body. If you need correctness and debugging, use `wait=true` during artifact uploads.

7) **Security hygiene**
- Webhook URL should never be logged.
- Diagnostics must redact it even on “verbose” mode.
- Any “send artifacts” command should require an explicit opt-in (flag/env), not implicit.

---

## 4. Concrete improvements to the document

Below are direct rewrite-ready replacements/additions to make the design note correct, repo-specific, and implementable.

### 4.1 Replace the “What’s failing” section with verifiable steps

**Replace your “Likely root causes” list with the following:**

> **Confirmed issues in this repo**  
> 1) **Multipart field name mismatch:** all current artifact uploads use `-F "file1=@..."` in `scripts/rj_run_tests.sh` (e.g., `send_discord_summary()` at lines 487–492). Discord documents file parts as `files[n]`.  
> 2) **Consolidated ZIP creation is unsafe:** `upload_consolidated_results_zip()` writes the ZIP (`${zip_file}.tmp`) inside the directory being zipped and runs `zip -r "$temp_zip" "$run_dir"` (lines 656–667). This can self-include the temp output and inflate or break the ZIP.  
> 3) **No error-body logging:** `discord_curl_with_retry()` captures the response body to a tmp file but never prints it on non-2xx codes (lines 288–331).  
>
> **How to confirm the exact failure mode (do this first):**  
> Update `discord_curl_with_retry()` so that on any non-2xx (except 429) it prints:  
> - HTTP status  
> - first 4–8 KiB of the response body (JSON), with webhook URL redacted  
> Then run an “all suites” test run and record whether the failing response is 400 (invalid form body), 413 (too large), 429 (rate limit), or 5xx (transient).

### 4.2 Tighten the Discord multipart recipe into an explicit contract

Add a new subsection:

> **Discord webhook upload contract (do not deviate):**  
> - Use `multipart/form-data` with a string field named `payload_json` containing the non-file JSON body.  
> - Each attached file must be included as a form part named `files[n]` where `n` starts at 0.  
> - Optional: include `attachments` metadata in `payload_json` if you need explicit filenames/descriptions or to reference attachments in embeds.  
> - For rate limiting, respect `Retry-After` header or `retry_after` in the 429 JSON response; don’t blind-retry other 4xx statuses.

### 4.3 Reframe the “all logs amalgamation” so it’s justified and bounded

Right now the repo already generates and uploads:
- `run_summary.md` (optionally attached),
- per-suite tar.gz bundles (size-gated),
- per-suite “critical files” (report/log/summary).

So the doc should clarify why `rustyjack_<run_id>_all_logs.txt` is still needed, and it must define what it contains.

**Add this exact scope definition:**

> **All-logs plaintext file: scope and policy**  
> The file is not “everything in the run directory.” It is a readable, bounded diagnostic artifact intended for Discord constraints.  
> Include in order:  
> 1) `run_summary.md` verbatim  
> 2) For each suite in run order:  
>    - `suite_id/report.md` verbatim (if present)  
>    - `suite_id/run.log`: include either (a) full log if ≤ N KiB, else (b) top 200 lines + last 400 lines, with a “[TRUNCATED]” marker.  
>    - `suite_id/summary.jsonl` verbatim if small, else first/last M lines.  
> 3) Environment footer: hostname, run ID, results root, RustyJack version/commit (if available without external tooling).
>
> **Chunking rule:** write `all_logs_partNN.txt` with a hard cap of `DISCORD_MAX_FILE_BYTES - 256 KiB` per part; split only on suite boundaries when possible.

### 4.4 Make the change plan “diff-ready” (PR task list)

The current plan jumps straight to “move everything into Rust.” That’s fine directionally, but too big as the *first* fix.

Add a phased plan:

- **Phase 1 (hotfix; minimal diff; immediate value):**
  - Fix multipart part names in Bash: `file1` → `files[0]`.
  - Fix consolidated ZIP creation location to avoid self-inclusion.
  - Print response body snippet on non-2xx.
  - Add size gate for consolidated ZIP using an env-configurable max (default to 8 MiB for safety).

- **Phase 2 (Rust-first networking):**
  - Add a Rust CLI path that performs the webhook send with proper multipart naming, `wait=true`, body diagnostics, and 429 backoff.
  - Update `rj_run_tests.sh` to call the Rust CLI for sending instead of `curl`.

- **Phase 3 (Rust packaging):**
  - Migrate ZIP creation into Rust (zip crate or alternative), ensuring streaming I/O and excludes for FIFOs and gigantic/binary content.

### 4.5 Add explicit failure UX and retention

Add a “Failure UX” subsection:

> On upload failure (non-2xx):  
> - Send a plain text Discord message with the run ID, which artifact failed, and the HTTP status + short error string.  
> - Retain artifacts locally under `$OUTROOT/$RUN_ID/` and print the path at the end of the run.  
> - Do **not** retry on 400/413; do retry with backoff on 429 and certain 5xx codes up to a bounded max duration.

---

## 5. Implementation sketch (minimal, repo-accurate)

This is a practical, smallest-diff plan that is still aligned with constraints.

### Phase 1: Bash hotfix (keep scope tight)

**Files to change**
- `scripts/rj_run_tests.sh`

**Edits**

1) **Fix multipart field names**
- Replace every `-F "file1=@...` with `-F "files[0]=@...`:
  - `send_discord_summary()` (`scripts/rj_run_tests.sh:487–493`)
  - `upload_suite_critical_files()` (`scripts/rj_run_tests.sh:555–577`)
  - `send_discord_suite_artifacts()` (`scripts/rj_run_tests.sh:632–636`)
  - `upload_consolidated_results_zip()` (`scripts/rj_run_tests.sh:690–695`)

2) **Stop zipping the directory into itself**
- In `upload_consolidated_results_zip()` (`scripts/rj_run_tests.sh:642–699`):
  - Create the temp ZIP **outside** `$run_dir` (e.g., `mktemp` under `${TMPDIR:-/tmp}`).
  - `pushd "$(dirname "$run_dir")"` and zip `$(basename "$run_dir")` so paths inside the ZIP are relative.
  - Add excludes for known garbage/unsafe types (fifos, existing archives, cores).
  - Move final ZIP into `$run_dir` only after it is fully built.

3) **Add a size gate before uploading**
- Reuse `DISCORD_BUNDLE_MAX_BYTES` (8 MiB today) or introduce `RJ_DISCORD_MAX_FILE_BYTES` with default `8 MiB`.
- If the ZIP exceeds the limit:
  - do not attempt upload,
  - send a text-only Discord message that the consolidated ZIP was skipped due to size and that per-suite bundles were uploaded (if any),
  - keep the ZIP locally.

4) **Add error-body printing + smarter retry boundaries**
- In `discord_curl_with_retry()` (`scripts/rj_run_tests.sh:288–331`):
  - On non-2xx and non-429:
    - print `head -c 8192 "$tmpfile"` (redact webhook URL; do not print headers containing it),
    - if status is `400`, `401`, `403`, `404`, `413`, **do not retry** (return 1 immediately).
  - On 429:
    - prefer `Retry-After` header (requires capturing headers); fall back to parsing `retry_after` from JSON body.

### Phase 2: Rust webhook sender (reduce dependency on curl; still small diff)

**Files to change**
- `crates/rustyjack-core/src/system/mod.rs`
- `crates/rustyjack-core/src/operations.rs`
- `crates/rustyjack-commands/src/lib.rs`

**Edits**

1) Fix existing `send_discord_payload()` multipart field name
- Change `.file("file", file_path)` (`mod.rs:639–642`) to add a `Part` under `files[0]`.
- On non-success:
  - read response body (truncate) and include it in the error message.
- Add 429 handling using `Retry-After` header or JSON `retry_after`.

2) Add a “send multiple files” function (optional but useful)
- New: `send_discord_payload_multi(root, embed, files: &[&Path], content)`
- Use `files[0..]` naming, optional `attachments` metadata, and bounded retries.

3) Add a CLI subcommand to send arbitrary attachments
- Extend `DiscordCommand` to include something like:
  - `SendFiles { title, message, files: Vec<PathBuf> }`
- Update `rj_run_tests.sh` to call this Rust command for uploads (eliminates curl dependency gradually).

### Phase 3: Rust packaging (only after uploads are correct)

- Implement ZIP generation in Rust only after the webhook send path is proven correct.
- The repo already depends on `tar`, `flate2`, and `walkdir`. If ZIP is mandatory, add `zip` crate with minimal features; otherwise consider `tar.gz` as a smaller “works everywhere” alternative.

---

## 6. What “fixed” looks like

### Acceptance criteria

1) **Multipart compliance**
- All Discord file uploads (Bash and Rust) use `files[0]` (and `files[n]` for multi-attach) with `payload_json` on multipart.

2) **Consolidated ZIP creation is safe**
- ZIP output is created outside the run directory and moved in only after completion.
- ZIP contents use relative paths and do not include the ZIP itself or FIFOs.

3) **Size-bound behavior**
- Before uploading any file, its size is checked against a configurable max (default safe value).
- If an artifact is too large:
  - upload is skipped (no retries),
  - a Discord message explains what was skipped and where the artifact lives locally.

4) **Observability**
- On any non-2xx response:
  - logs include HTTP status and first 4–8 KiB of the response body.
  - webhook URL is never logged.

5) **Retry behavior**
- 429 is retried with correct delay (Retry-After / retry_after).
- 5xx may be retried with bounded attempts.
- 400/413 are not retried.

### Test plan (realistic for Pi Zero 2 W)

1) **Happy path, single small attachment**
- Run a small suite and verify `run_summary.md` attachment shows in Discord.

2) **Artifact uploads with corrected field names**
- Run two suites and verify per-suite log + summary uploads succeed.

3) **Consolidated ZIP sanity**
- Confirm the ZIP exists, contains expected relative paths, and does *not* contain itself.
- Verify the upload succeeds when ZIP < max size.

4) **Oversize behavior**
- Artificially inflate run dir (add a big dummy file) so ZIP > max size.
- Confirm:
  - script skips upload,
  - sends fallback message,
  - leaves ZIP on disk.

5) **Rate limit simulation**
- Trigger multiple quick Discord posts (e.g., loop sending small payloads).
- Confirm 429 handling waits and eventually succeeds, without hammering.

6) **Offline / DNS failure**
- Disable network and run. Confirm:
  - the script times out,
  - produces meaningful warnings,
  - keeps local artifacts.

---

## References (for maintainers)

- Discord Developer Docs — Webhook Resource (Execute Webhook, `files[n]`, `payload_json`, `attachments`, `wait` query)
- Discord Developer Docs — Uploading Files (multipart form conventions; file-size limit guidance)
- Discord Developer Docs — Rate Limits (`Retry-After` header and `retry_after` JSON field on 429)
