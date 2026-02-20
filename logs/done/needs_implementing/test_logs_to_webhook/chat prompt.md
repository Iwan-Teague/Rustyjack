You are an autonomous coding agent working in a local git checkout of the RustyJack repo (Raspberry Pi Zero 2 W target). Your job is to IMPLEMENT (not just describe) the fixes outlined in these two design documents:

- /mnt/data/rustyjack_discord_artifacts_fix.md  (original plan)
- /mnt/data/rustyjack_discord_artifacts_fix_critique.md  (repo-specific critique + corrections)

NON-NEGOTIABLE CONSTRAINTS
- Rust-first where feasible. Prefer moving network behavior into Rust over expanding shell complexity.
- Do NOT add new third-party system binaries (no “install jq/zip/etc”). If the shell already uses a binary today, you may keep it temporarily but must provide a clean migration path into Rust (and implement the Rust side for webhooks).
- Keep changes minimal, testable, and robust on constrained hardware (CPU/RAM/storage). Streaming I/O only for big files.
- Never log the Discord webhook URL/token. Redact it in all error paths.

AUTHORITATIVE DISCORD RULES TO FOLLOW
- Multipart file uploads to webhooks use multipart/form-data with file parts named `files[n]` and optional JSON in `payload_json` (for multipart). Implement accordingly.
- On HTTP 429, you MUST rely on the `Retry-After` header or `retry_after` value in the JSON response to determine backoff before retry.

WORKFLOW: “PROGRESS LEDGER” + “GATES”
Before touching code:
1) Create a new branch: `fix/discord-artifacts`.
2) Create a tracking file: `docs/discord_artifacts_fix_progress.md`.
   - Populate it with a checklist of every task below.
   - Each checklist item must include:
     - a short description,
     - the exact file(s) you’ll change,
     - and a “proof” line you will fill in later (e.g., grep output, test name, or a short snippet).
3) You must keep this ledger updated as you work:
   - When you complete an item, mark it [x] and add:
     - commit hash
     - proof (command + summarized output)
4) Do not declare “done” unless ALL acceptance criteria at the end are met.

PHASE A — IMMEDIATE FIXES IN BASH (minimal diff, but must be correct)
Goal: Make current script uploads standards-compliant and diagnosable, without adding new binaries.

A1) Fix multipart field naming in `scripts/rj_run_tests.sh`
- Replace curl `-F "file1=@..."` with `-F "files[0]=@..."` everywhere it uploads a file to Discord.
- If there are multi-file sends (or you add one), use `files[0]`, `files[1]`, etc.
- PROOF: `rg 'file1=@' scripts/rj_run_tests.sh` returns zero matches.

A2) Improve observability in `discord_curl_with_retry`
- On any non-2xx response:
  - print HTTP status
  - print the first 8 KiB of the response body (if present)
  - ensure webhook URL is not leaked in logs (redact token if it appears)
- Retain a copy of the response body on disk inside the run dir (e.g., `discord_error_<timestamp>.json`) for postmortem, but do not store secrets.
- PROOF: a unit-like shell test or a manual repro note in the progress ledger showing the printed status + body snippet.

A3) Fix consolidated ZIP creation so it does NOT zip the directory into itself
- Ensure the temporary ZIP is created OUTSIDE the run directory (e.g., under `${TMPDIR:-/tmp}` via `mktemp`).
- Zip from the parent directory so paths inside are relative.
- Ensure the generated ZIP cannot include itself or its temp output.
- PROOF: show the command(s) and explain why self-inclusion is impossible.

A4) Add size preflight for the consolidated ZIP (and any new artifacts)
- Add a configurable max file size env var (e.g., `RJ_DISCORD_MAX_FILE_BYTES`) defaulting to the existing conservative cap (the repo already uses 8 MiB in places—keep that default).
- If the consolidated ZIP exceeds the cap:
  - do not attempt upload
  - send a Discord message explaining it was skipped due to size + local path retained
  - proceed (do not fail the whole run)
- PROOF: demonstrate a run where oversized file is skipped and a message is still sent.

A5) Retry policy tightening in bash
- Do NOT retry forever on 400/401/403/404/413. Fail fast with diagnostics.
- Retry on 429 using Retry-After (header preferred if you capture it; otherwise parse body).
- Optionally retry a small number of times on transient 5xx.
- PROOF: in progress ledger, list which status codes retry vs fail-fast, and where implemented.

PHASE B — RUST WEBHOOK SENDER: COMPLIANT MULTIPART + RETRIES + MULTI-FILE
Goal: Implement a correct Rust sender that follows Discord’s multipart contract and rate limiting, then migrate bash to call Rust for uploads.

B1) Locate the existing Rust webhook sender and fix its multipart field name
- Find `send_discord_payload(...)` (or equivalent) in the repo.
- It currently attaches the file under a non-standard field name; update it to `files[0]` and include `payload_json` for non-file fields in multipart.
- Ensure response body is captured and truncated in errors (first 8 KiB).
- Ensure webhook URL is never logged (redaction helper).
- PROOF: add/adjust a unit test that asserts the multipart form uses `files[0]` and includes `payload_json`.

B2) Add multi-file support in Rust
- Implement `send_discord_payload_multi(...)` or extend existing function:
  - accepts N files
  - attaches them as `files[0..N-1]`
  - uses a single `payload_json` containing message text (and optionally `attachments` metadata)
- If N exceeds a conservative per-message cap (choose a safe default like 10, configurable), split into multiple webhook posts.
- PROOF: unit tests for N=1, N=2, and “split into multiple requests” case.

B3) Implement correct retry/backoff in Rust
- On 429: sleep for Retry-After header OR retry_after from JSON, then retry.
- Bound retries (e.g., max attempts or max total time).
- Fail-fast for 400/401/403/404/413.
- Consider timeouts appropriate for Pi (configurable; default should not be tiny).
- PROOF: tests using a local HTTP mock server (Rust dev-dependency is fine) that simulates 429 and asserts correct sleep logic is invoked.

B4) Expose a repo-consistent CLI command
- Do NOT invent a new top-level command namespace unless the repo already uses it.
- Extend the existing `rustyjack notify discord send` (or existing command) to accept repeated `--file` args OR add `notify discord send-test-artifacts` under the same subtree.
- PROOF: `rustyjack --help` output snippet (or equivalent) showing the new flags/subcommand.

PHASE C — ARTIFACT STRATEGY: ZIP + “ALL LOGS” PLAINTEXT (STREAMING, CHUNKING)
Goal: Generate two artifacts and send them to Discord robustly.

C1) Generate plaintext “all logs” file (streaming)
- Implement a builder that writes a single scan-friendly plaintext file:
  - header metadata (run_id, timestamp, suite list, device info if cheap)
  - master run summary
  - per-suite sections in run order with clear delimiters
  - truncate huge logs (head/tail) rather than slurping everything
- Must stream (BufRead/BufWrite); never load entire logs into memory.
- PROOF: unit test verifying chunk boundaries and delimiter format.

C2) Chunk policy when plaintext exceeds cap
- Implement deterministic chunking: `all_logs_part01.txt`, `all_logs_part02.txt`, …
- Ensure each part <= (max_bytes - safety_margin).
- Prefer splitting on suite boundaries where possible.
- PROOF: test creates synthetic oversized content and asserts multiple parts are produced with correct sizes and naming.

C3) ZIP packaging: implement migration path to Rust (and do it if feasible)
- If the repo must remain zip-compatible, implement ZIP in Rust using a Rust crate (no system `zip` required) OR switch to tar.gz if that’s already the established artifact format and acceptable for Discord.
- Must avoid recursion/self-inclusion and use relative paths.
- Must skip problematic filesystem entries (FIFOs, sockets, etc.) safely.
- PROOF: unit/integration test builds an archive and validates it doesn’t contain itself and contains expected relative paths.

PHASE D — WIRE IT UP: SHELL CALLS RUST SENDER
Goal: Bash orchestrates; Rust does the network work.

D1) Update `scripts/rj_run_tests.sh` to call the Rust CLI for sending artifacts
- Replace the consolidated ZIP upload and the new plaintext upload with a single Rust call that sends both (or multiple calls if splitting is needed).
- Keep bash logic small: gather paths, call Rust, handle exit code.
- PROOF: `rg 'curl .*discord' scripts/rj_run_tests.sh` shows reduced/removed artifact send paths (some curl may remain for other things, but uploads should prefer Rust).

D2) Failure UX / fallback
- If ZIP fails due to size: send message + plaintext anyway.
- If upload fails for any reason: send minimal summary text (no attachments) so the user still gets a notification.
- Always retain artifacts locally and print their paths at end of run.
- PROOF: a documented failure-mode run in the progress ledger.

TESTS + VALIDATION (DO NOT SKIP)
- Add Rust tests for:
  - multipart field naming `files[n]`
  - presence of `payload_json`
  - 429 backoff uses Retry-After or retry_after
  - chunking behavior for plaintext
- Add at least a `bash -n scripts/rj_run_tests.sh` sanity check step (or equivalent).
- If CI exists, ensure it passes. Keep dev-deps minimal.

DELIVERABLES
1) Working code implementing all phases above.
2) Updated docs:
   - either update the original design note or add a new `docs/discord_artifacts_fix.md` that reflects the actual implementation and flags/env vars.
3) Final “implementation report” (in your final response) must include:
   - list of changed files
   - key snippets or line references for the most important changes
   - which acceptance criteria were proven and how (commands/tests)

ACCEPTANCE CRITERIA (MUST MEET ALL)
- Running the test runner with Discord enabled results in Discord receiving:
  - a consolidated archive (zip or tar.gz) when under cap, AND
  - a plaintext “all logs” file OR chunked parts, always under cap.
- If any artifact exceeds cap:
  - upload is skipped for that artifact, with a clear Discord message indicating skip + local retention path.
- Any non-2xx response logs status + body snippet (redacted) so diagnosis is immediate.
- 429 handling honors Retry-After/retry_after.
- No infinite retries on 400/401/403/404/413.
- Works on Pi Zero 2 W constraints: streaming I/O, no giant allocations, bounded retries/timeouts.
- No new third-party system binaries introduced.

Now execute the plan. Start by creating the progress ledger and populating the checklist before editing any code.
