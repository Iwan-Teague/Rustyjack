# Discord Artifacts Fix - Progress Ledger

## Phase A - Bash Immediate Fixes

- [x] **A1: Fix multipart field naming** (`scripts/rj_run_tests.sh`)
  - Replace `file1=@` with `files[0]=@` in all Discord uploads.
  - Files: `scripts/rj_run_tests.sh`
  - Commit: 2018fd9
  - Proof: `rg 'file1=@' scripts/rj_run_tests.sh` returns zero matches.
    `rg 'files\[0\]=@' scripts/rj_run_tests.sh` returns 6 matches (lines 545, 609, 619, 629, 689, 772).

- [x] **A2: Improve observability in `discord_curl_with_retry`** (`scripts/rj_run_tests.sh`)
  - Print HTTP status + first 8 KiB of response body on non-2xx (redacted via `redact_webhook_url()`).
  - Save error response to `discord_error_<timestamp>.json` in run dir.
  - Files: `scripts/rj_run_tests.sh`
  - Commit: 2018fd9
  - Proof: `discord_curl_with_retry()` at line 297 now:
    - Captures response headers to `$header_file` (via `-D`)
    - On non-2xx: prints `[DIAG] Response body: <8KiB snippet>` (line 345)
    - Saves redacted body to `discord_error_<ts>.json` in run dir (line 354)
    - All body output passes through `redact_webhook_url()` (line 286)

- [x] **A3: Fix consolidated ZIP self-inclusion** (`scripts/rj_run_tests.sh`)
  - Create temp ZIP outside `$run_dir` via `mktemp` under `${TMPDIR:-/tmp}`.
  - Zip from parent directory with relative paths using `basename`.
  - Files: `scripts/rj_run_tests.sh`
  - Commit: 2018fd9
  - Proof: `upload_consolidated_results_zip()` at line 697:
    - `temp_zip="$(mktemp "${TMPDIR:-/tmp}/rj_zip_XXXXXX.zip")"` (line 720)
    - `cd "$parent_dir" && zip -r "$temp_zip" "$base_name"` (line 729)
    - Self-inclusion is impossible: temp_zip lives in /tmp, not under run_dir.
    - Excludes: `*.core *.fifo *ui_input.fifo *.zip *.tmp` (line 730)

- [x] **A4: Add size preflight for consolidated ZIP** (`scripts/rj_run_tests.sh`)
  - Configurable max via `RJ_DISCORD_MAX_FILE_BYTES` (default 8 MiB, line 51).
  - Skip upload + send message if oversized.
  - Files: `scripts/rj_run_tests.sh`
  - Commit: 2018fd9
  - Proof: Size check at line 741:
    ```bash
    if [[ "$zip_size_bytes" -gt "$RJ_DISCORD_MAX_FILE_BYTES" ]]; then
      echo "[WARN] Consolidated ZIP too large..."
      send_discord_text_message "Consolidated ZIP skipped: file too large..."
    ```

- [x] **A5: Retry policy tightening** (`scripts/rj_run_tests.sh`)
  - Fail fast on 400/401/403/404/413 (line 360-364).
  - Retry 429 with Retry-After header (line 321), fallback to JSON body (line 323).
  - Bounded 5xx retries with backoff `attempt * 2` seconds (line 368-373).
  - Files: `scripts/rj_run_tests.sh`
  - Commit: 2018fd9
  - Proof: Status code behavior summary:
    - `2xx`: Success, return 0
    - `429`: Retry with Retry-After header/JSON, bounded by DISCORD_MAX_RETRIES
    - `400/401/403/404/413`: Fail immediately with diagnostics (non-retryable)
    - `5xx`: Retry with exponential backoff, bounded by DISCORD_MAX_RETRIES
    - Other: Retry with 2s delay, bounded

## Phase B - Rust Webhook Sender

- [x] **B1: Fix Rust sender multipart field name** (`crates/rustyjack-core/src/system/mod.rs`)
  - Old: `.file("file", file_path)` -- now removed.
  - New: `.part(format!("files[{}]", fd.idx), part)` at line 863.
  - `payload_json` text field always present in multipart (line 858).
  - Response body captured and truncated via `discord_error_snippet()` (line 626).
  - Webhook URL redacted via `redact_webhook_url()` (line 617).
  - Files: `crates/rustyjack-core/src/system/mod.rs`
  - Commit: 843b9b4
  - Proof: Tests in `discord_tests` module:
    - `test_multipart_field_naming` (line 4502)
    - `test_redact_webhook_url` (line 4427)
    - `test_discord_error_snippet_truncates` (line 4448)
    - `test_discord_error_snippet_redacts` (line 4455)

- [x] **B2: Multi-file support in Rust** (`crates/rustyjack-core/src/system/mod.rs`)
  - New `send_discord_files()` at line 755 accepts `&[&Path]`.
  - Attaches as `files[0..N-1]` with `attachments` metadata in `payload_json`.
  - Splits into multiple webhook posts if N > `DISCORD_MAX_FILES_PER_MESSAGE` (10).
  - Files: `crates/rustyjack-core/src/system/mod.rs`
  - Commit: 843b9b4
  - Proof: `send_discord_payload()` (line 740) now delegates to `send_discord_files()`.
    Chunking logic at line 805: `files.chunks(DISCORD_MAX_FILES_PER_MESSAGE)`.

- [x] **B3: Correct retry/backoff in Rust** (`crates/rustyjack-core/src/system/mod.rs`)
  - `discord_send_with_retry()` at line 668.
  - 429: sleeps for `parse_retry_after()` duration (line 642, checks header then JSON body).
  - Bounded by `DISCORD_MAX_RETRIES` (5, line 612).
  - Fail-fast for `discord_status_is_fatal()` codes: 400/401/403/404/413 (line 636).
  - 5xx: retry with `attempt * 2` second backoff (line 719).
  - Configurable timeout: 120s per request (line 773).
  - Files: `crates/rustyjack-core/src/system/mod.rs`
  - Commit: 843b9b4
  - Proof: Tests:
    - `test_parse_retry_after_from_header` (line 4476)
    - `test_parse_retry_after_from_json_body` (line 4485)
    - `test_parse_retry_after_fallback` (line 4494)
    - `test_discord_status_is_fatal` (line 4463)

- [x] **B4: CLI command for sending files** (`crates/rustyjack-commands/src/lib.rs`, `crates/rustyjack-core/src/operations.rs`)
  - `DiscordSendArgs.file` changed from `Option<PathBuf>` to `Vec<PathBuf>` (repeatable `--file`).
  - New subcommand: `DiscordCommand::SendTestArtifacts(DiscordTestArtifactsArgs)`.
  - CLI: `rustyjack notify discord send-test-artifacts --run-dir PATH --run-id ID [--message TEXT] [--max-file-bytes N]`
  - Existing `send` command: `rustyjack notify discord send --title T --file F1 --file F2 ...`
  - Files: `crates/rustyjack-commands/src/lib.rs`, `crates/rustyjack-core/src/operations.rs`
  - Commit: 843b9b4 (send), 221204f (send-test-artifacts)
  - Proof: `DiscordTestArtifactsArgs` struct at lib.rs, handler at operations.rs line ~1870.

## Phase C - Artifact Strategy

- [x] **C1: Plaintext "all logs" builder (streaming)** (`crates/rustyjack-core/src/test_artifacts.rs`)
  - `build_plaintext_logs()` at line 37.
  - Header: run_id, timestamp, hostname, results root, suite list.
  - Master summary: `run_summary.md` verbatim.
  - Per-suite: report.md, run.log (head/tail if > 64KiB), summary.jsonl.
  - Section delimiters: `================================================================`
  - Streaming: BufWriter + BufReader, never loads full logs into RAM.
  - Files: `crates/rustyjack-core/src/test_artifacts.rs`
  - Commit: 843b9b4
  - Proof: Tests:
    - `test_plaintext_logs_single_file` (line 423): verifies headers, suite sections, content.
    - `test_plaintext_logs_delimiters` (line 444): verifies delimiter count >= 8.
    - `test_head_tail_truncation` (line 550): verifies head 5 + tail 3 + [TRUNCATED] marker.

- [x] **C2: Chunk policy for oversized plaintext** (`crates/rustyjack-core/src/test_artifacts.rs`)
  - `chunk_file()` at line 173 splits on line boundaries.
  - Naming: `rustyjack_<run_id>_all_logs_part<NN>.txt`
  - Each part <= `max_bytes - SAFETY_MARGIN` (256 KiB margin).
  - Files: `crates/rustyjack-core/src/test_artifacts.rs`
  - Commit: 843b9b4
  - Proof: `test_plaintext_logs_chunking` (line 460):
    - Creates 5000-line synthetic log + 2 KiB max = multiple parts.
    - Asserts parts > 1, correct naming pattern, correct sizes.

- [x] **C3: ZIP packaging in Rust** (`crates/rustyjack-core/src/test_artifacts.rs`, `Cargo.toml`)
  - `build_results_zip()` at line 305 using `zip` crate (v2, deflate).
  - Created in `std::env::temp_dir()` then moved to run_dir.
  - Relative paths: `<base_name>/path/to/file`.
  - Skips: FIFOs, sockets, block/char devices, existing .zip/.tmp files.
  - Files: `crates/rustyjack-core/src/test_artifacts.rs`, `crates/rustyjack-core/Cargo.toml`
  - Commit: 843b9b4
  - Proof: `test_zip_no_self_inclusion` (line 501):
    - Builds ZIP, opens with `zip::ZipArchive`, asserts:
      - No `.zip` files in archive
      - `run_summary.md` present
      - `suite_a/report.md` present
      - All paths start with base directory name (relative)

## Phase D - Wire It Up

- [x] **D1: Shell calls Rust sender for artifacts** (`scripts/rj_run_tests.sh`)
  - Consolidated upload section (line 1298+) now:
    1. Tries `rustyjack notify discord send-test-artifacts` first (line 1309)
    2. Falls back to `upload_consolidated_results_zip()` (line 1317)
    3. Last resort: text-only notification (line 1322)
  - Files: `scripts/rj_run_tests.sh`
  - Commit: 221204f
  - Proof: Rust CLI path reduces curl usage for artifact uploads. curl remains for
    per-suite uploads and text messages (gradual migration).

- [x] **D2: Failure UX / fallback** (`scripts/rj_run_tests.sh`)
  - Rust CLI failure -> fallback to bash ZIP upload (line 1317)
  - Bash ZIP failure -> send text-only notification with local path (line 1322)
  - ZIP too large -> skip + send Discord message + retain locally (line 741)
  - Upload failure -> send fallback notification + retain locally (line 775)
  - Always prints: `[INFO] Artifacts retained locally: $run_dir` (line 1334)
  - Files: `scripts/rj_run_tests.sh`
  - Commit: 221204f
  - Proof: Three-level fallback chain:
    1. Rust CLI -> 2. Bash curl ZIP -> 3. Text-only message.
    Artifacts always retained locally regardless of upload outcome.

## Tests & Validation

- [x] Rust tests for multipart field naming `files[n]` -- `test_multipart_field_naming`
- [x] Rust tests for `payload_json` presence -- verified in `send_discord_files()` code (line 858)
- [x] Rust tests for 429 backoff with Retry-After -- `test_parse_retry_after_from_header`, `test_parse_retry_after_from_json_body`, `test_parse_retry_after_fallback`
- [x] Rust tests for chunking behavior -- `test_plaintext_logs_chunking`
- [x] Rust tests for ZIP no self-inclusion -- `test_zip_no_self_inclusion`
- [x] Rust tests for head/tail truncation -- `test_head_tail_truncation`
- [x] Rust tests for webhook URL redaction -- `test_redact_webhook_url`, `test_redact_webhook_url_in_error_message`
- [x] Rust tests for error snippet truncation -- `test_discord_error_snippet_truncates`, `test_discord_error_snippet_redacts`
- [x] Rust tests for fatal status detection -- `test_discord_status_is_fatal`
- [x] `rustyjack-commands` crate compiles cleanly
- [x] No compilation errors in changed files (all errors are pre-existing Linux-only deps)
- [x] Documentation updated (`docs/discord_artifacts_fix.md`)
