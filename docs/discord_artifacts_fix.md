# Discord Artifacts Fix - Implementation Reference

This document describes the Discord webhook upload fixes implemented across
the RustyJack test runner and core library.

## Problem Summary

1. **Multipart field name mismatch**: All Discord file uploads used `file1=@...`
   (bash) and `.file("file", ...)` (Rust). Discord requires `files[n]` naming.
2. **ZIP self-inclusion**: The consolidated ZIP was created inside the directory
   being zipped, causing self-inclusion and size inflation.
3. **No error diagnostics**: `discord_curl_with_retry()` discarded response bodies
   on failure, making diagnosis impossible.
4. **No size preflight**: The consolidated ZIP was uploaded regardless of size.
5. **Unbounded retries**: All non-2xx codes were retried equally, including
   non-retryable errors like 400/413.
6. **No plaintext log artifact**: Only a ZIP was generated; no scan-friendly
   plaintext file for quick Discord viewing.

## Changes

### Bash (`scripts/rj_run_tests.sh`)

**Multipart field naming (A1)**
- All `-F "file1=@..."` replaced with `-F "files[0]=@..."` (6 locations).

**Observability (A2)**
- `discord_curl_with_retry()` now captures response headers via `-D`.
- On non-2xx: prints HTTP status + first 8 KiB of response body (redacted).
- Saves redacted error body to `discord_error_<timestamp>.json` in run dir.
- New `redact_webhook_url()` function strips Discord webhook tokens from output.

**ZIP safety (A3)**
- Temp ZIP created under `${TMPDIR:-/tmp}` via `mktemp` (outside run dir).
- Zips using `cd parent_dir && zip -r temp_zip basename` for relative paths.
- Excludes: `*.core *.fifo *ui_input.fifo *.zip *.tmp`.

**Size preflight (A4)**
- New env var: `RJ_DISCORD_MAX_FILE_BYTES` (default: 8 MiB).
- If ZIP exceeds limit: skip upload, send Discord text notification with local path.

**Retry policy (A5)**
- `400/401/403/404/413`: Fail immediately with diagnostics (non-retryable).
- `429`: Retry using `Retry-After` header (preferred) or JSON `retry_after` value.
- `5xx`: Retry with backoff (`attempt * 2` seconds), bounded by `DISCORD_MAX_RETRIES`.

**Artifact upload wiring (D1, D2)**
- Consolidated upload tries Rust CLI first (`rustyjack notify discord send-test-artifacts`).
- Falls back to bash `upload_consolidated_results_zip()` if CLI unavailable.
- Last resort: text-only notification with local artifact path.
- Artifacts always retained locally with path printout.

### Rust (`crates/rustyjack-core`)

**Discord sender (`src/system/mod.rs`)**

Functions added/modified:
- `redact_webhook_url(s)` - Strips webhook tokens from strings.
- `discord_error_snippet(body)` - Truncates response body to 8 KiB, redacts.
- `discord_status_is_fatal(status)` - Returns true for 400/401/403/404/413.
- `parse_retry_after(headers, body)` - Extracts wait duration from 429 responses.
- `discord_send_with_retry(client, webhook, build_request)` - Retry loop with backoff.
- `send_discord_payload(root, embed, file, content)` - Now delegates to `send_discord_files()`.
- `send_discord_files(root, embed, files, content)` - Multi-file sender using `files[n]` naming.

Constants:
- `DISCORD_DIAG_MAX_BYTES` = 8192
- `DISCORD_MAX_RETRIES` = 5
- `DISCORD_MAX_FILES_PER_MESSAGE` = 10

**Test artifacts (`src/test_artifacts.rs`)**

New module for building test run artifacts:
- `build_plaintext_logs(run_dir, run_id, max_bytes)` - Streaming plaintext builder.
  - Header metadata, master summary, per-suite sections.
  - Truncates large logs (head 200 + tail 400 lines).
  - Chunks into `all_logs_partNN.txt` if oversized.
- `build_results_zip(run_dir, run_id)` - ZIP builder using `zip` crate.
  - Created outside run dir, moved in after completion.
  - Relative paths, skips FIFOs/sockets/existing archives.

**Commands (`crates/rustyjack-commands/src/lib.rs`)**

- `DiscordSendArgs.file` changed from `Option<PathBuf>` to `Vec<PathBuf>` (repeatable `--file`).
- New: `DiscordCommand::SendTestArtifacts(DiscordTestArtifactsArgs)` subcommand.
- `DiscordTestArtifactsArgs`: `--run-dir`, `--run-id`, `--message`, `--max-file-bytes`.

**Operations (`crates/rustyjack-core/src/operations.rs`)**

- `handle_discord_send()` updated for `Vec<PathBuf>` file list.
- New: `handle_discord_test_artifacts()` - builds ZIP + plaintext, sends via `send_discord_files()`.

**Dependencies (`crates/rustyjack-core/Cargo.toml`)**

- Added: `zip = { version = "2", default-features = false, features = ["deflate"] }`

### UI (`crates/rustyjack-ui/src/app/settings.rs`)

- Updated `DiscordSendArgs` construction from `file: Some(path)` to `file: vec![path]`.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RJ_DISCORD_MAX_FILE_BYTES` | `8388608` (8 MiB) | Max file size for Discord uploads |
| `RJ_DISCORD_WEBHOOK_URL` | (none) | Discord webhook URL override |
| `RJ_DISCORD_WEBHOOK_ENABLED` | `1` | Enable/disable Discord notifications |
| `RJ_DISCORD_WEBHOOK_USERNAME` | `RustyJack` | Discord webhook display name |
| `RJ_DISCORD_WEBHOOK_MENTION` | (none) | Mention text prefix |

## CLI Usage

```bash
# Send files manually
rustyjack notify discord send \
  --title "Test Results" \
  --file /path/to/file1.zip \
  --file /path/to/file2.txt \
  --message "Optional message"

# Build and send test artifacts (used by rj_run_tests.sh)
rustyjack notify discord send-test-artifacts \
  --run-dir /var/tmp/rustyjack-tests/20260217-153000 \
  --run-id 20260217-153000 \
  --message "RustyJack test run results" \
  --max-file-bytes 8388608
```

## Tests

14 unit tests covering:
- Webhook URL redaction (2 tests)
- Error snippet truncation + redaction (2 tests)
- Fatal status code detection (1 test)
- Retry-After parsing: header, JSON body, fallback (3 tests)
- Multipart field naming format (1 test)
- Plaintext logs: single file, delimiters, chunking (3 tests)
- ZIP: no self-inclusion, relative paths (1 test)
- Head/tail truncation of large logs (1 test)

## Acceptance Criteria Met

- [x] Discord receives consolidated ZIP when under cap
- [x] Discord receives plaintext all-logs file (or chunked parts) when under cap
- [x] Oversized artifacts: upload skipped with Discord message + local retention
- [x] Non-2xx responses log status + body snippet (redacted)
- [x] 429 handling honors Retry-After / retry_after
- [x] No infinite retries on 400/401/403/404/413
- [x] Streaming I/O, bounded retries/timeouts (Pi Zero 2 W constraints)
- [x] No new third-party system binaries
