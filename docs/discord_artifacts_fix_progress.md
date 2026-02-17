# Discord Artifacts Fix - Progress Ledger

## Phase A - Bash Immediate Fixes

- [ ] **A1: Fix multipart field naming** (`scripts/rj_run_tests.sh`)
  - Replace `file1=@` with `files[0]=@` in all Discord uploads.
  - Files: `scripts/rj_run_tests.sh`
  - Proof: `rg 'file1=@' scripts/rj_run_tests.sh` returns zero matches.

- [ ] **A2: Improve observability in `discord_curl_with_retry`** (`scripts/rj_run_tests.sh`)
  - Print HTTP status + first 8 KiB of response body on non-2xx (redacted).
  - Save error response to `discord_error_<timestamp>.json` in run dir.
  - Files: `scripts/rj_run_tests.sh`
  - Proof: manual review showing printed status + body snippet logic.

- [ ] **A3: Fix consolidated ZIP self-inclusion** (`scripts/rj_run_tests.sh`)
  - Create temp ZIP outside `$run_dir` via `mktemp` under `${TMPDIR:-/tmp}`.
  - Zip from parent directory with relative paths.
  - Files: `scripts/rj_run_tests.sh`
  - Proof: show commands and explain why self-inclusion is impossible.

- [ ] **A4: Add size preflight for consolidated ZIP** (`scripts/rj_run_tests.sh`)
  - Configurable max via `RJ_DISCORD_MAX_FILE_BYTES` (default 8 MiB).
  - Skip upload + send message if oversized.
  - Files: `scripts/rj_run_tests.sh`
  - Proof: demonstrate oversized-file skip path logic.

- [ ] **A5: Retry policy tightening** (`scripts/rj_run_tests.sh`)
  - Fail fast on 400/401/403/404/413.
  - Retry 429 with Retry-After.
  - Bounded retries on 5xx.
  - Files: `scripts/rj_run_tests.sh`
  - Proof: list status codes with retry/fail-fast behavior.

## Phase B - Rust Webhook Sender

- [ ] **B1: Fix Rust sender multipart field name** (`crates/rustyjack-core/src/system/mod.rs`)
  - Change `.file("file", ...)` to `.part("files[0]", ...)` with `payload_json`.
  - Add response body capture (truncated 8 KiB) on error.
  - Add webhook URL redaction.
  - Files: `crates/rustyjack-core/src/system/mod.rs`
  - Proof: unit test asserting `files[0]` and `payload_json` in multipart form.

- [ ] **B2: Multi-file support in Rust** (`crates/rustyjack-core/src/system/mod.rs`)
  - New `send_discord_files(...)` accepting N files as `files[0..N-1]`.
  - Split into multiple posts if N > 10.
  - Files: `crates/rustyjack-core/src/system/mod.rs`
  - Proof: unit tests for N=1, N=2, and split case.

- [ ] **B3: Correct retry/backoff in Rust** (`crates/rustyjack-core/src/system/mod.rs`)
  - 429: sleep Retry-After header or retry_after JSON value.
  - Bounded retries with max attempts.
  - Fail-fast for 400/401/403/404/413.
  - Files: `crates/rustyjack-core/src/system/mod.rs`
  - Proof: tests with mock HTTP server.

- [ ] **B4: CLI command for sending files** (`crates/rustyjack-commands/src/lib.rs`, `crates/rustyjack-core/src/operations.rs`)
  - Extend existing `notify discord send` with repeated `--file` args.
  - Files: `crates/rustyjack-commands/src/lib.rs`, `crates/rustyjack-core/src/operations.rs`
  - Proof: CLI help output showing new flags.

## Phase C - Artifact Strategy

- [ ] **C1: Plaintext "all logs" builder (streaming)** (`crates/rustyjack-core/src/test_artifacts.rs`)
  - Header metadata, master summary, per-suite sections.
  - Stream via BufRead/BufWrite; truncate huge logs.
  - Files: `crates/rustyjack-core/src/test_artifacts.rs`
  - Proof: unit test verifying chunk boundaries and delimiter format.

- [ ] **C2: Chunk policy for oversized plaintext** (`crates/rustyjack-core/src/test_artifacts.rs`)
  - Deterministic chunking: `all_logs_part01.txt`, `all_logs_part02.txt`, etc.
  - Each part <= (max_bytes - safety_margin).
  - Prefer splitting on suite boundaries.
  - Files: `crates/rustyjack-core/src/test_artifacts.rs`
  - Proof: test with synthetic oversized content producing multiple parts.

- [ ] **C3: ZIP packaging in Rust** (`crates/rustyjack-core/src/test_artifacts.rs`, `Cargo.toml`)
  - Use `zip` crate for archive creation.
  - Avoid recursion/self-inclusion, use relative paths.
  - Skip FIFOs/sockets.
  - Files: `crates/rustyjack-core/src/test_artifacts.rs`, `crates/rustyjack-core/Cargo.toml`
  - Proof: test builds archive, validates no self-inclusion, correct relative paths.

## Phase D - Wire It Up

- [ ] **D1: Shell calls Rust sender for artifacts** (`scripts/rj_run_tests.sh`)
  - Replace curl-based consolidated upload with Rust CLI call.
  - Files: `scripts/rj_run_tests.sh`
  - Proof: `rg 'curl .*discord' scripts/rj_run_tests.sh` shows reduced upload paths.

- [ ] **D2: Failure UX / fallback** (`scripts/rj_run_tests.sh`)
  - On ZIP fail: send message + plaintext anyway.
  - On upload fail: send minimal summary text.
  - Always retain artifacts locally with path printout.
  - Files: `scripts/rj_run_tests.sh`
  - Proof: documented failure-mode logic.

## Tests & Validation

- [ ] Rust tests for multipart field naming `files[n]`
- [ ] Rust tests for `payload_json` presence
- [ ] Rust tests for 429 backoff with Retry-After
- [ ] Rust tests for chunking behavior
- [ ] `bash -n scripts/rj_run_tests.sh` syntax check passes
- [ ] Documentation updated (`docs/discord_artifacts_fix.md`)
