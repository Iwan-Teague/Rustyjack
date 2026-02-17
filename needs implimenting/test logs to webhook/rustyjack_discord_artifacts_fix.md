# RustyJack: Send consolidated ZIP **and** plaintext logs to Discord after `rj_run_tests.sh`

## Goal

When `scripts/rj_run_tests.sh` is run on a Pi Zero 2 W (and “all” suites are selected), the user should receive:

1) A **ZIP** containing the full run artifacts (as today’s intent), and  
2) A **plain text, uncompressed** document containing the relevant logs/results in a single readable file.

This doc explains what’s failing today, where in the repo it’s happening, why it’s happening, and how to fix it **while following project constraints** (Rust-first; avoid relying on extra third‑party system binaries for fixes/features).

---

## What’s the problem?

### Symptom
Selecting “all” should upload a consolidated `rustyjack_<run_id>_results.zip` to a Discord webhook, but the upload fails (and the run ends without the ZIP showing up in Discord).

### Likely root causes (they stack)
1) **Discord multipart file field name mismatch**
   - The script uses curl form fields like `file1=@...`.
   - Discord’s API reference indicates file parts must be named `files[n]` (e.g. `files[0]`, `files[1]`).
   - This can yield `HTTP 400` “Invalid Form Body” style failures, and the script currently does not print the response body on failure, so it looks like a mysterious “zip upload is broken”.

2) **File size limit**
   - Discord applies an upload size limit **per file**. The consolidated ZIP can exceed that limit for an “all suites” run.
   - The script does not preflight/check file sizes for the consolidated ZIP (it checks size for suite bundles, but not the consolidated ZIP).

3) **The script hides the error details**
   - `discord_curl_with_retry` stores the response body in a temp file but does not print it when non-2xx codes happen, which makes diagnosis much harder.

4) **Constraint drift**
   - Uploading and packaging rely on system binaries (`curl`, `zip`, `tar`, etc.). On minimal images these may be missing or behave differently.
   - The project’s direction is to keep behavior in **Rust** where feasible, rather than “hope the appliance OS has the right utils installed”.

---

## Where is the problem in this repo?

### Bash test runner
File: `scripts/rj_run_tests.sh`

Key functions/blocks:
- `discord_curl_with_retry` — curl wrapper that retries on 429 but doesn’t surface response bodies on other failures.
- `send_discord_summary` — uploads `run_summary.md` using `-F "file1=@..."`
- `send_discord_suite_artifacts` / suite bundle uploads — also use `file1`
- `upload_consolidated_results_zip` — creates `rustyjack_<run_id>_results.zip` via `zip -r ...` and uploads it using `file1`

### Existing Rust Discord sender (already present)
File: `crates/rustyjack-core/src/system/mod.rs`

Function:
- `send_discord_payload(...)` — already uses `reqwest` multipart for a webhook, but currently attaches the file under a single name (`file`) and supports only one file.

CLI wiring:
- `crates/rustyjack-commands/src/lib.rs` defines the `DiscordCommand` and args.
- `crates/rustyjack-core/src/operations.rs` handles `DiscordCommand::Send` via `handle_discord_send(...)`, which calls `send_discord_payload(...)`.

---

## Why it’s a problem (mechanics)

### Discord wants `multipart/form-data` file parts named `files[n]`
Discord’s API reference says endpoints that accept file uploads use `files[n]` fields (e.g. `files[0]`, `files[1]`), with optional JSON provided as `payload_json`.  
Using a different name can work “sometimes” (depending on endpoint quirks), but it’s not something you can depend on.

### Discord enforces per-file upload limits
Even if the “field name” is corrected, the ZIP can still fail if it’s too large. If the consolidated ZIP is the entire run directory (including UI artifacts, screenshots, etc.), it can grow quickly.

### Poor error visibility
When a webhook responds with a JSON error body, the script discards it. That leaves you guessing whether it was:
- 400 invalid form body,
- 413 payload too large,
- 429 rate limited (handled),
- 500/502 transient Discord errors,
- DNS/TLS issues, etc.

---

## How to fix (recommended approach: Rust-first, constraint-aligned)

### High-level plan
1) **Generate** the two artifacts after the run:
   - `rustyjack_<run_id>_results.zip`
   - `rustyjack_<run_id>_all_logs.txt` (or chunked parts if needed)
2) **Upload** both artifacts to the Discord webhook in a single webhook execution (or two posts if you prefer simplicity).
3) Keep the bash script as an orchestrator only; move network + archive behavior into Rust so we stop depending on `curl`/`zip` availability.

---

## Step-by-step implementation (Rust changes)

### 1) Add multi-file support to `send_discord_payload`
**Where:** `crates/rustyjack-core/src/system/mod.rs`

Add a new function (or extend the existing one) to send multiple attachments:

- Accept `files: &[PathBuf]` (or `Vec<PathBuf>`)
- Build a multipart form where:
  - `payload_json` includes an `attachments` array referencing indices 0..N-1
  - each file part is named `files[0]`, `files[1]`, ...

Pseudo-code sketch:

```rust
pub fn send_discord_payload_multi(
    root: &Path,
    embed: Option<serde_json::Value>,
    files: &[PathBuf],
    message: Option<&str>,
) -> Result<bool> {
    let hook = read_discord_webhook(&ctx)?;
    let client = reqwest::blocking::Client::new();

    // Build payload_json (content + optional embeds + attachments[])
    let payload = build_payload_json(embed, message, files);

    let mut form = reqwest::blocking::multipart::Form::new()
        .text("payload_json", payload.to_string());

    for (i, path) in files.iter().enumerate() {
        let part = reqwest::blocking::multipart::Part::file(path)?;
        form = form.part(format!("files[{i}]"), part);
    }

    let resp = client.post(&hook).multipart(form).send()?;
    // handle non-2xx with body capture for debugging
    Ok(resp.status().is_success())
}
```

Also add better diagnostics:
- On non-2xx, read and log the response body (truncate to, say, 8 KB).
- Preserve/port the existing 429 retry logic, but in Rust (read `retry_after` / `Retry-After`).

### 2) Add test artifact builders (ZIP + plaintext)
**Where:** new module, e.g. `crates/rustyjack-core/src/test_artifacts.rs` (or `system/test_artifacts.rs`)

#### 2a) ZIP builder (no system `zip`)
Add a dependency in `crates/rustyjack-core/Cargo.toml`:

```toml
zip = { version = "2", default-features = false, features = ["deflate"] }
```

Then implement:

- walk the run dir (use existing `walkdir`)
- write each file into a `ZipWriter`
- use relative paths inside the ZIP
- exclude output artifacts themselves (avoid zipping `*_results.zip` into itself)

#### 2b) Plaintext bundle builder
Create a single text file that concatenates key files in a readable format, with section delimiters. Suggested inputs:

- `run_summary.md` (master report)
- `run_summary.json`
- each suite:
  - `<suite>/report.md`
  - `<suite>/run.log`
  - `<suite>/summary.jsonl` (if present)

Write in streaming mode (BufRead/BufWrite) so we don’t blow memory.

**Size strategy:** if the plaintext bundle exceeds the Discord limit, split into parts:

- `rustyjack_<run_id>_all_logs_part01.txt`
- `rustyjack_<run_id>_all_logs_part02.txt`
- …

Splitting can be done by byte count while writing.

### 3) Expose a single CLI entrypoint that the bash script can call
**Where:**  
- `crates/rustyjack-commands/src/lib.rs` (new command/args)  
- `crates/rustyjack-core/src/operations.rs` (handler)

Add a command like:

```
rustyjack discord send-test-artifacts --run-dir <PATH> --run-id <ID> [--message "..."]
```

Handler logic:

1) Build ZIP + plaintext bundle(s)
2) Send webhook message with:
   - ZIP
   - plaintext bundle (or multiple parts)

This keeps `rj_run_tests.sh` simple and makes uploads consistent across platforms.

---

## Step-by-step implementation (bash changes)

### Minimal bash integration (recommended)
**Where:** `scripts/rj_run_tests.sh`

After the run completes (right where it currently calls `upload_consolidated_results_zip`), replace the curl-based upload with the Rust CLI:

```bash
rustyjack discord send-test-artifacts   --run-dir "$OUTROOT/$RUN_ID"   --run-id "$RUN_ID"   --message "RustyJack consolidated artifacts (Run ID: $RUN_ID)"
```

Keep the existing summary message logic (or migrate that too).

### Optional: Improve shell-side debugging immediately
If you keep curl around temporarily, add one line to `discord_curl_with_retry`:

- When `http_code` is not 2xx, print the first N bytes of the response body temp file to stderr.
- That instantly reveals “invalid form body” vs “payload too large”.

---

## What “fixed” looks like (acceptance criteria)

After running `scripts/rj_run_tests.sh --all --discord-enable`:

1) Discord receives **one message** (preferred) containing:
   - `rustyjack_<run_id>_results.zip`
   - `rustyjack_<run_id>_all_logs.txt` (or `*_partNN.txt`)

2) If the ZIP or log bundle is too large:
   - Discord still receives *something* useful:
     - a smaller “critical-only” ZIP (optional enhancement), and/or
     - chunked plaintext parts
   - The message explicitly states what was trimmed/split.

3) On failure:
   - Logs include the HTTP status and the first chunk of Discord’s JSON error body (so you can tell **why** it failed).
   - Retrying honors Discord’s `retry_after` guidance.

---

## Notes on Discord expectations (implementation guardrails)

- Use `payload_json` for the message body when uploading files via multipart.
- Name file fields `files[0]`, `files[1]`, … when sending multiple attachments.
- Treat the upload limit as **per file** and avoid hard-coding the exact byte limit; make it configurable and keep a safety margin.

---

## Suggested test plan (Pi Zero 2 W)

1) Run a small suite set and confirm:
   - ZIP + plaintext both arrive
   - filenames are stable
2) Run “all” and confirm:
   - if files exceed limit, chunking happens (plaintext parts) and ZIP behavior is sensible
3) Validate failure mode:
   - temporarily set an invalid webhook URL and verify the system reports the response body/details cleanly

---

## Appendix: Stopgap curl fix (if you need a same-day unblock)

If you cannot ship the Rust refactor immediately, at least align with Discord’s field naming:

- Replace `file1=@...` with `files[0]=@...` in every curl multipart upload.
- For “ZIP + plaintext”, send both in one request:

```bash
discord_curl_with_retry   -F "payload_json=$payload_json"   -F "files[0]=@${zip_file};filename=rustyjack_${run_id}_results.zip"   -F "files[1]=@${txt_file};filename=rustyjack_${run_id}_all_logs.txt"
```

This does *not* satisfy the “avoid system binaries” constraint, but it will likely fix the webhook payload format quickly.
