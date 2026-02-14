# Area 16 — Observability: logging, redaction, audit trails (Architecture Doc 2)

**Repo snapshot:** `watchdog_shallow_20260213-173640.zip` (no git metadata in archive)  
**Report date:** `2026-02-14`  
**Hard constraints honored:** read-only analysis; logging/redaction *constraints* taken only from root docs (`README.md`, `AGENTS.md`, `CLAUDE.md`) plus `logs/done/*` (implementation details from code).  
**Safety scope:** This report discusses privacy, redaction correctness, integrity, and diagnostic value. It does **not** provide operational “how-to” guidance for offensive workflows.

---

## 0) What “good” looks like here

This system contains modules that handle extremely sensitive material (captured credentials, wireless keys, packet captures). Observability has to deliver:
- **Diagnostic value** (enough context to debug failures),
- **Privacy by default** (secrets *never* hit operational logs or exported UI bundles),
- **Predictable retention** (no runaway journald / SD wear),
- **Auditability** (append-only, timestamped, correlatable records for privileged actions).

---

## 1) Logging architecture (current)

### 1.1 Sinks / destinations
**Tracing / operational logs** (via `rustyjack-logging`):
- File logs under the runtime root: `root/logs/*.log`  
  - `rustyjackd.log`, `rustyjack-ui.log`
  - `usb.log`, `wifi.log`, `net.log`, `crypto.log`
  - `audit/audit.log` (separate JSONL file; also duplicated to tracing)
- Stdout layer → typically collected by **systemd-journald** when run as a service.

**“Loot” logs / artifacts** (not the same as operational logs):
- Under `root/loot/**` (e.g., portal credential/visit logs, pipeline logs, capture metadata).

**UI export surfaces**:
- `collect_log_bundle()` returns a **single string** that embeds log tails + system snapshots (routes/arp/resolv.conf, etc.). This is a high-risk egress path if any secret ever lands in operational logs.

### 1.2 Volume controls / toggles
- `LoggingConfig` supports:
  - `enabled: bool` (implemented as `EnvFilter = "off"` when disabled),
  - `level: trace|debug|info|warn|error`,
  - `keep_days: u32` retention for rolled logs.
- Runtime env toggle used across components:
  - `RUSTYJACK_LOGS_DISABLED=1` (set/unset by logging config application).
- Packet logging toggle (kernel/journal side):
  - `RUSTYJACK_NFTABLES_LOG=1` enables nftables log rules → can spam journald.

### 1.3 Retention / cleanup
- A daemon background task calls `rustyjack_logging::retention::run_retention(root, keep_days)` every 24h:
  - removes old rotated files,
  - caps `logs/` and `logs/audit/` to ~200 MB each (by deleting oldest).
- UI “Purge Logs” currently deletes **loot** log files (under `root/loot/**` matching `*.log*`), but does **not** guarantee journald vacuum, and does not delete `root/logs/*` component logs.

---

## 2) Data sensitivity map

### 2.1 MUST NEVER appear in operational logs (files or journald)
**Tier 0: Secrets (never log, never include in UI log bundle)**
- Captured portal submissions: `user`, `pass` (and derivatives).
- Wireless key material:
  - WPA/WPA2 PSKs, candidate passwords, “found password”.
  - PMK/PMKID/handshake-derived secrets (raw key material).
- Any private keys / tokens / API credentials (device management tokens, update signing keys, etc.).
- Full packet payloads that may contain credentials/session cookies.

**Tier 1: High-risk identifiers (log sparingly; avoid exporting by default)**
- Full IP/MAC address inventories, ARP tables, routing tables, resolv.conf, DNS servers/search domains.
- User agent strings + client IPs (portal visit logs are inherently sensitive).
- SSID/BSSID + timestamped presence (location inference / correlation risk).

**Tier 2: Lower-risk operational metadata (generally OK)**
- Operation start/stop, success/failure codes, durations.
- Interface names, component names, truncated hashes (if used), counts.
- Correlation IDs, request IDs, job IDs.

### 2.2 Where redaction is applied today
- **`crates/rustyjack-core/src/redact.rs`**
  - `redact!(value)` wrapper prints `[REDACTED]`.
  - `redact_json(&mut Value)` redacts fields whose *names* look sensitive.
- **Observed call sites using redaction**
  - `crates/rustyjack-core/src/external_tools/physical_access.rs` uses `redact!(pass)` in structured logs.
- **Notably absent**
  - No evidence of systematic redaction being applied at log sinks (format layer) or at UI export time (`collect_log_bundle`).

---

## 3) Redaction coverage audit

### 3.1 High-risk leak paths (confirmed)
1) **WPA cracking module logs password candidates and discovered passwords**  
   - `crates/rustyjack-wpa/src/crack.rs` logs:
     - `current: {password}` progress (candidate secrets),
     - `Quick crack SUCCESS! Password: {password}` (confirmed secret exfil into logs).

2) **UI log export includes raw tails (no redaction pass)**  
   - `crates/rustyjack-core/src/services/logs.rs` concatenates tails from `root/logs/*.log` and `root/logs/audit/audit.log` into an exportable string.

3) **Audit context is arbitrary JSON and is not redacted**  
   - `crates/rustyjack-core/src/audit.rs` serializes the `AuditEvent` including `context` exactly as provided.

### 3.2 Structured logging vs string concat
- There is a mix. Where `tracing::info!(field = %value, ...)` is used, it is **much easier** to guarantee redaction (wrap values, or enforce `skip()` in `#[instrument]`).
- Several of the most sensitive logs are **string-formatted**, which:
  - encourages accidental inclusion of secrets,
  - makes it harder to lint/scan in review,
  - is harder to redact post-hoc reliably.

---

## 4) Storage / volume risks

### 4.1 Journald spam
- Stdout is wired into journald for services; enabling verbose levels or nftables packet logging can overwhelm journal storage and CPU.
- Current mitigations:
  - UI log toggle can set `enabled=false` for tracing logs in-app,
  - but packet logging (nftables) is independent and can still generate massive kernel log volume.

### 4.2 SD wear / retention
- File logs are rotated daily + retained by days + capped by size (good baseline).
- However:
  - a single high-frequency log point can write continuously for hours before the 24h retention task runs,
  - journald volume is not comprehensively governed by this crate’s retention logic.

### 4.3 Export size controls
- Log bundle string is capped (`MAX_LOG_BUNDLE_BYTES=900_000`) and log tails are capped (`MAX_LOG_TAIL_BYTES=150_000`), which helps UI stability but **does not mitigate secret leakage**—it just truncates it.

---

## 5) Audit trail integrity

### 5.1 Current properties
- Audit events:
  - include `timestamp` (ms since epoch),
  - include `actor_uid`, `actor_pid`, optional `actor_group`,
  - written as JSON lines to `root/logs/audit/audit.log`.
- Integrity gaps:
  - write is via `writeln!` to an `OpenOptions::append(true)` file handle; without care, concurrent writers can interleave at the byte level,
  - no `fsync`/durability policy,
  - no correlation ID linking audit entries ↔ request/job IDs in operational logs,
  - no tamper-evidence (hash chaining / signatures).

### 5.2 What’s needed (minimum)
- “Append-only *semantics*” (single writer task or atomic line writes).
- Correlation IDs (request_id/job_id) on both operational logs and audit entries.
- Optional durability mode (batch sync) for high-value events.

---

## 6) Findings (18)

Each finding is structured as: **Problem → Why → Where → Fix → Fixed version looks like**.

### 1) Catastrophic: WPA cracking logs secret candidates + discovered passwords
- **Problem:** Candidate passwords and found passwords are written to tracing logs.
- **Why:** Leaks secrets into file logs and journald; later exported via UI log bundle; violates “never log secrets.”
- **Where:** `crates/rustyjack-wpa/src/crack.rs` (progress logging; quick crack success message).
- **Fix:** Remove password-bearing log fields entirely. Replace with count/rate only; optionally log a *short hash* if you need correlation (never the value).
- **Fixed version looks like:**
  ```rust
  // OK: no candidate value
  tracing::info!(attempts, rate = %format!("{rate:.1}"), "Crack progress");
  // OK: found without printing secret
  tracing::info!("Quick crack success");
  ```

### 2) Redaction utilities exist but are not enforced where it matters
- **Problem:** `redact!(...)` and `redact_json(...)` exist, but most call sites never use them.
- **Why:** The existence of helpers can create a false sense of safety; a single missed log site leaks secrets.
- **Where:** `crates/rustyjack-core/src/redact.rs`; only a couple of observed uses.
- **Fix:** Establish a “secret types can’t be Display/Debug’d” pattern:
  - wrap secrets in a `SecretString`/`Redacted<T>` newtype that redacts `Debug` and `Display`,
  - require explicit `.expose()` methods in the few places you truly need it (not logs),
  - add a CI grep/lint: forbid `Password:` / `current:` patterns and forbid formatting variables named `password|psk|token|key` in `tracing::` calls.
- **Fixed version looks like:**
  ```rust
  struct Secret(String); // Debug/Display => "[REDACTED]"
  tracing::info!(ssid=%ssid, "Trying candidate"); // no secret field at all
  ```

### 3) Documentation claim: “automatic redaction” does not match implementation reality
- **Problem:** Root docs claim passwords/keys/credentials are automatically redacted in logs, but the logging sink does not apply redaction generically.
- **Why:** Operators may assume logs are safe to export when they are not.
- **Where:** `README.md` (Logging / Safety statements); implementation: `rustyjack-logging` + call sites.
- **Fix:** Either:
  - implement a redacting formatter layer (hard; error-prone), **or**
  - change docs to “redaction is best-effort and enforced at call sites + tests” **and** add the test plan in section 7 to prove it.
- **Fixed version looks like:** docs + tests that continuously validate secret non-occurrence.

### 4) UI log bundle is an unredacted exfiltration channel
- **Problem:** `collect_log_bundle()` includes raw tails from multiple logs + system snapshots.
- **Why:** Any secret in operational logs becomes trivially exportable to screen/USB.
- **Where:** `crates/rustyjack-core/src/services/logs.rs`.
- **Fix:** Add a redaction pass over the assembled bundle *before* returning it:
  - apply regex-based scrubbing for known patterns (`pass=`, `Password:`),
  - and/or feed through a structured redaction filter if logs are migrated to JSON.
  - Still treat this as defense-in-depth; primary defense is “never log secrets.”
- **Fixed version looks like:** `collect_log_bundle_redacted()` that removes known secret markers.

### 5) AuditEvent context is not redacted
- **Problem:** `AuditEvent.context: Option<Value>` is serialized as-is.
- **Why:** A future call site can accidentally include secrets in context → durable audit leak.
- **Where:** `crates/rustyjack-core/src/audit.rs` (`with_context` and `log()`).
- **Fix:** Before serializing:
  - clone context,
  - run `redact_json(&mut value)` (and extend sensitivity rules),
  - or replace `Value` with a typed struct that never contains secrets.
- **Fixed version looks like:**
  ```rust
  let mut ctx = self.context.clone().unwrap_or(serde_json::json!({}));
  rustyjack_core::redact::redact_json(&mut ctx);
  ```

### 6) Audit file writes can interleave under concurrency
- **Problem:** `writeln!(file, "{}", json)` may perform multiple writes; concurrent writers can interleave bytes.
- **Why:** Breaks “append-only” semantics; corrupts JSONL; undermines integrity.
- **Where:** `crates/rustyjack-core/src/audit.rs` (`log()`).
- **Fix:** Ensure a single `write_all` call per event or centralize audit writing in a single-task channel.
- **Fixed version looks like:**
  ```rust
  let mut line = serde_json::to_vec(self)?;
  line.push(b'\n');
  file.write_all(&line)?;
  ```

### 7) Audit durability policy is undefined (power loss window)
- **Problem:** No flush/sync strategy for audit log.
- **Why:** Critical events can be lost during sudden power loss; integrity expectations unclear.
- **Where:** `crates/rustyjack-core/src/audit.rs`.
- **Fix:** Add policy knobs:
  - default: batch sync every N events / seconds,
  - “strict” mode: `sync_data()` for selected events (reboot/shutdown/config changes).
- **Fixed version looks like:** explicit durability mode in config + tests.

### 8) Portal credential logs are created without explicit restrictive permissions
- **Problem:** `credentials.log` and `visits.log` are opened without setting mode/ownership.
- **Why:** On misconfigured umask or directory permissions, secrets may become readable to unintended users.
- **Where:** `crates/rustyjack-portal/src/logging.rs` (`open_append()`).
- **Fix:** On Unix, use `OpenOptionsExt::mode(0o600)` (or 0o640 with correct group) and enforce directory perms.
- **Fixed version looks like:**
  ```rust
  #[cfg(unix)] opts.mode(0o600);
  ```

### 9) Portal logs are “log-shaped” and can be swept by log purge unexpectedly
- **Problem:** Loot purge treats `*.log` as disposable logs.
- **Why:** Captured credential artifacts may be deleted unintentionally; also encourages mixing “artifacts” with “diagnostic logs.”
- **Where:** UI purge logic in `crates/rustyjack-ui/src/app/system.rs` and portal files in loot.
- **Fix:** Separate directories/naming:
  - `loot/.../captures/credentials.txt` (not `.log`), or
  - implement allowlist: purge only `loot/**/logs/` not every `*.log`.
- **Fixed version looks like:** purge logic that targets only operational loot logs, not captured artifacts.

### 10) `is_sensitive_field()` is both over-broad and under-broad
- **Problem:** substring matching on `"pass"`, `"key"`, `"auth"` can redact benign fields (false positives) and miss others (false negatives).
- **Why:** False positives reduce diagnostic value; false negatives leak secrets.
- **Where:** `crates/rustyjack-core/src/redact.rs`.
- **Fix:** Make sensitivity rules explicit and typed:
  - exact key matches (`password`, `psk`, `api_key`, `token`, `secret`, `private_key`, …),
  - plus a small controlled set of prefixes/suffixes (`*_password`, `*_token`).
- **Fixed version looks like:** a curated matcher + unit tests for known real payload shapes.

### 11) Secret-bearing structs derive `Debug` without redaction
- **Problem:** Types like Wi-Fi profile include `password` and derive `Debug`.
- **Why:** Any accidental `{:?}` logging or error wrapping can leak secrets.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` (`WifiProfile { password: Option<String> }`).
- **Fix:** Implement `Debug` manually to redact secret fields, or store secrets in a redacting wrapper type.
- **Fixed version looks like:** `Debug` prints password as `"[REDACTED]"`.

### 12) Audit events are duplicated to operational logs without strong filtering
- **Problem:** `AuditEvent::log()` also emits `tracing::info!/warn!`.
- **Why:** If audit context ever expands, it can leak into regular logs; also increases log volume.
- **Where:** `crates/rustyjack-core/src/audit.rs` (after writing JSONL).
- **Fix:** Route audit tracing to a dedicated target and keep audit context out of tracing message entirely.
- **Fixed version looks like:**
  ```rust
  tracing::info!(target: "audit", operation=%self.operation, "Audit event");
  ```

### 13) Packet logging toggle can create unbounded journald growth
- **Problem:** `RUSTYJACK_NFTABLES_LOG=1` enables nftables `log` rules.
- **Why:** Per-packet logging is a journal flood vector + sensitive metadata leak (IPs, ports).
- **Where:** `crates/rustyjack-netlink/src/iptables.rs`.
- **Fix:** Make this opt-in with strong guardrails:
  - default OFF,
  - nftables rate limiting (`limit rate`),
  - log only counters unless actively debugging.
- **Fixed version looks like:** nft rules with `limit` + explicit UI warning.

### 14) Retention cadence (24h) can’t stop short-term log storms
- **Problem:** Retention job runs every 24h.
- **Why:** In a log storm, SD wear and disk fill can happen well before retention runs.
- **Where:** daemon retention task in `crates/rustyjack-daemon/src/main.rs`.
- **Fix:** Add a lightweight size check on a shorter interval (e.g., hourly) or trigger-on-rotate.
- **Fixed version looks like:** hourly size checks + delete-oldest when exceeding cap.

### 15) Log bundle exports network identity information by default
- **Problem:** Bundle includes `/etc/resolv.conf`, `/proc/net/*`, routes, ARP, etc.
- **Why:** These are often sensitive in real deployments; exporting them is a privacy risk.
- **Where:** `crates/rustyjack-core/src/services/logs.rs`.
- **Fix:** Provide “minimal” vs “full” bundle modes; default to minimal in UI; require explicit user action for full export.
- **Fixed version looks like:** a UI toggle “Include network inventory (sensitive)”.

### 16) Log directory permission model depends on external provisioning
- **Problem:** Some docs assume ownership/group for `root/logs` and UI access.
- **Why:** Mis-provisioned perms can cause log write failures or excessive access.
- **Where:** `AGENTS.md` notes ownership expectations; `crates/rustyjack-logging/src/init.rs` sets modes.
- **Fix:** Enforce:
  - setgid directory (2770),
  - consistent group ownership,
  - explicit error when perms are wrong (don’t silently degrade).
- **Fixed version looks like:** startup check “log dir writable + group correct”.

### 17) No “known-secret” regression test suite for redaction
- **Problem:** There’s no automated proof that secrets never hit logs.
- **Why:** Redaction regressions are silent and catastrophic.
- **Where:** Test suite (missing).
- **Fix:** Add end-to-end tests that inject sentinel secrets and then grep:
  - component logs,
  - audit log,
  - exported log bundle output.
- **Fixed version looks like:** CI test `assert_no_secret_in_logs()`.

### 18) Error paths may accidentally log sensitive inputs if future changes are careless
- **Problem:** Some modules log `{err}`; future errors might carry embedded secret material.
- **Why:** Error types sometimes include input values; this is a classic “oops” leak.
- **Where:** various `tracing::error!(..., "{err}")` call sites.
- **Fix:** Define a “safe error display” wrapper for errors in sensitive paths, or ensure errors do not include raw inputs. Also treat any untrusted string that can reach logs (hostnames, banners, SSIDs, user-provided labels) as *log data*: escape CR/LF and strip/escape ANSI control sequences to prevent log/terminal manipulation.
- **Fixed version looks like:** `tracing::error!(error=%SafeErr(err), "...")`.

---

## 7) Test plan

### 7.1 “Known secret” injection tests (redaction proof)
Goal: prove that a chosen sentinel secret string **never appears** in:
- `root/logs/*.log`
- `root/logs/audit/audit.log`
- output of `collect_log_bundle()`
- (optionally) service journal capture in test harness environments

**Sentinel:** `K0NOWN_SECRET_DO_NOT_LOG_9f2c1b`

Suggested tests:
1. **Redaction wrapper test**
   - Use `redact!(sentinel)` in a log message and assert logs contain `[REDACTED]` and **not** the sentinel.
2. **WPA crack logging regression test**
   - Run the cracking path with a password list containing the sentinel.
   - Assert *only* counts/rates are logged; sentinel absent.
3. **Audit context redaction test**
   - Create an `AuditEvent` with `context = { "password": sentinel }`.
   - Assert audit file contains `[REDACTED]`, not the sentinel.
4. **UI bundle export test**
   - Write a synthetic log line containing the sentinel into a component log file.
   - Call `collect_log_bundle()` and assert the sentinel is removed/redacted.

### 7.2 Load / spam tests (volume & retention)
Goal: prove that logging controls prevent runaway growth and SD wear.

1. **High-rate logging storm**
   - Emit N log lines/sec for M minutes at `debug` and `info`.
   - Confirm:
     - file sizes stay bounded by cap logic,
     - retention deletes oldest when exceeding cap,
     - UI remains responsive.
2. **Packet logging stress (if enabled in test env)**
   - Validate nftables log toggle includes a rate limit.
   - Confirm journal growth stays bounded (or the feature remains OFF by default).
3. **Export bundle size**
   - Ensure `collect_log_bundle()` truncation is deterministic and does not panic on large logs.

---

## 8) Prioritized “fix first” list (highest risk)
1. Remove WPA candidate/found password logging (Finding #1).  
2. Add bundle-time redaction defense-in-depth (Finding #4).  
3. Redact audit context + make audit writes atomic (Findings #5–#6).  
4. Tighten permissions on credential artifacts (Finding #8).  
5. Guardrails on nftables packet logging (Finding #13).  

---

## Appendix A — Key files touched by this audit (read-only)
- Logging framework: `crates/rustyjack-logging/src/*`
- Redaction utilities: `crates/rustyjack-core/src/redact.rs`
- Audit trail: `crates/rustyjack-core/src/audit.rs`
- Log export / UI surface: `crates/rustyjack-core/src/services/logs.rs`, `crates/rustyjack-ui/src/app/settings.rs`, `crates/rustyjack-ui/src/menu.rs`
- Portal capture logs: `crates/rustyjack-portal/src/logging.rs`
- High-risk leak: `crates/rustyjack-wpa/src/crack.rs`
