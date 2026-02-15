# Area 11 — Captive portal + DNSSpoof templates  
Date: 2026-02-15

**Repository:** `watchdog/` (RustyJack)  
**Scope (per request):** portal HTTP service (handlers, templating, form processing), template assets under `DNSSpoof/`, and redirection glue (DNAT/forward rules).  
**Hard rule respected:** this report is **read-only** and does **not** modify any repository files.

---

## Evidence used (repo-trusted constraints vs implementation evidence)

### Constraints / “rules of the appliance” (trusted sources)
- Root docs: `README.md`, `AGENTS.md`, `CLAUDE.md`, `TESTING.md`
- `logs/done/` notes, especially:
  - `logs/done/ethernet_mitm_dns_spoof.md` (states that captive portal is optional and logs visits/submissions)
  - `logs/done/loot_management.md` (loot layout + purge expectations)
  - `logs/done/crate_rustyjack_encryption.md` (encryption crate responsibilities)

### Implementation evidence (code + assets)
- Portal service: `crates/rustyjack-portal/src/{server.rs,state.rs,logging.rs,config.rs}`
- Template assets: `DNSSpoof/sites/portal/index.html`
- DNSSpoof orchestration + paths: `crates/rustyjack-core/src/operations.rs`
- Portal “service” entrypoint (fixed directories, DNAT mode): `crates/rustyjack-core/src/services/portal.rs`
- DNS spoof server + logging: `crates/rustyjack-netlink/src/dns_server.rs`
- Netfilter / DNAT glue: `crates/rustyjack-netlink/src/iptables.rs`
- Evil twin captive-portal netfilter lifecycle: `crates/rustyjack-wireless/src/evil_twin.rs`

---

## 1) Threat model

### Actors
- **Local clients (victim devices on the LAN/AP):** connect to the interface that RustyJack controls and make HTTP/DNS requests.
- **LAN adversary (same broadcast domain):** can spoof packets, flood the portal/DNS server, replay requests, and attempt to access local files via web paths (if possible).
- **Malicious inputs:** any data in:
  - HTTP headers (e.g., `User-Agent`)
  - HTTP path / query string
  - Form bodies (`application/x-www-form-urlencoded`)
  - DNS query names (domain labels can contain odd bytes; parser uses `from_utf8_lossy`)

### Assets to protect
- **Sensitive form submissions** (whatever the portal collects).
- **Operational logs** (they can contain user-controlled strings and potentially sensitive metadata).
- **System networking state** (iptables/nftables rules, IP forwarding), because “stuck” rules can break the box or leak traffic.

### Security goals (minimum viable)
- Prevent filesystem escape via template selection / static file serving.
- Prevent log injection and reduce sensitive data exposure in logs.
- Ensure networking rules are installed/removed predictably (including crash paths).
- Ensure request handling resists trivial DoS (size limits, timeouts, concurrency).

---

## 2) Web security audit (handlers, form processing, request limits, XSS, logging)

### What the portal does today (as implemented)
- Serves `/` by returning the contents of `index.html` loaded into memory at start (`PortalState::index_html`).
- Accepts `POST /capture` with an Axum `Form<CaptureForm>` and logs fields to `capture_dir/credentials.log`.
- Uses middleware:
  - request body limit (`RequestBodyLimitLayer`)
  - concurrency limit (`ConcurrencyLimitLayer`)
  - timeout (`TimeoutLayer`)
  - status classification + visit tracking (`rustyjack_logging::http`)

### Strengths
- **Explicit request body size cap** (configurable).  
- **Concurrency limit** (configurable).
- **Timeout** on requests (configurable).
- **Log injection mitigated in portal log files**: `escape_log_value` escapes newlines/control chars for `credentials.log` and `visits.log`.

### Risks / gaps
- No HTTP security headers (CSP, frame-ancestors, cache-control).
- Sensitive form submissions are written in a structured line format but **not encrypted** and file permissions are not forced.
- Visit logging can capture query strings; if other endpoints are added, secrets can leak via URL/query logging.
- No per-IP throttling / rate limiting; a LAN adversary can spam `POST /capture` until disk fills (bounded by body size but not by event rate).

---

## 3) Template handling safety (path traversal, asset integrity, encoding)

### How templates are selected today
- DNS spoof + portal flows in core accept a `site` string and build:
  - `site_dir = root/DNSSpoof/sites/<site>`
  - `capture_dir` derived from `site` (multiple call sites)
- The portal server serves a directory tree via `ServeDir::new(site_dir)` as a fallback service.

### Main template safety issues
- **Path traversal risk**: `PathBuf::join(&site)` is used without validation/canonicalization.
- **Repo-verified call sites**: the unvalidated `site` join appears in core operations that build both `site_dir` and capture paths (e.g., `crates/rustyjack-core/src/operations.rs`), and is later used to serve template trees (`ServeDir`) and to select capture output destinations.
- **Symlink escape risk**: a template directory can contain symlinks that point outside the intended web root; serving static files could leak arbitrary files if symlinks aren’t screened.
- **Template size / resource risk**: `index.html` is read into memory without a maximum size check.
- **Asset integrity**: nothing prevents accidental or malicious mutation of templates; at minimum, a “known templates allowlist” or hash inventory could help detect tampering on appliance installs.

---

## 4) Rule lifecycle and teardown (portal start/stop, crash cleanup)

### Portal DNAT lifecycle (portal service mode)
- `rustyjack-portal::start_portal` can install an iptables DNAT rule (`dnat_mode=true`) redirecting TCP/80 → `<listen_ip>:<listen_port>`.
- `stop_portal` removes the DNAT rule if it believes it was installed.

**Failure mode:** if the process crashes hard, teardown won’t run, and DNAT rules can remain.

### DNS spoof DNAT lifecycle
- `start_dns_spoof` installs DNAT for UDP/53 and TCP/53 to the local DNS server.
- `stop_dns_spoof` removes both rules.

Same crash concern: hard failures can strand DNAT rules.

### Captive portal netfilter lifecycle in Evil Twin
- `IptablesManager::setup_captive_portal` **flushes entire NAT and FILTER tables**, then adds DNAT for TCP/80 and TCP/443, and a forward accept rule.
- `evil_twin::cleanup` flushes NAT + FILTER tables again.

**This is risky** because it can remove unrelated rules and break coexisting features.

---

## 5) Findings (15)

Each finding follows: **Problem → Why → Where → Fix → Fixed version looks like**

### F1 — Sensitive form submissions stored in plaintext
- **Problem:** `credentials.log` writes user-submitted fields (including passwords) as plaintext lines.
- **Why:** local disk exposure (permissions/forensics) and accidental leakage via export/purge inconsistencies.
- **Where:** `crates/rustyjack-portal/src/logging.rs` (`credentials.log`), `crates/rustyjack-portal/src/server.rs` (`capture_post`).
- **Fix:** integrate `rustyjack-encryption` for loot-at-rest; store encrypted blobs (or encrypt the entire log file). Force file mode `0600`.
- **Fixed version looks like:** portal logger writes to `credentials.log.enc` via `encrypt_to_file`, or wraps an `AsyncWrite` that encrypts; plaintext never hits disk.

### F2 — Capture/visit log file permissions are not forced
- **Problem:** `OpenOptions::create(true).append(true)` relies on umask; logs may be readable by other users.
- **Why:** violates least privilege; sensitive data may become world-readable.
- **Where:** `crates/rustyjack-portal/src/logging.rs` (`open_append`).
- **Fix:** on Linux, set explicit permissions (e.g., create with `0o600`, or `chmod` after create).
- **Fixed version looks like:** after open/create, `set_permissions(0o600)` (and verify).

### F3 — DNSSpoof “site” parameter allows path traversal (template selection)
- **Problem:** `root.join("DNSSpoof").join("sites").join(&site)` uses unvalidated `site`.
- **Why:** a crafted `site` can escape the expected directory and potentially serve/read unintended files.
- **Where:** `crates/rustyjack-core/src/operations.rs` (`handle_dnsspoof_start`, `handle_eth_site_cred_capture`).
- **Fix:** validate `site` as a slug (e.g., `[A-Za-z0-9_-]+`), reject separators, and canonicalize + enforce that `canonical(site_dir).starts_with(canonical(DNSSpoof/sites))`.
- **Fixed version looks like:** `site_dir = safe_join_template_root(template_root, site)?;` where `safe_join_template_root` performs allowlist + canonical boundary check.

### F4 — DNSSpoof “site” also controls capture directory paths (write traversal)
- **Problem:** capture directories are built using `join(&site)` in multiple locations.
- **Why:** traversal becomes **write** capability (directory creation, writing logs) outside intended loot.
- **Where:** `crates/rustyjack-core/src/operations.rs` (capture_dir, dns_capture_dir creation).
- **Fix:** reuse the same `site` validation routine for both reading templates and choosing capture directories; also disallow `.`/`..` segments even if sanitized.
- **Fixed version looks like:** capture dir always under `loot/.../<safe_site>/` and never derived from raw user input.

### F5 — Default DNSSpoof captures stored outside standard loot/purge coverage
- **Problem:** `loot_directory` maps DNSSpoof to `root/DNSSpoof/captures`, not `root/loot/...`.
- **Why:** loot browser/export/purge expectations (per docs) can miss these files; anti-forensics purge may not remove them.
- **Where:** `crates/rustyjack-core/src/operations.rs` (`loot_directory`), `handle_dnsspoof_start` capture-dir default.
- **Fix:** store DNSSpoof captures under `loot/` (or ensure purge/export explicitly covers `DNSSpoof/captures`).
- **Fixed version looks like:** DNSSpoof capture root is `root/loot/Ethernet/...` (or `loot/DNSSpoof/...`) and documented consistently.

### F6 — Serving a whole directory tree without symlink screening can leak files
- **Problem:** `ServeDir::new(site_dir)` will serve whatever is reachable within that tree (including via symlinks if present).
- **Why:** if templates are modified (local attacker / supply chain / accidental), symlinks can expose files outside the intended web root.
- **Where:** `crates/rustyjack-portal/src/server.rs` (fallback `ServeDir`).
- **Fix:** at portal start, walk `site_dir` and reject symlinks; optionally serve only a fixed allowlist of file extensions.
- **Fixed version looks like:** `validate_template_tree(site_dir)` rejects any symlink and optionally enforces max file sizes.

### F7 — No security headers for sensitive portal pages
- **Problem:** responses lack CSP, frame-ancestors, and cache-control.
- **Why:** reduces resistance to XSS-in-template and clickjacking; caches might store sensitive pages.
- **Where:** `crates/rustyjack-portal/src/server.rs` (router layers).
- **Fix:** add a response header layer: `Cache-Control: no-store`, `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`), and a restrictive CSP for the static portal.
- **Fixed version looks like:** a `tower::Layer` that injects headers on all responses.

### F8 — `index.html` loaded into memory with no maximum size check
- **Problem:** portal reads `index.html` fully into a `String`.
- **Why:** a huge file can cause memory pressure; if templates are modifiable, this becomes an easy DoS.
- **Where:** `crates/rustyjack-portal/src/state.rs` (`start_portal` reads `index.html`).
- **Fix:** enforce max template size (e.g., 256 KB) and fail fast with a clear error.
- **Fixed version looks like:** `metadata.len() <= MAX_TEMPLATE_BYTES` checked before reading.

### F9 — Portal DNAT only targets TCP/80; evil twin redirects TCP/443 too (policy mismatch)
- **Problem:** portal service DNAT installs only port 80 redirect; evil twin captive portal redirects both 80 and 443.
- **Why:** inconsistent behavior across modes; redirecting 443 to an HTTP endpoint can break clients and generate noisy failures.
- **Where:** `crates/rustyjack-portal/src/state.rs` (install DNAT 80 only), `crates/rustyjack-netlink/src/iptables.rs` (`setup_captive_portal` adds 80+443).
- **Fix:** define a single policy: either redirect only 80, or run a real TLS endpoint on 443; avoid DNAT-ing 443 to 80.
- **Fixed version looks like:** `setup_captive_portal` only DNATs 80 unless TLS is explicitly configured.

### F10 — `setup_captive_portal` flushes entire NAT and FILTER tables
- **Problem:** captive portal setup calls `flush_table(Nat)` and `flush_table(Filter)`.
- **Why:** can delete unrelated rules (including system rules), breaking networking or other RustyJack features.
- **Where:** `crates/rustyjack-netlink/src/iptables.rs` (`setup_captive_portal`), used by `crates/rustyjack-wireless/src/evil_twin.rs`.
- **Fix:** create dedicated chains (e.g., `RJ_PORTAL_PREROUTING`, `RJ_PORTAL_FORWARD`) and only manage rules within those chains.
- **Fixed version looks like:** setup inserts a jump from PREROUTING to a RustyJack chain; teardown removes that jump and flushes only the RustyJack chain.

### F11 — Evil twin cleanup flushes NAT + FILTER tables again
- **Problem:** cleanup repeats full-table flushes.
- **Why:** same blast radius as F10; also makes post-mortem analysis harder because rules are wiped.
- **Where:** `crates/rustyjack-wireless/src/evil_twin.rs` (`cleanup`).
- **Fix:** teardown only what you created (dedicated chains + rule handles), not the whole table.
- **Fixed version looks like:** `teardown_captive_portal` removes only RustyJack chains/jumps.

### F12 — Stranded DNAT rules possible on hard crash (no startup reconciliation)
- **Problem:** teardown depends on clean shutdown paths; `portal_running()` cleanup requires polling and doesn’t help after process death.
- **Why:** a crash can leave DNAT rules active, breaking device networking or redirecting traffic unexpectedly.
- **Where:** `crates/rustyjack-portal/src/state.rs`, `crates/rustyjack-core/src/system/mod.rs` (DNS spoof DNAT).
- **Fix:** on startup (or before enabling a mode), remove known RustyJack rules/chains; store rule identifiers in a state file and reconcile.
- **Fixed version looks like:** a “netfilter reconcile” step that ensures tables are in the expected baseline before starting services.

### F13 — DNS query logging can leak sensitive hostnames and enable log injection
- **Problem:** DNS server logs query names at debug level; qnames are built with `from_utf8_lossy` and not escaped.
- **Why:** hostnames can contain sensitive hints (domains, internal names); also unescaped control chars could break log formats.
- **Where:** `crates/rustyjack-netlink/src/dns_server.rs` (`log_queries`, `parse_name`).
- **Fix:** default `log_queries` to false in user-facing ops; if logging is needed, escape control chars before logging and/or hash the qname.
- **Fixed version looks like:** `tracing::debug!("[DNS] Query … {}", escape_log_value(qname))` or `hash(qname)`.

### F14 — Lack of per-IP throttling for `POST /capture`
- **Problem:** portal has global concurrency limit but no per-client rate limit.
- **Why:** one LAN host can continuously post and fill disk; concurrency limit alone doesn’t bound total events.
- **Where:** `crates/rustyjack-portal/src/server.rs` (`capture_post`).
- **Fix:** add a small in-memory token bucket per IP (bounded map with LRU eviction) and enforce minimum interval.
- **Fixed version looks like:** repeated posts from one IP get `429 Too Many Requests` with minimal log spam.

### F15 — `rustyjack-portal` manifest references a missing binary path
- **Problem:** `Cargo.toml` declares `src/bin/main.rs` but the file is absent in this snapshot.
- **Why:** breaks builds/packaging, makes operational expectations unclear (library vs standalone).
- **Where:** `crates/rustyjack-portal/Cargo.toml`.
- **Fix:** either add the missing `main.rs` or remove the `[[bin]]` stanza and keep the crate library-only.
- **Fixed version looks like:** CI builds succeed and the install/unit configuration matches the crate’s intended usage.

---

## 6) Test plan (security + robustness)

### Malicious inputs (HTTP)
1. **Oversized body:** send `POST /capture` with body just over `max_body_bytes` and ensure 413/appropriate rejection; verify no partial write to logs.
2. **Many fields within size limit:** thousands of small key/value pairs to test parser CPU; ensure timeout triggers and service stays responsive.
3. **Header injection:** `User-Agent` containing `\n`, `\r`, quotes, and control bytes; verify `credentials.log` and `visits.log` remain one-line-per-event.
4. **Path probing:** request `/../../etc/passwd` and Windows-style paths; ensure `ServeDir` doesn’t escape (and your own site validation blocks it).
5. **Symlink leak test:** (in a controlled test env) add a symlink inside the template dir pointing outside; verify startup validation rejects the template tree.
6. **Replay:** resend identical `POST /capture` repeatedly; confirm rate limiting (if implemented) and disk growth bounds.
7. **XSS-in-template hardening:** add a `<script>` to the template and confirm CSP blocks inline script (if CSP implemented) or that the threat is documented as “template-trust dependent”.

### Malicious inputs (DNS)
8. **Weird qnames:** include labels with non-UTF8 bytes and control chars; ensure parser doesn’t panic and logs (if enabled) escape output.
9. **Flood:** burst DNS queries at high rate; ensure server thread doesn’t deadlock and stop routine still succeeds.

### Rule lifecycle / crash tests
10. **Crash mid-redirect:** start portal with `dnat_mode=true`, kill process (SIGKILL), reboot/restart, and verify netfilter reconcile removes stale rules.
11. **Start/stop loops:** rapidly start/stop DNS spoof and portal 100 times; confirm no rule accumulation and no resource leaks.
12. **Coexistence:** run DNS spoof + portal, then start evil twin and stop it; verify evil twin doesn’t wipe rules needed by other modules (post-fix: dedicated chains).

### Log redaction / encryption verification
13. **Encryption enabled:** turn on loot encryption (process-wide key set) and confirm portal logs are encrypted-at-rest (and cannot be opened without decrypt).
14. **Redaction policy:** confirm that sensitive values are either encrypted, hashed, or excluded from general tracing logs; ensure exports respect policy.
15. **Purge coverage:** run “system purge” and verify DNSSpoof/portal artifacts are removed consistently with documented loot paths.

---

## 7) OWASP ASVS alignment (for orientation only)

This repo is a local service on a controlled appliance, but the same categories apply. High-level mapping:
- **V1 Architecture, Design, Threat Modeling:** threat model + trust boundaries (this report’s §1).
- **V5 Validation, Sanitization and Encoding:** site slug validation, request body controls, log escaping (Findings F3/F4/F8/F13).
- **V7 Error Handling and Logging:** avoid sensitive logging, prevent log injection, consistent formats (F1/F2/F13).
- **V8 Data Protection:** encrypt sensitive submissions at rest; permissions; purge coverage (F1/F2/F5).
- **V9 Communications:** captive portal interception behavior and expectations (F9).
- **V14 Configuration:** safe defaults, consistent netfilter lifecycle, crash recovery (F10–F12, F14).

---

## Closing note
Most of the heavy lifting (size limits, timeouts, concurrency, log escaping) is already in place. The biggest risk cluster is **filesystem boundary enforcement for templates/capture paths** and **netfilter blast radius** (full-table flushes + crash-stranded rules). Addressing those two clusters will substantially harden this area without changing core functionality.
