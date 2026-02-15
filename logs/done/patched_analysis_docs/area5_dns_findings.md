# Area 5 — DNS & resolver ownership — Findings (18)

**Generated:** 2026-02-13  
**Scope:** `/etc/resolv.conf`, local resolver behavior, embedded DNS server code, portal/spoofing interactions, and boot-time reassertion assumptions.  
**Repo policy reminder:** This is a **read-only report**; no repository files were modified.

---

## Findings

Each item uses the format:

**Problem → Why → Where → Fix → Fixed version looks like**

### 1) No runtime “reassert ownership” of `/etc/resolv.conf`
- **Problem:** Ownership is established in installers, but the contract explicitly anticipates reclaiming `/etc/resolv.conf` after package activity; runtime does not enforce it.
- **Why:** If `/etc/resolv.conf` is replaced (file or different symlink), the host resolver may silently stop using `/var/lib/rustyjack/resolv.conf`.
- **Where:** `AGENTS.md` (“reclaim it after apt installs…”); installer scripts `install_rustyjack*.sh` `claim_resolv_conf()`.
- **Fix:** Add a **boot/service-start ownership verifier** (systemd oneshot, ExecStartPre, or timer) that asserts `/etc/resolv.conf → /var/lib/rustyjack/resolv.conf`.
- **Fixed version looks like:** A small checker that (a) verifies the symlink target, (b) repairs it if wrong, (c) emits a clear health/UI status if repair fails.

### 2) Two independent writers for the same resolver file with different semantics
- **Problem:** Two separate implementations write `${RUSTYJACK_ROOT}/resolv.conf`.
- **Why:** Divergent semantics = last-write-wins behavior with inconsistent fallback and formatting.
- **Where:** `crates/rustyjack-core/src/system/dns.rs` (`DnsManager::set_dns()`); `crates/rustyjack-core/src/system/mod.rs` (`rewrite_dns_servers()`).
- **Fix:** Consolidate into **one canonical writer** with a single policy and format.
- **Fixed version looks like:** One API (e.g. `set_system_dns(...)`) used everywhere + tests enforcing consistent output.

### 3) Empty DNS list is a no-op in `DnsManager::set_dns()`
- **Problem:** `set_dns([])` returns `Ok(())` without updating the file.
- **Why:** DNS can remain stale from a previous uplink during DHCP churn; breaks determinism.
- **Where:** `crates/rustyjack-core/src/system/dns.rs` (`if servers.is_empty() { return Ok(()); }`).
- **Fix:** Define a policy: write fallback DNS, or explicitly clear and mark “invalid” with a degraded warning.
- **Fixed version looks like:** Empty list triggers a well-defined state + a single structured warning surfaced to UI.

### 4) `select_active_uplink()` ignores DNS rewrite failures
- **Problem:** DNS rewrite errors are explicitly dropped.
- **Why:** “Route works / DNS broken” becomes a silent failure mode.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` (`let _ = rewrite_dns_servers(...)`).
- **Fix:** Return DNS status as part of uplink selection (or fail selection if DNS is mandatory).
- **Fixed version looks like:** `select_active_uplink()` produces `{ uplink, dns_status }`, and UI warns when DNS is stale/unowned.

### 5) Health check uses `/etc/resolv.conf` writability as a proxy for ownership
- **Problem:** Health check tries to append-open `/etc/resolv.conf`.
- **Why:** Writability doesn’t prove the symlink contract (and can fail for unrelated sandbox reasons).
- **Where:** `crates/rustyjack-core/src/operations.rs` (`ensure_route_health_check()`).
- **Fix:** Check the actual contract: “is `/etc/resolv.conf` a symlink to the expected target and is the target writable?”
- **Fixed version looks like:** Health check reports `resolv_conf_owner = rustyjack|systemd-resolved|other|unknown` plus remediation hint.

### 6) Installer writes bootstrap resolv.conf before fully neutralizing competitors
- **Problem:** Install flow can write `/etc/resolv.conf` while other managers are still alive.
- **Why:** Another service can overwrite DNS mid-install, causing flaky installs and confusing state.
- **Where:** `install_rustyjack*.sh` (`bootstrap_resolvers()` occurs before/around `disable_conflicting_services()` depending on script).
- **Fix:** Disable/stop competing DNS managers *before* relying on `/etc/resolv.conf`, or validate after each stage.
- **Fixed version looks like:** “Stop/mask competitors → claim resolv.conf → proceed”.

### 7) Resolver-ownership logic duplicated across installer scripts
- **Problem:** Multiple copies of `claim_resolv_conf()`/bootstrap logic exist.
- **Why:** Drift risk: one script gets fixed, others quietly diverge.
- **Where:** `install_rustyjack.sh`, `install_rustyjack_dev.sh`, `install_rustyjack_prebuilt.sh`, `install_rustyjack_usb.sh`.
- **Fix:** Factor into a shared script/library or generate installers from a single source.
- **Fixed version looks like:** One canonical `scripts/claim_resolv_conf.sh` sourced by all installers.

### 8) `read_dns_servers()` can report Rustyjack DNS even if the host isn’t using it
- **Problem:** Reader prefers `${root}/resolv.conf` if it exists, without verifying `/etc/resolv.conf` points to it.
- **Why:** Diagnostics can say “DNS is X” while effective resolver is something else.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` (`read_dns_servers()`).
- **Fix:** When root file exists, also validate symlink ownership; otherwise mark “stale/unowned.”
- **Fixed version looks like:** `read_dns_state()` returns `{ effective_source, expected_source, mismatch }`.

### 9) Recon reads `/etc/resolv.conf` directly instead of using shared DNS state logic
- **Problem:** Wireless recon code reads `/etc/resolv.conf` directly.
- **Why:** It may diverge from the “expected” Rustyjack resolver source and won’t explain mismatches.
- **Where:** `crates/rustyjack-wireless/src/recon.rs` (`get_dns_servers()`).
- **Fix:** Use the shared resolver state API and surface mismatch explicitly.
- **Fixed version looks like:** Recon includes `effective_dns_source` and `ownership_status` in output.

### 10) `rustyjackd.service` allows direct writes to `/etc/resolv.conf`
- **Problem:** Unit grants write access to `/etc/resolv.conf` under `ProtectSystem=strict`.
- **Why:** Increases blast radius: a bug could replace the symlink with a regular file and break ownership.
- **Where:** `services/rustyjackd.service` (`ReadWritePaths=... /etc/resolv.conf ...`).
- **Fix:** Restrict write access to `/var/lib/rustyjack` only; keep `/etc/resolv.conf` read-only unless strictly required.
- **Fixed version looks like:** Remove `/etc/resolv.conf` from `ReadWritePaths=` and eliminate code paths that write it.

### 11) Log bundle includes `/etc/resolv.conf` without a redaction policy
- **Problem:** Diagnostics bundle captures `/etc/resolv.conf` verbatim.
- **Why:** Search domains can expose internal network names; this is a privacy leak path.
- **Where:** `crates/rustyjack-core/src/services/logs.rs`.
- **Fix:** Redact `search`/`domain` lines by default; keep only `nameserver` IPs unless user opts in.
- **Fixed version looks like:** Exported log replaces search domains with `[REDACTED]` (or hashes).

### 12) Embedded DNS server can log full query names (highly sensitive)
- **Problem:** When `log_queries` is enabled, it logs qname per request.
- **Why:** DNS queries reveal user behavior; logs become persistent sensitive data.
- **Where:** `crates/rustyjack-netlink/src/dns_server.rs` (log path guarded by `log_queries`); enabled by default in helpers below.
- **Fix:** Default `log_queries=false`; when enabled, redact (eTLD+1), hash, or count-only + rate limit.
- **Fixed version looks like:** Logs store aggregate metrics (counts, timings), not plaintext domains.

### 13) `dns_helpers` enables `log_queries: true` in multiple modes
- **Problem:** Helpers start DNS server configs with `log_queries: true`.
- **Why:** Makes the sensitive logging path the default in portal/spoof modes.
- **Where:** `crates/rustyjack-core/src/dns_helpers.rs` (multiple `log_queries: true` initializations).
- **Fix:** Flip default to `false` and gate verbose logging behind an explicit debug flag with redaction.
- **Fixed version looks like:** “Debug mode” required + redaction always on.

### 14) Upstream forwarding creates a fresh UDP socket per query
- **Problem:** Upstream forwarding binds a new UDP socket for each query.
- **Why:** Resource churn under load; can amplify failures (fds/ephemeral ports/timeouts).
- **Where:** `crates/rustyjack-netlink/src/dns_server.rs` (`forward_upstream()`).
- **Fix:** Reuse a single upstream socket per server instance; add concurrency limits.
- **Fixed version looks like:** One socket + bounded in-flight map keyed by (client, txid) with timeouts.

### 15) Portal/spoof modes default upstream DNS to 8.8.8.8 (policy/privacy concern)
- **Problem:** Some DNS server configs pick a public upstream directly (8.8.8.8).
- **Why:** Increases third-party leakage and may conflict with the device’s intended upstream policy.
- **Where:** `crates/rustyjack-core/src/dns_helpers.rs` (`upstream_dns: Some(8.8.8.8)` in at least one config).
- **Fix:** Make upstream DNS configurable and/or derived from the selected uplink’s DNS by default.
- **Fixed version looks like:** `upstream_dns = system|custom`, default `system` (with safe fallback).

### 16) Mode teardown does not appear to have an explicit “no persistence” contract for DNS server behavior
- **Problem:** DNS server threads are started for modes; correctness depends on explicit stop/cleanup paths.
- **Why:** If a mode stops but state persists (or server keeps running), the system can remain in a surprising resolver state.
- **Where:** Mode orchestration references in `logs/done/ethernet_mitm_dns_spoof.md`; server lifecycle in `dns_server.rs`.
- **Fix:** Centralize teardown: stop server, clear mode-specific DNS state, and emit “restored” health status.
- **Fixed version looks like:** One teardown routine invoked on success/failure + unit/integration tests for cleanup.

### 17) Installer-created target file format differs from runtime writers
- **Problem:** Installer writes `/var/lib/rustyjack/resolv.conf` content that may not match runtime writer headers/format.
- **Why:** Confusing diagnostics; makes it harder to prove “runtime is updating what it owns.”
- **Where:** `install_rustyjack*.sh` writes the initial target file; runtime writers are `DnsManager` and `rewrite_dns_servers()`.
- **Fix:** Use the same canonical writer/template for installer output.
- **Fixed version looks like:** Installer calls the same “write fallback resolv.conf” routine used by runtime.

### 18) Partial reintroduction of DNS managers can create ambiguous “half-managed” states
- **Problem:** Contract assumes competitors are removed/disabled, but updates can re-enable them.
- **Why:** Modern distros actively manage `/etc/resolv.conf`; ownership drift is common and must be detected.
- **Where:** Installer `disable_conflicting_services()`; contract note in root docs.
- **Fix:** Add explicit “DNS ownership mode” with drift detection + remediation + UI warning.
- **Fixed version looks like:** Drift triggers a persistent warning: “Resolver ownership lost (points to X)” until repaired.

---

**End of findings.**
