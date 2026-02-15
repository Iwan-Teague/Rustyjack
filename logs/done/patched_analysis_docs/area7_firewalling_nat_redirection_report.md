# Area 7 — Firewalling, NAT, and redirection rules (nftables via netlink)
Date: 2026-02-15

_Date: 2026-02-14_

This is a **read-only engineering report** focused on:
- nftables / netfilter rule management via **netlink nf_tables**
- the **iptables-compat layer** (`rustyjack-netlink::iptables`)
- DNAT/redirect logic used for portal and DNS redirect
- teardown, rollback, and crash cleanup guarantees

It intentionally avoids “how to attack” operational guidance. It is about correctness, safety, and lifecycle hygiene.

---

## Evidence + trust model (policy sources)
Per the repository’s own trust rules, **policy constraints** are taken only from:
- **Root docs** (e.g., `CLAUDE.md`)
- **`logs/done/` docs** (e.g., interface isolation and operation notes)

Everything else (Rust code, services) is treated as implementation evidence.

### Policy constraints relevant to this area
1) **Privilege separation**: privileged operations live in the daemon; unprivileged services should not need `CAP_NET_ADMIN`. (Root docs + systemd service policy)
2) **“Pure Rust / no external binaries”**: runtime operations should prefer Rust implementations rather than shelling out. (`CLAUDE.md`)
3) **Interface isolation is a core safety invariant**: only selected interfaces should be UP; others forced DOWN / rfkill-blocked. (`logs/done/interface_isolation_overview.md`)
4) **Stop should tear down NAT/rules** for MITM/DNS flows. (`logs/done/ethernet_mitm_dns_spoof.md`)

---

## Where the code is (scope map)
### Netfilter/nftables substrate
- `crates/rustyjack-netlink/src/nf_tables.rs` — low-level nf_tables netlink client (create/list/delete rules)
- `crates/rustyjack-netlink/src/iptables.rs` — iptables-like API built on top of nf_tables

### Call-sites that install/remove rules
- Hotspot NAT: `crates/rustyjack-wireless/src/hotspot.rs`
- Captive portal DNAT (HTTP): `crates/rustyjack-portal/src/state.rs`
- DNS spoof redirect (TCP/UDP 53): `crates/rustyjack-core/src/system/mod.rs`
- “Ops disable” cleanup: `crates/rustyjack-daemon/src/ops_apply.rs`
- Captive portal in evil-twin flow (iptables setup + sysctl): `crates/rustyjack-wireless/src/evil_twin.rs`
- TCP MSS clamp (mangle): `crates/rustyjack-core/src/external_tools/evasion.rs`

---

## 1) Rule lifecycle model
### Current lifecycle (as implemented)
**Creation**
- Rules are created one-by-one via `NfTablesManager::add_rule()` which:
  - ensures the table exists
  - ensures the chain exists (possibly creating a base chain)
  - sends `NFT_MSG_NEWRULE` with `NFTA_RULE_USERDATA` set to a hash-like tag (`rj:<sha1…>`)
- Call-sites typically install **multiple rules in sequence** (e.g., masquerade + forward allows), without batching.

**Verification**
- No consistent post-apply verification exists.
- Success is assumed if netlink ACKs the single rule addition.
- There is no “expected ruleset” comparison or handle tracking.

**Removal**
- `delete_rule()` performs a list-and-match on `userdata` then deletes the matching handle (best-effort).
- Several code paths ignore errors during teardown (best-effort cleanup).

**Rollback**
- There is **no transactional rollback** for multi-rule applies. If rule #2 fails, rule #1 may remain.
- Some components use destructive “flush” as an attempted cleanup mechanism.

**Crash cleanup**
- There is no dedicated crash-recovery routine for nftables state.
- Some cleanups depend on running “stop” code paths (or “ops disable”).
- If the daemon crashes mid-apply, rules can remain and become active later (e.g., when an interface comes back up).

### Recommended lifecycle (transactional, verifiable, crash-safe)
A robust model for this repo’s constraints looks like:

1) **Plan**
   - Build an explicit “desired ruleset” for a feature (hotspot NAT, portal DNAT, DNS redirect).
   - Assign a **session id** (boot-scoped or job-scoped UUID).

2) **Transactional apply**
   - Use netlink **batch/transaction** semantics (`NFT_MSG_BATCH_BEGIN` / `…END`) so the kernel applies the whole change set atomically.
   - If batching is not available in your implementation layer yet, implement “manual rollback” with recorded handles.

3) **Verify**
   - Dump rules and verify:
     - the exact set of rules exists
     - each carries your ownership tag (userdata/comment)
     - ordering constraints are satisfied (where ordering matters)

4) **Commit**
   - Persist a small state file (e.g., `/run/rustyjack/netfilter/<session>.json`) containing:
     - session id
     - owned table/chain names
     - rule handles (if used)
     - feature reference counts (e.g., ip_forward enablement)

5) **Teardown**
   - Delete by **ownership**, not by global flush:
     - preferred: delete the **dedicated table** that contains all owned chains/rules
     - acceptable: delete only rules with your ownership tag, and only jump hooks you installed

6) **Crash recovery**
   - On daemon startup:
     - read the state file(s) and remove leftover owned state
     - OR scan for owned tables/chains by prefix (e.g., `rj_*`) and remove them safely
   - Ensure sysctls (e.g., `ip_forward`) are returned to a safe baseline if no active features require them.

---

## 2) Rule ownership model
### Current ownership approach
- Rules are tagged via `NFTA_RULE_USERDATA` using `rule_userdata()` which prefixes `b"rj:"` plus a SHA1 digest of rule fields.
- However, most rules are installed into **generic tables and base chains** (`filter`, `nat`, `mangle` with `INPUT/FORWARD/PREROUTING/...`), and there are code paths that **flush entire tables**, ignoring ownership tags.

### Why this is risky
- “Flush table” deletes non-owned rules (clobbering the system or other services).
- Using standard table/chain names increases collision likelihood.
- Hash-only userdata is hard to inspect/debug; it is ownership *but not readable ownership*.

### Recommended ownership model
- Create and manage a **dedicated nftables table**, e.g.:
  - table: `rj` (or `rustyjack`) in `ip` family
  - base chains inside it for the hooks you need (`prerouting`, `postrouting`, `forward`, possibly `output`)
- Make ownership **explicit**:
  - `userdata = b"rj:v1;sid=<uuid>;feature=<name>;rule=<shortname>"`
  - Keep the digest if you want, but include a readable prefix.
- Track rule **handles** (and/or delete the table as the unit of cleanup).
- Never flush system tables as a cleanup mechanism.

---

## 3) Safety model (dormant interfaces stay isolated/down)
This repo already treats interface isolation as a primary safety invariant (`logs/done/interface_isolation_overview.md`). Netfilter management should *reinforce* that invariant rather than accidentally undermining it.

### Current risk points
- Rules can persist after feature shutdown or crash.
- Sysctls like `net.ipv4.ip_forward` are enabled in multiple places and not consistently disabled.
- If a previously-dormant interface later comes UP (manual action, hotplug, or a different feature), stale rules may start forwarding/redirecting unexpectedly.

### Recommended safety posture
- **Default to “no forwarding”** unless a feature explicitly needs it:
  - manage `ip_forward` with a small reference counter (hotspot uses it, “offensive” uses it, etc.)
  - on crash recovery, force it OFF unless a valid active session says otherwise
- **Scope all rules to explicit interfaces**
  - every NAT/forward rule should match `iifname` / `oifname`
- **Prefer an owned table**
  - makes “remove everything we own” safe and easy
- **Make “interface down” and “rules removed” a paired invariant**
  - “stop” should do both, and crash recovery should enforce both
- Consider a “failsafe drop” inside your owned chains when the session is not active.

---

## 4) Findings (18)
Each finding uses the mandated template:
**Problem → Why → Where → Fix → Fixed version looks like**

### Finding 1 — Destructive table flush deletes non-owned rules
- **Problem:** `flush_table(Table::Nat)` / `flush_table(Table::Filter)` deletes *all* rules in those tables.
- **Why:** This violates ownership; it can clobber system nftables/iptables-nft rules and break networking unpredictably.
- **Where:**  
  - `crates/rustyjack-netlink/src/nf_tables.rs` `flush_table()` (lines ~366–387)  
  - Called from `crates/rustyjack-daemon/src/ops_apply.rs` `flush_nf_tables()` (lines 265–269)
- **Fix:** Remove global flush as a cleanup strategy. Replace with “delete only owned state”:
  - dedicated owned table deletion, or
  - delete only rules with `userdata` prefix `rj:` in a known owned chain/table.
- **Fixed version looks like:** A cleanup routine that targets `table rj` (or `rj_*`) only:
  - `delete_table("rj")` in an atomic batch, no touch to system tables.

### Finding 2 — Captive portal setup flushes *both* nat and filter tables
- **Problem:** Captive portal setup clears global tables before installing redirect/drop rules.
- **Why:** This is the worst-case clobber: it removes unrelated firewall/NAT state and may disable important protections.
- **Where:** `crates/rustyjack-netlink/src/iptables.rs` `setup_captive_portal()` (lines ~785–812)
- **Fix:** Implement captive portal rules in an owned table/chain. No flushing. Only install what you own.
- **Fixed version looks like:** `apply_portal_rules(session_id, ap_iface, portal_ip, portal_port)` that:
  - creates `table rj` if missing
  - creates `chain rj_prerouting` (nat hook prerouting)
  - adds DNAT rule scoped to `iifname=ap_iface` and `tcp dport 80`
  - adds optional filter rules in `rj_forward` if needed
  - all inside a single netlink transaction

### Finding 3 — Multi-step NAT apply is non-transactional (partial state on failure)
- **Problem:** NAT setup adds masquerade and forward rules sequentially; failure mid-way leaves partial config.
- **Why:** Partial rulesets are a classic “heisenbug factory” and can create unexpected routing/forwarding.
- **Where:** `crates/rustyjack-netlink/src/iptables.rs` `setup_nat_forwarding()` (lines ~699–720)
- **Fix:** Apply NAT/forward rules atomically (batch begin/end). If any step fails, nothing is committed.
- **Fixed version looks like:** `FirewallTxn::begin().add_rules([...]).commit()?;` where commit is atomic.

### Finding 4 — NAT teardown is best-effort and hides failures
- **Problem:** NAT teardown ignores deletion errors.
- **Why:** You can silently accumulate stale rules; later interface changes can re-activate them.
- **Where:** `crates/rustyjack-netlink/src/iptables.rs` `teardown_nat_forwarding()` (lines ~722–745)
- **Fix:** Make teardown verifiable:
  - attempt delete-by-handle or delete-owned-table
  - then dump and assert “no owned rules remain”
  - log failures as high-signal events (rate limited)
- **Fixed version looks like:** teardown returns an error if owned rules remain after a bounded retry.

### Finding 5 — DNS redirect setup lacks rollback if TCP rule add fails after UDP rule add
- **Problem:** DNS spoof install adds UDP DNAT then TCP DNAT in a chained `and_then`; on failure, UDP rule may remain.
- **Why:** Leaves stray redirect; can break DNS unexpectedly.
- **Where:** `crates/rustyjack-core/src/system/mod.rs` `start_dns_spoof()` (lines ~1232–1244)
- **Fix:** Transactional apply or explicit rollback:
  - if TCP add fails, delete the UDP rule before returning error
- **Fixed version looks like:** one atomic batch that adds both rules or none.

### Finding 6 — Portal DNAT is attempted inside the portal component, conflicting with unprivileged service policy
- **Problem:** Portal state tries to create netfilter rules (`IptablesManager::new()`) when `dnat_mode` is enabled.
- **Why:** The portal systemd service is configured as unprivileged and should not require `CAP_NET_ADMIN`; this will fail at runtime or force unsafe privilege broadening.
- **Where:** `crates/rustyjack-portal/src/state.rs` `install_dnat()` (lines ~224–236)
- **Fix:** Move DNAT rule installation into the privileged daemon/core layer:
  - portal asks daemon to enable/disable redirect
  - daemon performs netfilter transaction and records ownership
- **Fixed version looks like:** portal only runs the HTTP server; daemon owns all netfilter state.

### Finding 7 — Evil-twin captive portal enables ip_forward without guaranteed disable
- **Problem:** Evil-twin flow writes `/proc/sys/net/ipv4/ip_forward` = 1 and installs captive portal rules, but does not consistently disable or remove them on exit.
- **Why:** Persistent forwarding is a safety hazard and violates the “reversible when possible” posture.
- **Where:** `crates/rustyjack-wireless/src/evil_twin.rs` `setup_captive_portal()` (lines ~489–505)
- **Fix:** Manage ip_forward via a reference-counted “netfilter session” owned by daemon; ensure teardown in Drop + crash recovery.
- **Fixed version looks like:** enabling forwarding happens only through `NetfilterSession::acquire_forwarding()` and is released on teardown.

### Finding 8 — Hotspot enables ip_forward but never disables it on stop
- **Problem:** Hotspot start enables forwarding, but there is no corresponding disable in stop/cleanup.
- **Why:** Forwarding persists after hotspot stops; stale NAT rules (or future rules) can unexpectedly route traffic.
- **Where:** `crates/rustyjack-wireless/src/hotspot.rs` `enable_ip_forwarding()` usage (lines ~514–517) and the helper (lines ~935–956)
- **Fix:** Centralize forwarding toggles:
  - track “who needs forwarding”
  - disable when the last user releases it
- **Fixed version looks like:** `ForwardingLease` RAII + persisted session state; reboot cleanup disables unless active.

### Finding 9 — Ops-disable cleanup flushes global tables as a “catch-all”
- **Problem:** When `hotspot_ops`, `portal_ops`, or `offensive_ops` are disabled, daemon flushes NAT and FILTER tables globally.
- **Why:** This is dangerous cleanup that clobbers unrelated rules; it’s also an unreliable substitute for proper crash recovery.
- **Where:** `crates/rustyjack-daemon/src/ops_apply.rs` `flush_nf_tables()` (lines 265–269)
- **Fix:** Replace with “remove owned table(s) and owned sysctls”:
  - `cleanup_owned_netfilter_state()` during ops disable and during startup reconcile
- **Fixed version looks like:** daemon calls `netfilter::cleanup(prefix="rj")` and verifies.

### Finding 10 — `IptablesManager::new()` enforces “must be root” via geteuid, not capability
- **Problem:** `new()` rejects callers unless `geteuid()==0`.
- **Why:** The repo’s service model uses capabilities; future tightening could run with ambient `CAP_NET_ADMIN` without uid 0. This check prevents that hardening path.
- **Where:** `crates/rustyjack-netlink/src/iptables.rs` `IptablesManager::new()` (lines ~366–372)
- **Fix:** Prefer capability-based “try and fail”:
  - attempt to open netlink socket and return the real error
  - optionally check capabilities via `capget`
- **Fixed version looks like:** `new()` succeeds for uid!=0 when `CAP_NET_ADMIN` is present.

### Finding 11 — Base chain creation sets ACCEPT policy by default
- **Problem:** When creating base chains in `filter`/`mangle`/`raw`, policy defaults to ACCEPT.
- **Why:** If the table/chain is newly created on a system that previously had no such chain, you’re implicitly choosing a security policy. That’s risky and surprising.
- **Where:** `crates/rustyjack-netlink/src/nf_tables.rs` `base_chain_spec()` (lines ~566–597)
- **Fix:** Avoid creating system-style base chains at all by using an owned table with explicit behavior; or require explicit policy selection per feature.
- **Fixed version looks like:** `table rj` owns base chains and policy is defined by RustyJack, not by implicit defaults.

### Finding 12 — Rule ordering is not controlled (append semantics)
- **Problem:** Rule insertion uses append semantics; ordering relative to other rules is not guaranteed.
- **Why:** NAT and filter behavior can change drastically based on order. In mixed environments, your redirect may be bypassed or may override other components.
- **Where:** `crates/rustyjack-netlink/src/nf_tables.rs` add_rule uses `NLM_F_APPEND` (line ~323)
- **Fix:** Make ordering explicit:
  - use owned chains at known priority, or
  - install a single jump rule (owned) at top of a system chain and manage everything within your chain
- **Fixed version looks like:** deterministic order defined by chain priority or by a single owned jump at a known position.

### Finding 13 — Ownership tag is not human-readable (hard to audit)
- **Problem:** `userdata` is `rj:` + SHA1 digest of rule fields.
- **Why:** You can’t easily inspect “what is this rule for?” on-device; debugging becomes guesswork.
- **Where:** `crates/rustyjack-netlink/src/nf_tables.rs` `rule_userdata()` (lines ~833–892)
- **Fix:** Make userdata structured and readable; keep a digest if desired:
  - `rj:v1;sid=<uuid>;feature=hotspot;rule=masq;hash=<…>`
- **Fixed version looks like:** dumps show ownership + feature name without needing source code.

### Finding 14 — Delete-by-userdata can fail if the rule changed or was re-ordered externally
- **Problem:** `delete_rule()` lists rules and finds an exact userdata match; if rules were modified or duplicated, deletion may miss.
- **Why:** Leaves stale rules; cleanup becomes probabilistic.
- **Where:** `crates/rustyjack-netlink/src/nf_tables.rs` `delete_rule()` (lines ~330–340)
- **Fix:** Track handles at creation time and persist them; delete by handle, or delete the whole owned table.
- **Fixed version looks like:** session state stores handles; teardown deletes handles in a transaction and verifies no owned leftovers.

### Finding 15 — No startup reconciliation for leftover netfilter state
- **Problem:** Daemon startup reconciliation enforces interface isolation, but does not clean up leftover nftables state.
- **Why:** A crash or reboot can leave forwarding/NAT/redirect rules present; when interfaces come up later, behavior may be unsafe.
- **Where:** `crates/rustyjack-daemon/src/state.rs` `reconcile_on_startup()` (focus: no netfilter cleanup)
- **Fix:** Add `reconcile_netfilter_on_startup()`:
  - remove owned table(s)
  - ensure `ip_forward` baseline is safe when no active session exists
- **Fixed version looks like:** on startup, daemon removes `table rj` (if present) and logs a single recovery event.

### Finding 16 — Multiple components manage netfilter independently (no central “netfilter authority”)
- **Problem:** Hotspot, portal, DNS spoof, and evasion each instantiate `IptablesManager` and manipulate rules directly.
- **Why:** This creates coordination problems (ordering, reference counting, conflicting teardown).
- **Where:** multiple call-sites listed above
- **Fix:** Centralize into a single module (in daemon/core) that provides:
  - feature-scoped sessions
  - transactional apply
  - reference-counted sysctls
  - crash recovery
- **Fixed version looks like:** call-sites request “enable feature X on iface Y”, and the central manager owns the ruleset.

### Finding 17 — IPv6 is not addressed (potentially incomplete isolation/redirect)
- **Problem:** nf_tables payload uses `AF_INET` and rule building focuses on IPv4.
- **Why:** On networks where IPv6 is present, traffic may bypass IPv4-only redirects/filters.
- **Where:** `crates/rustyjack-netlink/src/nf_tables.rs` `nfgenmsg_payload()` (around line ~967)
- **Fix:** Either:
  - explicitly disable IPv6 on involved interfaces during these features, or
  - implement `inet` family support and IPv6 equivalents where needed.
- **Fixed version looks like:** an explicit stance: “IPv6 off for these features” or “IPv6 handled equivalently”.

### Finding 18 — Hotspot cleanup uses Drop (good), but other features lack similar guaranteed teardown hooks
- **Problem:** Hotspot has a Drop-based cleanup guard; portal/DNS spoof/evil-twin rely on explicit stop paths.
- **Why:** Panics, early returns, or thread failures can leave rules behind.
- **Where:** `crates/rustyjack-wireless/src/hotspot.rs` `HotspotCleanup` (lines ~236–264) vs others
- **Fix:** Use a shared `NetfilterSessionGuard` pattern across features.
- **Fixed version looks like:** every feature that touches netfilter obtains a guard; teardown is automatic on scope exit, with crash recovery as the final backstop.

---

## What a fixed version looks like (atomic transactions + explicit ownership)
This section describes the “end state” architecture for this area.

### Atomic rule transactions
Implement a transaction layer over nf_tables netlink:

- `FirewallTxn::begin(session_id)`
  - sends `NFT_MSG_BATCH_BEGIN`
  - accumulates create-table/create-chain/add-rule operations

- `FirewallTxn::commit()`
  - sends `NFT_MSG_BATCH_END`
  - waits for ACK/error
  - if error: kernel aborts entire transaction (no partial apply)

### Explicit ownership tags and handles
- Every rule includes `userdata` that is:
  - **human readable** (feature + session)
  - **machine parseable** (key/value)
  - includes a short digest if useful

Example `userdata` payload (conceptual):
- `rj:v1;sid=3f6c…;feature=hotspot;rule=masq;hash=9a21…`

Handles:
- After commit, dump the owned table/chains and record the rule handles for that session.
- Persist to `/run/rustyjack/netfilter/<sid>.json`.
- Teardown deletes by handle (or deletes the whole owned table).

### Ownership unit = owned table
Prefer “delete the whole owned table” to avoid needing to enumerate every rule:
- table `rj` (or `rj_<sid>`) is created per session/feature
- all chains/rules for that feature live inside it
- teardown = delete table
- crash recovery = delete any `rj_*` tables

---

## 5) Test plan
The goal is to validate lifecycle correctness under normal operation, failures, and conflicts—without relying on external binaries.

### A. Start/stop portal (DNAT lifecycle)
1) Start portal with DNAT enabled (through daemon-owned netfilter manager).
2) Verify (via netlink dump API) that:
   - owned table exists
   - DNAT rule exists with expected userdata and iifname constraint
3) Stop portal.
4) Verify owned table/rules are gone and sysctls are unchanged.

**Pass criteria:** no leftover rules; start/stop is idempotent.

### B. Start/stop hotspot (NAT + forward lifecycle)
1) Start hotspot with upstream present.
2) Verify:
   - masquerade rule exists (owned)
   - forward allow rules exist (owned)
   - forwarding sysctl lease count increments
3) Stop hotspot.
4) Verify:
   - owned rules removed
   - forwarding sysctl decremented and disabled if no other leasers

**Pass criteria:** forwarding is not left enabled when nothing needs it.

### C. Crash daemon mid-rule-apply (transactionality)
1) Instrument a test-only failpoint after N operations but before transaction commit.
2) Trigger feature start.
3) Simulate daemon crash.
4) On restart, run startup reconcile.
5) Verify:
   - either no rules were ever committed (atomic), or
   - reconcile removed any owned remnants safely

**Pass criteria:** no partial ruleset survives.

### D. Reboot cleanup (crash recovery)
1) Start feature (portal/hotspot).
2) Simulate sudden stop (no teardown path).
3) On next boot/startup:
   - reconcile scans for owned tables/state files and deletes them
   - resets forwarding sysctl if no valid active sessions

**Pass criteria:** device returns to safe baseline automatically.

### E. Conflicting rules (coexistence)
1) Preinstall a minimal “non-owned” ruleset in the system tables (in a test namespace or harness).
2) Start RustyJack features.
3) Verify:
   - non-owned rules are unchanged
   - owned rules apply only in owned table/chains
   - teardown removes only owned state

**Pass criteria:** no clobbering, deterministic ordering via owned chain priorities.

---

## Appendix: quick reference of key files
- Netlink nf_tables: `crates/rustyjack-netlink/src/nf_tables.rs`
- iptables-compat layer: `crates/rustyjack-netlink/src/iptables.rs`
- Portal DNAT hook: `crates/rustyjack-portal/src/state.rs`
- DNS spoof redirect: `crates/rustyjack-core/src/system/mod.rs`
- Ops cleanup flush: `crates/rustyjack-daemon/src/ops_apply.rs`
- Hotspot NAT: `crates/rustyjack-wireless/src/hotspot.rs`
- Evil-twin captive portal: `crates/rustyjack-wireless/src/evil_twin.rs`

