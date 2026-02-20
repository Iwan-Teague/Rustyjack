# TEST_LOG_FIX_REPORT critique

Date (Europe/Dublin): 2026-02-16

Repo + artefacts audited (as provided in this environment):

- Report under review: `TEST_LOG_FIX_REPORT.md`
- Repo root (unpacked): `watchdog/` (workspace contains `crates/*`, `services/*`, `scripts/*`)
- Test logs root: `watchdog/test_logs/`

Tooling note (build verification): `cargo` is **not available** in this environment, so I could not run `cargo check`. All “buildability” conclusions below are from static, path-accurate code inspection against the checked-in sources (and against the logs).

## Project constraints and non-negotiables

The repo does document several hard constraints that the fix report must treat as non-negotiable. Where the repo is explicit, I quote it directly (short excerpts only). Where it is not explicit, I label the point as an inference.

Quoted, explicit constraints and expectations:

> “This project targets a Raspberry Pi Zero 2 W…”

> “IMPORTANT: NetworkManager is REMOVED, not just disabled.”

> “Do NOT assume `nmcli` is available.”

> “Appliance forbids external process spawning.”

> “Linux bridge management using ioctl (no external binaries).”

Additional constraints from your audit brief (treated as non-negotiable for this audit):

- Rust-only (for product/runtime fixes), no new external system binaries, and no new runtime shell-outs for core functionality.
- No NetworkManager/nmcli assumptions.
- Pi Zero 2 W feasibility (performance + memory).
- No “fixing tests” by weakening authz, widening permissions, or bypassing security checks.

Where the report under review already drifts from these constraints:

- It recommends multiple **shell-script changes** and a **systemd unit change** as “fixes”. Those may be valid test-harness remedies, but they are not “Rust-only fixes” and must be framed accordingly.
- It proposes disabling the daemon’s **UI-only operations** gate globally; that has significant security implications unless contained to a test-only profile.

## Evidence fidelity

Requirement used here: for **every** row in the report’s failures table, confirm it exists in `*_summary.jsonl` and/or `*_run.log`, and quote 1–3 exact log lines that support the report’s “Evidence” column. If the row does not exist, mark it and show what the logs actually report instead.

Key:
- **PASS**: failure exists and the report’s quoted evidence matches the logs closely.
- **WARN**: failure exists, but the report’s evidence is incomplete, mislabelled, or mismatched in important details (wrong test name, wrong caller identity, wrong diff content, etc.).
- **FAIL**: the table row does not exist in the provided logs (or is attributed to the wrong suite), or the report cites evidence that does not appear.

### Table row checks

**wireless / wifi_scan_wlan0 — PASS**

Evidence (exists in `test_logs/wireless_run.log` and `wireless_summary.jsonl`):

```text
test_logs/wireless_run.log:33  there is no reactor running, must be called from the context of a Tokio 1.x runtime
test_logs/wireless_run.log:35  2026-02-15T20:43:31+00:00 [FAIL] wifi_scan_wlan0 (rc=101)
```

Report fidelity: correct. This is the exact panic signature the report claims.

**ethernet / eth_discover_eth0 — PASS**

Evidence (exists in `test_logs/ethernet_run.log` and `ethernet_summary.jsonl`):

```text
test_logs/ethernet_run.log:16  there is no reactor running, must be called from the context of a Tokio 1.x runtime
test_logs/ethernet_run.log:18  2026-02-15T20:43:59+00:00 [FAIL] eth_discover_eth0 (rc=101)
```

Report fidelity: correct (same panic class as wifi scan).

**ethernet / ethernet_eth0_readonly — WARN**

Evidence (exists in `test_logs/ethernet_run.log`; this one is a suite-level isolation check, not in `*_summary.jsonl`):

```text
test_logs/ethernet_run.log:30  2026-02-15T20:44:22+00:00 [FAIL] Isolation check failed: ethernet_eth0_readonly (route changed)
test_logs/ethernet_run.log:35  2026-02-15T20:44:22+00:00   -default via 192.168.18.1 dev eth0 proto static metric 100 
```

Report fidelity: partially correct (route removal is real), but the report’s table quotes a different route line (`proto dhcp … src …`) than the log actually shows (`proto static metric 100`).

**interface_selection / set_active_eth0 — WARN**

Evidence (exists in `test_logs/interface_selection_run.log` and `interface_selection_summary.jsonl`):

```text
test_logs/interface_selection_run.log:22  2026-02-15T20:44:45+00:00 [FAIL] set_active_eth0 (rc=0)
test_logs/interface_selection_run.log:25  2026-02-15T20:44:45+00:00   {"ok": false, "timing_ms": 9, "request_id": 1771188285092935, "handshake": {"protocol_version": 1, "daemon_version": "0.1.3", "features": ["job_progress", "uds_timeouts", "group_based_auth"], "max_frame": 1048576, "authz": {"uid": 0, "gid": 0, "role": "admin"}}, "response": {"v": 1, "request_id": 1771188285092935, "body": {"type": "Err", "data": {"code": 4, "message": "operations are restricted to the UI runtime", "detail": "client pid...
```

Report fidelity: the *error class* is correct (`code:4 operations are restricted…`), but the report’s evidence text claims this is coming from an operator test user (“caller=rjtest_op uid=1003…”). The provided log line shows this call is from `uid 0` (root).

**interface_selection / set_active_wlan0 — WARN**

Evidence:

```text
test_logs/interface_selection_run.log:37  2026-02-15T20:44:48+00:00 [FAIL] set_active_wlan0 (rc=0)
test_logs/interface_selection_run.log:39  2026-02-15T20:44:48+00:00   {"ok": false, "timing_ms": 7, "request_id": 1771188288570324, "handshake": {"protocol_version": 1, "daemon_version": "0.1.3", "features": ["job_progress", "uds_timeouts", "group_based_auth"], "max_frame": 1048576, "authz": {"uid": 0, "gid": 0, "role": "admin"}}, "response": {"v": 1, "request_id": 1771188288570324, "body": {"type": "Err", "data": {"code": 4, "message": "operations are restricted to the UI runtime", "detail": "client pid...
```

Same fidelity issue as `set_active_eth0`.

**interface_selection / set_active_wlan1 — WARN**

Evidence:

```text
test_logs/interface_selection_run.log:51  2026-02-15T20:44:52+00:00 [FAIL] set_active_wlan1 (rc=0)
test_logs/interface_selection_run.log:53  2026-02-15T20:44:52+00:00   {"ok": false, "timing_ms": 7, "request_id": 1771188292020728, "handshake": {"protocol_version": 1, "daemon_version": "0.1.3", "features": ["job_progress", "uds_timeouts", "group_based_auth"], "max_frame": 1048576, "authz": {"uid": 0, "gid": 0, "role": "admin"}}, "response": {"v": 1, "request_id": 1771188292020728, "body": {"type": "Err", "data": {"code": 4, "message": "operations are restricted to the UI runtime", "detail": "client pid...
```

Same fidelity issue as above.

**usb_mount / usb_mount_read_write — WARN**

Evidence (exists in `test_logs/usb_mount_run.log` and `usb_mount_summary.jsonl`):

```text
test_logs/usb_mount_run.log:12  2026-02-15T20:55:04+00:00 [FAIL] usb_mount_read_write (rc=1)
test_logs/usb_mount_run.log:15  2026-02-15T20:55:04+00:00   {"data":null,"details":["unsupported or unknown filesystem"],"message":"unsupported or unknown filesystem","status":"error"}
```

Report fidelity: the failure exists, but the report’s evidence text claims the error string includes the device path (“…on /dev/sda1”). The actual logged message is just “unsupported or unknown filesystem”.

**usb_mount / usb_detectability_preflight — WARN**

Evidence (exists in `test_logs/usb_mount_run.log`; not present in `usb_mount_summary.jsonl` because it is a derived check in the shell harness):

```text
test_logs/usb_mount_run.log:9  2026-02-15T20:55:03+00:00 [FAIL] usb_detectability_preflight (/dev/sda)
```

Report fidelity: existence confirmed, but the provided logs do not include the JSON output being parsed here, so the report’s claimed root cause cannot be verified from the artefacts you provided (the underlying JSON artefact lives under `/var/tmp/...` and is not in `test_logs/`).

**daemon / rpc_ok_A7_active_interface_clear — WARN**

Evidence (exists in `test_logs/daemon_run.log`):

```text
test_logs/daemon_run.log:21  2026-02-15T20:46:26+00:00 [FAIL] rpc_ok_A7 (expected Ok, got Err) err=operations are restricted to the UI runtime
```

Report fidelity: same core failure, but the report’s row name does not match the logged label (`rpc_ok_A7…` vs `rpc_ok_A7_active_interface_clear`). This matters because you cannot reliably map the proposed patch to the actual failing test without reading the script.

**daemon / rpc_ok_A9_system_sync — WARN**

Evidence:

```text
test_logs/daemon_run.log:26  2026-02-15T20:46:28+00:00 [FAIL] rpc_ok_A9 (expected Ok, got Err) err=operations are restricted to the UI runtime
```

Same naming mismatch concern.

**daemon / rpc_ok_F1_job_start — WARN**

Evidence (failure exists, but in the *comprehensive* sub-suite within the daemon run log):

```text
test_logs/daemon_run.log:170  2026-02-15T20:46:50+00:00 [RPC] F1 JobStart (user=root)
test_logs/daemon_run.log:171  2026-02-15T20:46:51+00:00 [FAIL] RPC F1 JobStart (python rc=10)
```

Report fidelity: the report’s table implies this is a `rpc_ok_F1_job_start` failure in the daemon suite; the actual label is `RPC F1 JobStart`. The log excerpt does not include the response/error details, so the report’s asserted root cause is not fully evidenced here.

**daemon / protocol_version_mismatch_rejected — WARN**

Evidence:

```text
test_logs/daemon_run.log:27  2026-02-15T20:46:28+00:00 [FAIL] protocol_version_mismatch_rejected
```

Report fidelity: failure exists, but the run log excerpt does not show what response the daemon actually returned. Any claim about “daemon did/did not reject” must be backed by the captured JSON artefact or an excerpt from the test script output; neither is present in `test_logs/daemon_run.log`.

**daemon / isolation_check_route_unchanged — WARN**

Evidence (exists as a suite-level route diff):

```text
test_logs/daemon_run.log:31  2026-02-15T20:46:29+00:00 [FAIL] Isolation check failed: daemon_rpc_readonly (route changed)
test_logs/daemon_run.log:36  2026-02-15T20:46:29+00:00   +default via 192.168.18.1 dev eth0 proto static metric 100 
```

Report fidelity: route churn is real, but the report’s row name does not match the concrete check name (`daemon_rpc_readonly`). If the report is trying to deduplicate failures, that should be stated explicitly.

**daemon (comprehensive) / D1_incompatible_protocol — WARN**

Evidence:

```text
test_logs/daemon_run.log:120  D1_OK
test_logs/daemon_run.log:121  2026-02-15T20:46:38+00:00 [FAIL] D1_protocol_version_mismatch (expected error response)
```

Report fidelity: correct symptoms (the suite thinks it got “OK”), but the reported test name does not match the actual failing label.

**daemon (comprehensive) / G4_log_dir_secure — PASS**

Evidence:

```text
test_logs/daemon_run.log:182  2026-02-15T20:46:52+00:00 [FAIL] G4_log_dir_secure (perms=2770, world-write bit set)
```

Report fidelity: matches.

**daemon (comprehensive) / I1_pid_disappears_auth — WARN**

Evidence:

```text
test_logs/daemon_run.log:208  2026-02-15T20:50:31+00:00 [FAIL] I1_pid_disappears_auth_VULNERABLE (CRITICAL SECURITY BUG!)
```

Report fidelity: failure exists; the suffix `_VULNERABLE` is relevant because it indicates the script is asserting a security conclusion, not merely a test failure.

**daemon (comprehensive) / J1_wifi_scan_request — WARN**

Evidence:

```text
test_logs/daemon_run.log:224  2026-02-15T20:50:35+00:00 [FAIL] RPC J1 WifiScanStart (python rc=10)
test_logs/daemon_run.log:225  2026-02-15T20:50:35+00:00   Response: {"ok": false, "timing_ms": 2, "request_id": 999, "handshake": {"protocol_version": 1, "daemon_version": "0.1.3", "features": ["job_progress", "uds_timeouts", "group_based_auth"], "max_frame": 1048576, "authz": {"uid": 0, "gid": 0, "role": "admin"}}, "response": {"v": 1, "request_id": 999, "body": {"type": "Err", "data": {"code": 2, "message": "invalid request: missing field `timeout_ms` at line 1 column 125", "detail": null, "retryable":...
```

Report fidelity: correct root symptom (“missing field timeout_ms”), but the report’s row name does not correspond to the actual failing label.

**loot / isolation_check_route_unchanged — WARN**

Evidence:

```text
test_logs/loot_run.log:20  2026-02-15T20:45:28+00:00 [FAIL] Isolation check failed: loot_readonly (route changed)
test_logs/loot_run.log:26  2026-02-15T20:45:29+00:00   -default via 192.168.18.1 dev eth0 proto static metric 100 
```

Report fidelity: route churn is real, but the check name is `loot_readonly`, not “route unchanged”.

**evasion / router_fingerprint_help — FAIL**

The evasion suite does not contain `router_fingerprint_help` at all. The suite’s actual failures are different and are dominated by a missing CLI surface:

```text
test_logs/evasion_run.log:4  error: unrecognized subcommand 'evasion'
test_logs/evasion_run.log:9  2026-02-15T20:45:56+00:00 [FAIL] evasion_mac_status (rc=2)
```

**evasion / host_discovery_help — FAIL**

No such test appears in any `*_run.log` or `*_summary.jsonl`. The evasion suite failures are subcommand-not-found failures (see above).

**evasion / mac_spoof_help — FAIL**

No such test appears in the logs. Evasion failures in this run are `evasion_*` tests failing with “unrecognized subcommand 'evasion'”.

**evasion / tx_power_help — FAIL**

No such test appears in the logs. Evasion failures exist but do not match the report’s table row names.

**physical_access / default_creds_help — FAIL**

The physical access suite fails `default_creds_list`, not `default_creds_help`:

```text
test_logs/physical_access_run.log:27  2026-02-15T20:46:15+00:00 [FAIL] default_creds_list (rc=2)
test_logs/physical_access_run.log:4   error: unrecognized subcommand 'physical-access'
```

**physical_access / router_fingerprint_help — PASS**

Evidence:

```text
test_logs/physical_access_run.log:9  2026-02-15T20:46:14+00:00 [FAIL] router_fingerprint_help (rc=2)
test_logs/physical_access_run.log:4  error: unrecognized subcommand 'physical-access'
```

**physical_access / captive_portal_help — FAIL**

No such test exists in `test_logs/physical_access_run.log` nor in `physical_access_summary.jsonl`. Only three physical access tests fail in this run: `router_fingerprint_help`, `credential_extract_help`, and `default_creds_list`.

**physical_access / patch_panel_help — FAIL**

Not present in the provided logs.

**physical_access / rogue_ap_help — FAIL**

Not present in the provided logs.

**physical_access / sim_swap_help — FAIL**

Not present in the provided logs.

**anti_forensics / audit_status_help — FAIL**

The anti-forensics suite fails `audit_log_status`, not `audit_status_help`:

```text
test_logs/anti_forensics_run.log:9  2026-02-15T20:46:09+00:00 [FAIL] audit_log_status (rc=2)
test_logs/anti_forensics_run.log:4  error: unrecognized subcommand 'audit'
```

**anti_forensics / artifact_sweep_help — FAIL**

The anti-forensics suite fails `artifact_sweep_list`, not `artifact_sweep_help`:

```text
test_logs/anti_forensics_run.log:38  2026-02-15T20:46:10+00:00 [FAIL] artifact_sweep_list (rc=2)
test_logs/anti_forensics_run.log:33  error: unrecognized subcommand 'artifact-sweep'
```

**anti_forensics / log_prune_help — FAIL**

The anti-forensics suite fails `log_purge_status`, not `log_prune_help`:

```text
test_logs/anti_forensics_run.log:29  2026-02-15T20:46:09+00:00 [FAIL] log_purge_status (rc=2)
test_logs/anti_forensics_run.log:24  error: unrecognized subcommand 'anti-forensics'
```

**anti_forensics / usb_trace_wipe_help — FAIL**

No such test appears in the provided logs. (The suite also fails `secure_delete_test` and `secure_delete_removed_file` which are not represented in the report’s table at all.)

### Major omissions and incorrect deduplication

Even if the report intended to list “unique root causes”, it omits or misrepresents several major failures that are clearly present in the logs:

- **Missing from the report table**: `wifi_scan_wlan1` fails with the same Tokio/reactor panic.  
  Evidence: `test_logs/wireless_run.log:65` (“there is no reactor running…”) and `:67` (`[FAIL] wifi_scan_wlan1 (rc=101)`).
- The report’s evasion / physical_access / anti_forensics rows use **test names that do not exist** in this run, even though those suites have multiple real failures (visible in their `*_summary.jsonl` files).
- The report’s daemon coverage is incomplete: additional daemon failures exist and are not represented (e.g., `RPC C1 Health`, `RPC C4 LoggingConfigSet`, `RPC C5 SystemLogsGet`, `RPC J4 SystemSync`, and `comprehensive_suite` failure marker in `test_logs/daemon_run.log`).

## Patch correctness and buildability

This section verifies each “Suggested Patch” in the report against the actual repository code and file layout.

### Tokio runtime initialisation patch (`crates/rustyjack-core/src/main.rs`)

Report status: **FAIL (won’t apply cleanly; references wrong APIs; risks nested/blocking runtime misuse)**

What the report proposes:
- Import `rustyjack_commands::cli::{Cli, OutputFormat}` and `tokio::runtime::Builder`, and run `run(cli, format)` inside `rt.block_on(async { … })`.

What the repo actually contains:
- `crates/rustyjack-core/src/main.rs` currently imports CLI types via `rustyjack_core::{…, Cli, OutputFormat}` (re-exported by `rustyjack-core`).
- `rustyjack-commands` exports `Cli` and `OutputFormat` at the crate root; there is **no** `rustyjack_commands::cli` module.
- The CLI struct differs from what the patch assumes: it uses `json` and `output_format` fields, not `output` string parsing.
- Most importantly: many sync wrappers in `rustyjack-core` call `tokio::runtime::Handle::try_current()` and then call `handle.block_on(…)`. If you wrap the entire CLI in `rt.block_on(async { … })`, you risk calling `Handle::block_on` from within an async runtime context, which is a common source of “cannot block in runtime” panics/deadlocks.

Minimal corrected diff (compiles *against the current code* by construction, and avoids nested `block_on` by using `Runtime::enter`):

```diff
diff --git a/crates/rustyjack-core/src/main.rs b/crates/rustyjack-core/src/main.rs
--- a/crates/rustyjack-core/src/main.rs
+++ b/crates/rustyjack-core/src/main.rs
@@
 use anyhow::Result;
 use clap::Parser;
 use rustyjack_core::{dispatch_command, logs_enabled, resolve_root, Cli, OutputFormat};
@@
 fn main() {
     let cli = Cli::parse();
     let format = if cli.json { OutputFormat::Json } else { cli.output_format };
 
     if logs_enabled() {
         tracing_subscriber::fmt()
             .with_env_filter("info")
             .with_writer(maybe_get_stderr)
             .with_ansi(false)
             .init();
     }
+
+    // Ensure a Tokio runtime/reactor is active for code paths that construct tokio-based
+    // netlink sockets (e.g., rtnetlink/new_connection). Avoid wrapping the whole program
+    // in block_on; we only need the runtime entered for synchronous callers.
+    let _tokio_guard = match rustyjack_core::runtime::shared_runtime() {
+        Ok(rt) => Some(rt.enter()),
+        Err(err) => {
+            emit_error(format, &err);
+            std::process::exit(1);
+        }
+    };
 
     if let Err(err) = run(cli, format) {
         emit_error(format, &err);
         std::process::exit(1);
     }
 }
```

Why this is the safer minimal approach:
- It uses the already-present shared runtime infrastructure (`rustyjack_core::runtime::shared_runtime()`).
- It avoids introducing a new runtime builder whose configuration might differ from the one used elsewhere.
- It avoids running synchronous logic inside an async `block_on` context, which reduces the risk of nested-runtime blocking issues.

### UI-only daemon gate configuration (`services/rustyjackd.service`)

Report status: **FAIL (diff does not match file; material security impact)**

What the report proposes:
- Add `Environment="RUSTYJACKD_UI_ONLY_OPERATIONS=false"` and claims it is safe because socket filesystem permissions still apply.

What the repo actually contains:
- `services/rustyjackd.service` is `Type=notify` and already sets multiple `Environment=` entries, but the diff in the report assumes `Type=simple` and references `RUSTYJACKD_STATE_DIR` (not present in the unit file). The proposed diff will not apply cleanly.

Correct “applyable” diff (if you decide you truly want this behaviour **on a test image**):

```diff
diff --git a/services/rustyjackd.service b/services/rustyjackd.service
--- a/services/rustyjackd.service
+++ b/services/rustyjackd.service
@@
 Environment=RUSTYJACKD_SOCKET=/run/rustyjack/rustyjackd.sock
+Environment=RUSTYJACKD_UI_ONLY_OPERATIONS=false
 Environment=RUSTYJACKD_ROOT=/var/lib/rustyjack
```

Important security qualifier:
- This change is *not* “low risk” by default. It intentionally removes a server-side restriction that denies privileged operations unless the client is the UI user or daemon-spawned. If shipped broadly, it increases the set of processes that can invoke high-impact RPCs (bounded by group membership, but still wider).

Safer alternatives the report should discuss (but does not):
- Make tests run the privileged RPCs as the **UI user** (`rustyjack-ui`), which satisfies the existing security model without disabling it.
- Apply `RUSTYJACKD_UI_ONLY_OPERATIONS=false` only via a **test-only systemd drop-in** or test harness environment, not in the production unit file.

### Passive isolation for ethernet discover (`crates/rustyjack-core/src/operations.rs`)

Report status: **FAIL (references non-existent types and wrong function signatures)**

Reasons:
- The report patch assumes `handle_eth_discover(cfg: &Config, args: &EthDiscoverArgs, …)`; in the repo it is `handle_eth_discover(root: &Path, args: EthernetDiscoverArgs, cancel: Option<&CancelFlag>)`.
- The report calls `apply_interface_isolation_with_ops_passive(ops, &iface)`; in the repo this helper exists as  
  `apply_interface_isolation_with_ops_passive(ops: Arc<dyn NetOps>, root: PathBuf)` — it does **not** take an interface, and cannot be called with `&iface`.
- The report’s patch also uses `.with_context(...)` but does not ensure `anyhow::Context` is imported at that site.

Corrective guidance:
- If the intent is “read-only discover must not churn routes”, the report must propose an implementable design for the current codebase, e.g.:
  - remove `enforce_single_interface(&interface.name)?;` from ethernet discover (and accept the behavioural change), or
  - create a *non-destructive* “selection-only” helper that brings down *other* interfaces without releasing DHCP/flush/deleting routes on the active interface.

A minimal, reviewable starting point (behaviour change is explicit) would be to **remove strict isolation** from ethernet discover and document why:

```diff
diff --git a/crates/rustyjack-core/src/operations.rs b/crates/rustyjack-core/src/operations.rs
--- a/crates/rustyjack-core/src/operations.rs
+++ b/crates/rustyjack-core/src/operations.rs
@@
     let interface = detect_ethernet_interface(args.interface.clone())?;
-
-    enforce_single_interface(&interface.name)?;
+    // NOTE: ethernet discover is observational. Running strict isolation here can delete the
+    // current default route and trigger DHCP churn, and if the operation aborts it can leave
+    // the device without connectivity. Tests currently assert the route table remains unchanged.
 
     check_cancel(cancel)?;
```

Whether this is *correct* for your product depends on your threat model; the report must justify it and consider any leakage risks.

### VFAT detection patch (`crates/rustyjack-core/src/mount.rs`)

Report status: **FAIL (wrong type names; wrong error format; diff does not match current code)**

Reasons:
- The repo uses `FsType` (not `FileSystemType`) and errors with `anyhow!("unsupported or unknown filesystem")` (no device string).
- The patch’s context and error line (`unsupported or unknown filesystem on {dev}`) do not match the current function.
- The heuristic itself is plausible, but must be wired into the actual code.

Corrected minimal diff (adds the heuristic to the existing `is_vfat` helper, keeping current public behaviour):

```diff
diff --git a/crates/rustyjack-core/src/mount.rs b/crates/rustyjack-core/src/mount.rs
--- a/crates/rustyjack-core/src/mount.rs
+++ b/crates/rustyjack-core/src/mount.rs
@@
 fn is_vfat(buf: &[u8]) -> bool {
     if buf.len() < 90 {
         return false;
     }
     let label1 = &buf[54..62];
     let label2 = &buf[82..90];
-    label1 == b"FAT12   " || label1 == b"FAT16   " || label2 == b"FAT32   "
+    if label1 == b"FAT12   " || label1 == b"FAT16   " || label2 == b"FAT32   " {
+        return true;
+    }
+
+    // Heuristic VFAT detection for formatters that leave the label fields blank.
+    // Require boot sector signature + plausibly valid BPB fields.
+    if buf.len() >= 512 {
+        let sig_ok = buf[510] == 0x55 && buf[511] == 0xAA;
+        let bps = u16::from_le_bytes([buf[11], buf[12]]);
+        let spc = buf[13];
+        let fats = buf[16];
+        let bps_ok = matches!(bps, 512 | 1024 | 2048 | 4096);
+        let spc_ok = spc != 0 && (spc & (spc - 1)) == 0;
+        let fats_ok = fats == 1 || fats == 2;
+        return sig_ok && bps_ok && spc_ok && fats_ok;
+    }
+
+    false
 }
```

### Test harness patches in scripts

Report status: **mixed (the diagnoses are often right, but the report does not provide concrete, applyable diffs; some recommendations conflict with “Rust-only fixes”)**

Items that are straightforward and correct in principle:
- `G4_log_dir_secure`: the report’s diagnosis matches the bash substring bug (using `${perms:2:1}` against a 4-digit mode like `2770`).
- `J1_wifi_scan_request`: the IPC type requires `timeout_ms`, and the log shows the daemon rejects the request when missing.
- Protocol mismatch checks: scripts are using brittle greps; the daemon error is a structured JSON envelope with numeric error codes, so grepping for “version” can be wrong.

Items needing stronger evidence or better framing:
- `I1_pid_disappears_auth_VULNERABLE`: the daemon auth implementation reads `/proc/<pid>/status` and explicitly fails closed when it cannot read groups, which makes the “VULNERABLE” conclusion suspicious. The report is likely right that this is a false positive, but it should prove that by showing the script does not actually drop privileges.

## Constraints compliance

Checklist applied to the report’s recommended fixes (as written):

- Rust-only changes? **No.** The report recommends multiple changes to `scripts/*.sh` and to `services/rustyjackd.service`.
- New binaries required? **No new system binaries are explicitly required by the report’s fixes**, but the report sometimes assumes tools (`sudo`, etc.) in the test environment. The project’s own scripts already depend on bash, python3, ip/iw/rfkill in places.
- Shell-outs introduced? **Not in the Rust patches**, but several fixes are explicitly shell-script based.
- NetworkManager/nmcli assumptions? **No** (the report correctly avoids nmcli assumptions, consistent with `AGENTS.md`).
- Minimal/reviewable diffs? **Mixed.** The report includes diffs, but several of them are not applicable to the current repo and would not compile/apply.

Most important: several of the report’s “Suggested Patch” diffs are effectively placeholders (wrong structs, wrong module paths/types/signatures). As-is, they do not meet the “do not handwave compilation” audit rule.

## Pi Zero 2 W viability

Assessment is about the *runtime impact* of the report’s recommended fixes on a Pi Zero 2 W class device.

- Tokio runtime initialisation for the CLI: **Low–Medium impact.** Entering an existing shared runtime is minimal; creating a fresh `enable_all` multi-thread runtime per command would be heavier. The report’s patch chooses a current-thread runtime, which is good for Pi, but the patch is not written against the repo and uses an approach (`block_on(async { run(...) })`) that may be risky with sync wrappers.  
  Safer Pi-friendly approach: use a **current-thread runtime** and `enter()` for the duration, but do not wrap the whole CLI in `block_on`.
- Passive/relaxed isolation for discovery: **Low impact** computationally, but can have behavioural impacts. Avoiding DHCP/route churn is actually *better* for device stability and battery/CPU.
- VFAT detection heuristic: **Low impact.** It merely adds a few integer checks on an already-read sector buffer.
- Script-only changes: **No runtime impact** on the device’s steady state, but adds test harness complexity.

## Security review

This is the most important section. Risk ratings assume the change is shipped to real devices, not only used in a lab.

- Disabling `ui_only_operations` via systemd (`RUSTYJACKD_UI_ONLY_OPERATIONS=false`): **High risk if shipped broadly.** It deliberately removes a server-side restriction that currently prevents non-UI clients from invoking non-read-only RPCs. While the UDS filesystem permissions and group-based auth still apply, the set of principals able to attempt privileged operations increases.  
  Mitigation: keep default UI-only true; enable headless operation only via explicit, test-only configuration or by making the test harness run as the UI user.
- Relaxing/avoiding strict interface isolation for read-only discovery: **Medium risk (context-dependent).** Strict isolation is a security boundary intended to prevent unintended traffic on non-selected interfaces. Removing it for “read-only” commands may be acceptable if those commands do not transmit sensitive data and already bind to the intended interface; but it should be a conscious policy decision, not just a test workaround.
- VFAT heuristic detection: **Low–Medium risk.** The main risk is false positives (treating a non-VFAT block device as VFAT). The mount path uses `MS_NOSUID|MS_NODEV|MS_NOEXEC`, which reduces the impact of mounting attacker-controlled media, but false classification can still lead to confusing behaviour and should be paired with kernel mount failure handling and clear logs.
- Protocol mismatch checks and JSON parsing improvements in test scripts: **Low risk.** This is test correctness, not product security.
- I1 “VULNERABLE” test: the daemon auth code fails closed when it cannot read `/proc/<pid>/status`, so “privilege escalation on PID disappearance” appears unlikely. The report is right to treat the test script’s conclusion sceptically, but it should explicitly reference the fail-closed behaviour in the daemon auth logic in its reasoning.

## Engineering quality and modern Rust assessment

The report shows awareness of several good practices (avoid nmcli, keep fixes minimal, prefer passive isolation, avoid broad permissions), but its concrete patches do not meet the bar for a senior Rust + embedded Linux triage document:

- Several Rust diffs will not compile because they reference non-existent modules/types/fields (`rustyjack_commands::cli`, `cli.output`, `FileSystemType`, wrong signatures for `apply_interface_isolation_with_ops_passive`).
- The “Tokio runtime” fix is described at the symptom level (“no reactor running”) but misses an important implementation detail: many call sites are synchronous wrappers that already call `Handle::try_current()` and `block_on`, which makes “wrap everything in block_on” potentially unsafe.
- The report’s table repeatedly uses test names that do not exist in the provided logs for evasion/anti-forensics/physical-access, indicating it was not verified against the actual run artefacts.
- The report suggests changing a security gate (UI-only operations) in a production unit file without a tight test-only strategy, which is not acceptable without explicit product owner approval.

## Verdict, punch list, and scoring rubric

### Verdict

**NEEDS REVISION**

The report contains several *plausible* diagnoses, but it is not presently actionable: too many table rows do not match the actual failures in the provided logs, and most “Suggested Patch” diffs do not apply to the current repo or will not compile.

### Prioritised punch list of edits needed to the report itself

- Correct the failures table so every row corresponds to a real failing check in `test_logs/*_run.log` and/or `test_logs/*_summary.jsonl`. At minimum:
  - add the missing `wifi_scan_wlan1` failure,
  - replace non-existent help-test names (`*_help`) with the actual failing test names (`evasion_mac_status`, `audit_log_status`, etc.),
  - fix the suite attribution errors (e.g., router fingerprint failures are under `physical_access`, not `evasion`).
- Replace placeholder/incorrect diffs with patches written against the current code:
  - fix imports/field names in `crates/rustyjack-core/src/main.rs`,
  - fix type names in `crates/rustyjack-core/src/mount.rs` (`FsType` not `FileSystemType`),
  - fix function signatures and availability for isolation helpers (`apply_interface_isolation_with_ops_passive` takes `(ops, root)` not `(ops, iface)`).
- Reframe the UI-only operations issue as a **policy decision**:
  - If UI-only mode is intended by default (it is the code default), tests asserting operator/admin RPC success are wrong and should be updated.
  - If headless mode is intended for CI/dev images, then document a *test-only* configuration mechanism (drop-in or environment set in harness) rather than changing the production unit.
- For script fixes (D1, G4, I1, J1), include concrete diffs and ensure they do not introduce new runtime dependencies beyond what the repo already expects.
- For route churn problems, clearly explain whether you are changing product behaviour (reducing strict isolation) or changing tests. Avoid “tolerate route changes” recommendations unless you can prove that route churn is an acceptable invariant on the dedicated device.

### Scoring rubric (0–5)

Evidence fidelity: **2/5**  
Too many table rows reference tests that do not exist in the provided logs, and some quoted evidence strings do not match the actual diff lines or caller identity.

Root-cause correctness: **3/5**  
Several high-level diagnoses are plausible (Tokio reactor absence, UI-only gate, missing IPC field, bash perms bug), but some are incomplete or under-evidenced (USB detectability preflight, daemon protocol mismatch “not rejected”, route churn interpretation).

Patch buildability: **1/5**  
Most included Rust diffs will not apply/compile against the current repo (wrong module paths/types/signatures). Script-level fixes are described but not delivered as concrete diffs.

Constraint compliance: **2/5**  
Recommendations include non-Rust edits (systemd + scripts) and a security-sensitive daemon config change. It does avoid nmcli assumptions and does not propose adding new binaries.

Pi Zero 2 W viability: **3/5**  
Intent is generally Pi-aware (current-thread runtime idea; low-overhead FS heuristic). However, details about Tokio runtime usage are not written in a way that is clearly safe with the code’s sync wrappers.

Security posture: **2/5**  
The report proposes weakening a significant daemon security gate in production configuration without strong guardrails. It does, however, correctly flag at least one likely false-positive “vulnerable” test.

Modern Rust engineering quality: **2/5**  
Good instincts, but the report fails the “verify functions/modules exist and compile” requirement and uses placeholder diffs.

Overall actionability: **1/5**  
Requires substantial revision before it can be used as a reliable remediation plan.

[Download TEST_LOG_FIX_REPORT_CRITIQUE.md](sandbox:/mnt/data/TEST_LOG_FIX_REPORT_CRITIQUE.md)