# FIX_IMPLEMENTATION_REPORT.md

[Download FIX_IMPLEMENTATION_REPORT.md](sandbox:/mnt/data/FIX_IMPLEMENTATION_REPORT.md)

## Constraints and non-negotiables

This remediation plan assumes the project’s documented platform and operational constraints are enforced: the target device is a Raspberry Pi Zero 2 W; NetworkManager is removed (so `nmcli` must not be assumed); and the appliance forbids external process spawning and runtime reliance on external binaries for core functionality. citeturn0file0

Security constraints are treated as highest priority: fixes must not widen filesystem/socket permissions “just to satisfy tests”, must not bypass daemon authorisation checks, and must not introduce privilege escalation paths. citeturn0file0

Finally, several failing suites are in sensitive/offensive-security territory (evasion, physical-access, anti-forensics). The correct remediation is **not** to implement or re-enable those capabilities to satisfy tests; instead, make sure test harness behaviour is explicit (SKIP with a reason) unless there is an intentional, explicit opt-in. The critique notes that many of these failures are currently just “unrecognised subcommand …” errors, which supports treating them as a gating/skipping policy problem rather than a product-functionality gap. citeturn0file0turn0file1

## Evidence reconciliation workflow and known mismatches

The first job for an in-repo AI agent is to reconcile the report’s failure table against `test_logs/*_run.log` and `test_logs/*_summary.jsonl`, treating logs as ground truth. The critique explicitly shows that some failures are correctly evidenced, but many are misnamed, misattributed, or missing from the report table. citeturn0file0

Examples of confirmed high-signal evidence from the logs (as quoted in the critique) include:

- Tokio/reactor panic lines (“there is no reactor running … must be called from the context of a Tokio 1.x runtime”) causing wireless scan and ethernet discover failures. citeturn0file0  
- Route snapshot diffs during readonly suites (e.g., default route removed/added) causing “Isolation check failed … (route changed)” failures. citeturn0file0turn0file1  
- Daemon RPC responses denying operations as “restricted to the UI runtime”. The critique notes this appears even when the handshake shows `uid 0` / role `admin`, so the issue is not simply “operator user lacks privileges” and must be handled as intended policy + test harness alignment. citeturn0file0turn0file1  
- USB mount failures returning “unsupported or unknown filesystem” (and not necessarily including a device path in the error string, despite what the original report claims). citeturn0file0turn0file1  
- Comprehensive-suite failures including a false “world-write bit set” conclusion on mode `2770`, and an IPC request rejected for missing `timeout_ms`. citeturn0file0turn0file1  

Known mismatches that the agent must correct before implementing fixes:

- A Tokio/reactor failure for `wifi_scan_wlan1` is present in the logs but omitted from the original report’s failure index. citeturn0file0turn0file1  
- For evasion/physical-access/anti-forensics, multiple failures in the report are listed as `*_help` tests that do not exist in the logs; the actual failures are dominated by “error: unrecognised subcommand …”. citeturn0file0turn0file1  
- Several “Suggested Patch” diffs in the report won’t apply because they reference wrong module paths/types or mismatched function signatures; the critique calls this out and provides implementable alternatives. citeturn0file0turn0file1  

## Remediation plan for product code

The agent should implement minimal, reviewable diffs that fix root causes without changing the security model or adding runtime process/binary dependencies.

The following sub-plans are intentionally detailed enough to be executed directly inside the repo, but they do not require you to accept any specific code patch verbatim; the agent must still confirm exact symbol names and signatures against the current tree before editing (as the critique recommends). citeturn0file0turn0file1

**Tokio runtime “no reactor running” panics**

The symptom is a CLI panic: “there is no reactor running … must be called from the context of a Tokio 1.x runtime.” citeturn0file0turn0file1

Tokio’s runtime context is entered via `Runtime::enter()` (or `Handle::enter()`), which uses a thread-local “current runtime” so that runtime-dependent APIs can find the active reactor. citeturn0search0 This matches the general class of failures where code attempts Tokio I/O/spawn without having entered a runtime context. citeturn0search13turn0search1

The critique identifies a key pitfall: the original report proposes wrapping the whole CLI inside `rt.block_on(async { run(cli, format) })`, but the repo appears to contain synchronous wrappers that call `Handle::try_current()` and then `handle.block_on(...)`. Running such synchronous wrappers inside an async `block_on` context can lead to “cannot block in runtime” panics or deadlocks; therefore the safer approach is to **enter** a runtime context for the program lifetime while keeping the CLI logic synchronous. citeturn0file0turn0file1

Implementation approach:

- In `crates/rustyjack-core/src/main.rs`, after CLI parsing and logging init, obtain a runtime (prefer an existing shared runtime helper if one exists) and call `rt.enter()`; keep the guard alive until the program exits. citeturn0file0  
- If a runtime must be created, prefer `tokio::runtime::Builder::new_current_thread()` and enable only what’s needed for netlink/Tokio I/O (`enable_io()` and, if timers are used, `enable_time()`), rather than `enable_all()`; this keeps overhead down on Pi Zero class devices while still providing the reactor. citeturn0search0turn0search4

Acceptance criteria:

- Wireless/ethernet discovery suites no longer exit early due to the reactor panic. citeturn0file0turn0file1  

**Route churn caused by strict isolation inside read-only operations**

The symptom is route snapshot diffs during suites that treat the operation as observational, producing failures such as “Isolation check failed … (route changed)” and showing default route removal/addition. citeturn0file0turn0file1

The critique ties this to “strict isolation” logic that deletes routes and flushes addresses, and notes that the original report’s patch proposals here often won’t apply because they reference non-existent signatures or wrong helper call shapes. citeturn0file0turn0file1

Implementation approach:

- Identify which commands are supposed to be observational (discover/inventory/read-only RPCs). For these, isolation must not be destructive: it should not flush IP addresses, delete default routes, or otherwise trigger DHCP churn.
- If the repo already contains a passive/non-destructive isolation helper, route observational commands through that helper; if not, implement a minimal “observational isolation policy” that does not modify routes/addresses and is idempotent. The critique suggests that one practical minimal change is to remove strict isolation from ethernet discover paths, explicitly documenting why (stability + test invariant). citeturn0file0turn0file1  
- Keep strict isolation only for explicitly disruptive operations where reconfiguration is intended and user-consented.

Acceptance criteria:

- `ethernet_eth0_readonly`, `loot_readonly`, and daemon RPC readonly route checks stop failing due to route diffs. citeturn0file0turn0file1  

**Daemon RPC blocked by “UI-only operations” default**

The symptom is that RPC calls return an error like “operations are restricted to the UI runtime” (the critique shows this even when the handshake indicates role `admin` and `uid 0`), so this is a server-side policy gate rather than a simple Unix permissions mismatch. citeturn0file0turn0file1

Security requirements:

- Do not widen UDS filesystem permissions or remove daemon-side credential/auth checks to satisfy tests. citeturn0file0  
- Prefer test-only configuration overrides rather than changing secure defaults globally. citeturn0file0turn0file1  

Implementation approach:

- First, confirm the defence-in-depth model: (a) UDS path filesystem permissions, and (b) daemon peer credential verification, typically using `SO_PEERCRED` on Unix domain sockets, which returns the peer’s credentials as of `connect(2)`. citeturn1search2  
- Then choose one of two “safe by default” paths:
  - If UI-only is intended by default, update tests to run privileged RPCs in the intended UI context (or to explicitly enable headless mode for tests only).
  - If headless/admin RPC is needed for CI/dev images, enable it via an explicit test-only profile.

Practically, the least risky test-only mechanism (when systemd launches the daemon) is to install a systemd drop-in during test runs, rather than editing the production unit file. systemd’s `Environment=` directive is designed for injecting environment variables into service processes, supports multiple occurrences, and later settings override earlier ones. citeturn4view0

Suggested harness behaviour (high-level):

- During tests, create `/etc/systemd/system/rustyjackd.service.d/test.conf` containing `Environment=RUSTYJACKD_UI_ONLY_OPERATIONS=false`, reload daemon state, restart the daemon, run RPC suites, then remove the drop-in and restart again. citeturn4view0turn0file0  

Important operational note: systemd warns that environment variables are not suitable for secrets and can be exposed via IPC; in this case the value is a non-secret boolean flag, but the warning reinforces the principle of keeping the override test-scoped and non-sensitive. citeturn4view0

Acceptance criteria:

- Interface selection and daemon RPC suites pass, while RO/untrusted callers remain blocked by filesystem permissions and daemon-side peer-credential/role checks. citeturn0file0turn0file1  

**USB filesystem detection rejects common FAT media**

The symptom is a mount rejection: “unsupported or unknown filesystem.” citeturn0file0turn0file1

The critique suggests the existing VFAT check is too strict (relying on optional label strings), and recommends adding conservative plausibility checks: require the boot sector signature and validate key BPB fields. citeturn0file0turn0file1

Implementation approach:

- Use conservative VFAT heuristics based on the FAT boot sector layout:
  - Bytes per sector is stored at offset `0x0B` (decimal 11), sectors per cluster at `0x0D` (decimal 13), number of FATs at `0x10` (decimal 16), as shown in standard FAT layout references. citeturn6view1turn1search4  
  - Require the `0x55 0xAA` boot sector signature at the end of the 512-byte sector (commonly described byte-wise as “55aa”). citeturn0search3turn6view1  
  - Apply plausibility checks: bytes-per-sector ∈ {512, 1024, 2048, 4096}; sectors-per-cluster > 0 and power-of-two; FAT count ∈ {1,2}. citeturn6view1turn1search4  
- Keep filesystem support conservative: do not broaden to new filesystems unless the product explicitly intends it. citeturn0file0turn0file1  
- Maintain mount hardening. Linux mount flags `MS_NODEV`, `MS_NOEXEC`, and `MS_NOSUID` respectively disable device access, execution, and honouring setuid/setgid capabilities on the mounted filesystem; these are standard hardening flags for mounting attacker-controlled removable media. citeturn8view0  

Acceptance criteria:

- `usb_mount_read_write` succeeds on typical FAT-formatted media, and the heuristic does not cause spurious mounts of non-FAT data. citeturn0file0turn0file1  

## Remediation plan for test harness and suite policy

The critique identifies multiple failures that are primarily harness correctness issues rather than product defects, and it recommends fixing them as harness fixes without weakening security. citeturn0file0turn0file1

Harness fixes to implement:

- Fix permissions parsing: the comprehensive test flags `perms=2770` as “world-write bit set”, which the critique attributes to a bash substring bug that reads the wrong digit from a 4-digit mode string (e.g., `${perms:2:1}` instead of reading the final “others” digit). citeturn0file0turn0file1  
- Fix missing IPC fields: the comprehensive suite’s WifiScanStart request is rejected as invalid due to missing required field `timeout_ms`, as shown in the daemon log excerpt. citeturn0file0turn0file1  
- Make protocol mismatch tests structured: the critique notes that some “protocol mismatch rejected” failures are under-evidenced in the logs and that grep-based checks are brittle; the harness should parse JSON envelopes and assert on structured error shape/codes, or treat connection failure as the expected “rejected” outcome. citeturn0file0turn0file1  
- Fix RO-user security tests: the critique flags that the “I1_pid_disappears_auth_VULNERABLE” conclusion is likely a false positive and that tests must actually run as the RO user, treating “cannot connect” (due to socket perms) as secure rather than a failure. citeturn0file0turn0file1  

Policy/gating fixes for sensitive suites:

- For evasion/physical-access/anti-forensics, the logs show missing CLI surfaces (“unrecognised subcommand …”), and the critique explicitly states multiple report rows don’t match actual tests. citeturn0file0turn0file1  
- The correct harness change is: detect missing subcommands early and SKIP with an explicit reason, optionally guarded by an explicit opt-in environment variable so that such suites never run accidentally. This satisfies the “no offensive enhancement” constraint while turning noisy failures into explicit, reviewable skips. citeturn0file0turn0file1  

## Verification protocol and artefacts

Verification must be done on a real Pi Zero 2 W and recorded in a reproducible way, re-running targeted suites after each fix and only then doing a full run. The repository’s fix workflow expectation is repeated throughout the report/critique materials: confirm failures in logs first, apply minimal diffs, and validate by re-running suites and capturing the resulting `*_run.log` / `*_summary.jsonl`. citeturn0file0turn0file1

At minimum, the agent should:

- Run `cargo check --workspace` after each code change to ensure proposed patches actually compile in this repo (the critique emphasises that several suggested patches in the original report would not compile as written). citeturn0file0turn0file1  
- Re-run suites corresponding to each fix area (wireless, ethernet, interface selection/daemon RPC, usb mount, comprehensive), capturing logs and noting any remaining failures with exact lines and dates. citeturn0file0turn0file1  

## Security and performance notes

Performance on Pi Zero class hardware: prefer Tokio current-thread runtime patterns and only enable the minimum drivers required (I/O and time), rather than defaulting to more heavyweight multi-thread runtimes. Tokio explicitly documents using runtime context entry (`Runtime::enter`) to make runtime-dependent operations work without restructuring the whole program into async. citeturn0search0turn0search4

Security invariants to preserve while fixing failing tests:

- Daemon authorisation must continue to rely on strong local identity signals (UDS permissions plus peer credentials such as `SO_PEERCRED`) and role checks. citeturn1search2turn0file0  
- Removable media mounts must keep hardening flags (`nodev`, `noexec`, `nosuid`) as defined in `mount(2)`, and filesystem detection must be conservative to reduce false positives. citeturn8view0turn6view1  
- Test-only overrides (like disabling a UI-only operational gate) should be implemented as **test-scoped** configuration (systemd drop-in or harness environment injection), not as a global weakening of production defaults; systemd’s unit environment mechanism supports this cleanly. citeturn4view0turn0file0