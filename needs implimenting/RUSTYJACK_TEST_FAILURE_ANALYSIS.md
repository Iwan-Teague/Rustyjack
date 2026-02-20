# Rustyjack on Pi Zero 2 W --- Test Failure Analysis & Fix Plan (Rust-first)

Run context: - Device: Raspberry Pi Zero 2 W - OS: Debian GNU/Linux 13
(trixie) - Install method: prebuilt installer - Tests executed over SSH
via Ethernet connection (Pi → router) - Run ID: 20260220-140515 -
Suites: 17 run, 12 failed (lots of cascading failures)

------------------------------------------------------------------------

## Executive Summary

Primary systemic issues identified:

1.  JSON output contaminated by log lines
2.  Daemon socket path disappears while service remains active
3.  Overly aggressive interface isolation logic
4.  Missing directory creation for loot artifacts
5.  RF-kill handling during MAC randomization
6.  Installer script pattern mismatches
7.  Read-only operations mutating network state

------------------------------------------------------------------------

## Major Root Causes & Fixes

### 1. JSON Output Contamination

Problem: Logs are written alongside JSON output, breaking JSON parsing
in tests.

Fix: When `--output json` is selected: - Do NOT initialize
tracing/logging. - Emit JSON only. - Ensure no stray println!/eprintln!
calls occur before structured output.

Recommended change in `main.rs`:

``` rust
if format != OutputFormat::Json && logs_enabled() {
    init_tracing();
}
```

------------------------------------------------------------------------

### 2. Daemon Socket Path Disappearing

Symptoms: - `rustyjackd.sock` missing from `/run/rustyjack` - RPC calls
fail with FileNotFoundError - `ss` still shows active listener

Root Cause: Conflict between socket unit and service runtime directory
management.

Fix: - Remove `RuntimeDirectory=rustyjack` from service unit - Let
socket unit own directory lifecycle - Or enable
`RuntimeDirectoryPreserve=yes`

------------------------------------------------------------------------

### 3. Ethernet Loot Directory Missing

Error: `No such file or directory` when writing discovery artifacts.

Fix: Ensure parent directories exist before writing:

``` rust
if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)?;
}
```

------------------------------------------------------------------------

### 4. Wireless Scan Failures

Problem: Scan fails if interface is DOWN and isolation logic enforces UP
state.

Fix: - Bring interface UP if needed - Do not enforce destructive
isolation for scan operations

------------------------------------------------------------------------

### 5. MAC Randomization & RF-kill

Problem: Bringing interface UP after MAC change fails when RF-kill is
active.

Fix: - Record original state - Only restore UP if previously UP - Treat
RF-kill UP failure as warning, not fatal error

------------------------------------------------------------------------

### 6. Read-Only Operations Mutating Network

Tests detect route/DNS changes after supposedly read-only commands.

Fix: Add operation metadata such as:

``` rust
fn requires_network_mutation(&self) -> bool
```

Only apply isolation/routing when required.

------------------------------------------------------------------------

### 7. Installer Script Pattern Failures

Wrapper installer scripts lack required function definitions and
strings.

Fix: - Extract shared logic into `scripts/install_common.sh` - Ensure
required functions exist in all installers

------------------------------------------------------------------------

## Recommended Fix Order

1.  JSON-only output mode
2.  Fix systemd daemon/socket ownership
3.  Prevent readonly network mutations
4.  Create loot directories before writing
5.  Relax wireless scan isolation
6.  RF-kill tolerant MAC randomization
7.  Installer refactor
8.  UI persistence validation

------------------------------------------------------------------------

End of Report.
