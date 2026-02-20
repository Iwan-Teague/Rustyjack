# RustyJack – Pi Zero W2 Test Failures & Fix Plan (2026-02-20)

## Context
- Device: Raspberry Pi Zero W2
- Tests executed over SSH via Ethernet
- Results analyzed from:
  - `rustyjack_20260220-140515_summary.md`
  - `rustyjack_20260220-140515_all_logs.txt`
  - results bundle `20260220-140515/*`

## High-level Root Causes (Most Impact)
1. **Logs written to stdout corrupt JSON outputs** used by multiple suites.
2. **Interface isolation invoked during read-only commands** (wifi scan, ethernet discover) causing network mutations and failures.
3. **Default route deletion bug:** “delete route for iface” deletes all default routes.
4. **Daemon unix socket path missing** (socket appears listening but filesystem entry absent) → RPC fails.
5. **Daemon routing changes are non-idempotent (delete then add)** → snapshot race sees route changes.
6. **Bash script issues** (hotspot missing function; theme navigation index drift).
7. **Installer wrappers missing required logic/patterns**.

---

## Suite-by-suite: What Failed and Why

### Discord Webhook
- Fail: `discord_send_succeeded`
- Cause: stdout logs precede JSON output; parser fails.
- Fix: move tracing logs to stderr.

### USB Mount
- Multiple failures that depend on reading JSON output.
- Cause: same stdout log pollution.
- Additional: route snapshot diffs likely due to daemon route flapping.
- Fix: stderr logs + daemon routing idempotence.

### Ethernet
- Fail: `eth_discover_eth0`
- Cause: loot filename uses CIDR string `192.168.18.0/24` → `/` becomes a path separator.
- Fix: sanitize label when building filenames.
- Also: route snapshot diffs caused by isolation enforcement and/or daemon route flapping.

### Wireless
- Fail: `wifi_scan_wlan0`, `wifi_scan_wlan1` (rc=1)
- Cause: `wifi scan` enforces strict interface isolation (brings other interfaces down, releases DHCP, rfkill changes). This can:
  - violate isolation invariants in a managed networking environment,
  - mutate routes and break “read-only snapshot” expectations.
- Fix: do NOT enforce strict isolation for `wifi scan` by default. Optional `--isolate` flag if desired.

### Evasion
- Fail: `evasion_mac_randomize`
- Cause: wlan interface soft-blocked by rfkill (likely left behind by earlier strict isolation failures); randomize-mac doesn’t unblock.
- Fix: ensure rfkill unblocked before MAC changes; reduce rfkill side effects from read-only commands.

### Daemon / Interface Selection / Deep Daemon
- Many RPC calls fail with FileNotFoundError for `/run/rustyjack/rustyjackd.sock`.
- Cause: socket inode exists but path entry missing/unlinked. Likely runtime directory management conflicts with socket unit.
- Fix: adjust systemd units + runtime directory creation strategy.

### Encryption / Theme / USB Mount route diffs
- Cause: daemon routing logic temporarily removes default route (delete then add), so snapshot races see route change.
- Fix: route updates must be idempotent/replace-based (never create a “no default route” window).

### Hotspot
- Script exits (rc=127) because `rj_detect_wifi_interface` is undefined.
- Fix: implement function in `scripts/rj_test_lib.sh` or update hotspot script.

### Installers
- Wrapper installers missing required patterns/steps.
- Fix: copy/inline the common functions and required log lines.

---

## Fix Plan (Detailed)

## 1) Stop corrupting JSON output: send logs to stderr

### Change
`crates/rustyjack-core/src/main.rs`

#### Before
```rust
tracing_subscriber::fmt()
  .with_env_filter(filter)
  .init();
```

#### After
```rust
tracing_subscriber::fmt()
  .with_env_filter(filter)
  .with_writer(std::io::stderr) // key change
  .with_ansi(atty::is(atty::Stream::Stderr)) // optional but recommended
  .init();
```

#### Why

The test harness captures stdout into .json artifact files; logs must never share that channel.

## 2) Fix ethernet discovery loot filename sanitization
Change

crates/rustyjack-core/src/operations.rs in handle_eth_discover

#### Before
```rust
let file_name = format!("discovery_{}_{}.txt", net, timestamp);
```

#### After
```rust
let safe_net = crate::system::sanitize_label(&net.to_string());
let file_name = format!("discovery_{}_{}.txt", safe_net, timestamp);
```

## 3) Remove strict isolation from read-only commands (wifi scan, ethernet discover)
WiFi Scan

crates/rustyjack-core/src/operations.rs in handle_wifi_scan

#### Before
```rust
system.enforce_single_interface(&interface)?;
```

After (default no isolation; optional flag)

Add CLI arg: --isolate default false.

Only enforce isolation if args.isolate == true.

**Pseudocode:**
```rust
if args.isolate {
  system.enforce_single_interface(&interface)?;
}
```

Ethernet Discover

handle_eth_discover currently enforces single interface.
Remove it; discovery should not reconfigure other links.

## 4) Fix default route deletion semantics (per-interface, not global)
Problem

NetOps::delete_default_route(iface) currently deletes ALL default routes.

Changes

In crates/rustyjack-netlink/src/route.rs:

Add delete_default_routes_on_interface(iface_name: &str):

map iface name -> ifindex

iterate default routes and delete only those where RTA_OIF == ifindex

In crates/rustyjack-core/src/netlink_helpers.rs:

Split helpers:

netlink_delete_all_default_routes()

netlink_delete_default_routes_on_interface(iface: &str)

In crates/rustyjack-core/src/system/ops.rs:

RealNetOps::delete_default_route(&self, iface) calls the interface-scoped helper.

## 5) Make routing idempotent to stop snapshot races
Problem

crates/rustyjack-core/src/system/routing.rs uses delete-then-add which creates a time window with no default route.

Fix

Use rustyjack_netlink::replace_default_route() (already present and used elsewhere) or “no-op if correct route already exists”.

**Pseudocode:**
```rust
fn set_default_route_with_metric(...) {
  // 1) if default route already matches iface+gateway(+metric), return Ok(())
  // 2) else call replace_default_route(gateway, ifindex, metric)
}
```

Result: daemon enforcement can run periodically without causing observable route changes.

## 6) Fix daemon socket path disappearance (systemd runtime dir conflict)
Likely cause

Service manages /run/rustyjack via RuntimeDirectory=rustyjack while socket unit binds a socket under the same path. The directory management can remove/unlink the socket entry while the inode remains open.

Fix options (preferred: tmpfiles)

Remove RuntimeDirectory=rustyjack from services/rustyjackd.service.

Ensure /run/rustyjack exists with correct ownership/mode via tmpfiles:

Add services/tmpfiles.d/rustyjack.conf:

```conf
d /run/rustyjack 0770 root rustyjack -
```

Installer must install this file to /etc/tmpfiles.d/ and run:

systemd-tmpfiles --create

Also ensure socket unit keeps:

```ini
ListenStream=/run/rustyjack/rustyjackd.sock
SocketGroup=rustyjack
SocketMode=0660
DirectoryMode=0770
```

## 7) RF-kill robustness for MAC randomization
Change

crates/rustyjack-core/src/operations.rs in handle_evasion_randomize_mac

Before calling mac_manager.set_mac(...):

detect rfkill idx for the interface (reuse rfkill_find_index)

if soft blocked, unblock

if hard blocked, return a clear error

**Pseudocode:**
```rust
if let Some(idx) = rfkill_find_index(&iface) {
  let state = rfkill_get_state(idx)?;
  if state.hard_blocked { bail!("...hard blocked...") }
  if state.soft_blocked { rfkill_set_state(idx, false)?; }
}
```

## 8) Hotspot test script fix
Change

scripts/rj_test_lib.sh
Add:

```bash
rj_detect_wifi_interface() {
  for d in /sys/class/net/*; do
    iface="$(basename "$d")"
    [[ -d "$d/wireless" ]] && { echo "$iface"; return 0; }
  done
  return 1
}
```

## 9) Theme test script fix (menu index drift)
Change

scripts/rj_test_theme.sh
In ui_nav_main_to_colors_menu, update:

rj_ui_send down 9 → rj_ui_send down 10

This matches current UI main_menu() where Settings is the 11th entry.

## 10) Installer wrapper scripts: add missing steps/patterns
Change

install_rustyjack.sh

install_rustyjack_dev.sh

They must include:

a purge network-manager section (literal text match)

disable_conflicting_services() { ... }

claim_resolv_conf() { ... }

print Running post install checks

chown -R rustyjack-ui:rustyjack ...logs

Best approach: copy the same function bodies from install_rustyjack_prebuilt.sh so behavior is consistent.

Security/Hardening Notes

Keep structured output strict: JSON must always be clean and machine-parseable.

Prefer idempotent netlink operations (replace vs delete+add) to avoid transient connectivity loss.

Avoid destructive isolation for informational commands; require explicit opt-in for “lockdown” behaviors.

Ensure systemd sandbox exceptions (ReadWritePaths) align with how files are written (avoid temp file rename across bind mounts if you later harden /etc).

Quick Regression Checklist

After applying fixes:

rustyjack notify discord send --output json emits ONLY JSON on stdout.

rustyjack usb-mount mount ... --output json emits ONLY JSON on stdout.

rustyjack ethernet discover creates loot files with sanitized names.

rustyjack wifi scan succeeds with eth0 up and does not change routes by default.

/run/rustyjack/rustyjackd.sock exists and is connectable by intended group users.

route snapshots remain stable while daemon is running.

---

## What I did *not* complete in this response (transparent gaps)
- I didn’t produce a separate downloadable `.md` file artifact (the content is complete and ready to save, but not emitted as a file attachment here).
- I didn’t implement and validate the patches by running the suite again (I can’t re-run on the Pi from here). The fixes are derived directly from the failing logs and the code paths that produced them, so the confidence is high.
- I didn’t fully design an “isolation rollback guard” (RAII state restoration) for strict isolation failures; I focused on removing strict isolation from read-only commands and fixing the route semantics that cause most trouble. If you want the isolation machinery to be safer under errors, adding a rollback guard is the next logical hardening step.

---

## Primary evidence used
- Summary of failures: `rustyjack_20260220-140515_summary.md`
- Full consolidated logs: `rustyjack_20260220-140515_all_logs.txt`
- Upstream references:
  - tracing_subscriber fmt logs to stdout by default: https://recursion.wtf/tracing-honeycomb/tracing_subscriber/fmt/index.html
  - systemd socket parent directory ownership limitation: https://github.com/systemd/systemd/issues/4125

---

If you paste that Markdown into a file and want it turned into **a patch series (diffs)** against the repo, I can structure the changes as a clean commit plan: “logging,” “netlink routing,” “daemon systemd units,” “script fixes,” etc., with minimal cross-churn.
