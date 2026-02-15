Date: 2026-02-15


### Socket permissions boundary

- `rustyjackd.socket` configures:
  - `ListenStream=/run/rustyjack/rustyjackd.sock`
  - `SocketMode=0660`
  - `SocketUser=root`
  - `SocketGroup=rustyjack`

This is the *first and most important* access gate: if you can’t open the socket, you can’t talk to the daemon.

---

## 3) AuthZ/AuthN model (what checks exist, where; what’s missing)

### Peer identity (AuthN-ish)

- The daemon obtains peer credentials on connect using `peer_credentials(...)` (UDS peer credential query) in:
  - `crates/rustyjack-daemon/src/server.rs`
  - `crates/rustyjack-daemon/src/auth.rs` defines `PeerCred { pid, uid, gid }`

This is not “authentication” in the cryptographic sense; it’s **kernel-provided identity** for local UDS peers.

### Authorization tiers (AuthZ)

Authorization is computed per peer:

- `authorization_for_peer(peer, config)` in `crates/rustyjack-daemon/src/auth.rs`
  - Root (`uid == 0`) → `AuthorizationTier::Admin`
  - Else, checks group membership:
    - `config.admin_group` (default: `rustyjack-admin`)
    - `config.operator_group` (default: `rustyjack`)
  - Uses `/proc/<pid>/status` and `/etc/group` parsing; tier summarized as `AuthzSummary` returned in handshake ack.

Tier enforcement:

- `required_tier_for_request(endpoint, body)` → required tier
- `tier_allows(actual, required)` → allow/deny
- Called in request handling path in `crates/rustyjack-daemon/src/server.rs`

Tier mapping highlights:

- Read-only endpoints: `Health`, `Version`, `Status`, `SystemStatusGet`, logs tail/get, interface list/status, etc. → `ReadOnly`
- `JobStart` tier depends on `JobKind` (`required_tier_for_jobkind`)
- `SystemCommand` tier depends on subcommand (`required_tier_for_system_command`)

### Ops gating (safety gates)

Beyond tiers, the daemon requires certain **Ops capabilities** per request:

- `required_ops_for_request(endpoint, body)` → `RequiredOps`
- `ops_allows(cfg, required)` checks current ops config flags
- Enforced in `crates/rustyjack-daemon/src/server.rs` against runtime ops config (`state.ops_runtime`)

Ops flags include: `wifi_ops`, `eth_ops`, `hotspot_ops`, `portal_ops`, `storage_ops`, `power_ops`, `system_ops`, `update_ops`, `dev_ops`, `offensive_ops`, `loot_ops`, `process_ops` (defined in `crates/rustyjack-ipc/src/types.rs` as `OpsConfig`).

### UI-only guardrails

Two config flags enforce “UI-only” restrictions:

- `ui_only_operations` (default true)  
  Blocks **non-read-only** requests unless peer is UI user or “internal descendant”:
  - `is_ui_peer(peer, config)` → checks UID of username `ui_client_user` (default: `rustyjack-ui`)
  - `is_descendant_of_process(peer.pid, daemon_pid)` → allows internal helpers spawned by daemon
  - Implemented in `crates/rustyjack-daemon/src/server.rs` using `is_read_only_request(...)`

- `ui_only_test_jobs` (default true)  
  Restricts `JobKind::UiTestRun` to UI peer only (`crates/rustyjack-daemon/src/server.rs`)

### What’s missing / weak

- No cryptographic authentication or session keys (probably fine for a local appliance, but should be explicit in threat model docs).
- No per-job ownership model (any authorized user can cancel any job).
- `JobSpec.requested_by` is not populated server-side from peer creds; client sets `None` (`crates/rustyjack-client/src/client.rs`), making audit trails weaker than they should be.

---

## 4) IPC robustness (framing, size limits, parsing failure behavior, rate limiting)

### Protocol + handshake

- Protocol version: `PROTOCOL_VERSION = 1` (`crates/rustyjack-ipc/src/lib.rs`)
- Max frame size: `MAX_FRAME = 1_048_576` (1 MiB, `crates/rustyjack-ipc/src/lib.rs`)
- Framing is **4-byte big-endian length prefix** (`u32::from_be_bytes`) in:
  - `crates/rustyjack-ipc/src/wire.rs` (`decode_frame_length`, `encode_frame`)
- Handshake:
  - Client sends `ClientHello`
  - Daemon responds with `HelloAck` including:
    - protocol version
    - daemon version
    - supported features
    - `max_frame`
    - `authz` summary (`AuthzSummary`)
  - Implemented in:
    - Server: `crates/rustyjack-daemon/src/server.rs`
    - Client: `crates/rustyjack-client/src/client.rs`

### Size limits

- The daemon enforces `max_frame` for frame parsing (`read_frame(..., config.max_frame)`).
- The client uses `ack.max_frame` for subsequent request/response frames (`write_frame(... info.max_frame)`).

### Parsing failures and protocol violations

In `crates/rustyjack-daemon/src/server.rs`:

- JSON parse failures return structured `DaemonError` (`ErrorCode::BadRequest`)
- The daemon counts **protocol violations** and closes connection after `MAX_PROTOCOL_VIOLATIONS = 3`
- Frame-level errors (zero length, too large) are considered protocol errors.

### Rate limiting and connection limiting

- Connection concurrency is capped by a semaphore (`max_connections`, default 64) in `server::run(...)`.
- Per-connection request rate limiting:
  - token bucket-ish counters inside the connection handler
  - configured by `max_requests_per_second` (default 20) in `crates/rustyjack-daemon/src/config.rs`
  - on excess, returns `ErrorCode::Busy` with message “rate limit exceeded”

### Missing / recommended IPC robustness

- No global per-UID throttling (per-connection only).
- No request queue depth limits besides the sequential read/dispatch loop.
- No explicit replay protection needed (local UDS), but **idempotency** and **re-entrancy** for jobs should be defined.

---

## 5) Job lifecycle model (start/progress/cancel/cleanup; crash consistency)

### Job types and schema

- `JobSpec { kind: JobKind, requested_by: Option<String> }` (`crates/rustyjack-ipc/src/job.rs`)
- `JobKind` includes:
  - `WifiScan`, `WifiConnect`, `HotspotStart`, `PortalStart`, `MountStart`, `UnmountStart`, `InterfaceSelect`, `SystemUpdate`, `ScanRun`, `UiTestRun`, `CoreCommand`, etc.

### Scheduler model

- `JobManager::start_job(...)`:
  - Allocates an ID
  - Stores `JobRecord` with `CancellationToken`
  - Spawns async task via `tokio::spawn` to run the job
  - `crates/rustyjack-daemon/src/jobs/mod.rs`

### Progress model

- Jobs report progress via callback closure:
  - `kinds::execute(..., |phase, percent, message| update_progress(...))`
- Progress update is throttled to avoid excessive spam (only updates if changed or 200ms elapsed).

### Cancellation model

- Cancellation is cooperative:
  - `JobManager::cancel_job(job_id)` triggers `CancellationToken.cancel()`
  - Each job kind checks `cancel.is_cancelled()` early
  - Many jobs bridge cancellation into sync/blocking code with an atomic cancel flag (`create_cancel_flag`) in:
    - `crates/rustyjack-daemon/src/jobs/cancel_bridge.rs`

Some job kinds also do explicit cleanup on cancel:

- `WifiConnect` cancel triggers `rustyjack_core::services::wifi::disconnect(...)` (`crates/rustyjack-daemon/src/jobs/kinds/wifi_connect.rs`)
- `HotspotStart` cancel triggers `rustyjack_core::services::hotspot::stop()` (`.../hotspot_start.rs`)
- `PortalStart` cancel triggers `rustyjack_core::services::portal::stop()` (`.../portal_start.rs`)
- `UiTestRun` cancels by killing the child process (`.../ui_test_run.rs`)

### Cleanup and retention

- Job records are retained in-memory up to `job_retention` (default 200). Old finished jobs are evicted; running jobs are never evicted (`enforce_retention`).
- On daemon shutdown:
  - `shutdown_gracefully(timeout=25s)` cancels all jobs and waits until none are active or timeout is reached (`crates/rustyjack-daemon/src/jobs/mod.rs`, `.../main.rs`)

### Crash consistency

- Job state is **not persisted**; restart loses all job records.
- Side effects may persist after crash/restart (mounts, iptables rules, partial update staging).
- On startup, daemon calls `reconcile_on_startup()` which enforces passive isolation via `IsolationEngine::enforce_passive()` (`crates/rustyjack-daemon/src/state.rs`). This helps network posture but does not fully model job rollback for all job types.

---

## 6) Findings (10–25) in mandatory format

### 1
**Problem →** The daemon can run the captive portal *embedded* inside the privileged daemon process.  
**Why →** Undermines privilege separation: portal code (HTTP parsing, request routing) increases attack surface in the most privileged component.  
**Where →** `crates/rustyjack-daemon/src/jobs/kinds/portal_start.rs`, `crates/rustyjack-core/src/services/portal.rs` (uses `rustyjack_portal::start_portal`).  
**Fix →** Make portal strictly out-of-process (service-managed), daemon only starts/stops via systemd/dbus wrapper or a tightly scoped helper.  
**Fixed version looks like →** `PortalStart` job triggers a minimal privileged action (iptables + interface prep) then signals an unprivileged portal service to run; HTTP server never runs in the daemon.

### 2
**Problem →** Update cancellation does not stop blocking work already running in `spawn_blocking`.  
**Why →** Dropping/aborting the async future does not terminate the blocking thread; it may continue installing files or restarting units.  
**Where →** `crates/rustyjack-daemon/src/jobs/kinds/update.rs` calls `rustyjack_updater::apply_update`, which uses `tokio::task::spawn_blocking(...)` for extraction/verification/install in `crates/rustyjack-updater/src/lib.rs`.  
**Fix →** Add cooperative cancellation inside updater’s blocking sections (periodic cancel checks), or run updates in a dedicated subprocess that can be terminated safely.  
**Fixed version looks like →** `apply_update(policy, url, cancel_token)` and each blocking stage checks cancel and performs rollback; or update worker subprocess is killed and staging cleaned.

### 3
**Problem →** Mount cancellation can return `Cancelled` after a successful mount, leaving mounts behind.  
**Why →** Cancel check happens after `policy_mount_device(...)`; a cancel arriving during mount can’t interrupt it, and a cancel after mount returns `Cancelled` without rollback.  
**Where →** `crates/rustyjack-core/src/services/mount.rs` (`mount(...)` checks cancel after mount).  
**Fix →** If mount succeeded and cancel is set, explicitly unmount the created mountpoint before returning cancellation.  
**Fixed version looks like →** A mount operation that is either (a) fully applied and reported as mounted, or (b) rolled back and reported as cancelled.

### 4
**Problem →** Socket access is gated primarily by group membership (`rustyjack`), which is coarse.  
**Why →** Any process in the group can connect; mistakes in system user/group assignment become a security boundary failure.  
**Where →** `rustyjackd.socket` (`SocketMode=0660`, `SocketGroup=rustyjack`) + `services/rustyjack-ui.service` (`SupplementaryGroups=rustyjack ...`).  
**Fix →** Tighten group membership policies; consider separate groups for UI vs operator tools, or per-service UDS proxies with narrower privilege.  
**Fixed version looks like →** Distinct socket(s): one for UI (mutating), one read-only; or a broker that enforces per-client policy by UID.

### 5
**Problem →** UI process has read-write access to `/var/lib/rustyjack`, including persisted ops overrides.  
**Why →** If UI is compromised, attacker can modify state/config used for enforcement (e.g., `ops_override.json`).  
**Where →** `services/rustyjack-ui.service` (`ReadWritePaths=/var/lib/rustyjack`), daemon loads `ops_override.json` (`crates/rustyjack-daemon/src/config.rs`).  
**Fix →** Move ops overrides to a more restricted config dir with explicit ownership; UI should request ops changes via daemon, not write files directly.  
**Fixed version looks like →** UI has RW only to UI-owned subdir; daemon persists ops overrides to root-owned config directory.

### 6
**Problem →** Job attribution is weak: `requested_by` is often `"unknown"`.  
**Why →** Client sets `requested_by: None`; daemon doesn’t populate from `PeerCred`. This weakens auditability and incident response.  
**Where →** `crates/rustyjack-client/src/client.rs` (sets `requested_by: None`), `crates/rustyjack-daemon/src/jobs/mod.rs` (logs `requested_by`).  
**Fix →** Populate requested_by server-side from peer UID/PID and optionally client_name from handshake.  
**Fixed version looks like →** Jobs store `requested_by_uid`, `requested_by_pid`, and `client_name`; logs reliably attribute actions.

### 7
**Problem →** Any authorized client can cancel any job.  
**Why →** No ownership or capability check on cancellation; enables cross-client disruption.  
**Where →** `crates/rustyjack-daemon/src/jobs/mod.rs` (`cancel_job` checks only job existence), `crates/rustyjack-daemon/src/dispatch.rs` handles `JobCancel`.  
**Fix →** Track job owner identity and enforce cancel policy (same UID, same tier, or Admin-only for foreign cancels).  
**Fixed version looks like →** Cancel checks `peer.uid == job.owner_uid || peer.tier==Admin`.

### 8
**Problem →** Embedded portal mode appears to be the default even though an unprivileged portal service exists.  
**Why →** Confusing dual-architecture; may lead to deployments accidentally running portal privileged.  
**Where →** `crates/rustyjack-daemon/src/jobs/kinds/portal_start.rs` warns external not supported and uses embedded. Also `services/rustyjack-portal.service` exists.  
**Fix →** Make external portal the supported default and remove/feature-gate embedded mode.  
**Fixed version looks like →** `PortalStart` job triggers systemd-managed unprivileged portal and fails closed if not available.

### 9
**Problem →** Per-connection rate limiting only; no per-UID or global controls.  
**Why →** Many connections (up to `max_connections`) can multiply load; a single UID could open many sockets.  
**Where →** `crates/rustyjack-daemon/src/server.rs` per-connection token logic; `DaemonConfig.max_connections`.  
**Fix →** Add per-UID budgeting and global request shaping.  
**Fixed version looks like →** Token buckets keyed by UID and a global concurrency limiter per endpoint class.

### 10
**Problem →** Protocol violations disconnect after 3 events, but violations include potentially ambiguous categories.  
**Why →** Some parse errors might be benign client bugs; immediate lockout could affect recoverability.  
**Where →** `crates/rustyjack-daemon/src/server.rs` (`MAX_PROTOCOL_VIOLATIONS=3`).  
**Fix →** Differentiate framing errors (hard) vs semantic errors (soft); keep the safety behavior but improve observability and metrics.  
**Fixed version looks like →** Separate counters: framing_violation, parse_violation, validation_error; structured telemetry.

### 11
**Problem →** `spawn_blocking`-based jobs can outlive shutdown timeout, leaving side effects mid-flight.  
**Why →** Graceful shutdown cancels jobs, but blocking tasks may continue.  
**Where →** `crates/rustyjack-daemon/src/main.rs` shutdown calls `shutdown_gracefully(25s)`; many job kinds use `spawn_blocking`.  
**Fix →** Move heavy privileged operations into dedicated subprocesses with explicit lifecycle management and kill semantics, or implement stronger cooperative cancel in blocking routines.  
**Fixed version looks like →** A “job runner” supervisor that can terminate OS processes and perform rollback.

### 12
**Problem →** Mount/unmount and some network operations rely on post-action cancel checks.  
**Why →** Cancel arriving after side-effect may cause confusing user experience (reports cancelled but state changed).  
**Where →** `crates/rustyjack-core/src/services/mount.rs`; similar patterns in other services.  
**Fix →** Define cancellation contract: once side-effect crosses a “commit point,” report completion (or rollback).  
**Fixed version looks like →** Explicit phases: prepare → commit → finalize; cancellation only valid before commit unless rollback exists.

### 13
**Problem →** UI-only operations gate is based on UID lookup of a username in `/etc/passwd`.  
**Why →** Identity is correct at OS level, but if that account is misused or shared, “UI-only” becomes meaningless.  
**Where →** `crates/rustyjack-daemon/src/auth.rs` (`is_ui_peer`, `uid_for_user`).  
**Fix →** Combine UID check with additional constraints (service-only via systemd `SO_PEERGROUPS` style group, or check executable path via `/proc/<pid>/exe` allowlist).  
**Fixed version looks like →** UI-only requires UID + membership in a dedicated group + binary allowlist hash/path.

### 14
**Problem →** Daemon runs as root with a broad capability set including `CAP_SYS_ADMIN`.  
**Why →** `CAP_SYS_ADMIN` is extremely powerful; increases blast radius.  
**Where →** `services/rustyjackd.service` (`CapabilityBoundingSet=... CAP_SYS_ADMIN ...`).  
**Fix →** Split capabilities across helper services or narrow further (mount helper, net helper).  
**Fixed version looks like →** Daemon mostly unprivileged; privileged helpers hold only needed caps.

### 15
**Problem →** Portal service unit appears unprivileged but portal code can install DNAT rules when `dnat_mode` is true.  
**Why →** If portal truly needs iptables modifications, it either fails unprivileged or pressures giving it dangerous capabilities.  
**Where →** `crates/rustyjack-core/src/services/portal.rs` constructs config with `dnat_mode: true`; portal code in `crates/rustyjack-portal/src/state.rs` installs DNAT.  
**Fix →** Ensure iptables/DNAT changes are done by daemon (privileged) and portal remains pure HTTP/static logging.  
**Fixed version looks like →** Portal service never touches iptables; daemon preconfigures routing.

### 16
**Problem →** Ops delta cleanup exists, but “deny-by-default” posture depends on correct ops config and enforcement points.  
**Why →** Great safety mechanism (`apply_ops_delta`), but must be uniformly applied and validated.  
**Where →** `crates/rustyjack-daemon/src/ops_apply.rs`, enforcement in `server.rs` via `required_ops_for_request`.  
**Fix →** Centralize ops + tier checks in one gate function; add tests ensuring every mutating endpoint declares RequiredOps.  
**Fixed version looks like →** Compile-time mapping coverage tests; missing RequiredOps fails CI.

### 17
**Problem →** Error responses may leak internal “source” strings.  
**Why →** Useful for debugging, but can reveal internal topology to untrusted local users in `rustyjack` group.  
**Where →** Many `.with_source("daemon.jobs...")` and dispatch error wrappers (`dispatch.rs`).  
**Fix →** Restrict detailed sources to admin tier or debug builds; keep a correlation ID for troubleshooting.  
**Fixed version looks like →** Public error: code + message; admin/debug includes `source`, `detail`.

### 18
**Problem →** Jobs are in-memory only; restart loses job history and status.  
**Why →** Makes long operations opaque after restart; increases confusion and may cause duplicated actions.  
**Where →** `crates/rustyjack-daemon/src/jobs/mod.rs` stores jobs in a `HashMap` only.  
**Fix →** Persist minimal job ledger (id, kind hash, start time, last progress, final state) to state dir.  
**Fixed version looks like →** After restart, `JobStatus` can show “unknown / lost after restart” and optionally attempt reconciliation.

---

## 7) Test plan (fuzz IPC, payload size limits, cancel mid-flight, daemon restart)

### IPC robustness

- Fuzz framed input at `read_frame` boundary:
  - length prefix edge cases: 0, max_frame+1, extremely large
  - truncated payload
  - random JSON
- Validate daemon behavior:
  - returns `BadRequest` for parse errors
  - increments protocol violations
  - disconnects after 3 violations
- Verify payload size enforcement:
  - send payload exactly `max_frame`
  - send payload `max_frame + 1` → must fail predictably

### Authorization & socket boundary

- Ensure `SocketMode=0660` is effective:
  - non-group user cannot connect
  - group user can connect but tier restrictions apply
- Validate tier mapping coverage:
  - operator cannot run admin-only job kinds (e.g., `ScanRun`, `CoreCommand`)
- Validate ops gating:
  - set `ops.offensive_ops=false`, attempt offensive endpoints/jobs → denied

### Job lifecycle tests

- Cancel each job kind mid-flight and validate:
  - consistent final state (`Cancelled` vs `Failed`)
  - cleanup side effects where promised:
    - `WifiConnect` cancel should disconnect
    - `HotspotStart` cancel should stop hotspot
    - `PortalStart` cancel should stop portal
- Cancellation timing tests:
  - cancel before “commit point” vs after “commit point” for mount/update-like operations
  - ensure reports match actual system state

### Restart / crash consistency

- Start a long job (sleep, update staging, scan placeholder) and restart daemon:
  - confirm daemon boot calls `reconcile_on_startup`
  - confirm job list is empty or shows persisted “lost jobs” if implemented later
  - confirm system state is sane (no stuck portal, hotspot, mounts, iptables rules)

---

## 8) Priority + recommended refactors

### Priority (highest first)

1. **De-privilege the portal**: make portal strictly unprivileged and out-of-process.
2. **Fix cancellation semantics for blocking work** (especially updater): cooperative cancel + rollback or subprocess-based execution.
3. **Centralize authorization gate**:
   - single function that enforces tier + ops + UI-only + endpoint mutability
   - ensure every endpoint is covered and tested
4. **Strengthen auditability**:
   - server-side job attribution from peer creds and handshake client_name
5. **Add per-UID rate limiting + quotas**:
   - prevent multi-connection amplification attacks

### Recommended refactors

- **Centralized Auth Gate**:  
  Create `authorize_request(peer, request, state) -> Result<(), DaemonError>` in `crates/rustyjack-daemon` used before dispatch.
- **Move long-running privileged operations into “job runner” subprocess**:
  - daemon orchestrates
  - OS process lifecycle (kill/timeout) is controllable
  - logs + cleanup are explicit
- **Define “commit point” policy for each job kind**:
  - cancellation behavior documented and tested
  - rollback required where feasible
- **Split socket / interfaces by privilege**:
  - separate read-only socket or per-service proxy
  - reduce reliance on shared `rustyjack` group membership

---

### Appendix: concrete references (selected)

- Socket unit: `rustyjackd.socket`
- Daemon unit: `services/rustyjackd.service`
- UI unit: `services/rustyjack-ui.service`
- Portal unit: `services/rustyjack-portal.service`
- IPC framing: `crates/rustyjack-ipc/src/wire.rs`
- IPC types: `crates/rustyjack-ipc/src/types.rs`, `crates/rustyjack-ipc/src/job.rs`
- Server: `crates/rustyjack-daemon/src/server.rs`
- AuthZ: `crates/rustyjack-daemon/src/auth.rs`
- Dispatch: `crates/rustyjack-daemon/src/dispatch.rs`
- Jobs: `crates/rustyjack-daemon/src/jobs/mod.rs`
- Job kinds: `crates/rustyjack-daemon/src/jobs/kinds/*.rs`
- Startup reconcile: `crates/rustyjack-daemon/src/state.rs`
- Updater: `crates/rustyjack-updater/src/lib.rs`
- Portal service (core): `crates/rustyjack-core/src/services/portal.rs`
- Portal implementation: `crates/rustyjack-portal/src/state.rs`
