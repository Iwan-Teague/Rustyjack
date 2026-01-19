# Rustyjack / Watchdog — Systems + Networking Hardening Report (2026-01-17)
Created: 2026-01-17

This report is written for Rust developers working close to the OS (processes, filesystems, sockets, netlink) and assumes the constraints:

- **Rust-only fixes** (i.e., implement behavior in Rust code).
- **No third‑party binaries** for fixes (no shelling out to `bash`, `tar`, `systemctl`, etc. as part of *the fix*).
- Keep the current architecture (daemon + IPC + core services), but harden boundaries.

> Practical note: the codebase currently contains places that shell out to system binaries. This report prioritizes replacing the most security-sensitive / brittle uses with Rust-native implementations or safely *gating* them behind explicit build/runtime switches.

---

## 0) Does the deep-dive document reflect the project?

**Mostly, yes — directionally.** The deep-dive matches the broad architecture (daemon, IPC framing, job runner, “dangerous ops” gating, export bundles, etc.).

**What it misses / understates (important):**

1. **Path-traversal exposure in LogTailGet** (daemon endpoint allows arbitrary file reads via `component` string; details below).
2. **Potential unbounded memory use in LogTailGet** (reads entire log into RAM then truncates).
3. **The *scale* of external command usage** (multiple crates shell out; some are legitimate ops, others are “sharp tools” that should be gated/removed for production safety). Even if CI prevents *new* `Command::new`, the current surface is still large.

**Net-net:** your document is a good “map”, but it needs a couple of red flags added so reviewers don’t miss the easiest-to-exploit boundary bugs.

---

## 1) High-priority findings (fix these first)

### 1.1 LogTailGet: path traversal + arbitrary file read

**What’s the problem?**

`LogTailGet` takes a user-controlled `component: String` and constructs:

- `root/logs/{component}.log`

If `component` contains path separators and `..`, you can request something like `../../etc/shadow` and the daemon will attempt to open:

- `root/logs/../../etc/shadow.log`  (which resolves outside `root`)

Even if the `.log` suffix reduces impact, it is still **path traversal** into arbitrary locations with `.log` suffixes (and can hit real files like `/var/log/auth.log`, `/etc/something.log`, etc.).

**Where is it happening?**

- `rustyjack-daemon/src/dispatch.rs` in the `RequestBody::LogTailGet(...)` arm.

**How to fix it (Rust-only, no binaries):**

Fix it at the type level *and* at the runtime level:

1) **Change IPC type** from free-form string to a controlled enum.

In `rustyjack-ipc/src/types.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogComponent {
    Rustyjackd,
    RustyjackUi,
    Portal,
    Usb,
    Wifi,
    Net,
    Crypto,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogTailRequest {
    pub component: LogComponent,
    pub max_lines: Option<usize>,
}
```

2) **Map enum → path via `match`** (no string formatting with user input):

```rust
fn log_path_for(root: &Path, c: LogComponent) -> PathBuf {
    match c {
        LogComponent::Rustyjackd => root.join("logs").join("rustyjackd.log"),
        LogComponent::RustyjackUi => root.join("logs").join("rustyjack-ui.log"),
        LogComponent::Portal => root.join("logs").join("portal.log"),
        LogComponent::Usb => root.join("logs").join("usb.log"),
        LogComponent::Wifi => root.join("logs").join("wifi.log"),
        LogComponent::Net => root.join("logs").join("net.log"),
        LogComponent::Crypto => root.join("logs").join("crypto.log"),
        LogComponent::Audit => root.join("logs").join("audit").join("audit.log"),
    }
}
```

3) **Add a defense-in-depth validator** if you must keep string compatibility for older clients (temporary):

- Reject any `component` containing `/` `\\` `..` `:` NUL, control chars.
- Prefer strict allowlist.

**What fixed looks like:**

- Requesting `component="../../var/log/auth"` returns `BadRequest`.
- Only known log components are accessible.
- The code no longer joins untrusted strings into filesystem paths.


#### Battle-tested approaches and how to translate them into Rust

This bug class ("user controls a path") has been exploited so many times that the Linux ecosystem has evolved **kernel-level and daemon-level patterns** to make it hard to get wrong.

**How battle-tested projects handle it**

1) **Prefer kernel-enforced safe path resolution (`openat2`)**

- Linux provides `openat2()` with resolution flags like:
  - `RESOLVE_BENEATH` (prevent `..` escapes outside a directory tree)
  - `RESOLVE_NO_SYMLINKS` / `RESOLVE_NO_MAGICLINKS` (block symlink and `/proc` magic-link traversal)
- This is strictly stronger than `O_NOFOLLOW`, which only affects the *final* path component. See `openat2(2)` for the distinction.  
  References: [BT-OPENAT2], [BT-OPENAT2-LWN]

**Rust translation (no external binaries):**

- Open the logs root directory once and keep it as an **fd capability**.
- Try `openat2(dirfd, relative_path, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`.
- If the kernel does not support it (`ENOSYS`), fall back to a userspace traversal strategy (below).

> Note: glibc historically lacked a stable `openat2()` wrapper, so real-world code often calls it via `syscall(2)`. `openat2(2)` explicitly documents this.  
> Reference: [BT-OPENAT2]

2) **Fallback for older kernels: `openat()` component-walk ("chase" style)**

When `openat2()` isn't available, hardened daemons avoid constructing a full path string and instead **walk each path component using directory fds**.

This pattern is prominent in systemd hardening work after real-world symlink exploits in tmpfiles: a key idea is to resolve from the root one component at a time and never follow a **non-terminal** symlink.  
References: [BT-SYSTEMD-OSS], [BT-SYMLINK-CVE]

**Rust translation (no external binaries):**

- Split a relative path into components.
- Reject `..` and empty components.
- For intermediate components, use `openat(parent_fd, component, O_PATH|O_NOFOLLOW|O_CLOEXEC)` (or `O_RDONLY|O_NOFOLLOW` if you avoid `O_PATH`).
- For the final component, open with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`.

3) **Keep the enum allowlist anyway**

Even with `openat2()`, your enum-based allowlist is valuable because it:
- shrinks the attack surface (only known logs exist), and
- makes review trivial (no hidden string transformations).

**What "battle-tested fixed" looks like**

- **Policy:** only a small set of known log components are exposed.
- **Mechanism:** even if someone later adds a string-based log path API, the filesystem open is still contained under the logs dir (kernel-enforced when available).


---

### 1.2 LogTailGet: unbounded memory usage (OOM risk)

**What’s the problem?**

The daemon currently reads **all** lines of the file into a `Vec<String>` and only then truncates. On a device with long-running logs, this can blow RAM.

**Where is it happening?**

- Same area: `rustyjack-daemon/src/dispatch.rs` `LogTailGet` branch.

**How to fix it (Rust-only):**

Use a fixed-capacity ring buffer (`VecDeque`) while reading:

```rust
use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader};

fn tail_lines(path: &Path, max_lines: usize) -> io::Result<(Vec<String>, bool)> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut buf: VecDeque<String> = VecDeque::with_capacity(max_lines + 1);
    let mut truncated = false;

    for line in reader.lines() {
        let line = line?;
        if buf.len() == max_lines {
            buf.pop_front();
            truncated = true;
        }
        buf.push_back(line);
    }

    Ok((buf.into_iter().collect(), truncated))
}
```

Also add a **hard cap** on `max_lines` from IPC (e.g., 5_000) so callers can’t request “a million lines”.

**What fixed looks like:**

- Log tail memory stays O(max_lines), not O(file_size).
- A 2GB log file does not allocate 2GB of RAM.


#### Battle-tested approaches and how to translate them into Rust

**How battle-tested projects handle it**

GNU coreutils `tail` has been tuned for decades. The key idea is: **don’t read the whole file** unless you have to.

- If the file is **seekable**, `tail` seeks to end-of-file and scans **backwards** until enough newlines are found.
- If it is **not seekable** (pipes, some special files), it uses a bounded in-memory strategy.

References: [BT-TAIL-SRC], [BT-TAIL-MANUAL], [BT-TAIL-EXPLAIN]

**Rust translation (two-tier strategy):**

1) If seekable: implement a backwards reader
- `pos = file.seek(SeekFrom::End(0))?`
- repeatedly move backward by a fixed block size (e.g., 64 KiB)
- read into a buffer, count `\n`
- once N lines found, slice the buffer and decode only the needed portion

This gives good behavior on multi-GB logs while keeping memory bounded.

2) If not seekable: fall back to your `VecDeque` ring-buffer approach
- This is effectively the same “bounded memory” strategy coreutils uses for non-seekable inputs.

**What "battle-tested fixed" looks like**

- 2GB file tail returns quickly and uses bounded memory and bounded IO.
- Non-seekable input still works correctly and safely with bounded RAM.


---

### 1.3 Audit log: world-readable risk + panic on clock skew

**What’s the problem?**

1) Audit log creation doesn’t set explicit permissions. Depending on umask, audit logs may become world-readable.
2) `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()` can panic if the clock is mis-set (not rare on embedded systems without RTC + NTP delay).

**Where is it happening?**

- `rustyjack-core/src/audit.rs`.

**How to fix it (Rust-only):**

1) Use `OpenOptionsExt::mode` on Unix when creating the file, and ensure the directory permissions are restrictive.
2) Replace `unwrap()` with `unwrap_or_default()` (as done elsewhere in the daemon).

Example:

```rust
let ts = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis() as u64;

#[cfg(unix)]
{
    use std::os::unix::fs::OpenOptionsExt;
    // create_dir_all doesn’t set mode; explicitly chmod after create if needed.
    let mut opts = OpenOptions::new();
    opts.create(true).append(true).mode(0o640);
    let mut file = opts.open(&audit_file)?;
    // ...
}
```

**What fixed looks like:**

- Audit logs are not accidentally readable by everyone.
- Device boot with wrong clock does not crash the daemon.

---

### 1.4 Authorization: fail-open on group lookup failure

**What’s the problem?**

Authorization is computed from supplementary groups by reading `/proc/<pid>/status` and resolving GIDs via `/etc/group`. If that lookup fails, the daemon currently **falls back to `Operator`** for non-root peers. That is a classic **fail-open**: any local user who can trigger a read failure (or simply races the process exit / PID reuse window) can gain operator-level access.

**Where is it happening?**

- `rustyjack-daemon/src/auth.rs` in `authorization_for_peer(..)` (the `Err(..) => AuthorizationTier::Operator` branch).

**How to fix it (Rust-only):**

1) **Fail closed**: change the fallback tier to `ReadOnly`, not `Operator`.
2) **Mitigate PID reuse**: when reading `/proc/<pid>/status`, also parse the `Uid:` line and verify it matches `peer.uid` from `SO_PEERCRED`. If it doesn’t match, treat it as failure and return `ReadOnly`.
3) **Stop re-parsing `/etc/group` per GID**: parse it once into a `HashMap<u32, String>` and resolve in-memory.

Sketch for (2) and (3):

```rust
fn read_supplementary_groups(peer: &PeerCred) -> io::Result<Vec<String>> {
    let status_path = format!("/proc/{}/status", peer.pid);
    let content = fs::read_to_string(&status_path)?;

    // Verify Uid matches SO_PEERCRED
    if let Some(uid_line) = content.lines().find(|l| l.starts_with("Uid:")) {
        let mut it = uid_line.split_whitespace();
        let _label = it.next();
        let real_uid: u32 = it.next().unwrap_or("0").parse().unwrap_or(0);
        if real_uid != peer.uid {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "pid uid mismatch"));
        }
    }

    let gids = /* parse Groups: line as today */;
    let map = parse_group_file()?;
    Ok(gids
        .into_iter()
        .filter_map(|gid| map.get(&gid).cloned())
        .collect())
}

fn parse_group_file() -> io::Result<std::collections::HashMap<u32, String>> {
    let mut out = std::collections::HashMap::new();
    for line in fs::read_to_string("/etc/group")?.lines() {
        let mut parts = line.split(':');
        let name = parts.next().unwrap_or("");
        let _pw = parts.next();
        let gid = parts.next().unwrap_or("").parse::<u32>().ok();
        if let Some(gid) = gid {
            out.insert(gid, name.to_string());
        }
    }
    Ok(out)
}
```

Then in `authorization_for_peer`, change the error case to `AuthorizationTier::ReadOnly`.

**What fixed looks like:**

- If `/proc/<pid>/status` can’t be read (or UID mismatches), caller is **ReadOnly**.
- Only users explicitly in `admin_group`/`operator_group` gain those tiers.
- Group resolution becomes cheaper and less racey.


#### Battle-tested approaches and how to translate them into Rust

This is a classic case of "don’t scrape /proc for identity if the kernel can tell you directly".

**How battle-tested projects handle it**

1) **Use kernel-provided peer credentials on AF_UNIX sockets**

- `SO_PEERCRED` returns the peer PID/UID/GID for a connected UNIX socket (read-only, kernel-provided).  
  Reference: [BT-SO_PEERCRED]

2) **Prefer `SO_PEERGROUPS` for supplementary groups (Linux)**

- Linux added `SO_PEERGROUPS` to retrieve the peer’s supplementary groups via `getsockopt(SOL_SOCKET, SO_PEERGROUPS, ...)`.
- It is explicitly designed to extend `SO_PEERCRED`, and uses an `ERANGE`/resize/retry pattern similar to `SO_PEERSEC`.  
  References: [BT-SO_PEERGROUPS]

3) **Fail closed when identity info is unavailable**

Even robust stacks treat “can’t determine identity” as **deny / lowest privilege**, not “operator”.

**Rust translation (no external binaries):**

- Keep using `SO_PEERCRED` as the primary identity.
- Attempt `SO_PEERGROUPS` when available (feature-detect by trying it; if it fails with `ENOPROTOOPT`, fall back).
- If falling back to `/proc/<pid>/status`, treat *any* failure or inconsistency as ReadOnly (fail-closed).

**What "battle-tested fixed" looks like**

- Group resolution failure never grants privilege.
- PID-reuse races are greatly reduced because the primary identity source is the connected socket creds.
- `/proc` parsing becomes a compatibility fallback rather than a core security primitive.


---

### 1.5 Job cancellation: aborting `spawn_blocking` does not stop the work

**What’s the problem?**

Many job kinds start long-running synchronous core functions via `tokio::task::spawn_blocking` and, on cancellation, call `handle.abort()`. Aborting a `JoinHandle` **does not terminate the underlying blocking thread’s work**. Result: a cancelled job can keep running, continue touching the network/device, and hold resources longer than expected.

**Where is it happening?**

- Multiple job kinds under `rustyjack-daemon/src/jobs/kinds/*` (e.g., `wifi_scan`, `wifi_connect`, `mount_start`, `scan`, `update`, etc.).

**How to fix it (Rust-only):**

1) Define a small cancellation interface in `rustyjack-core` that synchronous services can check frequently:

```rust
pub trait CancelFlag: Send + Sync {
    fn cancelled(&self) -> bool;
}

pub struct AtomicCancel(std::sync::atomic::AtomicBool);
impl CancelFlag for AtomicCancel {
    fn cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}
```

2) Update long-running core services to accept `&dyn CancelFlag` and periodically check `cancelled()` inside their loops. When set, return a typed error (mapped to `ErrorCode::Cancelled`).

3) In the daemon job wrapper, bridge `CancellationToken` into an `Arc<AtomicBool>` shared with the blocking task:

```rust
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};

let cancel_flag = Arc::new(AtomicBool::new(false));
let cancel_flag2 = cancel_flag.clone();
let handle = tokio::task::spawn_blocking(move || {
    rustyjack_core::services::wifi::scan(request, &cancel_flag2, callback)
});

tokio::select! {
  _ = cancel.cancelled() => {
      cancel_flag.store(true, Ordering::Relaxed);
      return cancelled_err();
  }
  res = handle => { /* normal completion */ }
}
```

4) Keep `abort()` only as a last resort (e.g., if the blocking code is hung and does not poll the cancel flag), but the goal is cooperative exit.

**What fixed looks like:**

- Cancelled jobs stop doing work quickly (bounded by poll frequency).
- Locks/resources are released promptly.
- No “ghost operations” after cancel ack.


#### Battle-tested approaches and how to translate them into Rust

**How battle-tested projects handle it**

Tokio’s own docs are blunt: **`spawn_blocking` tasks cannot be aborted once they’ve started running** — calling `abort()` on the `JoinHandle` won’t stop the underlying blocking work. Tokio also notes that runtime shutdown can wait indefinitely for started blocking tasks unless you use `shutdown_timeout`, and even then the blocking tasks are not actually cancelled.  
Reference: [BT-TOKIO-SPAWN_BLOCKING]

Because of that, production systems use one (or more) of these strategies:

1) **Cooperative cancellation (the default for threads)**
- A shared flag (atomic or cancellation token) that long-running code checks frequently.
- “Checkpoints” at all expensive operations (network IO loops, retry loops, long scans).

2) **Time-boxing + fail-safe unwind**
- Strict timeouts around operations.
- Ensure every loop has an upper bound (attempt count, elapsed time, bytes processed).

3) **Hard cancellation via process boundaries (only if you truly need it)**
- If an operation must be forcibly stopped (e.g., a library call that can hang forever), hardened systems often run it in a separate **process** so it can be killed. This is heavier, but it’s the only truly reliable “stop now” primitive on Unix.
- You can still satisfy “Rust-only” by implementing a worker subcommand in the same Rust binary and spawning it as a child process of **your own executable**. If you keep a strict “no new `Command::new`” policy, do this with `fork`+`execve` via `libc` (or explicitly allowlist self-exec in CI).

**Rust translation (recommended, minimal change):**

- Keep the cooperative cancel flag you already defined, but make it *structural*:
  - accept it as an argument in every long-running core service API
  - check it at consistent granularity (e.g., every iteration, every N packets, every 100ms)
  - plumb it into retry loops so cancellation doesn’t wait for the next retry delay

- Add an explicit, testable contract:
  - `Cancelled` must be returned within **T milliseconds** after the flag flips (pick a target, e.g., 250ms for UX-facing tasks, 1s for heavier scans)

- For operations that call into blocking syscalls with no timeout, prefer timeout-capable syscalls or patterns:
  - sockets: set timeouts or use non-blocking + `poll`/`select` wrappers
  - file IO: break into bounded chunks and check cancellation between chunks

**What “battle-tested fixed” looks like**

- Cancelling a job stops work promptly and predictably.
- Runtime shutdown does not hang indefinitely on blocking jobs.
- Cancellation semantics are unit-testable (no “it usually stops eventually” behavior).


---

### 1.6 Unbounded progress channels: potential memory growth under noisy producers

**What’s the problem?**

Most job kinds use `mpsc::unbounded_channel` to shuttle progress updates from blocking code to async. If the producer emits faster than the consumer can forward, the queue can grow without bound.

**Where is it happening?**

- `rustyjack-daemon/src/jobs/kinds/*` (multiple files use `mpsc::unbounded_channel`).

**How to fix it (Rust-only):**

Replace with a bounded channel and drop/coalesce updates:

```rust
let (tx, mut rx) = mpsc::channel::<(u8, String)>(64);

// In blocking callback:
let _ = tx.try_send((percent, message.to_string()));
// If full, drop the update (or keep only the latest in an Atomic/Mutex).
```

For better UX, implement *coalescing*: store the latest `(percent, message)` in an `Arc<Mutex<...>>` and have the async side poll it at a fixed rate (e.g., 10 Hz).

**What fixed looks like:**

- Progress memory is bounded.
- UI stays responsive even if a service spams progress.


#### Battle-tested approaches and how to translate them into Rust

**How battle-tested projects handle it**

Tokio’s docs for `unbounded_channel` include the important warning: if the receiver falls behind, messages are buffered without backpressure, and memory is the only bound — which can lead to the process being aborted by OOM.  
Reference: [BT-TOKIO-UNBOUNDED]

To avoid that, production systems typically choose one of these patterns:

1) **Backpressure (bounded queue)**
- `mpsc::channel(N)` with a chosen burst limit.
- Decide what happens when full: block, drop, or coalesce.

2) **Latest-value-wins (watch channels)**
- For progress/state, you usually don’t need every update.
- `tokio::sync::watch` retains only the latest value.  
  Reference: [BT-TOKIO-WATCH]

**Rust translation (recommended):**

- Replace progress reporting with `watch` for percent + message.
- Keep `mpsc::channel(N)` for event streams where order and completeness matter.

**What "battle-tested fixed" looks like**

- Progress cannot DOS the daemon via memory growth.
- Consumers always see the latest state, even if intermediate updates are dropped.


---

## 2) Additional hardening improvements (still strongly recommended)

### 2.1 UDS daemon: bound concurrent connections and per-connection request rate

**What’s the problem?**

The daemon spawns a task per accepted connection. On a multi-user system, a local attacker can open many UDS connections and create many tasks, increasing CPU/memory pressure.

**Where is it happening?**

- `rustyjack-daemon/src/server.rs` (`listener.accept()` then `tokio::spawn`).

**How to fix it:**

Add a `tokio::sync::Semaphore` to limit concurrent connections, and drop connections when saturated.

```rust
use tokio::sync::Semaphore;

let conn_limit = Arc::new(Semaphore::new(64)); // tune for device

loop {
  let (stream, _) = listener.accept().await?;
  let permit = match conn_limit.clone().try_acquire_owned() {
      Ok(p) => p,
      Err(_) => { /* optionally write a short error frame */ continue; }
  };
  tokio::spawn(async move {
      let _permit = permit; // held for task lifetime
      handle_connection(stream, state).await;
  });
}
```

Optionally add a simple per-connection token bucket (e.g., max 20 requests/sec) so a single client can’t hog CPU.

**What fixed looks like:**

- Connection floods stop at a stable resource ceiling.
- The daemon remains responsive under abuse.

---

### 2.2 LoggingConfigSet: validate `level`, apply consistently

**What’s the problem?**

The daemon accepts arbitrary `level: String`. If invalid, parts of the system may log inconsistently or silently fail to apply.

**Where is it happening?**

- `rustyjack-daemon/src/dispatch.rs` in `LoggingConfigSet`.

**How to fix it:**

Define a `LogLevel` enum and validate at the boundary:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel { Trace, Debug, Info, Warn, Error }
```

Then update config writing and apply logic to use the enum.

**What fixed looks like:**

- Invalid log levels are rejected with `BadRequest`.
- Consistent logging behavior across daemon/UI/portal.

---

### 2.3 Device mount validation: ensure the path is a real removable block device

**What’s the problem?**

Current validation checks path prefix (`/dev/`) and rejects some patterns (`mmcblk`, `loop`). That’s a good start, but it does not confirm:

- It’s a **block device** (not a regular file).
- It’s **removable**.
- It’s not a symlink trick (rare under `/dev`, but worth hardening).

**Where is it happening?**

- `rustyjack-daemon/src/validation.rs` (`validate_mount_device_hint`).

**How to fix it (Rust-only):**

1) Use `symlink_metadata` and reject symlinks.
2) Use `metadata` + `FileTypeExt` to ensure block device.
3) On Linux, derive major/minor and check `/sys/dev/block/<major>:<minor>/../removable`.

Sketch:

```rust
#[cfg(target_os = "linux")]
fn validate_block_removable(dev: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::FileTypeExt;

    let meta = std::fs::symlink_metadata(dev)
        .map_err(|e| DaemonError::new(ErrorCode::BadRequest, "cannot stat device", false)
            .with_detail(e.to_string()))?;

    if meta.file_type().is_symlink() {
        return Err(DaemonError::new(ErrorCode::BadRequest, "device must not be a symlink", false));
    }
    if !meta.file_type().is_block_device() {
        return Err(DaemonError::new(ErrorCode::BadRequest, "not a block device", false));
    }

    // major/minor from st_rdev
    let rdev = meta.rdev();
    let major = ((rdev >> 8) & 0xfff) as u32;
    let minor = ((rdev & 0xff) | ((rdev >> 12) & 0xfff00)) as u32;

    // Walk sysfs
    let sys = PathBuf::from(format!("/sys/dev/block/{}:{}/removable", major, minor));
    if let Ok(val) = std::fs::read_to_string(&sys) {
        if val.trim() != "1" {
            return Err(DaemonError::new(ErrorCode::BadRequest, "device not removable", false));
        }
    }

    Ok(())
}
```

**What fixed looks like:**

- Requests to mount non-removable system disks fail, even if named oddly.
- Mount requests become robust against device-path edge cases.

---

### 2.4 Export bundles: skip symlinks and hard-cap size

**What’s the problem?**

If export code recursively walks directories and follows symlinks, an attacker who can write into the export tree can create a symlink to a sensitive file (e.g., `/etc/shadow`) and trick the exporter into bundling it.

**Where to look:**

- Any recursive exporter / bundler that visits `root/loot` or similar.

**How to fix it:**

- Use `symlink_metadata` and skip symlinks.
- Enforce a total byte budget for exports.
- Prefer streaming compression rather than collecting entire files in memory.

**What fixed looks like:**

- Symlinks inside export trees are ignored.
- Exports have predictable maximum size.

---

### 2.5 Replace a few high-value external commands with syscalls (no binaries)

This is the biggest “practical hygiene” improvement under your constraint set.

**What’s the problem?**

Some core operations shell out to:

- `systemctl reboot`, `shutdown`, `reboot`, `sync`

This is brittle (missing binaries, PATH issues), slower, and harder to reason about.

**Where is it happening?**

- `rustyjack-core/src/operations.rs` in `handle_system_reboot()` / `handle_system_poweroff()`.

**How to fix it (Rust-only):**

Implement minimal Linux reboot/poweroff using syscalls.

```rust
#[cfg(target_os = "linux")]
fn system_sync() {
    unsafe { libc::sync() };
}

#[cfg(target_os = "linux")]
fn system_reboot() -> std::io::Result<()> {
    system_sync();

    // Linux reboot(2) requires magic constants; libc may not expose all.
    // Use syscall directly.
    const LINUX_REBOOT_MAGIC1: libc::c_int = 0xfee1dead_u32 as i32;
    const LINUX_REBOOT_MAGIC2: libc::c_int = 672274793;
    const LINUX_REBOOT_CMD_RESTART: libc::c_int = 0x01234567;

    let res = unsafe {
        libc::syscall(
            libc::SYS_reboot as libc::c_long,
            LINUX_REBOOT_MAGIC1,
            LINUX_REBOOT_MAGIC2,
            LINUX_REBOOT_CMD_RESTART,
            0,
        )
    };

    if res == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}
```

Poweroff uses `LINUX_REBOOT_CMD_POWER_OFF` (`0x4321fedc`).

**What fixed looks like:**

- Reboot/poweroff works even without systemd.
- No shell-outs, no external binaries, no parsing command outputs.


#### Battle-tested approaches and how to translate them into Rust

**How battle-tested projects handle it**

The “lowest-level truth” on Linux is `reboot(2)`. Higher-level tools (systemd, shutdown wrappers) eventually drive this syscall (or related kernel interfaces). `reboot(2)` documents:

- required capabilities (typically `CAP_SYS_BOOT`)
- the magic constants
- command values like `LINUX_REBOOT_CMD_RESTART` and `LINUX_REBOOT_CMD_POWER_OFF`

Reference: [BT-REBOOT]

**Rust translation (no external binaries):**

- Your syscall-based approach is exactly the right direction.
- Make it more robust by:
  - returning a structured error if `EPERM` (missing capability)
  - calling `sync()` first
  - optionally attempting a graceful shutdown path (flush audit logs, close sockets) before the syscall

**What "battle-tested fixed" looks like**

- Works on minimal images without systemd.
- Error reporting is explicit when the process lacks privileges.


---

### 2.6 CI guardrails: “no unwrap/expect in non-test code” + “no new Command::new”

You already have a CI guard for `Command::new`. Add a second Rust-native guard to reduce panic surface.

**What’s the problem?**

`unwrap()`/`expect()` in long-running daemons is a reliability hazard. (Panic == availability outage.)

**How to fix it:**

Add `ci/no_unwrap.rs` that:

- Walks workspace.
- Scans `*.rs` excluding `target/`, `tests/`, and `#[cfg(test)]` modules.
- Fails CI if it finds `unwrap(` / `expect(`.

This is not perfect (string search), but it is a strong low-effort filter.

**What fixed looks like:**

- New code cannot introduce `unwrap()` in production paths.
- Panics become rare and deliberate.

---

## 3) “Unsafe” code hygiene (systems folks will care)

The repo has a non-trivial amount of `unsafe` (raw sockets, ioctl, netlink, packet parsing). That’s expected.

**Improvements to implement:**

1) Add crate-level:

```rust
#![deny(unsafe_op_in_unsafe_fn)]
```

2) Wrap raw fds in `OwnedFd` / RAII types; avoid `from_raw_fd` unless ownership is crystal clear.
3) Document invariants for each unsafe block (“why this is safe”).
4) Add parser tests for packet decoding boundaries (lengths, malformed packets, etc.).

**What fixed looks like:**

- Unsafe blocks are isolated, documented, and reviewable.
- Fewer FD leaks and fewer “double close” hazards.

---

## 4) Production safety: gate/remove capabilities that can be misused

This repo contains modules whose names suggest stealth/evasion and traffic manipulation. Regardless of intent, these are the parts most likely to:

- Trigger compliance review issues
- Be misused
- Create accidental self-DoS

**Recommendation:**

- Compile these behind `#[cfg(feature = "dangerous_ops")]` **and** require an explicit runtime opt-in (`dangerous_ops_enabled`) to execute.
- Default builds for production should not include those features.

This is less about morality and more about “don’t ship a foot-gun by accident.”

---

## 5) Suggested implementation order (one sprint plan)

1) **Fix LogTailGet** (enum + ring buffer + max_lines cap).
2) **Audit log permissions + no clock-skew panic**.
3) **Connection semaphore + request rate limiting**.
4) **Device mount hardening** (block device + removable check).
5) **Replace reboot/poweroff shell-outs with syscalls**.
6) **CI: no unwrap/expect**.
7) **Unsafe hygiene pass** on netlink/raw socket modules.

---

## Appendix A — Minimal patch checklist per finding

For each change, your “definition of done” should include:

- Unit test(s) for the boundary (validation rejects bad inputs).
- A regression test for the exploit / failure mode.
- A short integration test (client → daemon) for success paths.

Examples:

- `LogTailGet` rejects `component="../../etc/passwd"`.
- `LogTailGet` with a huge log returns quickly and uses bounded memory.
- Audit log file has mode `0640` and directory `0750`.
- Daemon refuses >64 concurrent UDS connections.

## Appendix B — Battle-tested references (for review + implementation)

- **[BT-OPENAT2]** `openat2(2)` (resolution flags, O_NOFOLLOW vs RESOLVE_NO_SYMLINKS, ENOSYS fallback, syscall wrapper note): https://www.man7.org/linux/man-pages/man2/openat2.2.html
- **[BT-OPENAT2-LWN]** Background and rationale for `openat2`/`RESOLVE_BENEATH`: https://lwn.net/Articles/796868/
- **[BT-SYSTEMD-OSS]** systemd tmpfiles symlink-hardening discussion referencing `openat()`-recursive “chase” strategy: https://www.openwall.com/lists/oss-security/2018/12/22/1
- **[BT-SYMLINK-CVE]** CVE context for non-terminal symlink traversal in systemd-tmpfiles (why this matters): https://ubuntu.com/security/CVE-2018-6954
- **[BT-TAIL-SRC]** GNU coreutils `tail.c` source (seekable vs non-seekable logic, backwards scanning): https://github.com/coreutils/coreutils/blob/master/src/tail.c
- **[BT-TAIL-MANUAL]** GNU coreutils manual `tail` invocation (behavior + follow semantics): https://www.gnu.org/software/coreutils/manual/html_node/tail-invocation.html
- **[BT-TAIL-EXPLAIN]** Independent explanation of coreutils `tail` strategy (seek back / scan): https://www.maizure.org/projects/decoded-gnu-coreutils/tail.html
- **[BT-SO_PEERCRED]** `unix(7)` socket option `SO_PEERCRED` (kernel-provided peer creds): https://www.man7.org/linux/man-pages/man7/unix.7.html
- **[BT-SO_PEERGROUPS]** Linux `SO_PEERGROUPS` design/commit message (supplementary groups via getsockopt): https://cgit.freedesktop.org/~ramaling/linux/commit/arch/ia64?id=28b5ba2aa0f55d80adb2624564ed2b170c19519e
- **[BT-TOKIO-SPAWN_BLOCKING]** Tokio docs: `spawn_blocking` tasks cannot be aborted once running: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- **[BT-TOKIO-UNBOUNDED]** Tokio docs: `unbounded_channel` buffers without bound (OOM risk): https://docs.rs/tokio/latest/tokio/sync/mpsc/fn.unbounded_channel.html
- **[BT-TOKIO-WATCH]** Tokio docs: `watch` retains only the last value (good for progress/state): https://docs.rs/tokio/latest/tokio/sync/watch/index.html
- **[BT-REBOOT]** `reboot(2)` syscall (magic constants, cmd values, permissions): https://www.man7.org/linux/man-pages/man2/reboot.2.html

