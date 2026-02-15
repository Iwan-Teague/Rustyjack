# Platform & system integration (Area 1) — Analysis report

**Repo snapshot:** `watchdog_shallow_20260213-173640.zip` (read-only)  
**Area definition source:** `rustyjack_architecture_analysis_plan.md` (Architecture Doc 2)  
**Report date:** 2026-02-13

---

## 1) Executive summary (what’s strong, what’s risky)

### What’s strong
- **Systemd-first mindset is present (in places):** the *prebuilt* installer uses `RuntimeDirectory=`, `StateDirectory=` and `ConfigurationDirectory=` for predictable directory creation, and uses **socket activation** for the daemon (great for boot ordering and resilience).
- **Intentional privilege separation:** separate users exist for the UI (`rustyjack-ui`) and portal (`rustyjack-portal`), while the daemon stays privileged. This creates a clean place to enforce “UI asks, daemon decides”.
- **Hardening effort is real:** units consistently aim for `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectKernel*=` knobs, `RestrictNamespaces=`, and syscall filtering.

### What’s risky
- **Installer drift + outright breakage:** `install_rustyjack.sh` currently references an **undefined `$SERVICE`** under `set -u` (line ~970), meaning the “source build” installer will abort mid-run and leave the machine half-configured.
- **Policy vs implementation mismatch:** trusted docs require “pure Rust / avoid third‑party system binaries”, yet multiple paths still rely on `wpa_supplicant` (service `rustyjack-wpa_supplicant@.service`) and the *prebuilt* installer still installs `dnsmasq`/`isc-dhcp-client`/`hostapd`.
- **DNS ownership is fragile:** the design relies on `/etc/resolv.conf` being a symlink to `/var/lib/rustyjack/resolv.conf`; the installers enforce this (and even `chattr +i`) but the daemon’s startup validation largely checks **contents**, not the **symlink/immutability invariants**. A package update or manual change can silently break networking.
- **Udev hotplug path is heavy:** `scripts/99-rustyjack-wifi.rules` runs `/usr/local/bin/rustyjack-hotplugd …` via `RUN+=…`. Per upstream udev guidance, long-running work should be pulled in via `SYSTEMD_WANTS` (udev man page). The current approach risks event-handling stalls and inconsistent behavior across kernels/distros.
- **Security hardening has foot-guns:** a few directives look like they’re meant to restrict devices and syscalls, but are either inconsistent (different installers generate different daemon units) or likely ineffective/mis-scoped.

---

## 2) Component map (what files/services/scripts do what; include paths)

### Install & provisioning scripts
- `install_rustyjack.sh` — source-build installer; sets Pi boot params, removes conflicting networking stack, creates users/dirs, writes some units, sets DNS ownership. **Currently aborts due to undefined `$SERVICE`.**
- `install_rustyjack_prebuilt.sh` — installs prebuilt artifacts; writes daemon socket+service, UI and portal services; relies on systemd-managed directories; installs more runtime packages (`dnsmasq`, `isc-dhcp-client`, `hostapd`, etc.).
- `install_rustyjack_dev.sh` — similar structure to prebuilt; tuned for iterative/dev workflows.
- `install_rustyjack_usb.sh` — USB-flavored install path; similar scaffolding.

### Systemd units (checked in)
- `rustyjackd.socket` — socket activation for the daemon (`ListenStream=/run/rustyjack/rustyjackd.sock`, `SocketMode=0660`, `SocketGroup=rustyjack`).
- `services/rustyjackd.service` — daemon unit (notify + hardening + IPC socket config).
- `services/rustyjack-ui.service` — Rust UI unit (framebuffer + input access; extensive hardening).
- `services/rustyjack-portal.service` — captive portal service (unprivileged web server).
- `services/rustyjack-wpa_supplicant@.service` — per-interface `wpa_supplicant` runner.

### Integration & helper scripts
- `scripts/99-rustyjack-wifi.rules` — udev rule: on USB Wi‑Fi hotplug, run `/usr/local/bin/rustyjack-hotplugd add|remove %k` via `RUN+=`.
- `scripts/wifi_hotplug.sh` — **compatibility shim** for legacy rule paths; it execs `/usr/local/bin/rustyjack-hotplugd` (current logic). It can still be used if a custom/older udev rule points to it. It may also runs `wifi_driver_installer.sh`; starts UI service.
- `scripts/wifi_driver_installer.sh` — installs Realtek drivers; heavy (dkms/kernel headers/etc.); not obviously bounded by timeouts or “safe to run under udev”.
- `scripts/rj_shellops.sh` — “shell ops” wrappers used by installers; defines helper functions (e.g., `rj_sudo_tee`).
- `scripts/fde_*.sh` — full-disk-encryption helpers; platform-y and dependency-heavy (cryptsetup tooling); not boot-integrated here but affects system integration.
- `scripts/rustyjack_comprehensive_test.sh` — on-device test harness, including “Suite B: Systemd hardening posture”.

### Rust boot-time/setup logic (key entry points)
- `crates/rustyjack-daemon/src/main.rs` — daemon startup; binds/listens on socket; then `reconcile_on_startup()`.
- `crates/rustyjack-daemon/src/state.rs` — `reconcile_on_startup()` (retry loop) and transition to passive enforcement.
- `crates/rustyjack-core/src/system/isolation.rs` — “passive mode” enforcement and verification, including routing + DNS validation.
- `crates/rustyjack-core/src/system/dns.rs` — writes the Rustyjack-managed resolv.conf (atomic rewrite) and validates contents.
- `crates/rustyjack-daemon/src/systemd.rs` — supports socket activation (LISTEN_FDS) and fallback bind; sets socket perms + group.

---

## 3) Constraints/invariants (global + platform-specific, sourced from trusted docs)

> Hard rule note: only **repository-root docs** and **`logs/done/`** are treated as authoritative for constraints/invariants, plus the explicitly referenced Architecture Doc 2.

### Global invariants (authoritative)
- **“Pure Rust” direction:** `CLAUDE.md` states the goal is to avoid third‑party binaries at runtime (and explicitly calls out `dnsmasq`, `hostapd`, `isc-dhcp-client` as “still pulled by installers, but Rust should replace them”).  
- **DNS ownership invariant:** `CLAUDE.md` says **`/etc/resolv.conf` should be a symlink** to **`/var/lib/rustyjack/resolv.conf`** (Rustyjack owns the file).
- **Privileged separation:** `CLAUDE.md` requires UI to run as `rustyjack-ui` (non-root); daemon remains privileged.
- **Engineering workflow constraint:** `AGENTS.md` expects “read docs first; tests from `TESTING.md`; use `scripts/rustyjack_comprehensive_test.sh`.”

### Platform-specific invariants (Pi Zero 2 W)
- **Boot config is at `/boot/firmware/config.txt`** on Bookworm-era Raspberry Pi OS (installer uses this). The installer also enables `i2c_arm=on`, `spi=on`, ensures `dtoverlay=spi0-2cs`, and pins button GPIO pull-ups via a `gpio=...=pu` line.
- **Dedicated appliance assumptions:** installers purge `NetworkManager` and mask `systemd-resolved`, and intend Rustyjack to fully own interface setup and DNS.

### Isolation & interface assumptions (trusted log)
- `logs/done/interface_isolation_overview.md` describes the “USB Wi‑Fi is the control plane; ethernet is the data plane” design intent and the need to avoid cross-interface leakage.

(Exact doc quotes are in Appendix “Key excerpts”.)

---

## 4) Current behavior (what actually happens at boot/install; trace call flow)

### A) install_rustyjack_prebuilt.sh (the most internally consistent path)
**Install-time:**
1. Removes/neutralizes conflicting network stack pieces and claims DNS (functions like `purge_network_manager`, `claim_resolv_conf`).
2. Creates users/groups and uses systemd-native directory management for the daemon:
   - `RuntimeDirectory=rustyjack`
   - `StateDirectory=rustyjack`
   - `ConfigurationDirectory=rustyjack`
3. Writes **socket activation** unit `/etc/systemd/system/rustyjackd.socket` and corresponding service.
4. Writes UI and portal services to `/etc/systemd/system/…`.

**Boot-time:**
1. `rustyjack-ui.service` starts after `network.target`.  
2. UI connects to daemon socket (defaults to `/run/rustyjack/rustyjackd.sock`). If the daemon isn’t running, systemd socket-activates it.
3. `rustyjackd.service` starts:
   - `main.rs` initializes logging and config, then calls `state.reconcile_on_startup().await`.
   - `state.rs::reconcile_on_startup()` retries up to 3 times (with backoff) to `enforce_passive_mode().await`.
   - `rustyjack-core::system::isolation` enforces routing and ensures DNS content is as expected via `DnsManager::verify_dns()`.

### B) install_rustyjack.sh (source-build installer) — *currently broken*
Because the script uses `set -euo pipefail`, referencing **`$SERVICE`** without defining it triggers an immediate abort at ~line 970. That means:
- Parts earlier in the script *may* already have run (user creation, directory creation, daemon unit write, DNS claiming, etc.).
- The system is left **half-installed**: portal/UI units may not be installed; enable/start steps won’t run; and some network services may be disabled.

### C) Hotplug Wi‑Fi path (udev)
1. Kernel detects new USB Wi‑Fi → udev rule `scripts/99-rustyjack-wifi.rules` fires.
2. udev executes `/usr/local/bin/rustyjack-hotplugd add|remove %k` via `RUN+=…`.
3. `rustyjack-hotplugd` may (indirectly) trigger `wifi_driver_installer.sh` (heavy dependency work) and/or start `rustyjack-ui.service` depending on configuration (the legacy `scripts/wifi_hotplug.sh` shim also has this capability).

### D) Socket binding details (daemon fallback)
If socket activation isn’t used, `crates/rustyjack-daemon/src/systemd.rs::bind_socket()` will:
- `create_dir_all(parent)` of the socket path (e.g., `/run/rustyjack`)
- remove an existing socket file
- bind and chmod `0660`
- attempt to chgrp to the configured group (`RUSTYJACKD_SOCKET_GROUP`)

This is good for resilience, but it does **not** enforce directory ownership/mode invariants on `/run/rustyjack`.

---

## 5) Modern approaches (how similar appliances do provisioning + hardening today)

Modern embedded/appliance stacks generally converge on a few patterns:

- **Declarative identity + directories:** use `sysusers.d` for users/groups and unit-level `StateDirectory=`/`RuntimeDirectory=` (or `tmpfiles.d` when you need more control), instead of hand-rolled `useradd`/`mkdir/chown` in shell.  
  References: `sysusers.d(5)`, `tmpfiles.d(5)`, `systemd.exec(5)`.

- **Event handling via systemd, not long udev scripts:** udev rules should set properties like `SYSTEMD_WANTS` to start a unit, rather than running long scripts in udev itself.  
  Reference: `udev(7)` explicitly discourages starting long-running processes from rules.

- **DNS ownership via “provider of resolv.conf” or a local resolver API:** many appliances either
  1) run `systemd-resolved` and integrate via D-Bus / `resolvectl` with a stable mode (symlink to `/run/systemd/resolve/resolv.conf`), or  
  2) fully own `/etc/resolv.conf` but include **boot-time repair + health checks**, and avoid “immutable file” tricks that can surprise package managers.  
  Reference: `systemd-resolved(8)` documents the symlink-detection modes.

- **Immutable base + transactional updates:** A/B rootfs updates (e.g., **Mender**, **RAUC**) or atomic trees (**OSTree / rpm-ostree**) reduce “partial upgrade” failure modes. Many setups pair this with signed artifacts and robust rollback.  
  References: RAUC basics, Mender architecture docs, OSTree/rpm-ostree overview.

- **OS extension layering instead of mutating `/usr/local/bin`:** use mechanisms like `systemd-sysext` (system extensions overlaid onto `/usr`/`/opt`) for appliance-like deployments where the base is immutable and updates are atomic.  
  Reference: systemd “sysext” concept docs (general principle applies even if the linked page is a vendor explainer).

---

## 6) Findings list (10–25 items)

- **Undefined `$SERVICE` in source-build installer** → aborts installation under `set -u`, leaving a half-configured system → **Where it is:** `install_rustyjack.sh` around line 970 (`step "Installing systemd service $SERVICE..."`) → **How to fix:** define `SERVICE=/etc/systemd/system/rustyjack-ui.service` (and similar for any other unit) before use; add a “preflight” section that asserts required vars are set → **What the fixed version looks like:** `SERVICE=/etc/systemd/system/rustyjack-ui.service` immediately before the UI unit heredoc.

- **Conflicting `SystemCallFilter` allow/deny sets in the daemon unit (source-build installer path)** → can kill the daemon with `SIGSYS` when it attempts mount-related syscalls, and it’s hard to reason about because two filters are merged → **Where it is:** `install_rustyjack.sh` daemon unit heredoc (lines ~878-879) includes `SystemCallFilter=@mount` and later `SystemCallFilter=~… @mount …` → **How to fix:** use *one* coherent syscall filter strategy (either allow-list or deny-list) and keep it consistent across installers and checked-in units → **What the fixed version looks like:** a single `SystemCallFilter=~@clock @debug …` line **without** contradicting categories (or a single allow-list line).

- **Installer drift: prebuilt vs source-build create materially different daemon integration** → boot behavior, security posture, and failure modes differ depending on which installer you ran; this makes bugs “Heisenbugs” and breaks reproducibility → **Where it is:** `install_rustyjack_prebuilt.sh` writes socket activation + `StateDirectory=`; `install_rustyjack.sh` masks the socket and writes a different daemon unit → **How to fix:** choose a single canonical unit definition (prefer checked-in units + minimal templating) and make all installers install the same ones → **What the fixed version looks like:** installers copy `services/rustyjackd.service` + `rustyjackd.socket` verbatim (or generate from one template).

- **DNS ownership invariant not fully validated at boot** → `/etc/resolv.conf` can silently stop being the required symlink (or lose immutability), breaking name resolution in ways that look like “random Wi‑Fi flakiness” → **Where it is:** installers enforce symlink + `chattr +i`; runtime verification uses `crates/rustyjack-core/src/system/dns.rs::verify_dns()` via `system/isolation.rs` but focuses on contents → **How to fix:** add a startup check that verifies (a) `/etc/resolv.conf` is a symlink to the configured Rustyjack resolv file, (b) the target exists and is writable by the daemon, and (c) the link is repaired if safe → **What the fixed version looks like:** `verify_dns_ownership()` called from `reconcile_on_startup()` that asserts `read_link("/etc/resolv.conf")==root/resolv.conf`.

- **`chattr +i /etc/resolv.conf` is a sharp edge** → immutability can break package operations, troubleshooting, and recovery; it also creates “surprise” semantics for operators and scripts → **Where it is:** `install_rustyjack.sh` and prebuilt installer `claim_resolv_conf()` use `chattr +i` → **How to fix:** replace immutability with periodic repair + monitoring (or explicit apt hook), and document the ownership model; if immutability is kept, add “undo” paths and warnings → **What the fixed version looks like:** no `chattr`; instead, a boot-time repair + a health check in `scripts/rustyjack_comprehensive_test.sh`.

- **UI unit uses `DeviceAllow=` without an explicit `DevicePolicy=`** → intended device restrictions may be ineffective or depend on defaults; easy to misread as “locked down” when it’s not → **Where it is:** `services/rustyjack-ui.service` includes `DeviceAllow=/dev/mem r` and `/dev/fb0 rw` but no `DevicePolicy=` → **How to fix:** set `DevicePolicy=closed` (or `strict`) and list the minimum needed devices; prefer `PrivateDevices=yes` unless you truly need broad `/dev` → **What the fixed version looks like:** `PrivateDevices=yes` + `DevicePolicy=closed` + `DeviceAllow=/dev/fb0 rw` (and *avoid* `/dev/mem` if possible).

- **`/dev/mem` access in the UI service is high-risk** → `/dev/mem` is effectively “raw physical memory”; even read-only can leak secrets and crash the system on buggy drivers; it bypasses many of the unit hardening knobs → **Where it is:** `services/rustyjack-ui.service` (`DeviceAllow=/dev/mem r`) → **How to fix:** use kernel interfaces intended for display/input (DRM/KMS, fbdev, evdev, sysfs), or move the minimal privileged hardware access into the daemon with a narrow RPC → **What the fixed version looks like:** UI has no `/dev/mem` access; daemon exposes “set_backlight()/read_hw_state()” style API.

- **Daemon unit grants very broad capabilities (including `CAP_SYS_ADMIN` and `CAP_DAC_OVERRIDE`)** → `CAP_SYS_ADMIN` is “the new root”; it undermines sandboxing and widens blast radius of daemon bugs → **Where it is:** `services/rustyjackd.service` `CapabilityBoundingSet=… CAP_SYS_ADMIN CAP_DAC_OVERRIDE …` → **How to fix:** capability-minimize by operation; split privileged sub-ops into helpers (Rust) or use systemd `AmbientCapabilities=` only for what’s needed; drop `CAP_SYS_ADMIN` unless you demonstrably need it → **What the fixed version looks like:** `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW …` and remove `CAP_SYS_ADMIN`.

- **Writable `/usr/local/bin` in several services** → allowing a service to write where executable code lives is a self-modifying system; it increases persistence risk and undermines “immutable base” thinking → **Where it is:** `services/rustyjackd.service` and `services/rustyjack-ui.service` include `ReadWritePaths=… /usr/local/bin` → **How to fix:** remove `/usr/local/bin` from writable allow-lists; use a dedicated writable state dir for updates/artifacts (e.g., `/var/lib/rustyjack/bin`) → **What the fixed version looks like:** `ReadWritePaths=/var/lib/rustyjack /run/rustyjack /tmp/rustyjack /etc/resolv.conf` (no `/usr/local/bin`).

- **Source-build installer masks socket activation but code supports it** → losing socket activation removes a key robustness lever (auto-start on demand, ordering, simpler boot) and creates unnecessary behavioral divergence → **Where it is:** `install_rustyjack.sh` masks `rustyjackd.socket`; daemon code `listener_or_bind()` supports LISTEN_FDS → **How to fix:** standardize on socket activation for production images unless there’s a measured reason not to → **What the fixed version looks like:** `rustyjackd.socket` enabled; daemon service uses `Requires=rustyjackd.socket`.

- **Directory ownership/mode invariants are spread across scripts and units** → hard to audit; easy for one install path to forget a directory; subtle permission bugs appear as “socket can’t connect” → **Where it is:** `install_rustyjack.sh` manual `mkdir/chown`; prebuilt uses `StateDirectory=`; daemon fallback bind creates `/run/rustyjack` with default perms → **How to fix:** move directory creation into systemd (`StateDirectory=`/`RuntimeDirectory=`) and/or `tmpfiles.d` consistently, and have Rust verify preconditions at startup → **What the fixed version looks like:** all services use `RuntimeDirectory=rustyjack` with `RuntimeDirectoryMode=0770` and group ownership.

- **Udev `RUN+=` hotplug path is brittle** → udev kills long-running processes after event handling; heavy work under udev can cause nondeterminism and missed events → **Where it is:** `scripts/99-rustyjack-wifi.rules` (`RUN+=.../rustyjack-hotplugd ...`) → **How to fix:** change rule to set `ENV{SYSTEMD_WANTS}+=rustyjack-wifi-hotplug@%k.service` (template unit to be added) and run work in a normal systemd service with timeouts and logging → **What the fixed version looks like:** a udev rule that only sets properties; a `rustyjack-wifi-hotplug@.service` does the heavy lifting.

- **wifi_hotplug.sh can trigger driver installation from a hotplug event** → DKMS/kernel headers installs are slow and failure-prone; doing this “in reaction to hardware arrival” can hang UI and increase boot instability → **Where it is:** `scripts/wifi_hotplug.sh` calling `wifi_driver_installer.sh` → **How to fix:** separate “detect adapter” from “install driver”; gate driver installs behind explicit operator action or a background job queue with retries/rollback → **What the fixed version looks like:** hotplug service only records the device + notifies UI; a separate job runner performs driver installs.

- **Boot config toggles may duplicate conflicting lines** → `add_dtparam()` only edits existing `=on`; if a param exists as `=off` the script appends a new line, creating multiple settings and ambiguity → **Where it is:** `install_rustyjack.sh` `add_dtparam()` and boot config edits near `CFG=/boot/firmware/config.txt` → **How to fix:** normalize by replacing any existing `^dtparam=<k>=.*$` regardless of value; ensure idempotency → **What the fixed version looks like:** `sed -i -E 's/^dtparam=spi=.*/dtparam=spi=on/'` (or equivalent safe edit).

- **Service ordering uses `network.target` where semantics are weak** → `network.target` does not mean “network is configured”; this can produce flapping startups or misleading readiness → **Where it is:** `services/rustyjack-ui.service` and generated units use `After=network.target` → **How to fix:** either depend on `rustyjackd.socket` (since UI’s real dependency is the daemon) or use explicit readiness from the daemon (`Type=notify` + `After=rustyjackd.service`) → **What the fixed version looks like:** `After=rustyjackd.socket` and `Requires=rustyjackd.socket`.

- **Portal service binds broadly with limited network scoping** → captive portal should generally bind only on the AP/control interface; broad binding risks exposure on unintended interfaces → **Where it is:** `services/rustyjack-portal.service` (`PORTAL_BIND=0.0.0.0`) → **How to fix:** bind to the AP interface IP only (or use firewall rules); make the bind configurable per interface state → **What the fixed version looks like:** `PORTAL_BIND=192.168.4.1` (or whatever AP IP is), not `0.0.0.0`.

- **Install-time disabling of services lacks “reconcile” path** → if a user re-enables `systemd-resolved`, `dhcpcd`, etc., Rustyjack may misbehave without telling you why → **Where it is:** install scripts disable/mask services; daemon startup doesn’t explicitly detect/complain about conflicting daemons → **How to fix:** add a “conflict detector” at daemon boot that checks for known competing services and logs/alerts clearly → **What the fixed version looks like:** `check_conflicts()` called from `main.rs` that reports `systemctl is-active systemd-resolved`.

- **Prebuilt installer still installs legacy networking tools** → contradicts the “pure Rust runtime” constraint; increases attack surface and troubleshooting ambiguity (“who’s doing DNS/DHCP?”) → **Where it is:** `install_rustyjack_prebuilt.sh` `PACKAGES` includes `dnsmasq`, `isc-dhcp-client`, `hostapd`, `wpasupplicant` → **How to fix:** separate “legacy fallback” packages behind a flag; default to Rust implementations only; audit runtime calls → **What the fixed version looks like:** package list omits these by default; legacy mode explicitly documented.

- **Unit verification is applied inconsistently** → `systemd-analyze verify` is used for the daemon in one installer but not consistently for UI/portal; broken units may slip through install → **Where it is:** `install_rustyjack.sh` runs `systemd-analyze verify "$DAEMON_SERVICE"` only → **How to fix:** verify all installed units and fail fast with actionable output → **What the fixed version looks like:** `systemd-analyze verify "$DAEMON_SERVICE" "$SERVICE" "$PORTAL_SERVICE" "$WPA_SERVICE"`.

- **Socket directory permissions are “whatever create_dir_all gives you” in non-socket-activation mode** → may be acceptable today, but it’s not an explicit invariant and could become a security issue if more services share `/run/rustyjack` → **Where it is:** `crates/rustyjack-daemon/src/systemd.rs::bind_socket()` creates parent dir but doesn’t chmod/chown it → **How to fix:** either rely on systemd `RuntimeDirectory=` everywhere or explicitly enforce dir owner/mode in Rust → **What the fixed version looks like:** ensure `/run/rustyjack` is `root:rustyjack 0770`.

---

## 7) Test plan (idempotency, failure injection, rollback, upgrade tests; on-device)

### Idempotency
- Run each installer twice (`install_rustyjack_prebuilt.sh`, `install_rustyjack_dev.sh`, `install_rustyjack.sh` once fixed) and assert:
  - no duplicate lines in `/boot/firmware/config.txt`
  - `/etc/resolv.conf` is the expected symlink
  - system users/groups exist with correct IDs and memberships
  - systemd units validate and are enabled exactly once

### Failure injection
- Simulate package install failures (network unplug / DNS broken mid-install) and verify:
  - installer exits with a clear error
  - previously disabled services are restored or the system is left in a known-safe degraded mode
- Corrupt `/etc/resolv.conf` and reboot:
  - verify boot-time repair/alert catches it
- Break socket permissions (`chmod 0600 /run/rustyjack/rustyjackd.sock`) and ensure UI reports a clear error path.

### Rollback & recovery
- If supporting OTA or any “update” process, test:
  - downgrade daemon binary while keeping state, then upgrade again
  - “partial update” (missing portal binary) doesn’t brick boot; services fail independently and clearly
- For FDE scripts (if used in product flow), test dry-run mode and ensure abort paths do not leave crypttab/initramfs half-written.

### Upgrade tests
- Upgrade from a prior release:
  - ensure unit changes are applied deterministically (no stale units left behind)
  - ensure DNS ownership invariants survive distro upgrades (Bookworm point releases, etc.)
- Ensure socket activation and non-socket-activation modes both work (if both remain supported).

### On-device automation
- Extend `scripts/rustyjack_comprehensive_test.sh`:
  - add an “installer idempotency suite”
  - add a “DNS ownership invariant suite” (symlink + contents + writeability)
  - add a “udev hotplug behavior suite” that verifies udev does not run long tasks.

---

## 8) Priority list (P0/P1/P2) + quick wins

### P0 (must fix before trusting production installs)
- Fix `install_rustyjack.sh` undefined `$SERVICE` abort.
- Normalize daemon syscall filtering (remove contradictory merged filters).
- Standardize systemd units across installers (one canonical set).
- Add boot-time validation + repair/alert for `/etc/resolv.conf` ownership invariant.
- Replace udev `RUN+=` with `SYSTEMD_WANTS` + service unit.

### P1 (next tranche: reduce risk + sharpen boundaries)
- Remove `/usr/local/bin` from `ReadWritePaths` and create a dedicated writable artifact dir.
- Capability-minimize daemon; drop `CAP_SYS_ADMIN` unless strictly required.
- Fix boot config editing idempotency (`dtparam` replacement).
- Scope captive portal binding to AP interface only.

### P2 (hardening + maintainability polish)
- Move user/group creation to `sysusers.d`; move directory creation to `StateDirectory=`/`RuntimeDirectory=` everywhere.
- Rework UI’s need for `/dev/mem`; shift privileged hardware access behind a daemon RPC.
- Add explicit conflict detection for competing network services at daemon boot.

**Quick wins (hours, not days):**
- Add `systemd-analyze verify` for all units during install.
- Add a “preflight” block in installers printing detected OS + confirming `/boot/firmware/config.txt` existence.
- Make installers print a summary of “what got changed” (services masked, packages removed, DNS claimed).

---

## Appendix A — Key excerpts (authoritative sources)

### A.1 `CLAUDE.md` (constraints)
```text
   1 | # CLAUDE.md - RustyJack Project Context
   2 | 
   3 | ## Project Overview
   4 | 
   5 | **RustyJack** is a portable network security toolkit for Raspberry Pi Zero 2 W running Raspberry Pi OS Lite or Debian (Trixie). It combines a native Rust offensive security framework with an embedded LCD UI (Waveshare 1.44" ST7735S default profile `128x128`, runtime geometry/layout aware).
   6 | 
   7 | **Key Principle: Pure Rust with no external binaries.** All system operations are implemented natively - no iptables, wpa_cli, dnsmasq, dhclient, nmcli, or rfkill binaries. Temporary exceptions exist for shell scripts during installation only.
   8 | 
   9 | **Reality check (current state):**
  10 | - Installers still pull `wpa_supplicant` (and `wpa_cli` as a fallback), `hostapd`, `dnsmasq`, and `isc-dhcp-client` for compatibility. These are not fully eliminated yet.
  11 | - `/etc/resolv.conf` is claimed as a symlink to `/var/lib/rustyjack/resolv.conf` (not a plain file).
  12 | - 64-bit arm64 deployments on Debian 13 (Trixie) are in active use; 32-bit remains a supported target but should be revalidated when changing low-level networking.
  13 | 
  14 | ### Target Platform
  15 | - **Hardware:** Raspberry Pi Zero 2 W with Ethernet HAT + Waveshare 1.44" LCD HAT
  16 | - **Display model:** Runtime capability/layout metrics; default ST7735 profile is `128x128`, larger backends use same 8-button UX model
  17 | - **OS:** Debian 13 / Raspberry Pi OS Lite (Trixie); arm64 is supported (preferred for prebuilts), 32-bit remains supported
  18 | - **External Requirements:** USB WiFi adapter with monitor+injection for wireless attacks (built-in BCM43436 cannot monitor/inject)
  19 | 
  20 | ### License
  21 | MIT
  22 | 
  23 | ---
  24 | 
  25 | ## Architecture
  26 | 
  27 | ```
  28 | ┌─────────────────────────────────────────────────────────────────┐
  29 | │                    rustyjack-ui (unprivileged)                  │
  30 | │  LCD rendering, button input, menu navigation                   │
  31 | │  User: rustyjack-ui | Groups: gpio, spi                        │
  32 | └────────────────────────┬────────────────────────────────────────┘
  33 |                          │ Unix Domain Socket IPC
  34 |                          │ /run/rustyjack/rustyjackd.sock
  35 | ┌────────────────────────▼────────────────────────────────────────┐
  36 | │              rustyjackd (root daemon, hardened)                 │
  37 | │  Command dispatch, job execution, system operations             │
  38 | │  Capabilities: CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN       │
  39 | └─────────────────────────────────────────────────────────────────┘
  40 | ```
  41 | 
  42 | **Design Principles:**
  43 | - Privilege separation: UI cannot directly access hardware
  44 | - All privileged operations go through daemon IPC
  45 | - Job-based architecture for long-running operations with cancellation
  46 | - Hardened systemd units with strict sandboxing
  47 | - Display startup flow is backend-aware: detect backend, query mode, calibrate if needed, cache effective geometry
  48 | - UI layout metrics are runtime-derived (no fixed menu/dialog visible constants in core flow)
  49 | 
  50 | ---
  51 | 
  52 | ## Crate Structure (14 crates)
  53 | 
  54 | ### Core Infrastructure
  55 | 
  56 | | Crate | Purpose |
  57 | |-------|---------|
  58 | | `rustyjack-ipc` | IPC protocol types, endpoints, authorization levels |
  59 | | `rustyjack-commands` | CLI/IPC command enums and argument structures |
  60 | | `rustyjack-client` | Tokio-based Unix socket client for daemon communication |
```

### A.2 `AGENTS.md` (workflow expectations)
```text
   1 | # AGENTS.md
   2 | 
   3 | This project targets a Raspberry Pi Zero 2 W equipped with an Ethernet HAT and a Waveshare LCD HAT (ST7735S profile default `128x128`). The UI renders with runtime display capabilities/layout metrics, keeps the physical control model fixed at exactly 8 buttons, and defaults to landscape via `RUSTYJACK_DISPLAY_ROTATION=landscape` (set by installer service env).
   4 | 
   5 | Display support policy:
   6 | - Lowest supported layout target is `128x128`.
   7 | - Smaller displays are allowed in best-effort mode and should log `UNSUPPORTED_DISPLAY_SIZE` warnings.
   8 | - Startup flow is `detect backend -> query capabilities -> calibrate only when needed -> cache effective geometry`.
   9 | - Recalculation is manual-only from `Settings -> Display`.
  10 | 
  11 | Hardware specifics drawn from waveshare_gpio_pin_mapping.md and waveshare_button_mapping.md:
  12 | - Display pins (BCM): DC=25, RST=27, BL=24; SPI: SCLK=11, MOSI=10, CS=8. Backlight lives on BCM24 and can be toggled with `gpioset gpiochip0 24=1`.
  13 | - Input pins (BCM): UP=6, DOWN=19, LEFT=5, RIGHT=26, PRESS=13; KEY1=21, KEY2=20, KEY3=16. Button mapping in the UI: Up/Down move selection, Left is back, Right/Select accepts, Key1 refreshes, Key2 cancels (no-op in menus/dashboards; cancels dialogs/ops), Key3 opens reboot confirmation.
  14 | - GPIO pull-ups are expected in `/boot/firmware/config.txt` (or `/boot/config.txt`), using `gpio=6,19,5,26,13,21,20,16=pu`; the installers write this line and request a reboot so input remains stable.
  15 | 
  16 | Software/runtime expectations:
  17 | - Built and run on Linux (Pi OS) with root privileges via systemd service, so `CAP_NET_ADMIN` is available.
  18 | - Dependencies are installed by `install_rustyjack.sh`, `install_rustyjack_dev.sh`, and `install_rustyjack_prebuilt.sh`: `wpasupplicant` (for WPA auth + `wpa_cli` fallback), `isc-dhcp-client`, `hostapd`, `dnsmasq`, `rfkill`, `i2c-tools`, `git`, `curl`, plus build/firmware packages (dev/build includes `build-essential`, `pkg-config`, `libssl-dev`, `dkms`, `bc`, `libelf-dev`). When adding features that call new system binaries, update all installers accordingly.
  19 | - **IMPORTANT: NetworkManager is REMOVED, not just disabled.** Installers run `apt-get purge network-manager` to completely remove NetworkManager from the system. Do NOT assume `nmcli` is available. All network management is done through pure Rust netlink operations.
  20 | - Installers now:
  21 |   - Remount `/` read-write if needed (fresh Pi images can boot `ro`).
  22 |   - **Purge NetworkManager completely** via `apt-get purge network-manager` and mask the service.
  23 |   - Claim `/etc/resolv.conf` for Rustyjack (symlink to `/var/lib/rustyjack/resolv.conf`, root-owned) and reclaim it after apt installs so route/DNS enforcement can write reliably.
  24 |   - Disable competing DNS managers (systemd-resolved, dhcpcd, resolvconf if present). This ensures Rustyjack has sole control of DNS on the dedicated device.
  25 |   - Ensure `/var/lib/rustyjack/logs` exists and is owned by `rustyjack-ui:rustyjack` so the UI can write logs.
  26 | 
  27 | MAC randomization flow:
  28 | - UI uses `rustyjack-evasion::MacManager` with vendor-aware policy engine for secure, locally administered MACs. Prefers vendor-matched OUIs based on the current interface's OUI. After changing MAC it triggers DHCP renewal via netlink; reconnect is best-effort and does not rely on `nmcli`.
  29 | 
  30 | Built-in wireless (Raspberry Pi Zero 2 W):
  31 | - Chipset: Cypress/Infineon CYW43436 (2.4 GHz 802.11b/g/n, single-stream HT20, ~72 Mbps max link). No 5 GHz support.
  32 | - Modes supported by the stock driver: managed (client) and limited AP mode (2.4 GHz, 20 MHz). Suitable for `rustyjack-core` scanning/association and for UI status queries.
  33 | - Monitor/sniff/injection: not supported by the stock CYW43436 driver. Deauth, targeted handshake capture, and Evil Twin features require a USB Wi-Fi adapter with monitor+injection (e.g., ath9k/ath9k_htc or rtl8812au with proper driver). Passive probe sniffing with the built-in radio would require Nexmon patches; otherwise use an external adapter.
  34 | - Channel coverage: 2.4 GHz only; Rustyjack features that assume 5 GHz (e.g., channel setting beyond 14 or dual-band AP) need an external dual-band adapter.
  35 | 
  36 | Project structure (14 workspace crates):
  37 | - `crates/rustyjack-core/` — Operations orchestration (68 command handlers), anti-forensics, physical access, USB mount operations, loot management, pipelines.
  38 |   - `src/external_tools/anti_forensics.rs` — Secure file deletion (DoD 5220.22-M), RAM wipe, log purging, evidence management.
  39 |   - `src/external_tools/physical_access.rs` — WiFi credential extraction from routers via wired connection, router fingerprinting.
  40 |   - `src/mount.rs` — USB mounting with read-only/read-write mode selection and mount policy enforcement.
  41 |   - `src/redact.rs` — Sensitive data redaction for logs (passwords, keys, credentials).
  42 | - `crates/rustyjack-daemon/` — Privileged root daemon with IPC dispatch and job lifecycle management.
  43 | - `crates/rustyjack-ui/` — Embedded display UI for the Waveshare HAT.
  44 | - `crates/rustyjack-client/` — Tokio-based Unix socket client for daemon communication.
  45 | - `crates/rustyjack-ipc/` — IPC protocol types and endpoints.
  46 | - `crates/rustyjack-commands/` — CLI/IPC command enums and argument structures.
  47 | - `crates/rustyjack-netlink/` — Pure Rust networking: interfaces, routes, DHCP, DNS, ARP, rfkill, nf_tables (replaces iptables, nmcli, dhclient).
  48 | - `crates/rustyjack-wireless/` — 802.11 attacks (9,688 lines, 18 modules): nl80211, monitor/injection, deauth, PMKID, Karma, Evil Twin, hotspot with native DHCP/DNS.
  49 | - `crates/rustyjack-ethernet/` — Rust-only Ethernet recon (ICMP/ARP sweep + TCP port scan, banner grabbing, device inventory).
  50 | - `crates/rustyjack-portal/` — Captive portal HTTP server (Axum + Tower middleware).
  51 | - `crates/rustyjack-evasion/` — MAC randomization with vendor-aware policy engine, hostname randomization, TX power control.
  52 | - `crates/rustyjack-encryption/` — AES-GCM encryption for loot, zeroization of sensitive data.
  53 | - `crates/rustyjack-wpa/` — WPA/WPA2 handshake processing (PBKDF2, HMAC-SHA1 for PMK/PTK).
  54 | - `DNSSpoof/` — Captive portal HTML/JS templates (not a Rust crate).
  55 | - `scripts/` — WiFi driver installer (`wifi_driver_installer.sh`), FDE scripts (`fde_prepare_usb.sh`, `fde_migrate_root.sh`), USB hotplug helper.
  56 | - `install_rustyjack.sh`, `install_rustyjack_dev.sh`, `install_rustyjack_prebuilt.sh` — Production, debug, and prebuilt installers.
  57 | - `waveshare_gpio_pin_mapping.md`, `waveshare_button_mapping.md` — Validated pinout and button behavior references.
  58 | 
  59 | Loot storage:
  60 | - Wireless captures: `loot/Wireless/<target>/` (target = SSID, else BSSID).
```

### A.3 `logs/done/interface_isolation_overview.md` (interface intent)
```text
   1 | # Interface Isolation
   2 | Created: 2026-01-07
   3 | 
   4 | Ensures only selected interfaces are active to prevent leaks and conflicts.
   5 | 
   6 | Supersedes:
   7 | - `INTERFACE_ISOLATION_IMPLEMENTATION.md`
   8 | - `INTERFACE_ISOLATION_WIRELESS_FIX.md`
   9 | - `INTERFACE_ISOLATION_VERIFICATION.md`
  10 | 
  11 | ## Behavior
  12 | - `apply_interface_isolation(allowed)`: iterates `/sys/class/net`, skips `lo`, brings allowed interfaces up (and unblocks rfkill if wireless), brings others down and rfkill-blocks wireless.
  13 | - `enforce_single_interface(iface)`: convenience to allow only one interface (used before attacks/pipelines).
  14 | - Wireless fixes: rfkill is unblocked before link-up attempts; wireless UP failures on unassociated IFs no longer abort isolation.
  15 | 
  16 | ## Dependencies
  17 | - `rustyjack-core::system` and `netlink_helpers` using `rustyjack-netlink` for link state/rfkill; uses sysfs for rfkill indices.
  18 | - Root required; Linux-only.
  19 | 
  20 | ## Notes
  21 | - Active interface preferences are stored/read by core; UI exposes Hardware Detect and “Route ensure” flows to set the active interface.
  22 | - Isolation is applied automatically in pipelines and many operations to avoid multi-interface routing conflicts.
```

---

## Appendix B — Evidence snippets (implementation references)

### B.1 Undefined `$SERVICE` in `install_rustyjack.sh`
```bash
 964 | update_config=0
 965 | ap_scan=1
 966 | country=US
 967 | CONF
 968 | sudo chmod 600 "$WPA_CONF"
 969 | sudo systemctl unmask rustyjack-wpa_supplicant@.service 2>/dev/null || true
 970 | step "Installing systemd service $SERVICE..."
 971 | 
 972 | rj_sudo_tee "$SERVICE" >/dev/null <<UNIT
 973 | [Unit]
 974 | Description=Rustyjack UI Service (100% Rust)
 975 | After=local-fs.target network.target
 976 | Wants=network.target
 977 | 
 978 | [Service]
 979 | Type=simple
 980 | WorkingDirectory=$RUNTIME_ROOT
```

### B.2 Udev hotplug rule
```udev
   1 | # RustyJack USB WiFi Auto-Detection udev Rules
   2 | # Place in /etc/udev/rules.d/99-rustyjack-wifi.rules
   3 | 
   4 | # Trigger on USB WiFi adapter insertion
   5 | # This covers major WiFi chipset vendors
   6 | 
   7 | # Realtek WiFi Adapters
   8 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="0bda", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
   9 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="0bda", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  10 | 
  11 | # Ralink/MediaTek WiFi Adapters  
  12 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="148f", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  13 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="148f", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  14 | 
  15 | # MediaTek (alternate vendor ID)
  16 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="0e8d", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  17 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="0e8d", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  18 | 
  19 | # Atheros/Qualcomm WiFi Adapters
  20 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="0cf3", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  21 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="0cf3", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  22 | 
  23 | # TP-Link WiFi Adapters
  24 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="2357", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  25 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="2357", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  26 | 
  27 | # D-Link WiFi Adapters
  28 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="2001", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  29 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="2001", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  30 | 
  31 | # Alfa Network WiFi Adapters (uses Realtek/Atheros chipsets)
  32 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="0bda", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  33 | 
  34 | # NetGear WiFi Adapters
  35 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="0846", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  36 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="0846", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  37 | 
  38 | # Linksys/Belkin WiFi Adapters
  39 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="13b1", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  40 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="13b1", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  41 | 
  42 | # ASUS WiFi Adapters
  43 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="0b05", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  44 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="0b05", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  45 | 
  46 | # Edimax WiFi Adapters
  47 | SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="7392", RUN+="/usr/local/bin/rustyjack-hotplugd add %k"
  48 | SUBSYSTEM=="usb", ACTION=="remove", ATTR{idVendor}=="7392", RUN+="/usr/local/bin/rustyjack-hotplugd remove %k"
  49 | 
  50 | # Also trigger on net subsystem for interface creation
  51 | SUBSYSTEM=="net", ACTION=="add", KERNEL=="wlan*", RUN+="/usr/local/bin/rustyjack-hotplugd interface_add %k"
```

### B.3 Daemon socket activation support (Rust)
```rust
   1 | use std::env;
   2 | use std::ffi::CString;
   3 | use std::fs;
   4 | use std::io;
   5 | use std::os::unix::ffi::OsStrExt;
   6 | use std::os::unix::fs::PermissionsExt;
   7 | use std::os::unix::io::{AsRawFd, FromRawFd};
   8 | use std::os::unix::net::UnixDatagram;
   9 | use std::path::Path;
  10 | use std::time::Duration;
  11 | 
  12 | use tokio::net::UnixListener;
  13 | use tokio::task::JoinHandle;
  14 | use tokio::time;
  15 | use tracing::warn;
  16 | 
  17 | use crate::config::DaemonConfig;
  18 | 
  19 | pub fn listener_or_bind(config: &DaemonConfig) -> io::Result<UnixListener> {
  20 |     if let Some(listener) = systemd_listener()? {
  21 |         return Ok(listener);
  22 |     }
  23 |     bind_socket(&config.socket_path, config.socket_group.as_deref())
  24 | }
  25 | 
  26 | fn systemd_listener() -> io::Result<Option<UnixListener>> {
  27 |     let listen_pid = env::var("LISTEN_PID")
  28 |         .ok()
  29 |         .and_then(|v| v.parse::<u32>().ok());
  30 |     let listen_fds = env::var("LISTEN_FDS")
  31 |         .ok()
  32 |         .and_then(|v| v.parse::<i32>().ok());
  33 | 
  34 |     if listen_pid != Some(std::process::id()) {
  35 |         return Ok(None);
  36 |     }
  37 | 
  38 |     let fds = listen_fds.unwrap_or(0);
  39 |     if fds < 1 {
  40 |         return Ok(None);
  41 |     }
  42 | 
  43 |     if fds > 1 {
  44 |         warn!("LISTEN_FDS={} (expected 1)", fds);
  45 |     }
  46 | 
  47 |     let fd = 3;
  48 |     let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
  49 |     std_listener.set_nonblocking(true)?;
  50 |     Ok(Some(UnixListener::from_std(std_listener)?))
  51 | }
  52 | 
  53 | fn bind_socket(path: &Path, group: Option<&str>) -> io::Result<UnixListener> {
  54 |     if let Some(parent) = path.parent() {
  55 |         fs::create_dir_all(parent)?;
  56 |     }
  57 |     if path.exists() {
  58 |         fs::remove_file(path)?;
  59 |     }
  60 | 
  61 |     let listener = std::os::unix::net::UnixListener::bind(path)?;
  62 |     fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
  63 | 
  64 |     if let Some(group) = group {
  65 |         if let Err(err) = apply_socket_group(path, group) {
  66 |             warn!("Failed to set socket group {}: {}", group, err);
  67 |         }
  68 |     }
  69 | 
  70 |     listener.set_nonblocking(true)?;
  71 |     UnixListener::from_std(listener)
  72 | }
  73 | 
  74 | fn apply_socket_group(path: &Path, group: &str) -> io::Result<()> {
  75 |     let gid = lookup_gid(group)?;
  76 |     let c_path = CString::new(path.as_os_str().as_bytes())
  77 |         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket path"))?;
  78 |     let rc = unsafe { libc::chown(c_path.as_ptr(), 0, gid as libc::gid_t) };
  79 |     if rc != 0 {
  80 |         return Err(io::Error::last_os_error());
  81 |     }
  82 |     Ok(())
  83 | }
  84 | 
  85 | fn lookup_gid(group: &str) -> io::Result<u32> {
  86 |     let c_group = CString::new(group)
  87 |         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid group name"))?;
  88 |     let grp = unsafe { libc::getgrnam(c_group.as_ptr()) };
  89 |     if grp.is_null() {
  90 |         return Err(io::Error::new(
  91 |             io::ErrorKind::NotFound,
  92 |             format!("group {} not found", group),
  93 |         ));
  94 |     }
  95 |     let gid = unsafe { (*grp).gr_gid } as u32;
  96 |     Ok(gid)
  97 | }
  98 | 
  99 | pub fn notify_ready() {
 100 |     if let Err(err) = sd_notify("READY=1") {
 101 |         warn!("sd_notify READY failed: {}", err);
 102 |     }
 103 | }
 104 | 
 105 | pub fn spawn_watchdog_task() -> Option<JoinHandle<()>> {
 106 |     let interval = watchdog_interval()?;
 107 |     Some(tokio::spawn(async move {
 108 |         let mut ticker = time::interval(interval);
 109 |         loop {
 110 |             ticker.tick().await;
 111 |             if let Err(err) = sd_notify("WATCHDOG=1") {
 112 |                 warn!("sd_notify WATCHDOG failed: {}", err);
 113 |             }
 114 |         }
 115 |     }))
 116 | }
 117 | 
 118 | fn sd_notify(message: &str) -> io::Result<()> {
 119 |     let notify_socket = match env::var("NOTIFY_SOCKET") {
 120 |         Ok(value) => value,
```

### B.4 Daemon startup enforcement (Rust)
```rust
   1 | use std::fs;
   2 | use std::sync::Arc;
   3 | use std::time::{Instant, SystemTime, UNIX_EPOCH};
   4 | 
   5 | use tokio::sync::RwLock;
   6 | use tracing::{info, warn};
   7 | 
   8 | use crate::config::DaemonConfig;
   9 | use crate::jobs::JobManager;
  10 | use crate::locks::LockManager;
  11 | use crate::ops::OpsConfig;
  12 | 
  13 | #[derive(Debug, Clone)]
  14 | pub struct DaemonState {
  15 |     pub config: DaemonConfig,
  16 |     pub start_time: Instant,
  17 |     pub jobs: Arc<JobManager>,
  18 |     pub locks: Arc<LockManager>,
  19 |     pub version: String,
  20 |     pub ops_runtime: Arc<RwLock<OpsConfig>>,
  21 | }
  22 | 
  23 | impl DaemonState {
  24 |     pub fn new(config: DaemonConfig) -> Self {
  25 |         let start_time = Instant::now();
  26 |         let jobs = Arc::new(JobManager::new(config.job_retention));
  27 |         let locks = Arc::new(LockManager::new());
  28 |         let ops_runtime = Arc::new(RwLock::new(config.ops));
  29 |         let version = env!("CARGO_PKG_VERSION").to_string();
  30 |         Self {
  31 |             config,
  32 |             start_time,
  33 |             jobs,
  34 |             locks,
  35 |             version,
  36 |             ops_runtime,
  37 |         }
  38 |     }
  39 | 
  40 |     pub fn uptime_ms(&self) -> u64 {
  41 |         self.start_time.elapsed().as_millis() as u64
  42 |     }
  43 | 
  44 |     pub fn now_ms() -> u64 {
  45 |         SystemTime::now()
  46 |             .duration_since(UNIX_EPOCH)
  47 |             .unwrap_or_default()
  48 |             .as_millis() as u64
  49 |     }
  50 | 
  51 |     pub async fn reconcile_on_startup(&self) {
  52 |         let root = self.config.root_path.clone();
  53 |         tokio::task::spawn_blocking(move || {
  54 |             use rustyjack_core::system::{IsolationEngine, RealNetOps};
  55 |             use std::sync::Arc;
  56 | 
  57 |             // Read mount table (moved inside spawn_blocking to avoid blocking async runtime)
  58 |             match fs::read_to_string("/proc/mounts") {
  59 |                 Ok(contents) => {
  60 |                     let count = contents.lines().count();
  61 |                     info!("Startup mount table entries: {}", count);
  62 |                 }
  63 |                 Err(err) => warn!("Failed to read /proc/mounts: {}", err),
  64 |             }
  65 | 
  66 |             let ops = Arc::new(RealNetOps);
  67 |             let engine = IsolationEngine::new(ops, root);
  68 | 
  69 |             let mut retries = 0;
  70 |             let max_retries = 3;
  71 | 
  72 |             loop {
  73 |                 match engine.enforce_passive() {
  74 |                     Ok(outcome) => {
  75 |                         info!(
  76 |                             "Startup enforcement succeeded: allowed={:?}, blocked={:?}",
  77 |                             outcome.allowed, outcome.blocked
  78 |                         );
  79 |                         if !outcome.errors.is_empty() {
  80 |                             warn!("Enforcement had {} non-fatal errors", outcome.errors.len());
  81 |                             for err in &outcome.errors {
  82 |                                 warn!("  {}: {}", err.interface, err.message);
  83 |                             }
  84 |                         }
  85 |                         break;
  86 |                     }
  87 |                     Err(e) => {
  88 |                         warn!(
  89 |                             "Startup enforcement failed (attempt {}/{}): {}",
  90 |                             retries + 1,
  91 |                             max_retries,
  92 |                             e
  93 |                         );
  94 | 
  95 |                         retries += 1;
  96 |                         if retries >= max_retries {
  97 |                             tracing::error!(
  98 |                                 "Startup enforcement failed after {} attempts, continuing anyway",
  99 |                                 max_retries
 100 |                             );
 101 |                             break;
 102 |                         }
 103 | 
 104 |                         std::thread::sleep(std::time::Duration::from_secs(2));
 105 |                     }
 106 |                 }
 107 |             }
 108 |         })
 109 |         .await
 110 |         .unwrap_or_else(|e| {
 111 |             warn!("Network reconciliation task panicked: {}", e);
 112 |         });
 113 |     }
 114 | }
```

---

## Appendix C — External references (for section 5 / best practices)

- systemd execution environment and `SystemCallFilter=` semantics: Ubuntu manpage for `systemd.exec(5)`
- udev guidance on long-running processes and `SYSTEMD_WANTS`: `udev(7)` (man7.org)
- Declarative users/groups: `sysusers.d(5)` (Arch man pages)
- Temporary/runtime directories: `tmpfiles.d(5)` (man7.org)
- `systemd-resolved(8)` and `/etc/resolv.conf` symlink modes: Debian manpages
- Raspberry Pi boot config location `/boot/firmware/config.txt`: Raspberry Pi documentation (`config.txt`)
- Transactional/rollback update patterns: RAUC basics, Mender “How it works”, OSTree/rpm-ostree overview
