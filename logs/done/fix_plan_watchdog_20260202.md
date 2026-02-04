# Fix Plan — Watchdog/RustyJack (Pi Zero 2 W)  
Date: 3/02/26
**Based on:** `watchdog_shallow_20260202-234357.zip` (current code snapshot)  
**Reference spec:** `report_updated.md` (static UI + full wiring + ops split + D‑Bus Wi‑Fi backend + installer correctness)

This document is a **hands-on remediation plan** for the issues found in this code snapshot, with an emphasis on the **four installer programs**:

- `install_01_layout`
- `install_02_identities`
- `install_03_systemd`
- `install_04_seed_config`

It explains **what is currently true**, **why it is or isn’t correct**, and what the **correct implementation** should look like to reliably boot as a single‑purpose appliance.

---

## 0) Executive summary (what’s broken, what to fix first)

### What’s already good
- The UI is static and compiled-in (no dynamic feature construction).
- The daemon now supports **ops split** (Power vs System/Maintenance).
- A `wpa_supplicant` D‑Bus station backend exists, and a hardened systemd unit template for it exists.

### What prevents an end-to-end correct install right now (highest priority)
1) **Identity creation does not match the systemd unit files**  
   The installer creates only `rustyjack` (group) and `rustyjack-ui` (user), but your unit files require:
   - `User=rustyjack-ui` **and** `Group=rustyjack-ui`
   - `User=rustyjack-portal` **and** `Group=rustyjack-portal`

2) **Systemd enable/start step is incomplete**  
   `install_03_systemd` enables/starts only `rustyjackd.socket`. It does not enable/start:
   - the daemon service (`rustyjackd.service`)
   - the UI service (`rustyjack-ui.service`)
   - the `wpa_supplicant` template instance for wlan0 (`rustyjack-wpa_supplicant@wlan0.service`)

3) **Wi‑Fi D‑Bus backend prerequisites aren’t installed/seeded by the installers**  
   - The unit `rustyjack-wpa_supplicant@.service` exists but is **not installed** by `install_01_layout`.
   - `/etc/rustyjack/wpa_supplicant.conf` is referenced by the unit but is **not created** by `install_04_seed_config`.
   - Core reads country from `/etc/wpa_supplicant/wpa_supplicant.conf` today; your unit uses `/etc/rustyjack/wpa_supplicant.conf` → **path mismatch**.

4) **A duplicate UI unit (`services/rustyjack.service`) is likely a footgun**  
   You already have `Alias=rustyjack.service` in `rustyjack-ui.service`. Shipping a separate `rustyjack.service` file that starts the same binary increases the chance of double-starting UI.

---

## 1) Target “correct appliance install” (contract)

When a user runs the installers, the device should end in a state where:

### 1.1 Files and directories exist
**Binaries**
- `/usr/local/bin/rustyjackd`
- `/usr/local/bin/rustyjack-ui`
- `/usr/local/bin/rustyjack-portal` (optional if portal is part of the appliance)

**Systemd units**
- `/etc/systemd/system/rustyjackd.socket`
- `/etc/systemd/system/rustyjackd.service`
- `/etc/systemd/system/rustyjack-ui.service`
- `/etc/systemd/system/rustyjack-portal.service` (optional)
- `/etc/systemd/system/rustyjack-wpa_supplicant@.service` (required if using `RUSTYJACK_WIFI_BACKEND=dbus`)

**Config**
- `/etc/rustyjack/update_pubkey.ed25519`
- `/etc/rustyjack/wpa_supplicant.conf` (or an explicitly chosen canonical path)

**State**
- `/var/lib/rustyjack` should exist and be writable by the UI and portal processes as designed.

> Note: systemd can create runtime/state dirs for units via `RuntimeDirectory=` and `StateDirectory=` (see systemd exec docs).  
> References: `systemd.exec` docs and related manpages.  
> https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html  
> https://manpages.debian.org/buster/systemd/systemd.exec.5.en.html

### 1.2 Users/groups exist and match unit files
At minimum:
- group: `rustyjack` (for daemon socket access)
- group: `rustyjack-ui`
- group: `rustyjack-portal`
- user: `rustyjack-ui` (primary group: `rustyjack-ui`)
- user: `rustyjack-portal` (primary group: `rustyjack-portal`)
- supplementary group membership:
  - `rustyjack-ui` ∈ `rustyjack`
  - `rustyjack-portal` ∈ `rustyjack`

This is best managed via `sysusers.d` + applying it with `systemd-sysusers`.  
References:  
- https://www.freedesktop.org/software/systemd/man/systemd-sysusers.html  
- https://www.man7.org/linux/man-pages/man8/systemd-sysusers.8.html

### 1.3 Enabled/active services (boot behavior)
**Recommended default for appliance mode**
- `rustyjackd.service` **enabled and active**
- `rustyjackd.socket` **enabled and active** (socket activation can still be useful)
- `rustyjack-ui.service` **enabled and active**
- `rustyjack-wpa_supplicant@wlan0.service` **enabled and active** (if Wi‑Fi backend is D‑Bus)

To do this correctly from Rust, keep using systemd’s D‑Bus Manager interface (`org.freedesktop.systemd1.Manager`).  
Reference: https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html

---

## 2) Installer audit (script-by-script)

### 2.1 `install_01_layout` — layout and unit placement

#### What it does today
- Copies:
  - `rustyjackd` (required)
  - `rustyjack-ui` (optional but present)
  - `rustyjack-portal` (optional but present)
  into `/usr/local/bin`
- Installs units:
  - `rustyjackd.service`
  - `rustyjack-ui.service`
  - `rustyjack-portal.service`
  - `rustyjack.service` (optional)
  - `rustyjackd.socket`

#### What is missing / why it matters
- It **does not install** `services/rustyjack-wpa_supplicant@.service`.  
  If the daemon defaults to `RUSTYJACK_WIFI_BACKEND=dbus`, Wi‑Fi operations will fail unless the service is installed and running.

- It installs `rustyjack.service` even though `rustyjack-ui.service` already declares `Alias=rustyjack.service`.  
  This is redundant and risks confusion/double-start.

#### Correct implementation
1) **Add** install of the wpa template unit:
   - source: `services/rustyjack-wpa_supplicant@.service`
   - dest: `/etc/systemd/system/rustyjack-wpa_supplicant@.service`

2) **Remove** installation of `services/rustyjack.service` (or delete that file from repo).  
   Rely on the alias in `rustyjack-ui.service` if you want the alternate name.

3) Optional hardening:
   - Validate `/usr/local/bin` exists and is writable.
   - Print a summary of installed files.

---

### 2.2 `install_02_identities` — sysusers config

#### What it does today
Writes `/etc/sysusers.d/rustyjack.conf`:

- creates group `rustyjack`
- creates user `rustyjack-ui`
- adds `rustyjack-ui` as a member of `rustyjack`

#### Why it is not correct
Your unit files require these identities, but the installer does not create them:
- group `rustyjack-ui`
- user/group `rustyjack-portal`

Because `rustyjack-ui.service` has `Group=rustyjack-ui`, systemd will fail the unit start if that group doesn’t exist.

#### Correct implementation

**2.2.1 Update the sysusers content**  
A good baseline (primary groups match unit files):

```text
# Socket access group (daemon)
g rustyjack -

# UI user+group
g rustyjack-ui -
u rustyjack-ui - "RustyJack UI" - -
m rustyjack-ui rustyjack

# Portal user+group
g rustyjack-portal -
u rustyjack-portal - "RustyJack Portal" - -
m rustyjack-portal rustyjack
```

**2.2.2 Apply sysusers deterministically**
After writing the file, you should apply it immediately. The canonical way is to run `systemd-sysusers`.  
Reference: https://www.freedesktop.org/software/systemd/man/systemd-sysusers.html

Best practice options:
- Prefer calling `systemd-sysusers` once (no shell, absolute path, timeout).
- Or, if you refuse running external binaries here, then your installer must **not** enable/start services until after a reboot + manual sysusers apply. (Not recommended; brittle.)

---

### 2.3 `install_04_seed_config` — config seeding

#### What it does today
- Ensures `/etc/rustyjack` exists
- Writes `/etc/rustyjack/update_pubkey.ed25519` based on env:
  - `RUSTYJACK_UPDATE_PUBKEY_HEX` or
  - `RUSTYJACK_UPDATE_PUBKEY_FILE_SRC`

#### What’s missing / why it matters
- It does not create `/etc/rustyjack/wpa_supplicant.conf`, but your `rustyjack-wpa_supplicant@.service` unit requires it.
- It does not ensure file permissions appropriate for secrets (PSK).

#### Correct implementation

**4.3.1 Seed a minimal wpa_supplicant config**
Create `/etc/rustyjack/wpa_supplicant.conf` with:
- `update_config=0` (RustyJack owns config)
- `ctrl_interface` as appropriate
- `country=<code>` (derived or defaulted)

Example template (no networks embedded; networks should be added via D‑Bus at runtime):

```conf
ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev
update_config=0
country=IE
```

Also:
- file mode should be `0600` (or `0640` if you intentionally allow group read)
- ownership root:root (or a dedicated config group if you prefer)

**4.3.2 Align the “country source of truth” in Rust**
Today the code reads country from `/etc/wpa_supplicant/wpa_supplicant.conf`. Your unit uses `/etc/rustyjack/wpa_supplicant.conf`. Make this consistent:

Recommended:
- First try `/etc/rustyjack/wpa_supplicant.conf`
- Fall back to `/etc/wpa_supplicant/wpa_supplicant.conf` for compatibility

---

### 2.4 `install_03_systemd` — enable and start units via D‑Bus

#### What it does today
- Calls `Reload`
- Enables `rustyjackd.socket`
- Starts `rustyjackd.socket`

It uses the correct systemd Manager interface (`org.freedesktop.systemd1.Manager`) and D‑Bus connection.  
Reference: https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html

#### Why it is not correct for an appliance
A “UI-only appliance” should come up at boot without manual service management. Enabling only the socket will not:
- start the daemon service (so `StateDirectory=` won’t create `/var/lib/rustyjack`)
- start the UI service
- start the wpa_supplicant D‑Bus service instance needed by the backend

#### Correct implementation (recommended)

**2.4.1 Enable the correct set of units**
Use `EnableUnitFiles` for (at minimum):

- `rustyjackd.socket`
- `rustyjackd.service`
- `rustyjack-ui.service`
- `rustyjack-wpa_supplicant@wlan0.service`

Optionally:
- `rustyjack-portal.service` (if portal should always be available)

**2.4.2 Start the core units**
Call `StartUnit` for:

- `rustyjackd.service`
- `rustyjack-ui.service`
- `rustyjack-wpa_supplicant@wlan0.service`

You can keep starting the socket too, but starting the service is the part that creates state directories and makes the appliance come alive.

---

## 3) Unit file corrections (so the installed system is robust)

### 3.1 Remove or stop installing `services/rustyjack.service`
Because `rustyjack-ui.service` already declares `Alias=rustyjack.service`, shipping a separate file named `rustyjack.service` is confusing.

**Correct implementation options**
- Option A (preferred): delete `services/rustyjack.service` and stop installing it
- Option B: keep it, but do not enable it; enforce in installer that only `rustyjack-ui.service` is enabled

### 3.2 Ensure `/var/lib/rustyjack` exists before UI/portal start
Your daemon unit uses `StateDirectory=rustyjack`, which systemd can use to create `/var/lib/rustyjack` at daemon start (see systemd exec docs).  
Reference: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

However:
- `rustyjack-ui.service` currently orders after the socket, not the daemon service.
- If the daemon service is not started first, UI `WorkingDirectory=/var/lib/rustyjack` may be missing.

**Correct implementation options**
- Option A (simple): make UI require the daemon service:
  - `Requires=rustyjackd.service`
  - `After=rustyjackd.service`
- Option B (more autonomous): add to UI unit:
  - `StateDirectory=rustyjack`
  so UI can start even if daemon isn’t started yet (but still needs the socket for IPC)

**Also note:** systemd supports prefixing WorkingDirectory with `-` to make “missing directory not fatal”.  
Reference: https://manpages.debian.org/buster/systemd/systemd.exec.5.en.html

### 3.3 Portal directory creation
Portal uses:
- `WorkingDirectory=/var/lib/rustyjack/portal`
- `ReadWritePaths=/var/lib/rustyjack/portal /var/lib/rustyjack/logs`

Nothing guarantees those directories exist.

**Correct implementation options**
- Add `StateDirectory=rustyjack/portal rustyjack/logs` to portal unit, OR
- Ensure the portal binary creates them at startup (`create_dir_all`) and returns a clear error if it can’t.

---

## 4) Wi‑Fi D‑Bus backend readiness (what must be true on a fresh image)

Your backend expects the documented wpa_supplicant D‑Bus API (`fi.w1.wpa_supplicant1`).  
Reference: https://w1.fi/wpa_supplicant/devel/dbus.html

Linux wireless docs explain that GUIs commonly rely on the D‑Bus service file and running wpa_supplicant with D‑Bus enabled.  
Reference: https://wireless.docs.kernel.org/en/latest/en/users/documentation/wpa_supplicant.html

### 4.1 Minimum prerequisites the installers must ensure
- `wpa_supplicant` is present at the ExecStart path (`/sbin/wpa_supplicant` in your unit today)
- `dbus` is running
- `rustyjack-wpa_supplicant@.service` is installed and `@wlan0` instance enabled/started
- `/etc/rustyjack/wpa_supplicant.conf` exists and is readable by the service

### 4.2 Improve robustness of the wpa unit path
Different distros place `wpa_supplicant` at `/sbin`, `/usr/sbin`, or `/usr/local/sbin`.

**Correct implementation options**
- In the unit file: use `/usr/sbin/wpa_supplicant` if that matches your base image
- Or, in the installer: detect the binary path by checking a small list of known locations and update the unit template before installing it (pure Rust file checks; no shelling out)

---

## 5) Correct “appliance install” sequence (what users should run)

Given the current scripts, the correct conceptual order is:

1) `install_01_layout` — install binaries + unit files
2) `install_02_identities` — write sysusers config **and apply it**
3) `install_04_seed_config` — write update pubkey and wpa_supplicant.conf
4) `install_03_systemd` — reload, enable, start the set of units

This order avoids the common boot-time footgun:
- enabling/starting services before users/config exist.

---

## 6) Verification: how to prove the install is correct on-device

### 6.1 Identity verification
- `getent group rustyjack`
- `getent group rustyjack-ui`
- `getent group rustyjack-portal`
- `getent passwd rustyjack-ui`
- `getent passwd rustyjack-portal`

### 6.2 Files present
- `/usr/local/bin/rustyjackd`, `/usr/local/bin/rustyjack-ui`, `/usr/local/bin/rustyjack-portal`
- `/etc/systemd/system/rustyjack-wpa_supplicant@.service`
- `/etc/rustyjack/update_pubkey.ed25519`
- `/etc/rustyjack/wpa_supplicant.conf`

### 6.3 Service status
- `systemctl status rustyjackd.socket`
- `systemctl status rustyjackd.service`
- `systemctl status rustyjack-ui.service`
- `systemctl status rustyjack-wpa_supplicant@wlan0.service`

### 6.4 D‑Bus availability check (for Wi‑Fi backend)
- Confirm `fi.w1.wpa_supplicant1` is present on the system bus and that your daemon can call `GetInterface`/`CreateInterface` as needed (per the wpa D‑Bus API docs).  
  Reference: https://w1.fi/wpa_supplicant/devel/dbus.html

---

## 7) Appendix — concrete artifacts to add/modify

### A) Updated `/etc/sysusers.d/rustyjack.conf` content
```text
g rustyjack -
g rustyjack-ui -
u rustyjack-ui - "RustyJack UI" - -
m rustyjack-ui rustyjack

g rustyjack-portal -
u rustyjack-portal - "RustyJack Portal" - -
m rustyjack-portal rustyjack
```

### B) Seeded `/etc/rustyjack/wpa_supplicant.conf` template
```conf
ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev
update_config=0
country=IE
```

### C) Units to enable/start by default (appliance profile)
Enable:
- `rustyjackd.socket`
- `rustyjackd.service`
- `rustyjack-ui.service`
- `rustyjack-wpa_supplicant@wlan0.service`
- (optional) `rustyjack-portal.service`

Start:
- `rustyjackd.service`
- `rustyjack-ui.service`
- `rustyjack-wpa_supplicant@wlan0.service`

---

## References (high-quality upstream docs)

- systemd-sysusers (official): https://www.freedesktop.org/software/systemd/man/systemd-sysusers.html  
- systemd D‑Bus API (`org.freedesktop.systemd1`): https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html  
- systemd execution environment (`systemd.exec`): https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html  
- Debian manpage for `systemd.exec` (often easier to fetch): https://manpages.debian.org/buster/systemd/systemd.exec.5.en.html  
- wpa_supplicant D‑Bus API (official): https://w1.fi/wpa_supplicant/devel/dbus.html  
- Linux wireless documentation on wpa_supplicant + D‑Bus service file behavior: https://wireless.docs.kernel.org/en/latest/en/users/documentation/wpa_supplicant.html
