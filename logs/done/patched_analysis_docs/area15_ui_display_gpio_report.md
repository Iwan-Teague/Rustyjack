# Area 15 — UI + display subsystem + GPIO input (RustyJack)

Date: 2026-02-14  
Repo snapshot: `watchdog_shallow_20260213-173640.zip` (unpacked to analysis workspace)

## Evidence & trust model (per Architecture Doc 2)

**Authoritative UX constraints come only from:**
- Repository root docs (notably `AGENTS.md`, `README.md`)
- `logs/done/` docs (notably display + GPIO reports)

Everything else (Rust code, scripts, configs) is treated as implementation evidence.

---

## 1) UX contract

### 1.1 Physical controls (exactly 8 buttons)

Authoritative mapping (root docs + `logs/done/waveshare_gpio_pin_mapping.md`):

| Control | UI intent (contract) | Notes |
|---|---|---|
| Up / Down | Move selection, scroll | Used for menu navigation and scrolling dialogs |
| Left | Back / exit dialog | “Back” is expected to unwind navigation safely |
| Right / Center (Select) | Select / confirm | Confirmations must be explicit |
| Key1 | Refresh current view | May be a no-op on some screens, but should never do something destructive |
| Key2 | Cancel | No-op in menus; cancels dialogs/ops; should be honored broadly |
| Key3 | Reboot affordance | Should open a reboot confirmation (never immediate reboot) |

**Safety rule:** destructive/dangerous actions must be gated behind *explicit confirmation* (no single-press triggers), and dialogs must **persist until acknowledged** (no auto-dismiss).

### 1.2 Display + layout constraints

**Minimum supported layout target:** `128×128`.  
Smaller displays are allowed only in “best-effort” mode and must emit an `UNSUPPORTED_DISPLAY_SIZE` warning.

**Runtime display flow (contract):**  
detect backend → query capabilities → calibrate only when needed → cache effective geometry  
There is **no automatic “recalculation loop”** during normal boots; recalculation is **manual-only** from `Settings → Display`.

**Effective geometry precedence (contract):**  
override (env/config) > backend detected mode > backend profile

### 1.3 Calibration UX contract

Calibration is user-driven via `Settings → Display → Run Display Calibration`.

Workflow:
1) LEFT edge  
2) TOP edge  
3) RIGHT edge  
4) BOTTOM edge

Controls during calibration:
- Adjust vertical edges (LEFT/RIGHT): `LEFT/RIGHT` changes by 1 px
- Adjust horizontal edges (TOP/BOTTOM): `UP/DOWN` changes by 1 px
- `Select`: confirm edge
- `Key1`: reset current edge to profile default
- `Key2`: cancel calibration and keep previous saved values

**Cache:** calibrated edges + completion flags + effective geometry + backend/rotation + offsets + profile fingerprint are stored in `gui_conf.json` under the `display` block.

### 1.4 Warning behaviors (must be visible and high-signal)

The runtime may produce warnings/events such as:
- `DISPLAY_MODE_MISMATCH`
- `DISPLAY_UNVERIFIED_GEOMETRY`
- `UNSUPPORTED_DISPLAY_SIZE`

**Contract intent:** users should be able to understand what’s wrong and what to do next (e.g., “Run Display Discovery”, “Run Calibration”, “Reset Cache”) without needing a shell.

### 1.5 Dangerous operations & confirmations

For any operation that is destructive (e.g., wipe/purge/FDE) or has a high-impact external effect (e.g., active network transmissions), the UI must:
- Show **plain-language warnings** (what changes, what could be harmed, what cannot be undone)
- Require **explicit confirmation** (ideally more than one step for irreversible actions)
- Make **cancel/stop** prominent and reliable (Key2)
- Avoid “success” messaging until the daemon has verified the post-condition

---

## 2) Rendering / performance audit (Pi Zero 2 W reality)

### 2.1 Rendering model observed in code

**Primary behavior:** the UI is largely **event-driven** (redraw on button presses), which is appropriate for Pi resource constraints.

**Exceptions:** job/progress screens redraw periodically (≈1 Hz), and the stats overlay is refreshed by a background sampler thread.

### 2.2 Frame timing & SPI bandwidth (back-of-the-envelope)

On Linux, the ST7735 path uses SPI. With the current `max_speed_hz` value:
- Full-screen clear is the dominant cost (it writes all pixels).
- Worst-case payload:
  - 128×128×2 bytes ≈ 32 KiB
  - 240×240×2 bytes ≈ 115 KiB

At **4 MHz** SPI (≈0.5 MB/s theoretical), raw transfer time is roughly:
- 128×128: ~64 ms just to push the pixels
- 240×240: ~230 ms just to push the pixels

That does **not** include command overhead or extra drawing operations after clearing.

### 2.3 Allocation hot spots (static audit)

Most allocations are not catastrophic because redraws are infrequent, but they do exist:
- Text wrapping builds `Vec<String>` per dialog render (`draw_dialog`, `wrap_text`).
- Menu rendering formats strings (`format!`) on each redraw.
- Progress screens allocate formatted status lines at 1 Hz.

On Pi, this is usually fine; the bigger performance threat is *I/O frequency* (SPI + GPIO polling + daemon polling), not heap churn—until you scale to higher-res screens.

### 2.4 I/O frequency hot spots

**GPIO polling:** the button loop reads 8 GPIO values repeatedly (tight loop with small sleeps). Idle polling can reach ~200 iterations/sec, i.e., ~1600 GPIO reads/sec.

**Daemon polling:** the stats sampler performs multiple daemon calls every 2 seconds; each call establishes a new client connection in current code.

These are the two biggest levers for reducing jitter/CPU.

---

## 3) Input correctness

### 3.1 Debounce behavior (observed)

Implementation (`crates/rustyjack-ui/src/input.rs`):
- Physical buttons: active-low GPIO reads, polled.
- Debounce window: **120 ms**.
- `wait_for_press()` waits for a press, then **waits for release** before returning.

This prevents bounce and accidental repeats, but it has tradeoffs:
- Rapid navigation can feel “sticky” (especially repeated Up/Down).
- No “press-and-hold” behavior exists for repeating scroll or long-press confirmations.

### 3.2 Repeat / long-press support

There is **no explicit key repeat** and **no long-press detection** today. This impacts:
- Fast scrolling through long lists
- Stronger confirmations (“hold Select for 2 seconds”) for dangerous actions
- Accessibility (a single speed of interaction)

### 3.3 Accidental activation prevention

Strengths:
- Many irreversible actions already use multi-step confirmations (good).
- Confirm dialogs persist until acknowledged (good).
- Key2 is consistently treated as “cancel/escape” in several flows.

Gaps:
- “Global” safety keys (Key2 cancel, Key3 reboot confirmation) are not honored uniformly across all screens/loops.
- Some high-impact operations rely on a single Yes/No confirmation with minimal warning copy.

---

## 4) State coherence (UI vs daemon truth)

### 4.1 Good patterns already present

- Long-running operations are dispatched as daemon jobs; the UI polls job state and shows progress.
- Interface selection flow verifies the interface state after completion before claiming “active”.

### 4.2 Key coherence risks

- Cancellation paths sometimes report “Cancelled” after a short timeout even if the daemon has not confirmed cancellation.
- Some screens rely on periodic sampling; if sampling is delayed or errors, the UI can show stale status lines.

---

## 5) Findings (15)

Format: **Problem → Why → Where → Fix → Fixed version looks like**

### Finding 1 — Key3 reboot confirmation is not globally available
- **Problem:** Key3 maps to “Reboot” in the app-level mapper, but many screens ignore `ButtonAction::Reboot`, making Key3 a dead key outside the main menu.
- **Why:** Violates the documented UX contract; also removes an expected escape hatch during long operations.
- **Where:** `ui/screens/confirm.rs`, `ui/screens/cancel_confirm.rs`, progress loops in `app/menu.rs` and `app/iface_select.rs` (they don’t handle `ButtonAction::Reboot`).
- **Fix:** Add a global button handler in `UiContext` (or a shared helper) that can be invoked by every input loop: Cancel, Reboot, Refresh. Reboot should always be a confirmation dialog, never immediate.
- **Fixed version looks like:** Pressing Key3 on any screen opens the same reboot confirmation dialog; confirming reboots cleanly (optionally requesting job cancel first), and declining returns to the current screen with state intact.

### Finding 2 — Key2 “Cancel” isn’t honored consistently in non-menu screens
- **Problem:** Some screens treat `ButtonAction::Cancel` as a no-op instead of “back/escape”.
- **Why:** Increases user confusion and raises the risk of being “stuck” in a flow—bad during high-impact operations.
- **Where:** `ui/screens/confirm.rs` routes Cancel to a special cancel-confirm, but other screens/loops ignore it; file viewer and other dialogs may treat Cancel differently.
- **Fix:** Standardize: Key2 should always mean “cancel this screen/operation” with a consistent confirmation model for dangerous contexts.
- **Fixed version looks like:** Key2 always either (a) backs out immediately when safe, or (b) opens a clear cancel confirmation (“Stop operation?”) when stopping has side effects.

### Finding 3 — Startup calibration runs unconditionally if pending, with no skip
- **Problem:** On boot, when calibration is required, the UI runs the calibration flow immediately without the “skip” prompt described in the display report.
- **Why:** Can block the user from accessing the UI in scenarios where calibration is optional or deferred; also mismatches documented behavior.
- **Where:** `app/menu.rs` (startup path calling `run_display_calibration_flow(false)` when `display.needs_startup_calibration()`).
- **Fix:** Add a startup prompt: “Calibration recommended. Select = run, Key1 = skip”. Only force calibration if the screen is genuinely unusable without it.
- **Fixed version looks like:** Boot shows a small dialog explaining calibration; user can proceed or skip, and the choice is recorded (e.g., reminder badge in Settings).

### Finding 4 — Display warnings are not user-friendly
- **Problem:** Display diagnostics show warning *codes* but not plain-language explanations or recommended actions.
- **Why:** The warnings are intended to enforce UX safety (“unverified geometry” is a correctness risk), but users can’t act on cryptic codes.
- **Where:** `app/settings.rs::show_display_diagnostics` renders `warnings: ...` with raw strings.
- **Fix:** Map warning codes to human messages + next steps. Show a one-time banner at startup for high-severity warnings.
- **Fixed version looks like:** Diagnostics screen lists each warning with: meaning + “Fix now” action (e.g., jump to discovery/calibration).

### Finding 5 — Backend preference exists, but rendering path is effectively ST7735-only
- **Problem:** The configuration supports a display backend choice, but `Display::new` always initializes the ST7735 SPI LCD path on Linux.
- **Why:** If the backend is set to framebuffer/DRM (per docs), UI may fail to start even though the contract implies multi-backend support.
- **Where:** `crates/rustyjack-ui/src/display.rs::Display::new` (Linux section).
- **Fix:** Either (a) implement the alternate backends, or (b) fail closed with a clear error + instructions, and treat backend selection as “future”.
- **Fixed version looks like:** If backend != st7735, UI either renders via that backend or shows a crisp error (“backend not supported on this build”) instead of attempting SPI init.

### Finding 6 — SPI speed is conservative; may cause sluggish redraws on larger screens
- **Problem:** SPI `max_speed_hz` is set to 4 MHz, which can make full-screen clears slow.
- **Why:** Slow redraws increase perceived latency; progress screens that redraw at 1 Hz can still “stutter”.
- **Where:** `display.rs` SPI config section.
- **Fix:** Make SPI speed configurable with a safe default and a documented “compatibility” mode. Consider probing for stability.
- **Fixed version looks like:** `gui_conf.json` (or env) supports `display.spi_hz`; diagnostics show actual SPI speed and a “Speed test” page.

### Finding 7 — Full-screen clears on every draw are the dominant performance cost
- **Problem:** Many render paths start with `clear()`, writing every pixel even when only a few elements changed.
- **Why:** On SPI displays, full clears dominate time and power.
- **Where:** `display.rs` draw functions (`draw_menu`, `draw_dialog`, `draw_progress_dialog`, etc.).
- **Fix:** Introduce partial redraws (dirty rectangles) for stable layouts; at minimum, avoid clearing the whole screen when updating only a progress bar/line.
- **Fixed version looks like:** Progress screen updates only the bar/text region; menu redraw updates only changed rows; flicker reduced.

### Finding 8 — GPIO polling loop is heavier than it needs to be
- **Problem:** ButtonPad polls 8 lines in a tight loop with small sleeps.
- **Why:** On Pi Zero 2 W, excessive polling can waste CPU and introduce jitter in rendering and daemon comms.
- **Where:** `input.rs::wait_for_press` / `try_read`.
- **Fix:** Use edge-triggered GPIO events (`gpio-cdev` supports line events) or increase sleep/backoff when idle. Keep a low-rate “sanity poll” fallback.
- **Fixed version looks like:** Near-zero CPU when idle; immediate response on press; no change in correctness.

### Finding 9 — Debounce window + release-wait can feel sluggish and can drop rapid presses
- **Problem:** 120 ms debounce plus forced wait-for-release can suppress legitimate fast repeats (especially for scrolling).
- **Why:** Makes the UI feel sticky; harms usability in long lists.
- **Where:** `input.rs` (debounce constants, press handling).
- **Fix:** Make debounce per-button and adaptive (press debounce shorter, release debounce shorter). Add key-repeat for Up/Down with acceleration.
- **Fixed version looks like:** Single taps always register; holding Up/Down scrolls with repeat; accidental double-activations remain rare.

### Finding 10 — Virtual input FIFO can block UI startup if the FIFO exists but no writer is attached
- **Problem:** Opening a FIFO for reading can block until a writer opens the other end.
- **Why:** A development/CI environment could hang unexpectedly.
- **Where:** `input.rs::ButtonPad::new` (`OpenOptions::open` on `RUSTYJACK_INPUT_FIFO`).
- **Fix:** Open FIFO with `O_NONBLOCK` (via `libc`/`fcntl`) or use a regular file-based scripted input format.
- **Fixed version looks like:** UI starts normally even when the FIFO exists; virtual input becomes active when a writer connects.

### Finding 11 — Cancellation status can be misreported as “Cancelled”
- **Problem:** Some cancel flows show “Cancelled” after a short timeout even if the daemon hasn’t confirmed job termination.
- **Why:** Violates the “UI must not claim success before verification” safety rule; especially important for high-impact operations.
- **Where:** `app/menu.rs::dispatch_cancellable` (cancel path: 3-second wait, then unconditional “Attack Cancelled” message).
- **Fix:** Distinguish “Cancel requested” from “Cancelled”. Keep polling longer, or return to a status screen that continues tracking.
- **Fixed version looks like:** After Key2, UI shows “Cancel requested…” and only shows “Cancelled” when the job state transitions to Cancelled/Failed/Completed; otherwise it offers “View status”.

### Finding 12 — Warning copy for high-impact operations is sometimes too weak
- **Problem:** Operation confirmation screens sometimes list only targets/durations without strong safety warnings.
- **Why:** Users can trigger disruptive actions without being reminded about authorization and impact; this is a UX safety failure.
- **Where:** Operation confirm copy (e.g., `ops/wifi.rs` `confirm_lines()` in certain operations).
- **Fix:** Standardize a “High-impact operation” header + explicit authorization/impact warnings; optionally require a hold-to-confirm once long-press exists.
- **Fixed version looks like:** Confirm screen includes: “Authorized use only”, “May disrupt connectivity”, “Key2 stops”; requires an extra step for high-impact actions.

### Finding 13 — Stats sampler opens multiple daemon connections per cycle
- **Problem:** Each stats refresh does several daemon calls; each call creates a new client connection.
- **Why:** Extra overhead and potential jitter; worse under load; unnecessary on constrained hardware.
- **Where:** `stats.rs` + `core.rs::create_client`.
- **Fix:** Batch into a single “dashboard snapshot” IPC call, or reuse a persistent client connection for the sampler.
- **Fixed version looks like:** One request returns all dashboard fields; sampler costs drop; UI overlay updates become smoother.

### Finding 14 — Dashboard refresh is mostly manual; job progress can look stale
- **Problem:** The dashboard view changes mainly on button press (except overlay changes), so it may not reflect ongoing state transitions promptly.
- **Why:** Users watching job progress expect timely updates; stale displays increase confusion.
- **Where:** `app/menu.rs::run_dashboard_mode` (wait-for-press redraw loop).
- **Fix:** Add a low-frequency auto-refresh tick when a job is active, or redraw on sampler updates.
- **Fixed version looks like:** While a job is running, the dashboard refreshes at 1–2 Hz; when idle it stays event-driven.

### Finding 15 — Warning codes exist but lack a persistent “degraded mode” indicator
- **Problem:** Once dismissed, the UI does not show a persistent indicator that the display state is degraded/unverified.
- **Why:** Degraded UI rendering is a correctness/safety hazard (clipped warnings/confirmations are a real safety risk).
- **Where:** Display diagnostics and general rendering paths.
- **Fix:** Add a small, persistent status marker (e.g., `!` in toolbar) when warnings are present; pressing it opens diagnostics.
- **Fixed version looks like:** Toolbar shows `!` until the warning is cleared; users can quickly jump to the remediation screen.

---

## 6) Test plan

### 6.1 Headless tests (CI / developer machines)

**Goal:** validate navigation, input semantics, confirmations, and state coherence without requiring GPIO/SPI.

1) **Introduce a “sim” build mode** (feature flag):
   - Replace `Display` with a console/bitmap renderer on Linux for tests.
   - Replace `ButtonPad` with an in-memory scripted input source.
   - Keep real hardware path as default for release builds.

2) **Unit tests**
   - **Button mapping contract:** ensure physical Button → ButtonAction mapping matches the contract (including Key2/Key3 semantics).
   - **Debounce & repeat logic:** simulate sequences with jitter and verify single activation.
   - **Global key handling:** any screen must handle Key2/Key3 via shared helper.
   - **Warning mapping:** warning code → user message + action link is stable.

3) **Integration tests (UI state machine)**
   - Feed scripted input sequences to traverse menus, open confirm dialogs, cancel, and return home.
   - Use a fake CoreBridge that returns deterministic job state transitions, including:
     - successful completion
     - failure with error chain
     - slow cancellation acknowledgement

4) **Regression scripts (host)**
   - `scripts/ui_replay.sh`: run the UI in sim mode with an input script, capture the rendered output, compare to “golden” snapshots.
   - `scripts/ui_perf_smoke.sh`: run 1000 synthetic redraws and assert max wall-time / allocations under a budget (debug build).

### 6.2 On-device interactive tests (Pi Zero 2 W)

**Goal:** verify the real GPIO + LCD path, plus perceived UX safety.

1) **Button mapping sanity**
   - Run `Settings → Display → Diagnostics` and verify each button registers the correct action.
   - Verify press-and-release behavior (no double triggers).

2) **Display discovery + cache**
   - Reset display cache/calibration.
   - Run display discovery; confirm geometry displayed matches the panel.
   - Reboot; confirm cached geometry is reused (no re-probe loop).

3) **Calibration workflow**
   - Start calibration; verify controls:
     - adjust edge with correct directional keys
     - Key1 resets current edge
     - Key2 cancels and preserves previous values
   - Confirm edges are persisted to `gui_conf.json`.

4) **Warnings**
   - Force an unverified/mismatch condition (by changing rotation/backend/override), verify the UI shows a clear warning banner and the diagnostics marker.

5) **Dangerous operation confirmations**
   - For each destructive operation:
     - verify multi-step confirm
     - verify warning copy is explicit
     - verify Key2 cancels safely
   - For high-impact external operations:
     - verify strong warnings + explicit confirm
     - verify cancel behavior is reliable and does not misreport success/cancelled

6) **Performance checks**
   - Observe CPU usage while idle on main menu (should be low).
   - Run a long job with progress updates; observe redraw smoothness and responsiveness to Key2.
   - Verify no visible flicker that obscures confirm/warning text.

### 6.3 On-device regression scripts (safe)
- `scripts/rj_ui_button_test.sh` (manual-assisted): prints instructions, collects `journalctl` lines for button events if enabled.
- `scripts/rj_ui_display_smoke.sh`: runs discovery/calibration reset sequence and verifies `gui_conf.json` changes, then reboots and checks cache reuse.

---

## Component map (quick)

- **Input:** `crates/rustyjack-ui/src/input.rs`, `ui/input.rs`
- **Rendering + calibration:** `crates/rustyjack-ui/src/display.rs`, `ui/layout.rs`, `ui/theme.rs`, `ui/palette.rs`
- **Navigation + screens:** `app/menu.rs`, `app/settings.rs`, `ops/runner.rs`, `ui/screens/*`
- **Daemon bridge + status sampling:** `core.rs`, `stats.rs`
