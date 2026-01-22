# Rustyjack UI Streamlining — Implementation Playbook (Pi Zero 2 W, Rust-only)

This document **supersedes** the earlier *Rustyjack UI Streamlining Report* by including it **verbatim** (Appendix A) and then expanding every recommendation into an explicit, step-by-step implementation plan, with pseudocode and refactor “recipes”.

Hard requirements (from product direction)
- **Rust-only**: do not add new runtime dependencies on external binaries (no `Command`, no shell-outs).
- **No timer-driven screen transitions**: screens should not *advance* after timeouts; screen-to-screen transitions must be driven by explicit user input or by operation completion/cancellation events (not arbitrary delays).
- **Homogeneous operation pipeline**: **Preflight → Setup → Confirm (Yes/No) → Running (Cancelable) → Result (Acknowledge) → Home**.
- **Cancel always confirmed**: cancel request opens **Yes/No**, “No” returns to Running (not to a previous menu path), “Yes” cancels then shows Result then Home.
- **“No” always goes Home**: at Confirm stage, “No” returns to Home (not to a previous submenu like `/wireless/`).
- **KEY2 semantics consistent**: KEY2 must have one predictable meaning everywhere (see Section 3).
- **Errors must surface clearly**: preflight/setup/runtime/cancel failures must render a clear UI error page with the full cause chain (scrollable) and a safe “Return Home” affordance.
- **No text truncation surprises**: every screen must enforce layout constraints explicitly:
  - Single-line UI elements (menu items, titles) must be **ellipsized deterministically** (never silently cut by the LCD boundary).
  - Multi-line pages must **wrap + paginate/scroll** (never silently drop lines).
- **Titles must match the screen**: every page title must describe what the user is currently doing.

> Notation: file paths below are relative to `watchdog/crates/rustyjack-ui/src/`.


## 1) What’s currently happening in the code (deep dive)

### 1.1 Main loop + navigation
**Where**
- `app.rs`: `pub fn run(&mut self) -> Result<()>` (main event loop)
- `app.rs`: `ButtonAction` handling inside both **Dashboard mode** and **Menu mode**
- `app.rs`: `MenuState::{home, back, enter, move_up, move_down}`

**What happens today**
- UI runs in a single loop: either a dashboard view or a menu view is drawn, then a button press is awaited.
- Navigation uses a **string path** (e.g. `"a"`, `"aw"`, ...) rather than typed IDs.
- `MainMenu` (KEY2) frequently calls `self.menu_state.home()` **without** resetting other state (e.g., active interface) depending on code path.
- `Back` sometimes does extra cleanup (e.g. clears active interface when returning to main menu), while `MainMenu` often does not.

**Concrete inconsistency example**
- In `app.rs`, within the menu loop:
  - `ButtonAction::Back` checks whether we returned to main and clears active interface.
  - `ButtonAction::MainMenu` calls `menu_state.home()` with no cleanup.
  - Result: KEY2 is not a “true home” in terms of state isolation and behaves differently than backing out.

### 1.2 “Start/Cancel” vs immediate-start operations
**Where**
- `app.rs`: a repeated pattern:
  - `show_message("Press SELECT to start", ...)`
  - `choose_from_list("Start?", ["Start", "Cancel"])`
  - then either run immediately or return `Ok(())`
- Functions exhibiting this pattern include (not exhaustive):
  - `recon_gateway`, `recon_arp_scan`, `recon_service_scan`, `recon_mdns_scan`, `recon_bandwidth`, `recon_dns_capture`, `start_dns_spoof`,
  - `launch_deauth_attack`, `launch_evil_twin`, `launch_reverse_shell`,
  - maintenance flows like `install_wifi_drivers`, `purge_logs`, `complete_purge`, `secure_shutdown`.

**Why this is inconsistent**
- Some flows do “Start/Cancel” confirmation, others do not.
- “Cancel” generally returns to the caller (often leaving the user in the submenu they started from), which violates the new requirement (“No always goes Home”).

### 1.3 Cancellation handling is inconsistent and partially inverted
**Where**
- `app.rs`: `confirm_cancel_attack` + `check_attack_cancel` + `dispatch_cancellable`

**What happens today**
- While an attack runs, KEY2/Back triggers cancel *checks*.
- The cancel confirm UI is a two-choice menu like `["Cancel", "Continue"]`, and the mapping is sometimes inverted:
  - Selecting “Cancel” returns `CancelAction::GoMainMenu` (cancel and jump).
  - Selecting “Continue” returns `CancelAction::Continue`.
- Some screens interpret KEY2 as “back to menu” rather than “cancel the operation”.

### 1.4 Error visibility is truncated at the top level
**Where**
- `app.rs` menu Select handler: when `execute_action(action)` errors, it logs the error and shows `show_message("Error", ["Operation failed", shorten_for_display(...)])`.

**Why this is a problem**
- The UI often shows a truncated single-line error, losing the root cause chain (permission denied / underlying reason / which step failed).
- Some errors are logged but never shown.

### 1.5 Text truncation is currently implicit in multiple places
**Where**
- `display.rs`: `draw_toolbar_with_title` truncates title to `MAX_TITLE_CHARS` (currently 16) without an ellipsis.
- `display.rs`: menu labels and other single-line strings can exceed available width and will be clipped by the LCD boundary.
- `app.rs`: multiple uses of `shorten_for_display` in dialogs and error pages.

**Why this matters**
- Users see cut-off information with no indication it’s incomplete.
- Engineers can’t rely on UI fidelity when adding new operations.

### 1.6 Timer-driven UI behavior exists (must be removed for screen transitions)
**Where**
- `app.rs` constructor path includes `thread::sleep(Duration::from_millis(1500))` “Give splash screen time to be visible”.
- Some flows use `try_read_timeout(...)` to refresh content; this is acceptable for *refreshing the same screen*, but **must not** drive silent transitions between screens.


## 2) Target architecture: one pipeline, many operations

The goal is to stop encoding UI flow inside each operation and instead encode it once in an **Operation Runner** that all operations plug into.

### 2.1 Define a single operation pipeline contract

**Pipeline states**
1. **Preflight**: verify prerequisites; if fail → show error page → Home
2. **Setup**: gather required inputs; if user cancels setup → Home
3. **Confirm** (Yes/No): show summary; **No → Home**, Yes → Running
4. **Running**: show progress; KEY2 triggers CancelConfirm; operation completion → Result
5. **CancelConfirm** (Yes/No): No → Running, Yes → request cancellation → Result
6. **Result**: show success/fail/cancel summary; any dismiss input → Home

**Key property**: The only code an operation “owns” is:
- how to preflight,
- how to collect setup data,
- how to start,
- how to report progress,
- how to cancel,
- how to summarize its result.

### 2.2 Suggested module layout (incremental refactor friendly)

Create a `ui/` directory:
- `ui/mod.rs`
- `ui/nav.rs` — `go_home`, global key behavior, and navigation helpers
- `ui/confirm.rs` — Yes/No confirm pages (reusable)
- `ui/error.rs` — error formatting + error dialog
- `ui/text.rs` — text layout constraints (wrap/ellipsis/paginate)
- `ui/runner.rs` — Operation Runner and state machine
- `ui/ops/` — each operation as a small, testable module (grouped by category)
  - `ui/ops/recon.rs`
  - `ui/ops/wireless_attacks.rs`
  - `ui/ops/ethernet.rs`
  - `ui/ops/system.rs`
  - `ui/ops/loot.rs`
  - etc.

**Incremental approach**: you do not need to move all existing functions at once. You can:
- Add the Runner, migrate 1 operation, then migrate the next, etc.
- Keep `execute_action` dispatch working for unmigrated actions while migrated ones use the new pipeline.

### 2.3 Core types to implement

#### `UiContext`
A thin façade around the existing `App` dependencies, to reduce coupling:

```rust
pub struct UiContext<'a> {
    pub core: &'a mut CoreBridge,
    pub display: &'a mut Display,
    pub buttons: &'a mut ButtonPad,
    pub config: &'a mut GuiConfig,
    pub stats: &'a StatsSampler,
    // optional: logging hooks, root path, etc.
}

impl UiContext<'_> {
    pub fn overlay(&self) -> StatusOverlay { self.stats.snapshot() }

    pub fn wait_button(&mut self) -> Result<ButtonAction> {
        Ok(map_button(self.buttons.wait_for_press()?))
    }

    pub fn go_home(&mut self) -> Result<()> { /* see Section 3.1 */ }

    pub fn show_message(&mut self, title: &str, lines: &[String]) -> Result<()> { /* wrap+scroll */ }

    pub fn confirm_yes_no(&mut self, title: &str, body: &[String]) -> Result<bool> { /* Section 3.2 */ }

    pub fn show_error(&mut self, title: &str, err: &anyhow::Error) -> Result<()> { /* Section 4 */ }
}
```

#### `Operation` trait
Use a trait with associated types so each operation can have its own setup and handle types:

```rust
pub trait Operation {
    type Setup;
    type Handle;

    fn id(&self) -> OperationId;
    fn title(&self) -> &'static str;

    fn preflight(&self, ui: &mut UiContext) -> Result<()>;

    /// Return None if the user cancels setup.
    fn setup(&self, ui: &mut UiContext) -> Result<Option<Self::Setup>>;

    /// Lines shown on the Confirm page (summary of setup).
    fn confirm_lines(&self, setup: &Self::Setup) -> Vec<String>;

    fn start(&self, ui: &mut UiContext, setup: Self::Setup) -> Result<Self::Handle>;

    /// Called repeatedly while running.
    fn poll(&self, ui: &mut UiContext, handle: &mut Self::Handle) -> Result<OpPoll>;

    fn cancel(&self, ui: &mut UiContext, handle: &mut Self::Handle) -> Result<()>;

    fn result_lines(&self, outcome: &OpOutcome) -> Vec<String>;
}

pub enum OpPoll {
    InProgress(ProgressSnapshot),
    Finished(OpOutcome),
}

pub struct ProgressSnapshot {
    pub headline: String,          // short line
    pub details: Vec<String>,      // wrapped/paginated
    pub hint: String,              // e.g. "KEY2=Cancel"
}

pub enum OpOutcome {
    Succeeded { summary: String, details: Vec<String> },
    Cancelled { summary: String, details: Vec<String> },
    Failed { summary: String, error: anyhow::Error },
}
```

#### `OperationRunner`
The only place in the codebase that owns the pipeline:

```rust
pub struct OperationRunner;

impl OperationRunner {
    pub fn run<O: Operation>(&self, ui: &mut UiContext, op: &O) -> Result<()> {
        // 1) Preflight
        if let Err(e) = op.preflight(ui) {
            ui.show_error(&format!("Preflight failed: {}", op.title()), &e)?;
            return ui.go_home();
        }

        // 2) Setup
        let Some(setup) = match op.setup(ui) {
            Ok(v) => v,
            Err(e) => {
                ui.show_error(&format!("Setup failed: {}", op.title()), &e)?;
                return ui.go_home();
            }
        } else {
            return ui.go_home();
        };

        // 3) Confirm (Yes/No)
        let confirm_body = op.confirm_lines(&setup);
        let yes = ui.confirm_yes_no(&format!("Run {}", op.title()), &confirm_body)?;
        if !yes {
            return ui.go_home();
        }

        // 4) Start + Running loop
        let mut handle = match op.start(ui, setup) {
            Ok(h) => h,
            Err(e) => {
                ui.show_error(&format!("Start failed: {}", op.title()), &e)?;
                return ui.go_home();
            }
        };

        loop {
            // poll op for progress/result
            let poll = op.poll(ui, &mut handle)?;
            match poll {
                OpPoll::InProgress(p) => {
                    ui.render_running(op.title(), &p)?; // draw, no trunc surprises
                    match ui.wait_button()? {
                        ButtonAction::MainMenu => {
                            // Cancel request
                            let stop = ui.confirm_yes_no(
                                &format!("Cancel {}", op.title()),
                                &[
                                    "Stop the operation?".into(),
                                    "Yes = stop now".into(),
                                    "No = continue running".into(),
                                ],
                            )?;
                            if stop {
                                if let Err(e) = op.cancel(ui, &mut handle) {
                                    ui.show_error(&format!("Cancel failed: {}", op.title()), &e)?;
                                    let outcome = OpOutcome::Failed { summary: "Cancel failed".into(), error: e };
                                    ui.render_result(op.title(), &op.result_lines(&outcome))?;
                                    ui.wait_any_key()?;
                                    return ui.go_home();
                                }
                                let outcome = OpOutcome::Cancelled { summary: "Cancelled by user".into(), details: vec![] };
                                ui.render_result(op.title(), &op.result_lines(&outcome))?;
                                ui.wait_any_key()?;
                                return ui.go_home();
                            }
                        }
                        ButtonAction::Back => {
                            // In Running state, KEY1 can be mapped to "details" or ignored.
                        }
                        ButtonAction::Select | ButtonAction::Up | ButtonAction::Down | ButtonAction::Refresh => {}
                        ButtonAction::Reboot => { /* keep existing reboot confirm */ }
                    }
                }
                OpPoll::Finished(outcome) => {
                    let lines = op.result_lines(&outcome);
                    ui.render_result(op.title(), &lines)?;
                    ui.wait_any_key()?;       // user-driven exit (no timer)
                    return ui.go_home();
                }
            }
        }
    }
}
```

> Note: `wait_any_key()` is a helper that consumes a single button press and returns.


## 3) Fix-by-fix implementation guide (nothing left to guess)

Each fix uses the template:
**Problem → Where → Why → How to fix → What “fixed” looks like → Implementation steps**

---

### 3.1 Fix: Implement a real `go_home()` and use it everywhere

**Problem**
- KEY2 (“Main Menu”) is not a reliable “reset-to-home” action. Some code paths clear the active interface and other state; many do not.

**Where**
- `app.rs`:
  - Dashboard mode: `ButtonAction::MainMenu` calls `menu_state.home()` only.
  - Menu mode: `ButtonAction::MainMenu` calls `menu_state.home()` only.
  - `choose_from_menu` and other selector dialogs call `menu_state.home()` directly.
  - Cleanup logic exists only in the `Back` branch when detecting “returned to main”.

**Why**
- This creates “state ghosts” (active interface pinned, MITM session still tracked, dashboard mode not reset, etc.).
- It blocks the desired invariant: Home is always a clean slate and safe starting point.

**How to fix**
- Add a single `App::go_home(&mut self)` that:
  1. Resets menu path + selection
  2. Clears any operation-scoped state (dashboard view, MITM session, in-memory “active operation” marker)
  3. Clears the active network interface in the core daemon (and persists settings)
  4. Ensures the display is redrawn as the main menu on the next loop iteration

**What “fixed” looks like**
- KEY2 always returns to the exact same Home state no matter which page you’re on.
- Home always implies isolation: no active interface, no half-active “session” state, no leftover overlays.

**Implementation steps**
1. **Create the method**
   - In `app.rs` implement:
     ```rust
     impl App {
         fn go_home(&mut self) -> Result<()> {
             // 1) UI state
             self.dashboard_view = None;
             self.active_mitm = None;

             // 2) Menu state
             self.menu_state.home();

             // 3) Core isolation: clear active interface
             if let Err(e) = self.core.clear_active_interface() {
                 // show error but still attempt to proceed home
                 tracing::warn!("clear_active_interface failed: {:#}", e);
                 self.show_error_dialog("Home cleanup failed", &e)?;
             }

             // 4) Persist settings (if active interface affects config)
             let _ = self.config.store_settings();

             Ok(())
         }
     }
     ```
2. **Replace all `menu_state.home()` direct calls**
   - Replace every `self.menu_state.home();` in response to KEY2 with `self.go_home()?;`
   - Specifically update:
     - Dashboard KEY2 handler
     - Menu KEY2 handler
     - `choose_from_menu` KEY2 handler
     - file viewer KEY2 handler
     - any other “MainMenu” branch found via search: `rg "menu_state\.home\(" crates/rustyjack-ui/src/app.rs`
3. **Replace special Back→main cleanup**
   - Remove or simplify the “if returned to main, clear active interface” logic in the Back handler. That behavior should now live only in `go_home()`.
   - Back should mean “go up one menu level” and should not do cross-cutting cleanup.
4. **Add one invariant comment + test**
   - Add a doc comment on `go_home()` stating it is the only place that clears global state.
   - Add a unit test in `ui/nav.rs` (or a small test in `app.rs`) verifying that calling `go_home()` sets `dashboard_view=None` and `menu_state.path()=="a"`.

---

### 3.2 Fix: A single reusable Yes/No confirm page

**Problem**
- Multiple confirmation UIs exist (“Start/Cancel”, “Cancel/Continue”, etc.), with different semantics and different “No” destinations.

**Where**
- Many operations use `choose_from_list("Start?", ["Start", "Cancel"])`
- `confirm_cancel_attack` uses `["Cancel", "Continue"]`

**Why**
- Users have to learn a different “confirm language” per operation.
- Developers re-implement the same UX repeatedly, increasing spaghetti.

**How to fix**
- Implement exactly one confirm function:
  - `confirm_yes_no(title, lines) -> bool`
  - “Yes” is index 0, “No” is index 1
  - KEY2 maps to “No” (and returns Home at the call site)
  - Back can map to “No” (optional, but be consistent)

**What “fixed” looks like**
- Every confirm screen looks identical, behaves identical, and always returns a boolean.

**Implementation steps**
1. Implement in `ui/confirm.rs`:
   ```rust
   pub fn confirm_yes_no(ui: &mut UiContext, title: &str, body: &[String]) -> Result<bool> {
       // render dialog: title + body + "" + "[Yes]" "[No]"
       let mut idx = 0usize;
       loop {
           ui.render_yes_no(title, body, idx)?;
           match ui.wait_button()? {
               ButtonAction::Up | ButtonAction::Down => idx ^= 1,
               ButtonAction::Select => return Ok(idx == 0),
               ButtonAction::Back => return Ok(false),
               ButtonAction::MainMenu => return Ok(false),
               _ => {}
           }
       }
   }
   ```
2. Update `App::choose_from_list` call sites:
   - For the “Start/Cancel” pattern:
     - Replace with `if !confirm_yes_no("Confirm", summary_lines)? { return ui.go_home(); }`
3. Delete/retire `confirm_cancel_attack` and `confirm_cancel_update`
   - Replace with `confirm_yes_no("Cancel <op>?", ...)`
4. Ensure **No → Home** is handled by call sites:
   - For setup confirm: `if !yes { ui.go_home()?; return Ok(()); }`

---

### 3.3 Fix: Standardize Running screens + cancel semantics (KEY2 = Cancel)

**Problem**
- Running screens differ widely: some allow KEY2 to go home, some interpret it as cancel, some interpret Back as cancel, and cancellation UI varies.

**Where**
- `dispatch_cancellable` + `check_attack_cancel`
- other running loops (e.g., MITM status loop) interpret KEY2 as home

**Why**
- Users build muscle memory; inconsistent cancel behavior is a foot-gun, especially on a tiny device where “oops” is expensive.

**How to fix**
- Adopt a single policy:
  - While an operation is in Running state:
    - **KEY2 = request cancel**
    - Cancel request always opens a Yes/No confirm dialog
    - “No” returns to Running
    - “Yes” triggers cancellation, then shows Result, then Home
  - Back during Running does **not** navigate menus (either ignored or used for optional “details” page)
- Implement this policy once inside `OperationRunner` (Section 2.3), not per operation.

**What “fixed” looks like**
- Every Running screen includes a line like: `"KEY2 = Cancel"` (or `"KEY2=Cancel"`).
- No operation directly calls `menu_state.home()` while running; it always goes through cancel.

**Implementation steps**
1. Remove all direct “MainMenu → home” behavior inside per-operation loops.
2. In `OperationRunner`, treat `ButtonAction::MainMenu` during Running as cancel-request.
3. In legacy code (before full migration), for `dispatch_cancellable`:
   - Replace `check_attack_cancel` with a call to the new `confirm_yes_no`.
   - Ensure cancel returns `CancelAction::CancelRequested` and does **not** navigate.
4. Ensure `dispatch_cancellable` returns an `OpOutcome::Cancelled` instead of `Ok(None)` so the pipeline can show a Result screen consistently.

---

### 3.4 Fix: Migrate operations to `OperationRunner` (repeatable recipe)

This is the core refactor. Do it one operation at a time.

#### Migration recipe (for any existing operation function)
**Example input**: `fn recon_gateway(&mut self) -> Result<()>`

**Step A — Identify the operation phases**
- Preflight: anything like “is interface selected?”, “is tool installed?”, “is kernel module loaded?”
- Setup: prompts/selectors (interface selection, target selection, mode selection)
- Confirm: the current “Start/Cancel” prompt becomes “Yes/No” confirm and must **go home on No**
- Start: dispatch core command (often `core.start_core_command(...)`)
- Running: poll status + render progress; KEY2 triggers cancel confirm
- Result: show outcome page; require user input to exit; then go home

**Step B — Create an `Operation` implementation**
- In `ui/ops/recon.rs`:
  ```rust
  pub struct ReconGateway;

  impl Operation for ReconGateway {
      type Setup = ReconGatewaySetup;
      type Handle = JobHandle; // or custom

      fn id(&self) -> OperationId { OperationId::ReconGateway }
      fn title(&self) -> &'static str { "Gateway Recon" }

      fn preflight(&self, ui: &mut UiContext) -> Result<()> {
          ensure_interface_selected(ui).context("No interface selected")?;
          Ok(())
      }

      fn setup(&self, ui: &mut UiContext) -> Result<Option<Self::Setup>> {
          // gather params; if user cancels selector => None
      }

      fn confirm_lines(&self, setup: &Self::Setup) -> Vec<String> {
          vec![
              format!("Interface: {}", setup.iface),
              format!("Mode: {}", setup.mode),
              // ...
          ]
      }

      fn start(&self, ui: &mut UiContext, setup: Self::Setup) -> Result<Self::Handle> {
          ui.core.start_core_command(CoreCommand::ReconGateway { /* ... */ })
      }

      fn poll(&self, ui: &mut UiContext, handle: &mut Self::Handle) -> Result<OpPoll> {
          let job = ui.core.job_status(handle.id)?;
          match job.state {
              JobState::Running | JobState::Queued => Ok(OpPoll::InProgress(snapshot_from(job))),
              JobState::Succeeded => Ok(OpPoll::Finished(OpOutcome::Succeeded { summary: "Done".into(), details: vec![] })),
              JobState::Cancelled => Ok(OpPoll::Finished(OpOutcome::Cancelled { summary: "Cancelled".into(), details: vec![] })),
              JobState::Failed => Ok(OpPoll::Finished(OpOutcome::Failed { summary: "Failed".into(), error: anyhow::anyhow!(job.message) })),
          }
      }

      fn cancel(&self, ui: &mut UiContext, handle: &mut Self::Handle) -> Result<()> {
          ui.core.cancel_job(handle.id)?;
          Ok(())
      }

      fn result_lines(&self, outcome: &OpOutcome) -> Vec<String> {
          match outcome { /* render */ }
      }
  }
  ```

**Step C — Hook it into the menu**
- Create `OperationId` enum and store it as `MenuAction::Run(OperationId)`
- `execute_action` becomes:
  ```rust
  MenuAction::Run(op_id) => self.runner.run(&mut ui_ctx, registry.get(op_id))?,
  ```

**Step D — Delete old flow code**
- Once migrated, remove the old function or keep it behind `#[cfg(feature="legacy-ui")]` temporarily.

---

### 3.5 Fix: Menu path correctness (duplicate keys + typed IDs)

**Problem**
- `menu.rs` contains a duplicate key insertion: `"aw"` is inserted twice with different nodes, overwriting earlier entries.

**Where**
- `menu.rs`: search for `nodes.insert("aw"` — you’ll find two insertions.

**Why**
- Hidden bugs: entries disappear depending on insertion order.
- Stringly-typed paths are brittle and hard to refactor safely.

**How to fix**
- Short-term: remove the duplicate and ensure uniqueness.
- Long-term: replace string paths with a typed `MenuId` enum so duplicates become compile errors.

**Implementation steps**
1. **Immediate fix**: remove the duplicate `nodes.insert("aw", ...)` and decide the intended node.
2. **Introduce typed IDs**:
   ```rust
   #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
   pub enum MenuId { Root, Wireless, WifiRecon, WifiAttacks, Ethernet, System, Loot, /* ... */ }
   ```
3. Change `MenuTree` to use `HashMap<MenuId, MenuNode>`.
4. Replace `menu_state.path(): &str` with `menu_state.current(): MenuId`.
5. Provide a small mapping to display breadcrumbs like `/wireless/attacks/` if desired, but keep IDs typed.

---

### 3.6 Fix: One authoritative `MENU_VISIBLE_ITEMS` constant

**Problem**
- The number of visible menu items is duplicated and inconsistent (`7` in `MenuState::move_up`, `9` elsewhere).

**Where**
- `app.rs`: `MenuState::move_up` uses `const VISIBLE: usize = 7;`
- `app.rs`: `run` uses `const VISIBLE: usize = 9;`
- `choose_from_menu` uses `const VISIBLE: usize = 9;`
- `display.rs` implicitly constrains what fits based on y positions and item height.

**Why**
- Off-by-one scroll bugs and awkward selection jumps.

**How to fix**
- Define `MENU_VISIBLE_ITEMS` once (preferably in `display.rs` because it knows layout).
- Expose it via `Display::menu_visible_items()` or a shared `ui/layout.rs`.

**Implementation steps**
1. Add in `display.rs`:
   ```rust
   pub const MENU_ITEM_HEIGHT: u32 = 12;
   pub const MENU_VISIBLE_ITEMS: usize =
       ((LCD_HEIGHT as u32 - MENU_TOP as u32) / MENU_ITEM_HEIGHT) as usize;
   ```
2. Replace all hardcoded VISIBLE constants with `Display::MENU_VISIBLE_ITEMS`.
3. Update selection logic and add unit tests for scrolling behavior (select top/bottom, verify offset updates).

---


## 4) Requirements added in this revision

### 4.1 Remove timer-driven screen transitions

**Problem**
- There is at least one explicit timer delay used to “let splash be visible” and other fixed delays that exist purely for pacing.

**Where**
- `app.rs`: `thread::sleep(Duration::from_millis(1500))` after splash.

**Why**
- Violates “screen changes only when user acts” and introduces nondeterminism.

**How to fix**
- Remove any sleeps whose only purpose is UI pacing.
- If you want a splash, either:
  - keep it while initialization is happening (not a timer), and then move to Home, or
  - show a “Ready” page and wait for a button (user-driven).

**Implementation steps**
1. Delete the `thread::sleep(Duration::from_millis(1500))`.
2. Optionally replace with:
   ```rust
   display.show_splash_screen(...)?;
   // initialization work...
   display.draw_dialog(&["Ready".into(), "Press SELECT".into()], &stats.snapshot())?;
   loop { if map_button(buttons.wait_for_press()?) == ButtonAction::Select { break; } }
   ```
3. Grep for `try_read_timeout(` and ensure it is never used to auto-navigate away from a page.
4. Grep for `thread::sleep(` and classify each occurrence:
   - **Allowed**: hardware stabilization, retries, backoff in background loops
   - **Disallowed**: “show this page for N seconds then continue”

### 4.2 Show full, scrollable error details

**Problem**
- Top-level error UI truncates errors.

**Where**
- `app.rs` menu select error handler uses `shorten_for_display(&e.to_string(), 90)`.

**Why**
- It hides the actionable root cause (e.g. permission denied, missing interface, daemon unreachable).

**How to fix**
- Implement a standard error formatting function that:
  - Shows the top-level message
  - Shows the entire `source()` chain (anyhow supports `err.chain()`)
  - Shows any structured context (operation name, stage)
- Render via the existing scrollable dialog pattern (like `show_message` does), never truncated.

**Implementation steps**
1. Add `ui/error.rs`:
   ```rust
   pub fn format_error_chain(err: &anyhow::Error) -> Vec<String> {
       let mut out = vec![];
       for (i, cause) in err.chain().enumerate() {
           if i == 0 { out.push(format!("{}", cause)); }
           else { out.push(format!("caused by: {}", cause)); }
       }
       out
   }
   ```
2. Add `UiContext::show_error(title, err)` that calls `format_error_chain` and then `show_message`.
3. Replace the top-level handler:
   ```rust
   if let Err(e) = self.execute_action(action) {
       self.show_error_dialog("Operation failed", &e)?;
   }
   ```
4. Ensure each operation uses `.context("...")` at every boundary:
   - preflight failures: `context("Preflight: ...")`
   - setup failures: `context("Setup: ...")`
   - start failures: `context("Start: ...")`
   - poll failures: `context("Status: ...")`
   - cancel failures: `context("Cancel: ...")`

### 4.3 Enforce layout constraints (no surprise truncation)

**Problem**
- Titles and menu labels are truncated silently or clipped by the LCD boundary.

**Where**
- `display.rs`: `draw_toolbar_with_title` truncates to 16 chars without ellipsis.
- menu labels can overflow width.

**Why**
- Users see ambiguous labels and missing information, and developers can’t reason about UI correctness.

**How to fix**
- Introduce a small layout module with:
  - `max_columns(style, reserved_px) -> usize`
  - `ellipsize(s, max_cols) -> String`
  - `wrap_lines(s, max_cols) -> Vec<String>`
  - `paginate(lines, max_visible_lines) -> Vec<Page>`
- Use it in every renderer.

**Implementation steps**
1. Create `ui/text.rs` with helpers:
   ```rust
   pub fn ellipsize(s: &str, max: usize) -> String {
       if s.chars().count() <= max { return s.to_string(); }
       if max <= 3 { return "...".chars().take(max).collect(); }
       let mut out: String = s.chars().take(max - 3).collect();
       out.push_str("...");
       out
   }
   ```
2. Update `draw_toolbar_with_title` to use ellipsis, not raw truncate.
3. Update `draw_menu` to ellipsize each item label to fit.
4. For dialogs:
   - continue to wrap using `wrap_text` or migrate to `embedded-text` `TextBox` if you want pixel-accurate wrapping.
   - ensure callers use scroll when body lines exceed visible capacity (your `show_message` already does this).
5. Add an explicit “capacity struct”:
   ```rust
   pub struct DialogCapacity { pub cols: usize, pub visible_lines: usize }
   pub fn dialog_capacity() -> DialogCapacity { ... }
   ```
   and use it everywhere instead of hardcoded 20/7 values.

### 4.4 Screen titles must be specific

**Problem**
- Some pages show generic titles or reused titles that don’t match current context.

**How to fix**
- The Runner owns canonical titles by state:
  - Confirm: `"Run <Operation>?"`
  - Running: `"<Operation>"`
  - CancelConfirm: `"Cancel <Operation>?"`
  - Result: `"<Operation> Result"`
  - Error: `"Error: <Stage>"`

**Implementation steps**
1. Add helper functions in `ui/runner.rs`:
   ```rust
   fn title_confirm(op: &dyn Operation) -> String { format!("Run {}?", op.title()) }
   fn title_cancel(op: &dyn Operation) -> String { format!("Cancel {}?", op.title()) }
   fn title_result(op: &dyn Operation) -> String { format!("{} Result", op.title()) }
   ```
2. Remove ad-hoc titles in per-operation code (let runner supply them).


## 5) Reference patterns to borrow (Rust-only, no external binaries)

These are not mandatory dependencies. They’re examples of well-trodden patterns that map closely to your UI style:

1. **embedded-graphics simulator** (useful for UI regression tests and screenshots on a dev machine)
   - Lets you run the same drawing code on desktop and even dump frames to PNG for CI snapshot testing.
   - References:
```text
https://docs.rs/embedded-graphics-simulator/
https://github.com/embedded-graphics/simulator
```

2. **embedded-menu** (menu/state separation patterns)
   - Shows how to keep menu structure separate from rendering and input handling.
   - Even if you don’t adopt it, the separation-of-concerns is the lesson.
```text
https://docs.rs/embedded-menu/latest/
```

3. **embedded-text** (multiline text box + wrapping)
   - Can replace hand-rolled wrapping logic if you want bounding-rectangle aware layout with alignment.
```text
https://docs.rs/embedded-text/
https://github.com/embedded-graphics/embedded-text
```

4. **State machine modeling with enums** (Rust pattern)
   - The key insight: use `enum` states and `match` transitions; don’t encode “state” across many booleans and scattered functions.
```text
https://doc.rust-lang.org/book/ch06-00-enums.html
```


## 6) “Definition of done” checklist (per operation)

For each migrated operation, verify:

Pipeline
- [ ] Preflight runs before setup and shows a scrollable error page on failure.
- [ ] Setup returns `None` on user cancellation and returns Home.
- [ ] Confirm is a Yes/No page. “No” returns Home.
- [ ] Running page clearly shows:
  - operation name
  - progress info
  - `"KEY2 = Cancel"`
- [ ] Cancel request opens Yes/No. “No” returns Running. “Yes” cancels and shows Result.
- [ ] Result page requires a user input to exit (no timed auto-close).
- [ ] Exiting Result always returns Home via `go_home()`.

Input semantics
- [ ] KEY2 is consistent everywhere:
  - Home/Menu: go_home
  - Running: cancel-request
  - Confirm/CancelConfirm/Result/Error: treated as “No”/“Dismiss → Home”
- [ ] Back never performs global cleanup; it only navigates “up” within the current screen semantics.

Text/layout
- [ ] No silent clipping: titles and single-line labels are ellipsized.
- [ ] Multi-line pages wrap + scroll/paginate.
- [ ] Every page has a correct, specific title.

Error reporting
- [ ] Full error cause chain visible in UI.
- [ ] Errors include operation + stage context.



---

## Appendix A — Original report (verbatim)

# Rustyjack UI Streamlining Report (Pi Zero 2 W, Rust-only)

Audience: senior Rust developers working on the **Rustyjack UI** (`crates/rustyjack-ui`)  
Scope: UI consistency + flow architecture (not changing underlying “operations” behavior beyond making start/cancel semantics consistent and cancellation **actually** cancel).

Constraints (from product requirements)
- **Rust only** for all new work.
- **No shelling out to external binaries** from this point on.
- This will be the **only** operation on the Pi, so it may take full control of the hardware.

---

## 0) Executive summary

The current UI is functional but hard to extend because each operation implements its own mini “wizard / confirm / progress / cancel / results” loop. That leads to:
- inconsistent confirmation (“Start/Cancel” vs no confirmation at all),
- inconsistent cancellation semantics (sometimes “go back”, sometimes “go main”, sometimes cancellation doesn’t cancel),
- inconsistent “home” behavior (KEY2/Main Menu does not always trigger the same side-effects as returning via Back),
- code duplication spread across a very large `app.rs`.

### The highest leverage fix
Introduce a **single, reusable Operation Runner** (a small state machine) that enforces one pipeline for all operations:

**Preflight & setup → Confirm (Yes/No) → Running (progress + “Cancel” instruction) → Cancel confirm (Yes/No) → Result → Home**

Then convert existing operations to use it incrementally.

---

## 1) What the codebase is doing today (as-is)

### 1.1 UI architecture (render + input + menu + actions)
- **Rendering**: `display.rs` renders to an ST7735 LCD using `embedded-graphics` (Linux via `linux-embedded-hal` + SPI/GPIO).  
- **Input**: `input.rs` reads physical buttons (GPIO) and maps them to a `ButtonAction` via `App::map_button` in `app.rs` (e.g., KEY2 → `MainMenu`).
- **Menu navigation**: `MenuTree` + `MenuState` controls the hierarchical menu by *string IDs* like `"a"`, `"aw"`, `"awao"`, etc.
- **Actions**: Selecting a menu item calls `execute_action(...)`, which dispatches to large per-operation functions (e.g., `launch_probe_sniff`, `launch_deauth_attack`, `system_update`, pipelines, recon tools, ethernet tools, etc.).
- **Daemon bridge**: `core.rs` (`CoreBridge`) talks to a daemon via `rustyjack_client`. It can:
  - execute commands synchronously: `core.dispatch(cmd)`
  - start a cancellable background job: `core.start_core_command(cmd)` then poll `core.job_status(job_id)` and `core.cancel_job(job_id)`

### 1.2 There are currently *multiple* “operation pipelines”
You can roughly bucket operation implementations into:
1) **Job-based (good direction)**: uses `dispatch_cancellable(...)` which starts a daemon job and can cancel it (e.g., “Probe Sniff” uses it).
2) **Manual thread (problematic)**: spawns a UI thread that calls `core.dispatch(...)` while UI loops a local progress screen (e.g., “Deauth Attack”).
3) **Ad-hoc / mixed**: custom loops, extra “Press SELECT to start” screens, sometimes an extra progress “splash” before calling a job, sometimes no confirmation at all.

This is the root of the inconsistency: each new operation tends to copy/paste and drift.

---

## 2) Target UX contract (what we want “fixed” to look like)

**For every long-running or meaningful operation** (wireless / ethernet / update / storage tasks, etc.):

1) **Preflight + setup**  
   Gather required inputs (interface, target, duration, etc.) and validate prerequisites.
2) **Confirm screen (Yes/No menu)**  
   - Shows a short summary of what will happen (parameters, risks, duration).
   - Options: `Yes` / `No`.
   - **No always returns to Home** (no “back to /wireless/” or other menu path).
3) **Running screen**  
   - Shows progress (time elapsed/remaining, percentage when known, a stage label).
   - Shows one consistent instruction: “Press KEY2 to cancel” (or whichever single button you standardize on).
4) **Cancel confirmation (Yes/No menu)**  
   - “Cancel operation?” → `Yes` cancels → result summary → Home  
   - `No` returns to Running (no detours).
5) **Result screen**  
   - Shows success/failure summary, any output path hints.
   - “Press any button” then returns to Home.

This makes operations “slot-in-able”: adding a new operation becomes mostly implementing “preflight/setup/command/result formatting”, not re-implementing UI control flow.

---

## 3) Issues found (problem → where → why → how to fix → what fixed looks like)

### Category A — Navigation & “Home” consistency

#### A1) KEY2/Main Menu does not trigger the same side-effects as returning via Back
**Problem**  
Returning to main menu via Back triggers interface isolation cleanup; returning via Main Menu does not.

**Where**  
`crates/rustyjack-ui/src/app.rs`:
- Back branch clears active interface when transitioning to `"a"` (main): lines **1046–1058**
- MainMenu branch just calls `self.menu_state.home()` with **no cleanup**: line **1073**

**Why it’s a problem**  
If “Home” is an *enforced safe state* (the comment says “HARDWARE INTERFACE ISOLATION”), then there must be exactly one well-defined “go home” behavior. Otherwise, KEY2 sometimes leaves “active interface” set, and sometimes doesn’t—classic “this button sometimes works differently”.

**How to fix**  
Create a single helper:
- `fn go_home(&mut self, reason: HomeReason)` that:
  - sets `menu_state.home()`
  - clears active interface (and any other “reset to safe state” actions)
  - resets any per-operation UI state (dashboard view, overlays, temporary selections)

Then replace all `menu_state.home()` calls that are intended as “exit to home” with `go_home(...)`.

**What fixed looks like**  
From *anywhere* in the UI (menus, progress, dialogs, dashboards), “Home” means the same thing and triggers the same cleanup.

---

### Category B — Operation confirmation is inconsistent

#### B1) Some operations start immediately after setup with no “Perform action?” Yes/No
**Problem**  
Some flows go from setup straight into execution without an explicit Yes/No confirmation.

**Where (examples)**  
- `launch_probe_sniff`: after duration selection, it immediately dispatches the job (`dispatch_cancellable`) with no confirm screen. Lines **6004–6041** show duration selection and immediate start.  
- It also shows a “running indefinitely” message *after* the selection (lines **6021–6030**) but still no “Yes/No”.

**Why it’s a problem**  
Users don’t get a consistent “point of no return.” They can’t review settings and back out safely, and it trains muscle memory inconsistently.

**How to fix**  
Make “Confirm Yes/No” a **required state** in the Operation Runner:
- setup returns a typed `OpContext` (e.g., `{ iface, duration, channel_hop: true }`)
- runner renders a standardized confirm screen from that context
- `No` returns Home
- `Yes` starts execution

**What fixed looks like**  
All operations follow: setup → confirm → running. No exceptions.

---


#### B2) Confirmation screens use inconsistent labels and button instructions
**Problem**  
Confirmation UIs vary between:
- a two-item list like `Start/Cancel`,
- a dialog that says “Press SELECT to start”,
- or no explicit confirmation at all.

**Where (examples)**  
- WiFi recon tools frequently display a “Press SELECT to start” dialog and then a `choose_from_list("Start ...?", ["Start", "Cancel"])` prompt (e.g., `recon_gateway` around `app.rs` lines **4595–4614**).
- Other flows use different wording like “Start update / Cancel” (update flow), or “Start Pipeline / Cancel”.

**Why it’s a problem**  
It forces users to relearn the UI every time. For developers, it encourages copy/paste and creates a maintenance surface where small UX differences multiply.

**How to fix**  
Introduce a single component `confirm_yes_no(title, summary_lines)` and use it everywhere. If you want richer copy, keep the **options** always `Yes`/`No`, and put detail in the summary body.

**What fixed looks like**  
Every operation’s “point of no return” looks the same: a Yes/No menu with consistent navigation and consistent return-to-home behavior.

#### B3) “No/Cancel” currently returns to *whatever menu you came from* (not always Home)
**Problem**  
In many functions, declining a confirmation just returns `Ok(())` without changing `menu_state`, leaving the user in the previous submenu. This is exactly the drift you called out (e.g., bouncing back into `/wireless/`).

**Where (examples)**  
- `recon_gateway`: `if confirm != Some(0) { return Ok(()); }` (around `app.rs` lines **4611–4614**). Similar patterns are repeated across recon operations.

**Why it’s a problem**  
Your desired contract is: *No means abort the operation flow and go Home*, not “rewind one step into a subtree.”

**How to fix**  
In the Operation Runner, make `No` call `go_home()` unconditionally. When converting existing functions before the runner exists, do the minimal local fix: replace `return Ok(())` after a “No” with `self.go_home(...); return Ok(());`.

**What fixed looks like**  
Selecting `No` never drops you back into a category submenu. It always returns Home (and performs the same cleanup as any other Home transition).

### Category C — Cancellation semantics are inconsistent (and sometimes ineffective)

#### C1) Cancel confirmation text + destination logic is needlessly complex and inconsistent
**Problem**  
Cancel confirmation depends on whether the user pressed Back or Main Menu, and includes a “Return to previous menu vs main menu” concept.

**Where**  
`check_attack_cancel` + `confirm_cancel_attack` in `app.rs` lines **554–614**; similar duplication for updates in lines **616–666**.

**Why it’s a problem**  
- Users shouldn’t have to think about *where* they’ll land when canceling; canceling should cancel.
- Code duplication (`attack` vs `update`) increases drift.
- It contradicts the requested behavior: cancellation should be a simple Yes/No, and “No” should *not* return to submenus.

**How to fix**  
Replace `CancelAction::{GoBack, GoMainMenu}` with a simpler model:
- `enum CancelDecision { Continue, Cancel }`
- A single `confirm_cancel(label: &str) -> CancelDecision` that always returns to **Running** on `No`, and always goes to **Home** on `Yes` (after cancellation + result).

**What fixed looks like**  
In-progress screen: “Cancel?” → Yes cancels and returns home; No resumes. No destination branching.

---

#### C2) “Deauth Attack” cancellation currently cancels the UI, not necessarily the operation
**Problem**  
The “Deauth Attack” flow spawns a thread that calls `core.dispatch(...)`. The UI’s cancel path sets `cancelled = true` and breaks the loop, but it **does not cancel the underlying work**.

**Where**  
`launch_deauth_attack`:
- spawns thread at lines **5604–5629**
- cancel path just breaks UI loop at **5640–5650**
- there is no `core.cancel_job(...)` call for this operation

**Why it’s a problem**  
- Users believe the operation stopped (“Attack stopped early”), but the daemon may still be running it.
- It creates “phantom operations” running after the UI has returned home.
- It makes KEY2/Home behavior appear broken.

**How to fix**  
Convert Deauth Attack to the same job-based model used elsewhere:
- Build a `Commands::Wifi(WifiCommand::Deauth(...))`
- Start it via `core.start_core_command(...)`
- Track `job_id` and cancel with `core.cancel_job(job_id)` in the Operation Runner

(You already do this inside attack pipelines, where “Deauth” runs via `dispatch_cancellable`.)

**What fixed looks like**  
Canceling Deauth actually cancels the job; no background ghost work; result screen reflects the real cancellation.

#### C3) Progress screens mention different cancel buttons (and sometimes don’t mention KEY2 at all)
**Problem**  
Some screens instruct “Press Back to cancel”, others render labels like `Deauth [LEFT=Cancel]`, and `dispatch_cancellable` reacts to both Back and MainMenu—but the user-facing copy doesn’t consistently describe that.

**Where (examples)**  
- Many recon operations show `"Press Back to cancel"` before starting a cancellable job (e.g., `recon_gateway` progress splash at `app.rs` lines **4616–4625**).
- `dispatch_cancellable`’s progress dialog uses labels like `[LEFT=Cancel]` (see its render message construction around `app.rs` lines **728–744**).
- Some indefinite-mode dialogs mention `LEFT/Main=Stop` while others only mention `LEFT`.

**Why it’s a problem**  
Users learn the wrong muscle memory, and KEY2’s expected behavior becomes ambiguous. This also increases support load (“Which button cancels on this screen?”).

**How to fix**  
Pick exactly **one** cancel gesture to document on the Running screen (recommended: **KEY2** because it’s already the dedicated Main Menu key). Then implement it consistently by routing KEY2 → CancelConfirm in all operation states.

**What fixed looks like**  
Every Running screen shows the same instruction, e.g., “Press KEY2 to cancel”. The cancel confirmation is always the same Yes/No menu.

#### C4) `dispatch_cancellable` contains the *right* idea, but mixes UI concerns and policy decisions
**Problem**  
`dispatch_cancellable` both (a) runs the job and (b) decides UX details like when to redraw, what the message format is, and how long to wait for cancellation to settle.

**Where**  
`dispatch_cancellable` in `app.rs` lines **670–858**.

**Why it’s a problem**  
It becomes a de-facto “runner,” but it’s not reusable for operations that need custom progress copy, additional stages, or post-processing. As a result, some operations bypass it (and reintroduce inconsistency).

**How to fix**  
Move job orchestration (start/poll/cancel/finalize) into the Operation Runner, and keep rendering in a dedicated component. `dispatch_cancellable` can be replaced by a smaller `JobRunner` helper with no UI strings.

**What fixed looks like**  
One place decides cancel semantics and transition policy; one place renders a progress view; operations provide only the data they need to display.


---

### Category D — Menu system bugs / maintenance hazards

#### D1) Duplicate menu node key overwrites a menu (“wifi_menu” is unreachable)
**Problem**  
MenuTree inserts two nodes with the same key `"aw"`; the second overwrites the first.

**Where**  
`crates/rustyjack-ui/src/menu.rs` lines **198–200**:
- `nodes.insert("aw", MenuNode::Static(wifi_menu));`
- `nodes.insert("aw", MenuNode::Static(wireless_menu));`

**Why it’s a problem**  
- One of those menus is dead code.
- This is easy to miss because there’s no type-level guarantee (string keys + HashMap).

**How to fix**  
- Decide which menu should exist at `"aw"` and remove the other insert, OR
- Rename one node key and update its submenu references, OR
- Replace string IDs with a typed enum (longer refactor; recommended).

**What fixed looks like**  
Each node key is unique; “WiFi” vs “Wireless” are not silently shadowed.

---

#### D2) Menu visible window size mismatch (scroll math inconsistency)
**Problem**  
`MenuState::move_up` assumes `VISIBLE = 7`, while `move_down` assumes `VISIBLE = 9`.

**Where**  
`app.rs` lines **874–905** (`VISIBLE` at **885** vs **900**).

**Why it’s a problem**  
This makes scrolling behavior asymmetrical and can create “jumpy selection” bugs, depending on item count and selection position.

**How to fix**  
- Define `const MENU_VISIBLE_ITEMS: usize = ...` in one place.
- Make it match actual display layout (LCD height / item height in `display.rs`).
- Use the same constant for both directions.

**What fixed looks like**  
Selection always stays in a predictable window; no odd jumps.

---

### Category E — Code structure and duplication (hard to extend safely)

#### E1) `app.rs` is monolithic and contains duplicated concepts (types duplicated elsewhere)
**Problem**  
`app.rs` mixes:
- UI state machine,
- rendering,
- button handling,
- business logic for dozens of operations,
- pipeline logic.

There are also duplicated/overlapping types between `app.rs` and `types.rs` (e.g., cancel/pipeline-related concepts).

**Where**  
- `crates/rustyjack-ui/src/app.rs` (very large)
- `crates/rustyjack-ui/src/types.rs`

**Why it’s a problem**  
- Changes to one operation risk breaking others.
- It’s hard to enforce consistency.
- New operations copy patterns that already diverged.

**How to fix**  
Introduce module boundaries that mirror the desired architecture:

Suggested layout:
- `ui/state.rs` → global UI state machine (`UiState`)
- `ui/runner.rs` → Operation Runner (generic pipeline)
- `ui/components/` → confirm dialog, progress dialog, results viewer, list chooser
- `ops/` → one file per operation category:
  - `ops/wireless.rs`, `ops/ethernet.rs`, `ops/system.rs`, `ops/storage.rs`, etc.
- `ops/spec.rs` → `OperationSpec` and shared preflight/setup helpers

Then incrementally migrate operations.

**What fixed looks like**  
Adding an operation is mostly writing a small `OperationSpec` + a formatter, not adding another 200-line custom loop.

---

## 4) Proposed implementation: Operation Runner (single pipeline)

### 4.1 Core idea (small state machine)
Represent operation execution as a state machine instead of ad-hoc loops.

Minimal state sketch:

- `UiState::Menu`
- `UiState::Operation(OperationState)`
  - `OperationState::Preflight`
  - `OperationState::Setup`
  - `OperationState::Confirm { summary }`
  - `OperationState::Running { job_id, started_at, progress }`
  - `OperationState::CancelConfirm`
  - `OperationState::Result { outcome }`

This can be implemented either:
- synchronously (blocking loops, like today) but centralized, OR
- event-driven (tick-based) later.

### 4.2 Data-driven OperationSpec (recommended)
A pragmatic design that avoids “trait object soup”:

```rust
pub struct OperationSpec<Ctx> {
    pub id: &'static str,
    pub title: &'static str,
    pub preflight: fn(&mut App) -> anyhow::Result<()>,
    pub setup: fn(&mut App) -> anyhow::Result<Ctx>,
    pub summarize: fn(&Ctx) -> Vec<String>,          // lines for confirm screen
    pub start: fn(&mut App, Ctx) -> anyhow::Result<OpHandle>,
    pub poll: fn(&mut App, &OpHandle) -> anyhow::Result<OpProgress>,
    pub cancel: fn(&mut App, &OpHandle) -> anyhow::Result<()>,
    pub finalize: fn(&mut App, OpHandle) -> anyhow::Result<OpOutcome>,
}
```

Where:
- `OpHandle` is typically `{ job_id: u64 }` (daemon job) but can also be a local handle for instantaneous ops.
- `OpProgress` includes:
  - `percent: Option<f32>`
  - `stage: String`
  - `detail: String` (elapsed, packets, etc.)
- `OpOutcome` includes:
  - success/failure/cancelled and output metadata.

Then `run_operation(spec)` handles the universal UX.

### 4.3 Standardized confirm/cancel UI components
Build two tiny reusable widgets:
- `confirm_yes_no(title, summary_lines) -> bool`
- `confirm_cancel(title) -> bool`

Back/MainMenu should map consistently:
- In Confirm: Back/MainMenu == “No”
- In Running: Key2 triggers CancelConfirm; Back can also trigger CancelConfirm (optional), but **do not** allow “go back”.

### 4.4 Progress & cancellation: unify the job path
Everything long-running should be represented as a cancellable job:
- Start via `core.start_core_command(cmd)`
- Poll via `core.job_status(job_id)`
- Cancel via `core.cancel_job(job_id)`
- Extend the daemon status payload if you want richer progress (stage strings, percent, counts). The UI already displays `status.message` and `status.progress_percent` in update flow.

---

## 5) “What to convert first” (highest impact, lowest risk)

1) **Implement `go_home()`** and replace direct `menu_state.home()` calls where “home” semantics matter.  
2) **Unify cancel dialogs**: replace attack/update cancel duplication with one Yes/No cancel component.  
3) **Convert Deauth Attack** to job-based cancellation (remove the UI-spawned thread).  
4) **Add Confirm Yes/No** to operations that currently start immediately (Probe Sniff, PMKID Capture, etc.).  
5) **Introduce Operation Runner** and migrate one category at a time (e.g., WiFi recon → WiFi offensive → ethernet → system).

---

## 6) Notes from similar embedded UI projects (pitfalls to avoid)

These aren’t “copy this code,” but they highlight patterns that keep embedded UIs from becoming spaghetti:

- Menu + UI logic benefits from being modeled as a **finite state machine**: it clarifies which inputs are valid in each screen and makes “global keys” (like Home) reliable. (Embedded Rust patterns frequently recommend explicit state modeling rather than deep nested loops.)  
- Consider adding a **desktop simulator** for rapid UI testing: `embedded-graphics` has commonly used simulation tooling, which is useful for catching navigation regressions without flashing a Pi every time.  
- If you want a reference implementation of menu organization over `embedded-graphics`, `embedded-menu` is a useful codebase to skim for ideas about keeping menu definitions declarative and separate from actions.

References (links in a code block to keep the markdown clean):

```text
Embedded Rust Book: https://docs.rust-embedded.org/book/
Microchip online docs (state machine guidance appears across app-notes and UI examples): https://onlinedocs.microchip.com/
embedded-graphics docs: https://docs.rs/embedded-graphics
embedded-menu docs: https://docs.rs/embedded-menu
```


(Use these as “design pattern references,” not mandatory dependencies.)

---

## 7) Acceptance criteria (Definition of Done)

When the refactor is “done enough”:
- Every operation that executes work:
  - runs preflight,
  - shows a standard **Yes/No** confirm screen,
  - shows a standard Running screen with cancel instructions,
  - cancel always shows **Yes/No** confirm,
  - “No” (either at confirm or cancel confirm) never returns to a submenu path; it either resumes running or returns home.
- KEY2 behavior is consistent everywhere:
  - In menus: immediate home
  - In operations: triggers cancel confirm, then home after cancellation
- No operation can “keep running in the background” after the UI claims it was cancelled.
- Adding a new operation requires:
  - defining preflight/setup/command/outcome formatting,
  - not copying UI loops.

---

## Appendix: quick index of concrete code references cited above

- Menu key overwrite (`"aw"`): `menu.rs` lines 198–200  
- Menu visible mismatch: `app.rs` lines 874–905  
- Back clears active interface, MainMenu does not: `app.rs` lines 1046–1074  
- Cancel confirmation branching: `app.rs` lines 554–666  
- Probe Sniff starts without confirm: `app.rs` lines 6004–6041  
- Deauth cancellation not job-based: `app.rs` lines 5604–5650  
