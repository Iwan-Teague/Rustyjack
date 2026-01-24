22 Jan 2026

# RustyJack UI Homogenization — Final Plan (KEY2=Cancel, LEFT=Back)
**Reviewed against repo snapshot:** `watchdog_shallow_20260122-090149.zip` (extracted locally)  
**Target device:** Raspberry Pi Zero 2 W  
**Constraint:** Rust-only runtime; **do not shell out to external binaries** (no `std::process::Command` added; keep UI changes pure-Rust).

This document merges the prior streamlining report + the implementation playbook, and adds:
- A strict, project-wide **button contract** (**KEY2 = Cancel**, **LEFT = Back**, KEY2 does nothing if nothing to cancel)
- A concrete **code-level audit** of where the current snapshot violates that contract
- A more prescriptive **“big pipeline overhaul” implementation plan**, including which files/functions to refactor and how operations slot into the new pipeline
- A daemon impact assessment (what must change, what can remain)

---

## 0) Non‑negotiable UI contract

### 0.1 Button semantics (global)
This is the required behavior across the entire UI:

- **LEFT arrow = Back**  
  - Navigational meaning: go to the previous menu/screen/step.
  - If “Back” is not meaningful in the current state (e.g., already at root), it does nothing.

- **KEY2 = Cancel (contextual)**  
  - **If an operation is “in progress” or “in setup/confirm”**: KEY2 initiates cancel behavior for *that operation*.
  - **If there is nothing to cancel** (menu browsing, passive viewing screens, result screens, non-operation dialogs): **KEY2 does nothing**.
  - Cancel confirmation rules:
    - During **Running**: KEY2 must show a **Yes/No cancel confirm**.
    - During **Setup/Confirm**: KEY2 should also show a **Yes/No cancel confirm** (“Cancel this operation?”). (This is strongly recommended for consistency.)

- **No timer navigation**
  - Screens may update their *contents* (e.g., progress %), but **must not automatically navigate** to a different screen after N seconds.
  - Any “finished/cancelled/failed” state must land on a **Result** screen and require explicit user input to exit.

### 0.2 Operation pipeline (global)
Every operation must follow the same pipeline:

1) **Preflight** (verify requirements; if fail → Error screen → Home)  
2) **Setup** (collect parameters; LEFT=Back stepwise; KEY2=Cancel op)  
3) **Confirm Yes/No**  
   - **No → Home** (not back to submenu paths like `/wireless/`)  
   - LEFT=Back returns to Setup (to adjust parameters)  
   - KEY2=Cancel cancels the whole operation (confirm) → Home  
4) **Running** (progress + KEY2 cancel instruction)  
   - KEY2 → Cancel confirm → cancel job/cooperative cancel → Result → Home  
5) **Result** (success/cancel/failure)  
   - requires explicit input, then → Home  
   - KEY2 does nothing here (nothing to cancel)

---

## 1) Snapshot audit: where current code violates KEY2=Cancel / LEFT=Back

**Important:** In this snapshot, KEY2 is currently mapped to “MainMenu/Home”, not “Cancel”.  
This is the root source of inconsistent behavior.

### 1.1 Single source of truth for mapping (confirmed)
File: `watchdog/crates/rustyjack-ui/src/app.rs`

Current mapping (needs change):
```rust
match b {
    Button::Left => ButtonAction::Back,
    Button::Key2 => ButtonAction::MainMenu,
    // ...
}
```

### 1.2 Places where KEY2 currently performs “Go Home” (must be removed)
These are the specific functions in `app.rs` where KEY2 triggers `go_home()` today:

- `run()` (menu mode and dashboard mode): KEY2 sends user to Home immediately.
- `show_message(...)`: KEY2 sends user to Home.
- `choose_from_menu(...)`: KEY2 sends user to Home.
- `prompt_octet(...)`: KEY2 sends user to Home.
- `browse_usb_for_file(...)`: KEY2 sends user to Home.
- `scrollable_text_viewer(...)`: KEY2 sends user to Home.
- Additional action loops also treat KEY2 as “exit to main menu”.

**Required change:** These contexts have “nothing to cancel”, so **KEY2 must do nothing**.

### 1.3 Places where LEFT is currently treated like “No/Cancel” (must be corrected)
- `confirm_yes_no(...)` currently treats LEFT (Back) as “No” (`return Ok(false)`).
  - Under the new contract, LEFT is **Back to previous step**, not “No”.

**Required change:** Confirm screens must distinguish:
- LEFT = Back (to Setup)
- Selected “No” = No (→ Home)
- KEY2 = Cancel (confirm cancel → Home)

---

## 2) Mandatory refactor: rename `MainMenu` → `Cancel` and change behavior

### 2.1 Mechanical refactor (day-1 change)
File: `watchdog/crates/rustyjack-ui/src/app.rs`

#### Step A — Rename the concept
- Rename `ButtonAction::MainMenu` → `ButtonAction::Cancel`
- Update `map_button` so `Button::Key2 => ButtonAction::Cancel`

This is an intentionally “boring” refactor, but it prevents future engineers from accidentally using KEY2 as navigation again.

#### Step B — Update all match arms
Search in `app.rs` for `ButtonAction::MainMenu` and update behavior according to the contract:

- In **menu browsing** (`run()` menu mode):
  - `Cancel` must do nothing.
- In **dashboard view**:
  - `Cancel` must do nothing.
- In **view-only screens** (loot viewer, hardware detect view, help/info screens):
  - `Cancel` must do nothing.
- In **operation setup/confirm/running screens**:
  - `Cancel` performs operation cancel (with confirm).
  - LEFT is back (setup step back / confirm back).

> Practical grep for devs: `rg "ButtonAction::MainMenu" watchdog/crates/rustyjack-ui/src/app.rs`

### 2.2 Change `show_error_dialog` copy (important UX)
`show_error_dialog(...)` currently appends: “Press KEY2 for Home”.  
Under new semantics this is wrong (KEY2 does nothing when nothing to cancel).

**Replace with:**
- “Press SELECT to continue”
- optionally “LEFT = Back” (if you want to treat result/error as “Back to Home”)

---

## 3) The big UI overhaul (the missing pipeline) — implementation plan

The current codebase is still structured as “one-off mini-programs” per operation inside `app.rs`.  
The goal is to make *operations declarative* and drive them through a single runner.

### 3.1 File/Module changes (exactly what to add)
Add these modules under `watchdog/crates/rustyjack-ui/src/`:

```
ui/
  mod.rs
  input.rs              // maps Button -> UiInput (Back/Select/Cancel/...)
  layout.rs             // screen geometry, wrap, paginate (no truncation)
  screens/
    confirm.rs          // Yes/No confirm (LEFT=Back, KEY2=Cancel)
    cancel_confirm.rs   // generic cancel confirm (Yes/No)
    progress.rs         // running progress, KEY2=Cancel
    result.rs           // success/cancel/failure, KEY2 does nothing
    error.rs            // error with cause chain, KEY2 does nothing
    picker.rs           // list picker used by setup steps (LEFT=Back, KEY2=Cancel)
ops/
  mod.rs                // Operation trait + OperationRegistry
  runner.rs             // OperationRunner (pipeline)
  shared/
    preflight.rs
    setup.rs
    jobs.rs             // daemon job polling, cancel, progress display helpers
```

**Note:** You can keep `display.rs` as-is initially and just route all drawing through the new `ui/screens/*` code.

### 3.2 Core types (copy/paste-level pseudo-code)

#### `UiInput` (screen-level input)
```rust
pub enum UiInput {
    Up,
    Down,
    LeftBack,
    Select,
    Refresh,
    CancelKey2,
    RebootKey3,
}
```

#### `OperationPhase`
```rust
pub enum OperationPhase {
    Preflight,
    Setup,
    Confirm,
    Running,
    Result,
}
```

#### `OperationOutcome`
```rust
pub enum OperationOutcome {
    Success { summary: Vec<String> },
    Cancelled { summary: Vec<String> },
    Failed { error: anyhow::Error },
}
```

#### `Operation` trait
```rust
pub trait Operation {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;

    fn preflight(&mut self, ctx: &mut OperationContext) -> anyhow::Result<()>;

    /// Returns false if user cancelled setup via KEY2 confirm.
    fn setup(&mut self, ctx: &mut OperationContext) -> anyhow::Result<bool>;

    /// Rendered into Confirm screen.
    fn confirm_lines(&self) -> Vec<String>;

    /// Must be cancellable via ctx.cancel_token() / daemon job cancel.
    fn run(&mut self, ctx: &mut OperationContext) -> anyhow::Result<OperationOutcome>;
}
```

#### `OperationContext`
```rust
pub struct OperationContext<'a> {
    pub display: &'a mut Display,
    pub buttons: &'a mut ButtonPad,
    pub core: &'a mut CoreBridge,
    pub config: &'a mut GuiConfig,
    pub menu_state: &'a mut MenuState,
    pub stats: &'a StatsSampler,
    pub root: &'a Path,
}
```

#### `OperationRunner` (the pipeline)
```rust
pub struct OperationRunner;

impl OperationRunner {
    pub fn run(op: &mut dyn Operation, ctx: &mut OperationContext) -> anyhow::Result<()> {
        // Preflight
        if let Err(e) = op.preflight(ctx) {
            ui::screens::error::show(ctx, "Preflight failed", &e)?;
            go_home(ctx)?;
            return Ok(());
        }

        // Setup (LEFT=Back inside setup screens; KEY2=Cancel w/ confirm)
        if !op.setup(ctx)? {
            go_home(ctx)?;
            return Ok(());
        }

        // Confirm (LEFT=Back -> return to setup; No -> Home; KEY2 -> Cancel confirm -> Home)
        loop {
            match ui::screens::confirm::show(ctx, op.title(), op.confirm_lines())? {
                ConfirmChoice::Yes => break,
                ConfirmChoice::No => { go_home(ctx)?; return Ok(()); }
                ConfirmChoice::Back => { if !op.setup(ctx)? { go_home(ctx)?; return Ok(()); } }
                ConfirmChoice::Cancel => { if ui::screens::cancel_confirm::show(ctx, op.title())? { go_home(ctx)?; return Ok(()); } }
            }
        }

        // Running
        let outcome = match op.run(ctx) {
            Ok(outcome) => outcome,
            Err(e) => OperationOutcome::Failed { error: e },
        };

        // Result (KEY2 does nothing)
        ui::screens::result::show(ctx, op.title(), &outcome)?;
        go_home(ctx)?;
        Ok(())
    }
}
```

### 3.3 Where to integrate this into the existing code (exact file edits)

#### A) Thin down `App::run()`
File: `watchdog/crates/rustyjack-ui/src/app.rs`

- Keep the main loop, but:
  - **Remove KEY2 “go home”** behavior from menu/dashboard modes.
  - Ensure all “operation” MenuAction arms call the runner.

#### B) Replace `execute_action` for operations
File: `watchdog/crates/rustyjack-ui/src/app.rs`

Today, `execute_action` routes to handler methods like:
- `launch_deauth_attack`, `launch_evil_twin`, `recon_gateway`, etc.

Replace those arms with:
- Build the corresponding `Operation` struct
- Call `OperationRunner::run(...)`

Example pattern:
```rust
MenuAction::DeauthAttack => {
    let mut op = ops::wifi::DeauthAttackOp::new();
    ops::runner::OperationRunner::run(&mut op, &mut ctx)?;
}
```

Non-operation actions can remain direct:
- `Submenu`, `RefreshConfig`, `SaveConfig`, etc.

### 3.4 How existing operations fit the new pipeline (mapping confirmed)
This snapshot’s `MenuAction` already delegates into handler methods in `App` (confirmed in `execute_action`), e.g.:
- `MenuAction::EvilTwinAttack` -> `self.launch_evil_twin()`
- `MenuAction::CrackHandshake` -> `self.launch_crack_handshake()`
- `MenuAction::EthernetDiscovery` -> `self.launch_ethernet_discovery()`
- etc.

**Migration rule:** For each handler `App::launch_*` or `App::*_op`:
- Copy the preflight/setup logic into a new `Operation` struct
- Replace direct UI calls with `ui::screens::*` calls

You do **not** need to migrate everything at once. You can do it by category:
1) WiFi attacks (highest inconsistency risk)
2) Recon
3) Ethernet
4) System/USB/encryption
5) Toggles/views

---

## 4) KEY2=Cancel / LEFT=Back: concrete edits list (by function)

All of the following are in: `watchdog/crates/rustyjack-ui/src/app.rs`

### 4.1 `App::run()`
Current behavior:
- KEY2 immediately calls `go_home()` in menu mode and dashboard mode.

Required behavior:
- In menu/dashboard: **KEY2 does nothing**.
- LEFT remains back navigation.

### 4.2 `confirm_yes_no(...)`
Current behavior:
- LEFT and KEY2 both return `false`.

Required behavior:
- Replace with a new function that returns:
  - `Yes`, `No`, `Back`, `Cancel`
- Existing call sites that truly need only bool can keep a `confirm_yes_no_bool` wrapper:
  - `Back` and `Cancel` -> `false`

### 4.3 `show_message(...)` and `show_error_dialog(...)`
Current behavior:
- KEY2 calls `go_home()`.

Required behavior:
- KEY2 does nothing.
- Exit the dialog with SELECT (and optionally LEFT).

Also update the on-screen hints:
- remove “Press KEY2 for Home”
- prefer “Press SELECT to continue”

### 4.4 `choose_from_menu(...)`, `prompt_octet(...)`, `browse_usb_for_file(...)`
Current behavior:
- KEY2 calls `go_home()`.

Required behavior:
- KEY2 returns `None` (cancel current flow) **without** calling `go_home()`.
- Callers decide (runner returns Home when cancelling an operation).

### 4.5 “Running loops” that treat LEFT as cancel (must stop doing that)
Any running loop that matches:
```rust
ButtonAction::Back | ButtonAction::MainMenu => { ... cancel ... }
```
must become:
- LEFT does nothing (or is ignored)
- KEY2 triggers cancel confirm

In this snapshot, that pattern appears in:
- cracking progress flow (`crack_handshake_with_progress`)
- some job progress loops (`show_mitm_status`-style loops)
- any other “wait for press” loop where both are treated identically

---

## 5) Do we need daemon changes?

### 5.1 Cancellation: **no daemon change required**
The daemon already supports cooperative cancellation:
- UI calls `job_cancel`
- Daemon uses a `CancellationToken` to notify jobs
- Core-command jobs pass a cancel flag down into core operations (`dispatch_command_with_cancel`)

So KEY2 cancel semantics are purely **UI** work.

### 5.2 Progress display: daemon is capable; UI should leverage it
IPC job status includes:
- `JobInfo.progress: Option<Progress { phase, percent, message, updated_at_ms }>`

And daemon job execution passes a progress callback into job kinds.

**However:** To get the best “progress screen” UX, make sure:
- UI progress screen shows daemon-provided `progress.message` and `percent` when present.
- For jobs that don’t provide meaningful progress updates, extend the job kind to report better phase/message updates.

This is **optional**, but recommended because it makes progress screens consistent without inventing UI-specific timers.

---

## 6) Timer screens removal (confirmed offenders)
File: `watchdog/crates/rustyjack-ui/src/display.rs`

There is a diagnostic flow that sleeps ~900ms “so the user can see the result”.
This violates the “no timer screens” policy if it changes what the user sees without input.

Required fix:
- Replace sleeps in UI-visible flows with “Press SELECT to continue” screens.
- Internal retry sleeps that do not change screens are acceptable.

---

## 7) Verification checklist (what to test after implementing)
After changes land, verify these invariants manually and/or via simulator tests:

- In menu browsing:
  - LEFT navigates back
  - KEY2 does nothing
- In operation setup screens:
  - LEFT steps back
  - KEY2 opens “Cancel operation?” confirm
- In confirm screen:
  - LEFT returns to setup (not submenu)
  - selecting “No” returns Home
  - KEY2 opens “Cancel operation?” confirm
- In running screen:
  - KEY2 opens “Cancel operation?” confirm
  - LEFT does nothing
  - cancel → Cancelled Result → Home
- In result/error screen:
  - KEY2 does nothing
  - SELECT (and optionally LEFT) exits → Home
- Error clarity:
  - Preflight failures show the actual reason (permission denied, missing iface, etc.)
  - Job failures show error + detail.

---

## 8) External references (for patterns + pitfalls)
These are not dependencies you must adopt; they’re reference points for design/testing approaches:

- embedded-graphics simulator supports golden-image CI checks via `EG_SIMULATOR_CHECK` and `EG_SIMULATOR_CHECK_RAW` (useful to prevent UI regressions).  
  Source: embedded-graphics/simulator README.  
- embedded-text provides a robust multiline `TextBox` concept that avoids truncation and wrapping edge cases (even if you keep your own wrapper).  
  Source: embedded-graphics/embedded-text.
- For the longer-term “no external binaries anywhere” epic, `rustix` is a well-known safe wrapper around POSIX-ish syscalls if you need to replace `mount`, etc.  
  Source: bytecodealliance/rustix.

---

# Appendix A — Minimal patch plan (get KEY2 semantics correct first)
This is the recommended sequencing to reduce risk:

1) **Rename** `ButtonAction::MainMenu` → `Cancel` and map KEY2 → Cancel.  
2) Remove all `go_home()` calls on Cancel in menu/view/message contexts (Cancel does nothing there).  
3) Refactor cancel handling in running loops so only Cancel triggers cancel confirm (LEFT does nothing).  
4) Only after button behavior is stable, implement the operation pipeline and migrate operations one by one.

This avoids doing two behavior-changing refactors (buttons + pipeline) in the same PR.

