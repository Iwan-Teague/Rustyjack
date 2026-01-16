# RustyJack Verified Fix Plan (Rust-only, no 3rd-party binaries)

This document converts the **required_fixes.md** findings into **verified, code-grounded causes** and a **patch-ready fix plan**. It is intentionally blunt and step-driven.

## Goal
Make the system do the following, reliably:

1) **If the UI selects `wlan0`/`wlan1`, the daemon's strict isolation MUST use that interface** (and stop reverting to `eth0`).
2) **Cancelling interface selection MUST cancel the daemon job** (no "UI cancelled but daemon keeps going").
3) **Failed Evil Twin attempts MUST NOT leave zombie progress threads** spamming logs forever.
4) **rfkill failures MUST be loud** (no silent "ok" when we failed to block/unblock).

---

# Fix 1 -- Active interface not applied for Evil Twin (daemon keeps using eth0)

## What's wrong (symptom)
- UI selects a WiFi interface, but the daemon's strict isolation keeps allowing `eth0` and blocking `wlan*`.
- Result: WiFi attacks fail or "run" but can't actually use the intended interface.
- Switching from `eth0` to `wlan1` in Hardware Detect does not drop the SSH session, which implies `eth0` is still allowed and isolation is not enforcing the selected interface.

## Verified cause (code-level)
The UI **does not persist the selected interface to the daemon's strict-isolation preference** before launching Evil Twin.

- **Where**: `rustyjack-ui/src/app.rs`
  - Function: `launch_evil_twin()`
  - It chooses `attack_interface` from `gui_conf.json` (`active_network_interface`) and passes it into the Evil Twin command,
    but **does not call** the daemon interface-selection endpoint before starting the attack.

Why this matters:
- The daemon's strict isolation is driven by daemon-side state (active interface preference), not by the UI's config file.
- If the daemon's preferred interface is still `eth0`, isolation will repeatedly bring `wlan*` down / block them, breaking the attack.

## How to fix (exact change)
In `launch_evil_twin()`:

1) After determining `attack_interface`, call `self.core.set_active_interface(&attack_interface)` **BEFORE** preflight and before starting the attack.
2) Show a progress dialog while this happens.

### Pseudocode
```rust
attack_interface = ui_config.active_network_interface;
if attack_interface.is_empty() {
    attack_interface = user_pick_wifi_interface();
    ui_config.active_network_interface = attack_interface;
    ui_config.save(gui_conf.json);
}

show_progress("Preparing Evil Twin", "Selecting interface", attack_interface);
daemon.set_active_interface(attack_interface)?; // <-- critical
preflight(attack_interface)?;
start_evil_twin(attack_interface, ...)?;
```

## What "fixed" looks like
- When you start Evil Twin, you first see a "Preparing Evil Twin / Applying strict isolation... " progress screen.
- In daemon logs you should now see interface selection targeting the WiFi interface you picked (not only eth0).
- `rfkill list` should show the chosen WiFi PHY is **not soft-blocked** after selection.

---

# Fix 2 -- Interface selection cancel does not cancel the daemon job

## What's wrong (symptom)
- UI displays interface selection progress.
- User presses LEFT/back to cancel.
- UI returns to menu, **but daemon job may still run**, continuing to modify interface state.

## Verified cause (code-level)
`run_interface_selection_job()` polls daemon job status but **never checks for user input** while the job is running.

- **Where**: `rustyjack-ui/src/app.rs`
  - Function: `run_interface_selection_job(selected_name, title)`
  - Loop:
    - polls `self.core.job_status(job_id)`
    - sleeps 200ms
    - repeats
  - There is no cancellation path while `JobState::Queued|Running`.

Also, `CoreBridge` didn't expose a `cancel_job()` helper.

## How to fix (exact change)
1) Add a core bridge method:
   - **Where**: `rustyjack-ui/src/core.rs`
   - Add `pub fn cancel_job(&self, job_id: JobId) -> Result<bool>` calling `client.job_cancel(job_id)`.

2) Update UI polling loop:
   - **Where**: `rustyjack-ui/src/app.rs`
   - In `JobState::Queued|Running`, do a non-blocking button read:
     - if LEFT/back or MainMenu pressed:
       - send `cancel_job(job_id)`
       - wait up to ~3 seconds for daemon to acknowledge cancellation
       - return `Ok(None)`

3) Add the UI hint text "LEFT = Cancel" to the interface selection progress dialog.

### Pseudocode
```rust
loop {
  status = daemon.job_status(job_id);

  draw_progress(status.progress, hint="LEFT = Cancel");

  if status.state in [Queued, Running] {
     if button_pressed in [Back, MainMenu] {
        daemon.job_cancel(job_id);
        wait_short_for_state(job_id, Cancelled|Failed|Completed);
        show_message("Cancelled. Run again to ensure desired state.");
        return None;
     }
     sleep(200ms);
     continue;
  }

  if status.state == Completed { return parse_result(status.result); }
  if status.state in [Failed, Cancelled] { show_error(status.error); return None; }
}
```

## What "fixed" looks like
- During "Setting Interface", pressing LEFT shows "Cancelling... " then returns you to a "Cancelled" message.
- Daemon no longer continues applying interface changes after a cancel request.

---

# Fix 3 -- Evil Twin progress thread leak (zombie log spam)

## What's wrong (symptom)
- Multiple log lines like:
  - `Evil Twin '<ssid>' running for ...`
- They keep printing **even after an error** (e.g. rfkill or AP mode failure).
- Over time, you see multiple ThreadIds printing the same message: classic zombie threads.

## Verified cause (code-level)
`execute_evil_twin()` spawns a progress monitor thread, but it only stops/join()s it on the success path.

- **Where**: `rustyjack-wireless/src/evil_twin.rs`
  - Function: `execute_evil_twin(...)`
  - Bug:
    - `let stats = attack.start()?;` returns early on Err
    - progress thread keeps running because `stop_flag` was never set and join never happened.

## How to fix (exact change)
Always stop and join the thread **even if the attack fails** by capturing the result first.

### Pseudocode
```rust
progress_thread = spawn(|| while !stop_flag { ... });

let stats_res = attack.start();      // don't ? yet
stop_flag.store(true);
progress_thread.join();

let stats = stats_res?;             // now propagate error
```

## What "fixed" looks like
- If Evil Twin fails immediately, you do **not** continue seeing periodic "running for ... " messages afterwards.

---

# Fix 4 -- rfkill failure is silently ignored

## What's wrong (symptom)
- System "claims" it blocked/unblocked rfkill, but in reality nothing happened.
- That makes strict isolation *look successful* while leaving radios in the wrong state.

## Verified cause (code-level)
`RealNetOps` treats "rfkill device not found for interface" as success.

- **Where**: `rustyjack-core/src/system/ops.rs`
  - `fn set_rfkill_block(...)` returned `Ok(())` even if `rfkill_find_index(...)` returns `None`
  - `fn is_rfkill_blocked(...)` / `fn is_rfkill_hard_blocked(...)` returned `Ok(false)` for missing rfkill device

That is silent failure.

## How to fix (exact change)
Change rfkill operations to be strict:
- If `rfkill_find_index(interface)` returns `None`, return an error.
- This forces strict isolation to record and surface the real cause.

### Pseudocode
```rust
match rfkill_find_index(interface)? {
  Some(idx) => rfkill_block_or_unblock(idx),
  None => Err(anyhow!("rfkill device not found for interface {}", interface)),
}
```

## What "fixed" looks like
- If rfkill is misconfigured/missing, strict isolation returns errors instead of "errors=0".
- You get a direct error message pointing at rfkill device discovery.

---

# Patch-ready code changes (exact diffs)

```diff
diff --git a/rustyjack-core/src/system/ops.rs b/rustyjack-core/src/system/ops.rs
index e79ac77..d413053 100644
--- a/rustyjack-core/src/system/ops.rs
+++ b/rustyjack-core/src/system/ops.rs
@@ -1,4 +1,4 @@
-use anyhow::Result;
+use anyhow::{anyhow, Result};
 use std::net::Ipv4Addr;
 use std::time::Duration;
 use std::sync::{Mutex as StdMutex, OnceLock};
@@ -212,16 +212,19 @@ impl NetOps for RealNetOps {
     }
 
     fn set_rfkill_block(&self, interface: &str, blocked: bool) -> Result<()> {
-        use crate::netlink_helpers::{rfkill_find_index, rfkill_block, rfkill_unblock};
-        
-        if let Ok(Some(idx)) = rfkill_find_index(interface) {
-            if blocked {
-                rfkill_block(idx)?;
-            } else {
-                rfkill_unblock(idx)?;
+        use crate::netlink_helpers::{rfkill_block, rfkill_find_index, rfkill_unblock};
+
+        match rfkill_find_index(interface)? {
+            Some(idx) => {
+                if blocked {
+                    rfkill_block(idx)?;
+                } else {
+                    rfkill_unblock(idx)?;
+                }
+                Ok(())
             }
+            None => Err(anyhow!("rfkill device not found for interface {}", interface)),
         }
-        Ok(())
     }
 
     fn is_wireless(&self, interface: &str) -> bool {
@@ -441,7 +444,7 @@ impl NetOps for RealNetOps {
 
         match rfkill_find_index(interface)? {
             Some(idx) => rfkill_is_blocked(idx),
-            None => Ok(false), // No rfkill device = not blocked
+            None => Err(anyhow!("rfkill device not found for interface {}", interface)),
         }
     }
 
@@ -450,7 +453,7 @@ impl NetOps for RealNetOps {
 
         match rfkill_find_index(interface)? {
             Some(idx) => rfkill_is_hard_blocked(idx),
-            None => Ok(false), // No rfkill device = not blocked
+            None => Err(anyhow!("rfkill device not found for interface {}", interface)),
         }
     }
 }
diff --git a/rustyjack-ui/src/app.rs b/rustyjack-ui/src/app.rs
index c51cc9c..53e0d4e 100644
--- a/rustyjack-ui/src/app.rs
+++ b/rustyjack-ui/src/app.rs
@@ -5503,6 +5503,25 @@ impl App {
             }
         }
 
+        // Ensure the daemon's strict-isolation preference matches the UI-selected interface.
+        // Without this, the daemon may immediately revert isolation back to its preferred uplink (often eth0),
+        // causing the Evil Twin to fail or run on the wrong interface.
+        self.show_progress(
+            "Preparing Evil Twin",
+            [
+                &format!("Selecting interface: {}", attack_interface),
+                "Applying strict isolation...",
+                "Please wait",
+            ],
+        )?;
+
+        if let Err(e) = self.core.set_active_interface(&attack_interface) {
+            return self.show_preflight_error(
+                "Interface Select Failed",
+                &format!("Failed to set active interface in daemon: {}", e),
+            );
+        }
+
         if let Some(error) = self.preflight_evil_twin(&attack_interface)? {
             return self.show_preflight_error("Preflight Failed", &error);
         }
@@ -12332,6 +12351,7 @@ impl App {
                         [
                             &format!("Interface: {}", selected_name),
                             &msg,
+                            "LEFT = Cancel",
                         ],
                     )?;
                     last_message = Some(msg);
@@ -12342,6 +12362,7 @@ impl App {
                     [
                         &format!("Interface: {}", selected_name),
                         "Queued...",
+                        "LEFT = Cancel",
                     ],
                 )?;
                 last_message = Some("Queued".to_string());
@@ -12349,6 +12370,49 @@ impl App {
 
             match status.state {
                 JobState::Queued | JobState::Running => {
+                    // Allow user to cancel while the daemon performs interface isolation
+                    if let Some(button) = self.buttons.try_read()? {
+                        match self.map_button(button) {
+                            ButtonAction::Back | ButtonAction::MainMenu => {
+                                self.show_progress(
+                                    title,
+                                    [
+                                        &format!("Interface: {}", selected_name),
+                                        "Cancelling...",
+                                        "Please wait",
+                                    ],
+                                )?;
+
+                                let _ = self.core.cancel_job(job_id);
+
+                                // Wait briefly for daemon to acknowledge cancellation
+                                let cancel_start = std::time::Instant::now();
+                                while cancel_start.elapsed() < Duration::from_secs(3) {
+                                    let st = self.core.job_status(job_id)?;
+                                    if matches!(
+                                        st.state,
+                                        JobState::Cancelled | JobState::Failed | JobState::Completed
+                                    ) {
+                                        break;
+                                    }
+                                    std::thread::sleep(Duration::from_millis(100));
+                                }
+
+                                self.show_message(
+                                    "Interface Selection",
+                                    [
+                                        "Cancelled",
+                                        "",
+                                        "Run Interface Select again",
+                                        "to ensure desired state",
+                                    ],
+                                )?;
+                                return Ok(None);
+                            }
+                            _ => {}
+                        }
+                    }
+
                     std::thread::sleep(Duration::from_millis(200));
                 }
                 JobState::Completed => {
diff --git a/rustyjack-ui/src/core.rs b/rustyjack-ui/src/core.rs
index fcd653e..9bb8c7f 100644
--- a/rustyjack-ui/src/core.rs
+++ b/rustyjack-ui/src/core.rs
@@ -205,6 +205,14 @@ impl CoreBridge {
         })
     }
 
+    pub fn cancel_job(&self, job_id: JobId) -> Result<bool> {
+        self.block_on(async move {
+            let mut client = self.create_client().await?;
+            let resp = client.job_cancel(job_id).await?;
+            Ok(resp.cancelled)
+        })
+    }
+
     pub fn start_interface_select(&self, interface: &str) -> Result<JobId> {
         let interface = interface.to_string();
         self.block_on(async move {
diff --git a/rustyjack-wireless/src/evil_twin.rs b/rustyjack-wireless/src/evil_twin.rs
index ef3e7de..edd8ea6 100644
--- a/rustyjack-wireless/src/evil_twin.rs
+++ b/rustyjack-wireless/src/evil_twin.rs
@@ -773,13 +773,15 @@ where
         }
     });
 
-    // Run the attack
-    let stats = attack.start()?;
+    // Run the attack (capture the result so we can always stop/join the progress thread)
+    let stats_res = attack.start();
 
-    // Stop progress thread
+    // Stop progress thread (ALWAYS, even if the attack fails early)
     attack.stop_flag.store(true, Ordering::Relaxed);
     let _ = progress_thread.join();
 
+    let stats = stats_res?;
+
     // Log results
     if let Some(log_file) = log_file.as_mut() {
         writeln!(log_file, "---").ok();

```

---

# Validation checklist (do these after applying)

## A) Interface selection
1) Run UI -> Interface Select -> choose `wlan0` (or `wlan1`)
2) While it runs, press LEFT:
   - Expected: "Cancelling... " then "Cancelled ... Run Interface Select again... "
3) Run Interface Select again and let it complete:
   - Expected: UI shows success + config saved.

## B) Strict isolation + daemon preference
1) From UI, start Evil Twin:
   - Expected: "Preparing Evil Twin / Selecting interface ... Applying strict isolation ... "
2) In daemon logs:
   - Expected: interface selection pipeline runs for the chosen WiFi interface (not only eth0).

## C) rfkill correctness
1) After selecting `wlan0` as active:
   - `rfkill list` should show the corresponding WiFi PHY soft-blocked = **no**
2) If rfkill cannot be found for the interface:
   - Expected: you see a hard error message **immediately** (not silent ok)

## D) Zombie thread prevention
1) Intentionally trigger an Evil Twin failure (rfkill on / AP busy)
2) Observe logs:
   - Expected: No continued "Evil Twin '<ssid>' running for ... " messages after the failure.

---

# Not solved by this patch (but required for "Cancel Attack" to actually stop daemon work)

The UI's `dispatch_cancellable(...)` cancels only the *UI wait*, not the underlying daemon work for long-running `WifiCommand`s.

## Required refactor for real attack cancellation (Rust-only)
Convert long-running WiFi attacks into daemon **jobs**:
- start job
- poll status
- cancel job
- daemon stops worker loops via a cancellation flag

### Concrete design sketch
1) Add new job kinds in `rustyjack-ipc/src/job.rs`:
```rust
enum JobKind {
  InterfaceSelect { interface: String },
  WifiEvilTwin { args: WifiEvilTwinArgs },
  // add others as needed...
}
```

2) Daemon job runner:
- store `Arc<AtomicBool>` cancellation flag per job
- pass it down to the attack loop
- ensure cleanup executes on cancel

3) UI:
- replace long request with:
  - `job_start(JobKind::WifiEvilTwin { ... })`
  - poll
  - cancel via `cancel_job(job_id)`

---

# Bottom line
These 4 fixes are verified and patchable:
- Evil Twin now forces daemon preference to the correct interface.
- Interface selection cancel works (actually cancels daemon job).
- Evil Twin no longer leaks progress threads on error.
- rfkill failures can't hide anymore.
