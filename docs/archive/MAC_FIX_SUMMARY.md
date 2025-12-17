# MAC Management Fixes - Implementation Summary

## Changes Implemented

### Step 2: Per-Interface MAC Tracking ✅

**Config Changes** (`rustyjack-ui/src/config.rs`):
- Changed `original_mac: String` → `original_macs: HashMap<String, String>`
- Changed `current_mac: String` → `current_macs: HashMap<String, String>`
- Added `std::collections::HashMap` import

**App Changes** (`rustyjack-ui/src/app.rs`):
- Updated `build_dashboard_status()` to use per-interface lookups:
  ```rust
  let current_mac = interface_mac
      .or_else(|| settings.current_macs.get(interface_name).cloned())
      .unwrap_or_default();
  let original_mac = settings.original_macs.get(interface_name).cloned()
      .unwrap_or_else(|| ...);
  ```

- Updated `randomize_mac()` to save per-interface:
  ```rust
  self.config.settings.original_macs
      .entry(active_interface.clone())
      .or_insert_with(|| original_mac.clone());
  self.config.settings.current_macs
      .insert(active_interface.clone(), new_mac.clone());
  ```

- Updated `restore_mac()` to use per-interface lookups and remove per-interface entries:
  ```rust
  let original_mac = self.config.settings.original_macs.get(&active_interface)...
  self.config.settings.current_macs.remove(&active_interface);
  self.config.settings.original_macs.remove(&active_interface);
  ```

- Updated `set_vendor_mac()` to save per-interface

**Result**: MAC state is now correctly tracked per interface. Switching interfaces no longer corrupts MAC records.

---

### Step 3: Force LAA Bit on Vendor MACs ✅

**Library Changes** (`rustyjack-evasion/src/mac.rs`):
- Modified `MacAddress::random_with_oui()`:
  ```rust
  bytes[0] = (oui[0] | 0x02) & 0xFE;  // Force locally administered + unicast
  bytes[1] = oui[1];
  bytes[2] = oui[2];
  ```

**Result**: Vendor-specific MACs now always have the locally administered bit set, preventing globally administered collisions.

---

### Step 4: Check Reconnect Status ✅

**Function Changes** (`rustyjack-ui/src/app.rs`):

1. **`renew_dhcp_and_reconnect()` now returns `bool`**:
   ```rust
   fn renew_dhcp_and_reconnect(interface: &str) -> bool {
       let dhcp_renew = Command::new("dhclient").arg(interface).status();
       let wpa = Command::new("wpa_cli")...
       let nm = Command::new("nmcli")...
       
       dhcp_renew.map(|s| s.success()).unwrap_or(false)
           || wpa.map(|s| s.success()).unwrap_or(false)
           || nm.map(|s| s.success()).unwrap_or(false)
   }
   ```

2. **`randomize_mac_with_reconnect()` returns tuple**:
   ```rust
   fn randomize_mac_with_reconnect(interface: &str) 
       -> anyhow::Result<(rustyjack_evasion::MacState, bool)> {
       ...
       let reconnect_ok = renew_dhcp_and_reconnect(interface);
       Ok((state, reconnect_ok))
   }
   ```

3. **UI dialogs warn on failure**:
   ```rust
   if !reconnect_ok {
       lines.push("Warning: reconnect may");
       lines.push("have failed. Check DHCP.");
   }
   ```

4. **`restore_original_mac()` helper checks success**:
   ```rust
   result.map(|s| s.success()).unwrap_or(false)
   ```

**Result**: Users are now informed when DHCP/reconnect operations fail after MAC changes.

---

### Step 1: Remove `quick_randomize_mac()` ✅ (Option C)

**Library Changes** (`rustyjack-evasion/src/lib.rs`):
- Removed entire `quick_randomize_mac()` function and documentation

**Documentation** (`rustyjack-evasion/README.md`):
- Updated Quick Start example to use `MacManager` with explicit `set_auto_restore(false)`
- Removed stateless example

**Rationale**: The function's auto-restore behavior made the spoof ephemeral (Drop immediately restored MAC). UI already uses the correct pattern. Library users should manage `MacManager` lifetime explicitly.

---

### Step 5: De-duplicate MacManager States (HashMap Approach) ✅

**Library Changes** (`rustyjack-evasion/src/mac.rs`):

1. **Changed internal storage**:
   ```rust
   pub struct MacManager {
       states: HashMap<String, MacState>,  // Was: Vec<MacState>
       auto_restore: bool,
   }
   ```

2. **Updated `new()`**:
   ```rust
   states: HashMap::new()
   ```

3. **Updated `set_mac()` to use entry API**:
   ```rust
   let state = self.states.entry(interface.to_string())
       .or_insert_with(|| MacState {
           interface: interface.to_string(),
           original_mac: current_mac.clone(),
           current_mac: current_mac.clone(),
           is_randomized: false,
           changed_at: chrono::Utc::now().timestamp(),
       });
   
   // Apply MAC change...
   
   state.current_mac = mac.clone();
   state.is_randomized = true;
   state.changed_at = chrono::Utc::now().timestamp();
   
   Ok(state.clone())
   ```

4. **Updated `restore_all()`**:
   ```rust
   pub fn restore_all(&mut self) -> Result<()> {
       let states: Vec<_> = self.states.values().cloned().collect();
       let mut first_error = None;
       
       for state in states {
           if state.needs_restore() {
               if let Err(e) = self.restore_state(&state) {
                   log::warn!("Failed to restore MAC on {}: {}", state.interface, e);
                   if first_error.is_none() {
                       first_error = Some(e);
                   }
               }
           }
       }
       
       self.states.clear();
       first_error.map_or(Ok(()), Err)
   }
   ```

5. **Updated `get_state()`**:
   ```rust
   pub fn get_state(&self, interface: &str) -> Option<&MacState> {
       self.states.get(interface)
   }
   ```

6. **Updated `all_states()`**:
   ```rust
   pub fn all_states(&self) -> Vec<&MacState> {
       self.states.values().collect()
   }
   ```

**Result**: 
- Only one state per interface is maintained
- `original_mac` always points to the hardware MAC (first recorded value)
- Multiple randomizations on same interface update `current_mac` but preserve `original_mac`
- `restore_all()` is now idempotent and always restores to hardware MAC
- No duplicate states, no confusion about which MAC is "original"

---

## Testing Checklist

- [ ] Build succeeds: `cargo build --release`
- [ ] Randomize MAC on wlan0, check MAC persists after function returns
- [ ] Randomize MAC on wlan0, switch to eth0, randomize on eth0 → both should have separate state
- [ ] Restore MAC on wlan0 → should restore wlan0's hardware MAC, not eth0's
- [ ] Set vendor MAC → verify LAA bit is set (byte[0] & 0x02 != 0)
- [ ] Trigger DHCP failure (unplug cable/disable DHCP server) → UI should warn
- [ ] Multiple randomizations on same interface → restore should go to original hardware MAC

---

## Migration Notes for Existing Config Files

Old config files with `original_mac`/`current_mac` fields will load successfully due to `#[serde(default)]`. The old fields will be ignored, and new per-interface maps will start empty. Users will need to randomize MACs again to populate the new structure.

---

## API Behavior Changes

### Breaking Changes (rustyjack-evasion library):
1. **`quick_randomize_mac()` removed** → Use `MacManager` directly
2. **`MacManager::all_states()` return type changed** → Was `&[MacState]`, now `Vec<&MacState>`

### Non-Breaking Changes:
- `MacManager` internal storage changed (HashMap), but public API signatures unchanged for core methods
- Per-interface state tracking is transparent to callers
- `restore_all()` behavior improved (idempotent), but signature unchanged

---

## Documentation Updates

- [x] `rustyjack-evasion/README.md` - Removed quick_randomize_mac example
- [x] `rustyjack-evasion/src/lib.rs` - Removed function and doc comments
- [ ] Add migration guide if publishing breaking changes to crate registry

