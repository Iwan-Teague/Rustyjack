# Rustyjack Compilation Fix - Complete Guide

## Changes Made

### 1. rustyjack-core/Cargo.toml
- Added `libc = "0.2"` dependency (required for system.rs)

### 2. rustyjack-core/src/operations.rs
- Removed duplicate lines (1059-1061) that caused syntax error

### 3. rustyjack-core/src/autopilot.rs
- Removed unused imports: `serde_json::json`, `process_running_pattern`, `KillResult`

### 4. rustyjack-ui/Cargo.toml
- Downgraded to compatible versions:
  - `embedded-graphics = "0.7"` (was 0.8)
  - `st7735-lcd = "0.8"` (was 0.9/0.10)
  - `linux-embedded-hal = "0.3"` (was 0.4)
  - `gpio-cdev = "0.5"` (was 0.6)
  - `tinybmp = "0.3"` (was 0.4/0.5)
  - `image = "0.23"` (was 0.24)
- Added `[patch.crates-io]` section to force `embedded-hal = "=0.2.7"`

### 5. rustyjack-ui/src/display.rs  
- Updated imports for embedded-graphics 0.7:
  - `fonts::{Font6x8, Text}` instead of `mono_font`
  - `style::{PrimitiveStyle, TextStyle}` instead of separate imports
- Changed struct fields:
  - `text_style_regular` instead of `font_regular`
  - `text_style_highlight` instead of `font_highlight`  
  - `text_style_small` instead of `font_small`
- Updated initialization to use `TextStyle::new(Font6x8, color)`
- Fixed ST7735::new to use `u16` widths (not `u32`)
- Fixed Rectangle::new to use bottom-right Point (not Size)
- Added error mapping for `.draw()` calls (returns `()` in 0.7)

### 6. rustyjack-ui/src/input.rs
- Removed `LineRequestFlags::BIAS_PULL_UP` (not available in gpio-cdev 0.5)

### 7. rustyjack-ui/src/stats.rs
- Removed unused `Instant` import

## How to Deploy

### On Windows (where you edit code):

```bash
cd C:\Users\teagu\Desktop\Rustyjack

# Add all changes
git add -A

# Commit
git commit -m "Fix embedded-hal dependency conflicts and compilation errors

- Downgrade to compatible embedded-graphics 0.7 ecosystem
- Add missing libc dependency
- Remove duplicate code and unused imports  
- Fix display.rs for embedded-graphics 0.7 API
- Remove unsupported GPIO flags"

# Push
git push
```

### On Raspberry Pi:

```bash
# Switch to root
sudo su -

# Go to project
cd /root/Rustyjack

# Pull changes
git pull

# Clean everything
cargo clean
rm -rf */Cargo.lock

# IMPORTANT: Run the fix script to update display.rs
python3 fix_display_final.py

# Install
./install_rustyjack.sh
```

## What the fix_display_final.py Script Does

1. **Backs up** display.rs to display.rs.backup
2. **Fixes Rectangle API**: Changes from `Size` parameter to bottom-right `Point`
3. **Fixes draw() calls**: Adds `.map_err()` wrapper since 0.7 returns `()`
4. **Fixes Text API**: Updates to use `.into_styled()`  
5. **Removes Size import**: Not needed in 0.7

## If It Still Fails

Check the error message. Common issues:

1. **"no method named..."** - The API changed, check embedded-graphics 0.7 docs
2. **"trait bound not satisfied"** - Version mismatch, run `cargo tree` to debug
3. **"multiple versions of embedded_hal"** - The `[patch]` section should prevent this

## Testing

After successful compilation:

```bash
# Check service
systemctl status rustyjack

# View logs
journalctl -u rustyjack -f

# Test manually
sudo /usr/local/bin/rustyjack-ui
```

## Rollback if Needed

```bash
cd /root/Rustyjack
git log --oneline
git reset --hard <previous-commit-hash>
```

---

**Note**: This uses embedded-graphics 0.7 which is older but stable and compatible with the embedded-hal 0.2 ecosystem used by linux-embedded-hal 0.3.
