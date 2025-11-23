# RUSTYJACK FIX INSTRUCTIONS

## Problem
The rustyjack-ui crate has dependency conflicts between:
- `st7735-lcd` versions
- `embedded-graphics` versions  
- `embedded-hal` versions
- `linux-embedded-hal` versions

These crates must all use compatible versions of `embedded-hal`.

## Solution
Use this exact combination of versions that are known to work together:

```toml
embedded-graphics = "0.7"
st7735-lcd = "0.8" 
embedded-hal = "0.2.7"
linux-embedded-hal = "0.3"
gpio-cdev = "0.5"
tinybmp = "0.3"
image = "0.23"
```

## Changes Made

1. **Cargo.toml** - Updated to use compatible versions with [patch] section
2. **display.rs** - Updated imports to use embedded-graphics 0.7 API:
   - `TextStyle` instead of `MonoTextStyle`
   - `Font6x8` instead of `FONT_6X10`
   - Struct fields renamed to `text_style_*` instead of `font_*`
   - Rectangle constructor uses bottom-right Point instead of Size
   - `.draw()` returns `()` so needs `.map_err()` wrapper

## TODO on Pi

After git pull on the Pi, you need to:

1. Clean the build:
```bash
cd /root/Rustyjack
cargo clean
rm -rf */Cargo.lock */target
```

2. Run the fix script (if display.rs still has issues):
```bash
cd /root/Rustyjack
python3 fix_display_final.py
```

3. Build:
```bash
./install_rustyjack.sh
```

## If Still Fails

The display.rs file needs manual fixes for embedded-graphics 0.7 API:

1. All `Rectangle::new(Point::new(x, y), Size::new(w, h))` 
   → `Rectangle::new(Point::new(x, y), Point::new(x + w - 1, y + h - 1))`

2. All `.draw(&mut self.lcd)?`
   → `.draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?`

3. All `Text::new(text, point, style).draw()`
   → `Text::new(text, point).into_styled(style).draw()`

4. Replace `self.font_*` with `self.text_style_*`
