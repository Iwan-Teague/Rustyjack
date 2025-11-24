# Rustyjack Display Fix Summary

## Problem
Display backlight turns on but shows only a blank/white screen on Raspberry Pi Zero W 2.

## Root Cause
The **ST7735 LCD display** was initialized with incorrect color inversion settings. Different ST7735 variants (ST7735R, ST7735S, ST7735B) require different parameters.

## Solution Applied

### Code Changes
**File**: `rustyjack-ui/src/display.rs` (line ~93)

**BEFORE:**
```rust
let mut lcd = ST7735::new(spi, dc, rst, true, false, LCD_WIDTH as u32, LCD_HEIGHT as u32);
//                                       ^^^^ ^^^^^ - RGB mode, NOT inverted = WHITE SCREEN
```

**AFTER:**
```rust
let mut lcd = ST7735::new(spi, dc, rst, true, true, LCD_WIDTH as u32, LCD_HEIGHT as u32);
//                                       ^^^^ ^^^^ - RGB mode, INVERTED = Should work!
lcd.clear(Rgb565::BLACK)?;  // Clear to black
// Add test pattern to verify display works
Rectangle::new(Point::new(0, 0), Size::new(128, 128))
    .into_styled(PrimitiveStyle::with_stroke(Rgb565::GREEN, 2))
    .draw(&mut lcd)?;
```

## Deployment Instructions

### Option 1: Using the deployment script (Recommended)
```bash
cd ~/Rustyjack
chmod +x fix_display.sh
./fix_display.sh
```

### Option 2: Manual deployment
```bash
cd ~/Rustyjack
sudo systemctl stop rustyjack
cd rustyjack-ui
cargo build --release
sudo cp target/release/rustyjack-ui /usr/local/bin/
sudo systemctl start rustyjack
```

### Option 3: Using Git (if you've pushed changes)
```bash
cd ~/Rustyjack
git pull
./fix_display.sh
```

## Verification

After deploying, you should see:
1. **Backlight turns on** (already working)
2. **Screen clears to black** (new)
3. **Green border appears** around the screen (test pattern)
4. **Splash screen or menu appears** within 2 seconds

Check logs:
```bash
sudo journalctl -u rustyjack -f
```

## If Display Still Doesn't Work

### Step 1: Run Diagnostics
```bash
cd ~/Rustyjack
chmod +x diagnose_display.sh
./diagnose_display.sh
```

### Step 2: Verify SPI is Enabled
```bash
ls -l /dev/spidev0.0
```

If not found:
```bash
sudo raspi-config
# Navigate to: Interface Options -> SPI -> Enable -> Yes
sudo reboot
```

### Step 3: Try Alternative Configurations
See `DISPLAY_FIX_ALTERNATIVES.md` and `DISPLAY_VARIANTS.rs` for other configurations to try.

Most common alternatives:
1. **BGR mode**: Change `true, true` to `false, false` in ST7735::new()
2. **Different offset**: Change `set_offset(2, 1)` to `set_offset(0, 0)`
3. **Lower SPI speed**: Change `12_000_000` to `4_000_000` Hz

### Step 4: Verify Hardware Connections
Ensure your ST7735 display is connected to (Waveshare 1.44" HAT wiring):
- **VCC** → 3.3V (Pin 1 or 17)
- **GND** → Ground (Pin 6)
- **SCL** → GPIO 11 (Pin 23)
- **SDA** → GPIO 10 (Pin 19)
- **RES** → GPIO 27 (Pin 13)  # corrected for Waveshare HAT
- **DC** → GPIO 25 (Pin 22)
- **CS** → GPIO 8 (Pin 24)
- **BL** → GPIO 24 (Pin 18)   # corrected for Waveshare HAT

If your HAT uses different pins, edit `display.rs` lines 72-86.

## Pin Configuration Reference

Current configuration (Waveshare 1.44" LCD HAT):
```rust
DC Pin:  GPIO 25
RST Pin: GPIO 27
BL Pin:  GPIO 24
```

Alternative configurations:
- **Adafruit ST7735 displays**: DC=25, RST=24, BL=18
- **Pimoroni Display HAT Mini**: DC=9, RST=25, BL=13

## Quick Test Without Service
To test display changes quickly:
```bash
sudo systemctl stop rustyjack
cd ~/Rustyjack/rustyjack-ui
sudo ./target/release/rustyjack-ui
# Watch the display. Press Ctrl+C when done.
sudo systemctl start rustyjack
```

## Expected Behavior After Fix

1. **Startup (0-1s)**: Backlight on, black screen
2. **Init (1-2s)**: Green border appears around screen edges
3. **Splash (2-3s)**: "RUSTYJACK" logo or splash image
4. **Ready (3s+)**: Main menu appears

If you see the green border, the display is working correctly!

## Dimming / Reducing Backlight Brightness

The Waveshare HAT typically drives the backlight via a single GPIO (BCM24) as an on/off control. BCM24 is not a hardware PWM pin on most Pis, so there are two safe ways to reduce brightness:

1. Re-wire the backlight to a PWM-capable pin (recommended for software control)
    - Physical pin 12 = BCM18 is a hardware PWM pin on Raspberry Pi.
    - Move the HAT's BL wire to BCM18 (if your HAT wiring allows it) and then use a PWM utility such as pigpio to set a duty-cycle.
    - Example using pigpio (after installation):

```bash
sudo apt-get update && sudo apt-get install -y pigpio
sudo systemctl enable --now pigpiod
# Set 50% duty on GPIO 18 (0-255):
pigs p 18 128

# To reset to fully ON:
pigs p 18 255
```

2. Hardware reduction (works without re-wiring)
    - Fit a small series resistor (e.g. 10Ω–33Ω, try values starting high then lower) in the BL line to reduce LED current and lower perceived brightness.
    - This is the safest electrical method if you prefer not to change wiring or rely on software PWM.

Note: we can implement software (threaded) PWM in the code that toggles the BL line if you prefer a code-side implementation while leaving BL on BCM24 — tell me and I can add it, but hardware PWM (BCM18) will give smoother results and lower CPU load.

## Support

If issues persist:
1. Check `sudo journalctl -u rustyjack -n 100` for error messages
2. Run `./diagnose_display.sh` and share the output
3. Verify your specific ST7735 HAT/display model and pin configuration
4. Try the alternative configurations in `DISPLAY_VARIANTS.rs`

## Files Changed
- `rustyjack-ui/src/display.rs` - Fixed color inversion, added test pattern
- `fix_display.sh` - Automated deployment script
- `diagnose_display.sh` - Hardware diagnostic script
- `DISPLAY_DIAGNOSTIC.md` - Detailed troubleshooting guide
- `DISPLAY_FIX_ALTERNATIVES.md` - Alternative configurations
- `DISPLAY_VARIANTS.rs` - Code variants to try

## Technical Details

**Display Type**: ST7735 128x128 RGB LCD
**SPI Bus**: /dev/spidev0.0 (SPI0)
**SPI Mode**: MODE_0
**SPI Speed**: 12 MHz
**Color Mode**: RGB565
**Inverted**: Yes (changed from No)
**Orientation**: Landscape (90° clockwise by default)

You can override the default rotation by setting the environment variable
`RUSTYJACK_DISPLAY_ROTATION` to either `portrait` or `landscape`. The systemd
unit created by `install_rustyjack.sh` sets the service default to `landscape`.
**Offset**: X=2, Y=1
