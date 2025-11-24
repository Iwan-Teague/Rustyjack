# Waveshare 1.44″ LCD HAT - Complete GPIO Pin Mapping

## 🎯 Quick Reference

This document lists **ALL** GPIO pins used by the Waveshare 1.44″ LCD HAT on your Raspberry Pi Zero 2 W, as implemented in the Rustyjack project.

---

## 🔁 Display Rotation

By default Rustyjack rotates the display 90° clockwise so the UI is shown
in landscape mode on portable Pi builds (e.g. Pi Zero 2 W). You can override
the default at runtime using the environment variable:

```bash
# Set portrait (no rotation)
export RUSTYJACK_DISPLAY_ROTATION=portrait

# Set landscape (90° clockwise) - default
export RUSTYJACK_DISPLAY_ROTATION=landscape
```
If Rustyjack runs as a systemd service the installer enables landscape by
default (see `install_rustyjack.sh` systemd `Environment=` line).

---

## 📺 Display Pins (ST7735S LCD Controller)

### SPI Interface
| Function | BCM GPIO | Physical Pin | Description | Wire Color (typical) |
|----------|----------|--------------|-------------|----------------------|
| **SCLK** | GPIO 11 | Pin 23 | SPI Clock | Orange |
| **MOSI** | GPIO 10 | Pin 19 | SPI Data (Master Out) | Yellow |
| **CS** | GPIO 8 (CE0) | Pin 24 | SPI Chip Select | Green |

### Control Pins
| Function | BCM GPIO | Physical Pin | Description | Used In Code |
|----------|----------|--------------|-------------|--------------|
| **DC** | GPIO 25 | Pin 22 | Data/Command Select | `display.rs` line 114 |
| **RST** | GPIO 27 | Pin 13 | Reset (Active Low) | `display.rs` line 117 |
| **BL** | GPIO 24 | Pin 18 | Backlight Control | `display.rs` line 122 |

### Power
| Function | Physical Pin | Description |
|----------|--------------|-------------|
| **VCC** | Pin 1 or 17 | 3.3V Power Supply |
| **GND** | Pin 6, 9, 14, 20, 25, 30, 34, 39 | Ground |

---

## 🕹️ Input Pins (Joystick + Buttons)

### 5-Way Joystick
| Direction | BCM GPIO | Physical Pin | Description | Config File Key |
|-----------|----------|--------------|-------------|-----------------|
| **UP** | GPIO 6 | Pin 31 | Joystick Up | `key_up_pin: 6` |
| **DOWN** | GPIO 19 | Pin 35 | Joystick Down | `key_down_pin: 19` |
| **LEFT** | GPIO 5 | Pin 29 | Joystick Left | `key_left_pin: 5` |
| **RIGHT** | GPIO 26 | Pin 37 | Joystick Right | `key_right_pin: 26` |
| **PRESS** | GPIO 13 | Pin 33 | Joystick Center Press | `key_press_pin: 13` |

### Push Buttons
| Button | BCM GPIO | Physical Pin | Description | Config File Key |
|--------|----------|--------------|-------------|-----------------|
| **KEY1** | GPIO 21 | Pin 40 | Button 1 (leftmost) | `key1_pin: 21` |
| **KEY2** | GPIO 20 | Pin 38 | Button 2 (middle) | `key2_pin: 20` |
| **KEY3** | GPIO 16 | Pin 36 | Button 3 (rightmost) | `key3_pin: 16` |

---

## 🔧 Configuration Files

### Display Pins - `rustyjack-ui/src/display.rs`
```rust
// Lines 102-122 (corrected for Waveshare HAT)
let dc_line = chip.get_line(25).context("getting DC line")?;      // GPIO 25
let rst_line = chip.get_line(27).context("getting RST line")?;    // GPIO 27
let bl_line = chip.get_line(24).context("getting backlight line")?; // GPIO 24
```

### Input Pins - `gui_conf.json`
```json
{
  "pins": {
    "key_up_pin": 6,
    "key_down_pin": 19,
    "key_left_pin": 5,
    "key_right_pin": 26,
    "key_press_pin": 13,
    "key1_pin": 21,
    "key2_pin": 20,
    "key3_pin": 16
  }
}
```

### Input Defaults - `rustyjack-ui/src/config.rs`
```rust
// Lines 83-108 (Waveshare defaults)
const fn default_key_up() -> u32 { 6 }
const fn default_key_down() -> u32 { 19 }
const fn default_key_left() -> u32 { 5 }
const fn default_key_right() -> u32 { 26 }
const fn default_key_press() -> u32 { 13 }
const fn default_key1() -> u32 { 21 }
const fn default_key2() -> u32 { 20 }
const fn default_key3() -> u32 { 16 }
```

---

## 📋 Physical Layout Diagram

```
┌─────────────────────────────────────────┐
│  Waveshare 1.44" LCD HAT                │
│  ┌──────────────────────────────────┐   │
│  │                                  │   │
│  │    128x128 Color LCD Display    │   │
│  │      (ST7735S Controller)       │   │
│  │                                  │   │
│  └──────────────────────────────────┘   │
│                                         │
│        ◄ LEFT    UP ▲                  │
│                     │                   │
│   RIGHT ►  ● CENTER │ DOWN ▼           │
│              (PRESS)                    │
│                                         │
│    [KEY1]    [KEY2]    [KEY3]          │
│      21        20        16             │
└─────────────────────────────────────────┘
        Plugs onto Raspberry Pi GPIO
```

---

## 🧪 Pin Testing Commands

### Test Display Backlight
```bash
# Turn backlight ON
gpioset gpiochip0 24=1

# Turn backlight OFF
gpioset gpiochip0 24=0
```

### Dimming / Soft brightness control

If you want to reduce the backlight brightness slightly from software, you have two options:

1. Rewire BL to a PWM-capable pin (BCM18 / physical pin 12) and use a PWM daemon (recommended):

```bash
# Install and run pigpio (daemon)
sudo apt-get install -y pigpio
sudo systemctl enable --now pigpiod

# Example: set 60% duty on GPIO 18 (0-255 range)
pigs p 18 $((255 * 60 / 100))
```

2. Hardware resistor in series on the BL line to reduce LED current (e.g. 10Ω–33Ω) — smallest change and hardware-only.

Note: the project can add a software PWM implementation that toggles the BL pin on BCM24, but that is less efficient and can cause CPU usage. If you want that I can add code to support it.

### Test Buttons/Joystick
```bash
# Monitor joystick UP (GPIO 6)
gpioget gpiochip0 6
# Returns: 0 = pressed, 1 = released

# Monitor all input pins
watch -n 0.1 'echo "UP:$(gpioget gpiochip0 6) DOWN:$(gpioget gpiochip0 19) LEFT:$(gpioget gpiochip0 5) RIGHT:$(gpioget gpiochip0 26) PRESS:$(gpioget gpiochip0 13) K1:$(gpioget gpiochip0 21) K2:$(gpioget gpiochip0 20) K3:$(gpioget gpiochip0 16)"'
```

### Check SPI Bus
```bash
# Verify SPI device exists
ls -l /dev/spidev0.0

# Check SPI module loaded
lsmod | grep spi

# Test SPI communication (requires spi-tools)
sudo apt-get install spi-tools
spi-config -d /dev/spidev0.0 -q
```

---

## 🔍 Troubleshooting

### Display Not Working?

1. **Check SPI is enabled:**
   ```bash
   sudo raspi-config
   # Interface Options → SPI → Enable
   ```

2. **Verify GPIO pins in display.rs:**
   ```bash
   grep -n "get_line" ~/Rustyjack/rustyjack-ui/src/display.rs
   # Should show: DC=25, RST=27, BL=24
   ```

3. **Test hardware connections:**
   - HAT should be firmly seated on all 40 GPIO pins
   - No bent or missing pins
   - Power LED on HAT should be lit (if present)

### Buttons Not Responding?

**IMPORTANT**: If buttons stopped working after a code update, you may need the GPIO pull-up fix.

1. **Check if your code enables pull-ups programmatically:**
   ```bash
   grep -n "BIAS_PULL_UP" ~/Rustyjack/rustyjack-ui/src/input.rs
   # Should show: LineRequestFlags::INPUT | LineRequestFlags::BIAS_PULL_UP
   ```
   
   If missing, update your code (see BUTTON_FIX.md) or rebuild from latest commit.

2. **Check pull-up resistors are configured in boot config:**
   ```bash
   # For Pi images that need explicit config, add to /boot/config.txt (the
   # installer does this automatically). Note: changes to /boot/config.txt
   # require a reboot to take effect.
   gpio=6,19,5,26,13,21,20,16=pu
   ```

2. **Test individual buttons:**
   ```bash
   # Install gpio tools
   sudo apt-get install gpiod
   
   # Test joystick UP
   gpioget gpiochip0 6
   # Press UP → should read 0
   # Release → should read 1
   ```

3. **Check config file:**
   ```bash
   cat ~/Rustyjack/gui_conf.json
   # Verify pins match the table above
   ```

---

## 📖 Official Documentation

- **Waveshare Wiki**: [1.44inch LCD HAT](https://www.waveshare.com/wiki/1.44inch_LCD_HAT)
- **ST7735S Datasheet**: [PDF Link](https://files.waveshare.com/upload/e/e2/ST7735S_V1.1_20111121.pdf)
- **Raspberry Pi Pinout**: [pinout.xyz](https://pinout.xyz/)
- **BCM2835 GPIO**: [elinux.org/RPi_BCM2835_GPIOs](https://elinux.org/RPi_BCM2835_GPIOs)

---

## 🚨 Important Notes

### ✅ DO:
- Use BCM GPIO numbering (as shown in tables above)
- Ensure SPI is enabled before running Rustyjack
- Test buttons with `gpioget` before debugging code
- Keep HAT firmly seated on GPIO header

### ❌ DON'T:
- Use physical pin numbers in code (use BCM GPIO numbers)
- Hot-swap the HAT while Pi is powered on
- Connect 5V to any GPIO pins (all are 3.3V only)
- Use pins for other purposes while HAT is connected

---

## 📝 Change History

| Date | Change | Reason |
|------|--------|--------|
| 2024-11-24 | Fixed RST pin: GPIO 24 → GPIO 27 | Corrected to Waveshare spec |
| 2024-11-24 | Fixed BL pin: GPIO 18 → GPIO 24 | Corrected to Waveshare spec |
| 2024-11-24 | Verified all input pins match Waveshare | No changes needed |
| 2024-11-24 | Document created | Centralized pin reference |
| 2024-11-24 | Default display rotation set to Landscape and env var added | UX improvement for Pi Zero orientation |
| 2024-11-24 | Button GPIO pull-up fix applied to input.rs | Added BIAS_PULL_UP flag for reliable button input |

---

## ✅ Verification Checklist

Use this when setting up a new Pi or debugging hardware:

- [ ] SPI enabled in raspi-config
- [ ] /dev/spidev0.0 exists
- [ ] Display pins: DC=25, RST=27, BL=24
- [ ] Joystick pins: UP=6, DOWN=19, LEFT=5, RIGHT=26, PRESS=13
- [ ] Button pins: KEY1=21, KEY2=20, KEY3=16
- [ ] GPIO pull-ups enabled in code (BIAS_PULL_UP flag) or config.txt
- [ ] HAT firmly seated on GPIO header
- [ ] Power LED on (if present)
- [ ] Backlight can be controlled with `gpioset gpiochip0 24=1`
- [ ] Buttons respond to `gpioget` tests (0 when pressed, 1 when released)
- [ ] Rustyjack service starts without GPIO errors

---

**Last Updated**: November 24, 2024  
**Tested On**: Raspberry Pi Zero 2 W with Waveshare 1.44″ LCD HAT  
**Rustyjack Version**: Phase 3 (100% Rust UI)
