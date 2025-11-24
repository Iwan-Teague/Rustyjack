# URGENT: Deploy Display Fix to Raspberry Pi

## The Problem
The code fix IS in your repository, but it hasn't been compiled and deployed on your Pi yet!

## Quick Fix - Run These Commands on Your Pi:

### Step 1: SSH into your Pi
```bash
ssh root@rustyjack
# or whatever your Pi's hostname/IP is
```

### Step 2: Pull the latest code
```bash
cd ~/Rustyjack
git fetch origin
git checkout test
git pull origin test
```

### Step 3: Stop the service
```bash
sudo systemctl stop rustyjack
```

### Step 4: Rebuild the UI
```bash
cd ~/Rustyjack/rustyjack-ui
cargo build --release
```
**NOTE**: This will take 10-20 minutes on a Pi Zero W 2! Be patient.

### Step 5: Install the new binary
```bash
sudo cp target/release/rustyjack-ui /usr/local/bin/rustyjack-ui
sudo chmod +x /usr/local/bin/rustyjack-ui
```

### Step 6: Restart the service
```bash
sudo systemctl restart rustyjack
```

### Step 7: Check if it's working
```bash
# Watch the logs
sudo journalctl -u rustyjack -f
```

You should now see a black screen with a green border, then the menu!

---

## Alternative: Use the Deployment Script

If you see the `fix_display.sh` script in the repo:
```bash
cd ~/Rustyjack
chmod +x fix_display.sh
./fix_display.sh
```

This does all the steps above automatically.

---

## Why It Wasn't Working

1. ✅ Code changes ARE in the repository (test branch)
2. ❌ But the Pi is still running the OLD compiled binary
3. ❌ You need to **rebuild** the Rust code on the Pi
4. ❌ Then **install** the new binary to `/usr/local/bin/`

The systemd service runs the binary at `/usr/local/bin/rustyjack-ui` - you need to replace that file with the newly compiled version.

---

## What the Fix Does

Changes in `rustyjack-ui/src/display.rs` line 101:
- **Before**: `ST7735::new(spi, dc, rst, true, false, ...)`
- **After**: `ST7735::new(spi, dc, rst, true, true, ...)`
- Plus adds a test pattern (green border) to verify display works

This fixes the color inversion issue that causes the white screen.

---

## If Still Not Working After Rebuild

1. Check SPI is enabled:
   ```bash
   ls -l /dev/spidev0.0
   ```
   
2. Run diagnostics:
   ```bash
   cd ~/Rustyjack
   chmod +x diagnose_display.sh
   ./diagnose_display.sh
   ```

3. Check for errors in logs:
   ```bash
   sudo journalctl -u rustyjack -n 100 --no-pager
   ```

4. Try different display variants (see DISPLAY_VARIANTS.rs)
