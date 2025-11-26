use crate::config::ColorScheme;
use anyhow::Result;
use embedded_graphics::{
    image::Image,
    pixelcolor::{Rgb565, Rgb888},
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    mono_font::{ascii::FONT_6X10, MonoTextStyle, MonoTextStyleBuilder},
    text::{Baseline, Text},
};

/// Wraps text at specified character width, breaking on word boundaries when possible
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if text.len() <= max_width {
        return vec![text.to_string()];
    }
    
    let mut lines = Vec::new();
    let mut current_line = String::new();
    
    for word in text.split_whitespace() {
        if current_line.is_empty() {
            // First word on line
            if word.len() > max_width {
                // Word itself is too long, force-break it
                let mut remaining = word;
                while remaining.len() > max_width {
                    lines.push(remaining[..max_width].to_string());
                    remaining = &remaining[max_width..];
                }
                current_line = remaining.to_string();
            } else {
                current_line = word.to_string();
            }
        } else if current_line.len() + 1 + word.len() <= max_width {
            // Word fits on current line
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            // Word doesn't fit, start new line
            lines.push(current_line);
            if word.len() > max_width {
                // Word itself is too long, force-break it
                let mut remaining = word;
                while remaining.len() > max_width {
                    lines.push(remaining[..max_width].to_string());
                    remaining = &remaining[max_width..];
                }
                current_line = remaining.to_string();
            } else {
                current_line = word.to_string();
            }
        }
    }
    
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    
    if lines.is_empty() {
        vec![text.to_string()]
    } else {
        lines
    }
}
use std::path::Path;
use image::GenericImageView;

#[cfg(target_os = "linux")]
use anyhow::Context;

#[cfg(target_os = "linux")]
use tinybmp::Bmp;

#[cfg(target_os = "linux")]
use linux_embedded_hal::{
    Delay,
    spidev::{SpiModeFlags, SpidevOptions},
    SpidevDevice,
    CdevPin,
    gpio_cdev::{Chip, LineRequestFlags},
};

#[cfg(target_os = "linux")]
use st7735_lcd::{Orientation, ST7735};
use std::{thread::sleep, time::Duration as StdDuration};

#[cfg(target_os = "linux")]
const LCD_WIDTH: u16 = 128;
#[cfg(target_os = "linux")]
const LCD_HEIGHT: u16 = 128;
// Offset adjusted to utilize full screen width and avoid dead pixels
// ST7735S has a 132x162 buffer but Waveshare 1.44" uses 128x128 visible
// X offset of 2 shifts content to use full visible area
#[cfg(target_os = "linux")]
// Offset X is 0 by default to align drawing to left edge on most displays.
// Some ST7735 modules exposed an extra left column when set to 2 — this caused
// a white backlight column to show on the edge of some panels. Set default to
// 0 so UI fills the entire visible area on typical Waveshare 1.44" modules.
const LCD_OFFSET_X: u16 = 0;
#[cfg(target_os = "linux")]
const LCD_OFFSET_Y: u16 = 1;

#[cfg(target_os = "linux")]
pub struct Display {
    lcd: ST7735<SpidevDevice, CdevPin, CdevPin>,
    // Hold the backlight pin so it remains reserved for the lifetime of the
    // Display instance. Previously this was kept in a temporary local which
    // caused the line to be released when the constructor returned.
    backlight: CdevPin,
    palette: Palette,
    text_style_regular: MonoTextStyle<'static, Rgb565>,
    text_style_highlight: MonoTextStyle<'static, Rgb565>,
    text_style_small: MonoTextStyle<'static, Rgb565>,
}

#[cfg(not(target_os = "linux"))]
pub struct Display {
    palette: Palette,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct Palette {
    pub background: Rgb565,
    pub border: Rgb565,
    pub text: Rgb565,
    pub selected_text: Rgb565,
    pub selected_background: Rgb565,
}

#[cfg(target_os = "linux")]
impl Display {
    pub fn new(colors: &ColorScheme) -> Result<Self> {
        // Open SPI device using SpidevDevice (embedded-hal 1.0 compatible)
        let mut spi = SpidevDevice::open("/dev/spidev0.0")
            .context("opening SPI device")?;
        
        // Configure the underlying device
        // Use a slightly lower default SPI speed to improve stability on
        // long/fragile wiring and marginal ST7735 modules. If you still get a
        // blank screen try an even lower value (2_000_000) or change init
        // variants in DISPLAY_FIX_ALTERNATIVES.md
        let options = SpidevOptions::new()
            .bits_per_word(8)
            .max_speed_hz(4_000_000)
            .mode(SpiModeFlags::SPI_MODE_0)
            .build();
        spi.configure(&options)
            .context("configuring SPI")?;

        // If diagnostic mode is enabled via env var we run a set of init
        // permutations to help identify a working configuration on a
        // problematic module. The diagnostic routine needs to open SPI and
        // claim GPIO lines itself — so we must run diagnostics before this
        // function requests any gpio lines.
        if std::env::var("RUSTYJACK_DISPLAY_DIAG").is_ok() {
            if let Err(e) = Self::run_diagnostics(colors) {
                eprintln!("Display diagnostics failed: {:#}", e);
            }
            std::process::exit(0);
        }

        // Use CdevPin for GPIO (embedded-hal 1.0 compatible)
        // Pin configuration for Waveshare 1.44" LCD HAT:
        // DC (Data/Command): GPIO 25
        // RST (Reset): GPIO 27
        // BL (Backlight): GPIO 24
        let mut chip = Chip::new("/dev/gpiochip0").context("opening GPIO chip")?;
        
        let dc_line = chip.get_line(25).context("getting DC line")?;
        let dc_handle = dc_line.request(LineRequestFlags::OUTPUT, 0, "rustyjack-dc")
            .context("requesting DC line")?;
        let dc = CdevPin::new(dc_handle).context("creating DC pin")?;
        
        let rst_line = chip.get_line(27).context("getting RST line")?;
        let rst_handle = rst_line.request(LineRequestFlags::OUTPUT, 0, "rustyjack-rst")
            .context("requesting RST line")?;
        let rst = CdevPin::new(rst_handle).context("creating RST pin")?;
        
        let bl_line = chip.get_line(24).context("getting backlight line")?;
        let bl_handle = bl_line.request(LineRequestFlags::OUTPUT, 1, "rustyjack-bl")
            .context("requesting backlight line")?;
        let backlight = CdevPin::new(bl_handle).context("creating backlight pin")?;

        // If diagnostic mode is enabled via env var we run a set of init
        // permutations to help identify a working configuration on a
        // problematic module. This routine doesn't replace the normal UI
        // flow, it just allows you to run diagnostics when invoked.
        if std::env::var("RUSTYJACK_DISPLAY_DIAG").is_ok() {
            // run diagnostics by taking ownership of the SPI and pins.
            if let Err(e) = Self::run_diagnostics(colors) {
                eprintln!("Display diagnostics failed: {:#}", e);
            }
            std::process::exit(0);
        }

        let mut delay = Delay {};
        // Try RGB mode with inverted colors (common fix for white screen)
        let mut lcd = ST7735::new(spi, dc, rst, true, true, LCD_WIDTH as u32, LCD_HEIGHT as u32);
        lcd.init(&mut delay).map_err(|_| anyhow::anyhow!("LCD init failed"))?;
        // Rotate the display 90° clockwise by default (Landscape). Many Waveshare
        // HATs look better in landscape mode on the Pi Zero form factor.
        // Allow override with RUSTYJACK_DISPLAY_ROTATION={portrait|landscape}
        let orientation = match std::env::var("RUSTYJACK_DISPLAY_ROTATION").as_deref() {
            Ok("portrait") => Orientation::Portrait,
            Ok("landscape") => Orientation::Landscape,
            // fallback default: rotate 90° clockwise
            _ => Orientation::Landscape,
        };
        lcd.set_orientation(&orientation).map_err(|_| anyhow::anyhow!("LCD orientation failed"))?;
        lcd.set_offset(LCD_OFFSET_X, LCD_OFFSET_Y);
        
        // Clear screen to black on startup
        lcd.clear(Rgb565::BLACK).map_err(|_| anyhow::anyhow!("LCD clear failed"))?;

        let palette = Palette::from_scheme(colors);
        let text_style_regular = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(palette.text)
            .build();
        let text_style_highlight = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(palette.selected_text)
            .build();
        let text_style_small = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(palette.text)
            .build();

        Ok(Self {
            lcd,
            palette,
            text_style_regular,
            text_style_highlight,
            text_style_small,
            backlight,
        })
    }

    /// Run a diagnostic sequence on the LCD — cycles a few common SPI speeds
    /// and ST7735 init parameter combinations so you can visually identify
    /// a configuration that makes the module render correctly.
    pub fn run_diagnostics(_colors: &ColorScheme) -> Result<()> {
        // Common speeds to try (some modules are sensitive to speed)
        let speeds = [1_000_000u32, 2_000_000u32, 4_000_000u32, 8_000_000u32, 12_000_000u32];
        let bgr_choices = [true, false];
        let invert_choices = [true, false];
        let orientations = [Orientation::Portrait, Orientation::Landscape];

        // Small palette for borders so it's obvious on-screen which mode is active
        let diag_colors = [
            Rgb565::RED,
            Rgb565::GREEN,
            Rgb565::BLUE,
            Rgb565::YELLOW,
            Rgb565::MAGENTA,
            Rgb565::CYAN,
            Rgb565::WHITE,
        ];

        println!("Starting display diagnostics — cycling init options.\nSet RUSTYJACK_DISPLAY_DIAG=1 to run this from the device.");

        let mut attempt = 0usize;
        // helper to print orientation as text — Orientation doesn't implement Debug
        fn orient_label(o: Orientation) -> &'static str {
            match o {
                Orientation::Portrait => "portrait",
                Orientation::Landscape => "landscape",
                // keep sensible default for other variants
                _ => "other",
            }
        }
        for &speed in &speeds {
            for &bgr in &bgr_choices {
                for &inv in &invert_choices {
                    for &orient in &orientations {
                        attempt += 1;
                        eprintln!("Diag #{}: speed={} bgr={} invert={} orient={}", attempt, speed, bgr, inv, orient_label(orient));

                        // Open fresh SPI and GPIO lines for each attempt so ownership
                        // is clean between iterations.
                        let mut spi = match SpidevDevice::open("/dev/spidev0.0") {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("diag: opening SPI device failed: {:#}", e);
                                // skip this iteration
                                continue;
                            }
                        };

                        let options = SpidevOptions::new()
                            .bits_per_word(8)
                            .max_speed_hz(speed)
                            .mode(SpiModeFlags::SPI_MODE_0)
                            .build();
                        spi.configure(&options).context("configuring spi for diag")?;

                        let mut chip = match Chip::new("/dev/gpiochip0") {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("diag: opening gpiochip failed: {:#}", e);
                                continue;
                            }
                        };

                        // helper to request a line but retry briefly if it's busy
                        fn request_line_with_retry(chip: &mut Chip, line: u32, consumer: &str, default: u8) -> Result<CdevPin, anyhow::Error> {
                            let mut tries = 0usize;
                            loop {
                                match chip.get_line(line) {
                                    Ok(l) => match l.request(LineRequestFlags::OUTPUT, default, consumer) {
                                        Ok(handle) => return CdevPin::new(handle).map_err(|e| e.into()),
                                        Err(_e) => {
                                            // Common case is EBUSY (line owned by another
                                            // process). Retry a few times with a short backoff
                                            // in case the other process is shutting down.
                                            tries += 1;
                                            if tries < 8 {
                                                sleep(StdDuration::from_millis(120));
                                                continue;
                                            }

                                            // Before giving up, dump some system state so the
                                            // user (and us) can see who owns the gpiochip and
                                            // why the request failed.
                                            eprintln!("diag: requesting {} line for diag: failed after retries — dumping system state:", consumer);
                                            // Try `gpioinfo` (preferred) and a few helpful utilities
                                            // — these may or may not be present on the minimal image,
                                            // so we ignore errors.
                                            fn run_cmd(name: &str, args: &[&str]) {
                                                match std::process::Command::new(name).args(args).output() {
                                                    Ok(o) => {
                                                        if !o.stdout.is_empty() {
                                                            let out = String::from_utf8_lossy(&o.stdout);
                                                            eprintln!("--- {} {} stdout ---\n{}", name, args.join(" "), out);
                                                        }
                                                        if !o.stderr.is_empty() {
                                                            let err = String::from_utf8_lossy(&o.stderr);
                                                            eprintln!("--- {} {} stderr ---\n{}", name, args.join(" "), err);
                                                        }
                                                    }
                                                    Err(e) => eprintln!("--- {} not available: {:#}", name, e),
                                                }
                                            }

                                            run_cmd("gpioinfo", &[]);
                                            run_cmd("lsof", &["/dev/gpiochip0"]);
                                            run_cmd("fuser", &["-v", "/dev/gpiochip0"]);
                                            run_cmd("ls", &["-l", "/dev/gpiochip0", "/dev/spidev0.0", "/dev/spidev0.1"]);

                                            return Err(anyhow::anyhow!("requesting {} line for diag: failed after retries", consumer));
                                        }
                                    },
                                    Err(e) => return Err(anyhow::anyhow!("getting {} line for diag: {:#}", consumer, e)),
                                }
                            }
                        }

                        let dc = match request_line_with_retry(&mut chip, 25, "rustyjack-dc", 0u8) {
                            Ok(p) => p,
                            Err(e) => { eprintln!("diag: {}", e); continue; }
                        };

                        let rst = match request_line_with_retry(&mut chip, 27, "rustyjack-rst", 0u8) {
                            Ok(p) => p,
                            Err(e) => { eprintln!("diag: {}", e); continue; }
                        };
                        

                        let _backlight = match request_line_with_retry(&mut chip, 24, "rustyjack-bl", 1) {
                            Ok(p) => p,
                            Err(e) => { eprintln!("diag: {}", e); continue; }
                        };

                        let mut delay = Delay {};
                        // Create the LCD with this combination
                        let mut lcd = ST7735::new(spi, dc, rst, inv, bgr, LCD_WIDTH as u32, LCD_HEIGHT as u32);
                        let _ = lcd.init(&mut delay);
                        let _ = lcd.set_orientation(&orient);
                        lcd.set_offset(LCD_OFFSET_X, LCD_OFFSET_Y);

                        // Clear and draw a border in a diagnostic colour so it's easy
                        // to see which configuration is currently being displayed.
                        lcd.clear(Rgb565::BLACK).ok();
                        let color = diag_colors[attempt % diag_colors.len()];
                        Rectangle::new(Point::new(0, 0), Size::new(LCD_WIDTH as u32, LCD_HEIGHT as u32))
                            .into_styled(PrimitiveStyle::with_stroke(color, 3))
                            .draw(&mut lcd)
                            .ok();

                        // Draw a textual line showing the parameters (clamping length)
                        let info = format!("s={} bgr={} inv={} o={}", speed, bgr, inv, orient_label(orient));
                        let style = MonoTextStyleBuilder::new().font(&FONT_6X10).text_color(color).build();
                        let _ = Text::with_baseline(&info, Point::new(2, 60), style, Baseline::Top).draw(&mut lcd);

                        // Wait so user can see the result
                        sleep(StdDuration::from_millis(900));

                        // Drop lcd, backlight and line handles on loop iteration end so
                        // they are released and can be requested again next iteration
                    }
                }
            }
        }

        println!("Display diagnostics completed ({} attempts). If nothing changed try a hardware loopback test or different wiring.", attempt);
        Ok(())
    }

    pub fn update_palette(&mut self, colors: &ColorScheme) {
        self.palette = Palette::from_scheme(colors);
        self.text_style_regular = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(self.palette.text)
            .build();
        self.text_style_highlight = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(self.palette.selected_text)
            .build();
        self.text_style_small = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(self.palette.text)
            .build();
    }

    pub fn clear(&mut self) -> Result<()> {
        let style = PrimitiveStyle::with_fill(self.palette.background);
        Rectangle::new(
            Point::new(0, 0),
            Size::new(LCD_WIDTH as u32, LCD_HEIGHT as u32),
        )
        .into_styled(style)
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Failed to clear display"))?;
        Ok(())
    }

    pub fn show_splash_screen(&mut self, image_path: &Path) -> Result<()> {
        // Clear screen to black
        let style = PrimitiveStyle::with_fill(Rgb565::BLACK);
        Rectangle::new(Point::new(0, 0), Size::new(LCD_WIDTH.into(), LCD_HEIGHT.into()))
            .into_styled(style)
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Failed to clear screen"))?;

        // Try BMP first (much faster), then PNG fallback
        let bmp_path = image_path.with_extension("bmp");
        let image_to_load = if bmp_path.exists() {
            &bmp_path
        } else {
            image_path
        };

        // Try to load and display the image
        if image_to_load.exists() {
            // Check if it's a BMP file (easy and fast to display)
            if let Some(ext) = image_to_load.extension() {
                if ext == "bmp" {
                    // Load BMP directly (very fast!)
                    let bmp_data = std::fs::read(image_to_load)?;
                    if let Ok(bmp) = Bmp::<Rgb565>::from_slice(&bmp_data) {
                        // Center the image on the screen
                        let bmp_width = bmp.bounding_box().size.width as i32;
                        let bmp_height = bmp.bounding_box().size.height as i32;
                        let x = (LCD_WIDTH as i32 - bmp_width) / 2;
                        let y = (LCD_HEIGHT as i32 - bmp_height) / 2;
                        
                        let image = Image::new(&bmp, Point::new(x.max(0), y.max(0)));
                        image.draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
                        return Ok(());
                    }
                } else {
                    // For PNG/JPG, convert on-the-fly (slower)
                    let img = image::open(image_to_load)?;
                    
                    // Resize to fit screen if needed
                    let img = if img.width() > LCD_WIDTH as u32 || img.height() > LCD_HEIGHT as u32 {
                        img.resize(LCD_WIDTH as u32, LCD_HEIGHT as u32, image::imageops::FilterType::Lanczos3)
                    } else {
                        img
                    };
                    
                    let rgb_img = img.to_rgb8();
                    
                    // Draw pixel by pixel
                    let x_offset = ((LCD_WIDTH as u32 - rgb_img.width()) / 2) as i32;
                    let y_offset = ((LCD_HEIGHT as u32 - rgb_img.height()) / 2) as i32;
                    
                    for (x, y, pixel) in rgb_img.enumerate_pixels() {
                        let rgb888 = Rgb888::new(pixel[0], pixel[1], pixel[2]);
                        let rgb565 = Rgb565::from(rgb888);
                        let px_x = x_offset + x as i32;
                        let px_y = y_offset + y as i32;
                        if px_x >= 0 && px_x < LCD_WIDTH as i32 && px_y >= 0 && px_y < LCD_HEIGHT as i32 {
                            embedded_graphics::Pixel(Point::new(px_x, px_y), rgb565)
                                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
                        }
                    }
                    return Ok(());
                }
            }
        }
        
        // Image not found or load failed, show text fallback
        let text_style = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(Rgb565::new(21, 0, 31))  // Purple #AA00FF in Rgb565
            .build();
        Text::with_baseline("RUSTYJACK", Point::new(30, 60), text_style, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Text::with_baseline("Loading...", Point::new(30, 75), text_style, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    pub fn draw_toolbar(&mut self, status: &StatusOverlay) -> Result<()> {
        let style = PrimitiveStyle::with_fill(Rgb565::new(20, 20, 20));
        Rectangle::new(
            Point::new(0, 0),
            Size::new(LCD_WIDTH as u32, 14)
        )
        .into_styled(style)
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        let temp_text = format!("{:.0}°C", status.temp_c);
        Text::with_baseline(&temp_text, Point::new(2, 2), self.text_style_regular, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        // Display autopilot indicator if running
        if status.autopilot_running {
            let ap_indicator = if status.autopilot_mode.is_empty() {
                "[AP]".to_string()
            } else {
                // Abbreviate mode: Standard->STD, Aggressive->AGR, Stealth->STH, Harvest->HRV
                let mode_abbr = match status.autopilot_mode.as_str() {
                    "Standard" => "STD",
                    "Aggressive" => "AGR",
                    "Stealth" => "STH",
                    "Harvest" => "HRV",
                    _ => "AP"
                };
                format!("[{}]", mode_abbr)
            };
            
            // Draw in center of toolbar with highlight color
            let center_x = (LCD_WIDTH / 2) as i32 - 12; // Approximate center
            Text::with_baseline(&ap_indicator, Point::new(center_x, 2), self.text_style_highlight, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }
        
        if !status.text.is_empty() {
            // In embedded-graphics 0.8, we don't have with_alignment, so just draw at the position
            Text::with_baseline(&status.text, Point::new(90, 2), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }
        Ok(())
    }

    pub fn draw_menu(
        &mut self,
        title: &str,
        items: &[String],
        selected: usize,
        status: &StatusOverlay,
    ) -> Result<()> {
        self.clear()?;
        self.draw_toolbar(status)?;
        // Border removed for cleaner display

        Text::with_baseline(title, Point::new(2, 16), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        let mut y = 30;
        for (idx, label) in items.iter().enumerate() {
            if idx == selected {
                Rectangle::new(
                    Point::new(0, y - 2),
                    Size::new((LCD_WIDTH) as u32, 12)
                )
                .into_styled(PrimitiveStyle::with_fill(self.palette.selected_background))
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            }
            let style = if idx == selected {
                self.text_style_highlight
            } else {
                self.text_style_regular
            };
            Text::with_baseline(label, Point::new(2, y), style, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 12;
        }
        Ok(())
    }

    pub fn draw_dialog(&mut self, lines: &[String], status: &StatusOverlay) -> Result<()> {
        self.clear()?;
        self.draw_toolbar(status)?;
        // No border for cleaner look
        
        let mut y = 22;
        const MAX_CHARS: usize = 20;
        
        for line in lines {
            // Wrap each line if it's longer than MAX_CHARS characters
            let wrapped = wrap_text(line, MAX_CHARS);
            for wrapped_line in wrapped {
                if y > 90 {
                    break; // Stop if we're running out of space
                }
                Text::with_baseline(&wrapped_line, Point::new(2, y), self.text_style_regular, Baseline::Top)
                    .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
                y += 10; // Reduced from 12 to fit more lines
            }
        }
        Ok(())
    }

    pub fn draw_progress_dialog(
        &mut self,
        title: &str,
        message: &str,
        percentage: f32,
        status: &StatusOverlay,
    ) -> Result<()> {
        self.clear()?;
        self.draw_toolbar(status)?;
        
        // No border - cleaner look

        // Draw title (wrap if needed)
        const MAX_CHARS: usize = 20;
        let wrapped_title = wrap_text(title, MAX_CHARS);
        let y = 38;
        for (idx, line) in wrapped_title.iter().take(1).enumerate() {
            Text::with_baseline(line, Point::new(2, y + (idx as i32 * 10)), self.text_style_highlight, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        // Draw message (wrap instead of truncate)
        let wrapped_msg = wrap_text(message, MAX_CHARS);
        let mut msg_y = 50;
        for line in wrapped_msg.iter().take(2) {
            Text::with_baseline(line, Point::new(2, msg_y), self.text_style_regular, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            msg_y += 10;
        }

        // Draw progress bar
        let bar_width = 120u32;
        let bar_height = 8u32;
        let x = 4;
        let y = 70;
        
        Rectangle::new(
            Point::new(x, y),
            Size::new(bar_width, bar_height),
        )
        .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        let fill_width = ((percentage / 100.0) * (bar_width as f32 - 2.0)) as u32;
        if fill_width > 0 {
            Rectangle::new(
                Point::new(x + 1, y + 1),
                Size::new(fill_width, bar_height - 2),
            )
            .into_styled(PrimitiveStyle::with_fill(self.palette.text))
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        // Draw percentage text
        let pct_text = format!("{:.1}%", percentage);
        Text::with_baseline(&pct_text, Point::new(2, 82), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        Ok(())
    }

    pub fn draw_dashboard(&mut self, view: DashboardView, status: &StatusOverlay) -> Result<()> {
        self.clear()?;
        
        match view {
            DashboardView::SystemHealth => self.draw_system_health(status),
            DashboardView::AttackMetrics => self.draw_attack_metrics(status),
            DashboardView::LootSummary => self.draw_loot_summary(status),
            DashboardView::NetworkTraffic => self.draw_network_traffic(status),
        }
    }

    fn draw_system_health(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::with_baseline("SYSTEM HEALTH", Point::new(18, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        // No border line - just a gap

        let cpu_bar_len = ((status.cpu_percent / 100.0) * 100.0).min(100.0) as u32;
        let mem_percent = (status.mem_used_mb as f32 / status.mem_total_mb.max(1) as f32) * 100.0;
        let mem_bar_len = ((mem_percent / 100.0) * 100.0).min(100.0) as u32;
        let disk_percent = (status.disk_used_gb / status.disk_total_gb.max(0.1)) * 100.0;
        let disk_bar_len = ((disk_percent / 100.0) * 100.0).min(100.0) as u32;

        let mut y = 22;
        
        let cpu_text = format!("CPU:{:.0}C {:.0}%", status.temp_c, status.cpu_percent);
        if y <= 118 {
            Text::with_baseline(&cpu_text, Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
            self.draw_progress_bar(Point::new(2, y), cpu_bar_len)?;
            y += 12;
        }

        let mem_text = format!("MEM:{}M/{:.0}%", status.mem_used_mb, mem_percent);
        if y <= 118 {
            Text::with_baseline(&mem_text, Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
            self.draw_progress_bar(Point::new(2, y), mem_bar_len)?;
            y += 12;
        }

        let disk_text = format!("DSK:{:.1}G/{:.0}%", status.disk_used_gb, disk_percent);
        if y <= 118 {
            Text::with_baseline(&disk_text, Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
            self.draw_progress_bar(Point::new(2, y), disk_bar_len)?;
            y += 14;
        }

        let uptime_hrs = status.uptime_secs / 3600;
        let uptime_mins = (status.uptime_secs % 3600) / 60;
        let uptime_text = format!("Up:{}h{}m", uptime_hrs, uptime_mins);
        if y <= 118 {
            Text::with_baseline(&uptime_text, Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        Text::with_baseline("<- Back  Next ->", Point::new(18, 115), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    fn draw_attack_metrics(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::with_baseline("ATTACK METRICS", Point::new(16, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        // No border line

        let mut y = 22;
        
        if y <= 118 {
            Text::with_baseline("Active Ops:", Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 12;
        }

        for op in status.active_operations.iter().take(3) {
            if y > 110 { break; }
            // Wrap operation names instead of truncating (max 18 chars to account for "• " prefix)
            let wrapped = wrap_text(op, 18);
            for line in wrapped.iter().take(1) {
                Text::with_baseline(&format!("• {}", line), Point::new(4, y), self.text_style_small, Baseline::Top)
                    .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
                y += 10;
                if y > 110 { break; }
            }
        }
        y += 6;

        if y <= 118 {
            Text::with_baseline("Net Traffic:", Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 12;
        }

        let rx_kb = status.net_rx_rate / 1024.0;
        let tx_kb = status.net_tx_rate / 1024.0;
        
        if y <= 118 {
            Text::with_baseline(&format!("TX:{:.1}KB/s", tx_kb), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }
        
        if y <= 118 {
            Text::with_baseline(&format!("RX:{:.1}KB/s", rx_kb), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        if status.mitm_victims > 0 && y <= 118 {
            Text::with_baseline(&format!("MITM Vic:{}", status.mitm_victims), Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        Text::with_baseline("<- Back  Next ->", Point::new(18, 115), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    fn draw_loot_summary(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::with_baseline("LOOT SUMMARY", Point::new(22, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        // No border line

        let mut y = 24;
        
        if y <= 118 {
            Text::with_baseline("Session Stats:", Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        if y <= 118 {
            Text::with_baseline(&format!("Pkts:{}", status.packets_captured), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }

        let data_mb = status.net_rx_bytes / 1_048_576;
        if y <= 118 {
            Text::with_baseline(&format!("Data:{}MB", data_mb), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }

        let uptime_hrs = status.uptime_secs / 3600;
        let uptime_mins = (status.uptime_secs % 3600) / 60;
        if y <= 118 {
            Text::with_baseline(&format!("Time:{}h{}m", uptime_hrs, uptime_mins), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 16;
        }

        if y <= 118 {
            Text::with_baseline("Creds Found:", Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        if y <= 118 {
            if status.creds_found > 0 {
                Text::with_baseline(&format!("• NTLM:{}", status.creds_found), Point::new(4, y), self.text_style_small, Baseline::Top)
                    .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            } else {
                Text::with_baseline("• None yet", Point::new(4, y), self.text_style_small, Baseline::Top)
                    .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            }
        }

        Text::with_baseline("<- Back  Next ->", Point::new(18, 115), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    fn draw_network_traffic(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::with_baseline("NET TRAFFIC", Point::new(26, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        // No border line

        let mut y = 24;
        
        if y <= 118 {
            Text::with_baseline("Total:", Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        let rx_mb = status.net_rx_bytes / 1_048_576;
        let tx_mb = status.net_tx_bytes / 1_048_576;
        
        if y <= 118 {
            Text::with_baseline(&format!("RX:{}MB", rx_mb), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }
        
        if y <= 118 {
            Text::with_baseline(&format!("TX:{}MB", tx_mb), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 16;
        }

        if y <= 118 {
            Text::with_baseline("Rate:", Point::new(2, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        let rx_kb = status.net_rx_rate / 1024.0;
        let tx_kb = status.net_tx_rate / 1024.0;
        
        if y <= 118 {
            Text::with_baseline(&format!("RX:{:.1}KB/s", rx_kb), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }
        
        if y <= 118 {
            Text::with_baseline(&format!("TX:{:.1}KB/s", tx_kb), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }

        let rate_bars_rx = ((rx_kb / 100.0).min(1.0) * 80.0) as u32;
        let rate_bars_tx = ((tx_kb / 100.0).min(1.0) * 80.0) as u32;
        
        if y <= 110 {
            y += 4;
            self.draw_progress_bar(Point::new(4, y), rate_bars_rx)?;
            y += 8;
            self.draw_progress_bar(Point::new(4, y), rate_bars_tx)?;
        }

        Text::with_baseline("<- Back  Menu", Point::new(22, 115), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    fn draw_progress_bar(&mut self, pos: Point, fill_width: u32) -> Result<()> {
        let bar_width = 100u32;
        let bar_height = 6u32;
        
        Rectangle::new(
            pos,
            Size::new(bar_width, bar_height),
        )
        .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        if fill_width > 0 {
            Rectangle::new(
                Point::new(pos.x + 1, pos.y + 1),
                Size::new(fill_width.min(bar_width - 2), bar_height - 2),
            )
            .into_styled(PrimitiveStyle::with_fill(self.palette.text))
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }
        
        Ok(())
    }

    pub fn palette(&self) -> &Palette {
        &self.palette
    }
}

#[cfg(not(target_os = "linux"))]
impl Display {
    pub fn new(colors: &ColorScheme) -> Result<Self> {
        Ok(Self {
            palette: Palette::from_scheme(colors),
        })
    }

    pub fn update_palette(&mut self, colors: &ColorScheme) {
        self.palette = Palette::from_scheme(colors);
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) -> Result<()> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn show_splash_screen(&mut self, _image_path: &Path) -> Result<()> {
        println!("=== RUSTYJACK ===");
        println!("   Loading...");
        println!("=================");
        Ok(())
    }

    #[allow(dead_code)]
    pub fn draw_toolbar(&mut self, status: &StatusOverlay) -> Result<()> {
        let ap_status = if status.autopilot_running {
            format!(" [AP:{}]", status.autopilot_mode)
        } else {
            String::new()
        };
        println!(
            "[status] {:.0} °C{} | {}",
            status.temp_c,
            ap_status,
            status.text.as_str()
        );
        Ok(())
    }

    pub fn draw_menu(
        &mut self,
        title: &str,
        items: &[String],
        selected: usize,
        _: &StatusOverlay,
    ) -> Result<()> {
        println!("== {title} ==");
        for (idx, label) in items.iter().enumerate() {
            if idx == selected {
                println!("> {label}");
            } else {
                println!("  {label}");
            }
        }
        Ok(())
    }

    pub fn draw_dialog(&mut self, lines: &[String], _: &StatusOverlay) -> Result<()> {
        println!("--- dialog ---");
        for line in lines {
            println!("{line}");
        }
        println!("--------------");
        Ok(())
    }

    pub fn draw_progress_dialog(
        &mut self,
        title: &str,
        message: &str,
        percentage: f32,
        _: &StatusOverlay,
    ) -> Result<()> {
        println!("--- {title} ---");
        println!("{message}");
        println!("[{:.1}%]", percentage);
        println!("----------------");
        Ok(())
    }

    pub fn draw_dashboard(&mut self, view: DashboardView, status: &StatusOverlay) -> Result<()> {
        println!("=== DASHBOARD: {:?} ===", view);
        println!("CPU: {:.0}% ({:.0}°C)", status.cpu_percent, status.temp_c);
        println!("MEM: {}/{} MB", status.mem_used_mb, status.mem_total_mb);
        println!("DISK: {:.1}/{:.1} GB", status.disk_used_gb, status.disk_total_gb);
        println!("NET RX: {} MB  TX: {} MB", status.net_rx_bytes / 1_048_576, status.net_tx_bytes / 1_048_576);
        println!("Rate: RX:{:.1} KB/s TX:{:.1} KB/s", status.net_rx_rate / 1024.0, status.net_tx_rate / 1024.0);
        println!("Packets: {}  Creds: {}", status.packets_captured, status.creds_found);
        println!("Active: {:?}", status.active_operations);
        println!("========================");
        Ok(())
    }

    #[allow(dead_code)]
    pub fn palette(&self) -> &Palette {
        &self.palette
    }
}



impl Palette {
    pub fn from_scheme(colors: &ColorScheme) -> Self {
        Self {
            background: parse_color(&colors.background, Rgb565::BLACK),
            border: parse_color(&colors.border, Rgb565::WHITE),
            text: parse_color(&colors.text, Rgb565::WHITE),
            selected_text: parse_color(&colors.selected_text, Rgb565::WHITE),
            selected_background: parse_color(&colors.selected_background, Rgb565::BLACK),
        }
    }
}

fn parse_color(input: &str, fallback: Rgb565) -> Rgb565 {
    let trimmed = input.trim();
    let hex = trimmed.trim_start_matches('#');
    if hex.len() == 6 {
        if let Ok(value) = u32::from_str_radix(hex, 16) {
            let r = ((value >> 16) & 0xFF) as u8;
            let g = ((value >> 8) & 0xFF) as u8;
            let b = (value & 0xFF) as u8;
            return Rgb565::from(Rgb888::new(r, g, b));
        }
    }
    fallback
}

#[derive(Debug, Clone, Default)]
pub struct StatusOverlay {
    pub temp_c: f32,
    pub text: String,
    pub cpu_percent: f32,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub disk_used_gb: f32,
    pub disk_total_gb: f32,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub net_rx_rate: f32,
    pub net_tx_rate: f32,
    pub uptime_secs: u64,
    pub packets_captured: u64,
    pub creds_found: u32,
    pub active_operations: Vec<String>,
    pub mitm_victims: u32,
    pub autopilot_running: bool,
    pub autopilot_mode: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardView {
    SystemHealth,
    AttackMetrics,
    LootSummary,
    NetworkTraffic,
}
