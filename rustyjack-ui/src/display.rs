use crate::config::ColorScheme;
use anyhow::Result;
use embedded_graphics::{
    image::Image,
    pixelcolor::{Rgb565, Rgb888},
    prelude::RgbColor,
};
use std::path::Path;

#[cfg(target_os = "linux")]
use anyhow::Context;

#[cfg(target_os = "linux")]
use embedded_graphics::{
    mono_font::{MonoTextStyle, ascii::FONT_6X10},
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Alignment, Text},
};

#[cfg(target_os = "linux")]
use tinybmp::Bmp;

#[cfg(target_os = "linux")]
use linux_embedded_hal::{
    Delay, Spidev,
    spidev::{SpiModeFlags, SpidevOptions},
    sysfs_gpio::{Direction, Pin},
};

#[cfg(target_os = "linux")]
use st7735_lcd::{Orientation, ST7735};

#[cfg(target_os = "linux")]
const LCD_WIDTH: u16 = 128;
#[cfg(target_os = "linux")]
const LCD_HEIGHT: u16 = 128;
#[cfg(target_os = "linux")]
const LCD_OFFSET_X: u16 = 2;
#[cfg(target_os = "linux")]
const LCD_OFFSET_Y: u16 = 1;

#[cfg(target_os = "linux")]
pub struct Display {
    lcd: ST7735<Spidev, Pin>,
    palette: Palette,
    font_regular: MonoTextStyle<'static, Rgb565>,
    font_highlight: MonoTextStyle<'static, Rgb565>,
    font_small: MonoTextStyle<'static, Rgb565>,
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
        let mut spi = Spidev::open("/dev/spidev0.0").context("opening SPI device")?;
        let options = SpidevOptions::new()
            .bits_per_word(8)
            .max_speed_hz(12_000_000)
            .mode(SpiModeFlags::SPI_MODE_0)
            .build();
        spi.configure(&options).context("configuring SPI")?;

        let mut dc = Pin::new(25);  // GPIO 25 - DC (Data/Command)
        init_output_pin(&mut dc)?;
        let mut rst = Pin::new(24);  // GPIO 24 - RST (Reset)
        init_output_pin(&mut rst)?;
        let mut backlight = Pin::new(18);  // GPIO 18 - BL (Backlight)
        init_output_pin(&mut backlight)?;
        backlight.set_value(1)?;

        let mut delay = Delay {};
        let mut lcd = ST7735::new(spi, dc, rst, true, false, LCD_WIDTH, LCD_HEIGHT);
        lcd.init(&mut delay)?;
        lcd.set_orientation(&Orientation::Portrait)?;
        lcd.set_offset(LCD_OFFSET_X, LCD_OFFSET_Y);

        let palette = Palette::from_scheme(colors);
        let font_regular = MonoTextStyle::new(&FONT_6X10, palette.text);
        let font_highlight = MonoTextStyle::new(&FONT_6X10, palette.selected_text);
        let font_small = MonoTextStyle::new(&FONT_6X10, palette.text);

        Ok(Self {
            lcd,
            palette,
            font_regular,
            font_highlight,
            font_small,
        })
    }

    pub fn update_palette(&mut self, colors: &ColorScheme) {
        self.palette = Palette::from_scheme(colors);
        self.font_regular = MonoTextStyle::new(&FONT_6X10, self.palette.text);
        self.font_highlight = MonoTextStyle::new(&FONT_6X10, self.palette.selected_text);
        self.font_small = MonoTextStyle::new(&FONT_6X10, self.palette.text);
    }

    pub fn clear(&mut self) -> Result<()> {
        let style = PrimitiveStyle::with_fill(self.palette.background);
        Rectangle::new(
            Point::new(0, 0),
            Size::new(LCD_WIDTH.into(), LCD_HEIGHT.into()),
        )
        .into_styled(style)
        .draw(&mut self.lcd)?;
        Ok(())
    }

    pub fn show_splash_screen(&mut self, image_path: &Path) -> Result<()> {
        // Clear screen to black
        let style = PrimitiveStyle::with_fill(Rgb565::BLACK);
        Rectangle::new(
            Point::new(0, 0),
            Size::new(LCD_WIDTH.into(), LCD_HEIGHT.into()),
        )
        .into_styled(style)
        .draw(&mut self.lcd)?;

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
                        image.draw(&mut self.lcd)?;
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
                                .draw(&mut self.lcd)?;
                        }
                    }
                    return Ok(());
                }
            }
        }
        
        // Image not found or load failed, show text fallback
        let text_style = MonoTextStyle::new(&FONT_6X10, Rgb565::GREEN);
        Text::with_alignment(
            "RUSTYJACK",
            Point::new(64, 60),
            text_style,
            Alignment::Center,
        )
        .draw(&mut self.lcd)?;
        
        Text::with_alignment(
            "Loading...",
            Point::new(64, 75),
            text_style,
            Alignment::Center,
        )
        .draw(&mut self.lcd)?;
        
        Ok(())
    }

    pub fn draw_toolbar(&mut self, status: &StatusOverlay) -> Result<()> {
        let style = PrimitiveStyle::with_fill(Rgb565::new(20, 20, 20));
        Rectangle::new(Point::new(0, 0), Size::new(LCD_WIDTH.into(), 14))
            .into_styled(style)
            .draw(&mut self.lcd)?;

        let temp_text = format!("{:.0}°C", status.temp_c);
        Text::new(&temp_text, Point::new(2, 10), self.font_regular).draw(&mut self.lcd)?;
        
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
            Text::new(&ap_indicator, Point::new(center_x, 10), self.font_highlight)
                .draw(&mut self.lcd)?;
        }
        
        if !status.text.is_empty() {
            Text::with_alignment(
                &status.text,
                Point::new(124, 10),
                self.font_small,
                Alignment::Right,
            )
            .draw(&mut self.lcd)?;
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
        let style = PrimitiveStyle::with_stroke(self.palette.border, 2);
        Rectangle::new(
            Point::new(0, 12),
            Size::new(LCD_WIDTH.into(), (LCD_HEIGHT - 12).into()),
        )
        .into_styled(style)
        .draw(&mut self.lcd)?;

        Text::new(title, Point::new(4, 24), self.font_small).draw(&mut self.lcd)?;

        let mut y = 36;
        for (idx, label) in items.iter().enumerate() {
            if idx == selected {
                Rectangle::new(Point::new(2, y - 10), Size::new(LCD_WIDTH as u32 - 4, 12))
                    .into_styled(PrimitiveStyle::with_fill(self.palette.selected_background))
                    .draw(&mut self.lcd)?;
            }
            let style = if idx == selected {
                self.font_highlight
            } else {
                self.font_regular
            };
            Text::new(label, Point::new(6, y), style).draw(&mut self.lcd)?;
            y += 12;
        }
        Ok(())
    }

    pub fn draw_dialog(&mut self, lines: &[String], status: &StatusOverlay) -> Result<()> {
        self.clear()?;
        self.draw_toolbar(status)?;
        Rectangle::new(Point::new(6, 32), Size::new(116, 64))
            .into_styled(PrimitiveStyle::with_fill(self.palette.selected_background))
            .draw(&mut self.lcd)?;
        let mut y = 50;
        for line in lines {
            Text::new(line, Point::new(10, y), self.font_regular).draw(&mut self.lcd)?;
            y += 12;
        }
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
        Text::new("SYSTEM HEALTH", Point::new(20, 12), self.font_highlight)
            .draw(&mut self.lcd)?;
        
        Rectangle::new(Point::new(0, 14), Size::new(LCD_WIDTH.into(), 1))
            .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
            .draw(&mut self.lcd)?;

        let cpu_bar_len = ((status.cpu_percent / 100.0) * 100.0).min(100.0) as u32;
        let mem_percent = (status.mem_used_mb as f32 / status.mem_total_mb.max(1) as f32) * 100.0;
        let mem_bar_len = ((mem_percent / 100.0) * 100.0).min(100.0) as u32;
        let disk_percent = (status.disk_used_gb / status.disk_total_gb.max(0.1)) * 100.0;
        let disk_bar_len = ((disk_percent / 100.0) * 100.0).min(100.0) as u32;

        let mut y = 28;
        
        let cpu_text = format!("CPU:{:.0}C {:.0}%", status.temp_c, status.cpu_percent);
        if y <= 118 {
            Text::new(&cpu_text, Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
            self.draw_progress_bar(Point::new(4, y), cpu_bar_len)?;
            y += 12;
        }

        let mem_text = format!("MEM:{}M/{:.0}%", status.mem_used_mb, mem_percent);
        if y <= 118 {
            Text::new(&mem_text, Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
            self.draw_progress_bar(Point::new(4, y), mem_bar_len)?;
            y += 12;
        }

        let disk_text = format!("DSK:{:.1}G/{:.0}%", status.disk_used_gb, disk_percent);
        if y <= 118 {
            Text::new(&disk_text, Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
            self.draw_progress_bar(Point::new(4, y), disk_bar_len)?;
            y += 14;
        }

        let uptime_hrs = status.uptime_secs / 3600;
        let uptime_mins = (status.uptime_secs % 3600) / 60;
        let uptime_text = format!("Up:{}h{}m", uptime_hrs, uptime_mins);
        if y <= 118 {
            Text::new(&uptime_text, Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
        }

        Text::new("<- Back  Next ->", Point::new(20, 120), self.font_small)
            .draw(&mut self.lcd)?;
        
        Ok(())
    }

    fn draw_attack_metrics(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::new("ATTACK METRICS", Point::new(18, 12), self.font_highlight)
            .draw(&mut self.lcd)?;
        
        Rectangle::new(Point::new(0, 14), Size::new(LCD_WIDTH.into(), 1))
            .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
            .draw(&mut self.lcd)?;

        let mut y = 28;
        
        if y <= 118 {
            Text::new("Active Ops:", Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 12;
        }

        for op in status.active_operations.iter().take(3) {
            if y > 110 { break; }
            let truncated = if op.len() > 18 {
                format!("{}...", &op[..15])
            } else {
                op.clone()
            };
            Text::new(&format!("• {}", truncated), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
        }
        y += 6;

        if y <= 118 {
            Text::new("Net Traffic:", Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 12;
        }

        let rx_kb = status.net_rx_rate / 1024.0;
        let tx_kb = status.net_tx_rate / 1024.0;
        
        if y <= 118 {
            Text::new(&format!("↑ {:.1}KB/s", tx_kb), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
        }
        
        if y <= 118 {
            Text::new(&format!("↓ {:.1}KB/s", rx_kb), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 14;
        }

        if status.mitm_victims > 0 && y <= 118 {
            Text::new(&format!("MITM Vic:{}", status.mitm_victims), Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
        }

        Text::new("<- Back  Next ->", Point::new(20, 120), self.font_small)
            .draw(&mut self.lcd)?;
        
        Ok(())
    }

    fn draw_loot_summary(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::new("LOOT SUMMARY", Point::new(24, 12), self.font_highlight)
            .draw(&mut self.lcd)?;
        
        Rectangle::new(Point::new(0, 14), Size::new(LCD_WIDTH.into(), 1))
            .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
            .draw(&mut self.lcd)?;

        let mut y = 32;
        
        if y <= 118 {
            Text::new("Session Stats:", Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 14;
        }

        if y <= 118 {
            Text::new(&format!("Pkts:{}", status.packets_captured), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
        }

        let data_mb = status.net_rx_bytes / 1_048_576;
        if y <= 118 {
            Text::new(&format!("Data:{}MB", data_mb), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
        }

        let uptime_hrs = status.uptime_secs / 3600;
        let uptime_mins = (status.uptime_secs % 3600) / 60;
        if y <= 118 {
            Text::new(&format!("Time:{}h{}m", uptime_hrs, uptime_mins), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 16;
        }

        if y <= 118 {
            Text::new("Creds Found:", Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 14;
        }

        if y <= 118 {
            if status.creds_found > 0 {
                Text::new(&format!("• NTLM:{}", status.creds_found), Point::new(8, y), self.font_small)
                    .draw(&mut self.lcd)?;
            } else {
                Text::new("• None yet", Point::new(8, y), self.font_small)
                    .draw(&mut self.lcd)?;
            }
        }

        Text::new("<- Back  Next ->", Point::new(20, 120), self.font_small)
            .draw(&mut self.lcd)?;
        
        Ok(())
    }

    fn draw_network_traffic(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::new("NET TRAFFIC", Point::new(28, 12), self.font_highlight)
            .draw(&mut self.lcd)?;
        
        Rectangle::new(Point::new(0, 14), Size::new(LCD_WIDTH.into(), 1))
            .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
            .draw(&mut self.lcd)?;

        let mut y = 32;
        
        if y <= 118 {
            Text::new("Total:", Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 14;
        }

        let rx_mb = status.net_rx_bytes / 1_048_576;
        let tx_mb = status.net_tx_bytes / 1_048_576;
        
        if y <= 118 {
            Text::new(&format!("↓ RX:{}MB", rx_mb), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
        }
        
        if y <= 118 {
            Text::new(&format!("↑ TX:{}MB", tx_mb), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 16;
        }

        if y <= 118 {
            Text::new("Rate:", Point::new(4, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 14;
        }

        let rx_kb = status.net_rx_rate / 1024.0;
        let tx_kb = status.net_tx_rate / 1024.0;
        
        if y <= 118 {
            Text::new(&format!("↓ {:.1}KB/s", rx_kb), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
        }
        
        if y <= 118 {
            Text::new(&format!("↑ {:.1}KB/s", tx_kb), Point::new(8, y), self.font_small)
                .draw(&mut self.lcd)?;
            y += 10;
        }

        let rate_bars_rx = ((rx_kb / 100.0).min(1.0) * 80.0) as u32;
        let rate_bars_tx = ((tx_kb / 100.0).min(1.0) * 80.0) as u32;
        
        if y <= 110 {
            y += 4;
            self.draw_progress_bar(Point::new(8, y), rate_bars_rx)?;
            y += 8;
            self.draw_progress_bar(Point::new(8, y), rate_bars_tx)?;
        }

        Text::new("<- Back  Menu", Point::new(24, 120), self.font_small)
            .draw(&mut self.lcd)?;
        
        Ok(())
    }

    fn draw_progress_bar(&mut self, pos: Point, fill_width: u32) -> Result<()> {
        let bar_width = 100u32;
        let bar_height = 6u32;
        
        Rectangle::new(pos, Size::new(bar_width, bar_height))
            .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
            .draw(&mut self.lcd)?;
        
        if fill_width > 0 {
            Rectangle::new(
                Point::new(pos.x + 1, pos.y + 1),
                Size::new(fill_width.min(bar_width - 2), bar_height - 2),
            )
            .into_styled(PrimitiveStyle::with_fill(self.palette.text))
            .draw(&mut self.lcd)?;
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

    pub fn draw_dashboard(&mut self, view: DashboardView, status: &StatusOverlay) -> Result<()> {
        println!("=== DASHBOARD: {:?} ===", view);
        println!("CPU: {:.0}% ({:.0}°C)", status.cpu_percent, status.temp_c);
        println!("MEM: {}/{} MB", status.mem_used_mb, status.mem_total_mb);
        println!("DISK: {:.1}/{:.1} GB", status.disk_used_gb, status.disk_total_gb);
        println!("NET RX: {} MB  TX: {} MB", status.net_rx_bytes / 1_048_576, status.net_tx_bytes / 1_048_576);
        println!("Rate: ↓{:.1} KB/s ↑{:.1} KB/s", status.net_rx_rate / 1024.0, status.net_tx_rate / 1024.0);
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

#[cfg(target_os = "linux")]
fn init_output_pin(pin: &mut Pin) -> Result<()> {
    pin.export()?;
    std::thread::sleep(std::time::Duration::from_millis(10));
    pin.set_direction(Direction::Out)?;
    pin.set_value(0)?;
    Ok(())
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
