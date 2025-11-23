use crate::config::ColorScheme;
use anyhow::Result;
use embedded_graphics::{
    image::Image,
    pixelcolor::{Rgb565, Rgb888},
    prelude::*,
    primitives::{PrimitiveStyle, PrimitiveStyleBuilder, Rectangle},
    mono_font::{ascii::FONT_6X10, MonoTextStyle, MonoTextStyleBuilder},
    text::{Baseline, Text},
};
use std::path::Path;
use image::GenericImageView;

#[cfg(target_os = "linux")]
use anyhow::Context;

#[cfg(target_os = "linux")]
use tinybmp::Bmp;

#[cfg(target_os = "linux")]
use linux_embedded_hal::{
    Delay,
    spidev::{SpiModeFlags, SpidevOptions, Spidev},
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
    lcd: ST7735<Spidev, Pin, Pin>,
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
        })
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
            .text_color(Rgb565::GREEN)
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
        let style = PrimitiveStyle::with_stroke(self.palette.border, 2);
        Rectangle::new(
            Point::new(0, 12),
            Size::new(LCD_WIDTH as u32, (LCD_HEIGHT - 12) as u32),
        )
        .into_styled(style)
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        Text::with_baseline(title, Point::new(4, 16), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        let mut y = 30;
        for (idx, label) in items.iter().enumerate() {
            if idx == selected {
                Rectangle::new(
                    Point::new(2, y - 2),
                    Size::new((LCD_WIDTH - 4) as u32, 12)
                )
                .into_styled(PrimitiveStyle::with_fill(self.palette.selected_background))
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            }
            let style = if idx == selected {
                self.text_style_highlight
            } else {
                self.text_style_regular
            };
            Text::with_baseline(label, Point::new(6, y), style, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 12;
        }
        Ok(())
    }

    pub fn draw_dialog(&mut self, lines: &[String], status: &StatusOverlay) -> Result<()> {
        self.clear()?;
        self.draw_toolbar(status)?;
        Rectangle::new(
            Point::new(6, 32),
            Size::new(116, 64)
        )
        .into_styled(PrimitiveStyle::with_fill(self.palette.selected_background))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        let mut y = 38;
        for line in lines {
            Text::with_baseline(line, Point::new(10, y), self.text_style_regular, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 12;
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
        
        // Draw dialog box
        Rectangle::new(
            Point::new(6, 32),
            Size::new(116, 64)
        )
        .into_styled(PrimitiveStyle::with_fill(self.palette.selected_background))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        // Draw title
        Text::with_baseline(title, Point::new(10, 38), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        // Draw message (truncated if too long)
        let msg_display = if message.len() > 18 {
            format!("{}...", &message[..15])
        } else {
            message.to_string()
        };
        Text::with_baseline(&msg_display, Point::new(10, 52), self.text_style_regular, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        // Draw progress bar
        let bar_width = 100u32;
        let bar_height = 8u32;
        let x = 14;
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
        Text::with_baseline(&pct_text, Point::new(10, 82), self.text_style_small, Baseline::Top)
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
        Text::with_baseline("SYSTEM HEALTH", Point::new(20, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Rectangle::new(
            Point::new(0, 14),
            Size::new(LCD_WIDTH as u32, 1)
        )
        .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        let cpu_bar_len = ((status.cpu_percent / 100.0) * 100.0).min(100.0) as u32;
        let mem_percent = (status.mem_used_mb as f32 / status.mem_total_mb.max(1) as f32) * 100.0;
        let mem_bar_len = ((mem_percent / 100.0) * 100.0).min(100.0) as u32;
        let disk_percent = (status.disk_used_gb / status.disk_total_gb.max(0.1)) * 100.0;
        let disk_bar_len = ((disk_percent / 100.0) * 100.0).min(100.0) as u32;

        let mut y = 28;
        
        let cpu_text = format!("CPU:{:.0}C {:.0}%", status.temp_c, status.cpu_percent);
        if y <= 118 {
            Text::with_baseline(&cpu_text, Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
            self.draw_progress_bar(Point::new(4, y), cpu_bar_len)?;
            y += 12;
        }

        let mem_text = format!("MEM:{}M/{:.0}%", status.mem_used_mb, mem_percent);
        if y <= 118 {
            Text::with_baseline(&mem_text, Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
            self.draw_progress_bar(Point::new(4, y), mem_bar_len)?;
            y += 12;
        }

        let disk_text = format!("DSK:{:.1}G/{:.0}%", status.disk_used_gb, disk_percent);
        if y <= 118 {
            Text::with_baseline(&disk_text, Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
            self.draw_progress_bar(Point::new(4, y), disk_bar_len)?;
            y += 14;
        }

        let uptime_hrs = status.uptime_secs / 3600;
        let uptime_mins = (status.uptime_secs % 3600) / 60;
        let uptime_text = format!("Up:{}h{}m", uptime_hrs, uptime_mins);
        if y <= 118 {
            Text::with_baseline(&uptime_text, Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        Text::with_baseline("<- Back  Next ->", Point::new(20, 115), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    fn draw_attack_metrics(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::with_baseline("ATTACK METRICS", Point::new(18, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Rectangle::new(
            Point::new(0, 14),
            Size::new(LCD_WIDTH as u32, 1)
        )
        .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        let mut y = 28;
        
        if y <= 118 {
            Text::with_baseline("Active Ops:", Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 12;
        }

        for op in status.active_operations.iter().take(3) {
            if y > 110 { break; }
            let truncated = if op.len() > 18 {
                format!("{}...", &op[..15])
            } else {
                op.clone()
            };
            Text::with_baseline(&format!("• {}", truncated), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }
        y += 6;

        if y <= 118 {
            Text::with_baseline("Net Traffic:", Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 12;
        }

        let rx_kb = status.net_rx_rate / 1024.0;
        let tx_kb = status.net_tx_rate / 1024.0;
        
        if y <= 118 {
            Text::with_baseline(&format!("↑ {:.1}KB/s", tx_kb), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }
        
        if y <= 118 {
            Text::with_baseline(&format!("↓ {:.1}KB/s", rx_kb), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        if status.mitm_victims > 0 && y <= 118 {
            Text::with_baseline(&format!("MITM Vic:{}", status.mitm_victims), Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        Text::with_baseline("<- Back  Next ->", Point::new(20, 115), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    fn draw_loot_summary(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::with_baseline("LOOT SUMMARY", Point::new(24, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Rectangle::new(
            Point::new(0, 14),
            Size::new(LCD_WIDTH as u32, 1)
        )
        .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        let mut y = 32;
        
        if y <= 118 {
            Text::with_baseline("Session Stats:", Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        if y <= 118 {
            Text::with_baseline(&format!("Pkts:{}", status.packets_captured), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }

        let data_mb = status.net_rx_bytes / 1_048_576;
        if y <= 118 {
            Text::with_baseline(&format!("Data:{}MB", data_mb), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }

        let uptime_hrs = status.uptime_secs / 3600;
        let uptime_mins = (status.uptime_secs % 3600) / 60;
        if y <= 118 {
            Text::with_baseline(&format!("Time:{}h{}m", uptime_hrs, uptime_mins), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 16;
        }

        if y <= 118 {
            Text::with_baseline("Creds Found:", Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        if y <= 118 {
            if status.creds_found > 0 {
                Text::with_baseline(&format!("• NTLM:{}", status.creds_found), Point::new(8, y), self.text_style_small, Baseline::Top)
                    .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            } else {
                Text::with_baseline("• None yet", Point::new(8, y), self.text_style_small, Baseline::Top)
                    .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            }
        }

        Text::with_baseline("<- Back  Next ->", Point::new(20, 115), self.text_style_small, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Ok(())
    }

    fn draw_network_traffic(&mut self, status: &StatusOverlay) -> Result<()> {
        Text::with_baseline("NET TRAFFIC", Point::new(28, 2), self.text_style_highlight, Baseline::Top)
            .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
        
        Rectangle::new(
            Point::new(0, 14),
            Size::new(LCD_WIDTH as u32, 1)
        )
        .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
        .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;

        let mut y = 32;
        
        if y <= 118 {
            Text::with_baseline("Total:", Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        let rx_mb = status.net_rx_bytes / 1_048_576;
        let tx_mb = status.net_tx_bytes / 1_048_576;
        
        if y <= 118 {
            Text::with_baseline(&format!("↓ RX:{}MB", rx_mb), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }
        
        if y <= 118 {
            Text::with_baseline(&format!("↑ TX:{}MB", tx_mb), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 16;
        }

        if y <= 118 {
            Text::with_baseline("Rate:", Point::new(4, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 14;
        }

        let rx_kb = status.net_rx_rate / 1024.0;
        let tx_kb = status.net_tx_rate / 1024.0;
        
        if y <= 118 {
            Text::with_baseline(&format!("↓ {:.1}KB/s", rx_kb), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += 10;
        }
        
        if y <= 118 {
            Text::with_baseline(&format!("↑ {:.1}KB/s", tx_kb), Point::new(8, y), self.text_style_small, Baseline::Top)
                .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;
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

        Text::with_baseline("<- Back  Menu", Point::new(24, 115), self.text_style_small, Baseline::Top)
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
