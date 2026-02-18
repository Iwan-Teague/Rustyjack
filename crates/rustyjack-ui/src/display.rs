use crate::input::ButtonPad;
use crate::{
    config::{
        ColorScheme, DisplayBackend, DisplayConfig, DisplayGeometrySource, DisplayRotation,
        PinConfig,
    },
    ui::layout::{ellipsize, UiLayoutMetrics},
};
use anyhow::Result;
use chrono::Utc;
use embedded_graphics::{
    image::Image,
    mono_font::{ascii::FONT_6X10, MonoTextStyle, MonoTextStyleBuilder},
    pixelcolor::{Rgb565, Rgb888},
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};

pub(crate) const MIN_SUPPORTED_DIMENSION_PX: u32 = 128;
const DISPLAY_TESTS_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayWarning {
    DisplayModeMismatch,
    DisplayUnverifiedGeometry,
    UnsupportedDisplaySize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationEdge {
    Left,
    Top,
    Right,
    Bottom,
}

impl CalibrationEdge {
    pub const ALL: [Self; 4] = [Self::Left, Self::Top, Self::Right, Self::Bottom];

    pub fn label(self) -> &'static str {
        match self {
            Self::Left => "LEFT",
            Self::Top => "TOP",
            Self::Right => "RIGHT",
            Self::Bottom => "BOTTOM",
        }
    }

    pub fn help_text(self) -> &'static str {
        match self {
            Self::Left | Self::Right => "LEFT/RIGHT adjust edge",
            Self::Top | Self::Bottom => "UP/DOWN adjust edge",
        }
    }
}

impl DisplayWarning {
    pub fn code(self) -> &'static str {
        match self {
            Self::DisplayModeMismatch => "DISPLAY_MODE_MISMATCH",
            Self::DisplayUnverifiedGeometry => "DISPLAY_UNVERIFIED_GEOMETRY",
            Self::UnsupportedDisplaySize => "UNSUPPORTED_DISPLAY_SIZE",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DisplayCapabilities {
    pub width_px: u32,
    pub height_px: u32,
    pub orientation: DisplayRotation,
    pub backend: DisplayBackend,
    pub safe_padding_px: u32,
}

#[derive(Debug, Clone)]
pub struct DisplayDiagnostics {
    pub backend: DisplayBackend,
    pub detected_width_px: u32,
    pub detected_height_px: u32,
    pub effective_width_px: u32,
    pub effective_height_px: u32,
    pub effective_offset_x: i32,
    pub effective_offset_y: i32,
    pub geometry_source: DisplayGeometrySource,
    pub profile_fingerprint: String,
    pub probe_completed: bool,
    pub calibration_completed: bool,
    pub warnings: Vec<DisplayWarning>,
}

#[derive(Debug, Clone, Copy)]
struct DisplayGeometry {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    offset_x: i32,
    offset_y: i32,
}

impl DisplayGeometry {
    fn width(self) -> u32 {
        self.right
            .saturating_sub(self.left)
            .saturating_add(1)
            .max(1) as u32
    }

    fn height(self) -> u32 {
        self.bottom
            .saturating_sub(self.top)
            .saturating_add(1)
            .max(1) as u32
    }
}

#[cfg(not(target_os = "linux"))]
fn on_off(enabled: bool) -> &'static str {
    if enabled {
        "[ON]"
    } else {
        "[OFF]"
    }
}
use image::GenericImageView;
use std::{fs, path::Path};

#[cfg(target_os = "linux")]
use anyhow::Context;

#[cfg(target_os = "linux")]
use tinybmp::Bmp;

#[cfg(target_os = "linux")]
use linux_embedded_hal::{
    gpio_cdev::{Chip, LineRequestFlags},
    spidev::{SpiModeFlags, SpidevOptions},
    CdevPin, Delay, SpidevDevice,
};

#[cfg(target_os = "linux")]
use st7735_lcd::{Orientation, ST7735};
use std::{thread::sleep, time::Duration as StdDuration};

pub use crate::ui::layout::wrap_text;

#[cfg(target_os = "linux")]
const ST7735_PROFILE_WIDTH: u32 = 128;
#[cfg(target_os = "linux")]
const ST7735_PROFILE_HEIGHT: u32 = 128;
#[cfg(target_os = "linux")]
const ST7735_DEFAULT_OFFSET_X: i32 = 0;
#[cfg(target_os = "linux")]
const ST7735_DEFAULT_OFFSET_Y: i32 = 0;

#[cfg(target_os = "linux")]
fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

#[cfg(target_os = "linux")]
fn env_i32(name: &str, default: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(default)
}

#[cfg(target_os = "linux")]
fn env_backend(name: &str) -> Option<DisplayBackend> {
    let value = std::env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "st7735" => Some(DisplayBackend::St7735),
        "framebuffer" | "fb" | "fbdev" => Some(DisplayBackend::Framebuffer),
        "drm" => Some(DisplayBackend::Drm),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn env_rotation(name: &str) -> Option<DisplayRotation> {
    let value = std::env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "portrait" => Some(DisplayRotation::Portrait),
        "landscape" => Some(DisplayRotation::Landscape),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub struct Display {
    lcd: ST7735<SpidevDevice, CdevPin, CdevPin>,
    // Hold the backlight pin so it remains reserved for the lifetime of the
    // Display instance. Previously this was kept in a temporary local which
    // caused the line to be released when the constructor returned.
    #[allow(dead_code)]
    backlight: CdevPin,
    palette: Palette,
    text_style_regular: MonoTextStyle<'static, Rgb565>,
    text_style_highlight: MonoTextStyle<'static, Rgb565>,
    text_style_small: MonoTextStyle<'static, Rgb565>,
    layout: UiLayoutMetrics,
    capabilities: DisplayCapabilities,
    diagnostics: DisplayDiagnostics,
    pending_calibration: bool,
    probe_dirty: bool,
}

#[cfg(not(target_os = "linux"))]
pub struct Display {
    palette: Palette,
    layout: UiLayoutMetrics,
    capabilities: DisplayCapabilities,
    diagnostics: DisplayDiagnostics,
    pending_calibration: bool,
    probe_dirty: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct Palette {
    pub background: Rgb565,
    pub border: Rgb565,
    pub text: Rgb565,
    pub selected_text: Rgb565,
    pub selected_background: Rgb565,
    pub toolbar: Rgb565,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct RuntimeProbe {
    backend: DisplayBackend,
    rotation: DisplayRotation,
    detected_width: u32,
    detected_height: u32,
    geometry: DisplayGeometry,
    source: DisplayGeometrySource,
    warnings: Vec<DisplayWarning>,
    fingerprint: String,
    pending_calibration: bool,
    probe_dirty: bool,
}

#[cfg(target_os = "linux")]
fn detect_backend(config: &DisplayConfig) -> DisplayBackend {
    env_backend("RUSTYJACK_DISPLAY_BACKEND")
        .or_else(|| config.backend_preference.clone())
        .unwrap_or(DisplayBackend::St7735)
}

#[cfg(target_os = "linux")]
fn detect_rotation(config: &DisplayConfig) -> DisplayRotation {
    env_rotation("RUSTYJACK_DISPLAY_ROTATION")
        .or_else(|| config.rotation.clone())
        .unwrap_or(DisplayRotation::Landscape)
}

#[cfg(target_os = "linux")]
fn parse_fb_virtual_size(input: &str) -> Option<(u32, u32)> {
    let mut parts = input.trim().split(',');
    let w = parts.next()?.trim().parse::<u32>().ok()?;
    let h = parts.next()?.trim().parse::<u32>().ok()?;
    Some((w, h))
}

#[cfg(target_os = "linux")]
fn parse_mode(mode: &str) -> Option<(u32, u32)> {
    let trimmed = mode.trim();
    let (w, h) = trimmed.split_once('x')?;
    Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?))
}

#[cfg(target_os = "linux")]
fn query_backend_mode(backend: &DisplayBackend) -> Option<(u32, u32)> {
    match backend {
        DisplayBackend::St7735 => Some((ST7735_PROFILE_WIDTH, ST7735_PROFILE_HEIGHT)),
        DisplayBackend::Framebuffer => {
            let data = fs::read_to_string("/sys/class/graphics/fb0/virtual_size").ok()?;
            parse_fb_virtual_size(&data)
        }
        DisplayBackend::Drm => {
            let entries = fs::read_dir("/sys/class/drm").ok()?;
            for entry in entries.flatten() {
                let path = entry.path().join("modes");
                if !path.exists() {
                    continue;
                }
                if let Ok(data) = fs::read_to_string(&path) {
                    if let Some(mode) = data.lines().find_map(parse_mode) {
                        return Some(mode);
                    }
                }
            }
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn profile_mode(backend: &DisplayBackend) -> (u32, u32) {
    match backend {
        DisplayBackend::St7735 => (ST7735_PROFILE_WIDTH, ST7735_PROFILE_HEIGHT),
        DisplayBackend::Framebuffer | DisplayBackend::Drm => {
            (ST7735_PROFILE_WIDTH, ST7735_PROFILE_HEIGHT)
        }
    }
}

#[cfg(target_os = "linux")]
fn backend_offsets(config: &DisplayConfig) -> (i32, i32) {
    let default_x = match config.backend_preference {
        Some(DisplayBackend::St7735) | None => ST7735_DEFAULT_OFFSET_X,
        _ => 0,
    };
    let default_y = match config.backend_preference {
        Some(DisplayBackend::St7735) | None => ST7735_DEFAULT_OFFSET_Y,
        _ => 0,
    };
    let offset_x = env_i32(
        "RUSTYJACK_DISPLAY_OFFSET_X",
        config.offset_x.unwrap_or(default_x),
    );
    let offset_y = env_i32(
        "RUSTYJACK_DISPLAY_OFFSET_Y",
        config.offset_y.unwrap_or(default_y),
    );
    (offset_x, offset_y)
}

#[cfg(target_os = "linux")]
fn build_fingerprint(
    backend: &DisplayBackend,
    rotation: &DisplayRotation,
    detected_width: u32,
    detected_height: u32,
    safe_padding: u32,
) -> String {
    format!(
        "{}:{}x{}:{}:pad{}:v{}",
        backend.as_str(),
        detected_width,
        detected_height,
        rotation.as_str(),
        safe_padding,
        DISPLAY_TESTS_VERSION
    )
}

#[cfg(target_os = "linux")]
fn calibration_geometry(config: &DisplayConfig, base: &DisplayGeometry) -> Option<DisplayGeometry> {
    let left = config.calibrated_left?;
    let top = config.calibrated_top?;
    let right = config.calibrated_right?;
    let bottom = config.calibrated_bottom?;
    if right <= left || bottom <= top {
        return None;
    }
    let width = right.saturating_sub(left).saturating_add(1);
    let height = bottom.saturating_sub(top).saturating_add(1);
    Some(DisplayGeometry {
        left: 0,
        top: 0,
        right: width.saturating_sub(1),
        bottom: height.saturating_sub(1),
        offset_x: base.offset_x + left,
        offset_y: base.offset_y + top,
    })
}

#[cfg(target_os = "linux")]
fn resolve_runtime_probe(config: &mut DisplayConfig, force_discovery: bool) -> RuntimeProbe {
    let backend = detect_backend(config);
    let rotation = detect_rotation(config);
    let (profile_width, profile_height) = profile_mode(&backend);
    let (detected_width, detected_height) =
        query_backend_mode(&backend).unwrap_or((profile_width, profile_height));

    let override_width = env_u32(
        "RUSTYJACK_DISPLAY_WIDTH",
        config.width_override.unwrap_or(0),
    );
    let override_height = env_u32(
        "RUSTYJACK_DISPLAY_HEIGHT",
        config.height_override.unwrap_or(0),
    );
    let has_override = override_width > 0 && override_height > 0;
    let (offset_x, offset_y) = backend_offsets(config);

    let mut warnings = Vec::new();
    let fingerprint = build_fingerprint(
        &backend,
        &rotation,
        detected_width,
        detected_height,
        config.safe_padding_px,
    );
    if has_override && (override_width != detected_width || override_height != detected_height) {
        warnings.push(DisplayWarning::DisplayModeMismatch);
    }

    let use_cached = !force_discovery
        && config.display_probe_completed
        && config.display_tests_version == DISPLAY_TESTS_VERSION
        && config.effective_width.is_some()
        && config.effective_height.is_some()
        && config.effective_backend.as_ref() == Some(&backend);

    let geometry = if use_cached {
        let mut cached_width = config.effective_width.unwrap_or(profile_width).max(1);
        let mut cached_height = config.effective_height.unwrap_or(profile_height).max(1);
        if matches!(backend, DisplayBackend::St7735) {
            cached_width = cached_width.min(detected_width.max(1));
            cached_height = cached_height.min(detected_height.max(1));
        }
        if config
            .display_profile_fingerprint
            .as_ref()
            .filter(|fp| *fp == &fingerprint)
            .is_none()
        {
            warnings.push(DisplayWarning::DisplayModeMismatch);
        }
        DisplayGeometry {
            left: 0,
            top: 0,
            right: cached_width as i32 - 1,
            bottom: cached_height as i32 - 1,
            offset_x: config.effective_offset_x.unwrap_or(offset_x),
            offset_y: config.effective_offset_y.unwrap_or(offset_y),
        }
    } else {
        let mut width = if has_override {
            override_width
        } else {
            detected_width.max(1)
        };
        let mut height = if has_override {
            override_height
        } else {
            detected_height.max(1)
        };
        if matches!(backend, DisplayBackend::St7735) {
            width = width.min(detected_width.max(1));
            height = height.min(detected_height.max(1));
        }
        DisplayGeometry {
            left: 0,
            top: 0,
            right: width as i32 - 1,
            bottom: height as i32 - 1,
            offset_x,
            offset_y,
        }
    };

    let mut source = if use_cached {
        DisplayGeometrySource::Cached
    } else if has_override {
        DisplayGeometrySource::Override
    } else if matches!(backend, DisplayBackend::Framebuffer | DisplayBackend::Drm) {
        DisplayGeometrySource::Detected
    } else {
        DisplayGeometrySource::Profile
    };

    let mut effective_geometry = geometry;
    if !use_cached {
        if let Some(calibrated) = calibration_geometry(config, &geometry) {
            effective_geometry = calibrated;
            source = DisplayGeometrySource::Calibrated;
        }
    }

    let calibration_required = matches!(backend, DisplayBackend::St7735)
        && !has_override
        && !config.display_calibration_completed;

    let geometry_verified = !matches!(backend, DisplayBackend::St7735)
        || has_override
        || config.display_calibration_completed;
    if !geometry_verified {
        warnings.push(DisplayWarning::DisplayUnverifiedGeometry);
    }
    if effective_geometry.width() < MIN_SUPPORTED_DIMENSION_PX
        || effective_geometry.height() < MIN_SUPPORTED_DIMENSION_PX
    {
        warnings.push(DisplayWarning::UnsupportedDisplaySize);
    }

    let mut probe_dirty = false;
    if !use_cached {
        if config.effective_width != Some(effective_geometry.width())
            || config.effective_height != Some(effective_geometry.height())
            || config.effective_offset_x != Some(effective_geometry.offset_x)
            || config.effective_offset_y != Some(effective_geometry.offset_y)
            || config.effective_backend.as_ref() != Some(&backend)
            || config.effective_rotation.as_ref() != Some(&rotation)
            || config.display_profile_fingerprint.as_deref() != Some(fingerprint.as_str())
            || !config.display_probe_completed
            || config.display_tests_version != DISPLAY_TESTS_VERSION
        {
            probe_dirty = true;
        }

        config.display_probe_completed = true;
        config.display_tests_version = DISPLAY_TESTS_VERSION;
        config.display_profile_fingerprint = Some(fingerprint.clone());
        config.effective_width = Some(effective_geometry.width());
        config.effective_height = Some(effective_geometry.height());
        config.effective_offset_x = Some(effective_geometry.offset_x);
        config.effective_offset_y = Some(effective_geometry.offset_y);
        config.effective_backend = Some(backend.clone());
        config.effective_rotation = Some(rotation.clone());
        config.display_geometry_source = Some(source.clone());
    }

    RuntimeProbe {
        backend,
        rotation,
        detected_width,
        detected_height,
        geometry: effective_geometry,
        source,
        warnings,
        fingerprint,
        pending_calibration: calibration_required,
        probe_dirty,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn startup_reuses_cached_geometry_when_probe_completed() {
        let mut cfg = DisplayConfig {
            display_probe_completed: true,
            display_calibration_completed: true,
            display_tests_version: DISPLAY_TESTS_VERSION,
            effective_width: Some(128),
            effective_height: Some(128),
            effective_offset_x: Some(0),
            effective_offset_y: Some(0),
            effective_backend: Some(DisplayBackend::St7735),
            effective_rotation: Some(DisplayRotation::Landscape),
            display_profile_fingerprint: Some(build_fingerprint(
                &DisplayBackend::St7735,
                &DisplayRotation::Landscape,
                128,
                128,
                0,
            )),
            ..DisplayConfig::default()
        };

        let probe = resolve_runtime_probe(&mut cfg, false);
        assert_eq!(probe.source, DisplayGeometrySource::Cached);
        assert!(!probe.probe_dirty);
        assert_eq!(probe.geometry.width(), 128);
        assert_eq!(probe.geometry.height(), 128);
    }

    #[test]
    fn calibration_required_even_when_probe_cached() {
        // Regression: pending_calibration was gated on !use_cached, so after the probe
        // cache was written on first boot the wizard would never re-launch on subsequent
        // boots even though display_calibration_completed was still false.
        let mut cfg = DisplayConfig {
            display_probe_completed: true,
            display_calibration_completed: false, // <-- calibration not finished
            display_tests_version: DISPLAY_TESTS_VERSION,
            effective_width: Some(128),
            effective_height: Some(128),
            effective_offset_x: Some(0),
            effective_offset_y: Some(0),
            effective_backend: Some(DisplayBackend::St7735),
            effective_rotation: Some(DisplayRotation::Landscape),
            display_profile_fingerprint: Some(build_fingerprint(
                &DisplayBackend::St7735,
                &DisplayRotation::Landscape,
                128,
                128,
                0,
            )),
            ..DisplayConfig::default()
        };

        let probe = resolve_runtime_probe(&mut cfg, false);
        assert_eq!(probe.source, DisplayGeometrySource::Cached);
        assert!(probe.pending_calibration, "wizard must still launch when calibration is incomplete, even with a warm probe cache");
    }

    #[test]
    fn calibration_not_required_when_completed() {
        let mut cfg = DisplayConfig {
            display_probe_completed: true,
            display_calibration_completed: true,
            display_tests_version: DISPLAY_TESTS_VERSION,
            effective_width: Some(128),
            effective_height: Some(128),
            effective_offset_x: Some(0),
            effective_offset_y: Some(0),
            effective_backend: Some(DisplayBackend::St7735),
            effective_rotation: Some(DisplayRotation::Landscape),
            display_profile_fingerprint: Some(build_fingerprint(
                &DisplayBackend::St7735,
                &DisplayRotation::Landscape,
                128,
                128,
                0,
            )),
            ..DisplayConfig::default()
        };

        let probe = resolve_runtime_probe(&mut cfg, false);
        assert!(!probe.pending_calibration, "wizard must not launch after calibration is complete");
    }

    #[test]
    fn invalid_calibration_geometry_is_rejected() {
        let base = DisplayGeometry {
            left: 0,
            top: 0,
            right: 127,
            bottom: 127,
            offset_x: 0,
            offset_y: 0,
        };
        let mut cfg = DisplayConfig::default();
        cfg.calibrated_left = Some(10);
        cfg.calibrated_right = Some(5);
        cfg.calibrated_top = Some(0);
        cfg.calibrated_bottom = Some(10);
        assert!(calibration_geometry(&cfg, &base).is_none());
    }

    #[test]
    fn small_display_emits_unsupported_warning() {
        let mut cfg = DisplayConfig {
            width_override: Some(96),
            height_override: Some(64),
            ..DisplayConfig::default()
        };
        let probe = resolve_runtime_probe(&mut cfg, true);
        assert!(probe
            .warnings
            .iter()
            .any(|w| matches!(w, DisplayWarning::UnsupportedDisplaySize)));
    }
}

#[cfg(target_os = "linux")]
impl Display {
    pub fn new(colors: &ColorScheme, display_config: &mut DisplayConfig) -> Result<Self> {
        let probe = resolve_runtime_probe(display_config, false);
        let capabilities = DisplayCapabilities {
            width_px: probe.geometry.width(),
            height_px: probe.geometry.height(),
            orientation: probe.rotation.clone(),
            backend: probe.backend.clone(),
            safe_padding_px: display_config.safe_padding_px,
        };
        let layout = UiLayoutMetrics::from_dimensions(
            capabilities.width_px,
            capabilities.height_px,
            capabilities.safe_padding_px,
        );
        let diagnostics = DisplayDiagnostics {
            backend: probe.backend.clone(),
            detected_width_px: probe.detected_width,
            detected_height_px: probe.detected_height,
            effective_width_px: capabilities.width_px,
            effective_height_px: capabilities.height_px,
            effective_offset_x: probe.geometry.offset_x,
            effective_offset_y: probe.geometry.offset_y,
            geometry_source: probe.source.clone(),
            profile_fingerprint: probe.fingerprint.clone(),
            probe_completed: display_config.display_probe_completed,
            calibration_completed: display_config.display_calibration_completed,
            warnings: probe.warnings.clone(),
        };

        tracing::info!(
            backend = probe.backend.as_str(),
            detected_width = probe.detected_width,
            detected_height = probe.detected_height,
            effective_width = capabilities.width_px,
            effective_height = capabilities.height_px,
            offset_x = probe.geometry.offset_x,
            offset_y = probe.geometry.offset_y,
            source = probe.source.as_str(),
            calibration_completed = display_config.display_calibration_completed,
            "Display startup probe"
        );
        for warning in &diagnostics.warnings {
            tracing::warn!(
                event = warning.code(),
                backend = probe.backend.as_str(),
                detected_width = probe.detected_width,
                detected_height = probe.detected_height,
                effective_width = capabilities.width_px,
                effective_height = capabilities.height_px,
                "Display warning"
            );
        }

        // Open SPI device using SpidevDevice (embedded-hal 1.0 compatible)
        let mut spi = SpidevDevice::open("/dev/spidev0.0").context("opening SPI device")?;

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
        spi.configure(&options).context("configuring SPI")?;

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
        let dc_handle = dc_line
            .request(LineRequestFlags::OUTPUT, 0, "rustyjack-dc")
            .context("requesting DC line")?;
        let dc = CdevPin::new(dc_handle).context("creating DC pin")?;

        let rst_line = chip.get_line(27).context("getting RST line")?;
        let rst_handle = rst_line
            .request(LineRequestFlags::OUTPUT, 0, "rustyjack-rst")
            .context("requesting RST line")?;
        let rst = CdevPin::new(rst_handle).context("creating RST pin")?;

        let bl_line = chip.get_line(24).context("getting backlight line")?;
        let bl_handle = bl_line
            .request(LineRequestFlags::OUTPUT, 1, "rustyjack-bl")
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
        // Default to non-inverted / RGB mode so color names map correctly.
        // Previous default used inverted/BGR which can make blacks/whites and
        // red/blue channels appear swapped on many modules. If you have a
        // problematic module, run diagnostics with RUSTYJACK_DISPLAY_DIAG=1 which
        // will try other init permutations.
        let mut lcd = ST7735::new(
            spi,
            dc,
            rst,
            false,
            false,
            ST7735_PROFILE_WIDTH,
            ST7735_PROFILE_HEIGHT,
        );
        lcd.init(&mut delay)
            .map_err(|_| anyhow::anyhow!("LCD init failed"))?;
        let orientation = match probe.rotation {
            DisplayRotation::Portrait => Orientation::Portrait,
            DisplayRotation::Landscape => Orientation::Landscape,
        };
        lcd.set_orientation(&orientation)
            .map_err(|_| anyhow::anyhow!("LCD orientation failed"))?;
        let offset_x = probe.geometry.offset_x.max(0) as u16;
        let offset_y = probe.geometry.offset_y.max(0) as u16;
        lcd.set_offset(offset_x, offset_y);

        let palette = Palette::from_scheme(colors);

        // Clear screen using the configured theme background so startup does
        // not flash a hard-coded color.
        Rectangle::new(
            Point::new(0, 0),
            Size::new(capabilities.width_px, capabilities.height_px),
        )
        .into_styled(PrimitiveStyle::with_fill(palette.background))
        .draw(&mut lcd)
        .map_err(|_| anyhow::anyhow!("LCD clear failed"))?;
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
            layout,
            capabilities,
            diagnostics,
            pending_calibration: probe.pending_calibration,
            probe_dirty: probe.probe_dirty,
        })
    }

    /// Run a diagnostic sequence on the LCD — cycles a few common SPI speeds
    /// and ST7735 init parameter combinations so you can visually identify
    /// a configuration that makes the module render correctly.
    pub fn run_diagnostics(_colors: &ColorScheme) -> Result<()> {
        // Common speeds to try (some modules are sensitive to speed)
        let speeds = [
            1_000_000u32,
            2_000_000u32,
            4_000_000u32,
            8_000_000u32,
            12_000_000u32,
        ];
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
        let mut buttons = ButtonPad::new(&PinConfig::default())?;
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
                        eprintln!(
                            "Diag #{}: speed={} bgr={} invert={} orient={}",
                            attempt,
                            speed,
                            bgr,
                            inv,
                            orient_label(orient)
                        );

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
                        spi.configure(&options)
                            .context("configuring spi for diag")?;

                        let mut chip = match Chip::new("/dev/gpiochip0") {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("diag: opening gpiochip failed: {:#}", e);
                                continue;
                            }
                        };

                        // helper to request a line but retry briefly if it's busy
                        fn request_line_with_retry(
                            chip: &mut Chip,
                            line: u32,
                            consumer: &str,
                            default: u8,
                        ) -> Result<CdevPin, anyhow::Error> {
                            let mut tries = 0usize;
                            loop {
                                match chip.get_line(line) {
                                    Ok(l) => {
                                        match l.request(LineRequestFlags::OUTPUT, default, consumer)
                                        {
                                            Ok(handle) => {
                                                return CdevPin::new(handle).map_err(|e| e.into())
                                            }
                                            Err(_e) => {
                                                // Common case is EBUSY (line owned by another
                                                // process). Retry a few times with a short backoff
                                                // in case the other process is shutting down.
                                                tries += 1;
                                                if tries < 8 {
                                                    sleep(StdDuration::from_millis(120));
                                                    continue;
                                                }

                                                eprintln!("diag: requesting {} line for diag: failed after retries — dumping system state:", consumer);
                                                match crate::util::fetch_gpio_diagnostics() {
                                                    Ok(report) => eprintln!("{report}"),
                                                    Err(err) => eprintln!(
                                                        "diag: failed to collect gpio diagnostics: {:#}",
                                                        err
                                                    ),
                                                }

                                                return Err(anyhow::anyhow!("requesting {} line for diag: failed after retries", consumer));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        return Err(anyhow::anyhow!(
                                            "getting {} line for diag: {:#}",
                                            consumer,
                                            e
                                        ))
                                    }
                                }
                            }
                        }

                        let dc = match request_line_with_retry(&mut chip, 25, "rustyjack-dc", 0u8) {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("diag: {}", e);
                                continue;
                            }
                        };

                        let rst = match request_line_with_retry(&mut chip, 27, "rustyjack-rst", 0u8)
                        {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("diag: {}", e);
                                continue;
                            }
                        };

                        let _backlight =
                            match request_line_with_retry(&mut chip, 24, "rustyjack-bl", 1) {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("diag: {}", e);
                                    continue;
                                }
                            };

                        let mut delay = Delay {};
                        // Create the LCD with this combination
                        let mut lcd = ST7735::new(
                            spi,
                            dc,
                            rst,
                            inv,
                            bgr,
                            ST7735_PROFILE_WIDTH,
                            ST7735_PROFILE_HEIGHT,
                        );
                        let _ = lcd.init(&mut delay);
                        let _ = lcd.set_orientation(&orient);
                        let offset_x =
                            env_i32("RUSTYJACK_DISPLAY_OFFSET_X", ST7735_DEFAULT_OFFSET_X).max(0)
                                as u16;
                        let offset_y =
                            env_i32("RUSTYJACK_DISPLAY_OFFSET_Y", ST7735_DEFAULT_OFFSET_Y).max(0)
                                as u16;
                        lcd.set_offset(offset_x, offset_y);

                        // Clear and draw a border in a diagnostic colour so it's easy
                        // to see which configuration is currently being displayed.
                        lcd.clear(Rgb565::BLACK).ok();
                        let color = diag_colors[attempt % diag_colors.len()];
                        // Request display area to include the final hardware column
                        Rectangle::new(
                            Point::new(0, 0),
                            Size::new(ST7735_PROFILE_WIDTH, ST7735_PROFILE_HEIGHT),
                        )
                        .into_styled(PrimitiveStyle::with_stroke(color, 3))
                        .draw(&mut lcd)
                        .ok();

                        // Draw a textual line showing the parameters (clamping length)
                        let info = format!(
                            "s={} bgr={} inv={} o={}",
                            speed,
                            bgr,
                            inv,
                            orient_label(orient)
                        );
                        let style = MonoTextStyleBuilder::new()
                            .font(&FONT_6X10)
                            .text_color(color)
                            .build();
                        let _ = Text::with_baseline(&info, Point::new(2, 60), style, Baseline::Top)
                            .draw(&mut lcd);
                        let _ = Text::with_baseline(
                            "Press a button",
                            Point::new(2, 75),
                            style,
                            Baseline::Top,
                        )
                        .draw(&mut lcd);

                        // Wait for input before advancing
                        let _ = buttons.wait_for_press();

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

    pub fn layout(&self) -> &UiLayoutMetrics {
        &self.layout
    }

    pub fn capabilities(&self) -> &DisplayCapabilities {
        &self.capabilities
    }

    pub fn diagnostics(&self) -> &DisplayDiagnostics {
        &self.diagnostics
    }

    pub fn menu_visible_items(&self) -> usize {
        self.layout.menu_visible_items
    }

    pub fn dialog_visible_lines(&self) -> usize {
        self.layout.dialog_visible_lines
    }

    pub fn chars_per_line(&self) -> usize {
        self.layout.chars_per_line
    }

    pub fn title_chars_per_line(&self) -> usize {
        self.layout.title_chars_per_line
    }

    pub fn needs_startup_calibration(&self) -> bool {
        self.pending_calibration
    }

    pub fn probe_dirty(&self) -> bool {
        self.probe_dirty
    }

    pub fn reset_probe_dirty(&mut self) {
        self.probe_dirty = false;
    }

    pub fn run_display_discovery(&mut self, config: &mut DisplayConfig) -> Result<()> {
        let probe = resolve_runtime_probe(config, true);
        self.pending_calibration = probe.pending_calibration;
        self.probe_dirty = true;
        self.capabilities = DisplayCapabilities {
            width_px: probe.geometry.width(),
            height_px: probe.geometry.height(),
            orientation: probe.rotation.clone(),
            backend: probe.backend.clone(),
            safe_padding_px: config.safe_padding_px,
        };
        self.layout = UiLayoutMetrics::from_dimensions(
            self.capabilities.width_px,
            self.capabilities.height_px,
            self.capabilities.safe_padding_px,
        );
        self.diagnostics = DisplayDiagnostics {
            backend: probe.backend,
            detected_width_px: probe.detected_width,
            detected_height_px: probe.detected_height,
            effective_width_px: self.capabilities.width_px,
            effective_height_px: self.capabilities.height_px,
            effective_offset_x: probe.geometry.offset_x,
            effective_offset_y: probe.geometry.offset_y,
            geometry_source: probe.source,
            profile_fingerprint: probe.fingerprint,
            probe_completed: config.display_probe_completed,
            calibration_completed: config.display_calibration_completed,
            warnings: probe.warnings,
        };

        let orientation = match self.capabilities.orientation {
            DisplayRotation::Portrait => Orientation::Portrait,
            DisplayRotation::Landscape => Orientation::Landscape,
        };
        self.lcd
            .set_orientation(&orientation)
            .map_err(|_| anyhow::anyhow!("LCD orientation failed"))?;
        self.lcd.set_offset(
            self.diagnostics.effective_offset_x.max(0) as u16,
            self.diagnostics.effective_offset_y.max(0) as u16,
        );
        Ok(())
    }

    pub fn validate_calibration(&self, left: i32, top: i32, right: i32, bottom: i32) -> Result<()> {
        if right <= left || bottom <= top {
            anyhow::bail!("invalid calibration bounds: non-positive area");
        }
        let width = right - left + 1;
        let height = bottom - top + 1;
        if width < 32 || height < 32 {
            anyhow::bail!("invalid calibration bounds: area too small (min 32x32)");
        }
        Ok(())
    }

    pub fn apply_calibration(
        &mut self,
        config: &mut DisplayConfig,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    ) -> Result<()> {
        self.validate_calibration(left, top, right, bottom)?;
        let width = right.saturating_sub(left).saturating_add(1) as u32;
        let height = bottom.saturating_sub(top).saturating_add(1) as u32;

        config.calibrated_left = Some(left);
        config.calibrated_top = Some(top);
        config.calibrated_right = Some(right);
        config.calibrated_bottom = Some(bottom);
        config.last_calibrated_at = Some(Utc::now().to_rfc3339());
        config.display_calibration_completed = true;
        config.display_geometry_source = Some(DisplayGeometrySource::Calibrated);
        config.effective_width = Some(width);
        config.effective_height = Some(height);
        config.effective_offset_x = Some(self.diagnostics.effective_offset_x + left);
        config.effective_offset_y = Some(self.diagnostics.effective_offset_y + top);
        config.calibration_version = config.calibration_version.max(1);

        self.pending_calibration = false;
        self.probe_dirty = true;
        self.run_display_discovery(config)?;
        Ok(())
    }

    pub fn reset_calibration(&mut self, config: &mut DisplayConfig) -> Result<()> {
        config.clear_calibration();
        self.pending_calibration = true;
        self.run_display_discovery(config)
    }

    pub fn reset_cache(&mut self, config: &mut DisplayConfig) -> Result<()> {
        config.clear_cache();
        self.pending_calibration = true;
        self.run_display_discovery(config)
    }

    pub fn default_calibration_edges(&self) -> (i32, i32, i32, i32) {
        (
            0,
            0,
            self.diagnostics.detected_width_px.saturating_sub(1) as i32,
            self.diagnostics.detected_height_px.saturating_sub(1) as i32,
        )
    }

    pub fn draw_calibration_step(
        &mut self,
        edge: CalibrationEdge,
        candidate: i32,
        defaults: i32,
        status: &StatusOverlay,
    ) -> Result<()> {
        self.clear()?;
        self.draw_toolbar_with_title(Some("Display Calib"), status)?;

        let content_x = self.layout.safe_padding_px as i32;
        let content_w = self.layout.content_width() as i32;
        let content_y = self.layout.content_top as i32;
        let content_h = self.layout.content_height() as i32;
        let guide = PrimitiveStyle::with_stroke(Rgb565::WHITE, 1);
        let shade = PrimitiveStyle::with_fill(Rgb565::new(3, 3, 3));

        match edge {
            CalibrationEdge::Left | CalibrationEdge::Right => {
                let x = candidate.clamp(content_x, content_x + content_w.saturating_sub(1));
                if edge == CalibrationEdge::Left && x > content_x {
                    Rectangle::new(
                        Point::new(content_x, content_y),
                        Size::new((x - content_x) as u32, content_h as u32),
                    )
                    .into_styled(shade)
                    .draw(&mut self.lcd)
                    .map_err(|_| anyhow::anyhow!("Draw error"))?;
                }
                if edge == CalibrationEdge::Right && x < content_x + content_w - 1 {
                    Rectangle::new(
                        Point::new(x + 1, content_y),
                        Size::new((content_x + content_w - x - 1) as u32, content_h as u32),
                    )
                    .into_styled(shade)
                    .draw(&mut self.lcd)
                    .map_err(|_| anyhow::anyhow!("Draw error"))?;
                }
                Rectangle::new(Point::new(x, content_y), Size::new(1, content_h as u32))
                    .into_styled(guide)
                    .draw(&mut self.lcd)
                    .map_err(|_| anyhow::anyhow!("Draw error"))?;
            }
            CalibrationEdge::Top | CalibrationEdge::Bottom => {
                let y = candidate.clamp(content_y, content_y + content_h.saturating_sub(1));
                if edge == CalibrationEdge::Top && y > content_y {
                    Rectangle::new(
                        Point::new(content_x, content_y),
                        Size::new(content_w as u32, (y - content_y) as u32),
                    )
                    .into_styled(shade)
                    .draw(&mut self.lcd)
                    .map_err(|_| anyhow::anyhow!("Draw error"))?;
                }
                if edge == CalibrationEdge::Bottom && y < content_y + content_h - 1 {
                    Rectangle::new(
                        Point::new(content_x, y + 1),
                        Size::new(content_w as u32, (content_y + content_h - y - 1) as u32),
                    )
                    .into_styled(shade)
                    .draw(&mut self.lcd)
                    .map_err(|_| anyhow::anyhow!("Draw error"))?;
                }
                Rectangle::new(Point::new(content_x, y), Size::new(content_w as u32, 1))
                    .into_styled(guide)
                    .draw(&mut self.lcd)
                    .map_err(|_| anyhow::anyhow!("Draw error"))?;
            }
        }

        let edge_label = edge.label();
        let help = edge.help_text();
        let lines = [
            format!("Edge: {edge_label}"),
            format!("Value: {candidate}px"),
            format!("Default: {defaults}px"),
            help.to_string(),
            "SEL=Confirm K1=Reset".to_string(),
            "K2=Cancel".to_string(),
        ];
        let mut y = self.layout.content_top as i32;
        for line in lines.iter() {
            let clipped = ellipsize(line, self.layout.chars_per_line);
            Text::with_baseline(
                &clipped,
                Point::new(content_x + 2, y),
                self.text_style_small,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += self.layout.line_height_px as i32;
            if y > self.layout.content_bottom as i32 {
                break;
            }
        }
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        let style = PrimitiveStyle::with_fill(self.palette.background);
        Rectangle::new(
            Point::new(0, 0),
            Size::new(self.capabilities.width_px, self.capabilities.height_px),
        )
        .into_styled(style)
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Failed to clear display"))?;
        Ok(())
    }

    pub fn show_splash_screen(&mut self, image_path: &Path) -> Result<()> {
        // Clear with theme background so splash matches configured colors.
        let style = PrimitiveStyle::with_fill(self.palette.background);
        // If clearing the simulated display in non-linux builds, cover the
        // full buffer area including the last column/row used by hardware
        Rectangle::new(
            Point::new(0, 0),
            Size::new(self.capabilities.width_px, self.capabilities.height_px),
        )
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
                        let x = (self.capabilities.width_px as i32 - bmp_width) / 2;
                        let y = (self.capabilities.height_px as i32 - bmp_height) / 2;

                        let image = Image::new(&bmp, Point::new(x.max(0), y.max(0)));
                        image
                            .draw(&mut self.lcd)
                            .map_err(|_| anyhow::anyhow!("Draw error"))?;
                        return Ok(());
                    }
                } else {
                    // For PNG/JPG, convert on-the-fly (slower)
                    let img = image::open(image_to_load)?;

                    // Resize to fit screen if needed
                    let img = if img.width() > self.capabilities.width_px
                        || img.height() > self.capabilities.height_px
                    {
                        img.resize(
                            self.capabilities.width_px,
                            self.capabilities.height_px,
                            image::imageops::FilterType::Lanczos3,
                        )
                    } else {
                        img
                    };

                    let rgb_img = img.to_rgb8();

                    // Draw pixel by pixel
                    let x_offset = ((self.capabilities.width_px - rgb_img.width()) / 2) as i32;
                    let y_offset = ((self.capabilities.height_px - rgb_img.height()) / 2) as i32;

                    for (x, y, pixel) in rgb_img.enumerate_pixels() {
                        let rgb888 = Rgb888::new(pixel[0], pixel[1], pixel[2]);
                        let rgb565 = Rgb565::from(rgb888);
                        let px_x = x_offset + x as i32;
                        let px_y = y_offset + y as i32;
                        if px_x >= 0
                            && px_x < self.capabilities.width_px as i32
                            && px_y >= 0
                            && px_y < self.capabilities.height_px as i32
                        {
                            embedded_graphics::Pixel(Point::new(px_x, px_y), rgb565)
                                .draw(&mut self.lcd)
                                .map_err(|_| anyhow::anyhow!("Draw error"))?;
                        }
                    }
                    return Ok(());
                }
            }
        }

        // Image not found or load failed, show text fallback
        let text_style = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(self.palette.text)
            .build();
        Text::with_baseline("RUSTYJACK", Point::new(30, 60), text_style, Baseline::Top)
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;

        Text::with_baseline("Loading...", Point::new(30, 75), text_style, Baseline::Top)
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;

        Ok(())
    }

    pub fn draw_toolbar(&mut self, status: &StatusOverlay) -> Result<()> {
        self.draw_toolbar_with_title(None, status)
    }

    pub fn draw_toolbar_with_title(
        &mut self,
        title: Option<&str>,
        status: &StatusOverlay,
    ) -> Result<()> {
        let style = PrimitiveStyle::with_fill(self.palette.toolbar);
        Rectangle::new(
            Point::new(0, 0),
            Size::new(self.capabilities.width_px, self.layout.header_height),
        )
        .into_styled(style)
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

        // Draw title in top left if provided, clipped to avoid overlapping temp
        if let Some(t) = title {
            let title_text = ellipsize(t, self.layout.title_chars_per_line);
            Text::with_baseline(
                &title_text,
                Point::new(self.layout.safe_padding_px as i32 + 2, 3),
                self.text_style_small,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        // Temperature in top-right corner
        let temp_text = format!("{:.0}C", status.temp_c.min(99.0));
        let temp_x = (self
            .capabilities
            .width_px
            .saturating_sub(self.layout.toolbar_temp_width_px)) as i32;
        Text::with_baseline(
            &temp_text,
            Point::new(temp_x, 3),
            self.text_style_regular,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

        Ok(())
    }

    fn draw_ops_status(&mut self, status: &StatusOverlay) -> Result<()> {
        let ops_tag = |enabled: bool| if enabled { "ON" } else { "OFF" };
        let ops_text = format!(
            "Wi{} Et{} Hs{} Po{} St{} Pw{} Up{} Sy{} Dv{} Of{} Lo{} Pr{}",
            ops_tag(status.ops_wifi),
            ops_tag(status.ops_ethernet),
            ops_tag(status.ops_hotspot),
            ops_tag(status.ops_portal),
            ops_tag(status.ops_storage),
            ops_tag(status.ops_power),
            ops_tag(status.ops_update),
            ops_tag(status.ops_system),
            ops_tag(status.ops_dev),
            ops_tag(status.ops_offensive),
            ops_tag(status.ops_loot),
            ops_tag(status.ops_process),
        );
        let mut ops_lines = wrap_text(&ops_text, self.layout.chars_per_line);
        let max_ops_lines = ((self.layout.content_height() / self.layout.line_height_px)
            .max(1)
            .min(3)) as usize;
        ops_lines.truncate(max_ops_lines);
        let mut ops_y = self.layout.header_height as i32;
        for line in ops_lines.into_iter() {
            Text::with_baseline(
                &line,
                Point::new(self.layout.safe_padding_px as i32 + 2, ops_y),
                self.text_style_small,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            ops_y += self.layout.line_height_px as i32;
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
        self.draw_toolbar_with_title(Some(title), status)?;

        let mut y = self.layout.content_top as i32;
        let row_h = self.layout.menu_row_height as i32;
        for (idx, label) in items.iter().enumerate() {
            if idx == selected {
                Rectangle::new(
                    Point::new(0, y.saturating_sub(1)),
                    Size::new(self.capabilities.width_px, self.layout.menu_row_height),
                )
                .into_styled(PrimitiveStyle::with_fill(self.palette.selected_background))
                .draw(&mut self.lcd)
                .map_err(|_| anyhow::anyhow!("Draw error"))?;
            }
            let style = if idx == selected {
                self.text_style_highlight
            } else {
                self.text_style_regular
            };
            let display_label = ellipsize(label, self.layout.chars_per_line);
            Text::with_baseline(
                &display_label,
                Point::new(self.layout.safe_padding_px as i32 + 2, y),
                style,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += row_h;
            if y > self.layout.content_bottom as i32 {
                break;
            }
        }
        Ok(())
    }

    pub fn draw_dialog(&mut self, lines: &[String], status: &StatusOverlay) -> Result<()> {
        self.draw_dialog_with_offset(lines, 0, status)
    }

    pub fn draw_dialog_with_offset(
        &mut self,
        lines: &[String],
        body_offset: usize,
        status: &StatusOverlay,
    ) -> Result<()> {
        self.clear()?;

        // Use first line as the toolbar title when available
        let (title, body) = if let Some((first, rest)) = lines.split_first() {
            (Some(first.as_str()), rest)
        } else {
            (None, &[][..])
        };

        self.draw_toolbar_with_title(title, status)?;

        // Flatten and wrap body text before applying offset
        let wrapped: Vec<String> = body
            .iter()
            .flat_map(|line| wrap_text(line, self.layout.chars_per_line))
            .collect();

        let max_offset = wrapped
            .len()
            .saturating_sub(self.layout.dialog_visible_lines);
        let clamped_offset = body_offset.min(max_offset);

        // Body content below the toolbar
        let mut y = self.layout.content_top as i32;
        let mut shown = 0usize;
        for line in wrapped.iter().skip(clamped_offset) {
            if shown >= self.layout.dialog_visible_lines {
                break; // Only render what fits on-screen
            }
            Text::with_baseline(
                line,
                Point::new(self.layout.safe_padding_px as i32 + 2, y),
                self.text_style_regular,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += self.layout.line_height_px as i32;
            shown += 1;
        }
        Ok(())
    }

    /// Draw file viewer with scrolling filename in toolbar
    /// `title_offset` controls the horizontal scroll position of the filename
    pub fn draw_file_viewer(
        &mut self,
        filename: &str,
        title_offset: usize,
        lines: &[String],
        line_offset: usize,
        total_lines: usize,
        truncated: bool,
        status: &StatusOverlay,
    ) -> Result<()> {
        self.clear()?;
        self.draw_toolbar_with_title(None, status)?;

        // Apply scrolling offset to filename if it's too long
        let max_title_chars = self.layout.title_chars_per_line;
        let display_title = if filename.chars().count() > max_title_chars {
            let scroll_text = format!("{}   ", filename); // Add padding for wrap-around
            let start = title_offset % scroll_text.len();
            let visible: String = scroll_text
                .chars()
                .cycle()
                .skip(start)
                .take(max_title_chars)
                .collect();
            visible
        } else {
            filename.to_string()
        };

        Text::with_baseline(
            &display_title,
            Point::new(self.layout.safe_padding_px as i32 + 2, 3),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

        // Draw line position indicator below toolbar
        let pos_text = format!("{}/{}", line_offset + 1, total_lines);
        Text::with_baseline(
            &pos_text,
            Point::new(
                self.layout.safe_padding_px as i32 + 2,
                self.layout.content_top as i32,
            ),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

        // Draw file content starting below position indicator
        let mut y = self.layout.content_top as i32 + self.layout.line_height_px as i32 + 2;
        let max_chars = self.layout.chars_per_line;
        let body_bottom = self.layout.footer_y as i32 - self.layout.line_height_px as i32;

        for line in lines {
            if y > body_bottom {
                break;
            }
            // Truncate long lines rather than wrap for file viewing
            let display_line = ellipsize(line, max_chars);
            Text::with_baseline(
                &display_line,
                Point::new(self.layout.safe_padding_px as i32 + 2, y),
                self.text_style_regular,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += self.layout.line_height_px as i32;
        }

        // Draw footer hint
        let footer = if line_offset + lines.len() < total_lines {
            "DOWN=More"
        } else if truncated {
            "[Truncated]"
        } else {
            "END"
        };
        Text::with_baseline(
            footer,
            Point::new(
                self.layout.safe_padding_px as i32 + 2,
                self.layout.footer_y as i32,
            ),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

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

        let wrapped_title = wrap_text(title, self.layout.chars_per_line);
        let y = self.layout.content_top as i32 + 12;
        for (idx, line) in wrapped_title.iter().take(1).enumerate() {
            Text::with_baseline(
                line,
                Point::new(
                    self.layout.safe_padding_px as i32 + 2,
                    y + (idx as i32 * self.layout.line_height_px as i32),
                ),
                self.text_style_highlight,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        let wrapped_msg = wrap_text(message, self.layout.chars_per_line);
        let mut msg_y = y + self.layout.line_height_px as i32 + 2;
        for line in wrapped_msg.iter().take(2) {
            Text::with_baseline(
                line,
                Point::new(self.layout.safe_padding_px as i32 + 2, msg_y),
                self.text_style_regular,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            msg_y += self.layout.line_height_px as i32;
        }

        // Draw progress bar
        let bar_width = self.layout.content_width().saturating_sub(8).max(30);
        let bar_height = 8u32;
        let x = self.layout.safe_padding_px as i32 + 2;
        let y = (msg_y + 4).min(self.layout.footer_y as i32 - 14);

        Rectangle::new(Point::new(x, y), Size::new(bar_width, bar_height))
            .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;

        let fill_width = ((percentage / 100.0) * (bar_width as f32 - 2.0)) as u32;
        if fill_width > 0 {
            Rectangle::new(
                Point::new(x + 1, y + 1),
                Size::new(fill_width, bar_height - 2),
            )
            .into_styled(PrimitiveStyle::with_fill(self.palette.text))
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        // Draw percentage text
        let pct_text = format!("{:.1}%", percentage);
        Text::with_baseline(
            &pct_text,
            Point::new(self.layout.safe_padding_px as i32 + 2, y + 12),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

        Ok(())
    }

    pub fn draw_dashboard(&mut self, view: DashboardView, status: &StatusOverlay) -> Result<()> {
        self.clear()?;

        match view {
            DashboardView::SystemHealth => self.draw_system_health(status),
            DashboardView::TargetStatus => self.draw_target_status(status),
            DashboardView::MacStatus => self.draw_mac_status(status),
            DashboardView::NetworkInterfaces => self.draw_network_interfaces(status),
        }
    }

    fn draw_system_health(&mut self, status: &StatusOverlay) -> Result<()> {
        self.draw_toolbar_with_title(Some("SYSTEM HEALTH"), status)?;
        self.draw_ops_status(status)?;

        let cpu_bar_len = ((status.cpu_percent / 100.0) * 100.0).min(100.0) as u32;
        let mem_percent = (status.mem_used_mb as f32 / status.mem_total_mb.max(1) as f32) * 100.0;
        let mem_bar_len = ((mem_percent / 100.0) * 100.0).min(100.0) as u32;
        let disk_percent = (status.disk_used_gb / status.disk_total_gb.max(0.1)) * 100.0;
        let disk_bar_len = ((disk_percent / 100.0) * 100.0).min(100.0) as u32;

        let mut y = self.layout.header_height as i32 + (self.layout.line_height_px as i32 * 3) + 4;
        let left = self.layout.safe_padding_px as i32 + 2;
        let body_limit = self.layout.footer_y as i32 - (self.layout.line_height_px as i32 * 2);

        let cpu_text = format!("CPU:{:.0}C {:.0}%", status.temp_c, status.cpu_percent);
        if y <= body_limit {
            Text::with_baseline(
                &cpu_text,
                Point::new(left, y),
                self.text_style_small,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += self.layout.line_height_px as i32;
            self.draw_progress_bar(Point::new(left, y), cpu_bar_len)?;
            y += 12;
        }

        let mem_text = format!("MEM:{}M/{:.0}%", status.mem_used_mb, mem_percent);
        if y <= body_limit {
            Text::with_baseline(
                &mem_text,
                Point::new(left, y),
                self.text_style_small,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += self.layout.line_height_px as i32;
            self.draw_progress_bar(Point::new(left, y), mem_bar_len)?;
            y += 12;
        }

        let disk_text = format!("DSK:{:.1}G/{:.0}%", status.disk_used_gb, disk_percent);
        if y <= body_limit {
            Text::with_baseline(
                &disk_text,
                Point::new(left, y),
                self.text_style_small,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
            y += self.layout.line_height_px as i32;
            self.draw_progress_bar(Point::new(left, y), disk_bar_len)?;
            y += 14;
        }

        let uptime_hrs = status.uptime_secs / 3600;
        let uptime_mins = (status.uptime_secs % 3600) / 60;
        let uptime_text = format!("Up:{}h{}m", uptime_hrs, uptime_mins);
        if y <= body_limit {
            Text::with_baseline(
                &uptime_text,
                Point::new(left, y),
                self.text_style_small,
                Baseline::Top,
            )
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        Text::with_baseline(
            "LEFT=Exit SEL=Next",
            Point::new(
                self.layout.safe_padding_px as i32 + 2,
                self.layout.footer_y as i32,
            ),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

        Ok(())
    }

    fn draw_target_status(&mut self, status: &StatusOverlay) -> Result<()> {
        self.draw_toolbar_with_title(Some("TARGET STATUS"), status)?;
        self.draw_ops_status(status)?;

        let target_label = if !status.target_network.is_empty() {
            status.target_network.clone()
        } else if !status.target_bssid.is_empty() {
            status.target_bssid.clone()
        } else {
            "Not set".to_string()
        };

        let bssid_label = if status.target_bssid.is_empty() {
            "-".to_string()
        } else {
            status.target_bssid.clone()
        };

        let channel_text = if status.target_channel > 0 {
            status.target_channel.to_string()
        } else {
            "-".to_string()
        };

        let interface_label = if status.active_interface.is_empty() {
            "None".to_string()
        } else {
            status.active_interface.clone()
        };

        let entries = [
            format!("Target: {}", target_label),
            format!("BSSID: {}", bssid_label),
            format!("Channel: {}", channel_text),
            format!("Module: {}", interface_label),
        ];

        let mut y = self.layout.header_height as i32 + (self.layout.line_height_px as i32 * 3) + 4;
        let max_chars = self.layout.chars_per_line;
        let left = self.layout.safe_padding_px as i32 + 2;
        let body_limit = self.layout.footer_y as i32 - self.layout.line_height_px as i32;
        for line in entries.iter() {
            for wrapped in wrap_text(line, max_chars) {
                if y > body_limit {
                    break;
                }
                Text::with_baseline(
                    &wrapped,
                    Point::new(left, y),
                    self.text_style_small,
                    Baseline::Top,
                )
                .draw(&mut self.lcd)
                .map_err(|_| anyhow::anyhow!("Draw error"))?;
                y += self.layout.line_height_px as i32 + 2;
            }
        }

        Text::with_baseline(
            "LEFT=Exit SEL=Next",
            Point::new(
                self.layout.safe_padding_px as i32 + 2,
                self.layout.footer_y as i32,
            ),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;

        Ok(())
    }

    fn draw_mac_status(&mut self, status: &StatusOverlay) -> Result<()> {
        self.draw_toolbar_with_title(Some("MAC STATUS"), status)?;
        self.draw_ops_status(status)?;

        let interface_label = if status.active_interface.is_empty() {
            "None".to_string()
        } else {
            status.active_interface.clone()
        };

        let real_mac = if status.original_mac.is_empty() {
            "Unknown".to_string()
        } else {
            status.original_mac.clone()
        };

        let current_mac = if status.current_mac.is_empty() {
            "Unknown".to_string()
        } else {
            status.current_mac.clone()
        };

        let entries = [
            format!("Interface: {}", interface_label),
            format!("Real MAC: {}", real_mac),
            format!("Current: {}", current_mac),
        ];

        let mut y = self.layout.header_height as i32 + (self.layout.line_height_px as i32 * 3) + 4;
        let max_chars = self.layout.chars_per_line;
        let left = self.layout.safe_padding_px as i32 + 2;
        let body_limit = self.layout.footer_y as i32 - self.layout.line_height_px as i32;
        for line in entries.iter() {
            for wrapped in wrap_text(line, max_chars) {
                if y > body_limit {
                    break;
                }
                Text::with_baseline(
                    &wrapped,
                    Point::new(left, y),
                    self.text_style_small,
                    Baseline::Top,
                )
                .draw(&mut self.lcd)
                .map_err(|_| anyhow::anyhow!("Draw error"))?;
                y += self.layout.line_height_px as i32 + 2;
            }
        }

        Text::with_baseline(
            "LEFT=Exit SEL=Next",
            Point::new(
                self.layout.safe_padding_px as i32 + 2,
                self.layout.footer_y as i32,
            ),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;
        Ok(())
    }

    fn draw_network_interfaces(&mut self, status: &StatusOverlay) -> Result<()> {
        self.draw_toolbar_with_title(Some("NETWORK IFS"), status)?;
        self.draw_ops_status(status)?;

        let mut entries = Vec::new();

        if !status.active_interface.is_empty() {
            let state_label = if status.active_interface_up {
                "UP"
            } else {
                match status.active_interface_state.as_str() {
                    "down" => "DN",
                    "dormant" => "DR",
                    "lowerlayerdown" => "DN",
                    "" => "??",
                    _ => "??",
                }
            };
            let ip_label = status.active_interface_ip.as_deref().unwrap_or("-");
            entries.push(format!(
                "Active: {} [{}]",
                status.active_interface, state_label
            ));
            entries.push(format!("  IP: {}", ip_label));
        }

        for iface in status.interfaces.iter() {
            if iface.name == "lo" {
                continue;
            }

            let is_active = iface.name == status.active_interface;
            let (state_symbol, ip_display) = if is_active {
                let symbol = if status.active_interface_up {
                    "UP"
                } else {
                    match status.active_interface_state.as_str() {
                        "down" => "DN",
                        "dormant" => "DR",
                        "lowerlayerdown" => "DN",
                        "" => "??",
                        _ => "??",
                    }
                };
                let ip = status.active_interface_ip.as_deref().unwrap_or("-");
                (symbol, ip)
            } else {
                let symbol = match iface.oper_state.as_str() {
                    "up" => "UP",
                    "down" => "DN",
                    other => {
                        if other.eq_ignore_ascii_case("dormant") {
                            "DR"
                        } else {
                            "??"
                        }
                    }
                };
                let ip = if iface.oper_state == "up" {
                    iface.ip.as_deref().unwrap_or("-")
                } else {
                    "-"
                };
                (symbol, ip)
            };

            let label = if is_active {
                format!("*{} [{}] {}", iface.name, state_symbol, iface.kind)
            } else {
                format!("{} [{}] {}", iface.name, state_symbol, iface.kind)
            };
            entries.push(label);
            entries.push(format!("  IP: {}", ip_display));
        }

        if entries.is_empty() {
            entries.push("No interfaces found".to_string());
        }

        let mut y = self.layout.header_height as i32 + (self.layout.line_height_px as i32 * 3) + 4;
        let max_chars = self.layout.chars_per_line;
        let left = self.layout.safe_padding_px as i32 + 2;
        let body_limit = self.layout.footer_y as i32 - self.layout.line_height_px as i32;
        for line in entries.iter() {
            for wrapped in wrap_text(line, max_chars) {
                if y > body_limit {
                    break;
                }
                Text::with_baseline(
                    &wrapped,
                    Point::new(left, y),
                    self.text_style_small,
                    Baseline::Top,
                )
                .draw(&mut self.lcd)
                .map_err(|_| anyhow::anyhow!("Draw error"))?;
                y += self.layout.line_height_px as i32;
            }
        }

        Text::with_baseline(
            "LEFT=Exit SEL=Next",
            Point::new(
                self.layout.safe_padding_px as i32 + 2,
                self.layout.footer_y as i32,
            ),
            self.text_style_small,
            Baseline::Top,
        )
        .draw(&mut self.lcd)
        .map_err(|_| anyhow::anyhow!("Draw error"))?;
        Ok(())
    }

    fn draw_progress_bar(&mut self, pos: Point, fill_width: u32) -> Result<()> {
        let bar_width = self.layout.content_width().saturating_sub(12).max(30);
        let bar_height = 6u32;

        Rectangle::new(pos, Size::new(bar_width, bar_height))
            .into_styled(PrimitiveStyle::with_stroke(self.palette.border, 1))
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;

        if fill_width > 0 {
            Rectangle::new(
                Point::new(pos.x + 1, pos.y + 1),
                Size::new(fill_width.min(bar_width - 2), bar_height - 2),
            )
            .into_styled(PrimitiveStyle::with_fill(self.palette.text))
            .draw(&mut self.lcd)
            .map_err(|_| anyhow::anyhow!("Draw error"))?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn palette(&self) -> &Palette {
        &self.palette
    }
}

#[cfg(not(target_os = "linux"))]
impl Display {
    pub fn new(colors: &ColorScheme, display_config: &mut DisplayConfig) -> Result<Self> {
        let width = display_config.effective_width.unwrap_or(128);
        let height = display_config.effective_height.unwrap_or(128);
        let backend = display_config
            .effective_backend
            .clone()
            .unwrap_or(DisplayBackend::St7735);
        let rotation = display_config
            .effective_rotation
            .clone()
            .unwrap_or(DisplayRotation::Landscape);
        let layout =
            UiLayoutMetrics::from_dimensions(width, height, display_config.safe_padding_px);
        Ok(Self {
            palette: Palette::from_scheme(colors),
            layout,
            capabilities: DisplayCapabilities {
                width_px: width,
                height_px: height,
                orientation: rotation,
                backend: backend.clone(),
                safe_padding_px: display_config.safe_padding_px,
            },
            diagnostics: DisplayDiagnostics {
                backend,
                detected_width_px: width,
                detected_height_px: height,
                effective_width_px: width,
                effective_height_px: height,
                effective_offset_x: 0,
                effective_offset_y: 0,
                geometry_source: display_config
                    .display_geometry_source
                    .clone()
                    .unwrap_or(DisplayGeometrySource::Profile),
                profile_fingerprint: display_config
                    .display_profile_fingerprint
                    .clone()
                    .unwrap_or_else(|| "simulated".to_string()),
                probe_completed: display_config.display_probe_completed,
                calibration_completed: display_config.display_calibration_completed,
                warnings: Vec::new(),
            },
            pending_calibration: false,
            probe_dirty: false,
        })
    }

    pub fn update_palette(&mut self, colors: &ColorScheme) {
        self.palette = Palette::from_scheme(colors);
    }

    pub fn layout(&self) -> &UiLayoutMetrics {
        &self.layout
    }

    pub fn capabilities(&self) -> &DisplayCapabilities {
        &self.capabilities
    }

    pub fn diagnostics(&self) -> &DisplayDiagnostics {
        &self.diagnostics
    }

    pub fn menu_visible_items(&self) -> usize {
        self.layout.menu_visible_items
    }

    pub fn dialog_visible_lines(&self) -> usize {
        self.layout.dialog_visible_lines
    }

    pub fn chars_per_line(&self) -> usize {
        self.layout.chars_per_line
    }

    pub fn title_chars_per_line(&self) -> usize {
        self.layout.title_chars_per_line
    }

    pub fn needs_startup_calibration(&self) -> bool {
        self.pending_calibration
    }

    pub fn probe_dirty(&self) -> bool {
        self.probe_dirty
    }

    pub fn reset_probe_dirty(&mut self) {
        self.probe_dirty = false;
    }

    pub fn run_display_discovery(&mut self, _config: &mut DisplayConfig) -> Result<()> {
        Ok(())
    }

    pub fn validate_calibration(
        &self,
        _left: i32,
        _top: i32,
        _right: i32,
        _bottom: i32,
    ) -> Result<()> {
        Ok(())
    }

    pub fn apply_calibration(
        &mut self,
        config: &mut DisplayConfig,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    ) -> Result<()> {
        config.calibrated_left = Some(left);
        config.calibrated_top = Some(top);
        config.calibrated_right = Some(right);
        config.calibrated_bottom = Some(bottom);
        config.display_calibration_completed = true;
        self.probe_dirty = true;
        Ok(())
    }

    pub fn reset_calibration(&mut self, config: &mut DisplayConfig) -> Result<()> {
        config.clear_calibration();
        self.probe_dirty = true;
        Ok(())
    }

    pub fn reset_cache(&mut self, config: &mut DisplayConfig) -> Result<()> {
        config.clear_cache();
        self.probe_dirty = true;
        Ok(())
    }

    pub fn default_calibration_edges(&self) -> (i32, i32, i32, i32) {
        (
            0,
            0,
            self.capabilities.width_px as i32 - 1,
            self.capabilities.height_px as i32 - 1,
        )
    }

    pub fn draw_calibration_step(
        &mut self,
        edge: CalibrationEdge,
        candidate: i32,
        _defaults: i32,
        _: &StatusOverlay,
    ) -> Result<()> {
        println!("Calibrate {} -> {}", edge.label(), candidate);
        Ok(())
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
        println!(
            "[status] {:.0} °C | {}",
            status.temp_c,
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

    pub fn draw_dialog(&mut self, lines: &[String], status: &StatusOverlay) -> Result<()> {
        self.draw_dialog_with_offset(lines, 0, status)
    }

    pub fn draw_dialog_with_offset(
        &mut self,
        lines: &[String],
        body_offset: usize,
        _: &StatusOverlay,
    ) -> Result<()> {
        if let Some((first, rest)) = lines.split_first() {
            println!("--- {first} ---");
            let wrapped: Vec<String> = rest
                .iter()
                .flat_map(|line| wrap_text(line, self.layout.chars_per_line))
                .collect();
            let max_offset = wrapped
                .len()
                .saturating_sub(self.layout.dialog_visible_lines);
            let clamped_offset = body_offset.min(max_offset);
            for line in wrapped
                .iter()
                .skip(clamped_offset)
                .take(self.layout.dialog_visible_lines)
            {
                println!("{line}");
            }
            println!("--------------");
        } else {
            println!("--- dialog ---");
            println!("(empty)");
            println!("--------------");
        }
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
        println!(
            "[ops] Wi{} Et{} Hs{} Po{} St{} Pw{} Up{} Sy{} Dv{} Of{} Lo{} Pr{}",
            on_off(status.ops_wifi),
            on_off(status.ops_ethernet),
            on_off(status.ops_hotspot),
            on_off(status.ops_portal),
            on_off(status.ops_storage),
            on_off(status.ops_power),
            on_off(status.ops_update),
            on_off(status.ops_system),
            on_off(status.ops_dev),
            on_off(status.ops_offensive),
            on_off(status.ops_loot),
            on_off(status.ops_process),
        );
        match view {
            DashboardView::SystemHealth => {
                println!("CPU: {:.0}% ({:.0}°C)", status.cpu_percent, status.temp_c);
                println!("MEM: {}/{} MB", status.mem_used_mb, status.mem_total_mb);
                println!(
                    "DISK: {:.1}/{:.1} GB",
                    status.disk_used_gb, status.disk_total_gb
                );
                println!("Uptime: {}s", status.uptime_secs);
            }
            DashboardView::TargetStatus => {
                println!(
                    "Target: {}",
                    if status.target_network.is_empty() {
                        status.target_bssid.as_str()
                    } else {
                        status.target_network.as_str()
                    }
                );
                println!(
                    "BSSID: {}",
                    if status.target_bssid.is_empty() {
                        "-"
                    } else {
                        status.target_bssid.as_str()
                    }
                );
                println!(
                    "Channel: {}",
                    if status.target_channel > 0 {
                        status.target_channel.to_string()
                    } else {
                        "-".to_string()
                    }
                );
                println!(
                    "Module: {}",
                    if status.active_interface.is_empty() {
                        "None"
                    } else {
                        status.active_interface.as_str()
                    }
                );
            }
            DashboardView::MacStatus => {
                println!(
                    "Interface: {}",
                    if status.active_interface.is_empty() {
                        "None"
                    } else {
                        status.active_interface.as_str()
                    }
                );
                println!(
                    "Real MAC: {}",
                    if status.original_mac.is_empty() {
                        "Unknown"
                    } else {
                        status.original_mac.as_str()
                    }
                );
                println!(
                    "Current MAC: {}",
                    if status.current_mac.is_empty() {
                        "Unknown"
                    } else {
                        status.current_mac.as_str()
                    }
                );
            }
            DashboardView::NetworkInterfaces => {
                if status.interfaces.is_empty() {
                    println!("No interfaces");
                } else {
                    for iface in status.interfaces.iter() {
                        if let Some(ip) = iface.ip.as_ref() {
                            println!("{}: {}", iface.name, ip);
                        }
                    }
                }
            }
        }
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
            toolbar: parse_color(&colors.toolbar, Rgb565::new(20, 20, 20)),
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
    pub dns_spoof_running: bool,
    pub ops_wifi: bool,
    pub ops_ethernet: bool,
    pub ops_hotspot: bool,
    pub ops_portal: bool,
    pub ops_storage: bool,
    pub ops_power: bool,
    pub ops_update: bool,
    pub ops_system: bool,
    pub ops_dev: bool,
    pub ops_offensive: bool,
    pub ops_loot: bool,
    pub ops_process: bool,
    pub cpu_percent: f32,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub disk_used_gb: f32,
    pub disk_total_gb: f32,
    pub uptime_secs: u64,
    pub target_network: String,
    pub target_bssid: String,
    pub target_channel: u8,
    pub active_interface: String,
    pub active_interface_state: String,
    pub active_interface_up: bool,
    pub active_interface_carrier: Option<bool>,
    pub active_interface_ip: Option<String>,
    pub active_interface_has_ip: bool,
    pub original_mac: String,
    pub current_mac: String,
    pub interfaces: Vec<crate::types::InterfaceSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardView {
    SystemHealth,
    TargetStatus,
    MacStatus,
    NetworkInterfaces,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_from_scheme_uses_fallbacks_for_invalid_hex() {
        let scheme = ColorScheme {
            background: "invalid".to_string(),
            border: "#12".to_string(),
            text: "xyzxyz".to_string(),
            selected_text: "#ABCDE".to_string(),
            selected_background: "#12345G".to_string(),
            toolbar: "qwerty".to_string(),
        };

        let palette = Palette::from_scheme(&scheme);
        assert_eq!(palette.background, Rgb565::BLACK);
        assert_eq!(palette.border, Rgb565::WHITE);
        assert_eq!(palette.text, Rgb565::WHITE);
        assert_eq!(palette.selected_text, Rgb565::WHITE);
        assert_eq!(palette.selected_background, Rgb565::BLACK);
        assert_eq!(palette.toolbar, Rgb565::new(20, 20, 20));
    }
}
