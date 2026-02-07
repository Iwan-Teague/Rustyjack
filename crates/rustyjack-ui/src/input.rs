use std::{
    env,
    fs::OpenOptions,
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;

use crate::config::PinConfig;

pub const BUTTON_COUNT: usize = 8;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Up,
    Down,
    Left,
    Right,
    Select,
    Key1,
    Key2,
    Key3,
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use anyhow::{anyhow, Context};
    use linux_embedded_hal::gpio_cdev::{Chip, LineHandle, LineRequestFlags};
    use std::collections::HashSet;

    struct ButtonInput {
        kind: Button,
        handle: LineHandle,
    }

    impl ButtonInput {
        fn new(kind: Button, pin: u32, chip: &mut Chip) -> Result<Self> {
            let line = chip
                .get_line(pin)
                .with_context(|| format!("requesting GPIO line {}", pin))?;
            // Waveshare HAT buttons are active-low (pressed = 0, released = 1).
            // Pull-ups are configured via /boot/config.txt (gpio=6,19,5,26,13,21,20,16=pu)
            // which the installer sets automatically. The default value of 1 represents
            // the normal unpressed state (pulled high).
            let handle = line
                .request(LineRequestFlags::INPUT, 1, "rustyjack-ui")
                .with_context(|| format!("configuring GPIO line {}", pin))?;
            Ok(Self { kind, handle })
        }

        fn is_pressed(&self) -> Result<bool> {
            Ok(self.handle.get_value()? == 0)
        }
    }

    pub struct ButtonPad {
        buttons: Vec<ButtonInput>,
        virtual_rx: Option<Receiver<Button>>,
        pending_virtual: Option<Button>,
        __debounce: Duration,
        last_press: Instant,
    }

    impl ButtonPad {
        pub fn new(pins: &PinConfig) -> Result<Self> {
            let pin_map = [
                ("Up", pins.key_up_pin, Button::Up),
                ("Down", pins.key_down_pin, Button::Down),
                ("Left", pins.key_left_pin, Button::Left),
                ("Right", pins.key_right_pin, Button::Right),
                ("Select", pins.key_press_pin, Button::Select),
                ("Key1", pins.key1_pin, Button::Key1),
                ("Key2", pins.key2_pin, Button::Key2),
                ("Key3", pins.key3_pin, Button::Key3),
            ];

            if pin_map.len() != BUTTON_COUNT {
                return Err(anyhow!(
                    "button map invariant failed: expected {} controls, got {}",
                    BUTTON_COUNT,
                    pin_map.len()
                ));
            }

            let mut seen_pins = HashSet::new();
            for (name, pin, _) in pin_map {
                if pin == 0 {
                    return Err(anyhow!(
                        "button map invariant failed: missing GPIO mapping for {}",
                        name
                    ));
                }
                if !seen_pins.insert(pin) {
                    return Err(anyhow!(
                        "button map invariant failed: duplicate GPIO pin {} for {}",
                        pin,
                        name
                    ));
                }
            }

            let mut chip = Chip::new("/dev/gpiochip0")?;
            let mut buttons = Vec::new();
            buttons.push(ButtonInput::new(Button::Up, pins.key_up_pin, &mut chip)?);
            buttons.push(ButtonInput::new(
                Button::Down,
                pins.key_down_pin,
                &mut chip,
            )?);
            buttons.push(ButtonInput::new(
                Button::Left,
                pins.key_left_pin,
                &mut chip,
            )?);
            buttons.push(ButtonInput::new(
                Button::Right,
                pins.key_right_pin,
                &mut chip,
            )?);
            buttons.push(ButtonInput::new(
                Button::Select,
                pins.key_press_pin,
                &mut chip,
            )?);
            buttons.push(ButtonInput::new(Button::Key1, pins.key1_pin, &mut chip)?);
            buttons.push(ButtonInput::new(Button::Key2, pins.key2_pin, &mut chip)?);
            buttons.push(ButtonInput::new(Button::Key3, pins.key3_pin, &mut chip)?);

            if buttons.len() != BUTTON_COUNT {
                return Err(anyhow!(
                    "button map invariant failed: expected {} controls, initialized {}",
                    BUTTON_COUNT,
                    buttons.len()
                ));
            }

            for button in &buttons {
                button
                    .is_pressed()
                    .with_context(|| format!("button {:?} GPIO line not readable", button.kind))?;
            }

            let debounce = Duration::from_millis(120);
            Ok(Self {
                buttons,
                virtual_rx: spawn_virtual_input(),
                pending_virtual: None,
                __debounce: debounce,
                last_press: Instant::now() - debounce,
            })
        }

        pub fn wait_for_press(&mut self) -> Result<Button> {
            loop {
                if let Some(kind) = self.poll()? {
                    self.wait_for_release(kind)?;
                    return Ok(kind);
                }
                thread::sleep(Duration::from_millis(20));
            }
        }

        /// Non-blocking button check - returns immediately with Some(Button) if pressed, None otherwise
        pub fn try_read(&mut self) -> Result<Option<Button>> {
            if let Some(kind) = self.poll()? {
                self.wait_for_release(kind)?;
                return Ok(Some(kind));
            }
            Ok(None)
        }

        /// Button check with timeout - polls for button press until timeout expires
        pub fn try_read_timeout(&mut self, timeout: Duration) -> Result<Option<Button>> {
            let start = Instant::now();
            while start.elapsed() < timeout {
                if let Some(kind) = self.poll()? {
                    self.wait_for_release(kind)?;
                    return Ok(Some(kind));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None)
        }

        fn wait_for_release(&mut self, kind: Button) -> Result<()> {
            let button = self
                .buttons
                .iter()
                .find(|btn| btn.kind == kind)
                .ok_or_else(|| anyhow!("button {kind:?} missing"))?;
            loop {
                if !button.is_pressed()? {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn poll(&mut self) -> Result<Option<Button>> {
            if let Some(kind) = self.next_virtual_button() {
                if self.last_press.elapsed() < self.__debounce {
                    self.pending_virtual = Some(kind);
                    return Ok(None);
                }
                self.last_press = Instant::now();
                return Ok(Some(kind));
            }
            for btn in &self.buttons {
                if btn.is_pressed()? {
                    if self.last_press.elapsed() < self.__debounce {
                        return Ok(None);
                    }
                    self.last_press = Instant::now();
                    return Ok(Some(btn.kind));
                }
            }
            Ok(None)
        }

        fn next_virtual_button(&mut self) -> Option<Button> {
            if let Some(kind) = self.pending_virtual.take() {
                return Some(kind);
            }
            let rx = self.virtual_rx.as_ref()?;
            rx.try_recv().ok()
        }
    }

    fn spawn_virtual_input() -> Option<Receiver<Button>> {
        let path = env::var("RUSTYJACK_UI_VINPUT").ok()?;
        let debug = env::var("RUSTYJACK_UI_VINPUT_DEBUG").is_ok();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let fifo = PathBuf::from(path);
            loop {
                let file = match OpenOptions::new().read(true).open(&fifo) {
                    Ok(file) => file,
                    Err(err) => {
                        if debug {
                            eprintln!("virtual-input: failed to open {}: {}", fifo.display(), err);
                        }
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                };
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line = match line {
                        Ok(line) => line,
                        Err(err) => {
                            if debug {
                                eprintln!("virtual-input: read error: {}", err);
                            }
                            break;
                        }
                    };
                    if let Some(button) = parse_virtual_button(&line) {
                        if tx.send(button).is_err() {
                            return;
                        }
                    } else if debug {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            eprintln!("virtual-input: unknown token '{}'", trimmed);
                        }
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        });

        Some(rx)
    }

    fn parse_virtual_button(line: &str) -> Option<Button> {
        let token = line.trim();
        if token.is_empty() || token.starts_with('#') {
            return None;
        }
        let token = token.to_ascii_lowercase();
        match token.as_str() {
            "up" | "u" => Some(Button::Up),
            "down" | "d" => Some(Button::Down),
            "left" | "l" | "back" => Some(Button::Left),
            "right" | "r" => Some(Button::Right),
            "select" | "ok" | "enter" | "press" => Some(Button::Select),
            "key1" | "k1" | "refresh" => Some(Button::Key1),
            "key2" | "k2" | "cancel" => Some(Button::Key2),
            "key3" | "k3" | "reboot" => Some(Button::Key3),
            _ => None,
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    pub struct ButtonPad;

    impl ButtonPad {
        pub fn new(_: &PinConfig) -> Result<Self> {
            Ok(Self)
        }

        pub fn wait_for_press(&mut self) -> Result<Button> {
            thread::sleep(Duration::from_millis(250));
            Ok(Button::Select)
        }

        pub fn try_read(&mut self) -> Result<Option<Button>> {
            Ok(None)
        }

        pub fn try_read_timeout(&mut self, timeout: Duration) -> Result<Option<Button>> {
            thread::sleep(timeout);
            Ok(None)
        }
    }
}

pub use platform::ButtonPad;
