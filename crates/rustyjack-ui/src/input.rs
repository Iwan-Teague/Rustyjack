use std::{
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;

use crate::config::PinConfig;

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
        __debounce: Duration,
        last_press: Instant,
    }

    impl ButtonPad {
        pub fn new(pins: &PinConfig) -> Result<Self> {
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

            let debounce = Duration::from_millis(120);
            Ok(Self {
                buttons,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_button_enum_completeness() {
        // Verify all 8 buttons are defined
        let buttons = vec![
            Button::Up,
            Button::Down,
            Button::Left,
            Button::Right,
            Button::Select,
            Button::Key1,
            Button::Key2,
            Button::Key3,
        ];
        assert_eq!(buttons.len(), 8, "Expected exactly 8 buttons");
    }

    #[test]
    fn test_button_equality() {
        // Verify Button implements PartialEq correctly
        assert_eq!(Button::Up, Button::Up);
        assert_ne!(Button::Up, Button::Down);
        assert_eq!(Button::Select, Button::Select);
        assert_ne!(Button::Left, Button::Right);
    }

    #[test]
    fn test_button_debug() {
        // Verify Debug trait implementation
        let button = Button::Up;
        let debug_str = format!("{:?}", button);
        assert!(debug_str.contains("Up"));
    }
}
