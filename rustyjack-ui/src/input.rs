use std::{thread, time::Duration};

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
    use anyhow::{Context, anyhow};
    use rppal::gpio::{Gpio, InputPin};

    struct ButtonInput {
        kind: Button,
        pin: InputPin,
    }

    impl ButtonInput {
        fn new(kind: Button, pin_num: u32, gpio: &Gpio) -> Result<Self> {
            let pin = gpio
                .get(pin_num as u8)
                .with_context(|| format!("requesting GPIO line {}", pin_num))?
                .into_input_pullup();
            Ok(Self { kind, pin })
        }

        fn is_pressed(&self) -> Result<bool> {
            Ok(self.pin.is_low())
        }
    }

    pub struct ButtonPad {
        buttons: Vec<ButtonInput>,
        debounce: Duration,
    }

    impl ButtonPad {
        pub fn new(pins: &PinConfig) -> Result<Self> {
            let gpio = Gpio::new()?;
            let mut buttons = Vec::new();
            buttons.push(ButtonInput::new(Button::Up, pins.key_up_pin, &gpio)?);
            buttons.push(ButtonInput::new(
                Button::Down,
                pins.key_down_pin,
                &gpio,
            )?);
            buttons.push(ButtonInput::new(
                Button::Left,
                pins.key_left_pin,
                &gpio,
            )?);
            buttons.push(ButtonInput::new(
                Button::Right,
                pins.key_right_pin,
                &gpio,
            )?);
            buttons.push(ButtonInput::new(
                Button::Select,
                pins.key_press_pin,
                &gpio,
            )?);
            buttons.push(ButtonInput::new(Button::Key1, pins.key1_pin, &gpio)?);
            buttons.push(ButtonInput::new(Button::Key2, pins.key2_pin, &gpio)?);
            buttons.push(ButtonInput::new(Button::Key3, pins.key3_pin, &gpio)?);

            Ok(Self {
                buttons,
                debounce: Duration::from_millis(120),
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

        fn poll(&self) -> Result<Option<Button>> {
            for btn in &self.buttons {
                if btn.is_pressed()? {
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
    }
}

pub use platform::ButtonPad;
