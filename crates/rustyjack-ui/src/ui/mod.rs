pub mod input;
pub mod layout;
pub mod screens;

use std::time::Duration;

use anyhow::Result;

use crate::{
    config::GuiConfig,
    core::CoreBridge,
    display::{Display, StatusOverlay},
    input::ButtonPad,
    stats::StatsSampler,
};
use std::path::Path;

use self::input::{map_button, UiInput};

pub struct UiContext<'a> {
    pub display: &'a mut Display,
    pub buttons: &'a mut ButtonPad,
    pub stats: &'a StatsSampler,
    pub core: &'a mut CoreBridge,
    pub config: &'a mut GuiConfig,
    pub root: &'a Path,
}

impl<'a> UiContext<'a> {
    pub fn new(
        display: &'a mut Display,
        buttons: &'a mut ButtonPad,
        stats: &'a StatsSampler,
        core: &'a mut CoreBridge,
        config: &'a mut GuiConfig,
        root: &'a Path,
    ) -> Self {
        Self {
            display,
            buttons,
            stats,
            core,
            config,
            root,
        }
    }

    pub fn overlay(&self) -> StatusOverlay {
        self.stats.snapshot()
    }

    pub fn wait_input(&mut self) -> Result<UiInput> {
        let button = self.buttons.wait_for_press()?;
        Ok(map_button(button))
    }

    pub fn try_read_input(&mut self) -> Result<Option<UiInput>> {
        let button = self.buttons.try_read()?;
        Ok(button.map(map_button))
    }

    #[allow(dead_code)]
    pub fn try_read_input_timeout(&mut self, timeout: Duration) -> Result<Option<UiInput>> {
        let button = self.buttons.try_read_timeout(timeout)?;
        Ok(button.map(map_button))
    }

    pub fn confirm_reboot(&mut self) -> Result<()> {
        crate::ui::screens::reboot::confirm(self)
    }
}
