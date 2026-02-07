use anyhow::Result;

use super::state::{App, ButtonAction};

impl App {
    pub(crate) fn choose_from_list(
        &mut self,
        title: &str,
        items: &[String],
    ) -> Result<Option<usize>> {
        // Reuse the menu-style selector so options are visible as a list.
        self.choose_from_menu(title, items)
    }

    /// Show a paginated menu (styled like the main menu) and return index
    pub(crate) fn choose_from_menu(
        &mut self,
        title: &str,
        items: &[String],
    ) -> Result<Option<usize>> {
        if items.is_empty() {
            return Ok(None);
        }

        let mut index: usize = 0;
        let mut offset: usize = 0;

        loop {
            let total = items.len();
            let visible_items = self.display.menu_visible_items();
            // Clamp offset so selected is visible
            if index < offset {
                offset = index;
            } else if index >= offset + visible_items {
                offset = index.saturating_sub(visible_items.saturating_sub(1));
            }

            let overlay = self.stats.snapshot();

            // Build window slice of labels
            let slice: Vec<String> = items
                .iter()
                .skip(offset)
                .take(visible_items)
                .cloned()
                .collect();
            // Display menu with selected relative index
            let displayed_selected = index.saturating_sub(offset);
            self.display
                .draw_menu(title, &slice, displayed_selected, &overlay)?;

            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => {
                    if index == 0 {
                        index = total - 1;
                    } else {
                        index -= 1;
                    }
                }
                ButtonAction::Down => index = (index + 1) % total,
                ButtonAction::Select => return Ok(Some(index)),
                ButtonAction::Back => return Ok(None),
                ButtonAction::Cancel => return Ok(None),
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
                _ => {}
            }
        }
    }

    pub(crate) fn prompt_octet(&mut self, prefix: &str) -> Result<Option<u8>> {
        let mut value: i32 = 1;
        loop {
            let overlay = self.stats.snapshot();
            let content = vec![
                "Reverse shell target".to_string(),
                format!("{prefix}.{}", value.clamp(0, 255)),
                "UP/DOWN to adjust".to_string(),
                "OK to confirm".to_string(),
            ];
            self.display.draw_dialog(&content, &overlay)?;
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => value = (value + 1).min(255),
                ButtonAction::Down => value = (value - 1).max(0),
                ButtonAction::Select => return Ok(Some(value as u8)),
                ButtonAction::Back => return Ok(None),
                ButtonAction::Cancel => return Ok(None),
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
                _ => {}
            }
        }
    }
}
