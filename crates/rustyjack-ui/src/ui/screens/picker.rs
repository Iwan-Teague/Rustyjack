use anyhow::Result;

use crate::ui::{input::UiInput, screens::cancel_confirm, UiContext};

pub enum PickerChoice {
    Selected(usize),
    Back,
    Cancel,
}

pub fn choose(
    ctx: &mut UiContext,
    title: &str,
    items: &[String],
    cancel_label: &str,
) -> Result<PickerChoice> {
    if items.is_empty() {
        return Ok(PickerChoice::Back);
    }

    let mut index: usize = 0;
    let mut offset: usize = 0;

    loop {
        let total = items.len();
        let visible_items = ctx.display.menu_visible_items();
        if index < offset {
            offset = index;
        } else if index >= offset + visible_items {
            offset = index.saturating_sub(visible_items.saturating_sub(1));
        }

        let overlay = ctx.overlay();
        let slice: Vec<String> = items
            .iter()
            .skip(offset)
            .take(visible_items)
            .cloned()
            .collect();
        let displayed_selected = index.saturating_sub(offset);
        ctx.display
            .draw_menu(title, &slice, displayed_selected, &overlay)?;

        let input = ctx.wait_input()?;
        match input {
            UiInput::Up => {
                if index == 0 {
                    index = total - 1;
                } else {
                    index -= 1;
                }
            }
            UiInput::Down => index = (index + 1) % total,
            UiInput::Select => return Ok(PickerChoice::Selected(index)),
            UiInput::LeftBack => return Ok(PickerChoice::Back),
            UiInput::CancelKey2 => {
                if cancel_confirm::show(ctx, cancel_label)? {
                    return Ok(PickerChoice::Cancel);
                }
            }
            UiInput::Refresh => {}
            UiInput::RebootKey3 => {
                ctx.confirm_reboot()?;
            }
        }
    }
}
