pub mod cancel_confirm;
pub mod confirm;
pub mod error;
pub mod picker;
pub mod progress;
pub mod reboot;
pub mod result;

use anyhow::Result;

use crate::display::wrap_text;
use crate::ui::{input::UiInput, UiContext};

pub(crate) fn show_scrollable_dialog(
    ctx: &mut UiContext,
    title: &str,
    body: &[String],
) -> Result<()> {
    let overlay = ctx.overlay();
    let content: Vec<String> = std::iter::once(title.to_string())
        .chain(body.iter().cloned())
        .collect();

    let wrapped_body: Vec<String> = body
        .iter()
        .flat_map(|line| wrap_text(line, ctx.display.chars_per_line()))
        .collect();
    let total_lines = wrapped_body.len();
    let max_offset =
        crate::ui::layout::max_scroll_offset(total_lines, ctx.display.dialog_visible_lines());

    let mut offset = 0usize;
    let mut needs_redraw = true;

    loop {
        if needs_redraw {
            ctx.display
                .draw_dialog_with_offset(&content, offset, &overlay)?;
            needs_redraw = false;
        }

        let input = ctx.wait_input()?;
        match input {
            UiInput::Up => {
                if offset > 0 {
                    offset -= 1;
                    needs_redraw = true;
                }
            }
            UiInput::Down => {
                if offset < max_offset {
                    offset += 1;
                    needs_redraw = true;
                }
            }
            UiInput::Select | UiInput::LeftBack => break,
            UiInput::Refresh => {
                needs_redraw = true;
            }
            UiInput::CancelKey2 => {}
            UiInput::RebootKey3 => {
                ctx.confirm_reboot()?;
                needs_redraw = true;
            }
        }
    }

    Ok(())
}
