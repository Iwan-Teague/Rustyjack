use anyhow::Result;

use crate::ui::{input::UiInput, UiContext};

pub fn show(ctx: &mut UiContext, label: &str) -> Result<bool> {
    let mut idx = 0usize;

    loop {
        let overlay = ctx.overlay();
        let content = vec![
            format!("Cancel {label}?"),
            "Stop the operation?".to_string(),
            "".to_string(),
            format!("{}Yes", if idx == 0 { "> " } else { "  " }),
            format!("{}No", if idx == 1 { "> " } else { "  " }),
        ];
        ctx.display.draw_dialog(&content, &overlay)?;

        let input = ctx.wait_input()?;
        match input {
            UiInput::Up | UiInput::Down => idx ^= 1,
            UiInput::Select => return Ok(idx == 0),
            UiInput::LeftBack => return Ok(false),
            UiInput::CancelKey2 => return Ok(true),
            UiInput::Refresh => {}
            UiInput::RebootKey3 => {
                ctx.confirm_reboot()?;
            }
        }
    }
}
