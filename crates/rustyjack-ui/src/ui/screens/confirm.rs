use anyhow::Result;

use crate::ui::{input::UiInput, screens::cancel_confirm, UiContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmChoice {
    Yes,
    No,
    Back,
    Cancel,
}

pub fn show(ctx: &mut UiContext, title: &str, body: &[String]) -> Result<ConfirmChoice> {
    let mut idx = 0usize;

    loop {
        let overlay = ctx.overlay();
        let mut content = Vec::with_capacity(body.len() + 4);
        content.push(title.to_string());
        content.extend(body.iter().cloned());
        content.push(String::new());
        content.push(format!("{}Yes", if idx == 0 { "> " } else { "  " }));
        content.push(format!("{}No", if idx == 1 { "> " } else { "  " }));
        ctx.display.draw_dialog(&content, &overlay)?;

        let input = ctx.wait_input()?;
        match input {
            UiInput::Up | UiInput::Down => idx ^= 1,
            UiInput::Select => {
                return Ok(if idx == 0 {
                    ConfirmChoice::Yes
                } else {
                    ConfirmChoice::No
                });
            }
            UiInput::LeftBack => return Ok(ConfirmChoice::Back),
            UiInput::CancelKey2 => {
                if cancel_confirm::show(ctx, title)? {
                    return Ok(ConfirmChoice::Cancel);
                }
            }
            UiInput::Refresh => {}
            UiInput::RebootKey3 => {
                ctx.confirm_reboot()?;
            }
        }
    }
}
