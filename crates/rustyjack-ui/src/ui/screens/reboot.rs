use anyhow::Result;

use crate::ui::{input::UiInput, screens::error, UiContext};

pub fn confirm(ctx: &mut UiContext) -> Result<()> {
    let content = vec![
        "Confirm reboot".to_string(),
        "SELECT = Reboot".to_string(),
        "LEFT/KEY2 = Cancel".to_string(),
    ];

    loop {
        let overlay = ctx.overlay();
        ctx.display.draw_dialog(&content, &overlay)?;

        match ctx.wait_input()? {
            UiInput::Select => {
                if let Err(err) = ctx.core.system_reboot() {
                    error::show(ctx, "Reboot Failed", &err)?;
                } else {
                    std::process::exit(0);
                }
            }
            UiInput::LeftBack | UiInput::CancelKey2 => return Ok(()),
            UiInput::Refresh => {}
            UiInput::Up | UiInput::Down | UiInput::RebootKey3 => {}
        }
    }
}
