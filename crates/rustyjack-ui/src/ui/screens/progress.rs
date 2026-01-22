use anyhow::Result;

use crate::ui::UiContext;

pub fn draw(ctx: &mut UiContext, title: &str, message: &str, percent: f32) -> Result<()> {
    let overlay = ctx.overlay();
    ctx.display
        .draw_progress_dialog(title, message, percent, &overlay)
}
