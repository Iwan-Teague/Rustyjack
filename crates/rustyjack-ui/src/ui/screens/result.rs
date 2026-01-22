use anyhow::Result;

use crate::ui::{screens::show_scrollable_dialog, UiContext};

pub fn show(ctx: &mut UiContext, title: &str, lines: &[String]) -> Result<()> {
    show_scrollable_dialog(ctx, title, lines)
}
