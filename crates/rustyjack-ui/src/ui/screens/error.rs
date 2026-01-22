use anyhow::{Error, Result};

use crate::ui::{screens::show_scrollable_dialog, UiContext};

pub fn show(ctx: &mut UiContext, title: &str, err: &Error) -> Result<()> {
    let mut lines = Vec::new();
    for (idx, cause) in err.chain().enumerate() {
        if idx == 0 {
            lines.push(format!("Error: {}", cause));
        } else {
            lines.push(format!("Cause: {}", cause));
        }
    }
    lines.push("Press SELECT to continue".to_string());
    show_scrollable_dialog(ctx, title, &lines)
}
