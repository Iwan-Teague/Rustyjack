use crate::display::wrap_text;

pub const MENU_VISIBLE_ITEMS: usize = 7;

pub fn wrap_lines(lines: &[String], max_chars: usize) -> Vec<String> {
    lines
        .iter()
        .flat_map(|line| wrap_text(line, max_chars))
        .collect()
}
