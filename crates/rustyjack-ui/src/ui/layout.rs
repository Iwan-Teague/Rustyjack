#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiLayoutMetrics {
    pub width_px: u32,
    pub height_px: u32,
    pub safe_padding_px: u32,
    pub char_width_px: u32,
    pub line_height_px: u32,
    pub header_height: u32,
    pub content_top: u32,
    pub content_bottom: u32,
    pub footer_height: u32,
    pub footer_y: u32,
    pub menu_row_height: u32,
    pub menu_visible_items: usize,
    pub dialog_visible_lines: usize,
    pub file_view_visible_lines: usize,
    pub chars_per_line: usize,
    pub title_chars_per_line: usize,
    pub toolbar_temp_width_px: u32,
}

impl UiLayoutMetrics {
    pub fn from_dimensions(width_px: u32, height_px: u32, safe_padding_px: u32) -> Self {
        let char_width_px = 6;
        let line_height_px = 10;
        let toolbar_temp_width_px = 26;

        let safe_padding_px = safe_padding_px.min(width_px.saturating_sub(1) / 2);
        let header_height = 14u32.min(height_px.max(12));
        let footer_height = line_height_px + 2;
        let content_top = header_height
            .saturating_add(2)
            .min(height_px.saturating_sub(1));
        let footer_y = height_px.saturating_sub(footer_height);
        let content_bottom = footer_y.saturating_sub(2);
        let content_height = content_bottom
            .saturating_sub(content_top)
            .saturating_add(1)
            .max(line_height_px);

        let content_width = width_px.saturating_sub(safe_padding_px.saturating_mul(2));
        let chars_per_line = chars_that_fit(content_width, char_width_px).max(1);
        let title_width = content_width.saturating_sub(toolbar_temp_width_px);
        let title_chars_per_line = chars_that_fit(title_width, char_width_px).max(1);
        let menu_row_height = line_height_px + 2;
        let menu_visible_items = (content_height / menu_row_height).max(1) as usize;
        let dialog_visible_lines = (content_height / line_height_px).max(1) as usize;
        let file_view_visible_lines = (content_height / line_height_px).max(1) as usize;

        Self {
            width_px,
            height_px,
            safe_padding_px,
            char_width_px,
            line_height_px,
            header_height,
            content_top,
            content_bottom,
            footer_height,
            footer_y,
            menu_row_height,
            menu_visible_items,
            dialog_visible_lines,
            file_view_visible_lines,
            chars_per_line,
            title_chars_per_line,
            toolbar_temp_width_px,
        }
    }

    pub fn content_width(&self) -> u32 {
        self.width_px
            .saturating_sub(self.safe_padding_px.saturating_mul(2))
    }

    pub fn content_height(&self) -> u32 {
        self.content_bottom
            .saturating_sub(self.content_top)
            .saturating_add(1)
    }
}

pub fn chars_that_fit(width_px: u32, char_width_px: u32) -> usize {
    if char_width_px == 0 {
        return 1;
    }
    (width_px / char_width_px).max(1) as usize
}

pub fn ellipsize(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    if max_chars <= 3 {
        return text.chars().take(max_chars).collect();
    }
    let keep = max_chars - 3;
    let head: String = text.chars().take(keep).collect();
    format!("{head}...")
}

pub fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    if max_chars == 0 {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    for source_line in text.lines() {
        if source_line.trim().is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut current = String::new();
        for token in source_line.split_whitespace() {
            if token.chars().count() > max_chars {
                if !current.is_empty() {
                    lines.push(current);
                    current = String::new();
                }
                let mut chunk = String::new();
                for ch in token.chars() {
                    chunk.push(ch);
                    if chunk.chars().count() == max_chars {
                        lines.push(std::mem::take(&mut chunk));
                    }
                }
                if !chunk.is_empty() {
                    current = chunk;
                }
                continue;
            }

            let candidate_len = if current.is_empty() {
                token.chars().count()
            } else {
                current.chars().count() + 1 + token.chars().count()
            };

            if candidate_len <= max_chars {
                if !current.is_empty() {
                    current.push(' ');
                }
                current.push_str(token);
            } else {
                lines.push(current);
                current = token.to_string();
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }

    if lines.is_empty() {
        vec![text.to_string()]
    } else {
        lines
    }
}

#[allow(dead_code)]
pub fn wrap_lines(lines: &[String], max_chars: usize) -> Vec<String> {
    lines
        .iter()
        .flat_map(|line| wrap_text(line, max_chars))
        .collect()
}

pub fn max_scroll_offset(total_lines: usize, visible_lines: usize) -> usize {
    total_lines.saturating_sub(visible_lines.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_scale_with_resolution() {
        let m128 = UiLayoutMetrics::from_dimensions(128, 128, 0);
        let m240 = UiLayoutMetrics::from_dimensions(240, 240, 0);
        let m320 = UiLayoutMetrics::from_dimensions(320, 240, 0);
        let m480 = UiLayoutMetrics::from_dimensions(480, 320, 0);

        assert!(m128.menu_visible_items >= 1);
        assert!(m240.chars_per_line > m128.chars_per_line);
        assert!(m320.chars_per_line > m128.chars_per_line);
        assert!(m480.menu_visible_items >= m128.menu_visible_items);
        assert!(m480.dialog_visible_lines >= m128.dialog_visible_lines);
    }

    #[test]
    fn wrap_handles_long_tokens() {
        let wrapped = wrap_text("superlongtokenthatcannotfit", 6);
        assert!(wrapped.iter().all(|line| line.chars().count() <= 6));
        assert!(wrapped.len() > 1);
    }

    #[test]
    fn wrap_respects_bounds_for_various_sizes() {
        for width in [128u32, 240, 320, 480] {
            let metrics = UiLayoutMetrics::from_dimensions(width, 240, 0);
            let lines = wrap_text(
                "This sentence is intentionally verbose to force wrapping behavior.",
                metrics.chars_per_line,
            );
            assert!(lines
                .iter()
                .all(|line| line.chars().count() <= metrics.chars_per_line));
        }
    }

    #[test]
    fn ellipsis_never_exceeds_bound() {
        for max in [1usize, 2, 3, 4, 8, 12] {
            let text = ellipsize("abcdefghijklmnopqrstuvwxyz", max);
            assert!(text.chars().count() <= max);
        }
    }

    #[test]
    fn pagination_offset_never_exceeds_bounds() {
        assert_eq!(max_scroll_offset(0, 1), 0);
        assert_eq!(max_scroll_offset(5, 5), 0);
        assert_eq!(max_scroll_offset(12, 7), 5);
        assert_eq!(max_scroll_offset(12, 0), 11);
    }

    #[test]
    fn footer_and_content_do_not_overlap() {
        for (w, h) in [(128u32, 128u32), (240, 240), (320, 240), (480, 320)] {
            let m = UiLayoutMetrics::from_dimensions(w, h, 0);
            assert!(m.content_bottom < m.footer_y);
            assert!(m.footer_y < m.height_px);
            assert!(m.content_top < m.height_px);
        }
    }
}
