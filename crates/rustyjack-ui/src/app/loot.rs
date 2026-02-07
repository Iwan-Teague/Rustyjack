use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use rustyjack_commands::{Commands, LootCommand, LootReadArgs};
use serde_json::Value;

use crate::{menu::LootSection, util::shorten_for_display};

use super::state::{App, ButtonAction};

impl App {
    pub(crate) fn show_loot(&mut self, section: LootSection) -> Result<()> {
        let (bases, menu_title, empty_msg) = match section {
            LootSection::Wireless => (
                vec![self.root.join("loot/Wireless")],
                "Wireless Targets",
                "No captures yet",
            ),
            LootSection::Ethernet => (
                vec![self.root.join("loot/Ethernet")],
                "Ethernet Targets",
                "No captures yet",
            ),
            LootSection::Reports => (
                vec![self.root.join("loot").join("reports")],
                "Reports",
                "No reports yet",
            ),
        };

        if !bases.iter().any(|b| b.exists()) {
            return self.show_message("Loot", [empty_msg]);
        }

        // Get list of network folders (or special folders like probe_sniff, karma)
        let mut networks: Vec<(String, PathBuf)> = Vec::new();
        let mut seen_networks: HashSet<String> = HashSet::new();

        for base in &bases {
            if !base.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if seen_networks.insert(name.to_string()) {
                                networks.push((name.to_string(), path));
                            }
                        }
                    }
                }
            }
        }

        // Also check for any loose files directly in loot_base
        let mut loose_files: Vec<PathBuf> = Vec::new();
        let mut seen_files: HashSet<String> = HashSet::new();
        for base in &bases {
            if !base.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if seen_files.insert(name.to_string()) {
                                loose_files.push(path);
                            }
                        }
                    }
                }
            }
        }

        if networks.is_empty() && loose_files.is_empty() {
            return self.show_message("Loot", [empty_msg]);
        }

        // Sort networks alphabetically
        networks.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        // Build menu - networks first, then loose files
        let mut labels: Vec<String> = networks
            .iter()
            .map(|(name, _)| format!("[{}]", name))
            .collect();
        let mut paths: Vec<PathBuf> = networks.iter().map(|(_, p)| p.clone()).collect();

        // Add loose files at the end
        for file in &loose_files {
            if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
                labels.push(name.to_string());
                paths.push(file.clone());
            }
        }

        loop {
            let Some(index) = self.choose_from_menu(menu_title, &labels)? else {
                return Ok(());
            };

            let selected_path = &paths[index];

            if selected_path.is_dir() {
                // Show files in this network folder
                self.show_network_loot(selected_path)?;
            } else {
                // View the file directly
                self.view_loot_file(&selected_path.to_string_lossy())?;
            }
        }
    }

    /// Show loot files for a specific network/target
    pub(crate) fn show_network_loot(&mut self, network_dir: &Path) -> Result<()> {
        let network_name = network_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown");

        self.browse_loot_dir(network_name, network_dir)
    }

    /// Generic directory browser for loot (shows dirs first, then files)
    pub(crate) fn browse_loot_dir(&mut self, title: &str, dir: &Path) -> Result<()> {
        let mut dirs: Vec<(String, PathBuf)> = Vec::new();
        let mut files: Vec<(String, PathBuf)> = Vec::new();

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                if path.is_dir() {
                    dirs.push((name, path));
                } else if path.is_file() {
                    files.push((name, path));
                }
            }
        }

        if dirs.is_empty() && files.is_empty() {
            return self.show_message(title, ["No files in this target"]);
        }

        dirs.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
        files.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        let mut labels = Vec::new();
        let mut paths = Vec::new();
        let mut is_dir_flags = Vec::new();

        for (name, path) in &dirs {
            labels.push(format!("{}/", name));
            paths.push(path.clone());
            is_dir_flags.push(true);
        }
        for (name, path) in &files {
            labels.push(name.clone());
            paths.push(path.clone());
            is_dir_flags.push(false);
        }

        loop {
            let Some(index) = self.choose_from_menu(title, &labels)? else {
                return Ok(());
            };

            let path = &paths[index];
            if is_dir_flags[index] {
                let next_title = format!(
                    "{}/{}",
                    title,
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("")
                );
                self.browse_loot_dir(&next_title, path)?;
            } else {
                self.view_loot_file(&path.to_string_lossy())?;
            }
        }
    }

    pub(crate) fn view_loot_file(&mut self, path: &str) -> Result<()> {
        let file_path = PathBuf::from(path);

        // Check if file is encrypted
        if path.ends_with(".enc") {
            let opts = vec!["Decrypt in RAM".to_string(), "Cancel".to_string()];

            let choice = self.choose_from_list("Encrypted File", &opts)?;
            if choice != Some(0) {
                return Ok(());
            }

            // Decrypt in RAM
            let decrypted_bytes = match rustyjack_encryption::decrypt_file(&file_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return self.show_message(
                        "Decryption Failed",
                        [
                            "Could not decrypt file",
                            &shorten_for_display(&e.to_string(), 90),
                        ],
                    );
                }
            };

            // Convert to string
            let content = match String::from_utf8(decrypted_bytes) {
                Ok(s) => s,
                Err(_) => {
                    return self.show_message(
                        "View Error",
                        ["File contains binary data", "Cannot display as text"],
                    );
                }
            };

            // Split into lines with limit
            let max_lines = 5000;
            let mut lines = Vec::new();
            let mut truncated = false;

            for (idx, line) in content.lines().enumerate() {
                if idx >= max_lines {
                    truncated = true;
                    break;
                }
                lines.push(line.to_string());
            }

            if lines.is_empty() {
                return self.show_message("Loot", ["File is empty"]);
            }

            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string();

            // Display decrypted content (content will be dropped after this returns)
            return self.scrollable_text_viewer(&filename, &lines, truncated);
        }

        // For non-encrypted files, use the normal read path
        let read_args = LootReadArgs {
            path: file_path.clone(),
            max_lines: 5000,
        };
        let (_, data) = self
            .core
            .dispatch(Commands::Loot(LootCommand::Read(read_args)))?;

        let lines = data
            .get("lines")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let truncated = data
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if lines.is_empty() {
            return self.show_message("Loot", ["File is empty"]);
        }

        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        // Scrollable file viewer
        self.scrollable_text_viewer(&filename, &lines, truncated)
    }

    pub(crate) fn scrollable_text_viewer(
        &mut self,
        title: &str,
        lines: &[String],
        truncated: bool,
    ) -> Result<()> {
        let lines_per_page = self.display.layout().file_view_visible_lines.max(1);
        let max_title_chars = self.display.title_chars_per_line().max(1);

        let total_lines = lines.len();
        let mut line_offset = 0;
        let mut needs_redraw = true; // Track when redraw is needed

        // Clamp title without animation to avoid constant redraws
        let display_title = if title.chars().count() > max_title_chars {
            let keep = max_title_chars.saturating_sub(3);
            let head: String = title.chars().take(keep).collect();
            format!("{head}...")
        } else {
            title.to_string()
        };

        loop {
            if needs_redraw {
                let overlay = self.stats.snapshot();
                let end = (line_offset + lines_per_page).min(total_lines);
                let visible_lines: Vec<String> = lines[line_offset..end].to_vec();

                self.display.draw_file_viewer(
                    &display_title,
                    0,
                    &visible_lines,
                    line_offset,
                    total_lines,
                    truncated,
                    &overlay,
                )?;
                needs_redraw = false;
            }

            // Non-blocking button check with short timeout
            if let Some(button) = self.buttons.try_read_timeout(Duration::from_millis(100))? {
                match self.map_button(button) {
                    ButtonAction::Down => {
                        if line_offset + lines_per_page < total_lines {
                            line_offset += 1;
                            needs_redraw = true;
                        }
                    }
                    ButtonAction::Up => {
                        if line_offset > 0 {
                            line_offset = line_offset.saturating_sub(1);
                            needs_redraw = true;
                        }
                    }
                    ButtonAction::Select => {
                        // Page down
                        if line_offset + lines_per_page < total_lines {
                            line_offset = (line_offset + lines_per_page)
                                .min(total_lines.saturating_sub(lines_per_page));
                            needs_redraw = true;
                        }
                    }
                    ButtonAction::Back => {
                        return Ok(());
                    }
                    ButtonAction::Cancel => {}
                    ButtonAction::Refresh => {
                        needs_redraw = true;
                    }
                    ButtonAction::Reboot => {
                        self.confirm_reboot()?;
                        needs_redraw = true;
                    }
                }
            }
        }
    }
}
