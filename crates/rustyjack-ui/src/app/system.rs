use std::{fs, path::Path, time::Duration};

use anyhow::{Context, Result};
use rustyjack_commands::{Commands, SystemCommand};
use rustyjack_ipc::JobState;
use walkdir::WalkDir;

use crate::util::shorten_for_display;

use super::state::{App, CancelDecision};

impl App {
    pub(crate) fn restart_system(&mut self) -> Result<()> {
        match self.core.system_reboot() {
            Ok(_) => Ok(()),
            Err(err) => {
                let msg = shorten_for_display(&err.to_string(), 90);
                self.show_message("Reboot Failed", [msg])
            }
        }
    }

    pub(crate) fn system_update(&mut self) -> Result<()> {
        let options = vec![
            "Update from USB bundle".to_string(),
            "Use URL from USB file".to_string(),
            "Cancel".to_string(),
        ];

        let choice = self.choose_from_list("System Update", &options)?;
        let Some(choice) = choice else {
            return Ok(());
        };

        let url = match choice {
            0 => {
                let Some(path) = self.browse_usb_for_file("Update Bundle", Some(&["zst"]))? else {
                    return Ok(());
                };
                format!("file://{}", path.display())
            }
            1 => {
                let Some(path) = self.browse_usb_for_file("Update URL", Some(&["txt", "url"]))?
                else {
                    return Ok(());
                };
                let contents = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let url = contents.lines().next().unwrap_or("").trim().to_string();
                if url.is_empty() {
                    self.show_message("Update URL", ["URL file is empty"])?;
                    return Ok(());
                }
                url
            }
            _ => return Ok(()),
        };

        let confirm_lines = vec![
            format!("Source: {}", shorten_for_display(&url, 18)),
            "Proceed with update?".to_string(),
        ];
        if !self.confirm_yes_no_bool("Apply update?", &confirm_lines)? {
            self.go_home()?;
            return Ok(());
        }

        let job_id = match self.core.start_system_update(&url) {
            Ok(job_id) => job_id,
            Err(err) => {
                let msg = shorten_for_display(&err.to_string(), 90);
                self.show_message("Update Error", [msg])?;
                return Ok(());
            }
        };

        self.run_update_job(job_id)
    }

    pub(crate) fn run_update_job(&mut self, job_id: u64) -> Result<()> {
        let title = "System Update";
        let mut last_msg: Option<String> = None;
        let mut last_percent: Option<u8> = None;

        loop {
            let status = match self.core.job_status(job_id) {
                Ok(status) => status,
                Err(err) => {
                    let msg = shorten_for_display(&err.to_string(), 90);
                    self.show_message("Update Error", [msg])?;
                    return Ok(());
                }
            };

            let (percent, message) = if let Some(progress) = status.progress.clone() {
                (
                    progress.percent,
                    format!("{}% {}", progress.percent, progress.message),
                )
            } else {
                (0, "Queued...".to_string())
            };

            if last_msg.as_ref() != Some(&message) || last_percent != Some(percent) {
                let overlay = self.stats.snapshot();
                self.display
                    .draw_progress_dialog(title, &message, percent as f32, &overlay)?;
                last_msg = Some(message);
                last_percent = Some(percent);
            }

            match status.state {
                JobState::Queued | JobState::Running => {
                    if matches!(self.check_cancel_request("Update")?, CancelDecision::Cancel) {
                        if let Err(err) = self.core.cancel_job(job_id) {
                            self.show_error_dialog("Update cancel failed", &err)?;
                            return Ok(());
                        }
                        let cancel_start = std::time::Instant::now();
                        while cancel_start.elapsed() < Duration::from_secs(3) {
                            let st = self.core.job_status(job_id)?;
                            if matches!(
                                st.state,
                                JobState::Cancelled | JobState::Failed | JobState::Completed
                            ) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        self.show_message("Update Cancelled", ["Update was cancelled"])?;
                        self.go_home()?;
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                JobState::Completed => {
                    self.show_message(
                        "Update Applied",
                        ["Update complete", "Daemon restart may take a moment"],
                    )?;
                    self.go_home()?;
                    return Ok(());
                }
                JobState::Cancelled => {
                    self.show_message("Update Cancelled", ["Update was cancelled"])?;
                    self.go_home()?;
                    return Ok(());
                }
                JobState::Failed => {
                    let mut lines = vec!["Update failed".to_string()];
                    if let Some(err) = status.error {
                        lines.push(err.message);
                        if let Some(detail) = err.detail {
                            lines.push(shorten_for_display(&detail, 120));
                        }
                    }
                    self.show_message("Update Error", lines.iter().map(|s| s.as_str()))?;
                    self.go_home()?;
                    return Ok(());
                }
            }
        }
    }

    /// Attempt to wipe free memory then power off the device.
    /// This is best-effort: it overwrites available RAM pages before shutdown.
    pub(crate) fn secure_shutdown(&mut self) -> Result<()> {
        // Explain what will happen
        self.show_message(
            "Secure Shutdown",
            [
                "Attempt to overwrite free RAM",
                "and power off the device.",
                "",
                "Use on the Pi only. This",
                "will stop all services.",
            ],
        )?;

        let options = vec!["Wipe RAM + Power Off".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Confirm", &options)?;
        if choice != Some(0) {
            return Ok(());
        }

        // Best-effort memory wipe
        self.show_progress(
            "Secure Shutdown",
            ["Wiping memory...", "This may take a few seconds"],
        )?;
        if let Err(err) = self.best_effort_ram_wipe() {
            tracing::warn!("RAM wipe failed: {:#}", err);
        }

        // Power off
        self.show_progress("Secure Shutdown", ["Powering off now...", ""])?;
        if let Err(err) = self.core.system_shutdown() {
            let msg = shorten_for_display(&err.to_string(), 90);
            self.show_message("Shutdown Failed", [msg])?;
        }

        Ok(())
    }

    /// Overwrite available RAM to reduce residual data.
    pub(crate) fn best_effort_ram_wipe(&self) -> Result<()> {
        // Parse MemAvailable from /proc/meminfo
        let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let available_kb = meminfo
            .lines()
            .find(|l| l.starts_with("MemAvailable:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .unwrap_or(64 * 1024); // fall back to 64MB if parsing fails

        // Use ~95% of available RAM; keep a small buffer to avoid the OOM killer
        let target_bytes = available_kb.saturating_mul(1024) * 95 / 100;
        let chunk_size: usize = 1 * 1024 * 1024; // 1MB chunks for tighter coverage

        let mut allocated = 0u64;
        let mut buffers: Vec<Vec<u8>> = Vec::new();

        while allocated < target_bytes {
            let remaining = target_bytes - allocated;
            let size = std::cmp::min(chunk_size as u64, remaining) as usize;
            if size == 0 {
                break;
            }

            // Allocate and touch the memory so pages are actually written
            let mut buf = Vec::with_capacity(size);
            buf.resize(size, 0u8);
            for chunk in buf.chunks_mut(4096) {
                chunk[0] = 0;
            }
            allocated += size as u64;
            buffers.push(buf);
        }

        // Drop buffers to release memory before shutdown
        drop(buffers);
        Ok(())
    }
    pub(crate) fn complete_purge(&mut self) -> Result<()> {
        self.show_message(
            "Complete Purge",
            [
                "Erase Rustyjack completely.",
                "Deletes loot/logs, binaries,",
                "source tree, service, udev.",
                "Journal logs are vacuumed.",
                "",
                "Cannot be undone.",
            ],
        )?;

        let confirm = self.choose_from_list(
            "Erase Rustyjack?",
            &["Delete everything".to_string(), "Cancel".to_string()],
        )?;
        if confirm != Some(0) {
            return Ok(());
        }

        let final_confirm = self.choose_from_list(
            "Final Confirm",
            &["Yes - wipe Rustyjack".to_string(), "Abort".to_string()],
        )?;
        if final_confirm != Some(0) {
            return Ok(());
        }

        self.show_progress("Complete Purge", ["Removing Rustyjack...", "Please wait"])?;
        let (msg, data) = match self.core.dispatch(Commands::System(SystemCommand::Purge)) {
            Ok(result) => result,
            Err(err) => {
                return self.show_message(
                    "Complete Purge",
                    ["Purge failed", &shorten_for_display(&err.to_string(), 90)],
                );
            }
        };

        if let Some(lines) = crate::ops::shared::preflight::preflight_only_summary(&data) {
            return self.show_message("Complete Purge", lines.iter().map(|s| s.as_str()));
        }

        let removed = data.get("removed").and_then(|v| v.as_u64()).unwrap_or(0);
        let service_disabled = data
            .get("service_disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let errors = data.get("errors").and_then(|v| v.as_array());

        let mut lines = vec![
            format!("Removed {} item(s)", removed),
            if service_disabled {
                "Service disabled".to_string()
            } else {
                "Service disable failed".to_string()
            },
            "Logs cleared".to_string(),
            "Reboot recommended".to_string(),
        ];

        if let Some(errors) = errors {
            if !errors.is_empty() {
                lines.push("Errors:".to_string());
                for err in errors.iter().take(3) {
                    if let Some(text) = err.as_str() {
                        lines.push(shorten_for_display(text, 18));
                    }
                }
                if errors.len() > 3 {
                    lines.push(format!("+{} more", errors.len() - 3));
                }
            } else {
                lines.push("No errors reported".to_string());
            }
        } else {
            lines.push("No errors reported".to_string());
        }
        lines.push(msg);
        lines.push("UI exiting now".to_string());

        self.show_message("Complete Purge", lines)?;
        std::process::exit(0);
    }

    pub(crate) fn purge_logs(&mut self) -> Result<()> {
        let root = self.root.clone();
        let bases = vec![root.join("loot")];

        // Collect candidates first for confirmation
        let mut candidates = Vec::new();
        for base in &bases {
            if !base.exists() {
                continue;
            }
            for entry in WalkDir::new(base).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && self.is_log_file(path) {
                    candidates.push(path.to_path_buf());
                }
            }
        }

        if candidates.is_empty() {
            return self.show_message("Purge Logs", ["No log files found", "Nothing to delete"]);
        }

        let confirm = self.choose_from_list(
            "Delete Logs?",
            &[
                format!("Delete {} log file(s)", candidates.len()),
                "Cancel".to_string(),
            ],
        )?;
        if confirm != Some(0) {
            return Ok(());
        }

        let mut deleted = 0usize;
        for path in candidates {
            if fs::remove_file(&path).is_ok() {
                deleted += 1;
            }
        }

        self.show_message(
            "Purge Logs",
            [
                format!("Removed {} log file(s)", deleted),
                "Captures/results kept".to_string(),
            ],
        )
    }

    pub(crate) fn is_log_file(&self, path: &Path) -> bool {
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_ascii_lowercase(),
            None => return false,
        };

        // Strip a trailing .enc when present so encrypted logs are matched by their base name.
        let normalized = name.strip_suffix(".enc").unwrap_or(&name);
        let in_logs_dir = path
            .ancestors()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("logs"));

        let looks_like_log = Self::is_log_basename(normalized);
        looks_like_log || (in_logs_dir && Self::is_log_basename(&name))
    }

    pub(crate) fn is_log_basename(name: &str) -> bool {
        if name.ends_with(".log") || name.contains(".log.") {
            return true;
        }

        if name.starts_with("log.") || name.starts_with("log_") || name.starts_with("log-") {
            return true;
        }

        let without_compression = name
            .strip_suffix(".gz")
            .or_else(|| name.strip_suffix(".xz"))
            .or_else(|| name.strip_suffix(".bz2"))
            .unwrap_or(name);

        without_compression.ends_with("_log")
            || without_compression.ends_with("-log")
            || without_compression.ends_with(".log")
    }
}
