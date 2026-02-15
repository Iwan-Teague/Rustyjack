use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use rustyjack_ipc::{JobState, UiTestRunRequestIpc};

use crate::util::shorten_for_display;

use super::state::{App, CancelDecision};

#[derive(Clone, Copy, PartialEq, Eq)]
enum TestPreset {
    All,
    Wireless,
    Ethernet,
    InterfaceSelect,
    Custom,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SuiteId {
    Wireless,
    Ethernet,
    InterfaceSelect,
    Encryption,
    Loot,
    Mac,
    Daemon,
    DaemonDeep,
    Installers,
    Usb,
    UiLayout,
    Theme,
}

impl SuiteId {
    fn label(self) -> &'static str {
        match self {
            SuiteId::Wireless => "Wireless",
            SuiteId::Ethernet => "Ethernet",
            SuiteId::InterfaceSelect => "Interface Selection",
            SuiteId::Encryption => "Encryption",
            SuiteId::Loot => "Loot",
            SuiteId::Mac => "MAC Randomization",
            SuiteId::Daemon => "Daemon/IPC",
            SuiteId::DaemonDeep => "Daemon Deep Diagnostics",
            SuiteId::Installers => "Installers",
            SuiteId::Usb => "USB Mount",
            SuiteId::UiLayout => "UI Layout/Display",
            SuiteId::Theme => "Theme/Palette",
        }
    }

    fn flag(self) -> &'static str {
        match self {
            SuiteId::Wireless => "--wireless",
            SuiteId::Ethernet => "--ethernet",
            SuiteId::InterfaceSelect => "--iface-select",
            SuiteId::Encryption => "--encryption",
            SuiteId::Loot => "--loot",
            SuiteId::Mac => "--mac",
            SuiteId::Daemon => "--daemon",
            SuiteId::DaemonDeep => "--daemon-deep",
            SuiteId::Installers => "--installers",
            SuiteId::Usb => "--usb",
            SuiteId::UiLayout => "--ui-layout",
            SuiteId::Theme => "--theme",
        }
    }
}

impl App {
    pub(crate) fn run_ui_tests_all(&mut self) -> Result<()> {
        self.run_ui_test_flow(TestPreset::All)
    }

    pub(crate) fn run_ui_tests_wireless(&mut self) -> Result<()> {
        self.run_ui_test_flow(TestPreset::Wireless)
    }

    pub(crate) fn run_ui_tests_ethernet(&mut self) -> Result<()> {
        self.run_ui_test_flow(TestPreset::Ethernet)
    }

    pub(crate) fn run_ui_tests_interface_select(&mut self) -> Result<()> {
        self.run_ui_test_flow(TestPreset::InterfaceSelect)
    }

    pub(crate) fn configure_and_run_ui_tests(&mut self) -> Result<()> {
        self.run_ui_test_flow(TestPreset::Custom)
    }

    pub(crate) fn show_latest_ui_test_report(&mut self) -> Result<()> {
        let base = PathBuf::from("/var/lib/rustyjack/tests");
        if !base.exists() {
            return self.show_message(
                "Tests",
                [
                    "No test artifacts found.",
                    "Run a test suite from",
                    "Main Menu -> Tests first.",
                ],
            );
        }

        let Some(latest) = latest_dir(&base) else {
            return self.show_message("Tests", ["No test run directories found."]);
        };

        let runner_log = latest.join("ui_test_runner.log");
        let mut lines = vec![
            "Latest test artifacts".to_string(),
            shorten_for_display(&latest.display().to_string(), 96),
        ];
        if runner_log.exists() {
            lines.push(shorten_for_display(&runner_log.display().to_string(), 96));
            let fail_lines = tail_fail_lines(&runner_log, 3);
            if fail_lines.is_empty() {
                lines.push("No [FAIL] lines in runner log".to_string());
            } else {
                lines.push("Recent [FAIL] lines:".to_string());
                for line in fail_lines {
                    lines.push(shorten_for_display(&line, 96));
                }
            }
        } else {
            lines.push("ui_test_runner.log missing".to_string());
        }
        self.show_message("Tests", lines.iter().map(|line| line.as_str()))
    }

    fn run_ui_test_flow(&mut self, preset: TestPreset) -> Result<()> {
        let suites = match preset {
            TestPreset::All => vec![
                SuiteId::Wireless,
                SuiteId::Ethernet,
                SuiteId::InterfaceSelect,
                SuiteId::Encryption,
                SuiteId::Loot,
                SuiteId::Mac,
                SuiteId::Daemon,
                SuiteId::Installers,
                SuiteId::Usb,
                SuiteId::UiLayout,
                SuiteId::Theme,
            ],
            TestPreset::Wireless => vec![SuiteId::Wireless],
            TestPreset::Ethernet => vec![SuiteId::Ethernet],
            TestPreset::InterfaceSelect => vec![SuiteId::InterfaceSelect],
            TestPreset::Custom => {
                let Some(selected) = self.choose_test_suites()? else {
                    return Ok(());
                };
                selected
            }
        };

        if suites.is_empty() {
            return self.show_message("Tests", ["No suites selected."]);
        }

        let mut args: Vec<String> = Vec::new();
        if preset == TestPreset::All {
            args.push("--all".to_string());
        } else {
            for suite in &suites {
                args.push((*suite).flag().to_string());
            }
        }

        let dangerous = self
            .confirm_toggle(
                "Dangerous tests",
                "Enable dangerous tests where supported?",
                false,
            )?
            .unwrap_or(false);
        if dangerous {
            args.push("--dangerous".to_string());
        }

        // UI-driven runs always use UI automation.
        args.push("--ui".to_string());

        if suites.contains(&SuiteId::Daemon)
            || suites.contains(&SuiteId::DaemonDeep)
            || preset == TestPreset::All
        {
            let run_deep = self
                .confirm_toggle(
                    "Deep daemon",
                    "Run deep daemon diagnostics suite?",
                    preset == TestPreset::All,
                )?
                .unwrap_or(preset == TestPreset::All);
            if run_deep && !suites.contains(&SuiteId::DaemonDeep) {
                args.push("--daemon-deep".to_string());
            }
        }

        if suites.contains(&SuiteId::Wireless) || suites.contains(&SuiteId::InterfaceSelect) {
            self.append_interface_mode_args(true, &mut args)?;
        }
        if suites.contains(&SuiteId::Ethernet) || suites.contains(&SuiteId::InterfaceSelect) {
            self.append_interface_mode_args(false, &mut args)?;
        }

        let outroot = self.select_test_outroot()?;
        let req = UiTestRunRequestIpc {
            scripts_dir: None,
            args,
            outroot: Some(outroot.clone()),
            run_id: None,
            force_ui: true,
        };

        let job_id = match self.core.start_ui_test_run(req) {
            Ok(job_id) => job_id,
            Err(err) => {
                let msg = shorten_for_display(&err.to_string(), 90);
                return self.show_message("Tests", [format!("Failed to start: {msg}")]);
            }
        };

        self.monitor_ui_test_job(job_id, &outroot)
    }

    fn monitor_ui_test_job(&mut self, job_id: u64, outroot: &str) -> Result<()> {
        let title = "Test Runner";
        let mut last_msg: Option<String> = None;
        let mut last_percent: Option<u8> = None;

        loop {
            let status = match self.core.job_status(job_id) {
                Ok(status) => status,
                Err(err) => {
                    let msg = shorten_for_display(&err.to_string(), 90);
                    self.show_message("Tests", [format!("Status failed: {msg}")])?;
                    return Ok(());
                }
            };

            let (percent, message) = if let Some(progress) = status.progress.clone() {
                (
                    progress.percent,
                    format!("{}% {}", progress.percent, progress.message),
                )
            } else {
                (0, "Waiting for updates...".to_string())
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
                    if matches!(
                        self.check_cancel_request("Test run")?,
                        CancelDecision::Cancel
                    ) {
                        if let Err(err) = self.core.cancel_job(job_id) {
                            self.show_error_dialog("Cancel failed", &err)?;
                            return Ok(());
                        }
                        self.show_message("Tests", ["Test run cancellation requested"])?;
                        self.go_home()?;
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                JobState::Completed => {
                    let mut lines = vec![
                        "Test run complete".to_string(),
                        format!("Outroot: {}", shorten_for_display(outroot, 72)),
                    ];
                    if let Some(result) = status.result {
                        let success = result
                            .get("success")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let exit_code = result
                            .get("exit_code")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(-1);
                        let results_root = result
                            .get("results_root")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let runner_log = result
                            .get("runner_log")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        lines.push(format!(
                            "Status: {} (exit {})",
                            if success { "PASS" } else { "FAIL" },
                            exit_code
                        ));
                        if !results_root.is_empty() {
                            lines.push(shorten_for_display(results_root, 96));
                        }
                        if !runner_log.is_empty() {
                            lines.push(shorten_for_display(runner_log, 96));
                        }
                    }
                    self.show_message("Tests", lines.iter().map(|line| line.as_str()))?;
                    self.go_home()?;
                    return Ok(());
                }
                JobState::Cancelled => {
                    self.show_message("Tests", ["Test run cancelled"])?;
                    self.go_home()?;
                    return Ok(());
                }
                JobState::Failed => {
                    let mut lines = vec!["Test run failed".to_string()];
                    if let Some(err) = status.error {
                        lines.push(shorten_for_display(&err.message, 96));
                        if let Some(detail) = err.detail {
                            lines.push(shorten_for_display(&detail, 96));
                        }
                    }
                    self.show_message("Tests", lines.iter().map(|line| line.as_str()))?;
                    self.go_home()?;
                    return Ok(());
                }
            }
        }
    }

    fn choose_test_suites(&mut self) -> Result<Option<Vec<SuiteId>>> {
        let all = [
            SuiteId::Wireless,
            SuiteId::Ethernet,
            SuiteId::InterfaceSelect,
            SuiteId::Encryption,
            SuiteId::Loot,
            SuiteId::Mac,
            SuiteId::Daemon,
            SuiteId::DaemonDeep,
            SuiteId::Installers,
            SuiteId::Usb,
            SuiteId::UiLayout,
            SuiteId::Theme,
        ];
        let mut selected = vec![false; all.len()];

        loop {
            let mut labels: Vec<String> = all
                .iter()
                .enumerate()
                .map(|(idx, suite)| {
                    format!(
                        "[{}] {}",
                        if selected[idx] { "x" } else { " " },
                        suite.label()
                    )
                })
                .collect();
            labels.push("Run selected suites".to_string());
            labels.push("Cancel".to_string());

            let Some(choice) = self.choose_from_list("Select suites", &labels)? else {
                return Ok(None);
            };
            if choice < all.len() {
                selected[choice] = !selected[choice];
                continue;
            }
            if choice == all.len() {
                let suites: Vec<SuiteId> = all
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, suite)| if selected[idx] { Some(*suite) } else { None })
                    .collect();
                if suites.is_empty() {
                    self.show_message("Tests", ["Select at least one suite"])?;
                    continue;
                }
                return Ok(Some(suites));
            }
            return Ok(None);
        }
    }

    fn confirm_toggle(
        &mut self,
        title: &str,
        question: &str,
        default_yes: bool,
    ) -> Result<Option<bool>> {
        let yes = if default_yes { "Yes (default)" } else { "Yes" };
        let no = if default_yes { "No" } else { "No (default)" };
        let options = vec![yes.to_string(), no.to_string(), "Cancel".to_string()];
        let Some(choice) = self.choose_from_list(title, &options)? else {
            return Ok(None);
        };
        match choice {
            0 => Ok(Some(true)),
            1 => Ok(Some(false)),
            _ => {
                self.show_message(title, [question, "Cancelled; using default"])?;
                Ok(None)
            }
        }
    }

    fn append_interface_mode_args(&mut self, wireless: bool, args: &mut Vec<String>) -> Result<()> {
        let title = if wireless {
            "Wireless interfaces"
        } else {
            "Ethernet interfaces"
        };
        let mode_options = vec![
            "Auto-detect (default)".to_string(),
            "Single interface".to_string(),
            "Comma-separated list".to_string(),
            "All interfaces".to_string(),
        ];
        let choice = self.choose_from_list(title, &mode_options)?.unwrap_or(0);
        match choice {
            1 => {
                let interfaces = self.list_interfaces_by_type(wireless)?;
                if interfaces.is_empty() {
                    self.show_message("Tests", ["No matching interfaces detected"])?;
                    return Ok(());
                }
                let Some(index) = self.choose_from_list(title, &interfaces)? else {
                    return Ok(());
                };
                let iface = interfaces[index].clone();
                if wireless {
                    args.push("--wifi-interface".to_string());
                } else {
                    args.push("--eth-interface".to_string());
                }
                args.push(iface);
            }
            2 => {
                let interfaces = self.list_interfaces_by_type(wireless)?;
                if interfaces.is_empty() {
                    self.show_message("Tests", ["No matching interfaces detected"])?;
                    return Ok(());
                }
                let Some(selected) = self.select_multiple_interfaces(title, &interfaces)? else {
                    return Ok(());
                };
                if selected.is_empty() {
                    return Ok(());
                }
                let list = selected.join(",");
                if wireless {
                    args.push("--wifi-interfaces".to_string());
                } else {
                    args.push("--eth-interfaces".to_string());
                }
                args.push(list);
            }
            3 => {
                if wireless {
                    args.push("--wifi-all-interfaces".to_string());
                } else {
                    args.push("--eth-all-interfaces".to_string());
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn list_interfaces_by_type(&self, wireless: bool) -> Result<Vec<String>> {
        let mut interfaces: Vec<String> = self
            .core
            .interfaces_list()?
            .interfaces
            .into_iter()
            .filter(|iface| {
                iface.exists && iface.interface != "lo" && iface.is_wireless == wireless
            })
            .map(|iface| iface.interface)
            .collect();
        interfaces.sort();
        interfaces.dedup();
        Ok(interfaces)
    }

    fn select_multiple_interfaces(
        &mut self,
        title: &str,
        interfaces: &[String],
    ) -> Result<Option<Vec<String>>> {
        let mut selected = vec![false; interfaces.len()];
        loop {
            let mut labels: Vec<String> = interfaces
                .iter()
                .enumerate()
                .map(|(idx, iface)| {
                    format!("[{}] {}", if selected[idx] { "x" } else { " " }, iface)
                })
                .collect();
            labels.push("Done".to_string());
            labels.push("Cancel".to_string());

            let Some(choice) = self.choose_from_list(title, &labels)? else {
                return Ok(None);
            };
            if choice < interfaces.len() {
                selected[choice] = !selected[choice];
                continue;
            }
            if choice == interfaces.len() {
                let picks: Vec<String> = interfaces
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, iface)| {
                        if selected[idx] {
                            Some(iface.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                return Ok(Some(picks));
            }
            return Ok(None);
        }
    }

    fn select_test_outroot(&mut self) -> Result<String> {
        let options = vec![
            "/var/lib/rustyjack/tests (recommended)".to_string(),
            "/var/tmp/rustyjack-tests".to_string(),
            "Use script default".to_string(),
        ];
        let choice = self
            .choose_from_list("Test output root", &options)?
            .unwrap_or(0);
        let selected = match choice {
            1 => "/var/tmp/rustyjack-tests",
            2 => "/var/tmp/rustyjack-tests",
            _ => "/var/lib/rustyjack/tests",
        };
        Ok(selected.to_string())
    }
}

fn latest_dir(base: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(base).ok()?;
    let mut latest: Option<(PathBuf, std::time::SystemTime)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match latest {
            Some((_, ts)) if modified <= ts => {}
            _ => latest = Some((path, modified)),
        }
    }
    latest.map(|item| item.0)
}

fn tail_fail_lines(path: &Path, limit: usize) -> Vec<String> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut lines: Vec<String> = content
        .lines()
        .filter(|line| line.contains("[FAIL]"))
        .map(|line| line.to_string())
        .collect();
    if lines.len() > limit {
        lines = lines.split_off(lines.len() - limit);
    }
    lines
}
