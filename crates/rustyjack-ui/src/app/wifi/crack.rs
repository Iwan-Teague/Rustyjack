use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
    sync::mpsc::{self, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};

#[cfg(target_os = "linux")]
use rustyjack_wpa::crack::{
    generate_common_passwords, generate_ssid_passwords, CrackProgress, CrackResult, CrackerConfig,
    WpaCracker,
};

#[cfg(target_os = "linux")]
use crate::types::{CrackOutcome, CrackUpdate, DictionaryOption, HandshakeBundle};

use crate::ops::shared::preflight::preflight_only_summary;
use crate::util::shorten_for_display;
use rustyjack_commands::{Commands, WifiCommand, WifiCrackArgs};

use super::super::state::{App, ButtonAction};

impl App {
    pub(crate) fn launch_crack_handshake(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message(
                "Crack",
                [
                    "Handshake cracking",
                    "is available on Linux",
                    "targets only.",
                ],
            );
        }

        #[cfg(target_os = "linux")]
        {
            let loot_dir = self.root.join("loot/Wireless");

            if !loot_dir.exists() {
                return self.show_message(
                    "Crack",
                    [
                        "No handshakes found",
                        "",
                        "Capture a handshake",
                        "using Deauth Attack",
                        "or PMKID Capture first",
                    ],
                );
            }

            let mut handshake_files: Vec<(String, std::path::PathBuf)> = Vec::new();
            fn scan_dir(dir: &std::path::Path, files: &mut Vec<(String, std::path::PathBuf)>) {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            scan_dir(&path, files);
                        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("handshake_export_") && name.ends_with(".json") {
                                let display_name = if let Some(parent) = path.parent() {
                                    if let Some(parent_name) = parent.file_name() {
                                        format!(
                                            "{}/{}",
                                            parent_name.to_string_lossy(),
                                            path.file_name().unwrap_or_default().to_string_lossy()
                                        )
                                    } else {
                                        path.file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .to_string()
                                    }
                                } else {
                                    path.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string()
                                };
                                files.push((display_name, path));
                            }
                        }
                    }
                }
            }
            scan_dir(&loot_dir, &mut handshake_files);

            if handshake_files.is_empty() {
                return self.show_message(
                    "Crack",
                    [
                        "No handshake exports",
                        "found in loot/",
                        "",
                        "Capture a handshake",
                        "first. Native cracker",
                        "uses JSON exports.",
                    ],
                );
            }

            let display_names: Vec<String> = handshake_files
                .iter()
                .map(|(name, _)| name.clone())
                .collect();
            let choice = self.choose_from_menu("Select Handshake", &display_names)?;

            let Some(idx) = choice else {
                return Ok(());
            };

            let (_selected_name, file_path) = &handshake_files[idx];
            let bundle = self.load_handshake_bundle(file_path)?;

            let dictionaries = self.available_dictionaries(&bundle.ssid)?;
            let labels: Vec<String> = dictionaries.iter().map(|d| d.label()).collect();

            let dict_choice = self.choose_from_menu("Dictionary", &labels)?;
            let Some(selection) = dict_choice else {
                return Ok(());
            };
            let dictionary = dictionaries[selection].clone();

            let review_path = self.root.join("REVIEW_APPROVED.md");
            if !review_path.exists() {
                let (mode, wordlist) = match &dictionary {
                    DictionaryOption::Quick { .. } => ("quick".to_string(), None),
                    DictionaryOption::SsidPatterns { .. } => ("ssid".to_string(), None),
                    DictionaryOption::Bundled { path, .. } => (
                        "wordlist".to_string(),
                        Some(path.to_string_lossy().to_string()),
                    ),
                };

                let args = WifiCrackArgs {
                    file: file_path.to_string_lossy().to_string(),
                    ssid: Some(bundle.ssid.clone()),
                    mode,
                    wordlist,
                };
                let (msg, data) = self
                    .core
                    .dispatch(Commands::Wifi(WifiCommand::Crack(args)))?;
                if let Some(lines) = preflight_only_summary(&data) {
                    return self.show_message("Crack", lines.iter().map(|s| s.as_str()));
                }
                return self.show_message("Crack", [msg]);
            }

            let result = self.crack_handshake_with_progress(bundle, dictionary)?;

            let mut lines = Vec::new();
            lines.push(format!(
                "Attempts: {}/{}",
                result.attempts, result.total_attempts
            ));
            lines.push(format!("Elapsed: {:.1}s", result.elapsed.as_secs_f32()));
            if let Some(p) = result.password {
                lines.push("".to_string());
                lines.push("PASSWORD FOUND!".to_string());
                lines.push(p);
            } else if result.cancelled {
                lines.push("Cancelled before finish".to_string());
            } else {
                lines.push("No match found".to_string());
                lines.push("Try another dictionary".to_string());
            }

            self.show_message("Crack Result", lines.iter().map(|s| s.as_str()))?;
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn load_handshake_bundle(&self, path: &Path) -> Result<HandshakeBundle> {
        let data = fs::read(path)
            .with_context(|| format!("reading handshake export {}", path.display()))?;
        let bundle: HandshakeBundle =
            serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))?;
        Ok(bundle)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn load_wordlist(&self, path: &Path) -> Result<Vec<String>> {
        let file =
            File::open(path).with_context(|| format!("opening wordlist {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut passwords = Vec::new();
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            let pw = line.trim();
            if pw.len() >= 8 && pw.len() <= 63 {
                passwords.push(pw.to_string());
            }
        }
        Ok(passwords)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn count_wordlist(&self, path: &Path) -> usize {
        File::open(path)
            .ok()
            .map(|file| {
                BufReader::new(file)
                    .lines()
                    .filter_map(|l| l.ok())
                    .filter(|pw| {
                        let len = pw.trim().len();
                        len >= 8 && len <= 63
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn available_dictionaries(&self, ssid: &str) -> Result<Vec<DictionaryOption>> {
        let base = self.root.join("wordlists");
        let quick_total =
            (generate_common_passwords().len() + generate_ssid_passwords(ssid).len()) as u64;
        let ssid_total = generate_ssid_passwords(ssid).len() as u64;

        let mut options = vec![
            DictionaryOption::Quick { total: quick_total },
            DictionaryOption::SsidPatterns { total: ssid_total },
        ];

        let bundled = [
            ("WiFi common", base.join("wifi_common.txt")),
            ("Top passwords", base.join("common_top.txt")),
        ];
        for (label, path) in bundled {
            let count = self.count_wordlist(&path) as u64;
            if count > 0 {
                options.push(DictionaryOption::Bundled {
                    name: label.to_string(),
                    path,
                    total: count,
                });
            }
        }

        Ok(options)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn crack_handshake_with_progress(
        &mut self,
        bundle: HandshakeBundle,
        dictionary: DictionaryOption,
    ) -> Result<CrackOutcome> {
        use std::thread;

        let passwords = match &dictionary {
            DictionaryOption::Quick { .. } => {
                let mut list = generate_common_passwords();
                list.extend(generate_ssid_passwords(&bundle.ssid));
                list
            }
            DictionaryOption::SsidPatterns { .. } => generate_ssid_passwords(&bundle.ssid),
            DictionaryOption::Bundled { path, .. } => self.load_wordlist(path)?,
        };

        if passwords.is_empty() {
            return Err(anyhow::anyhow!("Selected dictionary is empty"));
        }

        let total_attempts = passwords.len() as u64;

        let mut cracker =
            WpaCracker::new(bundle.handshake.clone(), &bundle.ssid).with_config(CrackerConfig {
                // Update UI on every attempt so the progress bar moves consistently
                progress_interval: 1,
                max_attempts: 0,
                throttle_interval: 200,
                threads: 1,
            });
        let stop_flag = cracker.stop_handle();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut cb = |p: CrackProgress| {
                if tx
                    .send(CrackUpdate::Progress {
                        attempts: p.attempts,
                        total: total_attempts,
                        rate: p.rate,
                        current: p.current.clone(),
                    })
                    .is_err()
                {
                    return;
                }
            };

            let res = cracker.crack_passwords_with_progress(
                &passwords,
                Some(total_attempts),
                Some(&mut cb),
            );

            let final_attempts = cracker.attempts();
            let send_res = match res {
                Ok(CrackResult::Found(pw)) => tx.send(CrackUpdate::Done {
                    password: Some(pw),
                    attempts: final_attempts,
                    total: total_attempts,
                    cancelled: false,
                }),
                Ok(CrackResult::Exhausted { attempts }) => tx.send(CrackUpdate::Done {
                    password: None,
                    attempts,
                    total: total_attempts,
                    cancelled: false,
                }),
                Ok(CrackResult::Stopped { attempts }) => tx.send(CrackUpdate::Done {
                    password: None,
                    attempts,
                    total: total_attempts,
                    cancelled: true,
                }),
                Err(e) => tx.send(CrackUpdate::Error(e.to_string())),
            };
            if let Err(err) = send_res {
                tracing::warn!("Crack update send failed: {:#}", err);
            }
        });

        let mut attempts = 0u64;
        let mut current = String::new();
        let mut rate = 0.0f32;
        let mut finished: Option<CrackOutcome> = None;
        let started = Instant::now();

        // Initial draw so user sees 0/N
        self.draw_crack_progress(attempts, total_attempts, rate, &current)?;

        loop {
            match rx.try_recv() {
                Ok(update) => match update {
                    CrackUpdate::Progress {
                        attempts: a,
                        total,
                        rate: r,
                        current: c,
                    } => {
                        attempts = a;
                        rate = r;
                        current = c;
                        self.draw_crack_progress(attempts, total, rate, &current)?;
                    }
                    CrackUpdate::Done {
                        password,
                        attempts: a,
                        total,
                        cancelled,
                    } => {
                        // draw final state before exiting
                        self.draw_crack_progress(a, total, rate, &current)?;
                        finished = Some(CrackOutcome {
                            password,
                            attempts: a,
                            total_attempts: total,
                            elapsed: started.elapsed(),
                            cancelled,
                        });
                    }
                    CrackUpdate::Error(e) => {
                        self.show_message("Crack", [e.clone()])?;
                        return Err(anyhow!(e));
                    }
                },
                Err(TryRecvError::Disconnected) => {
                    finished = Some(CrackOutcome {
                        password: None,
                        attempts,
                        total_attempts,
                        elapsed: started.elapsed(),
                        cancelled: true,
                    });
                }
                Err(TryRecvError::Empty) => {}
            }

            if finished.is_some() {
                break;
            }

            if let Some(button) = self.buttons.try_read()? {
                match self.map_button(button) {
                    ButtonAction::Cancel => {
                        if self.confirm_cancel("Crack")? {
                            stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    ButtonAction::Reboot => self.confirm_reboot()?,
                    _ => {}
                }
            }

            self.draw_crack_progress(attempts, total_attempts, rate, &current)?;
            thread::sleep(Duration::from_millis(350));
        }

        Ok(finished.unwrap_or(CrackOutcome {
            password: None,
            attempts,
            total_attempts,
            elapsed: started.elapsed(),
            cancelled: true,
        }))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn draw_crack_progress(
        &mut self,
        attempts: u64,
        total: u64,
        rate: f32,
        current: &str,
    ) -> Result<()> {
        let pct = if total > 0 {
            (attempts as f32 / total as f32 * 100.0).min(100.0)
        } else {
            0.0
        };
        let message = format!(
            "{} / {} tried | {:.1}/s | {}",
            attempts,
            total,
            rate,
            shorten_for_display(current, 14)
        );
        let status = self.status_overlay();
        self.display
            .draw_progress_dialog("Crack Handshake", &message, pct, &status)?;
        Ok(())
    }
}
