use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use rustyjack_commands::{Commands, SystemCommand, SystemFdeMigrateArgs, SystemFdePrepareArgs};
use rustyjack_encryption::{clear_encryption_key, set_encryption_key};
use walkdir::WalkDir;
use zeroize::Zeroize;

use crate::util::shorten_for_display;

use super::state::{App, UsbAccessRequirement, UsbDevice};

impl App {
    pub(crate) fn parse_key_file(&self, path: &Path) -> Result<[u8; 32]> {
        let data = fs::read(path)?;
        // Try hex first
        let content = String::from_utf8_lossy(&data).trim().to_string();
        let hex_only = content
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c.is_whitespace());
        if hex_only {
            let clean: String = content.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if clean.len() == 64 {
                let mut out = [0u8; 32];
                for i in 0..32 {
                    let byte = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
                        .map_err(|e| anyhow!("Invalid hex in key file: {e}"))?;
                    out[i] = byte;
                }
                return Ok(out);
            }
        }

        // Fallback: raw 32-byte key
        if data.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&data);
            return Ok(out);
        }

        bail!("Key file must contain 32 raw bytes or 64 hex chars");
    }

    pub(crate) fn load_encryption_key_from_usb(&mut self) -> Result<()> {
        let Some(file_path) = self.browse_usb_for_file("Load Key", Some(&["key", "txt", "enc"]))?
        else {
            return Ok(());
        };

        match self.parse_key_file(&file_path) {
            Ok(key) => {
                clear_encryption_key();
                set_encryption_key(&key)?;
                self.config.settings.encryption_key_path = file_path.to_string_lossy().to_string();
                let config_path = self.root.join("gui_conf.json");
                self.save_config_file(&config_path)?;
                self.show_message(
                    "Encryption",
                    [
                        "Key loaded into RAM",
                        &shorten_for_display(&file_path.to_string_lossy(), 18),
                        "Path saved for next boot",
                    ],
                )?;
            }
            Err(e) => {
                self.show_message(
                    "Encryption",
                    [
                        "Failed to load key",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                )?;
            }
        }
        clear_encryption_key();
        Ok(())
    }

    pub(crate) fn encrypt_loot_file_in_place(&mut self, path: &Path) -> Result<PathBuf> {
        self.ensure_saved_key_loaded();
        if !rustyjack_encryption::encryption_enabled() {
            bail!("Encryption enabled but key is not loaded");
        }
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("Invalid filename"))?;
        let mut data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let dest = path.with_file_name(format!("{filename}.enc"));
        if dest.exists() {
            if let Err(err) = fs::remove_file(&dest) {
                tracing::warn!("Failed to remove {}: {:#}", dest.display(), err);
            }
        }
        rustyjack_encryption::encrypt_to_file(&dest, &data)
            .with_context(|| format!("encrypting {}", dest.display()))?;
        data.zeroize();
        if let Err(err) = fs::remove_file(path) {
            tracing::warn!("Failed to remove {}: {:#}", path.display(), err);
        }
        clear_encryption_key();
        Ok(dest)
    }

    pub(crate) fn generate_encryption_key_on_usb(&mut self) -> Result<()> {
        // Guard rail: Prevent key generation if encryption is active with encrypted data
        if self.config.settings.encryption_enabled {
            let has_encrypted_data = self.config.settings.encrypt_loot
                || self.config.settings.encrypt_wifi_profiles
                || self.config.settings.encrypt_discord_webhook;

            if has_encrypted_data {
                let warning = vec![
                    "DANGER: Encryption Active".to_string(),
                    "".to_string(),
                    "Generating a new key will".to_string(),
                    "make existing encrypted".to_string(),
                    "data UNRECOVERABLE.".to_string(),
                    "".to_string(),
                    "Disable encryption first".to_string(),
                    "or load existing key.".to_string(),
                ];
                return self.show_message("Encryption Warning", warning.iter().map(|s| s.as_str()));
            }
        }

        let Some(usb_root) = self.select_usb_mount(UsbAccessRequirement::RequireWritable)? else {
            return Ok(());
        };

        let key_path = usb_root.join("rustyjack.key");
        if key_path.exists() {
            let opts = vec!["Overwrite key".to_string(), "Cancel".to_string()];
            if let Some(choice) = self.choose_from_list("Key exists", &opts)? {
                if choice != 0 {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        fs::write(&key_path, hex.as_bytes())?;

        clear_encryption_key();
        set_encryption_key(&key)?;
        self.config.settings.encryption_key_path = key_path.to_string_lossy().to_string();
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;

        let res = self.show_message(
            "Encryption",
            [
                "New key generated",
                &shorten_for_display(&key_path.to_string_lossy(), 18),
                "Loaded into RAM",
            ],
        );
        clear_encryption_key();
        res
    }

    /// Disabling master encryption should walk all encryption toggles and turn them off.
    pub(crate) fn toggle_encryption_master(&mut self) -> Result<()> {
        let enabling = !self.config.settings.encryption_enabled;
        if enabling {
            // Require key file present and loadable
            if !self.ensure_keyfile_available() {
                return self.show_message(
                    "Encryption",
                    [
                        "Load or generate a keyfile first",
                        "Use Encryption menu to set key",
                    ],
                );
            }
            self.config.settings.encryption_enabled = true;
        } else {
            // When disabling, verify key presence and ask for confirmation
            if !self.ensure_keyfile_available() {
                return self.show_message(
                    "Encryption",
                    [
                        "Keyfile missing or invalid",
                        "Set correct key path before disabling",
                    ],
                );
            }

            let options = vec!["Yes - decrypt all now".to_string(), "Cancel".to_string()];
            self.show_message(
                "Turn off encryption?",
                [
                    "All encrypted items will be decrypted.",
                    "Do NOT remove power; uncancellable.",
                ],
            )?;
            let confirm = self.choose_from_list("Proceed?", &options)?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.disable_all_encryptions()?;
            self.config.settings.encryption_enabled = false;
        }
        rustyjack_encryption::set_wifi_profile_encryption(self.wifi_encryption_active());
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;
        let res = self.show_message(
            "Encryption",
            [format!(
                "Encryption {}",
                if self.config.settings.encryption_enabled {
                    "ENABLED"
                } else {
                    "DISABLED"
                }
            )],
        );
        clear_encryption_key();
        res
    }

    pub(crate) fn ensure_keyfile_available(&mut self) -> bool {
        let path_str = self.config.settings.encryption_key_path.clone();
        if path_str.is_empty() {
            if let Err(err) = self.show_message(
                "Encryption",
                ["No keyfile path set", "Generate or load a key first"],
            ) {
                tracing::warn!("Failed to show encryption message: {:#}", err);
            }
            return false;
        }
        let path = PathBuf::from(&path_str);
        if !path.exists() {
            if let Err(err) = self.show_message(
                "Encryption",
                [
                    "Keyfile missing at saved path",
                    &shorten_for_display(&path_str, 18),
                ],
            ) {
                tracing::warn!("Failed to show encryption message: {:#}", err);
            }
            return false;
        }
        match self.parse_key_file(&path) {
            Ok(key) => {
                clear_encryption_key();
                if let Err(e) = set_encryption_key(&key) {
                    if let Err(err) = self.show_message(
                        "Encryption",
                        [
                            "Failed to load key",
                            &shorten_for_display(&e.to_string(), 90),
                        ],
                    ) {
                        tracing::warn!("Failed to show encryption error: {:#}", err);
                    }
                    false
                } else {
                    true
                }
            }
            Err(e) => {
                if let Err(err) = self.show_message(
                    "Encryption",
                    ["Invalid keyfile", &shorten_for_display(&e.to_string(), 90)],
                ) {
                    tracing::warn!("Failed to show encryption error: {:#}", err);
                }
                false
            }
        }
    }

    pub(crate) fn list_usb_devices(&self) -> Result<Vec<UsbDevice>> {
        let devices = self.core.block_devices().context("listing block devices")?;
        let mut usb_devices = Vec::new();
        for dev in devices {
            let is_usb = dev
                .transport
                .as_deref()
                .map(|t| t.eq_ignore_ascii_case("usb"))
                .unwrap_or(false);
            if !is_usb {
                continue;
            }
            let model = dev.model.trim().to_string();
            usb_devices.push(UsbDevice {
                name: dev.name,
                size: dev.size,
                model: if model.is_empty() {
                    "Unknown".to_string()
                } else {
                    model
                },
                transport: dev.transport,
                is_partition: dev.is_partition,
                parent: dev.parent,
            });
        }
        Ok(usb_devices)
    }

    pub(crate) fn list_usb_partitions(&self) -> Result<Vec<UsbDevice>> {
        Ok(self
            .list_usb_devices()?
            .into_iter()
            .filter(|dev| dev.is_partition)
            .collect())
    }

    pub(crate) fn list_usb_disks(&self) -> Result<Vec<UsbDevice>> {
        Ok(self
            .list_usb_devices()?
            .into_iter()
            .filter(|dev| !dev.is_partition)
            .collect())
    }

    /// Turn off all encryption toggles with a simple progress display.
    pub(crate) fn disable_all_encryptions(&mut self) -> Result<()> {
        let status = self.stats.snapshot();
        let mut total_steps = 0usize;
        if self.config.settings.encrypt_discord_webhook {
            total_steps += 1;
        }
        if self.config.settings.encrypt_loot {
            total_steps += 1;
        }
        if self.config.settings.encrypt_wifi_profiles {
            total_steps += 1;
        }
        if total_steps == 0 {
            total_steps = 1; // Avoid division by zero; still show completion
        }
        let mut current_step = 0usize;

        // Step 1: webhook encryption
        if self.config.settings.encrypt_discord_webhook {
            current_step += 1;
            let pct = (current_step as f32 / total_steps as f32) * 100.0;
            self.display.draw_progress_dialog(
                "Encryption",
                "Disabling webhook encryption...\nDo not power off\nUncancellable",
                pct,
                &status,
            )?;
            self.set_webhook_encryption(false, false)?;
        }

        // Step 2: loot encryption
        if self.config.settings.encrypt_loot {
            current_step += 1;
            let pct = (current_step as f32 / total_steps as f32) * 100.0;
            self.display.draw_progress_dialog(
                "Encryption",
                "Disabling loot encryption...\nDo not power off\nUncancellable",
                pct,
                &status,
            )?;
            self.set_loot_encryption(false, false)?;
        }

        // Step 2: Wi-Fi profile encryption
        if self.config.settings.encrypt_wifi_profiles {
            current_step += 1;
            let pct = (current_step as f32 / total_steps as f32) * 100.0;
            self.display.draw_progress_dialog(
                "Encryption",
                "Disabling Wi-Fi profile encryption...\nDo not power off\nUncancellable",
                pct,
                &status,
            )?;
            self.set_wifi_encryption(false, false)?;
        }

        // Final message
        self.display.draw_progress_dialog(
            "Encryption",
            "All encryption toggles set to OFF\nDo not power off\nUncancellable",
            100.0,
            &status,
        )?;

        // Ensure flags are off
        self.config.settings.encrypt_discord_webhook = false;
        self.config.settings.encrypt_loot = false;
        self.config.settings.encrypt_wifi_profiles = false;
        rustyjack_encryption::set_wifi_profile_encryption(false);
        rustyjack_encryption::set_loot_encryption(false);
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;
        clear_encryption_key();
        Ok(())
    }

    pub(crate) fn toggle_encrypt_wifi_profiles(&mut self) -> Result<()> {
        self.set_wifi_encryption(!self.config.settings.encrypt_wifi_profiles, true)
    }

    pub(crate) fn set_wifi_encryption(&mut self, enable: bool, interactive: bool) -> Result<()> {
        if enable && !self.config.settings.encryption_enabled {
            return self.show_message(
                "Encryption",
                ["Enable master encryption first", "Toggle Encryption [ON]"],
            );
        }
        if !self.ensure_keyfile_available() {
            return Ok(());
        }

        if interactive {
            let prompt = if enable {
                "Encrypt saved Wi-Fi profiles with the current key?"
            } else {
                "Decrypt Wi-Fi profiles to plaintext?"
            };
            let options = vec!["Proceed".to_string(), "Cancel".to_string()];
            if self.choose_from_list(prompt, &options)? != Some(0) {
                clear_encryption_key();
                return Ok(());
            }
        }

        let profiles_dir = self.root.join("wifi").join("profiles");
        if enable {
            fs::create_dir_all(&profiles_dir)
                .with_context(|| format!("creating {}", profiles_dir.display()))?;
        }

        let mut changed = 0usize;
        let mut errors: Vec<String> = Vec::new();

        if profiles_dir.exists() {
            if let Ok(entries) = fs::read_dir(&profiles_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let name = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default()
                        .to_string();

                    if enable {
                        if path.extension().and_then(|e| e.to_str()) != Some("json") {
                            continue;
                        }
                        match fs::read_to_string(&path) {
                            Ok(mut contents) => {
                                let dest = path.with_file_name(format!("{name}.enc"));
                                if let Err(e) = rustyjack_encryption::encrypt_to_file(
                                    &dest,
                                    contents.as_bytes(),
                                ) {
                                    errors.push(shorten_for_display(&e.to_string(), 80));
                                } else {
                                    if let Err(err) = fs::remove_file(&path) {
                                        tracing::warn!(
                                            "Failed to remove {}: {:#}",
                                            path.display(),
                                            err
                                        );
                                    }
                                    changed += 1;
                                }
                                contents.zeroize();
                            }
                            Err(e) => errors.push(shorten_for_display(&e.to_string(), 80)),
                        }
                    } else {
                        if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                            continue;
                        }
                        match rustyjack_encryption::decrypt_file(&path) {
                            Ok(mut bytes) => {
                                let plain_name = name.trim_end_matches(".enc");
                                let dest = path.with_file_name(plain_name);
                                if let Err(e) = fs::write(&dest, &bytes) {
                                    errors.push(shorten_for_display(&e.to_string(), 80));
                                } else {
                                    if let Err(err) = fs::remove_file(&path) {
                                        tracing::warn!(
                                            "Failed to remove {}: {:#}",
                                            path.display(),
                                            err
                                        );
                                    }
                                    changed += 1;
                                }
                                bytes.zeroize();
                            }
                            Err(e) => errors.push(shorten_for_display(&e.to_string(), 80)),
                        }
                    }
                }
            }
        }

        self.config.settings.encrypt_wifi_profiles = enable;
        rustyjack_encryption::set_wifi_profile_encryption(self.wifi_encryption_active());
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;

        if interactive {
            if errors.is_empty() {
                let res = self.show_message(
                    "Encryption",
                    [format!(
                        "Wi-Fi profiles encryption {} ({} file{})",
                        if enable { "ENABLED" } else { "DISABLED" },
                        changed,
                        if changed == 1 { "" } else { "s" }
                    )],
                );
                clear_encryption_key();
                return res;
            }
            let res = self.show_message(
                "Encryption",
                [
                    "Completed with errors",
                    &shorten_for_display(&errors.join("; "), 90),
                ],
            );
            clear_encryption_key();
            return res;
        }

        clear_encryption_key();
        Ok(())
    }

    pub(crate) fn toggle_encrypt_loot(&mut self) -> Result<()> {
        self.set_loot_encryption(!self.config.settings.encrypt_loot, true)
    }

    pub(crate) fn set_loot_encryption(&mut self, enable: bool, interactive: bool) -> Result<()> {
        if enable && !self.config.settings.encryption_enabled {
            return self.show_message(
                "Encryption",
                ["Enable encryption first", "Toggle master Encryption ON"],
            );
        }
        if !self.ensure_keyfile_available() {
            return Ok(());
        }

        if interactive {
            let prompt = if enable {
                "Encrypt all loot files with the current key?"
            } else {
                "Decrypt all loot files (uncancellable)?"
            };
            let options = vec!["Proceed".to_string(), "Cancel".to_string()];
            if self.choose_from_list(prompt, &options)? != Some(0) {
                clear_encryption_key();
                return Ok(());
            }
        }

        let targets = vec![self.root.join("loot")];
        let mut files = Vec::new();

        for dir in targets {
            if !dir.exists() {
                continue;
            }
            for entry in WalkDir::new(&dir) {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path().to_path_buf();
                let name = match path.file_name().and_then(|s| s.to_str()) {
                    Some(n) => n,
                    None => continue,
                };
                if enable {
                    if name.ends_with(".enc") {
                        continue;
                    }
                } else if !name.ends_with(".enc") {
                    continue;
                }
                files.push(path);
            }
        }

        let total = files.len();
        let status = self.stats.snapshot();
        let mut errors: Vec<String> = Vec::new();
        if total == 0 && interactive {
            clear_encryption_key();
            return self.show_message(
                "Encryption",
                [if enable {
                    "No plaintext loot files found"
                } else {
                    "No encrypted loot files found"
                }],
            );
        }

        for (idx, path) in files.iter().enumerate() {
            let progress = ((idx + 1) as f32 / total.max(1) as f32) * 100.0;
            let msg = if enable {
                "Encrypting loot...\nDo not power off"
            } else {
                "Decrypting loot...\nDo not power off"
            };
            self.display
                .draw_progress_dialog("Encryption", msg, progress, &status)?;

            if enable {
                let mut data = match fs::read(&path) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(shorten_for_display(&e.to_string(), 80));
                        continue;
                    }
                };
                let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
                let dest = path.with_file_name(format!("{filename}.enc"));
                if dest.exists() {
                    if let Err(err) = fs::remove_file(&dest) {
                        tracing::warn!("Failed to remove {}: {:#}", dest.display(), err);
                    }
                }
                if let Err(e) = rustyjack_encryption::encrypt_to_file(&dest, &data) {
                    errors.push(shorten_for_display(&e.to_string(), 80));
                } else {
                    if let Err(err) = fs::remove_file(&path) {
                        tracing::warn!("Failed to remove {}: {:#}", path.display(), err);
                    }
                }
                data.zeroize();
            } else {
                let filename = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                let plain_name = filename.trim_end_matches(".enc");
                let dest = path.with_file_name(plain_name);
                if dest.exists() {
                    errors.push(format!(
                        "Plaintext exists, skip: {}",
                        shorten_for_display(dest.to_string_lossy().as_ref(), 40)
                    ));
                    continue;
                }
                match rustyjack_encryption::decrypt_file(&path) {
                    Ok(mut data) => {
                        if let Err(e) = fs::write(&dest, &data) {
                            errors.push(shorten_for_display(&e.to_string(), 80));
                        } else {
                            if let Err(err) = fs::remove_file(&path) {
                                tracing::warn!(
                                    "Failed to remove {}: {:#}",
                                    path.display(),
                                    err
                                );
                            }
                        }
                        data.zeroize();
                    }
                    Err(e) => errors.push(shorten_for_display(&e.to_string(), 80)),
                }
            }
        }

        self.config.settings.encrypt_loot = enable;
        rustyjack_encryption::set_loot_encryption(self.loot_encryption_active());
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;

        if interactive {
            if errors.is_empty() {
                let res = self.show_message(
                    "Encryption",
                    [format!(
                        "Loot encryption {}",
                        if enable { "ENABLED" } else { "DISABLED" }
                    )],
                );
                clear_encryption_key();
                return res;
            }
            let res = self.show_message(
                "Encryption",
                [
                    "Completed with errors",
                    &shorten_for_display(&errors.join("; "), 90),
                ],
            );
            clear_encryption_key();
            return res;
        }
        clear_encryption_key();
        Ok(())
    }

    pub(crate) fn toggle_encrypt_webhook(&mut self) -> Result<()> {
        self.set_webhook_encryption(!self.config.settings.encrypt_discord_webhook, true)
    }

    /// UI flow for full disk encryption USB preparation.
    pub(crate) fn start_full_disk_encryption_flow(&mut self) -> Result<()> {
        self.show_message(
            "Full Disk Encryption",
            [
                "WARNING:",
                "Will require formatting a USB key for unlock",
                "and re-encrypting the SD root; power loss can brick.",
            ],
        )?;
        let proceed_opts = vec!["Select USB".to_string(), "Cancel".to_string()];
        if self
            .choose_from_list("Continue?", &proceed_opts)?
            .map(|i| i != 0)
            .unwrap_or(true)
        {
            return Ok(());
        }

        let devices = match self.list_usb_disks() {
            Ok(d) => d,
            Err(e) => {
                return self.show_message(
                    "Full Disk Encryption",
                    [
                        "Failed to list USB devices",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
        };
        if devices.is_empty() {
            return self.show_message(
                "Full Disk Encryption",
                [
                    "No removable USB devices detected",
                    "Insert USB key and retry",
                ],
            );
        }

        let labels: Vec<String> = devices
            .iter()
            .map(|d| format!("{}  {}  {}", d.name, d.size, d.model))
            .collect();
        let Some(choice) = self.choose_from_list("Select USB to format (will wipe)", &labels)?
        else {
            return Ok(());
        };
        let dev = &devices[choice];
        let confirm_opts = vec![
            format!("Format {} ({})", dev.name, dev.size),
            "Cancel".to_string(),
        ];
        if self
            .choose_from_list("Final confirmation", &confirm_opts)?
            .map(|i| i != 0)
            .unwrap_or(true)
        {
            return Ok(());
        }

        self.run_usb_prepare(&dev.name)
    }

    pub(crate) fn start_fde_migration(&mut self) -> Result<()> {
        // FDE migration feature not yet implemented
        self.show_message(
            "FDE Migration",
            [
                "Feature not yet implemented",
                "Use command line tools instead",
            ],
        )?;
        Ok(())
    }

    pub(crate) fn run_usb_prepare(&mut self, device: &str) -> Result<()> {
        self.show_progress(
            "Full Disk Encryption",
            ["Preparing USB key...", "Do not remove power/USB"],
        )?;

        let args = SystemFdePrepareArgs {
            device: device.to_string(),
        };
        let (msg, data) = match self
            .core
            .dispatch(Commands::System(SystemCommand::FdePrepare(args)))
        {
            Ok(result) => result,
            Err(err) => {
                let err_text = err.to_string();
                if err_text.contains("FDE prepare disabled")
                    || err_text.contains("external scripts removed")
                {
                    return self.show_message(
                        "Full Disk Encryption",
                        [
                            "Feature disabled",
                            "Rust-only build",
                            "",
                            "No Rust implementation yet",
                        ],
                    );
                }
                return self.show_message(
                    "Full Disk Encryption",
                    ["Failed to start", &shorten_for_display(&err_text, 90)],
                );
            }
        };

        let stdout = data
            .get("stdout")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut lines: Vec<String> = stdout
            .lines()
            .map(|l| shorten_for_display(l, 32))
            .collect();
        if lines.is_empty() {
            lines.push(msg);
        }
        self.show_message("Full Disk Encryption", lines)
    }

    #[allow(dead_code)]
    pub(crate) fn run_fde_migrate(&mut self, target: &str, keyfile: &str, execute: bool) -> Result<()> {
        self.show_progress(
            "Full Disk Encryption",
            ["Migrating root...", "Do not remove power/USB"],
        )?;

        let args = SystemFdeMigrateArgs {
            target: target.to_string(),
            keyfile: keyfile.to_string(),
            execute,
        };
        let (msg, data) = match self
            .core
            .dispatch(Commands::System(SystemCommand::FdeMigrate(args)))
        {
            Ok(result) => result,
            Err(err) => {
                return self.show_message(
                    "Full Disk Encryption",
                    ["Failed to start", &shorten_for_display(&err.to_string(), 90)],
                );
            }
        };

        let stderr = data
            .get("stderr")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !stderr.trim().is_empty() {
            return self.show_message(
                "Full Disk Encryption",
                [shorten_for_display(stderr.trim(), 90)],
            );
        }

        let mut lines = vec![msg];
        if execute {
            lines.push("Reboot required".to_string());
        }
        self.show_message("Full Disk Encryption", lines)
    }

    pub(crate) fn set_webhook_encryption(&mut self, enable: bool, show_msg: bool) -> Result<()> {
        if enable && !self.config.settings.encryption_enabled {
            return self.show_message(
                "Encryption",
                ["Enable encryption first", "Toggle master encryption ON"],
            );
        }
        if !self.ensure_keyfile_available() {
            return Ok(());
        }

        let plain = self.root.join("discord_webhook.txt");
        let enc = self.root.join("discord_webhook.txt.enc");

        if enable {
            self.config.settings.encrypt_discord_webhook = true;
            if plain.exists() {
                let content =
                    fs::read(&plain).with_context(|| format!("reading {}", plain.display()))?;
                rustyjack_encryption::encrypt_to_file(&enc, &content)
                    .with_context(|| format!("encrypting {}", enc.display()))?;
                let mut content_mut = content.clone();
                content_mut.zeroize();
                fs::remove_file(&plain)
                    .with_context(|| format!("removing {}", plain.display()))?;
            }
        } else {
            self.config.settings.encrypt_discord_webhook = false;
            if enc.exists() {
                let bytes = rustyjack_encryption::decrypt_file(&enc)
                    .with_context(|| format!("decrypting {}", enc.display()))?;
                fs::write(&plain, &bytes)
                    .with_context(|| format!("writing {}", plain.display()))?;
                let mut tmp = bytes.clone();
                tmp.zeroize();
                let mut bytes_mut = bytes;
                bytes_mut.zeroize();
            }
        }

        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;
        if show_msg {
            let res = self.show_message(
                "Encryption",
                [format!(
                    "Webhook encryption {}",
                    if self.config.settings.encrypt_discord_webhook {
                        "ENABLED"
                    } else {
                        "DISABLED"
                    }
                )],
            );
            clear_encryption_key();
            return res;
        }
        clear_encryption_key();
        Ok(())
    }
}
