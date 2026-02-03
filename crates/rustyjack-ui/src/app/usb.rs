use std::{
    fs,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use rustyjack_commands::{
    Commands, ExportLogsToUsbArgs, SystemCommand, UsbMountArgs, UsbUnmountArgs,
};
use tempfile::{NamedTempFile, TempPath};
use walkdir::WalkDir;
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

use crate::util::shorten_for_display;

use super::state::{App, ButtonAction, MountEntry, UsbAccessRequirement, UsbDevice};

impl App {
    pub(crate) fn export_logs_to_usb(&mut self) -> Result<()> {
        let Some(device) = self.select_usb_partition("Export Logs")? else {
            return Ok(());
        };

        let status = self.stats.snapshot();
        self.display.draw_progress_dialog(
            "Export Logs",
            "Exporting logs...\nDo not remove USB",
            40.0,
            &status,
        )?;

        let args = ExportLogsToUsbArgs {
            device: device.name.clone(),
        };

        let result = self
            .core
            .dispatch(Commands::System(SystemCommand::ExportLogsToUsb(args)));

        match result {
            Ok((_msg, data)) => {
                let filename = data
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("rustyjack_logs.txt");

                self.display.draw_progress_dialog(
                    "Export Logs",
                    "Writing logs...\nDo not remove USB",
                    100.0,
                    &status,
                )?;

                let file_line = format!("Saved {}", shorten_for_display(filename, 24));
                let dev_line = format!("Device: {}", shorten_for_display(&device.name, 18));
                self.show_message("Export Logs", [file_line, dev_line])?;
            }
            Err(e) => {
                self.show_message(
                    "Export Logs",
                    ["Export failed", &shorten_for_display(&e.to_string(), 90)],
                )?;
            }
        }

        Ok(())
    }

    pub(crate) fn select_usb_partition(&mut self, title: &str) -> Result<Option<UsbDevice>> {
        let devices = match self.list_usb_partitions() {
            Ok(d) => d,
            Err(e) => {
                self.show_message(
                    title,
                    [
                        "Failed to list USB devices",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                )?;
                return Ok(None);
            }
        };

        if devices.is_empty() {
            self.show_message(
                title,
                ["No USB partitions detected", "Insert USB and retry"],
            )?;
            return Ok(None);
        }

        let labels: Vec<String> = devices
            .iter()
            .map(|d| format!("{}  {}  {}", d.name, d.size, d.model))
            .collect();

        let choice = if devices.len() == 1 {
            Some(0)
        } else {
            self.choose_from_list("Select USB device", &labels)?
        };

        let Some(choice) = choice else {
            return Ok(None);
        };

        Ok(Some(devices[choice].clone()))
    }

    pub(crate) fn transfer_to_usb(&mut self) -> Result<()> {
        // Find USB mount point
        let Some(usb_path) = self.select_usb_mount(UsbAccessRequirement::RequireWritable)? else {
            return Ok(());
        };

        let loot_dir = self.root.join("loot");

        if !loot_dir.exists() {
            self.show_message("USB Transfer", ["No loot to transfer"])?;
            return Ok(());
        }

        // Collect all files to transfer
        let mut files = Vec::new();
        if loot_dir.exists() {
            for entry in WalkDir::new(&loot_dir) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
        if files.is_empty() {
            self.show_message("USB Transfer", ["No files to transfer"])?;
            return Ok(());
        }

        let total_files = files.len();
        let status = self.stats.snapshot();

        // Transfer files with progress
        for (idx, file_path) in files.iter().enumerate() {
            let progress = ((idx + 1) as f32 / total_files as f32) * 100.0;

            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");

            self.display
                .draw_progress_dialog("USB Transfer", filename, progress, &status)?;

            // Determine destination path
            let dest = if file_path.starts_with(&loot_dir) {
                let rel = file_path.strip_prefix(&loot_dir).unwrap_or(file_path);
                usb_path.join("Rustyjack_Loot").join("loot").join(rel)
            } else {
                continue;
            };

            // Create destination directory
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            // Copy file
            fs::copy(file_path, &dest)?;
        }

        self.show_message(
            "USB Transfer",
            [
                &format!("Transferred {} files", total_files),
                "to USB drive",
            ],
        )?;

        Ok(())
    }

    /// Browse a USB drive and let the user pick a file. Returns None on cancel.
    pub(crate) fn browse_usb_for_file(
        &mut self,
        title: &str,
        allowed_ext: Option<&[&str]>,
    ) -> Result<Option<PathBuf>> {
        let Some(usb_root) = self.select_usb_mount(UsbAccessRequirement::ReadableOk)? else {
            return Ok(None);
        };

        let mut current = usb_root.clone();
        let mut stack: Vec<PathBuf> = Vec::new();
        let mut selection: usize = 0;

        loop {
            let mut entries: Vec<(String, PathBuf, bool)> = Vec::new();
            if let Ok(read) = fs::read_dir(&current) {
                for entry in read.flatten() {
                    let path = entry.path();
                    let is_dir = path.is_dir();
                    let name = entry.file_name().to_string_lossy().to_string();
                    entries.push((name, path, is_dir));
                }
            }
            // Sort dirs first, then files
            entries.sort_by(|a, b| {
                b.2.cmp(&a.2)
                    .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
            });

            // Build labels
            let labels: Vec<String> = if entries.is_empty() {
                vec!["<empty directory>".to_string()]
            } else {
                entries
                    .iter()
                    .map(|(name, _, is_dir)| {
                        if *is_dir {
                            format!("[DIR] {}", name)
                        } else {
                            name.clone()
                        }
                    })
                    .collect()
            };

            selection = selection.min(labels.len().saturating_sub(1));

            let path_label = shorten_for_display(current.to_string_lossy().as_ref(), 18);
            let status = self.stats.snapshot();
            self.display.draw_menu(
                &format!("{title} ({path_label})"),
                &labels,
                selection,
                &status,
            )?;

            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => {
                    if selection == 0 {
                        selection = labels.len().saturating_sub(1);
                    } else {
                        selection -= 1;
                    }
                }
                ButtonAction::Down => {
                    selection = (selection + 1) % labels.len().max(1);
                }
                ButtonAction::Select => {
                    if entries.is_empty() {
                        continue;
                    }
                    let (name, path, is_dir) = &entries[selection];
                    if *is_dir {
                        stack.push(current.clone());
                        current = path.clone();
                        selection = 0;
                        continue;
                    } else {
                        // Only allow configured file types if provided
                        if let Some(allowed) = allowed_ext {
                            let ext_ok = path
                                .extension()
                                .and_then(|e| e.to_str())
                                .map(|e| allowed.iter().any(|a| e.eq_ignore_ascii_case(a)))
                                .unwrap_or(false);
                            if !ext_ok {
                                self.show_message(
                                    "USB",
                                    [
                                        "Unsupported file type",
                                        &format!("{}", shorten_for_display(name, 18)),
                                        &format!("Allowed: {}", allowed.join(", ")),
                                    ],
                                )?;
                                continue;
                            }
                        }

                        let confirm_opts = vec![
                            format!("Use {}", shorten_for_display(name, 18)),
                            "Cancel".to_string(),
                        ];
                        if let Some(choice) = self.choose_from_list("Load file?", &confirm_opts)? {
                            if choice == 0 {
                                return Ok(Some(path.clone()));
                            }
                        }
                    }
                }
                ButtonAction::Back => {
                    if let Some(prev) = stack.pop() {
                        current = prev;
                        selection = 0;
                    } else {
                        let opts = vec!["Cancel import".to_string(), "Stay".to_string()];
                        if let Some(choice) = self.choose_from_list("Exit USB import?", &opts)? {
                            if choice == 0 {
                                return Ok(None);
                            }
                        }
                    }
                }
                ButtonAction::Cancel => return Ok(None),
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
                ButtonAction::Refresh => {}
            }
        }
    }

    pub(crate) fn select_usb_mount(
        &mut self,
        req: UsbAccessRequirement,
    ) -> Result<Option<PathBuf>> {
        let Some(device) = self.select_usb_partition("USB")? else {
            return Ok(None);
        };

        if let Some(path) = self.find_mount_for_device(&device.name, req)? {
            return Ok(Some(path));
        }

        if let Some(path) = self.mount_usb_device(&device, req)? {
            return Ok(Some(path));
        }

        let line = match req {
            UsbAccessRequirement::RequireWritable => "USB detected but not writable",
            UsbAccessRequirement::ReadableOk => "USB device detected but not mounted",
        };
        self.show_message("USB", [line, "Check filesystem and retry"])?;
        Ok(None)
    }

    pub(crate) fn find_mount_for_device(
        &self,
        device: &str,
        req: UsbAccessRequirement,
    ) -> Result<Option<PathBuf>> {
        let mount_root = self.root.join("mounts");
        let mounts = self.read_mount_points()?;
        for mount in mounts {
            if mount.device != device {
                continue;
            }
            let mount_path = Path::new(&mount.mount_point);
            if !mount_path.starts_with(&mount_root) {
                continue;
            }
            let path = mount_path.to_path_buf();
            if self.mount_access_ok(&path, req) {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    pub(crate) fn mount_usb_device(
        &mut self,
        device: &UsbDevice,
        req: UsbAccessRequirement,
    ) -> Result<Option<PathBuf>> {
        let dev_basename = Path::new(&device.name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&device.name);
        let request = UsbMountArgs {
            device: device.name.clone(),
            mode: req.mount_mode(),
            preferred_name: Some(dev_basename.to_string()),
        };

        match self
            .core
            .dispatch(Commands::System(SystemCommand::UsbMount(request)))
        {
            Ok((_, data)) => {
                let mountpoint = data
                    .get("mountpoint")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);
                let readonly = data
                    .get("readonly")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if let Some(mountpoint) = mountpoint {
                    if req.needs_write() && readonly {
                        self.core
                            .dispatch(Commands::System(SystemCommand::UsbUnmount(
                                UsbUnmountArgs {
                                    mountpoint: mountpoint.to_string_lossy().to_string(),
                                    detach: false,
                                },
                            )))
                            .with_context(|| {
                                format!("unmounting {} after readonly mount", mountpoint.display())
                            })?;
                        return Ok(None);
                    }
                    if self.mount_access_ok(&mountpoint, req) {
                        return Ok(Some(mountpoint));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Mount failed for {} (device={}): {}",
                    dev_basename,
                    device.name,
                    e
                );
                let err_msg = shorten_for_display(&e.to_string(), 120);
                self.show_message(
                    "USB Mount Failed",
                    [
                        "Mount failed:",
                        &err_msg,
                        "Fix: format USB as FAT32/ext4 or verify kernel filesystem support",
                    ],
                )?;
            }
        }

        Ok(None)
    }

    /// Read mount points from /proc/mounts
    pub(crate) fn read_mount_points(&self) -> Result<Vec<MountEntry>> {
        let contents = fs::read_to_string("/proc/mounts").context("Failed to read /proc/mounts")?;

        let mut mounts = Vec::new();
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let device = parts[0].to_string();

                // Only consider actual device mounts (not tmpfs, proc, etc.)
                if device.starts_with("/dev/") {
                    mounts.push(MountEntry {
                        device,
                        mount_point: Self::decode_proc_mount(parts[1]),
                        fs_type: parts[2].to_string(),
                        options: parts[3].to_string(),
                    });
                }
            }
        }

        Ok(mounts)
    }

    pub(crate) fn decode_proc_mount(value: &str) -> String {
        value
            .replace("\\134", "\\")
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
    }

    pub(crate) fn mount_entry_for(&self, mountpoint: &Path) -> Option<MountEntry> {
        let mount_str = mountpoint.to_string_lossy();
        self.read_mount_points()
            .ok()
            .and_then(|mounts| mounts.into_iter().find(|m| m.mount_point == mount_str))
    }

    pub(crate) fn mount_options_for(&self, mountpoint: &Path) -> Option<String> {
        self.mount_entry_for(mountpoint).map(|entry| entry.options)
    }

    pub(crate) fn is_readable_mount(&self, path: &Path) -> bool {
        if !path.is_dir() {
            return false;
        }
        self.mount_options_for(path)
            .map(|opts| opts.split(',').any(|o| o == "ro" || o == "rw"))
            .unwrap_or(false)
    }

    pub(crate) fn mount_access_ok(&self, path: &Path, req: UsbAccessRequirement) -> bool {
        match req {
            UsbAccessRequirement::ReadableOk => self.is_readable_mount(path),
            UsbAccessRequirement::RequireWritable => self.is_writable_mount(path),
        }
    }

    pub(crate) fn is_writable_mount(&self, path: &Path) -> bool {
        self.mount_options_for(path)
            .map(|opts| opts.split(',').any(|o| o == "rw"))
            .unwrap_or(false)
    }

    pub(crate) fn build_loot_archive(&self) -> Result<(TempPath, PathBuf)> {
        const MAX_LOOT_ARCHIVE_BYTES: u64 = 500 * 1024 * 1024;
        let mut temp = NamedTempFile::new()?;
        let mut total_bytes: u64 = 0;
        {
            let mut zip = ZipWriter::new(&mut temp);
            let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
            self.add_directory_to_zip(
                &mut zip,
                &self.root.join("loot"),
                "loot/",
                options.clone(),
                &mut total_bytes,
                MAX_LOOT_ARCHIVE_BYTES,
            )?;
            zip.finish()?;
        }
        let temp_path = temp.into_temp_path();
        let path = temp_path.to_path_buf();
        Ok((temp_path, path))
    }

    pub(crate) fn add_directory_to_zip(
        &self,
        zip: &mut ZipWriter<&mut NamedTempFile>,
        dir: &Path,
        prefix: &str,
        options: FileOptions,
        total_bytes: &mut u64,
        max_bytes: u64,
    ) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in WalkDir::new(dir) {
            let entry = entry?;
            let file_type = entry.file_type();
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_file() {
                let meta = entry.metadata()?;
                let size = meta.len();
                if total_bytes.saturating_add(size) > max_bytes {
                    bail!("Loot archive exceeds size cap ({} bytes).", max_bytes);
                }

                let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
                let mut name = PathBuf::from(prefix);
                name.push(rel);
                let name = name.to_string_lossy().replace('\\', "/");
                zip.start_file(name, options)?;
                let mut file = File::open(entry.path())?;
                std::io::copy(&mut file, zip)?;
                *total_bytes = total_bytes.saturating_add(size);
            }
        }
        Ok(())
    }
}
