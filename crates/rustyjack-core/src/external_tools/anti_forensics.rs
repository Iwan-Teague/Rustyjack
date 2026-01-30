use std::{
    ffi::CString,
    fs,
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use tar::{Archive, Builder};
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use zeroize::Zeroize;

const ENC_MAGIC: &[u8; 6] = b"RJENC1";
const ENC_SALT_LEN_GCM: usize = 16;
const ENC_NONCE_LEN_GCM: usize = 12;
const ENC_PBKDF2_ITERS: u32 = 10_000;
const OPENSSL_MAGIC: &[u8; 8] = b"Salted__";
const OPENSSL_SALT_LEN: usize = 8;
const OPENSSL_KEY_LEN: usize = 32;
const OPENSSL_IV_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiForensicsConfig {
    pub secure_delete_passes: u8,
    pub clear_logs_on_exit: bool,
    pub ram_only_mode: bool,
    pub encrypt_loot: bool,
    pub anti_dump_protection: bool,
    pub hide_processes: bool,
    pub randomize_hostname: bool,
    pub disable_leds: bool,
    pub disable_swap: bool,
}

impl Default for AntiForensicsConfig {
    fn default() -> Self {
        Self {
            secure_delete_passes: 7, // DoD 5220.22-M standard
            clear_logs_on_exit: true,
            ram_only_mode: false,
            encrypt_loot: false,
            anti_dump_protection: false,
            hide_processes: false,
            randomize_hostname: false,
            disable_leds: false,
            disable_swap: false,
        }
    }
}

/// Securely delete a file using multiple overwrite passes
pub fn secure_delete(path: &Path, passes: u8) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    info!(
        "Securely deleting {} with {} passes",
        path.display(),
        passes
    );

    // Use Rust-only overwrite to avoid external binaries.
    manual_secure_delete(path, passes)?;

    info!("File securely deleted: {}", path.display());
    Ok(())
}

/// Manual secure deletion implementation
fn manual_secure_delete(path: &Path, passes: u8) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let metadata = fs::metadata(path)?;
    let size = metadata.len() as usize;

    let mut file = fs::OpenOptions::new().write(true).open(path)?;

    // Pattern array for DoD standard
    let patterns: Vec<Vec<u8>> = vec![
        vec![0xFF; size], // All 1s
        vec![0x00; size], // All 0s
        vec![0xFF; size], // All 1s
        vec![0x00; size], // All 0s
        vec![0xFF; size], // All 1s
        vec![0x00; size], // All 0s
        vec![0x00; size], // Final zeros
    ];

    for (i, pattern) in patterns.iter().enumerate().take(passes as usize) {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(pattern)?;
        file.sync_all()?;
        debug!("Overwrite pass {}/{}", i + 1, passes);
    }

    drop(file);
    fs::remove_file(path)?;

    Ok(())
}

/// Securely delete a directory recursively
pub fn secure_delete_dir(path: &Path, passes: u8) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    info!("Securely deleting directory: {}", path.display());

    // Delete all files first
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            secure_delete(entry.path(), passes)?;
        }
    }

    // Remove empty directories
    fs::remove_dir_all(path)?;

    Ok(())
}

/// Clear system logs that might contain evidence
pub fn clear_system_logs() -> Result<()> {
    info!("Clearing system logs");

    let log_files = vec![
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
    ];

    for log in log_files {
        if Path::new(log).exists() {
            // Truncate instead of delete (less suspicious)
            if let Err(e) = fs::write(log, "") {
                warn!("Failed to clear {}: {}", log, e);
            } else {
                debug!("Cleared {}", log);
            }
        }
    }

    // Clear bash history
    if let Ok(home) = std::env::var("HOME") {
        let bash_history = PathBuf::from(home).join(".bash_history");
        if bash_history.exists() {
            let _ = fs::write(bash_history, "");
        }
    }

    warn!("Skipping systemd journal vacuum in rust-only mode");

    info!("System logs cleared");
    Ok(())
}

/// Clear application-specific logs
pub fn clear_app_logs(root: &Path) -> Result<()> {
    info!("Clearing application logs");

    let log_locations = vec![
        root.join("logs"),
        PathBuf::from("/var/log/rustyjack"),
        PathBuf::from("/tmp/rustyjack"),
    ];

    for location in log_locations {
        if location.exists() {
            secure_delete_dir(&location, 3)?;
        }
    }

    Ok(())
}

/// Wipe network connection history
pub fn clear_network_history() -> Result<()> {
    info!("Clearing network connection history");

    let network_files = vec![
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/NetworkManager",
        "/etc/NetworkManager/system-connections",
    ];

    for file in network_files {
        let path = Path::new(file);
        if path.exists() {
            if path.is_dir() {
                let _ = secure_delete_dir(path, 3);
            } else {
                let _ = secure_delete(path, 3);
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeReport {
    pub removed: usize,
    pub service_disabled: bool,
    pub errors: Vec<String>,
}

/// Remove Rustyjack artifacts from the system and return a summary of actions taken.
pub fn perform_complete_purge(root: &Path) -> PurgeReport {
    let mut removed = 0usize;
    let mut errors = Vec::new();
    let mut service_disabled = false;

    let _ = std::env::set_current_dir("/tmp");

    let mut delete_path = |path: &Path| {
        if !path.exists() {
            return;
        }
        if path == Path::new("/") {
            errors.push("Refused to delete /".to_string());
            return;
        }
        let res = if path.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
        match res {
            Ok(_) => removed += 1,
            Err(e) => errors.push(format!("{}: {}", path.display(), e)),
        }
    };

    let system_paths = [
        PathBuf::from("/usr/local/bin/rustyjack-ui"),
        PathBuf::from("/etc/systemd/system/rustyjack.service"),
        PathBuf::from("/etc/systemd/system/multi-user.target.wants/rustyjack.service"),
        PathBuf::from("/etc/udev/rules.d/99-rustyjack-wifi.rules"),
    ];
    for path in system_paths.iter() {
        delete_path(path);
    }

    let data_paths = [
        root.join("loot"),
        root.join("wifi"),
        root.join("scripts"),
        root.join("target"),
        root.to_path_buf(),
    ];
    for path in data_paths.iter() {
        delete_path(path);
    }

    // Drop closure to release borrow on errors
    drop(delete_path);

    service_disabled = !Path::new("/etc/systemd/system/multi-user.target.wants/rustyjack.service")
        .exists();
    if !service_disabled {
        errors.push("systemd unit link still present (manual disable required)".to_string());
    }

    for entry in WalkDir::new("/var/log").into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let path = entry.path();
            match fs::remove_file(path) {
                Ok(_) => removed += 1,
                Err(e) => errors.push(format!("{}: {}", path.display(), e)),
            }
        }
    }

    unsafe {
        libc::sync();
    }

    PurgeReport {
        removed,
        service_disabled,
        errors,
    }
}

/// Clear DNS cache
pub fn clear_dns_cache() -> Result<()> {
    info!("Clearing DNS cache");
    warn!("DNS cache clearing requires systemd DBus integration; skipping in rust-only mode");

    Ok(())
}

/// Enable RAM-only mode (tmpfs for sensitive data)
pub fn enable_ram_only_mode(_root: &Path) -> Result<()> {
    info!("Enabling RAM-only mode");

    let ram_dir = Path::new("/tmp/rustyjack_ram");

    // Create tmpfs mount
    fs::create_dir_all(ram_dir)?;

    let ram_dir_str = ram_dir
        .to_str()
        .ok_or_else(|| anyhow!("ram dir must be valid UTF-8"))?;
    let source = CString::new("tmpfs")?;
    let target = CString::new(ram_dir_str)?;
    let fstype = CString::new("tmpfs")?;
    let data = CString::new("size=500M,mode=0700")?;
    let res = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            data.as_ptr() as *const _,
        )
    };
    if res != 0 {
        return Err(anyhow!(
            "mount tmpfs failed: {}",
            io::Error::last_os_error()
        ));
    }

    info!("RAM-only mode enabled at {}", ram_dir.display());
    Ok(())
}

/// Disable RAM-only mode and wipe memory
pub fn disable_ram_only_mode() -> Result<()> {
    info!("Disabling RAM-only mode");

    let ram_dir = Path::new("/tmp/rustyjack_ram");

    if ram_dir.exists() {
        // Wipe data before unmounting
        secure_delete_dir(ram_dir, 1)?;

        let ram_dir_str = ram_dir
            .to_str()
            .ok_or_else(|| anyhow!("ram dir must be valid UTF-8"))?;
        let target = CString::new(ram_dir_str)?;
        let res = unsafe { libc::umount2(target.as_ptr(), 0) };
        if res != 0 {
            return Err(anyhow!(
                "unmount tmpfs failed: {}",
                io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

/// Encrypt loot directory
pub fn encrypt_loot(root: &Path, password: &str) -> Result<()> {
    info!("Encrypting loot directory");

    let loot_dir = root.join("loot");
    if !loot_dir.exists() {
        return Ok(());
    }

    let archive = root.join("loot.tar.gz.enc");

    let tar_path = root.join("loot.tar.gz");
    create_tar_gz(&loot_dir, &tar_path).context("creating loot archive")?;
    let tar_bytes = fs::read(&tar_path).context("reading loot archive")?;
    let enc = encrypt_bytes_with_password(password, &tar_bytes)?;
    fs::write(&archive, enc).context("writing encrypted loot")?;
    let _ = fs::remove_file(&tar_path);

    // Securely delete original
    secure_delete_dir(&loot_dir, 3)?;

    info!("Loot encrypted to {}", archive.display());
    Ok(())
}

/// Decrypt loot directory
pub fn decrypt_loot(root: &Path, password: &str) -> Result<()> {
    info!("Decrypting loot directory");

    let archive = root.join("loot.tar.gz.enc");
    if !archive.exists() {
        return Err(anyhow!("Encrypted loot not found"));
    }

    let tar_path = root.join("loot.tar.gz");
    let enc = fs::read(&archive).context("reading encrypted loot")?;
    let tar_bytes = decrypt_bytes_with_password(password, &enc)?;
    fs::write(&tar_path, tar_bytes).context("writing loot archive")?;
    extract_tar_gz(&tar_path, root).context("extracting loot archive")?;
    let _ = fs::remove_file(&tar_path);

    info!("Loot decrypted successfully");
    Ok(())
}

/// Anti-memory dump protection
pub fn enable_anti_dump_protection() -> Result<()> {
    info!("Enabling anti-memory dump protection");

    // Prevent core dumps
    #[cfg(target_os = "linux")]
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
            warn!(
                "Failed to set RLIMIT_CORE: {}",
                io::Error::last_os_error()
            );
        }
    }

    // Disable ptrace for this process (prevents debugging)
    #[cfg(target_os = "linux")]
    {
        // PR_SET_DUMPABLE = 4
        unsafe {
            libc::prctl(4, 0, 0, 0, 0);
        }
    }

    info!("Anti-dump protection enabled");
    Ok(())
}

/// Hide process from process list (requires root)
pub fn hide_process() -> Result<()> {
    info!("Attempting to hide process");

    // This is a simplified approach - real rootkit would be more complex
    // Option 1: Use libprocesshider.so (LD_PRELOAD)
    // Option 2: Rename process to common system process

    // Rename to look like system process
    let new_name = "[kworker/0:0]";

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;

        let name = CString::new(new_name).unwrap();
        unsafe {
            // PR_SET_NAME = 15
            libc::prctl(15, name.as_ptr(), 0, 0, 0);
        }
    }

    info!("Process renamed to {}", new_name);
    Ok(())
}

/// Sanitize file metadata (remove exif, timestamps, etc.)
pub fn sanitize_file_metadata(path: &Path) -> Result<()> {
    info!("Sanitizing metadata for {}", path.display());

    warn!("Metadata stripping skipped (exiftool removed). Only timestamps will be reset.");

    // Reset timestamps to epoch
    let epoch = SystemTime::UNIX_EPOCH;
    filetime::set_file_mtime(path, filetime::FileTime::from_system_time(epoch))?;
    filetime::set_file_atime(path, filetime::FileTime::from_system_time(epoch))?;

    Ok(())
}

/// Clear ARP cache
pub fn clear_arp_cache() -> Result<()> {
    info!("Clearing ARP cache");

    #[cfg(target_os = "linux")]
    {
        use std::io;
        use std::mem;

        fn delete_arp_entry(ip: std::net::Ipv4Addr) -> io::Result<()> {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut req: libc::arpreq = unsafe { mem::zeroed() };
            let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
            addr.sin_family = libc::AF_INET as u16;
            addr.sin_addr.s_addr = u32::from_be_bytes(ip.octets());

            unsafe {
                std::ptr::copy_nonoverlapping(
                    &addr as *const _ as *const u8,
                    &mut req.arp_pa as *mut _ as *mut u8,
                    mem::size_of::<libc::sockaddr_in>(),
                );
            }

            let res = unsafe { libc::ioctl(fd, libc::SIOCDARP, &req) };
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }

            if res < 0 {
                return Err(err);
            }
            Ok(())
        }

        if let Ok(contents) = std::fs::read_to_string("/proc/net/arp") {
            for (idx, line) in contents.lines().enumerate() {
                if idx == 0 {
                    continue;
                }
                let mut parts = line.split_whitespace();
                if let Some(ip_str) = parts.next() {
                    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                        if let Err(err) = delete_arp_entry(ip) {
                            tracing::debug!("Failed to delete ARP entry {}: {}", ip, err);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Clear routing table entries
pub fn clear_routing_artifacts() -> Result<()> {
    info!("Clearing routing artifacts");

    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::write("/proc/sys/net/ipv4/route/flush", "1");
    }

    Ok(())
}

/// Dead man's switch - wipe everything if trigger file missing
pub fn check_dead_mans_switch(root: &Path, trigger_file: &Path) -> Result<()> {
    if !trigger_file.exists() {
        warn!("Dead man's switch triggered! Wiping data...");
        emergency_wipe(root)?;

        // Shutdown system
        poweroff_now();
    }

    Ok(())
}

/// Emergency wipe - fast but secure cleanup
pub fn emergency_wipe(root: &Path) -> Result<()> {
    warn!("EMERGENCY WIPE INITIATED");

    // Wipe sensitive directories
    let sensitive_dirs = vec![
        root.join("loot"),
        root.join("wifi"),
        root.join("logs"),
        Path::new("/tmp/rustyjack_ram").to_path_buf(),
    ];

    for dir in sensitive_dirs {
        if dir.exists() {
            secure_delete_dir(&dir, 3)?;
        }
    }

    // Clear all logs
    clear_system_logs()?;
    clear_app_logs(root)?;
    clear_network_history()?;

    // Clear caches
    clear_dns_cache()?;
    clear_arp_cache()?;

    warn!("Emergency wipe complete");
    Ok(())
}

/// Comprehensive cleanup on exit
pub fn cleanup_on_exit(root: &Path, config: &AntiForensicsConfig) -> Result<()> {
    info!("Performing cleanup on exit");

    if config.clear_logs_on_exit {
        clear_app_logs(root)?;
    }

    if config.ram_only_mode {
        disable_ram_only_mode()?;
    }

    // Clear network artifacts
    clear_arp_cache()?;
    clear_dns_cache()?;
    clear_routing_artifacts()?;

    // Restore original MAC addresses
    let mut state_mgr = rustyjack_evasion::StateManager::new();
    let interfaces: Vec<String> = state_mgr
        .modified_interfaces()
        .iter()
        .map(|s| s.to_string())
        .collect();
    for interface in interfaces {
        let _ = state_mgr.restore(&interface);
    }

    info!("Cleanup complete");
    Ok(())
}

/// Create encrypted backup before risky operations
pub fn create_safety_backup(root: &Path, password: &str) -> Result<PathBuf> {
    info!("Creating safety backup");

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_file = root.join(format!("backup_{}.enc", timestamp));

    let loot_dir = root.join("loot");
    let tar_path = root.join("backup.tar.gz");
    create_tar_gz(&loot_dir, &tar_path).context("creating backup archive")?;
    let tar_bytes = fs::read(&tar_path).context("reading backup archive")?;
    let enc = encrypt_bytes_with_password(password, &tar_bytes)?;
    fs::write(&backup_file, enc).context("writing encrypted backup")?;
    let _ = fs::remove_file(&tar_path);

    info!("Safety backup created: {}", backup_file.display());
    Ok(backup_file)
}

/// Verify system is clean (no artifacts remaining)
pub fn verify_clean() -> Result<Vec<String>> {
    let mut artifacts = Vec::new();

    // Check for common artifacts
    let suspicious_files = vec![
        "/tmp/rustyjack",
        "/var/log/rustyjack",
        "/root/.bash_history",
    ];

    for file in suspicious_files {
        if Path::new(file).exists() {
            artifacts.push(file.to_string());
        }
    }

    // Check for suspicious processes without spawning ps.
    if process_list_contains("rustyjack")? {
        artifacts.push("Suspicious processes found".to_string());
    }

    if artifacts.is_empty() {
        info!("System verified clean");
    } else {
        warn!("Artifacts found: {:?}", artifacts);
    }

    Ok(artifacts)
}

/// Randomize system hostname to avoid identification
pub fn randomize_hostname() -> Result<String> {
    info!("Randomizing hostname");

    let mut rng = rand::thread_rng();
    use rand::Rng;

    // Generate a random generic name
    let prefixes = ["desktop", "laptop", "win", "pc", "workstation"];
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    let suffix: u32 = rng.gen_range(1000..9999);
    let new_hostname = format!("{}-{}", prefix, suffix);

    // Set hostname without spawning hostnamectl.
    set_hostname(&new_hostname).context("setting hostname")?;
    fs::write("/etc/hostname", format!("{new_hostname}\n"))
        .context("writing /etc/hostname")?;

    // Update /etc/hosts to prevent sudo warnings
    let hosts_path = Path::new("/etc/hosts");
    if hosts_path.exists() {
        let hosts_content = fs::read_to_string(hosts_path)?;
        let mut new_lines = Vec::new();

        for line in hosts_content.lines() {
            if line.starts_with("127.0.1.1") {
                new_lines.push(format!("127.0.1.1\t{}", new_hostname));
            } else {
                new_lines.push(line.to_string());
            }
        }

        fs::write(hosts_path, new_lines.join("\n"))?;
    }

    info!("Hostname changed to {}", new_hostname);
    Ok(new_hostname)
}

/// Disable system LEDs to reduce physical visibility
pub fn disable_leds() -> Result<()> {
    info!("Disabling system LEDs");

    // Raspberry Pi specific LED paths
    let led_paths = vec![
        "/sys/class/leds/led0/brightness", // Activity LED
        "/sys/class/leds/led1/brightness", // Power LED
        "/sys/class/leds/pwr_led/brightness",
        "/sys/class/leds/act_led/brightness",
    ];

    for path_str in led_paths {
        let path = Path::new(path_str);
        if path.exists() {
            // Try to set brightness to 0
            if let Err(e) = fs::write(path, "0") {
                // Sometimes we need to set trigger to none first
                let trigger_path = path.parent().unwrap().join("trigger");
                if trigger_path.exists() {
                    let _ = fs::write(trigger_path, "none");
                }
                // Try writing 0 again
                let _ = fs::write(path, "0");
                debug!("Failed to disable LED at {}: {}", path_str, e);
            }
        }
    }

    Ok(())
}

/// Disable swap to prevent sensitive data hitting disk
pub fn disable_swap() -> Result<()> {
    info!("Disabling swap");

    disable_swap_all();

    Ok(())
}

fn create_tar_gz(src_dir: &Path, out_path: &Path) -> Result<()> {
    let tar_gz = fs::File::create(out_path).context("creating tarball")?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = Builder::new(enc);
    let archive_root = archive_root_name(src_dir)?;
    tar.append_dir_all(&archive_root, src_dir)
        .context("adding directory to tarball")?;
    let enc = tar.into_inner().context("finalizing tarball")?;
    enc.finish().context("writing tarball")?;
    Ok(())
}

fn extract_tar_gz(archive_path: &Path, dest: &Path) -> Result<()> {
    let tar_gz = fs::File::open(archive_path).context("opening tarball")?;
    let dec = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(dec);
    archive.unpack(dest).context("extracting tarball")?;
    Ok(())
}

fn archive_root_name(dir: &Path) -> Result<PathBuf> {
    let name = dir
        .file_name()
        .ok_or_else(|| anyhow!("archive source must have a terminal directory name"))?;
    Ok(PathBuf::from(name))
}

fn encrypt_bytes_with_password(password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    // OpenSSL-compatible AES-256-CBC with PBKDF2 and "Salted__" header.
    let mut salt = [0u8; OPENSSL_SALT_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    let mut key_iv = [0u8; OPENSSL_KEY_LEN + OPENSSL_IV_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ENC_PBKDF2_ITERS, &mut key_iv);
    let (key, iv) = key_iv.split_at(OPENSSL_KEY_LEN);
    let ciphertext = Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| anyhow!("Invalid encryption key/iv"))?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    key_iv.zeroize();

    let mut out = Vec::with_capacity(OPENSSL_MAGIC.len() + OPENSSL_SALT_LEN + ciphertext.len());
    out.extend_from_slice(OPENSSL_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_bytes_with_password(password: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.starts_with(OPENSSL_MAGIC) {
        return decrypt_openssl_bytes(password, data);
    }
    if data.starts_with(ENC_MAGIC) {
        return decrypt_rjenc_bytes(password, data);
    }
    Err(anyhow!("Invalid encrypted data header"))
}

fn decrypt_openssl_bytes(password: &str, data: &[u8]) -> Result<Vec<u8>> {
    let header_len = OPENSSL_MAGIC.len() + OPENSSL_SALT_LEN;
    if data.len() < header_len {
        return Err(anyhow!("Encrypted data too short"));
    }
    let salt = &data[OPENSSL_MAGIC.len()..header_len];
    let ct = &data[header_len..];
    let mut key_iv = [0u8; OPENSSL_KEY_LEN + OPENSSL_IV_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ENC_PBKDF2_ITERS, &mut key_iv);
    let (key, iv) = key_iv.split_at(OPENSSL_KEY_LEN);
    let mut buf = ct.to_vec();
    let plaintext = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| anyhow!("Invalid decryption key/iv"))?
        .decrypt_padded_vec_mut::<Pkcs7>(&mut buf)
        .map_err(|_| anyhow!("Decryption failed: wrong password or corrupted data"))?;
    key_iv.zeroize();
    Ok(plaintext)
}

fn decrypt_rjenc_bytes(password: &str, data: &[u8]) -> Result<Vec<u8>> {
    let header_len = ENC_MAGIC.len() + ENC_SALT_LEN_GCM + ENC_NONCE_LEN_GCM;
    if data.len() < header_len {
        return Err(anyhow!("Encrypted data too short"));
    }
    let salt_start = ENC_MAGIC.len();
    let nonce_start = salt_start + ENC_SALT_LEN_GCM;
    let ct_start = nonce_start + ENC_NONCE_LEN_GCM;
    let salt = &data[salt_start..nonce_start];
    let nonce_bytes = &data[nonce_start..ct_start];
    let ct = &data[ct_start..];
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ENC_PBKDF2_ITERS, &mut key);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Invalid encryption key: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow!("Decryption failed: {e}"))?;
    key.zeroize();
    Ok(plaintext)
}

fn poweroff_now() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::sync();
        if libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) != 0 {
            warn!("Poweroff failed: {}", io::Error::last_os_error());
        }
    }
}

fn process_list_contains(needle: &str) -> Result<bool> {
    let proc_dir = fs::read_dir("/proc").context("reading /proc")?;
    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let cmdline_path = entry.path().join("cmdline");
        let Ok(cmdline) = fs::read(cmdline_path) else {
            continue;
        };
        let mut text = String::from_utf8_lossy(&cmdline).to_string();
        if text.is_empty() {
            let comm_path = entry.path().join("comm");
            if let Ok(comm) = fs::read_to_string(comm_path) {
                text = comm;
            }
        }
        let text = text.replace('\0', " ");
        if text.contains(needle) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn set_hostname(name: &str) -> Result<()> {
    let cname = CString::new(name)?;
    let res = unsafe { libc::sethostname(cname.as_ptr(), name.len()) };
    if res != 0 {
        return Err(anyhow!(
            "sethostname failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn disable_swap_all() {
    let Ok(contents) = fs::read_to_string("/proc/swaps") else {
        return;
    };
    for (idx, line) in contents.lines().enumerate() {
        if idx == 0 {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(path) = parts.next() else {
            continue;
        };
        let Ok(cpath) = CString::new(path) else {
            continue;
        };
        unsafe {
            if libc::swapoff(cpath.as_ptr()) != 0 {
                warn!("swapoff {} failed: {}", path, io::Error::last_os_error());
            }
        }
    }
}
