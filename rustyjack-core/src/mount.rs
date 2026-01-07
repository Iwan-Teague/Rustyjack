use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsType {
    Vfat,
    Ext4,
    Exfat,
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct MountPolicy {
    pub mount_root: PathBuf,
    pub allowed_fs: BTreeSet<FsType>,
    pub default_mode: MountMode,
    pub allow_rw: bool,
    pub max_devices: usize,
    pub lock_timeout: Duration,
}

impl Default for MountPolicy {
    fn default() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(FsType::Vfat);
        allowed.insert(FsType::Ext4);
        allowed.insert(FsType::Exfat);
        Self {
            mount_root: PathBuf::from("/mnt/rustyjack"),
            allowed_fs: allowed,
            default_mode: MountMode::ReadOnly,
            allow_rw: false,
            max_devices: 4,
            lock_timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MountRequest {
    pub device: PathBuf,
    pub mode: MountMode,
    pub preferred_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MountResponse {
    pub device: PathBuf,
    pub mountpoint: PathBuf,
    pub fs_type: FsType,
    pub readonly: bool,
}

#[derive(Debug, Clone)]
pub struct UnmountRequest {
    pub mountpoint: PathBuf,
    pub detach: bool,
}

#[derive(Debug, Clone)]
pub struct BlockDevice {
    pub name: String,
    pub devnode: PathBuf,
    pub removable: bool,
    pub is_usb: bool,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub name: String,
    pub devnode: PathBuf,
    pub size_bytes: Option<u64>,
}

const MOUNT_LOCK_PATH: &str = "/run/rustyjack.mount.lock";

pub fn mount_device(policy: &MountPolicy, req: MountRequest) -> Result<MountResponse> {
    let _lock = MountLock::acquire(policy.lock_timeout)?;
    ensure_mount_root(policy)?;

    let device = canonical_device_path(&req.device)?;
    let dev_name = device
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid device path"))?;

    if !is_allowed_device(dev_name) {
        bail!("device not allowed: {}", dev_name);
    }

    ensure_block_device(&device)?;
    ensure_usb_removable(dev_name)?;

    if is_whole_disk(dev_name)? && has_partitions(dev_name)? {
        bail!("refusing to mount whole disk {} with partitions", dev_name);
    }

    let fs_type = detect_fs_type(&device)?;
    if !policy.allowed_fs.contains(&fs_type) {
        bail!("filesystem not allowed: {:?}", fs_type);
    }

    let existing = list_mounts_under(policy)?;
    for entry in &existing {
        if entry.device == device {
            return Ok(entry.clone());
        }
    }
    if existing.len() >= policy.max_devices {
        bail!("maximum mount count reached");
    }

    let mode = if policy.allow_rw {
        req.mode
    } else {
        policy.default_mode
    };

    let mount_name = sanitize_mount_name(req.preferred_name.as_deref(), dev_name);
    let mountpoint = policy.mount_root.join(&mount_name);

    if let Some(existing) = find_mount(&device, &mountpoint)? {
        return Ok(existing);
    }
    if is_mountpoint_in_use(&mountpoint)? {
        bail!("mountpoint already in use: {}", mountpoint.display());
    }

    let created = if !mountpoint.exists() {
        fs::create_dir_all(&mountpoint).with_context(|| {
            format!("creating mountpoint {}", mountpoint.display())
        })?;
        true
    } else {
        false
    };

    if let Err(err) = do_mount(&device, &mountpoint, &fs_type, mode) {
        if created {
            let _ = fs::remove_dir(&mountpoint);
        }
        return Err(err);
    }

    if let Some(entry) = find_mount(&device, &mountpoint)? {
        verify_mount_safety(&entry)?;
        return Ok(entry);
    }

    if created {
        let _ = fs::remove_dir(&mountpoint);
    }

    Err(anyhow!(
        "mount did not appear in mountinfo for {}",
        mountpoint.display()
    ))
}

pub fn unmount(policy: &MountPolicy, req: UnmountRequest) -> Result<()> {
    let _lock = MountLock::acquire(policy.lock_timeout)?;
    ensure_mount_root(policy)?;

    let mount_root = fs::canonicalize(&policy.mount_root)
        .with_context(|| format!("canonicalizing {}", policy.mount_root.display()))?;
    let mountpoint = fs::canonicalize(&req.mountpoint)
        .with_context(|| format!("canonicalizing {}", req.mountpoint.display()))?;

    if !mountpoint.starts_with(&mount_root) {
        bail!("mountpoint outside policy root");
    }

    let entry = find_mount_by_mountpoint(&mountpoint)?
        .ok_or_else(|| anyhow!("mountpoint not mounted"))?;

    do_unmount(&mountpoint, req.detach)?;

    if mountpoint.read_dir().map(|mut i| i.next().is_none()).unwrap_or(false) {
        let _ = fs::remove_dir(&mountpoint);
    }

    info!(
        "Unmounted {} from {}",
        entry.device.display(),
        mountpoint.display()
    );
    Ok(())
}

pub fn list_mounts_under(policy: &MountPolicy) -> Result<Vec<MountResponse>> {
    let mounts = read_mountinfo()?;
    let mut found = Vec::new();

    for m in mounts {
        if !m.mountpoint.starts_with(&policy.mount_root) {
            continue;
        }

        let fs_type = map_fs_type(&m.fstype);
        let readonly = m
            .options
            .iter()
            .any(|opt| opt == "ro" || opt == "rdonly");

        found.push(MountResponse {
            device: m.source.clone(),
            mountpoint: m.mountpoint.clone(),
            fs_type,
            readonly,
        });
    }

    Ok(found)
}

pub fn enumerate_usb_block_devices() -> Result<Vec<BlockDevice>> {
    let mut devices = Vec::new();
    let sys_block = Path::new("/sys/block");
    if !sys_block.exists() {
        return Ok(devices);
    }

    for entry in fs::read_dir(sys_block)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_allowed_device(&name) {
            continue;
        }

        let removable = read_sysfs_flag(entry.path().join("removable")).unwrap_or(false);
        let is_usb = sysfs_path_contains_usb(entry.path().join("device")).unwrap_or(false);

        if !removable || !is_usb {
            continue;
        }

        let mut dev = BlockDevice {
            name: name.clone(),
            devnode: PathBuf::from("/dev").join(&name),
            removable,
            is_usb,
            partitions: Vec::new(),
        };
        dev.partitions = enumerate_partitions(&dev)?;
        devices.push(dev);
    }

    Ok(devices)
}

pub fn enumerate_partitions(dev: &BlockDevice) -> Result<Vec<Partition>> {
    let sys_dev = Path::new("/sys/block").join(&dev.name);
    let mut partitions = Vec::new();
    if !sys_dev.exists() {
        return Ok(partitions);
    }

    if let Ok(entries) = fs::read_dir(&sys_dev) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == dev.name {
                continue;
            }
            if !name.starts_with(&dev.name) {
                continue;
            }
            let size_bytes = read_block_size_bytes(&name).ok();
            partitions.push(Partition {
                name: name.clone(),
                devnode: PathBuf::from("/dev").join(&name),
                size_bytes,
            });
        }
    }

    partitions.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(partitions)
}

pub fn is_allowed_device(name: &str) -> bool {
    !(name.starts_with("mmcblk") || name.starts_with("loop") || name.starts_with("ram"))
}

struct MountLock {
    _file: File,
}

impl MountLock {
    fn acquire(timeout: Duration) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(MOUNT_LOCK_PATH)
            .with_context(|| format!("opening {}", MOUNT_LOCK_PATH))?;

        let start = Instant::now();
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(Self { _file: file });
            }

            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK)
                || err.raw_os_error() == Some(libc::EAGAIN)
            {
                if start.elapsed() >= timeout {
                    bail!("mount lock busy");
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }

            return Err(err.into());
        }
    }
}

fn ensure_mount_root(policy: &MountPolicy) -> Result<()> {
    if policy.mount_root.as_os_str().is_empty() {
        bail!("mount_root not set");
    }
    if !policy.mount_root.exists() {
        fs::create_dir_all(&policy.mount_root)
            .with_context(|| format!("creating {}", policy.mount_root.display()))?;
    }
    if !policy.mount_root.is_dir() {
        bail!("mount_root is not a directory");
    }
    Ok(())
}

fn canonical_device_path(path: &Path) -> Result<PathBuf> {
    if !path.starts_with("/dev") {
        bail!("device path must be under /dev");
    }
    let dev = fs::canonicalize(path).with_context(|| format!("canonicalizing {}", path.display()))?;
    if !dev.starts_with("/dev") {
        bail!("device path resolved outside /dev");
    }
    Ok(dev)
}

fn ensure_block_device(path: &Path) -> Result<()> {
    let c_path = path_to_cstring(path)?;
    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::stat(c_path.as_ptr(), stat_buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("stat device");
    }
    let stat_buf = unsafe { stat_buf.assume_init() };
    let mode = stat_buf.st_mode & libc::S_IFMT;
    if mode != libc::S_IFBLK {
        bail!("not a block device");
    }
    Ok(())
}

fn ensure_usb_removable(dev_name: &str) -> Result<()> {
    let base = base_device_name(dev_name)?;
    let sys_base = Path::new("/sys/class/block").join(&base);
    let removable = read_sysfs_flag(sys_base.join("removable")).unwrap_or(false);
    if !removable {
        bail!("device not marked removable");
    }
    let is_usb = sysfs_path_contains_usb(sys_base.join("device")).unwrap_or(false);
    if !is_usb {
        bail!("device not on USB path");
    }
    Ok(())
}

fn base_device_name(dev_name: &str) -> Result<String> {
    let sys_path = Path::new("/sys/class/block").join(dev_name);
    let real = fs::canonicalize(&sys_path)
        .with_context(|| format!("resolving {}", sys_path.display()))?;
    let part_flag = sys_path.join("partition").exists();
    if part_flag {
        let parent = real
            .parent()
            .ok_or_else(|| anyhow!("missing parent for {}", dev_name))?;
        let name = parent
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("invalid parent name"))?;
        return Ok(name.to_string());
    }
    let name = real
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid device name"))?;
    Ok(name.to_string())
}

fn is_whole_disk(dev_name: &str) -> Result<bool> {
    let sys_path = Path::new("/sys/class/block").join(dev_name);
    Ok(!sys_path.join("partition").exists())
}

fn has_partitions(dev_name: &str) -> Result<bool> {
    let sys_dev = Path::new("/sys/class/block").join(dev_name);
    if !sys_dev.exists() {
        return Ok(false);
    }
    if let Ok(entries) = fs::read_dir(&sys_dev) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(dev_name) && name != dev_name {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn detect_fs_type(device: &Path) -> Result<FsType> {
    let mut file = File::open(device)
        .with_context(|| format!("opening device {}", device.display()))?;
    let mut buf = vec![0u8; 2048];
    file.read_exact(&mut buf)
        .with_context(|| "reading device header")?;

    if is_ext4(&buf) {
        return Ok(FsType::Ext4);
    }
    if is_exfat(&buf) {
        return Ok(FsType::Exfat);
    }
    if is_vfat(&buf) {
        return Ok(FsType::Vfat);
    }

    Err(anyhow!("unsupported or unknown filesystem"))
}

fn is_ext4(buf: &[u8]) -> bool {
    if buf.len() < 0x400 + 0x3a {
        return false;
    }
    let magic = u16::from_le_bytes([buf[0x438], buf[0x439]]);
    magic == 0xEF53
}

fn is_exfat(buf: &[u8]) -> bool {
    if buf.len() < 11 {
        return false;
    }
    &buf[3..11] == b"EXFAT   "
}

fn is_vfat(buf: &[u8]) -> bool {
    if buf.len() < 90 {
        return false;
    }
    let fat16 = &buf[54..62];
    let fat32 = &buf[82..90];
    fat16 == b"FAT16   " || fat16 == b"FAT12   " || fat32 == b"FAT32   "
}

fn do_mount(device: &Path, target: &Path, fs: &FsType, mode: MountMode) -> Result<()> {
    let src = path_to_cstring(device)?;
    let tgt = path_to_cstring(target)?;
    let fstype = CString::new(match fs {
        FsType::Vfat => "vfat",
        FsType::Ext4 => "ext4",
        FsType::Exfat => "exfat",
        FsType::Unknown(_) => bail!("fs type not allowed"),
    })?;

    let mut flags: libc::c_ulong =
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong;
    if mode == MountMode::ReadOnly {
        flags |= libc::MS_RDONLY as libc::c_ulong;
    }

    let data_str = match fs {
        FsType::Vfat | FsType::Exfat => "utf8,uid=0,gid=0,fmask=0077,dmask=0077",
        FsType::Ext4 => "errors=remount-ro",
        FsType::Unknown(_) => "",
    };
    let data = CString::new(data_str)?;

    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.as_ptr() as *const _,
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "mount(2) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn do_unmount(target: &Path, detach: bool) -> Result<()> {
    let tgt = path_to_cstring(target)?;
    let flags = if detach { libc::MNT_DETACH } else { 0 };
    let rc = unsafe { libc::umount2(tgt.as_ptr(), flags) };
    if rc != 0 {
        return Err(anyhow!(
            "umount2 failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct MountInfo {
    mountpoint: PathBuf,
    source: PathBuf,
    fstype: String,
    options: Vec<String>,
}

fn read_mountinfo() -> Result<Vec<MountInfo>> {
    let contents =
        fs::read_to_string("/proc/self/mountinfo").context("reading mountinfo")?;
    let mut mounts = Vec::new();
    for line in contents.lines() {
        if let Some((left, right)) = line.split_once(" - ") {
            let left_parts: Vec<&str> = left.split_whitespace().collect();
            if left_parts.len() < 6 {
                continue;
            }
            let mountpoint = decode_mount_escape(left_parts[4]);
            let options = left_parts[5]
                .split(',')
                .map(|s| s.to_string())
                .collect::<Vec<_>>();

            let right_parts: Vec<&str> = right.split_whitespace().collect();
            if right_parts.len() < 3 {
                continue;
            }
            let fstype = right_parts[0].to_string();
            let source = decode_mount_escape(right_parts[1]);

            mounts.push(MountInfo {
                mountpoint: PathBuf::from(mountpoint),
                source: PathBuf::from(source),
                fstype,
                options,
            });
        }
    }
    Ok(mounts)
}

fn find_mount(device: &Path, mountpoint: &Path) -> Result<Option<MountResponse>> {
    let mounts = read_mountinfo()?;
    for m in mounts {
        if m.mountpoint == mountpoint && m.source == device {
            let fs_type = map_fs_type(&m.fstype);
            let readonly = m
                .options
                .iter()
                .any(|opt| opt == "ro" || opt == "rdonly");
            return Ok(Some(MountResponse {
                device: m.source,
                mountpoint: m.mountpoint,
                fs_type,
                readonly,
            }));
        }
    }
    Ok(None)
}

fn find_mount_by_mountpoint(mountpoint: &Path) -> Result<Option<MountResponse>> {
    let mounts = read_mountinfo()?;
    for m in mounts {
        if m.mountpoint == mountpoint {
            let fs_type = map_fs_type(&m.fstype);
            let readonly = m
                .options
                .iter()
                .any(|opt| opt == "ro" || opt == "rdonly");
            return Ok(Some(MountResponse {
                device: m.source,
                mountpoint: m.mountpoint,
                fs_type,
                readonly,
            }));
        }
    }
    Ok(None)
}

fn is_mountpoint_in_use(mountpoint: &Path) -> Result<bool> {
    let mounts = read_mountinfo()?;
    Ok(mounts.iter().any(|m| m.mountpoint == mountpoint))
}

fn verify_mount_safety(entry: &MountResponse) -> Result<()> {
    let mounts = read_mountinfo()?;
    let m = mounts
        .into_iter()
        .find(|m| m.mountpoint == entry.mountpoint && m.source == entry.device)
        .ok_or_else(|| anyhow!("mount not found for verification"))?;

    let required = ["nosuid", "nodev", "noexec"];
    for opt in required {
        if !m.options.iter().any(|o| o == opt) {
            bail!("mount missing required option: {}", opt);
        }
    }
    Ok(())
}

fn map_fs_type(fs: &str) -> FsType {
    match fs.to_lowercase().as_str() {
        "vfat" => FsType::Vfat,
        "ext4" => FsType::Ext4,
        "exfat" => FsType::Exfat,
        other => FsType::Unknown(other.to_string()),
    }
}

fn decode_mount_escape(value: &str) -> String {
    value
        .replace("\\134", "\\")
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
}

fn sanitize_mount_name(preferred: Option<&str>, dev_name: &str) -> String {
    let raw = preferred.unwrap_or(dev_name);
    let filtered: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if filtered.is_empty() {
        dev_name.to_string()
    } else {
        filtered.chars().take(32).collect()
    }
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("invalid path for C string"))
}

fn read_sysfs_flag(path: PathBuf) -> Result<bool> {
    let contents = fs::read_to_string(path)?;
    Ok(contents.trim() == "1")
}

fn sysfs_path_contains_usb(path: PathBuf) -> Result<bool> {
    let target = fs::read_link(&path)?;
    Ok(target.to_string_lossy().to_lowercase().contains("/usb"))
}

fn read_block_size_bytes(name: &str) -> Result<u64> {
    let size_path = Path::new("/sys/class/block").join(name).join("size");
    let sectors = fs::read_to_string(size_path)?
        .trim()
        .parse::<u64>()
        .context("parsing size sectors")?;
    Ok(sectors * 512)
}
