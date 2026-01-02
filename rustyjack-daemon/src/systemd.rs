use std::env;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;

use log::warn;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio::time;

use crate::config::DaemonConfig;

pub fn listener_or_bind(config: &DaemonConfig) -> io::Result<UnixListener> {
    if let Some(listener) = systemd_listener()? {
        return Ok(listener);
    }
    bind_socket(&config.socket_path, config.socket_group.as_deref())
}

fn systemd_listener() -> io::Result<Option<UnixListener>> {
    let listen_pid = env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let listen_fds = env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok());

    if listen_pid != Some(std::process::id()) {
        return Ok(None);
    }

    let fds = listen_fds.unwrap_or(0);
    if fds < 1 {
        return Ok(None);
    }

    if fds > 1 {
        warn!("LISTEN_FDS={} (expected 1)", fds);
    }

    let fd = 3;
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    Ok(Some(UnixListener::from_std(std_listener)?))
}

fn bind_socket(path: &Path, group: Option<&str>) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }

    let listener = std::os::unix::net::UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;

    if let Some(group) = group {
        if let Err(err) = apply_socket_group(path, group) {
            warn!("Failed to set socket group {}: {}", group, err);
        }
    }

    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener)
}

fn apply_socket_group(path: &Path, group: &str) -> io::Result<()> {
    let gid = lookup_gid(group)?;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket path"))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), 0, gid as libc::gid_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn lookup_gid(group: &str) -> io::Result<u32> {
    let c_group = CString::new(group)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid group name"))?;
    let grp = unsafe { libc::getgrnam(c_group.as_ptr()) };
    if grp.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("group {} not found", group),
        ));
    }
    let gid = unsafe { (*grp).gr_gid } as u32;
    Ok(gid)
}

pub fn notify_ready() {
    if let Err(err) = sd_notify("READY=1") {
        warn!("sd_notify READY failed: {}", err);
    }
}

pub fn spawn_watchdog_task() -> Option<JoinHandle<()>> {
    let interval = watchdog_interval()?;
    Some(tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(err) = sd_notify("WATCHDOG=1") {
                warn!("sd_notify WATCHDOG failed: {}", err);
            }
        }
    }))
}

fn sd_notify(message: &str) -> io::Result<()> {
    let notify_socket = match env::var("NOTIFY_SOCKET") {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };

    if let Some(stripped) = notify_socket.strip_prefix('@') {
        send_abstract_notification(message.as_bytes(), stripped.as_bytes())?;
    } else {
        let sock = UnixDatagram::unbound()?;
        sock.send_to(message.as_bytes(), notify_socket)?;
    }
    Ok(())
}

fn send_abstract_notification(message: &[u8], name: &[u8]) -> io::Result<()> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "notify socket name is empty",
        ));
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    let max_len = addr.sun_path.len();
    if name.len() + 1 > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "notify socket name too long",
        ));
    }

    addr.sun_path[0] = 0;
    for (slot, byte) in addr.sun_path[1..=name.len()].iter_mut().zip(name.iter()) {
        *slot = *byte as libc::c_char;
    }

    let addr_len =
        (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
    let sock = UnixDatagram::unbound()?;
    let rc = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            message.as_ptr() as *const libc::c_void,
            message.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            addr_len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn watchdog_interval() -> Option<Duration> {
    let usec = env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())?;
    if usec == 0 {
        return None;
    }

    if let Ok(pid) = env::var("WATCHDOG_PID") {
        if pid.parse::<u32>().ok() != Some(std::process::id()) {
            return None;
        }
    }

    let interval = Duration::from_micros(usec / 2).max(Duration::from_secs(1));
    Some(interval)
}
