use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;

use crate::ops::OpsConfig;
use crate::state::DaemonState;

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnforcementSnapshot {
    allowed: Vec<String>,
    blocked: Vec<String>,
}

impl EnforcementSnapshot {
    fn from_outcome(outcome: &rustyjack_core::system::IsolationOutcome) -> Self {
        let mut allowed = outcome.allowed.clone();
        let mut blocked = outcome.blocked.clone();
        allowed.sort();
        blocked.sort();
        Self { allowed, blocked }
    }
}

#[cfg(target_os = "linux")]
struct NetlinkSocket {
    fd: RawFd,
}

#[cfg(target_os = "linux")]
impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(target_os = "linux")]
fn open_netlink_socket() -> anyhow::Result<AsyncFd<NetlinkSocket>> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()));
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        unsafe { libc::close(fd) };
        return Err(anyhow::Error::new(std::io::Error::last_os_error()));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        unsafe { libc::close(fd) };
        return Err(anyhow::Error::new(std::io::Error::last_os_error()));
    }

    let groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR) as u32;
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = unsafe { libc::getpid() as u32 };
    addr.nl_groups = groups;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return Err(anyhow::Error::new(std::io::Error::last_os_error()));
    }

    Ok(AsyncFd::new(NetlinkSocket { fd })?)
}

#[cfg(target_os = "linux")]
pub async fn run_netlink_watcher(state: Arc<DaemonState>) -> anyhow::Result<()> {
    info!("Starting netlink watcher for hardware isolation enforcement");

    let last_event: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>> =
        Arc::new(StdMutex::new(None));
    let debounce_duration = Duration::from_millis(250);

    start_periodic_enforcement(Arc::clone(&state), Arc::clone(&enforcement_snapshot));

    loop {
        match watch_netlink_events(
            Arc::clone(&state),
            Arc::clone(&last_event),
            debounce_duration,
            Arc::clone(&enforcement_snapshot),
        )
        .await
        {
            Ok(_) => {
                info!("Netlink watcher stopped normally");
                break;
            }
            Err(e) => {
                warn!("Netlink watcher error: {}, restarting in 5s", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn run_netlink_watcher(_state: Arc<DaemonState>) -> anyhow::Result<()> {
    info!("Netlink watcher disabled on non-Linux platform");
    futures::future::pending::<()>().await;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn watch_netlink_events(
    state: Arc<DaemonState>,
    last_event: Arc<Mutex<Option<Instant>>>,
    debounce_duration: Duration,
    enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>>,
) -> anyhow::Result<()> {
    let socket = open_netlink_socket()?;
    let mut buf = vec![0u8; 8192];

    loop {
        let mut received = false;
        let mut guard = socket.readable().await?;
        loop {
            let len = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if len > 0 {
                received = true;
                continue;
            }
            if len == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow::Error::new(err));
        }
        guard.clear_ready();

        if received {
            debug!("Netlink event");
            schedule_enforcement(
                Arc::clone(&state),
                Arc::clone(&last_event),
                debounce_duration,
                Arc::clone(&enforcement_snapshot),
            )
            .await;
        }
    }
}

#[cfg(target_os = "linux")]
async fn schedule_enforcement(
    state: Arc<DaemonState>,
    last_event: Arc<Mutex<Option<Instant>>>,
    debounce_duration: Duration,
    enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>>,
) {
    let now = Instant::now();

    {
        let mut last = last_event.lock().await;
        if let Some(prev) = *last {
            if now.duration_since(prev) < debounce_duration {
                *last = Some(now);
                return;
            }
        }
        *last = Some(now);
    }

    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        sleep(debounce_duration).await;

        let _lock = state_clone.locks.acquire_uplink().await;

        let root = state_clone.config.root_path.clone();
        let ops_cfg = *state_clone.ops_runtime.read().await;
        let snapshot = Arc::clone(&enforcement_snapshot);
        tokio::task::spawn_blocking(move || {
            match run_ops_enforcement(root, ops_cfg) {
                Ok(outcome) => log_enforcement_outcome("Netlink enforcement", &outcome, &snapshot),
                Err(e) => warn!("Netlink event enforcement failed: {}", e),
            };
        })
        .await
        .ok();
    });
}

#[cfg(target_os = "linux")]
fn start_periodic_enforcement(
    state: Arc<DaemonState>,
    enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>>,
) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(3);
        loop {
            sleep(interval).await;

            let _lock = state.locks.acquire_uplink().await;
            let root = state.config.root_path.clone();
            let ops_cfg = *state.ops_runtime.read().await;
            let snapshot = Arc::clone(&enforcement_snapshot);

            tokio::task::spawn_blocking(move || {
                match run_ops_enforcement(root, ops_cfg) {
                    Ok(outcome) => {
                        log_enforcement_outcome("Periodic enforcement", &outcome, &snapshot)
                    }
                    Err(e) => warn!("Periodic enforcement failed: {}", e),
                };
            })
            .await
            .ok();
        }
    });
}

#[cfg(target_os = "linux")]
fn log_enforcement_outcome(
    label: &str,
    outcome: &rustyjack_core::system::IsolationOutcome,
    snapshot: &Arc<StdMutex<Option<EnforcementSnapshot>>>,
) {
    let current = EnforcementSnapshot::from_outcome(outcome);
    let mut guard = snapshot.lock().unwrap_or_else(|e| e.into_inner());
    let changed = guard.as_ref().map(|prev| prev != &current).unwrap_or(true);

    if changed {
        info!(
            "{}: allowed={:?}, blocked={:?}",
            label, current.allowed, current.blocked
        );
        *guard = Some(current);
    }

    if !outcome.errors.is_empty() {
        warn!("{} had {} errors:", label, outcome.errors.len());
        for err in &outcome.errors {
            warn!("  {}: {}", err.interface, err.message);
        }
    }
}

#[cfg(target_os = "linux")]
fn run_ops_enforcement(
    root: std::path::PathBuf,
    ops_cfg: OpsConfig,
) -> anyhow::Result<rustyjack_core::system::IsolationOutcome> {
    use rustyjack_core::system::ops::NetOps;
    use rustyjack_core::system::{
        apply_interface_isolation_with_ops_block_all, apply_interface_isolation_with_ops_strict,
        IsolationEngine, RealNetOps,
    };
    use std::sync::Arc;

    let ops: Arc<dyn NetOps> = Arc::new(RealNetOps);
    if ops_cfg.wifi_ops && ops_cfg.eth_ops {
        let engine = IsolationEngine::new(Arc::clone(&ops), root);
        return engine.enforce();
    }

    let interfaces = ops.list_interfaces()?;
    let allowed: Vec<String> = interfaces
        .into_iter()
        .filter(|iface| {
            (iface.is_wireless && ops_cfg.wifi_ops) || (!iface.is_wireless && ops_cfg.eth_ops)
        })
        .map(|iface| iface.name)
        .collect();

    if allowed.is_empty() {
        apply_interface_isolation_with_ops_block_all(Arc::clone(&ops))
    } else {
        apply_interface_isolation_with_ops_strict(Arc::clone(&ops), &allowed)
    }
}

#[cfg(not(target_os = "linux"))]
fn run_ops_enforcement(
    _root: std::path::PathBuf,
    _ops_cfg: OpsConfig,
) -> anyhow::Result<rustyjack_core::system::IsolationOutcome> {
    Ok(rustyjack_core::system::IsolationOutcome {
        allowed: Vec::new(),
        blocked: Vec::new(),
        errors: Vec::new(),
    })
}
