use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};

use crate::config::PortalConfig;
use crate::logging::PortalLogger;
use crate::server::{build_router, run_server, PortalState};

struct PortalHandle {
    interface: String,
    listen_ip: std::net::Ipv4Addr,
    listen_port: u16,
    dnat_installed: bool,
    shutdown: tokio::sync::oneshot::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

static PORTAL_STATE: OnceLock<Mutex<Option<PortalHandle>>> = OnceLock::new();

fn portal_state() -> &'static Mutex<Option<PortalHandle>> {
    PORTAL_STATE.get_or_init(|| Mutex::new(None))
}

pub fn portal_running() -> bool {
    let mut state = portal_state().lock().unwrap();
    if let Some(handle) = state.as_ref() {
        if handle.thread.is_finished() {
            let handle = state.take();
            if let Some(handle) = handle {
                let _ = handle.thread.join();
                if handle.dnat_installed {
                    let _ =
                        remove_dnat_rule(&handle.interface, handle.listen_ip, handle.listen_port);
                }
            }
            return false;
        }
        return true;
    }
    false
}

pub fn start_portal(cfg: PortalConfig) -> Result<()> {
    let _ = stop_portal();
    validate_config(&cfg)?;

    let index_path = cfg.site_dir.join("index.html");
    let index_html = std::fs::read_to_string(&index_path)
        .with_context(|| format!("reading portal HTML from {}", index_path.display()))?;

    let logger = PortalLogger::new(&cfg.capture_dir)?;
    let listener = build_listener(&cfg)?;

    let dnat_installed = if cfg.dnat_mode {
        install_dnat(&cfg)?
    } else {
        false
    };

    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let state = PortalState::new(logger, index_html);
    let app = build_router(&cfg, state);

    let listener_addr = SocketAddr::new(IpAddr::V4(cfg.listen_ip), cfg.listen_port);
    tracing::info!("Starting portal server on {listener_addr}");

    let thread = match std::thread::Builder::new()
        .name("rustyjack-portal".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::error!("failed to build portal runtime: {err}");
                    return;
                }
            };

            let result = runtime.block_on(run_server(listener, app, shutdown_rx));
            if let Err(err) = result {
                tracing::error!("portal server exited with error: {err:#}");
            }
        }) {
        Ok(thread) => thread,
        Err(err) => {
            if dnat_installed {
                let _ = remove_dnat_rule(&cfg.interface, cfg.listen_ip, cfg.listen_port);
            }
            return Err(err).context("spawning portal server thread");
        }
    };

    let handle = PortalHandle {
        interface: cfg.interface,
        listen_ip: cfg.listen_ip,
        listen_port: cfg.listen_port,
        dnat_installed,
        shutdown,
        thread,
    };

    let mut state = portal_state().lock().unwrap();
    *state = Some(handle);

    Ok(())
}

pub fn stop_portal() -> Result<()> {
    let handle = {
        let mut state = portal_state().lock().unwrap();
        state.take()
    };

    if let Some(handle) = handle {
        let _ = handle.shutdown.send(());
        let _ = handle.thread.join();

        if handle.dnat_installed {
            let _ = remove_dnat_rule(&handle.interface, handle.listen_ip, handle.listen_port);
        }
    }

    Ok(())
}

fn validate_config(cfg: &PortalConfig) -> Result<()> {
    if cfg.listen_ip.is_unspecified() {
        bail!("portal listen_ip must not be 0.0.0.0");
    }
    if cfg.listen_port == 0 {
        bail!("portal listen_port must be non-zero");
    }
    if cfg.max_body_bytes == 0 {
        bail!("portal max_body_bytes must be non-zero");
    }
    if cfg.max_concurrency == 0 {
        bail!("portal max_concurrency must be non-zero");
    }
    if cfg.interface.trim().is_empty() {
        bail!("portal interface must be set");
    }
    if !cfg.site_dir.is_dir() {
        bail!("portal site_dir not found: {}", cfg.site_dir.display());
    }
    let index_path = cfg.site_dir.join("index.html");
    if !index_path.is_file() {
        bail!("portal index.html not found: {}", index_path.display());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_listener(cfg: &PortalConfig) -> Result<std::net::TcpListener> {
    use std::ffi::CString;
    use std::os::unix::io::AsRawFd;

    use socket2::{Domain, Protocol, Socket, Type};

    let addr = SocketAddr::new(IpAddr::V4(cfg.listen_ip), cfg.listen_port);

    if !cfg.bind_to_device {
        let listener = std::net::TcpListener::bind(addr)
            .with_context(|| format!("binding portal listener to {addr}"))?;
        listener
            .set_nonblocking(true)
            .context("setting portal listener nonblocking")?;
        return Ok(listener);
    }

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .context("creating portal socket")?;
    socket
        .set_reuse_address(true)
        .context("setting portal socket reuse address")?;

    let iface = CString::new(cfg.interface.clone()).context("invalid interface name")?;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface.as_ptr().cast::<libc::c_void>(),
            iface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(anyhow!(
            "setting SO_BINDTODEVICE failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .with_context(|| format!("binding portal listener to {addr}"))?;
    socket.listen(128).context("listening on portal socket")?;

    let listener: std::net::TcpListener = socket.into();
    listener
        .set_nonblocking(true)
        .context("setting portal listener nonblocking")?;
    Ok(listener)
}

#[cfg(not(target_os = "linux"))]
fn build_listener(cfg: &PortalConfig) -> Result<std::net::TcpListener> {
    if cfg.bind_to_device {
        bail!("portal bind_to_device is only supported on linux");
    }

    let addr = SocketAddr::new(IpAddr::V4(cfg.listen_ip), cfg.listen_port);
    let listener = std::net::TcpListener::bind(addr)
        .with_context(|| format!("binding portal listener to {addr}"))?;
    listener
        .set_nonblocking(true)
        .context("setting portal listener nonblocking")?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn install_dnat(cfg: &PortalConfig) -> Result<bool> {
    use rustyjack_netlink::IptablesManager;

    let ipt = IptablesManager::new().context("initializing netfilter for portal DNAT")?;
    let listen = cfg.listen_ip.to_string();

    let _ = ipt.delete_dnat(&cfg.interface, 80, &listen, cfg.listen_port);
    ipt.add_dnat(&cfg.interface, 80, &listen, cfg.listen_port)
        .context("adding portal DNAT rule")?;

    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn install_dnat(_cfg: &PortalConfig) -> Result<bool> {
    bail!("portal dnat_mode is only supported on linux");
}

#[cfg(target_os = "linux")]
fn remove_dnat_rule(
    interface: &str,
    listen_ip: std::net::Ipv4Addr,
    listen_port: u16,
) -> Result<()> {
    use rustyjack_netlink::IptablesManager;

    if let Ok(ipt) = IptablesManager::new() {
        let listen = listen_ip.to_string();
        let _ = ipt.delete_dnat(interface, 80, &listen, listen_port);
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn remove_dnat_rule(
    _interface: &str,
    _listen_ip: std::net::Ipv4Addr,
    _listen_port: u16,
) -> Result<()> {
    Ok(())
}
