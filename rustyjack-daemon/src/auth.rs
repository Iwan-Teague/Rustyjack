use std::io;
use std::os::unix::io::AsRawFd;

use tokio::net::UnixStream;

use rustyjack_ipc::{AuthorizationTier, Endpoint};

#[derive(Debug, Clone, Copy)]
pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCred> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(PeerCred {
        pid: cred.pid as u32,
        uid: cred.uid as u32,
        gid: cred.gid as u32,
    })
}

pub fn authorization_for(uid: u32) -> AuthorizationTier {
    if uid == 0 {
        AuthorizationTier::Admin
    } else {
        AuthorizationTier::Operator
    }
}

pub fn required_tier(endpoint: Endpoint) -> AuthorizationTier {
    match endpoint {
        Endpoint::Health => AuthorizationTier::ReadOnly,
        Endpoint::Version => AuthorizationTier::ReadOnly,
        Endpoint::Status => AuthorizationTier::ReadOnly,
        Endpoint::JobStart => AuthorizationTier::Operator,
        Endpoint::JobStatus => AuthorizationTier::Operator,
        Endpoint::JobCancel => AuthorizationTier::Operator,
        Endpoint::CoreDispatch => AuthorizationTier::Operator,
        Endpoint::SystemStatusGet => AuthorizationTier::ReadOnly,
        Endpoint::DiskUsageGet => AuthorizationTier::ReadOnly,
        Endpoint::SystemReboot => AuthorizationTier::Admin,
        Endpoint::SystemShutdown => AuthorizationTier::Admin,
        Endpoint::SystemSync => AuthorizationTier::Admin,
        Endpoint::HostnameRandomizeNow => AuthorizationTier::Admin,
        Endpoint::BlockDevicesList => AuthorizationTier::ReadOnly,
        Endpoint::SystemLogsGet => AuthorizationTier::Operator,
        Endpoint::WifiCapabilitiesGet => AuthorizationTier::ReadOnly,
        Endpoint::HotspotWarningsGet => AuthorizationTier::Operator,
        Endpoint::HotspotDiagnosticsGet => AuthorizationTier::Operator,
        Endpoint::HotspotClientsList => AuthorizationTier::Operator,
        Endpoint::GpioDiagnosticsGet => AuthorizationTier::Operator,
    }
}

pub fn tier_allows(actual: AuthorizationTier, required: AuthorizationTier) -> bool {
    match (actual, required) {
        (AuthorizationTier::Admin, _) => true,
        (AuthorizationTier::Operator, AuthorizationTier::Operator)
        | (AuthorizationTier::Operator, AuthorizationTier::ReadOnly) => true,
        (AuthorizationTier::ReadOnly, AuthorizationTier::ReadOnly) => true,
        _ => false,
    }
}
