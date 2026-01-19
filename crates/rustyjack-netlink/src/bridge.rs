//! Linux bridge management using ioctl (no external binaries).

use crate::error::{NetlinkError, Result};
use std::ffi::CString;

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
const SIOCBRADDBR: libc::c_ulong = 0x89a0;
#[cfg(target_os = "linux")]
const SIOCBRDELBR: libc::c_ulong = 0x89a1;
#[cfg(target_os = "linux")]
const SIOCBRADDIF: libc::c_ulong = 0x89a2;
#[cfg(target_os = "linux")]
const SIOCBRDELIF: libc::c_ulong = 0x89a3;

#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReqIndex {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_ifindex: libc::c_int,
}

#[cfg(target_os = "linux")]
fn open_ioctl_socket() -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(NetlinkError::OperationFailed(format!(
            "Failed to open ioctl socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn close_ioctl_socket(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

#[cfg(target_os = "linux")]
fn validate_ifname(name: &str) -> Result<CString> {
    if name.trim().is_empty() {
        return Err(NetlinkError::InvalidInput(
            "Interface name cannot be empty".to_string(),
        ));
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(NetlinkError::InvalidInput(format!(
            "Interface name '{}' too long",
            name
        )));
    }
    CString::new(name).map_err(|_| {
        NetlinkError::InvalidInput(format!("Interface name '{}' contains NUL", name))
    })
}

#[cfg(target_os = "linux")]
fn build_ifreq_index(bridge: &str, ifindex: u32) -> Result<IfReqIndex> {
    let mut ifr = IfReqIndex {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_ifindex: ifindex as libc::c_int,
    };
    for (dst, src) in ifr
        .ifr_name
        .iter_mut()
        .zip(bridge.as_bytes().iter())
    {
        *dst = *src as libc::c_char;
    }
    Ok(ifr)
}

#[cfg(target_os = "linux")]
pub async fn bridge_create(name: &str) -> Result<()> {
    let name_c = validate_ifname(name)?;
    let fd = open_ioctl_socket()?;
    let res = unsafe { libc::ioctl(fd, SIOCBRADDBR, name_c.as_ptr()) };
    let err = std::io::Error::last_os_error();
    close_ioctl_socket(fd);
    if res < 0 {
        return Err(NetlinkError::OperationFailed(format!(
            "Failed to create bridge '{}': {}",
            name, err
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn bridge_delete(name: &str) -> Result<()> {
    let name_c = validate_ifname(name)?;
    let fd = open_ioctl_socket()?;
    let res = unsafe { libc::ioctl(fd, SIOCBRDELBR, name_c.as_ptr()) };
    let err = std::io::Error::last_os_error();
    close_ioctl_socket(fd);
    if res < 0 {
        return Err(NetlinkError::OperationFailed(format!(
            "Failed to delete bridge '{}': {}",
            name, err
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn bridge_add_interface(bridge: &str, iface: &str) -> Result<()> {
    let iface_c = validate_ifname(iface)?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        return Err(NetlinkError::InterfaceNotFound {
            name: iface.to_string(),
        });
    }

    let ifr = build_ifreq_index(bridge, ifindex)?;
    let fd = open_ioctl_socket()?;
    let res = unsafe { libc::ioctl(fd, SIOCBRADDIF, &ifr as *const _ as *const libc::c_void) };
    let err = std::io::Error::last_os_error();
    close_ioctl_socket(fd);
    if res < 0 {
        return Err(NetlinkError::OperationFailed(format!(
            "Failed to add '{}' to bridge '{}': {}",
            iface, bridge, err
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn bridge_remove_interface(bridge: &str, iface: &str) -> Result<()> {
    let iface_c = validate_ifname(iface)?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        return Err(NetlinkError::InterfaceNotFound {
            name: iface.to_string(),
        });
    }

    let ifr = build_ifreq_index(bridge, ifindex)?;
    let fd = open_ioctl_socket()?;
    let res = unsafe { libc::ioctl(fd, SIOCBRDELIF, &ifr as *const _ as *const libc::c_void) };
    let err = std::io::Error::last_os_error();
    close_ioctl_socket(fd);
    if res < 0 {
        return Err(NetlinkError::OperationFailed(format!(
            "Failed to remove '{}' from bridge '{}': {}",
            iface, bridge, err
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn bridge_create(_name: &str) -> Result<()> {
    Err(NetlinkError::OperationNotSupported(
        "bridge_create is supported on Linux only".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn bridge_delete(_name: &str) -> Result<()> {
    Err(NetlinkError::OperationNotSupported(
        "bridge_delete is supported on Linux only".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn bridge_add_interface(_bridge: &str, _iface: &str) -> Result<()> {
    Err(NetlinkError::OperationNotSupported(
        "bridge_add_interface is supported on Linux only".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn bridge_remove_interface(_bridge: &str, _iface: &str) -> Result<()> {
    Err(NetlinkError::OperationNotSupported(
        "bridge_remove_interface is supported on Linux only".to_string(),
    ))
}
