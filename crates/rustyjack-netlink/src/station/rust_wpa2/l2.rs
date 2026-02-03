use std::os::unix::io::RawFd;
use std::time::Duration;

use std::ffi::CString;

use crate::error::{NetlinkError, Result};

pub struct EapolSocket {
    pub fd: RawFd,
    pub ifindex: i32,
}

impl EapolSocket {
    pub fn open(interface: &str) -> Result<Self> {
        let ifindex = interface_index(interface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (0x888e as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(NetlinkError::OperationFailed(format!(
                "Failed to open raw EAPOL socket: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (0x888e as u16).to_be();
        sll.sll_ifindex = ifindex;

        let bind_res = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if bind_res != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(NetlinkError::OperationFailed(format!(
                "Failed to bind EAPOL socket: {}",
                err
            )));
        }

        Ok(Self { fd, ifindex })
    }

    pub fn send(&self, frame: &[u8]) -> Result<()> {
        let sent = unsafe {
            libc::send(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(NetlinkError::OperationFailed(format!(
                "Failed to send EAPOL frame: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    pub fn recv(&self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let res = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if res != 0 {
            return Err(NetlinkError::OperationFailed(format!(
                "Failed to set EAPOL recv timeout: {}",
                std::io::Error::last_os_error()
            )));
        }

        let received =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if received < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut
            {
                return Err(NetlinkError::Timeout {
                    operation: "EAPOL recv".to_string(),
                    timeout_secs: timeout.as_secs(),
                });
            }
            return Err(NetlinkError::OperationFailed(format!(
                "Failed to recv EAPOL frame: {}",
                err
            )));
        }
        Ok(received as usize)
    }
}

impl Drop for EapolSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn interface_index(interface: &str) -> Result<i32> {
    let cstr = CString::new(interface)
        .map_err(|_| NetlinkError::InvalidInput("Invalid interface name".to_string()))?;
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        return Err(NetlinkError::InterfaceIndexError {
            interface: interface.to_string(),
            reason: "if_nametoindex returned 0".to_string(),
        });
    }
    Ok(idx as i32)
}
