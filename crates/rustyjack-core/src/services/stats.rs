use std::ffi::CString;
use std::path::Path;

use crate::services::error::ServiceError;
use crate::system::{arp_spoof_running, compose_status_text, dns_spoof_running, pcap_capture_running};

#[derive(Debug, Clone)]
pub struct StatusSummary {
    pub mitm_running: bool,
    pub dnsspoof_running: bool,
    pub status_text: String,
}

pub fn status_summary() -> Result<StatusSummary, ServiceError> {
    let mitm_running = pcap_capture_running() || arp_spoof_running();
    let dnsspoof_running = dns_spoof_running();
    let status_text = compose_status_text(mitm_running, dnsspoof_running);
    Ok(StatusSummary {
        mitm_running,
        dnsspoof_running,
        status_text,
    })
}

pub fn disk_usage(path: &Path) -> Result<(u64, u64), ServiceError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ServiceError::InvalidInput("invalid path".to_string()))?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if rc != 0 {
            return Err(ServiceError::Io(std::io::Error::last_os_error()));
        }
        let block_size = stat.f_frsize as u64;
        let total = stat.f_blocks as u64 * block_size;
        let available = stat.f_bavail as u64 * block_size;
        let used = total.saturating_sub(available);
        return Ok((used, total));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(ServiceError::Internal(
            "disk usage supported on Linux only".to_string(),
        ))
    }
}
