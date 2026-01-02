use crate::operations::{handle_system_poweroff, handle_system_reboot};
use crate::services::error::ServiceError;
use crate::system::randomize_hostname;

pub fn reboot() -> Result<(), ServiceError> {
    handle_system_reboot()
        .map(|_| ())
        .map_err(|err| ServiceError::External(err.to_string()))
}

pub fn shutdown() -> Result<(), ServiceError> {
    handle_system_poweroff()
        .map(|_| ())
        .map_err(|err| ServiceError::External(err.to_string()))
}

pub fn sync() -> Result<(), ServiceError> {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::sync();
    }
    Ok(())
}

pub fn randomize_hostname_now() -> Result<String, ServiceError> {
    randomize_hostname().map_err(|err| ServiceError::External(err.to_string()))
}
