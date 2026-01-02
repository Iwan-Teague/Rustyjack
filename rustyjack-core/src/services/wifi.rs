use crate::services::error::ServiceError;
use crate::wireless_native::{check_capabilities, WirelessCapabilities};

pub fn capabilities(interface: &str) -> Result<WirelessCapabilities, ServiceError> {
    if interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }
    Ok(check_capabilities(interface))
}
