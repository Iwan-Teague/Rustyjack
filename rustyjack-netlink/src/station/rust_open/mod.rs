use crate::error::{NetlinkError, Result};
use crate::station::backend::{ScanOutcome, StationBackend};
use crate::supplicant::{BssCandidate, StationConfig, StationOutcome};
use crate::wpa::WpaStatus;

pub struct RustOpenBackend {
    interface: String,
}

impl RustOpenBackend {
    pub fn new(interface: &str) -> Result<Self> {
        if interface.trim().is_empty() {
            return Err(NetlinkError::InvalidInput(
                "Interface cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            interface: interface.to_string(),
        })
    }
}

impl StationBackend for RustOpenBackend {
    fn ensure_ready(&self) -> Result<()> {
        Err(NetlinkError::OperationNotSupported(
            "RustOpen backend not implemented".to_string(),
        ))
    }

    fn scan(&self, _cfg: &StationConfig) -> Result<ScanOutcome> {
        Err(NetlinkError::OperationNotSupported(
            "RustOpen backend not implemented".to_string(),
        ))
    }

    fn connect(&self, _cfg: &StationConfig, _candidate: Option<&BssCandidate>) -> Result<StationOutcome> {
        Err(NetlinkError::OperationNotSupported(
            "RustOpen backend not implemented".to_string(),
        ))
    }

    fn disconnect(&self) -> Result<()> {
        Err(NetlinkError::OperationNotSupported(
            "RustOpen backend not implemented".to_string(),
        ))
    }

    fn status(&self) -> Result<WpaStatus> {
        Err(NetlinkError::OperationNotSupported(
            "RustOpen backend not implemented".to_string(),
        ))
    }

    fn cleanup(&self) -> Result<()> {
        Err(NetlinkError::OperationNotSupported(
            "RustOpen backend not implemented".to_string(),
        ))
    }
}
