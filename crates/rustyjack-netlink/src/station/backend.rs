use crate::error::Result;
use crate::supplicant::{BssCandidate, StationConfig, StationOutcome};
use crate::wpa::WpaStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StationBackendKind {
    ExternalWpa,
    RustOpen,
    RustWpa2,
}

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub candidates: Vec<BssCandidate>,
    pub used_scan_ssid: bool,
}

pub trait StationBackend: Send + Sync {
    fn ensure_ready(&self) -> Result<()>;
    fn scan(&self, cfg: &StationConfig) -> Result<ScanOutcome>;
    fn connect(&self, cfg: &StationConfig, candidate: Option<&BssCandidate>) -> Result<StationOutcome>;
    fn disconnect(&self) -> Result<()>;
    fn status(&self) -> Result<WpaStatus>;
    fn cleanup(&self) -> Result<()>;
}
