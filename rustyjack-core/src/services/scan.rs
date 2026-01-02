use std::path::Path;

use serde_json::Value;

use crate::operations::run_scan_with_progress;
use crate::services::error::ServiceError;
use rustyjack_commands::{ScanDiscovery, ScanRunArgs};

#[derive(Debug, Clone, Copy)]
pub enum ScanMode {
    DiscoveryOnly,
    DiscoveryAndPorts,
}

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub target: String,
    pub mode: ScanMode,
    pub ports: Option<Vec<u16>>,
    pub timeout_ms: u64,
}

pub fn run_scan<F>(root: &Path, req: ScanRequest, mut on_progress: F) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    let ports = req
        .ports
        .as_ref()
        .map(|list| list.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));
    let args = ScanRunArgs {
        label: "scan".to_string(),
        nmap_args: Vec::new(),
        interface: None,
        target: Some(req.target),
        output_path: None,
        no_discord: true,
        ports,
        top_ports: None,
        timeout_ms: req.timeout_ms,
        discovery: ScanDiscovery::Both,
        no_discovery: false,
        no_port_scan: matches!(req.mode, ScanMode::DiscoveryOnly),
        service_detect: false,
        os_detect: false,
        workers: 4,
        max_hosts: None,
        arp_rate_pps: None,
    };

    let result = run_scan_with_progress(root, args, |percent, message| {
        let clamped = percent.max(0.0).min(100.0);
        on_progress(clamped.round() as u8, message);
    });

    match result {
        Ok((_message, data)) => Ok(data),
        Err(err) => Err(ServiceError::External(err.to_string())),
    }
}
