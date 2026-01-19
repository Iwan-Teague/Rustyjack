use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

#[derive(Clone, Debug)]
pub struct PortalConfig {
    pub interface: String,
    pub listen_ip: Ipv4Addr,
    pub listen_port: u16,
    pub site_dir: PathBuf,
    pub capture_dir: PathBuf,
    pub max_body_bytes: usize,
    pub max_concurrency: usize,
    pub request_timeout: Duration,
    pub dnat_mode: bool,
    pub bind_to_device: bool,
}
