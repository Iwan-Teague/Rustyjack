use anyhow::Result;

use rustyjack_commands::{
    Commands, WifiCommand, WifiReconArpScanArgs, WifiReconBandwidthArgs, WifiReconCommand,
    WifiReconDnsCaptureArgs, WifiReconGatewayArgs, WifiReconMdnsScanArgs, WifiReconServiceScanArgs,
};

use crate::ops::{
    shared::{jobs, preflight},
    Operation, OperationContext, OperationOutcome,
};
use crate::ui::screens::picker::{self, PickerChoice};

const INDEFINITE_SECS: u32 = 86_400;

// ============================================================================
// Gateway Recon Operation
// ============================================================================

pub struct GatewayReconOp {
    interface: String,
    duration_secs: u64,
}

impl GatewayReconOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
        }
    }
}

impl Operation for GatewayReconOp {
    fn id(&self) -> &'static str {
        "gateway_recon"
    }

    fn title(&self) -> &'static str {
        "Gateway Recon"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_active_interface(ctx.ui.config)?;
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();

        let durations = vec![
            "30 seconds".to_string(),
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "Indefinite".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "Recon Duration", &durations, "Gateway Recon")? {
            PickerChoice::Selected(0) => self.duration_secs = 30,
            PickerChoice::Selected(1) => self.duration_secs = 60,
            PickerChoice::Selected(2) => self.duration_secs = 300,
            PickerChoice::Selected(3) => self.duration_secs = INDEFINITE_SECS as u64,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        let duration_str = if self.duration_secs >= INDEFINITE_SECS as u64 {
            "Indefinite".to_string()
        } else {
            format!("{}s", self.duration_secs)
        };
        vec![
            format!("Interface: {}", self.interface),
            format!("Duration: {}", duration_str),
            "Discover gateway and route".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Recon(WifiReconCommand::Gateway(
            WifiReconGatewayArgs {
                interface: Some(self.interface.clone()),
            },
        )));

        jobs::run_cancellable_job(ctx, &cmd, "Gateway Recon", "Discovering gateway...")
    }
}

// ============================================================================
// ARP Scan Operation
// ============================================================================

pub struct ArpScanOp {
    interface: String,
    duration_secs: u64,
}

impl ArpScanOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
        }
    }
}

impl Operation for ArpScanOp {
    fn id(&self) -> &'static str {
        "arp_scan"
    }

    fn title(&self) -> &'static str {
        "ARP Scan"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_active_interface(ctx.ui.config)?;
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();

        let durations = vec![
            "Quick (30s)".to_string(),
            "Normal (60s)".to_string(),
            "Deep (5 min)".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "Scan Duration", &durations, "ARP Scan")? {
            PickerChoice::Selected(0) => self.duration_secs = 30,
            PickerChoice::Selected(1) => self.duration_secs = 60,
            PickerChoice::Selected(2) => self.duration_secs = 300,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Interface: {}", self.interface),
            format!("Duration: {}s", self.duration_secs),
            "Scan local network for hosts".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Recon(WifiReconCommand::ArpScan(
            WifiReconArpScanArgs {
                interface: self.interface.clone(),
            },
        )));

        jobs::run_cancellable_job(ctx, &cmd, "ARP Scan", "Scanning for hosts...")
    }
}

// ============================================================================
// Service Scan Operation
// ============================================================================

pub struct ServiceScanOp {
    interface: String,
    duration_secs: u64,
}

impl ServiceScanOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
        }
    }
}

impl Operation for ServiceScanOp {
    fn id(&self) -> &'static str {
        "service_scan"
    }

    fn title(&self) -> &'static str {
        "Service Scan"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_active_interface(ctx.ui.config)?;
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();

        let durations = vec![
            "Quick (1 min)".to_string(),
            "Normal (5 min)".to_string(),
            "Deep (10 min)".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "Scan Duration", &durations, "Service Scan")? {
            PickerChoice::Selected(0) => self.duration_secs = 60,
            PickerChoice::Selected(1) => self.duration_secs = 300,
            PickerChoice::Selected(2) => self.duration_secs = 600,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Interface: {}", self.interface),
            format!("Duration: {}s", self.duration_secs),
            "Scan for open ports/services".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Recon(WifiReconCommand::ServiceScan(
            WifiReconServiceScanArgs {
                interface: self.interface.clone(),
            },
        )));

        jobs::run_cancellable_job(ctx, &cmd, "Service Scan", "Scanning services...")
    }
}

// ============================================================================
// mDNS Scan Operation
// ============================================================================

pub struct MdnsScanOp {
    interface: String,
    duration_secs: u64,
}

impl MdnsScanOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
        }
    }
}

impl Operation for MdnsScanOp {
    fn id(&self) -> &'static str {
        "mdns_scan"
    }

    fn title(&self) -> &'static str {
        "mDNS Scan"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_active_interface(ctx.ui.config)?;
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();

        let durations = vec![
            "30 seconds".to_string(),
            "1 minute".to_string(),
            "5 minutes".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "Scan Duration", &durations, "mDNS Scan")? {
            PickerChoice::Selected(0) => self.duration_secs = 30,
            PickerChoice::Selected(1) => self.duration_secs = 60,
            PickerChoice::Selected(2) => self.duration_secs = 300,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Interface: {}", self.interface),
            format!("Duration: {}s", self.duration_secs),
            "Discover mDNS/Bonjour devices".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Recon(WifiReconCommand::MdnsScan(
            WifiReconMdnsScanArgs {
                duration: self.duration_secs,
            },
        )));

        jobs::run_cancellable_job(ctx, &cmd, "mDNS Scan", "Scanning for mDNS devices...")
    }
}

// ============================================================================
// Bandwidth Monitor Operation
// ============================================================================

pub struct BandwidthMonitorOp {
    interface: String,
    duration_secs: u64,
}

impl BandwidthMonitorOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
        }
    }
}

impl Operation for BandwidthMonitorOp {
    fn id(&self) -> &'static str {
        "bandwidth_monitor"
    }

    fn title(&self) -> &'static str {
        "Bandwidth Monitor"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_active_interface(ctx.ui.config)?;
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();

        let durations = vec![
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
            "Indefinite".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "Monitor Duration", &durations, "Bandwidth Monitor")? {
            PickerChoice::Selected(0) => self.duration_secs = 60,
            PickerChoice::Selected(1) => self.duration_secs = 300,
            PickerChoice::Selected(2) => self.duration_secs = 600,
            PickerChoice::Selected(3) => self.duration_secs = INDEFINITE_SECS as u64,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        let duration_str = if self.duration_secs >= INDEFINITE_SECS as u64 {
            "Indefinite".to_string()
        } else {
            format!("{}s", self.duration_secs)
        };
        vec![
            format!("Interface: {}", self.interface),
            format!("Duration: {}", duration_str),
            "Monitor network bandwidth".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Recon(WifiReconCommand::Bandwidth(
            WifiReconBandwidthArgs {
                interface: self.interface.clone(),
                duration: self.duration_secs,
            },
        )));

        jobs::run_cancellable_job(ctx, &cmd, "Bandwidth Monitor", "Monitoring bandwidth...")
    }
}

// ============================================================================
// DNS Capture Operation
// ============================================================================

pub struct DnsCaptureOp {
    interface: String,
    duration_secs: u64,
}

impl DnsCaptureOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
        }
    }
}

impl Operation for DnsCaptureOp {
    fn id(&self) -> &'static str {
        "dns_capture"
    }

    fn title(&self) -> &'static str {
        "DNS Capture"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_active_interface(ctx.ui.config)?;
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();

        let durations = vec![
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
            "Indefinite".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "Capture Duration", &durations, "DNS Capture")? {
            PickerChoice::Selected(0) => self.duration_secs = 60,
            PickerChoice::Selected(1) => self.duration_secs = 300,
            PickerChoice::Selected(2) => self.duration_secs = 600,
            PickerChoice::Selected(3) => self.duration_secs = INDEFINITE_SECS as u64,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        let duration_str = if self.duration_secs >= INDEFINITE_SECS as u64 {
            "Indefinite".to_string()
        } else {
            format!("{}s", self.duration_secs)
        };
        vec![
            format!("Interface: {}", self.interface),
            format!("Duration: {}", duration_str),
            "Capture DNS queries".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Recon(WifiReconCommand::DnsCapture(
            WifiReconDnsCaptureArgs {
                interface: self.interface.clone(),
                duration: self.duration_secs,
            },
        )));

        jobs::run_cancellable_job(ctx, &cmd, "DNS Capture", "Capturing DNS queries...")
    }
}
