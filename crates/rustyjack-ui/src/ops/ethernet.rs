use anyhow::Result;

use rustyjack_commands::{
    Commands, EthernetCommand, EthernetDiscoverArgs, EthernetInventoryArgs,
    EthernetPortScanArgs, EthernetSiteCredArgs, MitmCommand, MitmStartArgs,
};

use crate::ops::{
    shared::{jobs, preflight},
    Operation, OperationContext, OperationOutcome,
};

// ============================================================================
// Ethernet Discovery Operation
// ============================================================================

pub struct EthernetDiscoveryOp {
    interface: String,
}

impl EthernetDiscoveryOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
        }
    }
}

impl Operation for EthernetDiscoveryOp {
    fn id(&self) -> &'static str {
        "ethernet_discovery"
    }

    fn title(&self) -> &'static str {
        "Ethernet Discovery"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "Ethernet discovery blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        Ok(())
    }

    fn setup(&mut self, _ctx: &mut OperationContext) -> Result<bool> {
        Ok(true) // No setup needed
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Interface: {}", self.interface),
            "Discover hosts on LAN".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Ethernet(EthernetCommand::Discover(EthernetDiscoverArgs {
            interface: self.interface.clone(),
        }));

        jobs::run_cancellable_job(ctx, &cmd, "Ethernet Discovery", "Discovering hosts...")
    }
}

// ============================================================================
// Ethernet Port Scan Operation
// ============================================================================

pub struct EthernetPortScanOp {
    interface: String,
    target: String,
}

impl EthernetPortScanOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            target: String::new(),
        }
    }
}

impl Operation for EthernetPortScanOp {
    fn id(&self) -> &'static str {
        "ethernet_port_scan"
    }

    fn title(&self) -> &'static str {
        "Port Scan"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "Port scanning blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        // In real implementation, would use picker to choose target from discovered hosts
        // For now, use a placeholder
        self.target = ctx
            .ui
            .config
            .settings
            .target_network
            .clone()
            .split_whitespace()
            .next()
            .unwrap_or("192.168.1.1")
            .to_string();
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Target: {}", self.target),
            format!("Interface: {}", self.interface),
            "Scan common ports".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Ethernet(EthernetCommand::PortScan(EthernetPortScanArgs {
            target: self.target.clone(),
            ports: None, // Use default common ports
        }));

        jobs::run_cancellable_job(ctx, &cmd, "Port Scan", "Scanning ports...")
    }
}

// ============================================================================
// Ethernet Inventory Operation
// ============================================================================

pub struct EthernetInventoryOp {
    interface: String,
}

impl EthernetInventoryOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
        }
    }
}

impl Operation for EthernetInventoryOp {
    fn id(&self) -> &'static str {
        "ethernet_inventory"
    }

    fn title(&self) -> &'static str {
        "Device Inventory"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "Inventory blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        Ok(())
    }

    fn setup(&mut self, _ctx: &mut OperationContext) -> Result<bool> {
        Ok(true) // No setup needed
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Interface: {}", self.interface),
            "Build device inventory".to_string(),
            "(mDNS, LLMNR, NetBIOS)".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Ethernet(EthernetCommand::Inventory(EthernetInventoryArgs {
            interface: self.interface.clone(),
        }));

        jobs::run_cancellable_job(ctx, &cmd, "Device Inventory", "Building inventory...")
    }
}

// ============================================================================
// Ethernet MITM Operation
// ============================================================================

pub struct EthernetMitmOp {
    interface: String,
    target: String,
    gateway: String,
}

impl EthernetMitmOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            target: String::new(),
            gateway: String::new(),
        }
    }
}

impl Operation for EthernetMitmOp {
    fn id(&self) -> &'static str {
        "ethernet_mitm"
    }

    fn title(&self) -> &'static str {
        "MITM Attack"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "MITM blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        // In real implementation, would use picker to choose target and gateway
        // For now, use placeholders
        self.target = "192.168.1.100".to_string();
        self.gateway = ctx
            .ui
            .config
            .settings
            .target_network
            .clone()
            .split_whitespace()
            .next()
            .unwrap_or("192.168.1.1")
            .to_string();
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Target: {}", self.target),
            format!("Gateway: {}", self.gateway),
            format!("Interface: {}", self.interface),
            "".to_string(),
            "ARP poison to intercept".to_string(),
            "traffic between target & GW".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Mitm(MitmCommand::Start(MitmStartArgs {
            interface: self.interface.clone(),
            target: self.target.clone(),
            gateway: self.gateway.clone(),
        }));

        jobs::run_cancellable_job(ctx, &cmd, "MITM Attack", "Poisoning ARP cache...")
    }
}

// ============================================================================
// Ethernet Site Credential Capture Pipeline
// ============================================================================

pub struct EthernetSiteCredOp {
    interface: String,
}

impl EthernetSiteCredOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
        }
    }
}

impl Operation for EthernetSiteCredOp {
    fn id(&self) -> &'static str {
        "ethernet_site_cred"
    }

    fn title(&self) -> &'static str {
        "Site Cred Capture"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "Site cred capture blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        Ok(())
    }

    fn setup(&mut self, _ctx: &mut OperationContext) -> Result<bool> {
        Ok(true) // No setup needed
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Interface: {}", self.interface),
            "".to_string(),
            "Automated pipeline:".to_string(),
            "1. Classify devices".to_string(),
            "2. ARP poison targets".to_string(),
            "3. DNS spoof + capture".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Ethernet(EthernetCommand::SiteCredCapture(
            EthernetSiteCredArgs {
                interface: self.interface.clone(),
            },
        ));

        jobs::run_cancellable_job(
            ctx,
            &cmd,
            "Site Cred Capture",
            "Running pipeline...",
        )
    }
}
