use anyhow::{bail, Result};
use std::fs;

use rustyjack_commands::{
    Commands, EthernetCommand, EthernetDiscoverArgs, EthernetInventoryArgs, EthernetPortScanArgs,
    EthernetSiteCredArgs, MitmCommand, MitmStartArgs,
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
        Ok(true)
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
            interface: Some(self.interface.clone()),
            target: None,
            timeout_ms: 500,
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
            target: Some(self.target.clone()),
            interface: Some(self.interface.clone()),
            ports: None, // Use default common ports
            timeout_ms: 500,
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
            interface: Some(self.interface.clone()),
            target: None,
            timeout_ms: 800,
        }));

        jobs::run_cancellable_job(ctx, &cmd, "Device Inventory", "Building inventory...")
    }
}

// ============================================================================
// Ethernet MITM Operation
// ============================================================================

pub struct EthernetMitmOp {
    interface: String,
    network_label: String,
    max_hosts: usize,
}

impl EthernetMitmOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            network_label: String::new(),
            max_hosts: 8,
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
        let loot_label = if !ctx.ui.config.settings.target_network.is_empty() {
            ctx.ui.config.settings.target_network.clone()
        } else {
            self.interface.clone()
        };
        self.network_label = loot_label;
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Network: {}", self.network_label),
            format!("Interface: {}", self.interface),
            "".to_string(),
            "ARP poison discovered hosts".to_string(),
            format!("Max hosts: {}", self.max_hosts),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Mitm(MitmCommand::Start(MitmStartArgs {
            interface: Some(self.interface.clone()),
            network: if self.network_label.is_empty() {
                None
            } else {
                Some(self.network_label.clone())
            },
            max_hosts: self.max_hosts,
            label: if self.network_label.is_empty() {
                None
            } else {
                Some(self.network_label.clone())
            },
        }));

        jobs::run_cancellable_job(ctx, &cmd, "MITM Attack", "Poisoning ARP cache...")
    }
}

// ============================================================================
// Ethernet Site Credential Capture Pipeline
// ============================================================================

pub struct EthernetSiteCredOp {
    interface: String,
    site: String,
    max_hosts: usize,
}

impl EthernetSiteCredOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            site: String::new(),
            max_hosts: 8,
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

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        let base = ctx.ui.root.join("DNSSpoof").join("sites");
        let mut sites = Vec::new();
        if let Ok(entries) = fs::read_dir(&base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        sites.push(name.to_string());
                    }
                }
            }
        }
        sites.sort();
        if let Some(first) = sites.first() {
            self.site = first.clone();
        } else {
            bail!("No DNS spoof site templates found in DNSSpoof/sites");
        }
        Ok(true) // No setup needed
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Interface: {}", self.interface),
            format!("Site: {}", self.site),
            format!("Max hosts: {}", self.max_hosts),
            "".to_string(),
            "Automated pipeline:".to_string(),
            "1. Classify devices".to_string(),
            "2. ARP poison targets".to_string(),
            "3. DNS spoof + capture".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Ethernet(EthernetCommand::SiteCredCapture(EthernetSiteCredArgs {
            interface: Some(self.interface.clone()),
            target: None,
            site: self.site.clone(),
            max_hosts: self.max_hosts,
            timeout_ms: 800,
        }));

        jobs::run_cancellable_job(ctx, &cmd, "Site Cred Capture", "Running pipeline...")
    }
}
