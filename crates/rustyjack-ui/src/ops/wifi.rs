use anyhow::{bail, Result};

use rustyjack_commands::{
    Commands, WifiCommand, WifiDeauthArgs, WifiEvilTwinArgs, WifiKarmaArgs, WifiPmkidArgs,
    WifiProbeSniffArgs,
};

use crate::ops::{
    shared::{jobs, preflight},
    Operation, OperationContext, OperationOutcome,
};
use crate::ui::screens::picker::{self, PickerChoice};

const INDEFINITE_SECS: u32 = 86_400;

pub struct DeauthAttackOp {
    interface: String,
    target_network: String,
    target_bssid: String,
    target_channel: u8,
    duration_secs: u64,
}

impl DeauthAttackOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            target_network: String::new(),
            target_bssid: String::new(),
            target_channel: 0,
            duration_secs: 0,
        }
    }
}

impl Operation for DeauthAttackOp {
    fn id(&self) -> &'static str {
        "deauth_attack"
    }

    fn title(&self) -> &'static str {
        "Deauth Attack"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "Deauth attack blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        let iface = ctx.ui.config.settings.active_network_interface.clone();
        preflight::deauth_attack(ctx.ui.core, ctx.ui.config, &iface)?;
        if ctx.ui.config.settings.target_channel == 0 {
            bail!("No target channel set. Scan networks first and select a target.");
        }
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        self.target_network = ctx.ui.config.settings.target_network.clone();
        self.target_bssid = ctx.ui.config.settings.target_bssid.clone();
        self.target_channel = ctx.ui.config.settings.target_channel;

        let durations = vec![
            "1 minute".to_string(),
            "2 minutes".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "Attack Duration", &durations, "Deauth Attack")? {
            PickerChoice::Selected(0) => self.duration_secs = 60,
            PickerChoice::Selected(1) => self.duration_secs = 120,
            PickerChoice::Selected(2) => self.duration_secs = 300,
            PickerChoice::Selected(3) => self.duration_secs = 600,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        let target = if self.target_network.is_empty() {
            self.target_bssid.clone()
        } else {
            self.target_network.clone()
        };
        vec![
            format!("Target: {}", target),
            format!("BSSID: {}", self.target_bssid),
            format!("Channel: {}", self.target_channel),
            format!("Interface: {}", self.interface),
            format!("Duration: {}s", self.duration_secs),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
            bssid: self.target_bssid.clone(),
            ssid: if self.target_network.is_empty() {
                None
            } else {
                Some(self.target_network.clone())
            },
            interface: self.interface.clone(),
            channel: self.target_channel,
            duration: self.duration_secs as u32,
            packets: 64,
            client: None,
            continuous: true,
            interval: 1,
        }));

        let result = jobs::dispatch_cancellable(ctx, "Deauth", cmd, self.duration_secs)?;
        match result {
            jobs::JobRunResult::Cancelled => Ok(OperationOutcome::Cancelled {
                summary: vec![
                    "Cancelled by user".to_string(),
                    "Partial results may be".to_string(),
                    "in loot/Wireless/".to_string(),
                ],
            }),
            jobs::JobRunResult::Completed { message, data } => {
                if let Some(lines) = preflight::preflight_only_summary(&data) {
                    return Ok(OperationOutcome::Success { summary: lines });
                }
                let mut lines = vec![message];

                if let Some(captured) = data.get("handshake_captured").and_then(|v| v.as_bool()) {
                    if captured {
                        lines.push("HANDSHAKE CAPTURED!".to_string());
                        if let Some(hf) = data.get("handshake_file").and_then(|v| v.as_str()) {
                            let name = std::path::Path::new(hf)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("handshake.cap");
                            lines.push(format!("File: {}", name));
                        }
                    } else {
                        lines.push("No handshake detected".to_string());
                    }
                }

                if let Some(packets) = data.get("total_packets_sent").and_then(|v| v.as_u64()) {
                    lines.push(format!("Packets: {}", packets));
                }

                if let Some(bursts) = data.get("deauth_bursts").and_then(|v| v.as_u64()) {
                    lines.push(format!("Bursts: {}", bursts));
                }

                if let Some(log) = data.get("log_file").and_then(|v| v.as_str()) {
                    let name = std::path::Path::new(log)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("log.txt");
                    lines.push(format!("Log: {}", name));
                }

                lines.push("Check Loot > Wireless".to_string());

                Ok(OperationOutcome::Success { summary: lines })
            }
        }
    }
}

pub struct ProbeSniffOp {
    interface: String,
    duration_secs: u32,
}

impl ProbeSniffOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
        }
    }
}

impl Operation for ProbeSniffOp {
    fn id(&self) -> &'static str {
        "probe_sniff"
    }

    fn title(&self) -> &'static str {
        "Probe Sniff"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_active_interface(ctx.ui.config)?;
        let iface = ctx.ui.config.settings.active_network_interface.clone();
        preflight::probe_sniff(ctx.ui.core, &iface)?;
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
        match picker::choose(&mut ctx.ui, "Sniff Duration", &durations, "Probe Sniff")? {
            PickerChoice::Selected(0) => self.duration_secs = 30,
            PickerChoice::Selected(1) => self.duration_secs = 60,
            PickerChoice::Selected(2) => self.duration_secs = 300,
            PickerChoice::Selected(3) => self.duration_secs = INDEFINITE_SECS,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        let duration_label = if self.duration_secs == INDEFINITE_SECS {
            "Indefinite".to_string()
        } else {
            format!("{}s", self.duration_secs)
        };
        vec![
            format!("Interface: {}", self.interface),
            format!("Duration: {}", duration_label),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
            interface: self.interface.clone(),
            duration: self.duration_secs,
            channel: 0,
        }));
        let result =
            jobs::dispatch_cancellable(ctx, "Probe Sniff", cmd, self.duration_secs as u64)?;

        match result {
            jobs::JobRunResult::Cancelled => Ok(OperationOutcome::Cancelled {
                summary: vec![
                    "Cancelled by user".to_string(),
                    "Partial results may be".to_string(),
                    "saved in loot/Wireless/".to_string(),
                ],
            }),
            jobs::JobRunResult::Completed { message, data } => {
                if let Some(lines) = preflight::preflight_only_summary(&data) {
                    return Ok(OperationOutcome::Success { summary: lines });
                }
                let mut lines = vec![message];
                if let Some(probes) = data.get("total_probes").and_then(|v| v.as_u64()) {
                    lines.push(format!("Probes: {}", probes));
                }
                if let Some(clients) = data.get("unique_clients").and_then(|v| v.as_u64()) {
                    lines.push(format!("Clients: {}", clients));
                }
                if let Some(networks) = data.get("unique_networks").and_then(|v| v.as_u64()) {
                    lines.push(format!("Networks: {}", networks));
                }
                Ok(OperationOutcome::Success { summary: lines })
            }
        }
    }
}

pub struct PmkidCaptureOp {
    interface: String,
    target_network: String,
    target_bssid: String,
    target_channel: u8,
    use_target: bool,
    duration_secs: u32,
}

impl PmkidCaptureOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            target_network: String::new(),
            target_bssid: String::new(),
            target_channel: 0,
            use_target: false,
            duration_secs: 0,
        }
    }
}

impl Operation for PmkidCaptureOp {
    fn id(&self) -> &'static str {
        "pmkid_capture"
    }

    fn title(&self) -> &'static str {
        "PMKID Capture"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "PMKID capture blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        let iface = ctx.ui.config.settings.active_network_interface.clone();
        preflight::pmkid_capture(ctx.ui.core, &iface)?;
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        self.target_network = ctx.ui.config.settings.target_network.clone();
        self.target_bssid = ctx.ui.config.settings.target_bssid.clone();
        self.target_channel = ctx.ui.config.settings.target_channel;

        let options = vec![
            if self.target_network.is_empty() {
                "Passive Capture".to_string()
            } else {
                format!("Target: {}", self.target_network)
            },
            "Passive (any network)".to_string(),
            "Indefinite (manual stop)".to_string(),
            "Cancel".to_string(),
        ];
        match picker::choose(&mut ctx.ui, "PMKID Mode", &options, "PMKID Capture")? {
            PickerChoice::Selected(0) if !self.target_network.is_empty() => {
                self.use_target = true;
                self.duration_secs = 30;
            }
            PickerChoice::Selected(1) | PickerChoice::Selected(0) => {
                self.use_target = false;
                self.duration_secs = 60;
            }
            PickerChoice::Selected(2) => {
                self.use_target = false;
                self.duration_secs = INDEFINITE_SECS;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        let target_label = if self.use_target && !self.target_network.is_empty() {
            format!("Target: {}", self.target_network)
        } else {
            "Target: Any".to_string()
        };
        let duration_label = if self.duration_secs == INDEFINITE_SECS {
            "Indefinite".to_string()
        } else {
            format!("{}s", self.duration_secs)
        };
        vec![
            target_label,
            format!("Interface: {}", self.interface),
            format!("Duration: {}", duration_label),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
            interface: self.interface.clone(),
            bssid: if self.use_target {
                Some(self.target_bssid.clone())
            } else {
                None
            },
            ssid: if self.use_target {
                Some(self.target_network.clone())
            } else {
                None
            },
            channel: if self.use_target {
                self.target_channel
            } else {
                0
            },
            duration: self.duration_secs,
        }));

        let result =
            jobs::dispatch_cancellable(ctx, "PMKID Capture", cmd, self.duration_secs as u64)?;

        match result {
            jobs::JobRunResult::Cancelled => Ok(OperationOutcome::Cancelled {
                summary: vec![
                    "Cancelled by user".to_string(),
                    "Partial results may be".to_string(),
                    "saved in loot/Wireless/".to_string(),
                ],
            }),
            jobs::JobRunResult::Completed { message, data } => {
                if let Some(lines) = preflight::preflight_only_summary(&data) {
                    return Ok(OperationOutcome::Success { summary: lines });
                }
                let mut lines = vec![message];
                if let Some(pmkids) = data.get("pmkids_captured").and_then(|v| v.as_u64()) {
                    lines.push(format!("PMKIDs: {}", pmkids));
                }
                if let Some(path) = data.get("hashcat_file").and_then(|v| v.as_str()) {
                    let name = std::path::Path::new(path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("pmkid.hc22000");
                    lines.push(format!("File: {}", name));
                }
                Ok(OperationOutcome::Success { summary: lines })
            }
        }
    }
}

// ============================================================================
// Evil Twin Attack Operation
// ============================================================================

pub struct EvilTwinAttackOp {
    interface: String,
    target_network: String,
    target_bssid: String,
    target_channel: u8,
    duration_secs: u64,
}

impl EvilTwinAttackOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            target_network: String::new(),
            target_bssid: String::new(),
            target_channel: 0,
            duration_secs: 0,
        }
    }
}

impl Operation for EvilTwinAttackOp {
    fn id(&self) -> &'static str {
        "evil_twin_attack"
    }

    fn title(&self) -> &'static str {
        "Evil Twin"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "Evil Twin blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;

        let target_network = ctx.ui.config.settings.target_network.clone();
        let target_bssid = ctx.ui.config.settings.target_bssid.clone();

        if target_network.is_empty() || target_bssid.is_empty() {
            bail!("No target network set. Scan networks first and select 'Set as Target'.");
        }

        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        self.target_network = target_network;
        self.target_bssid = target_bssid;
        self.target_channel = ctx.ui.config.settings.target_channel;

        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        let durations = vec![
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
            "30 minutes".to_string(),
        ];

        match picker::choose(&mut ctx.ui, "Attack Duration", &durations, "Evil Twin")? {
            PickerChoice::Selected(0) => self.duration_secs = 60,
            PickerChoice::Selected(1) => self.duration_secs = 300,
            PickerChoice::Selected(2) => self.duration_secs = 600,
            PickerChoice::Selected(3) => self.duration_secs = 1800,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn confirm_lines(&self) -> Vec<String> {
        vec![
            format!("Target: {}", self.target_network),
            format!("BSSID: {}", self.target_bssid),
            format!("Channel: {}", self.target_channel),
            format!("Interface: {}", self.interface),
            format!("Duration: {}s", self.duration_secs),
            "".to_string(),
            "Creates open AP copy to".to_string(),
            "capture connecting clients".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::EvilTwin(WifiEvilTwinArgs {
            ssid: self.target_network.clone(),
            target_bssid: Some(self.target_bssid.clone()),
            channel: self.target_channel,
            interface: self.interface.clone(),
            duration: self.duration_secs as u32,
            open: true,
        }));

        let result = jobs::dispatch_cancellable(ctx, "Evil Twin", cmd, self.duration_secs)?;

        match result {
            jobs::JobRunResult::Cancelled => Ok(OperationOutcome::Cancelled {
                summary: vec![
                    "Cancelled by user".to_string(),
                    "Check loot/Wireless/".to_string(),
                ],
            }),
            jobs::JobRunResult::Completed { message, data } => {
                if let Some(lines) = preflight::preflight_only_summary(&data) {
                    return Ok(OperationOutcome::Success { summary: lines });
                }
                let mut lines = vec![message];

                if let Some(clients) = data.get("clients_connected").and_then(|v| v.as_u64()) {
                    lines.push(format!("Clients: {}", clients));
                }

                if let Some(pcap) = data.get("pcap_file").and_then(|v| v.as_str()) {
                    let name = std::path::Path::new(pcap)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("capture.pcap");
                    lines.push(format!("PCAP: {}", name));
                }

                Ok(OperationOutcome::Success { summary: lines })
            }
        }
    }
}

// ============================================================================
// Karma Attack Operation
// ============================================================================

pub struct KarmaAttackOp {
    interface: String,
    duration_secs: u64,
    with_ap: bool,
}

impl KarmaAttackOp {
    pub fn new() -> Self {
        Self {
            interface: String::new(),
            duration_secs: 0,
            with_ap: false,
        }
    }
}

impl Operation for KarmaAttackOp {
    fn id(&self) -> &'static str {
        "karma_attack"
    }

    fn title(&self) -> &'static str {
        "Karma Attack"
    }

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()> {
        preflight::require_not_stealth(ctx.ui.config, "Karma blocked in stealth")?;
        preflight::require_active_interface(ctx.ui.config)?;
        self.interface = ctx.ui.config.settings.active_network_interface.clone();
        Ok(())
    }

    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool> {
        // Choose mode
        let modes = vec!["Passive (sniff only)".to_string(), "With AP".to_string()];

        match picker::choose(&mut ctx.ui, "Karma Mode", &modes, "Karma Attack")? {
            PickerChoice::Selected(0) => self.with_ap = false,
            PickerChoice::Selected(1) => self.with_ap = true,
            PickerChoice::Back | PickerChoice::Cancel => return Ok(false),
            _ => return Ok(false),
        }

        // Choose duration
        let durations = vec![
            "5 minutes".to_string(),
            "10 minutes".to_string(),
            "30 minutes".to_string(),
            "Indefinite".to_string(),
        ];

        match picker::choose(&mut ctx.ui, "Duration", &durations, "Karma Attack")? {
            PickerChoice::Selected(0) => self.duration_secs = 300,
            PickerChoice::Selected(1) => self.duration_secs = 600,
            PickerChoice::Selected(2) => self.duration_secs = 1800,
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

        let mode = if self.with_ap {
            "With fake AP"
        } else {
            "Passive sniff"
        };

        vec![
            format!("Interface: {}", self.interface),
            format!("Mode: {}", mode),
            format!("Duration: {}", duration_str),
            "".to_string(),
            "Responds to ALL probe".to_string(),
            "requests from devices".to_string(),
            "KEY2 cancels while running".to_string(),
        ]
    }

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome> {
        let cmd = Commands::Wifi(WifiCommand::Karma(WifiKarmaArgs {
            interface: self.interface.clone(),
            ap_interface: if self.with_ap {
                Some(self.interface.clone())
            } else {
                None
            },
            duration: self.duration_secs as u32,
            channel: 0, // hop channels
            with_ap: self.with_ap,
            ssid_whitelist: None,
            ssid_blacklist: None,
        }));

        let result = jobs::dispatch_cancellable(ctx, "Karma Attack", cmd, self.duration_secs)?;

        match result {
            jobs::JobRunResult::Cancelled => Ok(OperationOutcome::Cancelled {
                summary: vec![
                    "Cancelled by user".to_string(),
                    "Check loot/Wireless/".to_string(),
                ],
            }),
            jobs::JobRunResult::Completed { message, data } => {
                if let Some(lines) = preflight::preflight_only_summary(&data) {
                    return Ok(OperationOutcome::Success { summary: lines });
                }
                let mut lines = vec![message];

                if let Some(probes) = data.get("probes_captured").and_then(|v| v.as_u64()) {
                    lines.push(format!("Probes: {}", probes));
                }

                if let Some(devices) = data.get("unique_devices").and_then(|v| v.as_u64()) {
                    lines.push(format!("Devices: {}", devices));
                }

                if let Some(clients) = data.get("clients_connected").and_then(|v| v.as_u64()) {
                    if clients > 0 {
                        lines.push(format!("Clients connected: {}", clients));
                    }
                }

                Ok(OperationOutcome::Success { summary: lines })
            }
        }
    }
}
