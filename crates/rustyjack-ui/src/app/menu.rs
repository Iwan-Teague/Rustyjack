use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use rustyjack_commands::{Commands, WifiCommand, WifiRouteCommand, WifiRouteEnsureArgs};
use rustyjack_encryption::{clear_encryption_key, set_encryption_key};
use rustyjack_ipc::{JobState, OpsConfig};

use crate::{
    config::GuiConfig,
    core::CoreBridge,
    display::{
        wrap_text, DashboardView, Display, StatusOverlay, DIALOG_MAX_CHARS, DIALOG_VISIBLE_LINES,
    },
    input::{Button, ButtonPad},
    menu::{
        menu_title, ColorTarget, MenuAction, MenuEntry, MenuTree, OpsCategory, PipelineType,
        TxPowerSetting,
    },
    ops::{
        ethernet::{
            EthernetDiscoveryOp, EthernetInventoryOp, EthernetMitmOp, EthernetPortScanOp,
            EthernetSiteCredOp,
        },
        recon::{
            ArpScanOp, BandwidthMonitorOp, DnsCaptureOp, GatewayReconOp, MdnsScanOp, ServiceScanOp,
        },
        runner::OperationRunner,
        wifi::{DeauthAttackOp, EvilTwinAttackOp, KarmaAttackOp, PmkidCaptureOp, ProbeSniffOp},
        OperationContext,
    },
    stats::StatsSampler,
    ui::{layout::MENU_VISIBLE_ITEMS, UiContext},
    util::shorten_for_display,
};

use super::state::{App, ButtonAction, CancelDecision, ConfirmChoice, MenuState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionRoute {
    Navigation,
    Local(&'static str),
    Operation(&'static str),
    Info,
}

pub(crate) fn action_route(action: &MenuAction) -> ActionRoute {
    match action {
        MenuAction::Submenu(_) => ActionRoute::Navigation,
        MenuAction::RefreshConfig => ActionRoute::Local("reload_config"),
        MenuAction::SaveConfig => ActionRoute::Local("save_config"),
        MenuAction::SetColor(_) => ActionRoute::Local("pick_color"),
        MenuAction::RestartSystem => ActionRoute::Local("restart_system"),
        MenuAction::SystemUpdate => ActionRoute::Local("system_update"),
        MenuAction::SecureShutdown => ActionRoute::Local("secure_shutdown"),
        MenuAction::Loot(_) => ActionRoute::Local("show_loot"),
        MenuAction::DiscordUpload => ActionRoute::Local("discord_upload"),
        MenuAction::ViewDashboards => ActionRoute::Local("dashboard_view"),
        MenuAction::ToggleDiscord => ActionRoute::Local("toggle_discord"),
        MenuAction::ToggleLogs => ActionRoute::Local("toggle_logs"),
        MenuAction::ExportLogsToUsb => ActionRoute::Local("export_logs_to_usb"),
        MenuAction::TransferToUSB => ActionRoute::Local("transfer_to_usb"),
        MenuAction::HardwareDetect => ActionRoute::Local("show_hardware_detect"),
        MenuAction::SelectActiveInterface => ActionRoute::Local("select_active_interface"),
        MenuAction::ViewInterfaceStatus => ActionRoute::Local("view_interface_status"),
        MenuAction::ScanNetworks => ActionRoute::Local("scan_wifi_networks"),
        MenuAction::DeauthAttack => ActionRoute::Operation("DeauthAttackOp"),
        MenuAction::ConnectKnownNetwork => ActionRoute::Local("connect_known_network"),
        MenuAction::EvilTwinAttack => ActionRoute::Operation("EvilTwinAttackOp"),
        MenuAction::ProbeSniff => ActionRoute::Operation("ProbeSniffOp"),
        MenuAction::PmkidCapture => ActionRoute::Operation("PmkidCaptureOp"),
        MenuAction::CrackHandshake => ActionRoute::Local("launch_crack_handshake"),
        MenuAction::KarmaAttack => ActionRoute::Operation("KarmaAttackOp"),
        MenuAction::WifiStatus => ActionRoute::Local("show_wifi_status"),
        MenuAction::WifiDisconnect => ActionRoute::Local("disconnect_wifi"),
        MenuAction::WifiEnsureRoute => ActionRoute::Local("ensure_route"),
        MenuAction::ReconGateway => ActionRoute::Operation("GatewayReconOp"),
        MenuAction::ReconArpScan => ActionRoute::Operation("ArpScanOp"),
        MenuAction::ReconServiceScan => ActionRoute::Operation("ServiceScanOp"),
        MenuAction::ReconMdnsScan => ActionRoute::Operation("MdnsScanOp"),
        MenuAction::ReconBandwidth => ActionRoute::Operation("BandwidthMonitorOp"),
        MenuAction::ReconDnsCapture => ActionRoute::Operation("DnsCaptureOp"),
        MenuAction::ManageSavedNetworks => ActionRoute::Local("manage_saved_networks"),
        MenuAction::DnsSpoofStart => ActionRoute::Local("start_dns_spoof"),
        MenuAction::DnsSpoofStop => ActionRoute::Local("stop_dns_spoof"),
        MenuAction::ToggleDnsSpoof => ActionRoute::Local("toggle_dns_spoof"),
        MenuAction::ReverseShell => ActionRoute::Local("launch_reverse_shell"),
        MenuAction::AttackPipeline(_) => ActionRoute::Local("launch_attack_pipeline"),
        MenuAction::ToggleMacRandomization => ActionRoute::Local("toggle_mac_randomization"),
        MenuAction::TogglePerNetworkMac => ActionRoute::Local("toggle_per_network_mac"),
        MenuAction::RandomizeMacNow => ActionRoute::Local("randomize_mac_now"),
        MenuAction::ImportWifiFromUsb => ActionRoute::Local("import_wifi_from_usb"),
        MenuAction::ImportWebhookFromUsb => ActionRoute::Local("import_webhook_from_usb"),
        MenuAction::SetVendorMac => ActionRoute::Local("set_vendor_mac"),
        MenuAction::RestoreMac => ActionRoute::Local("restore_mac"),
        MenuAction::ToggleHostnameRandomization => {
            ActionRoute::Local("toggle_hostname_randomization")
        }
        MenuAction::RandomizeHostnameNow => ActionRoute::Local("randomize_hostname_now"),
        MenuAction::SetOperationMode(_) => ActionRoute::Local("select_operation_mode"),
        MenuAction::SetTxPower(_) => ActionRoute::Local("set_tx_power"),
        MenuAction::TogglePassiveMode => ActionRoute::Local("toggle_passive_mode"),
        MenuAction::ToggleOps(_) => ActionRoute::Local("toggle_ops"),
        MenuAction::PassiveRecon => ActionRoute::Local("launch_passive_recon"),
        MenuAction::EthernetDiscovery => ActionRoute::Operation("EthernetDiscoveryOp"),
        MenuAction::EthernetPortScan => ActionRoute::Operation("EthernetPortScanOp"),
        MenuAction::EthernetInventory => ActionRoute::Operation("EthernetInventoryOp"),
        MenuAction::EthernetMitm => ActionRoute::Operation("EthernetMitmOp"),
        MenuAction::EthernetMitmStatus => ActionRoute::Local("show_mitm_status"),
        MenuAction::EthernetMitmStop => ActionRoute::Local("stop_ethernet_mitm"),
        MenuAction::EthernetSiteCredPipeline => ActionRoute::Navigation,
        MenuAction::EthernetSiteCredCapture => ActionRoute::Operation("EthernetSiteCredOp"),
        MenuAction::BuildNetworkReport => ActionRoute::Local("build_network_report"),
        MenuAction::ToggleEncryptionMaster => ActionRoute::Local("toggle_encryption_master"),
        MenuAction::ToggleEncryptWebhook => ActionRoute::Local("toggle_encrypt_webhook"),
        MenuAction::ToggleEncryptLoot => ActionRoute::Local("toggle_encrypt_loot"),
        MenuAction::ToggleEncryptWifiProfiles => ActionRoute::Local("toggle_encrypt_wifi_profiles"),
        MenuAction::CompletePurge => ActionRoute::Local("complete_purge"),
        MenuAction::PurgeLogs => ActionRoute::Local("purge_logs"),
        MenuAction::Hotspot => ActionRoute::Local("manage_hotspot"),
        MenuAction::EncryptionLoadKey => ActionRoute::Local("load_encryption_key_from_usb"),
        MenuAction::EncryptionGenerateKey => ActionRoute::Local("generate_encryption_key_on_usb"),
        MenuAction::FullDiskEncryptionSetup => {
            ActionRoute::Local("start_full_disk_encryption_flow")
        }
        MenuAction::FullDiskEncryptionMigrate => ActionRoute::Local("start_fde_migration"),
        MenuAction::ShowInfo => ActionRoute::Info,
    }
}

// Map low-level Button values to higher-level ButtonAction values
impl App {
    pub(crate) fn map_button(&self, b: Button) -> ButtonAction {
        match b {
            Button::Up => ButtonAction::Up,
            Button::Down => ButtonAction::Down,
            Button::Left => ButtonAction::Back,
            Button::Right | Button::Select => ButtonAction::Select,
            Button::Key1 => ButtonAction::Refresh,
            Button::Key2 => ButtonAction::Cancel,
            Button::Key3 => ButtonAction::Reboot,
        }
    }

    /// Reset UI state and return to Home with isolation cleanup.
    /// This is the only place that clears global UI/daemon state for Home.
    pub(crate) fn go_home(&mut self) -> Result<()> {
        self.dashboard_view = None;
        self.active_mitm = None;
        self.menu_state.home();

        if let Err(e) = self.core.clear_active_interface() {
            tracing::warn!("clear_active_interface failed: {:#}", e);
            if let Err(err) = self.show_error_dialog("Home cleanup failed", &e) {
                tracing::warn!("Failed to show error dialog: {:#}", err);
            }
        }

        self.config.settings.active_network_interface.clear();
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;
        Ok(())
    }

    pub(crate) fn save_config_file(&mut self, path: &Path) -> Result<()> {
        self.config
            .save(path)
            .with_context(|| format!("saving {}", path.display()))
    }

    pub(crate) fn save_config_warn(&mut self, path: &Path, context: &str) {
        if let Err(err) = self.save_config_file(path) {
            tracing::warn!("{}: {:#}", context, err);
        }
    }

    pub(crate) fn confirm_yes_no<I, S>(&mut self, title: &str, body: I) -> Result<ConfirmChoice>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut idx = 0usize;
        let body_lines: Vec<String> = body
            .into_iter()
            .map(|line| line.as_ref().to_string())
            .collect();

        loop {
            let overlay = self.stats.snapshot();
            let mut content = Vec::with_capacity(body_lines.len() + 4);
            content.push(title.to_string());
            content.extend(body_lines.iter().cloned());
            content.push(String::new());
            content.push(format!("{}Yes", if idx == 0 { "> " } else { "  " }));
            content.push(format!("{}No", if idx == 1 { "> " } else { "  " }));
            self.display.draw_dialog(&content, &overlay)?;

            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up | ButtonAction::Down => idx ^= 1,
                ButtonAction::Select => {
                    return Ok(if idx == 0 {
                        ConfirmChoice::Yes
                    } else {
                        ConfirmChoice::No
                    })
                }
                ButtonAction::Back => return Ok(ConfirmChoice::Back),
                ButtonAction::Cancel => return Ok(ConfirmChoice::Cancel),
                ButtonAction::Refresh => {}
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
            }
        }
    }

    pub(crate) fn confirm_yes_no_bool<I, S>(&mut self, title: &str, body: I) -> Result<bool>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(matches!(
            self.confirm_yes_no(title, body)?,
            ConfirmChoice::Yes
        ))
    }

    pub(crate) fn confirm_cancel(&mut self, label: &str) -> Result<bool> {
        let choice = self.confirm_yes_no(
            &format!("Cancel {label}?"),
            ["Stop the operation?", "Yes = stop now", "No = keep running"],
        )?;
        Ok(matches!(choice, ConfirmChoice::Yes | ConfirmChoice::Cancel))
    }

    pub(crate) fn check_cancel_request(&mut self, label: &str) -> Result<CancelDecision> {
        if let Some(button) = self.buttons.try_read()? {
            if matches!(self.map_button(button), ButtonAction::Cancel) {
                if self.confirm_cancel(label)? {
                    return Ok(CancelDecision::Cancel);
                }
            }
        }
        Ok(CancelDecision::Continue)
    }

    pub(crate) fn show_error_dialog(&mut self, title: &str, err: &anyhow::Error) -> Result<()> {
        let mut lines = Vec::new();
        for (idx, cause) in err.chain().enumerate() {
            if idx == 0 {
                lines.push(format!("Error: {}", cause));
            } else {
                lines.push(format!("Cause: {}", cause));
            }
        }
        lines.push("Press SELECT to continue".to_string());
        self.show_message(title, lines)
    }

    pub(crate) fn try_load_saved_key(&mut self) {
        let path = self.config.settings.encryption_key_path.clone();
        if path.is_empty() {
            return;
        }
        let key_path = PathBuf::from(path);
        if !key_path.exists() {
            return;
        }
        if let Ok(key) = self.parse_key_file(&key_path) {
            clear_encryption_key();
            if let Err(err) = set_encryption_key(&key) {
                tracing::warn!(
                    "Failed to load encryption key from {}: {:#}",
                    key_path.display(),
                    err
                );
            } else {
                tracing::info!(
                    "Loaded encryption key from saved path {}",
                    key_path.display()
                );
            }
            clear_encryption_key();
        }
    }

    /// Attempt to load the saved key if none is currently loaded.
    pub(crate) fn ensure_saved_key_loaded(&mut self) {
        if rustyjack_encryption::encryption_enabled() {
            return;
        }
        let path = self.config.settings.encryption_key_path.clone();
        if path.is_empty() {
            return;
        }
        let key_path = PathBuf::from(path);
        if !key_path.exists() {
            return;
        }
        if let Ok(key) = self.parse_key_file(&key_path) {
            if let Err(err) = set_encryption_key(&key) {
                tracing::warn!(
                    "Failed to load encryption key from {}: {:#}",
                    key_path.display(),
                    err
                );
            }
        }
    }

    pub(crate) fn show_wifi_status(&mut self) -> Result<()> {
        let Some(iface) = self.require_connected_wireless("WiFi Status")? else {
            return Ok(());
        };
        let status = match self.fetch_wifi_status(Some(iface.clone())) {
            Ok(s) => s,
            Err(e) => {
                return self.show_message(
                    "WiFi Status",
                    [
                        "Failed to read WiFi status",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
        };
        let route = self.fetch_route_snapshot().ok();

        let mut lines = Vec::new();
        lines.push(format!(
            "Connected: {}",
            if status.connected { "YES" } else { "NO" }
        ));
        if let Some(ssid) = status.ssid {
            lines.push(format!("SSID: {}", ssid));
        }
        if let Some(intf) = status.interface {
            lines.push(format!("Iface: {}", intf));
        }
        if let Some(sig) = status.signal_dbm {
            lines.push(format!("Signal: {} dBm", sig));
        }
        if let Some(rt) = route {
            if let Some(gw) = rt.default_gateway {
                lines.push(format!("Gateway: {}", gw));
            }
            if let Some(di) = rt.default_interface {
                lines.push(format!("Default: {}", di));
            }
        }
        if !status.connected {
            lines.push("No active connection detected.".to_string());
        }

        if lines.len() == 1 {
            lines.push("No WiFi info found".to_string());
        }

        self.show_message("WiFi Status", lines.iter().map(|s| s.as_str()))
    }

    pub(crate) fn disconnect_wifi(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        if active_interface.is_empty() {
            return self.show_message("WiFi", ["No active interface set"]);
        }
        match self.core.wifi_disconnect(&active_interface) {
            Ok(disconnected) => {
                let msg = if disconnected {
                    format!("Disconnected from {}", active_interface)
                } else {
                    format!("{} was already disconnected", active_interface)
                };
                self.show_message("WiFi", [msg])
            }
            Err(e) => self.show_message("WiFi", [format!("Disconnect failed: {}", e)]),
        }
    }

    pub(crate) fn ensure_route(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        if active_interface.is_empty() {
            return self.show_message("Route", ["No active interface set"]);
        }

        match self.ensure_route_for_interface(&active_interface) {
            Ok(Some(msg)) => self.show_message("Route", [msg]),
            Ok(None) => Ok(()),
            Err(e) => self.show_message("Route", [format!("Route failed: {}", e)]),
        }
    }

    pub(crate) fn require_connected_wireless(&mut self, title: &str) -> Result<Option<String>> {
        let iface = self.config.settings.active_network_interface.clone();
        if iface.is_empty() {
            self.show_message(
                title,
                ["No active interface set", "Run Hardware Sanity Check first"],
            )?;
            return Ok(None);
        }

        let wireless_dir = format!("/sys/class/net/{}/wireless", iface);
        if !Path::new(&wireless_dir).exists() {
            self.show_message(
                title,
                [
                    &format!("Interface: {}", iface),
                    "Requires wireless interface",
                    "connected with an IP.",
                ],
            )?;
            return Ok(None);
        }

        if !self.interface_has_carrier(&iface) {
            self.show_message(
                title,
                [
                    &format!("Interface: {}", iface),
                    "Link is down / no AP",
                    "Connect first, then retry",
                ],
            )?;
            return Ok(None);
        }

        if !self.interface_has_ip(&iface) {
            self.show_message(
                title,
                [
                    &format!("Interface: {}", iface),
                    "No IPv4 address.",
                    "Connect to a network",
                    "before running this.",
                ],
            )?;
            return Ok(None);
        }

        if !self.mode_allows_active("Blocked in Stealth mode")? {
            return Ok(None);
        }

        Ok(Some(iface))
    }

    pub(crate) fn ensure_route_for_interface(&mut self, interface: &str) -> Result<Option<String>> {
        if interface.is_empty() {
            return Ok(None);
        }

        let args = WifiRouteEnsureArgs {
            interface: interface.to_string(),
        };

        let result = self.core.dispatch(Commands::Wifi(WifiCommand::Route(
            WifiRouteCommand::Ensure(args),
        )));

        match result {
            Ok((msg, _)) => Ok(Some(msg)),
            Err(e) => {
                let err = e.to_string();
                let mut lines = vec![format!("Route failed for {}", interface)];
                lines.push(shorten_for_display(&err, 90));
                if err.contains("No gateway found") {
                    lines.push("No gateway detected; connect first.".to_string());
                }
                self.show_message("Route", lines)?;
                Ok(None)
            }
        }
    }

    pub(crate) fn status_overlay(&self) -> StatusOverlay {
        let mut status = self.stats.snapshot();
        let settings = &self.config.settings;

        status.target_network = settings.target_network.clone();
        status.target_bssid = settings.target_bssid.clone();
        status.target_channel = settings.target_channel;
        if status.active_interface.is_empty() {
            status.active_interface = settings.active_network_interface.clone();
        }

        let interface_name = &status.active_interface;
        let interface_mac = self.read_interface_mac(interface_name);
        let current_mac = interface_mac
            .clone()
            .or_else(|| settings.current_macs.get(interface_name).cloned())
            .unwrap_or_default();
        let original_mac = settings
            .original_macs
            .get(interface_name)
            .cloned()
            .unwrap_or_else(|| interface_mac.unwrap_or_else(|| current_mac.clone()));

        status.current_mac = current_mac.to_uppercase();
        status.original_mac = original_mac.to_uppercase();

        status
    }

    pub(crate) fn ops_category_label(category: OpsCategory) -> &'static str {
        match category {
            OpsCategory::Wifi => "WiFi Ops",
            OpsCategory::Ethernet => "Ethernet Ops",
            OpsCategory::Hotspot => "Hotspot Ops",
            OpsCategory::Portal => "Portal Ops",
            OpsCategory::Storage => "Storage Ops",
            OpsCategory::Power => "Power Ops",
            OpsCategory::Update => "Update Ops",
            OpsCategory::System => "System Ops",
            OpsCategory::Dev => "Dev Ops",
            OpsCategory::Offensive => "Offensive Ops",
            OpsCategory::Loot => "Loot Ops",
            OpsCategory::Process => "Process Ops",
        }
    }

    pub(crate) fn ops_enabled_in_overlay(status: &StatusOverlay, category: OpsCategory) -> bool {
        match category {
            OpsCategory::Wifi => status.ops_wifi,
            OpsCategory::Ethernet => status.ops_ethernet,
            OpsCategory::Hotspot => status.ops_hotspot,
            OpsCategory::Portal => status.ops_portal,
            OpsCategory::Storage => status.ops_storage,
            OpsCategory::Power => status.ops_power,
            OpsCategory::Update => status.ops_update,
            OpsCategory::System => status.ops_system,
            OpsCategory::Dev => status.ops_dev,
            OpsCategory::Offensive => status.ops_offensive,
            OpsCategory::Loot => status.ops_loot,
            OpsCategory::Process => status.ops_process,
        }
    }

    pub(crate) fn ops_enabled_in_config(config: &OpsConfig, category: OpsCategory) -> bool {
        match category {
            OpsCategory::Wifi => config.wifi_ops,
            OpsCategory::Ethernet => config.eth_ops,
            OpsCategory::Hotspot => config.hotspot_ops,
            OpsCategory::Portal => config.portal_ops,
            OpsCategory::Storage => config.storage_ops,
            OpsCategory::Power => config.power_ops,
            OpsCategory::Update => config.update_ops,
            OpsCategory::System => config.system_ops,
            OpsCategory::Dev => config.dev_ops,
            OpsCategory::Offensive => config.offensive_ops,
            OpsCategory::Loot => config.loot_ops,
            OpsCategory::Process => config.process_ops,
        }
    }

    pub(crate) fn set_ops_config_value(
        config: &mut OpsConfig,
        category: OpsCategory,
        enabled: bool,
    ) {
        match category {
            OpsCategory::Wifi => config.wifi_ops = enabled,
            OpsCategory::Ethernet => config.eth_ops = enabled,
            OpsCategory::Hotspot => config.hotspot_ops = enabled,
            OpsCategory::Portal => config.portal_ops = enabled,
            OpsCategory::Storage => config.storage_ops = enabled,
            OpsCategory::Power => config.power_ops = enabled,
            OpsCategory::Update => config.update_ops = enabled,
            OpsCategory::System => config.system_ops = enabled,
            OpsCategory::Dev => config.dev_ops = enabled,
            OpsCategory::Offensive => config.offensive_ops = enabled,
            OpsCategory::Loot => config.loot_ops = enabled,
            OpsCategory::Process => config.process_ops = enabled,
        }
    }

    pub(crate) fn read_interface_mac(&self, interface: &str) -> Option<String> {
        if interface.is_empty() {
            return None;
        }
        let path = format!("/sys/class/net/{}/address", interface);
        fs::read_to_string(&path)
            .ok()
            .map(|mac| mac.trim().to_uppercase())
    }

    pub(crate) fn interface_oper_state(&self, interface: &str) -> String {
        if interface.is_empty() {
            return "unknown".to_string();
        }
        let oper_path = format!("/sys/class/net/{}/operstate", interface);
        fs::read_to_string(&oper_path)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string()
    }

    pub(crate) fn interface_admin_up(&self, interface: &str) -> bool {
        if interface.is_empty() {
            return false;
        }
        let flags_path = format!("/sys/class/net/{}/flags", interface);
        let flags = match fs::read_to_string(&flags_path) {
            Ok(val) => val.trim().to_string(),
            Err(_) => return false,
        };
        let hex = flags.trim_start_matches("0x");
        let parsed = u32::from_str_radix(hex, 16).or_else(|_| flags.parse::<u32>());
        match parsed {
            Ok(value) => value & 0x1 != 0,
            Err(_) => false,
        }
    }

    pub(crate) fn interface_is_up(&self, interface: &str) -> bool {
        self.interface_admin_up(interface)
    }

    pub(crate) fn wait_for_interface_up(&self, interface: &str, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.interface_is_up(interface) {
                return true;
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.interface_is_up(interface)
    }

    pub(crate) fn wait_for_interface_up_with_ip(&self, interface: &str, timeout: Duration) -> bool {
        let start = Instant::now();

        // Wait for interface to be administratively UP (not just existence)
        // For ethernet:
        // - No carrier: fails immediately at daemon (~1 second)
        // - Has carrier, DHCP works: succeeds in 5-10 seconds
        // - Has carrier, slow DHCP: succeeds within 15 seconds (3 retries × 5s)
        // - No DHCP server: fails after ~15 seconds
        while start.elapsed() < timeout {
            if self.interface_is_up(interface) {
                // Interface is up - wait a bit more to ensure DHCP fully completes
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining > Duration::from_millis(500) {
                    thread::sleep(Duration::from_millis(500));
                    // Check one more time to ensure it stays up
                    if self.interface_is_up(interface) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }

        // Final check: interface is up
        self.interface_is_up(interface)
    }

    pub(crate) fn interface_has_carrier(&self, interface: &str) -> bool {
        if interface.is_empty() {
            return false;
        }
        let carrier_path = format!("/sys/class/net/{}/carrier", interface);
        let oper_state = self.interface_oper_state(interface);
        let oper_ready = matches!(oper_state.as_str(), "up" | "unknown");
        match fs::read_to_string(&carrier_path) {
            Ok(val) => val.trim() == "1" || oper_ready,
            Err(_) => oper_ready,
        }
    }

    pub(crate) fn confirm_reboot(&mut self) -> Result<()> {
        // Ask the user to confirm reboot — waits for explicit confirmation
        let overlay = self.stats.snapshot();
        let content = vec![
            "Confirm reboot".to_string(),
            "SELECT = Reboot".to_string(),
            "LEFT/KEY2 = Cancel".to_string(),
        ];

        self.display.draw_dialog(&content, &overlay)?;

        loop {
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Select => match self.core.system_reboot() {
                    Ok(_) => {
                        std::process::exit(0);
                    }
                    Err(err) => {
                        let msg = shorten_for_display(&err.to_string(), 90);
                        self.show_message("Reboot Failed", [msg])?;
                    }
                },
                ButtonAction::Back | ButtonAction::Cancel => {
                    // Cancel and return
                    break;
                }
                ButtonAction::Refresh => {
                    // redraw the dialog
                    self.display.draw_dialog(&content, &overlay)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Run a command with cancel support - shows progress and allows user to cancel
    /// Returns Ok(Some(result)) if completed, Ok(None) if cancelled
    pub(crate) fn dispatch_cancellable(
        &mut self,
        attack_name: &str,
        cmd: Commands,
        duration_secs: u64,
    ) -> Result<Option<(String, serde_json::Value)>> {
        use std::time::{Duration, Instant};

        let job_id = self.core.start_core_command(cmd)?;
        let start = Instant::now();
        let mut last_displayed_secs: u64 = u64::MAX; // Force initial draw
        let poll_interval = Duration::from_millis(200);
        let mut last_poll = Instant::now() - poll_interval;
        let mut last_status = None;

        loop {
            let elapsed = start.elapsed().as_secs();

            // Check for cancel (non-blocking button check)
            if matches!(
                self.check_cancel_request(attack_name)?,
                CancelDecision::Cancel
            ) {
                self.show_progress(attack_name, ["Cancelling...", "Please wait", ""])?;
                if let Err(e) = self.core.cancel_job(job_id) {
                    self.show_error_dialog(&format!("Cancel failed: {attack_name}"), &e)?;
                    self.go_home()?;
                    return Ok(None);
                }

                let cancel_start = Instant::now();
                while cancel_start.elapsed() < Duration::from_secs(3) {
                    let st = self.core.job_status(job_id)?;
                    if matches!(
                        st.state,
                        JobState::Cancelled | JobState::Failed | JobState::Completed
                    ) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

                self.show_message(
                    &format!("{attack_name} Cancelled"),
                    [
                        "Operation stopped early",
                        "",
                        "Partial results may be",
                        "saved in loot folder",
                    ],
                )?;
                self.go_home()?;
                return Ok(None);
            }

            if last_status.is_none() || last_poll.elapsed() >= poll_interval {
                last_status = Some(self.core.job_status(job_id)?);
                last_poll = Instant::now();
            }

            if let Some(status) = last_status.as_ref() {
                match status.state {
                    JobState::Completed => {
                        let value = status
                            .result
                            .clone()
                            .ok_or_else(|| anyhow!("Job completed without result"))?;
                        let message = value
                            .get("message")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| anyhow!("Job result missing message"))?
                            .to_string();
                        let data = value
                            .get("data")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        return Ok(Some((message, data)));
                    }
                    JobState::Failed => {
                        let err_msg = status
                            .error
                            .as_ref()
                            .map(|e| e.message.clone())
                            .unwrap_or_else(|| "Job failed".to_string());
                        let detail = status.error.as_ref().and_then(|e| e.detail.clone());
                        let full = if let Some(detail) = detail {
                            format!("{} ({})", err_msg, detail)
                        } else {
                            err_msg
                        };
                        bail!("Job failed: {}", full);
                    }
                    JobState::Cancelled => {
                        self.show_message(
                            &format!("{} Cancelled", attack_name),
                            [
                                "Attack stopped early",
                                "",
                                "Partial results may be",
                                "saved in loot folder",
                            ],
                        )?;
                        return Ok(None);
                    }
                    JobState::Queued | JobState::Running => {}
                }
            }

            // Only redraw if seconds changed (reduces flicker significantly)
            if elapsed != last_displayed_secs {
                last_displayed_secs = elapsed;

                let progress = if duration_secs > 0 {
                    (elapsed as f32 / duration_secs as f32).min(1.0) * 100.0
                } else {
                    0.0
                };

                let msg = if duration_secs > 0 && elapsed < duration_secs {
                    format!("{}s/{}s [KEY2=Cancel]", elapsed, duration_secs)
                } else if duration_secs > 0 {
                    "Finalizing... [KEY2=Cancel]".to_string()
                } else {
                    format!("Elapsed: {}s [KEY2=Cancel]", elapsed)
                };

                let overlay = self.stats.snapshot();
                self.display
                    .draw_progress_dialog(attack_name, &msg, progress, &overlay)?;
            }

            // Sleep briefly between button checks (50ms for responsive cancellation)
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl App {
    pub fn new() -> Result<Self> {
        let core = CoreBridge::with_root(None)?;
        let root = core.root().to_path_buf();
        let config = GuiConfig::load(&root)?;
        let mut display = Display::new(&config.colors)?;
        let buttons = ButtonPad::new(&config.pins)?;

        // Show splash screen during initialization
        let splash_path = root.join("img").join("rustyjack.png");
        if let Err(err) = display.show_splash_screen(&splash_path) {
            tracing::warn!("Splash screen failed: {:#}", err);
        }

        // Let splash show while stats sampler starts up
        let stats = StatsSampler::spawn(core.clone(), config.pins.status_led_pin);

        let mut app = Self {
            core,
            display,
            buttons,
            config,
            menu: MenuTree::new(),
            menu_state: MenuState::new(),
            stats,
            root,
            dashboard_view: None,
            active_mitm: None,
        };
        // Apply log preference from config at startup so the backend honors it
        if let Err(err) = app.apply_log_setting() {
            tracing::warn!("Failed to apply logging config: {}", err);
        }
        app.try_load_saved_key();
        rustyjack_encryption::set_wifi_profile_encryption(app.wifi_encryption_active());
        rustyjack_encryption::set_loot_encryption(app.loot_encryption_active());
        Ok(app)
    }

    pub fn run(mut self) -> Result<()> {
        loop {
            if let Some(view) = self.dashboard_view {
                // Dashboard mode
                let status = self.status_overlay();
                self.display.draw_dashboard(view, &status)?;

                let button = self.buttons.wait_for_press()?;
                match self.map_button(button) {
                    ButtonAction::Back => {
                        // Exit dashboard, return to menu
                        self.dashboard_view = None;
                    }
                    ButtonAction::Select => {
                        // Cycle to next dashboard
                        self.dashboard_view = Some(match view {
                            DashboardView::SystemHealth => DashboardView::TargetStatus,
                            DashboardView::TargetStatus => DashboardView::MacStatus,
                            DashboardView::MacStatus => DashboardView::NetworkInterfaces,
                            DashboardView::NetworkInterfaces => DashboardView::SystemHealth,
                        });
                    }
                    ButtonAction::Refresh => {
                        // force redraw; nothing else required (loop will redraw)
                    }
                    ButtonAction::Cancel => {}
                    ButtonAction::Reboot => {
                        self.confirm_reboot()?;
                    }
                    _ => {}
                }
            } else {
                // Menu mode
                let entries = self.render_menu()?;
                let button = self.buttons.wait_for_press()?;
                match self.map_button(button) {
                    ButtonAction::Up => self.menu_state.move_up(entries.len()),
                    ButtonAction::Down => self.menu_state.move_down(entries.len()),
                    ButtonAction::Back => {
                        self.menu_state.back();
                    }
                    ButtonAction::Select => {
                        if let Some(entry) = entries.get(self.menu_state.selection) {
                            let action = entry.action.clone();
                            if let Err(e) = self.execute_action(action) {
                                tracing::error!("Menu action failed: {:#}", e);
                                self.show_error_dialog("Operation failed", &e)?;
                            }
                        }
                    }
                    ButtonAction::Refresh => {
                        // Force refresh — nothing required here because the loop redraws
                    }
                    ButtonAction::Cancel => {}
                    ButtonAction::Reboot => self.confirm_reboot()?,
                }
            }
        }
    }

    pub(crate) fn render_menu(&mut self) -> Result<Vec<MenuEntry>> {
        let status = self.status_overlay();
        let mut entries = self.menu.entries(self.menu_state.current_id())?;

        // Dynamic label updates based on current settings
        for entry in &mut entries {
            match &entry.action {
                MenuAction::ToggleDiscord => {
                    let state = if self.config.settings.discord_enabled {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Discord [{}]", state);
                }
                MenuAction::ToggleLogs => {
                    let state = if self.config.settings.logs_enabled {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Logs [{}]", state);
                }
                MenuAction::ToggleMacRandomization => {
                    let state = if self.config.settings.mac_randomization_enabled {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Auto MAC [{}]", state);
                }
                MenuAction::TogglePerNetworkMac => {
                    let state = if self.config.settings.per_network_mac_enabled {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Per-Network MAC [{}]", state);
                }
                MenuAction::ToggleHostnameRandomization => {
                    let state = if self.config.settings.hostname_randomization_enabled {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Auto Hostname [{}]", state);
                }
                MenuAction::TogglePassiveMode => {
                    let state = if self.config.settings.passive_mode_enabled {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Passive [{}]", state);
                }
                MenuAction::ToggleOps(category) => {
                    let enabled = Self::ops_enabled_in_overlay(&status, *category);
                    let state = if enabled { "ON" } else { "OFF" };
                    entry.label = format!("{} [{}]", Self::ops_category_label(*category), state);
                }
                MenuAction::Submenu("aops") => {
                    entry.label = format!("Mode: {}", self.mode_display_name());
                }
                MenuAction::SetOperationMode(mode) => {
                    let name = self.mode_display(*mode);
                    let active = self
                        .config
                        .settings
                        .operation_mode
                        .eq_ignore_ascii_case(mode);
                    let prefix = if active { "*" } else { " " };
                    entry.label = format!("{} {}", prefix, name);
                }
                MenuAction::SetTxPower(level) => {
                    let (base, key) = Self::tx_power_label(*level);
                    let active = self
                        .config
                        .settings
                        .tx_power_level
                        .eq_ignore_ascii_case(key);
                    let prefix = if active { "*" } else { " " };
                    entry.label = format!("{} {}", prefix, base);
                }
                MenuAction::ToggleEncryptionMaster => {
                    let state = if self.config.settings.encryption_enabled {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Encryption [{}]", state);
                }
                MenuAction::ToggleEncryptWebhook => {
                    let state = if self.config.settings.encrypt_discord_webhook {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Webhook [{}]", state);
                }
                MenuAction::ToggleEncryptLoot => {
                    let state = if self.config.settings.encrypt_loot {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("Loot [{}]", state);
                }
                MenuAction::ToggleEncryptWifiProfiles => {
                    let state = if self.config.settings.encrypt_wifi_profiles {
                        "ON"
                    } else {
                        "OFF"
                    };
                    entry.label = format!("WiFi Profiles [{}]", state);
                }
                MenuAction::ToggleDnsSpoof => {
                    let is_running = status.dns_spoof_running;
                    let state = if is_running { "ON" } else { "OFF" };
                    entry.label = format!("DNS Spoof [{}]", state);
                }
                _ => {}
            }
        }

        if entries.is_empty() {
            entries.push(MenuEntry {
                label: " Nothing here".to_string(),
                action: MenuAction::ShowInfo,
            });
        }
        if self.menu_state.selection >= entries.len() {
            self.menu_state.selection = entries.len().saturating_sub(1);
        }
        // When there are more entries than fit on-screen, show a sliding window
        // so the selected item is always visible. MenuState::offset tracks the
        // first item index in the current view.
        let total = entries.len();
        if self.menu_state.selection >= total && total > 0 {
            self.menu_state.selection = total - 1;
        }
        // clamp offset
        if self.menu_state.offset >= total {
            self.menu_state.offset = 0;
        }

        let start = self.menu_state.offset.min(total);
        let _end = (start + MENU_VISIBLE_ITEMS).min(total);

        let labels: Vec<String> = entries
            .iter()
            .skip(start)
            .take(MENU_VISIBLE_ITEMS)
            .map(|entry| entry.label.clone())
            .collect();

        // selected index relative to the slice
        let displayed_selected = if total == 0 {
            0
        } else {
            self.menu_state.selection.saturating_sub(start)
        };

        self.display.draw_menu(
            menu_title(self.menu_state.current_id()),
            &labels,
            displayed_selected,
            &status,
        )?;
        Ok(entries)
    }

    pub(crate) fn execute_action(&mut self, action: MenuAction) -> Result<()> {
        match action {
            MenuAction::Submenu(id) => self.menu_state.enter(id),
            MenuAction::RefreshConfig => self.reload_config()?,
            MenuAction::SaveConfig => self.save_config()?,
            MenuAction::SetColor(target) => self.pick_color(target)?,
            MenuAction::RestartSystem => self.restart_system()?,
            MenuAction::SystemUpdate => self.system_update()?,
            MenuAction::SecureShutdown => self.secure_shutdown()?,
            MenuAction::Loot(section) => self.show_loot(section)?,
            MenuAction::DiscordUpload => self.discord_upload()?,
            MenuAction::ToggleLogs => self.toggle_logs()?,
            MenuAction::ViewDashboards => {
                self.dashboard_view = Some(DashboardView::SystemHealth);
            }
            MenuAction::ToggleDiscord => self.toggle_discord()?,
            MenuAction::ExportLogsToUsb => self.export_logs_to_usb()?,
            MenuAction::TransferToUSB => self.transfer_to_usb()?,
            MenuAction::HardwareDetect => self.show_hardware_detect()?,
            MenuAction::SelectActiveInterface => self.select_active_interface()?,
            MenuAction::ViewInterfaceStatus => self.view_interface_status()?,
            MenuAction::ScanNetworks => self.scan_wifi_networks()?,
            MenuAction::DeauthAttack => self.run_operation(DeauthAttackOp::new())?,
            MenuAction::ConnectKnownNetwork => self.connect_known_network()?,
            MenuAction::EvilTwinAttack => self.run_operation(EvilTwinAttackOp::new())?,
            MenuAction::ProbeSniff => self.run_operation(ProbeSniffOp::new())?,
            MenuAction::PmkidCapture => self.run_operation(PmkidCaptureOp::new())?,
            MenuAction::CrackHandshake => self.launch_crack_handshake()?,
            MenuAction::KarmaAttack => self.run_operation(KarmaAttackOp::new())?,
            MenuAction::WifiStatus => self.show_wifi_status()?,
            MenuAction::WifiDisconnect => self.disconnect_wifi()?,
            MenuAction::WifiEnsureRoute => self.ensure_route()?,
            MenuAction::ManageSavedNetworks => self.manage_saved_networks()?,
            MenuAction::ReconGateway => self.run_operation(GatewayReconOp::new())?,
            MenuAction::ReconArpScan => self.run_operation(ArpScanOp::new())?,
            MenuAction::ReconServiceScan => self.run_operation(ServiceScanOp::new())?,
            MenuAction::ReconMdnsScan => self.run_operation(MdnsScanOp::new())?,
            MenuAction::ReconBandwidth => self.run_operation(BandwidthMonitorOp::new())?,
            MenuAction::ReconDnsCapture => self.run_operation(DnsCaptureOp::new())?,
            MenuAction::DnsSpoofStart => self.start_dns_spoof()?,
            MenuAction::DnsSpoofStop => self.stop_dns_spoof()?,
            MenuAction::ToggleDnsSpoof => self.toggle_dns_spoof()?,
            MenuAction::ReverseShell => self.launch_reverse_shell()?,
            MenuAction::AttackPipeline(pipeline_type) => {
                if let Err(e) = self.launch_attack_pipeline(pipeline_type) {
                    let msg = shorten_for_display(&e.to_string(), 20);
                    self.show_message("Pipeline Error", [msg])?;
                }
            }
            MenuAction::ToggleMacRandomization => self.toggle_mac_randomization()?,
            MenuAction::TogglePerNetworkMac => self.toggle_per_network_mac()?,
            MenuAction::ToggleHostnameRandomization => self.toggle_hostname_randomization()?,
            MenuAction::RandomizeMacNow => self.randomize_mac_now()?,
            MenuAction::SetVendorMac => self.set_vendor_mac()?,
            MenuAction::RandomizeHostnameNow => self.randomize_hostname_now()?,
            MenuAction::RestoreMac => self.restore_mac()?,
            MenuAction::SetTxPower(level) => self.set_tx_power(level)?,
            MenuAction::TogglePassiveMode => self.toggle_passive_mode()?,
            MenuAction::ToggleOps(category) => self.toggle_ops(category)?,
            MenuAction::PassiveRecon => self.launch_passive_recon()?,
            MenuAction::EthernetDiscovery => self.run_operation(EthernetDiscoveryOp::new())?,
            MenuAction::EthernetPortScan => self.run_operation(EthernetPortScanOp::new())?,
            MenuAction::EthernetInventory => self.run_operation(EthernetInventoryOp::new())?,
            MenuAction::EthernetMitm => self.run_operation(EthernetMitmOp::new())?,
            MenuAction::EthernetMitmStatus => self.show_mitm_status()?,
            MenuAction::EthernetMitmStop => self.stop_ethernet_mitm()?,
            MenuAction::EthernetSiteCredPipeline => self.menu_state.enter("aethp"),
            MenuAction::EthernetSiteCredCapture => self.run_operation(EthernetSiteCredOp::new())?,
            MenuAction::BuildNetworkReport => self.build_network_report()?,
            MenuAction::ToggleEncryptionMaster => self.toggle_encryption_master()?,
            MenuAction::ToggleEncryptWebhook => self.toggle_encrypt_webhook()?,
            MenuAction::ToggleEncryptLoot => self.toggle_encrypt_loot()?,
            MenuAction::ToggleEncryptWifiProfiles => self.toggle_encrypt_wifi_profiles()?,
            MenuAction::ImportWifiFromUsb => self.import_wifi_from_usb()?,
            MenuAction::ImportWebhookFromUsb => self.import_webhook_from_usb()?,
            MenuAction::CompletePurge => self.complete_purge()?,
            MenuAction::PurgeLogs => self.purge_logs()?,
            MenuAction::Hotspot => self.manage_hotspot()?,
            MenuAction::EncryptionLoadKey => self.load_encryption_key_from_usb()?,
            MenuAction::EncryptionGenerateKey => self.generate_encryption_key_on_usb()?,
            MenuAction::FullDiskEncryptionSetup => self.start_full_disk_encryption_flow()?,
            MenuAction::FullDiskEncryptionMigrate => self.start_fde_migration()?,
            MenuAction::SetOperationMode(mode) => self.select_operation_mode(mode)?,
            MenuAction::ShowInfo => {} // No-op for informational entries
        }
        Ok(())
    }

    pub(crate) fn run_operation<O: crate::ops::Operation>(&mut self, mut op: O) -> Result<()> {
        let result = {
            let mut ui = UiContext::new(
                &mut self.display,
                &mut self.buttons,
                &self.stats,
                &mut self.core,
                &mut self.config,
                &self.root,
            );
            let mut ctx = OperationContext::new(ui);
            OperationRunner::run(&mut ctx, &mut op)
        };
        result?;
        self.go_home()
    }

    #[allow(dead_code)]
    pub(crate) fn simple_command(&mut self, command: Commands, success: &str) -> Result<()> {
        if let Err(err) = self.core.dispatch(command) {
            self.show_message("Error", [format!("{:#}", err)])?;
        } else {
            self.show_message("Success", [success.to_string()])?;
        }
        Ok(())
    }

    pub(crate) fn show_message<I, S>(&mut self, title: &str, lines: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let overlay = self.stats.snapshot();
        let content: Vec<String> = std::iter::once(title.to_string())
            .chain(lines.into_iter().map(|line| line.as_ref().to_string()))
            .collect();

        // Pre-compute wrapped body lines so we know when scrolling is needed
        let wrapped_body: Vec<String> = content
            .iter()
            .skip(1)
            .flat_map(|line| wrap_text(line, DIALOG_MAX_CHARS))
            .collect();
        let total_lines = wrapped_body.len();

        let mut offset: usize = 0;
        let mut needs_redraw = true;

        // Draw the dialog and require an explicit button press to dismiss
        loop {
            if needs_redraw {
                self.display
                    .draw_dialog_with_offset(&content, offset, &overlay)?;
                needs_redraw = false;
            }

            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => {
                    if offset > 0 {
                        offset -= 1;
                        needs_redraw = true;
                    }
                }
                ButtonAction::Down => {
                    if offset + DIALOG_VISIBLE_LINES < total_lines {
                        offset += 1;
                        needs_redraw = true;
                    }
                }
                ButtonAction::Select | ButtonAction::Back => break,
                ButtonAction::Cancel => {}
                ButtonAction::Refresh => {
                    // redraw the dialog so user can refresh view content if desired
                    needs_redraw = true;
                }
                ButtonAction::Reboot => {
                    // confirm and perform reboot if accepted
                    self.confirm_reboot()?;
                    needs_redraw = true;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn show_progress<I, S>(&mut self, title: &str, lines: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let overlay = self.stats.snapshot();
        let content: Vec<String> = std::iter::once(title.to_string())
            .chain(lines.into_iter().map(|line| line.as_ref().to_string()))
            .collect();
        self.display.draw_dialog(&content, &overlay)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn execute_with_progress<F, T>(
        &mut self,
        title: &str,
        message: &str,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.show_progress(title, [message, "Please wait..."])?;
        let result = operation();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{action_route, ActionRoute};
    use crate::menu::MenuTree;

    #[test]
    fn menu_actions_have_routes() {
        let tree = MenuTree::new();
        let mut actions = Vec::new();
        for id in tree.node_ids() {
            if let Ok(entries) = tree.entries(id) {
                actions.extend(entries.into_iter().map(|entry| entry.action));
            }
        }

        assert!(!actions.is_empty(), "menu actions should not be empty");

        for action in actions {
            let route = action_route(&action);
            match route {
                ActionRoute::Navigation
                | ActionRoute::Local(_)
                | ActionRoute::Operation(_)
                | ActionRoute::Info => {}
            }
        }
    }
}
