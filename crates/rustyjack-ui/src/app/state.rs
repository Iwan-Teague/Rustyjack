use std::path::PathBuf;
use std::time::Instant;

use rustyjack_commands::UsbMountMode;

use crate::{
    config::GuiConfig,
    core::CoreBridge,
    display::{DashboardView, Display},
    input::ButtonPad,
    menu::MenuTree,
    stats::StatsSampler,
};

#[allow(dead_code)]
pub const INDEFINITE_SECS: u32 = 86_400; // 24h stand-in for "run until stopped"

pub struct App {
    pub(crate) core: CoreBridge,
    pub(crate) display: Display,
    pub(crate) buttons: ButtonPad,
    pub(crate) config: GuiConfig,
    pub(crate) menu: MenuTree,
    pub(crate) menu_state: MenuState,
    pub(crate) stats: StatsSampler,
    pub(crate) root: PathBuf,
    pub(crate) dashboard_view: Option<DashboardView>,
    pub(crate) active_mitm: Option<MitmSession>,
}

/// Result of checking for cancel during an operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CancelDecision {
    Continue,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmChoice {
    Yes,
    No,
    Back,
    Cancel,
}

/// Result from pipeline execution
pub(crate) struct PipelineResult {
    pub(crate) cancelled: bool,
    pub(crate) steps_completed: usize,
    pub(crate) pmkids_captured: u32,
    pub(crate) handshakes_captured: u32,
    pub(crate) password_found: Option<String>,
    pub(crate) networks_found: u32,
    pub(crate) clients_found: u32,
}

pub(crate) enum StepOutcome {
    Completed(Option<(u32, u32, Option<String>, u32, u32)>),
    Skipped(String),
}

#[derive(Clone)]
pub(crate) struct MitmSession {
    pub(crate) started: Instant,
    pub(crate) site: Option<String>,
    pub(crate) visit_log: Option<PathBuf>,
    pub(crate) cred_log: Option<PathBuf>,
}

pub(crate) struct MenuState {
    stack: Vec<String>,
    pub(crate) selection: usize,
    // Scroll offset for current menu view — ensures selection stays visible
    pub(crate) offset: usize,
}

impl MenuState {
    pub(crate) fn new() -> Self {
        Self {
            stack: vec!["a".to_string()],
            selection: 0,
            offset: 0,
        }
    }

    pub(crate) fn current_id(&self) -> &str {
        self.stack.last().map(|s| s.as_str()).unwrap_or("a")
    }

    #[allow(dead_code)]
    pub(crate) fn path(&self) -> &str {
        self.current_id()
    }

    pub(crate) fn enter(&mut self, id: &str) {
        self.stack.push(id.to_string());
        self.selection = 0;
        self.offset = 0;
    }

    pub(crate) fn back(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
            self.selection = 0;
            self.offset = 0;
        }
    }

    pub(crate) fn move_up(&mut self, total: usize, visible_items: usize) {
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
        if self.selection < self.offset {
            self.offset = self.selection;
        } else if self.selection >= self.offset + visible_items {
            self.offset = self
                .selection
                .saturating_sub(visible_items.saturating_sub(1));
        }
    }

    pub(crate) fn move_down(&mut self, total: usize, visible_items: usize) {
        if total == 0 {
            self.selection = 0;
            return;
        }
        self.selection = (self.selection + 1) % total;
        // Ensure selection is inside visible window
        if self.selection < self.offset {
            self.offset = self.selection;
        } else if self.selection >= self.offset + visible_items {
            self.offset = self
                .selection
                .saturating_sub(visible_items.saturating_sub(1));
        }
    }

    pub(crate) fn home(&mut self) {
        self.stack = vec!["a".to_string()];
        self.selection = 0;
        self.offset = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ButtonAction {
    Up,
    Down,
    Back,
    Select,
    Refresh,
    Cancel,
    Reboot,
}

#[derive(Debug, Clone)]
pub(crate) struct UsbDevice {
    pub(crate) name: String,
    pub(crate) size: String,
    pub(crate) model: String,
    #[allow(dead_code)]
    pub(crate) transport: Option<String>,
    pub(crate) is_partition: bool,
    #[allow(dead_code)]
    pub(crate) parent: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum UsbAccessRequirement {
    ReadableOk,
    RequireWritable,
}

impl UsbAccessRequirement {
    pub(crate) fn mount_mode(self) -> UsbMountMode {
        match self {
            UsbAccessRequirement::ReadableOk => UsbMountMode::ReadOnly,
            UsbAccessRequirement::RequireWritable => UsbMountMode::ReadWrite,
        }
    }

    pub(crate) fn needs_write(self) -> bool {
        matches!(self, UsbAccessRequirement::RequireWritable)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MountEntry {
    pub(crate) device: String,
    pub(crate) mount_point: String,
    #[allow(dead_code)]
    pub(crate) fs_type: String,
    pub(crate) options: String,
}

pub(crate) struct StartApErrorHint {
    pub(crate) category: &'static str,
    pub(crate) hint: &'static str,
}
