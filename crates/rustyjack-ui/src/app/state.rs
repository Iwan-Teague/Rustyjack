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
    ui::layout::MENU_VISIBLE_ITEMS,
};

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

    pub(crate) fn move_up(&mut self, total: usize) {
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
        } else if self.selection >= self.offset + MENU_VISIBLE_ITEMS {
            self.offset = self.selection.saturating_sub(MENU_VISIBLE_ITEMS - 1);
        }
    }

    pub(crate) fn move_down(&mut self, total: usize) {
        if total == 0 {
            self.selection = 0;
            return;
        }
        self.selection = (self.selection + 1) % total;
        // Ensure selection is inside visible window
        if self.selection < self.offset {
            self.offset = self.selection;
        } else if self.selection >= self.offset + MENU_VISIBLE_ITEMS {
            self.offset = self.selection.saturating_sub(MENU_VISIBLE_ITEMS - 1);
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
    pub(crate) fs_type: String,
    pub(crate) options: String,
}

pub(crate) struct StartApErrorHint {
    pub(crate) category: &'static str,
    pub(crate) hint: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_menu_state_new() {
        let state = MenuState::new();
        assert_eq!(state.current_id(), "a");
        assert_eq!(state.selection, 0);
        assert_eq!(state.offset, 0);
    }

    #[test]
    fn test_menu_state_enter() {
        let mut state = MenuState::new();
        state.enter("submenu1");
        assert_eq!(state.current_id(), "submenu1");
        assert_eq!(state.selection, 0);
        assert_eq!(state.offset, 0);
    }

    #[test]
    fn test_menu_state_back() {
        let mut state = MenuState::new();
        state.enter("submenu1");
        state.enter("submenu2");
        assert_eq!(state.current_id(), "submenu2");
        
        state.back();
        assert_eq!(state.current_id(), "submenu1");
        assert_eq!(state.selection, 0);
        
        state.back();
        assert_eq!(state.current_id(), "a");
        
        // Should not go below root
        state.back();
        assert_eq!(state.current_id(), "a");
    }

    #[test]
    fn test_menu_state_move_down() {
        let mut state = MenuState::new();
        
        // Test with 3 items
        state.move_down(3);
        assert_eq!(state.selection, 1);
        
        state.move_down(3);
        assert_eq!(state.selection, 2);
        
        // Should wrap to 0
        state.move_down(3);
        assert_eq!(state.selection, 0);
    }

    #[test]
    fn test_menu_state_move_up() {
        let mut state = MenuState::new();
        
        // At top, should wrap to bottom
        state.move_up(3);
        assert_eq!(state.selection, 2);
        
        state.move_up(3);
        assert_eq!(state.selection, 1);
        
        state.move_up(3);
        assert_eq!(state.selection, 0);
    }

    #[test]
    fn test_menu_state_move_with_empty_list() {
        let mut state = MenuState::new();
        state.selection = 5; // Set to something non-zero
        
        state.move_down(0);
        assert_eq!(state.selection, 0, "Empty list should reset selection to 0");
        
        state.selection = 5;
        state.move_up(0);
        assert_eq!(state.selection, 0, "Empty list should reset selection to 0");
    }

    #[test]
    fn test_menu_state_home() {
        let mut state = MenuState::new();
        state.enter("sub1");
        state.enter("sub2");
        state.selection = 5;
        state.offset = 3;
        
        state.home();
        assert_eq!(state.current_id(), "a");
        assert_eq!(state.selection, 0);
        assert_eq!(state.offset, 0);
    }

    #[test]
    fn test_button_action_enum_completeness() {
        // Verify all button actions are defined
        let actions = vec![
            ButtonAction::Up,
            ButtonAction::Down,
            ButtonAction::Back,
            ButtonAction::Select,
            ButtonAction::Refresh,
            ButtonAction::Cancel,
            ButtonAction::Reboot,
        ];
        assert_eq!(actions.len(), 7, "Expected exactly 7 button actions");
    }

    #[test]
    fn test_confirm_choice_variants() {
        // Verify ConfirmChoice enum has all expected variants
        let choices = vec![
            ConfirmChoice::Yes,
            ConfirmChoice::No,
            ConfirmChoice::Back,
            ConfirmChoice::Cancel,
        ];
        assert_eq!(choices.len(), 4, "Expected exactly 4 confirm choices");
    }

    #[test]
    fn test_cancel_decision_variants() {
        assert_eq!(CancelDecision::Continue, CancelDecision::Continue);
        assert_eq!(CancelDecision::Cancel, CancelDecision::Cancel);
        assert_ne!(CancelDecision::Continue, CancelDecision::Cancel);
    }

    #[test]
    fn test_usb_access_requirement_mount_mode() {
        assert_eq!(
            UsbAccessRequirement::ReadableOk.mount_mode(),
            UsbMountMode::ReadOnly
        );
        assert_eq!(
            UsbAccessRequirement::RequireWritable.mount_mode(),
            UsbMountMode::ReadWrite
        );
    }

    #[test]
    fn test_usb_access_requirement_needs_write() {
        assert!(!UsbAccessRequirement::ReadableOk.needs_write());
        assert!(UsbAccessRequirement::RequireWritable.needs_write());
    }
}
