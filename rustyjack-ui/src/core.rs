use std::path::{Path, PathBuf};

use anyhow::Result;
use rustyjack_core::{Commands, HandlerResult, dispatch_command, resolve_root};
use rustyjack_core::cli::{ScanRunArgs, SystemUpdateArgs};
use rustyjack_core::operations::{run_scan_with_progress, run_system_update_with_progress};

#[derive(Clone)]
pub struct CoreBridge {
    root: PathBuf,
}

impl CoreBridge {
    pub fn with_root(root: Option<PathBuf>) -> Result<Self> {
        let resolved = resolve_root(root)?;
        Ok(Self { root: resolved })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dispatch(&self, command: Commands) -> Result<HandlerResult> {
        dispatch_command(&self.root, command)
    }

    pub fn run_scan_with_progress<F>(&self, args: ScanRunArgs, mut on_progress: F) -> Result<HandlerResult>
    where
        F: FnMut(f32, &str),
    {
        run_scan_with_progress(&self.root, args, on_progress)
    }

    pub fn run_system_update_with_progress<F>(&self, args: SystemUpdateArgs, mut on_progress: F) -> Result<HandlerResult>
    where
        F: FnMut(f32, &str),
    {
        run_system_update_with_progress(&self.root, args, on_progress)
    }
}
