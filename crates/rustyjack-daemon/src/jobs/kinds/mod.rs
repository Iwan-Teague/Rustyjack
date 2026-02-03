mod core_command;
mod hotspot_start;
mod interface_select;
mod mount_start;
mod noop;
mod portal_start;
mod scan;
mod sleep;
mod unmount_start;
mod update;
mod wifi_connect;
mod wifi_scan;

use std::future::Future;

use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::state::DaemonState;
use rustyjack_ipc::{DaemonError, JobKind};

pub async fn execute<F, Fut>(
    kind: &JobKind,
    cancel: &CancellationToken,
    state: &Arc<DaemonState>,
    mut progress: F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: Future<Output = ()>,
{
    match kind {
        JobKind::Noop => noop::run().await,
        JobKind::Sleep { seconds } => sleep::run(*seconds, cancel).await,
        JobKind::ScanRun { req } => scan::run(req.clone(), cancel, &mut progress).await,
        JobKind::SystemUpdate { req } => {
            update::run(
                req.clone(),
                cancel,
                &mut progress,
                state.config.root_path.clone(),
                state.config.update_pubkey,
            )
            .await
        }
        JobKind::WifiScan { req } => wifi_scan::run(req.clone(), cancel, &mut progress).await,
        JobKind::WifiConnect { req } => wifi_connect::run(req.clone(), cancel, &mut progress).await,
        JobKind::HotspotStart { req } => {
            hotspot_start::run(req.clone(), cancel, &mut progress).await
        }
        JobKind::PortalStart { req } => portal_start::run(req.clone(), cancel, &mut progress).await,
        JobKind::MountStart { req } => mount_start::run(req.clone(), cancel, &mut progress).await,
        JobKind::UnmountStart { req } => {
            unmount_start::run(req.clone(), cancel, &mut progress).await
        }
        JobKind::InterfaceSelect { interface } => {
            interface_select::run(interface.clone(), Arc::clone(state), cancel, &mut progress).await
        }
        JobKind::CoreCommand { command } => {
            core_command::run(command.clone(), Arc::clone(state), cancel, &mut progress).await
        }
    }
}
