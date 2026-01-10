use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::state::DaemonState;
use rustyjack_ipc::{
    DaemonError, ErrorCode, InterfaceSelectDhcpResult, InterfaceSelectJobResult,
};

pub async fn run<F, Fut>(
    interface: String,
    state: Arc<DaemonState>,
    cancel: &CancellationToken,
    progress: &mut F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if cancel.is_cancelled() {
        return Err(DaemonError::new(
            ErrorCode::Cancelled,
            "Job cancelled",
            false,
        ));
    }

    let root_path = state.config.root_path.clone();
    let (tx, mut rx) = mpsc::unbounded_channel::<(String, u8, String)>();

    let mut handle = tokio::task::spawn_blocking(move || {
        let mut cb = |phase: &str, percent: u8, message: &str| {
            let _ = tx.send((
                phase.to_string(),
                percent,
                message.to_string(),
            ));
        };

        rustyjack_core::system::interface_selection::select_interface(
            root_path,
            &interface,
            Some(&mut cb),
        )
    });

    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                handle.abort();
                return Err(DaemonError::new(
                    ErrorCode::Cancelled,
                    "Job cancelled",
                    false,
                ));
            }
            Some((phase, percent, message)) = rx.recv() => {
                progress(&phase, percent, &message).await;
            }
            res = &mut handle => {
                break res;
            }
        }
    };

    match result {
        Ok(Ok(outcome)) => {
            let dhcp = outcome.dhcp.as_ref().map(|d| InterfaceSelectDhcpResult {
                ip: d.ip.map(|ip| ip.to_string()),
                gateway: d.gateway.map(|gw| gw.to_string()),
                dns_servers: d.dns_servers.iter().map(|ip| ip.to_string()).collect(),
            });

            let response = InterfaceSelectJobResult {
                interface: outcome.interface,
                allowed: outcome.allowed,
                blocked: outcome.blocked,
                carrier: outcome.carrier,
                dhcp,
                notes: outcome.notes,
            };

            serde_json::to_value(response).map_err(|e| {
                DaemonError::new(
                    ErrorCode::Internal,
                    "Failed to serialize interface selection result",
                    false,
                )
                .with_detail(e.to_string())
                .with_source("daemon.jobs.interface_select")
            })
        }
        Ok(Err(err)) => Err(
            DaemonError::new(
                ErrorCode::Internal,
                "Interface selection failed",
                false,
            )
            .with_detail(format!("{:#}", err))
            .with_source("daemon.jobs.interface_select"),
        ),
        Err(join_err) => Err(DaemonError::new(
            ErrorCode::Internal,
            "Interface selection job panicked",
            false,
        )
        .with_detail(join_err.to_string())
        .with_source("daemon.jobs.interface_select")),
    }
}
