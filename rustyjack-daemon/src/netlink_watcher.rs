use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::state::DaemonState;

#[cfg(target_os = "linux")]
pub async fn run_netlink_watcher(state: Arc<DaemonState>) -> anyhow::Result<()> {
    info!("Starting netlink watcher for hardware isolation enforcement");
    
    let last_event: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let debounce_duration = Duration::from_millis(250);
    
    loop {
        match watch_netlink_events(Arc::clone(&state), Arc::clone(&last_event), debounce_duration).await {
            Ok(_) => {
                info!("Netlink watcher stopped normally");
                break;
            }
            Err(e) => {
                warn!("Netlink watcher error: {}, restarting in 5s", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
    
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn run_netlink_watcher(_state: Arc<DaemonState>) -> anyhow::Result<()> {
    info!("Netlink watcher disabled on non-Linux platform");
    futures::future::pending::<()>().await;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn watch_netlink_events(
    state: Arc<DaemonState>,
    last_event: Arc<Mutex<Option<Instant>>>,
    debounce_duration: Duration,
) -> anyhow::Result<()> {
    use futures::stream::StreamExt;
    use rtnetlink::new_connection;

    // RC6: Subscribe to RTNLGRP_LINK for real-time link state notifications
    // This allows daemon to detect carrier up/down events automatically
    let (connection, handle) = new_connection()?;

    // Subscribe to link change events (carrier, admin-state, etc.)
    // Using socket_ref().add_membership() to subscribe to link group
    // This enables receiving RTM_NEWLINK messages when interface state changes
    if let Err(e) = connection.socket_ref().add_membership(1) {  // RTNLGRP_LINK = 1
        warn!("Failed to subscribe to link change events: {}", e);
    }

    tokio::spawn(connection.run());

    // Initial dump to get current state
    let mut link_stream = handle.link().get().execute();
    let mut address_stream = handle.address().get().execute();

    loop {
        enum Event { Link, Address, End }
        
        let event = tokio::select! {
            biased;
            link_result = link_stream.next() => {
                if link_result.is_some() { Event::Link } else { Event::End }
            }
            addr_result = address_stream.next() => {
                if addr_result.is_some() { Event::Address } else { Event::End }
            }
        };
        
        match event {
            Event::Link => {
                debug!("Netlink link event");
                schedule_enforcement(Arc::clone(&state), Arc::clone(&last_event), debounce_duration).await;
            }
            Event::Address => {
                debug!("Netlink address event");
                schedule_enforcement(Arc::clone(&state), Arc::clone(&last_event), debounce_duration).await;
            }
            Event::End => {
                debug!("Netlink stream ended");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn schedule_enforcement(
    state: Arc<DaemonState>,
    last_event: Arc<Mutex<Option<Instant>>>,
    debounce_duration: Duration,
) {
    let now = Instant::now();
    
    {
        let mut last = last_event.lock().await;
        if let Some(prev) = *last {
            if now.duration_since(prev) < debounce_duration {
                *last = Some(now);
                return;
            }
        }
        *last = Some(now);
    }
    
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        sleep(debounce_duration).await;
        
        let _lock = state_clone.locks.acquire_uplink().await;
        
        let root = state_clone.config.root_path.clone();
        tokio::task::spawn_blocking(move || {
            use rustyjack_core::system::{IsolationEngine, RealNetOps};
            use std::sync::Arc;
            
            let ops = Arc::new(RealNetOps);
            let engine = IsolationEngine::new(ops, root);
            
            match engine.enforce() {
                Ok(outcome) => {
                    info!("Netlink event enforcement: allowed={:?}, blocked={:?}",
                        outcome.allowed, outcome.blocked);
                    if !outcome.errors.is_empty() {
                        warn!("Enforcement had {} errors:", outcome.errors.len());
                        for err in &outcome.errors {
                            warn!("  {}: {}", err.interface, err.message);
                        }
                    }
                }
                Err(e) => {
                    warn!("Netlink event enforcement failed: {}", e);
                }
            }
        })
        .await
        .ok();
    });
}
