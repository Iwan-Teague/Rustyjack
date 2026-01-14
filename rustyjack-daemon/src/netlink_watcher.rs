use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::state::DaemonState;

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnforcementSnapshot {
    allowed: Vec<String>,
    blocked: Vec<String>,
}

impl EnforcementSnapshot {
    fn from_outcome(outcome: &rustyjack_core::system::IsolationOutcome) -> Self {
        let mut allowed = outcome.allowed.clone();
        let mut blocked = outcome.blocked.clone();
        allowed.sort();
        blocked.sort();
        Self { allowed, blocked }
    }
}

#[cfg(target_os = "linux")]
pub async fn run_netlink_watcher(state: Arc<DaemonState>) -> anyhow::Result<()> {
    info!("Starting netlink watcher for hardware isolation enforcement");
    
    let last_event: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>> = Arc::new(StdMutex::new(None));
    let debounce_duration = Duration::from_millis(250);

    start_periodic_enforcement(Arc::clone(&state), Arc::clone(&enforcement_snapshot));
    
    loop {
        match watch_netlink_events(
            Arc::clone(&state),
            Arc::clone(&last_event),
            debounce_duration,
            Arc::clone(&enforcement_snapshot),
        )
        .await
        {
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
    enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>>,
) -> anyhow::Result<()> {
    use futures::stream::StreamExt;
    use rtnetlink::new_connection;

    // RC6: Subscribe to netlink events for real-time link state notifications
    // This allows daemon to detect carrier up/down events automatically
    let (connection, handle, _messages) = new_connection()?;

    // Keep the connection alive in the background
    // This enables receiving RTM_NEWLINK/RTM_NEWADDR messages from kernel
    tokio::spawn(connection);

    // Get streams for link and address changes
    // These will be triggered when interface state changes occur
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
                schedule_enforcement(
                    Arc::clone(&state),
                    Arc::clone(&last_event),
                    debounce_duration,
                    Arc::clone(&enforcement_snapshot),
                )
                .await;
            }
            Event::Address => {
                debug!("Netlink address event");
                schedule_enforcement(
                    Arc::clone(&state),
                    Arc::clone(&last_event),
                    debounce_duration,
                    Arc::clone(&enforcement_snapshot),
                )
                .await;
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
    enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>>,
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
        let snapshot = Arc::clone(&enforcement_snapshot);
        tokio::task::spawn_blocking(move || {
            use rustyjack_core::system::{IsolationEngine, RealNetOps};
            use std::sync::Arc;
            
            let ops = Arc::new(RealNetOps);
            let engine = IsolationEngine::new(ops, root);
            
            match engine.enforce() {
                Ok(outcome) => log_enforcement_outcome("Netlink enforcement", &outcome, &snapshot),
                Err(e) => {
                    warn!("Netlink event enforcement failed: {}", e);
                }
            }
        })
        .await
        .ok();
    });
}

#[cfg(target_os = "linux")]
fn start_periodic_enforcement(
    state: Arc<DaemonState>,
    enforcement_snapshot: Arc<StdMutex<Option<EnforcementSnapshot>>>,
) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(3);
        loop {
            sleep(interval).await;

            let _lock = state.locks.acquire_uplink().await;
            let root = state.config.root_path.clone();
            let snapshot = Arc::clone(&enforcement_snapshot);

            tokio::task::spawn_blocking(move || {
                use rustyjack_core::system::{IsolationEngine, RealNetOps};
                use std::sync::Arc;

                let ops = Arc::new(RealNetOps);
                let engine = IsolationEngine::new(ops, root);

                match engine.enforce() {
                    Ok(outcome) => {
                        log_enforcement_outcome("Periodic enforcement", &outcome, &snapshot)
                    }
                    Err(e) => {
                        warn!("Periodic enforcement failed: {}", e);
                    }
                }
            })
            .await
            .ok();
        }
    });
}

#[cfg(target_os = "linux")]
fn log_enforcement_outcome(
    label: &str,
    outcome: &rustyjack_core::system::IsolationOutcome,
    snapshot: &Arc<StdMutex<Option<EnforcementSnapshot>>>,
) {
    let current = EnforcementSnapshot::from_outcome(outcome);
    let mut guard = snapshot.lock().unwrap_or_else(|e| e.into_inner());
    let changed = guard.as_ref().map(|prev| prev != &current).unwrap_or(true);

    if changed {
        info!("{}: allowed={:?}, blocked={:?}", label, current.allowed, current.blocked);
        *guard = Some(current);
    }

    if !outcome.errors.is_empty() {
        warn!("{} had {} errors:", label, outcome.errors.len());
        for err in &outcome.errors {
            warn!("  {}: {}", err.interface, err.message);
        }
    }
}
