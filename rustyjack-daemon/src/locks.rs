use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockKind {
    Update,
    Mount,
    Wifi,
    Portal,
}

impl LockKind {
    fn order(self) -> u8 {
        match self {
            LockKind::Update => 0,
            LockKind::Mount => 1,
            LockKind::Wifi => 2,
            LockKind::Portal => 3,
        }
    }
}

#[derive(Debug)]
pub struct LockManager {
    update: Arc<Semaphore>,
    mount: Arc<Semaphore>,
    wifi: Arc<Semaphore>,
    portal: Arc<Semaphore>,
}

impl LockManager {
    pub fn new() -> Self {
        Self {
            update: Arc::new(Semaphore::new(1)),
            mount: Arc::new(Semaphore::new(1)),
            wifi: Arc::new(Semaphore::new(1)),
            portal: Arc::new(Semaphore::new(1)),
        }
    }

    pub async fn acquire(&self, locks: &[LockKind]) -> LockSet {
        let mut ordered = locks.to_vec();
        ordered.sort_by_key(|lock| lock.order());
        ordered.dedup();

        let mut permits = Vec::with_capacity(ordered.len());
        for lock in ordered {
            let permit = match lock {
                LockKind::Update => self.update.clone().acquire_owned().await,
                LockKind::Mount => self.mount.clone().acquire_owned().await,
                LockKind::Wifi => self.wifi.clone().acquire_owned().await,
                LockKind::Portal => self.portal.clone().acquire_owned().await,
            };

            if let Ok(permit) = permit {
                permits.push(permit);
            }
        }

        LockSet { _permits: permits }
    }
}

pub struct LockSet {
    _permits: Vec<OwnedSemaphorePermit>,
}
