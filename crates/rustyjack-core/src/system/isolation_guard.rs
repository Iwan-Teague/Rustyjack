use std::path::PathBuf;

use anyhow::Result;

use super::isolation_policy::{IsolationMode, IsolationPolicy, IsolationPolicyManager};

pub struct IsolationPolicyGuard {
    prev: Option<IsolationPolicy>,
    mgr: IsolationPolicyManager,
}

impl IsolationPolicyGuard {
    pub fn set_allow_list(root: PathBuf, allowed: Vec<String>, session: String) -> Result<Self> {
        let mgr = IsolationPolicyManager::new(root);
        let prev = mgr.read()?;
        let policy = IsolationPolicy {
            version: 1,
            mode: IsolationMode::AllowList,
            allowed,
            session,
            expires_at: None,
        };
        mgr.write(&policy)?;
        Ok(Self { prev, mgr })
    }
}

impl Drop for IsolationPolicyGuard {
    fn drop(&mut self) {
        let _ = match &self.prev {
            Some(prev) => self.mgr.write(prev),
            None => self.mgr.clear(),
        };
    }
}
