use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    AllowList,
    BlockAll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationPolicy {
    pub version: u32,
    pub mode: IsolationMode,
    pub allowed: Vec<String>,
    pub session: String,
    pub expires_at: Option<String>,
}

pub struct IsolationPolicyManager {
    path: PathBuf,
}

impl IsolationPolicyManager {
    pub fn new(root: PathBuf) -> Self {
        let path = root.join("network").join("isolation_policy.json");
        Self { path }
    }

    pub fn read(&self) -> Result<Option<IsolationPolicy>> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => {
                let policy = serde_json::from_str(&contents).context("parsing isolation policy")?;
                Ok(Some(policy))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).context("reading isolation policy"),
        }
    }

    pub fn write(&self, policy: &IsolationPolicy) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("creating isolation policy directory")?;
        }
        let payload = serde_json::to_vec_pretty(policy).context("serializing isolation policy")?;
        fs::write(&self.path, payload).context("writing isolation policy")?;
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).context("removing isolation policy"),
        }
    }
}
