use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use tracing::debug;

pub struct PreferenceManager {
    pref_file: PathBuf,
}

impl PreferenceManager {
    pub fn new(root: PathBuf) -> Self {
        let pref_file = root.join("network").join("preferred_interface");
        Self { pref_file }
    }

    pub fn get_preferred(&self) -> Result<Option<String>> {
        if !self.pref_file.exists() {
            return Ok(None);
        }

        let content =
            fs::read_to_string(&self.pref_file).context("failed to read preference file")?;

        let iface = content.trim().to_string();

        if iface.is_empty() {
            Ok(None)
        } else {
            debug!("Loaded preferred interface: {}", iface);
            Ok(Some(iface))
        }
    }

    pub fn set_preferred(&self, iface: &str) -> Result<()> {
        if let Some(parent) = self.pref_file.parent() {
            fs::create_dir_all(parent).context("failed to create preference directory")?;
        }

        let temp_path = self.pref_file.with_extension("tmp");

        {
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;

            #[cfg(unix)]
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)
                .context("failed to open temp preference file")?;

            #[cfg(not(unix))]
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .context("failed to open temp preference file")?;

            file.write_all(iface.as_bytes())
                .context("failed to write preference")?;

            file.sync_all().context("failed to sync preference")?;
        }

        fs::rename(&temp_path, &self.pref_file).context("failed to rename preference file")?;

        debug!("Saved preferred interface: {}", iface);
        Ok(())
    }

    pub fn clear_preferred(&self) -> Result<()> {
        if self.pref_file.exists() {
            fs::remove_file(&self.pref_file).context("failed to remove preference file")?;
            debug!("Cleared preferred interface");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_preference_not_set() {
        let temp_dir = TempDir::new().unwrap();
        let prefs = PreferenceManager::new(temp_dir.path().to_path_buf());

        let result = prefs.get_preferred().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_preference_set_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let prefs = PreferenceManager::new(temp_dir.path().to_path_buf());

        prefs.set_preferred("eth0").unwrap();

        let result = prefs.get_preferred().unwrap();
        assert_eq!(result, Some("eth0".to_string()));
    }

    #[test]
    fn test_preference_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let prefs = PreferenceManager::new(temp_dir.path().to_path_buf());

        prefs.set_preferred("eth0").unwrap();
        prefs.set_preferred("wlan0").unwrap();

        let result = prefs.get_preferred().unwrap();
        assert_eq!(result, Some("wlan0".to_string()));
    }

    #[test]
    fn test_preference_clear() {
        let temp_dir = TempDir::new().unwrap();
        let prefs = PreferenceManager::new(temp_dir.path().to_path_buf());

        prefs.set_preferred("eth0").unwrap();
        prefs.clear_preferred().unwrap();

        let result = prefs.get_preferred().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_preference_persistence() {
        let temp_dir = TempDir::new().unwrap();

        {
            let prefs = PreferenceManager::new(temp_dir.path().to_path_buf());
            prefs.set_preferred("eth0").unwrap();
        }

        // Create new instance with same path
        let prefs2 = PreferenceManager::new(temp_dir.path().to_path_buf());
        let result = prefs2.get_preferred().unwrap();
        assert_eq!(result, Some("eth0".to_string()));
    }
}
