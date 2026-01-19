use std::{fs::OpenOptions, path::Path, sync::Arc};

use anyhow::{Context, Result};
use chrono::{Local, SecondsFormat};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct PortalLogger {
    credentials: Arc<Mutex<File>>,
    visits: Arc<Mutex<File>>,
}

impl PortalLogger {
    pub fn new(capture_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(capture_dir).context("creating portal capture directory")?;

        let credentials = open_append(capture_dir.join("credentials.log"))
            .context("opening credentials log")?;
        let visits = open_append(capture_dir.join("visits.log")).context("opening visits log")?;

        Ok(Self {
            credentials: Arc::new(Mutex::new(File::from_std(credentials))),
            visits: Arc::new(Mutex::new(File::from_std(visits))),
        })
    }

    pub async fn log_credentials_line(&self, line: &str) -> Result<()> {
        let mut file = self.credentials.lock().await;
        file.write_all(line.as_bytes())
            .await
            .context("writing credentials log")?;
        file.flush().await.context("flushing credentials log")?;
        Ok(())
    }

    pub async fn log_visit_line(&self, line: &str) -> Result<()> {
        let mut file = self.visits.lock().await;
        file.write_all(line.as_bytes())
            .await
            .context("writing visits log")?;
        file.flush().await.context("flushing visits log")?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn log_visit_lines(&self, lines: &[String]) -> Result<()> {
        let mut file = self.visits.lock().await;
        for line in lines {
            file.write_all(line.as_bytes())
                .await
                .context("writing visits log")?;
        }
        file.flush().await.context("flushing visits log")?;
        Ok(())
    }
}

pub fn format_credentials_line(ip: &str, ua: &str, user: &str, pass: &str) -> String {
    let timestamp = timestamp_now();
    format_credentials_line_at(&timestamp, ip, ua, user, pass)
}

pub fn format_visit_line(ip: &str, ua: &str, uri: &str, status: &str) -> String {
    let timestamp = timestamp_now();
    format_visit_line_at(&timestamp, ip, ua, uri, status)
}

pub fn format_credentials_line_at(
    timestamp: &str,
    ip: &str,
    ua: &str,
    user: &str,
    pass: &str,
) -> String {
    format!(
        "[{timestamp}] ip={ip} ua=\"{ua}\" user=\"{user}\" pass=\"{pass}\"\n"
    )
}

pub fn format_visit_line_at(
    timestamp: &str,
    ip: &str,
    ua: &str,
    uri: &str,
    status: &str,
) -> String {
    format!(
        "[{timestamp}] ip={ip} ua=\"{ua}\" uri=\"{uri}\" status={status}\n"
    )
}

fn timestamp_now() -> String {
    Local::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn open_append(path: impl AsRef<Path>) -> Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context("opening log file")
}

#[cfg(test)]
mod tests {
    use super::{format_credentials_line_at, format_visit_line_at};

    #[test]
    fn formats_credentials_line() {
        let line = format_credentials_line_at(
            "2025-12-30T12:34:56+00:00",
            "192.168.1.10",
            "UA",
            "alice",
            "secret",
        );
        assert_eq!(
            line,
            "[2025-12-30T12:34:56+00:00] ip=192.168.1.10 ua=\"UA\" user=\"alice\" pass=\"secret\"\n"
        );
    }

    #[test]
    fn formats_visit_line() {
        let line = format_visit_line_at(
            "2025-12-30T12:34:56+00:00",
            "192.168.1.10",
            "UA",
            "/?err=1",
            "view",
        );
        assert_eq!(
            line,
            "[2025-12-30T12:34:56+00:00] ip=192.168.1.10 ua=\"UA\" uri=\"/?err=1\" status=view\n"
        );
    }
}
