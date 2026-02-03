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

        let credentials =
            open_append(capture_dir.join("credentials.log")).context("opening credentials log")?;
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
    // Escape user-controlled input to prevent log injection attacks
    let ua = escape_log_value(ua);
    let user = escape_log_value(user);
    let pass = escape_log_value(pass);
    format!("[{timestamp}] ip={ip} ua=\"{ua}\" user=\"{user}\" pass=\"{pass}\"\n")
}

pub fn format_visit_line_at(
    timestamp: &str,
    ip: &str,
    ua: &str,
    uri: &str,
    status: &str,
) -> String {
    // Escape user-controlled input to prevent log injection attacks
    let ua = escape_log_value(ua);
    let uri = escape_log_value(uri);
    format!("[{timestamp}] ip={ip} ua=\"{ua}\" uri=\"{uri}\" status={status}\n")
}

/// Escape a string for safe inclusion in log files.
/// Prevents log injection by escaping:
/// - Newlines (could create fake log entries)
/// - Carriage returns (could overwrite log lines)
/// - Double quotes (could break field parsing)
/// - Backslashes (escape character itself)
/// - Control characters (could confuse log parsers)
fn escape_log_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            // Escape other control characters as \xNN
            c if c.is_control() => {
                for byte in c.to_string().bytes() {
                    result.push_str(&format!("\\x{:02x}", byte));
                }
            }
            c => result.push(c),
        }
    }
    result
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
    use super::{escape_log_value, format_credentials_line_at, format_visit_line_at};

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

    #[test]
    fn escapes_newlines() {
        // Attacker tries to inject fake log entry
        let malicious =
            "legit\n[2025-01-01T00:00:00+00:00] ip=evil ua=\"x\" user=\"admin\" pass=\"pwned\"";
        let escaped = escape_log_value(malicious);
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("\\n"));
    }

    #[test]
    fn escapes_quotes() {
        // Attacker tries to break out of quoted field
        let malicious = "value\" injected=\"malicious";
        let escaped = escape_log_value(malicious);
        assert!(!escaped.contains('"'));
        assert!(escaped.contains("\\\""));
    }

    #[test]
    fn escapes_control_chars() {
        let malicious = "hello\x00world\x1b[31mred";
        let escaped = escape_log_value(malicious);
        assert!(!escaped.chars().any(|c| c.is_control()));
    }

    #[test]
    fn escapes_backslashes() {
        let input = "path\\to\\file";
        let escaped = escape_log_value(input);
        assert_eq!(escaped, "path\\\\to\\\\file");
    }

    #[test]
    fn credentials_line_with_injection_attempt() {
        let line = format_credentials_line_at(
            "2025-12-30T12:34:56+00:00",
            "192.168.1.10",
            "Mozilla\n[fake] ip=evil",
            "admin\" pass=\"",
            "x\ninjected=true",
        );
        // Verify no raw newlines in output
        assert_eq!(line.matches('\n').count(), 1); // Only the trailing newline
                                                   // Verify quotes are escaped
        assert!(line.contains("\\\""));
    }
}
