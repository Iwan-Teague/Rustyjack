//! Logging helpers.
//!
//! Provides an opt-in journald logger so services can forward library logs
//! directly to `journalctl` without extra glue code.

#[cfg(feature = "journald")]
use systemd_journal_logger::JournalLog;

/// Initialize the journald logger once for the process.
///
/// Safe to call multiple times; the logger will only be installed on first call.
/// Falls back to no-op if the `journald` feature is not enabled.
pub fn init_journald_logger() {
    #[cfg(feature = "journald")]
    {
        if let Err(e) = JournalLog::new().map_err(|e| e.into()).and_then(|l| {
            l.install()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        }) {
            eprintln!("failed to init journald logger: {}", e);
        } else {
            log::info!("journald logger initialized for rustyjack-netlink");
        }
    }
}
