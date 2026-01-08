// Audit trail for privileged operations
//
// This module provides structured logging for security-sensitive operations,
// separate from operational logs. Audit events are logged with:
// - Actor identity (uid/pid/group)
// - Operation performed
// - Result (success/failure)
// - Timestamp
// - Optional context data

use std::path::Path;
use std::fs::OpenOptions;
use std::io::Write;
use serde::{Serialize, Deserialize};
use serde_json;

/// Audit event representing a privileged operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub operation: String,
    pub actor_uid: Option<u32>,
    pub actor_pid: Option<u32>,
    pub actor_group: Option<String>,
    pub result: AuditResult,
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    Success,
    Failure { reason: String },
    Denied { reason: String },
}

impl AuditEvent {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            operation: operation.into(),
            actor_uid: None,
            actor_pid: None,
            actor_group: None,
            result: AuditResult::Success,
            context: None,
        }
    }

    pub fn with_actor(mut self, uid: u32, pid: u32) -> Self {
        self.actor_uid = Some(uid);
        self.actor_pid = Some(pid);
        self
    }

    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.actor_group = Some(group.into());
        self
    }

    pub fn with_result(mut self, result: AuditResult) -> Self {
        self.result = result;
        self
    }

    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }

    pub fn success(mut self) -> Self {
        self.result = AuditResult::Success;
        self
    }

    pub fn failure(mut self, reason: impl Into<String>) -> Self {
        self.result = AuditResult::Failure {
            reason: reason.into(),
        };
        self
    }

    pub fn denied(mut self, reason: impl Into<String>) -> Self {
        self.result = AuditResult::Denied {
            reason: reason.into(),
        };
        self
    }

    /// Write this audit event to the audit log
    pub fn log(&self, root: &Path) -> std::io::Result<()> {
        // Write to audit log file
        let audit_dir = root.join("logs").join("audit");
        std::fs::create_dir_all(&audit_dir)?;

        let audit_file = audit_dir.join("audit.log");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_file)?;

        let json = serde_json::to_string(self)?;
        writeln!(file, "{}", json)?;

        // Also log to tracing for visibility
        match &self.result {
            AuditResult::Success => {
                tracing::info!(
                    audit = true,
                    operation = %self.operation,
                    actor_uid = ?self.actor_uid,
                    actor_pid = ?self.actor_pid,
                    actor_group = ?self.actor_group,
                    "Audit: operation succeeded"
                );
            }
            AuditResult::Failure { reason } => {
                tracing::warn!(
                    audit = true,
                    operation = %self.operation,
                    actor_uid = ?self.actor_uid,
                    actor_pid = ?self.actor_pid,
                    actor_group = ?self.actor_group,
                    reason = %reason,
                    "Audit: operation failed"
                );
            }
            AuditResult::Denied { reason } => {
                tracing::warn!(
                    audit = true,
                    operation = %self.operation,
                    actor_uid = ?self.actor_uid,
                    actor_pid = ?self.actor_pid,
                    actor_group = ?self.actor_group,
                    reason = %reason,
                    "Audit: operation denied"
                );
            }
        }

        Ok(())
    }
}

/// Operations that should be audited
pub mod operations {
    pub const SYSTEM_REBOOT: &str = "system.reboot";
    pub const SYSTEM_SHUTDOWN: &str = "system.shutdown";
    pub const MAC_RANDOMIZE: &str = "evasion.mac_randomize";
    pub const LOGS_CLEAR: &str = "evasion.logs_clear";
    pub const HOTSPOT_START: &str = "network.hotspot_start";
    pub const HOTSPOT_STOP: &str = "network.hotspot_stop";
    pub const PORTAL_START: &str = "network.portal_start";
    pub const PORTAL_STOP: &str = "network.portal_stop";
    pub const WIFI_DEAUTH: &str = "attack.wifi_deauth";
    pub const DNS_SPOOF: &str = "attack.dns_spoof";
    pub const MITM_START: &str = "attack.mitm_start";
    pub const LOGGING_CONFIG_CHANGE: &str = "config.logging_change";
    pub const INTERFACE_ISOLATION_CHANGE: &str = "config.interface_isolation";
}

/// Quick audit macro for common operations
#[macro_export]
macro_rules! audit {
    ($root:expr, $op:expr, $uid:expr, $pid:expr => success) => {{
        let event = $crate::audit::AuditEvent::new($op)
            .with_actor($uid, $pid)
            .success();
        let _ = event.log(&$root);
    }};

    ($root:expr, $op:expr, $uid:expr, $pid:expr => failure, $reason:expr) => {{
        let event = $crate::audit::AuditEvent::new($op)
            .with_actor($uid, $pid)
            .failure($reason);
        let _ = event.log(&$root);
    }};

    ($root:expr, $op:expr, $uid:expr, $pid:expr => denied, $reason:expr) => {{
        let event = $crate::audit::AuditEvent::new($op)
            .with_actor($uid, $pid)
            .denied($reason);
        let _ = event.log(&$root);
    }};
}
