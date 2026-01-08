# Rustyjack Logging Policy

**Date:** 2026-01-08
**Version:** 1.0

## Overview

This document defines the logging policy boundaries for Rustyjack, establishing clear guidelines for what should be logged where, how sensitive data should be handled, and retention policies.

## Log Categories

### 1. Operational Logs

**Purpose:** Debuggable, non-sensitive system operations
**Location:** `/var/lib/rustyjack/logs/{component}.log`
**Retention:** Daily rotation, last 7 days kept
**Access:** daemon (root) writes, UI reads via daemon IPC

**What to log:**
- Job start/stop with job IDs
- Interface state changes (up/down, IP assignment)
- Service start/stop (hotspot, portal, etc.)
- Configuration changes (redacted)
- Errors and warnings
- Performance metrics

**What NOT to log:**
- Passwords, PSKs, or other credentials
- Captured network traffic content
- Cracked keys or passwords
- Full command output that may contain secrets

**Redaction policy:**
- Use `[REDACTED]` for sensitive fields
- Log parameter names but not values for credentials
- Example: `wifi_connect(ssid="TargetNetwork", psk=[REDACTED])`

### 2. Audit Logs

**Purpose:** Who did what (security accountability)
**Location:** `/var/lib/rustyjack/logs/audit/audit.log`
**Retention:** Append-only (cleared only via explicit log clearing operation)
**Access:** daemon (root) writes only, read via daemon IPC
**Format:** JSON lines for easy parsing

**What to log:**
- Actor identity (UID, PID, group)
- Privileged operations:
  - System reboot/shutdown
  - MAC randomization
  - Log clearing
  - Network attack operations (deauth, DNS spoof, MITM)
  - Hotspot/portal start/stop
  - Logging configuration changes
  - Interface isolation changes
- Authorization decisions (allowed/denied)
- Result (success/failure/denied)
- Minimal context data (no secrets)

**Audit event structure:**
```json
{
  "timestamp": 1704672000000,
  "operation": "system.reboot",
  "actor_uid": 1000,
  "actor_pid": 12345,
  "actor_group": "rustyjack",
  "result": "success",
  "context": null
}
```

### 3. Loot Logs

**Purpose:** Attack results and captured data
**Location:** `/var/lib/rustyjack/loot/<scope>/<target>/<action>/`
**Retention:** User-controlled (part of loot data)
**Access:** daemon (root) writes, UI reads via daemon IPC
**Format:** Varies (credentials, captures, etc.)

**What to log:**
- Captured credentials (portal, PMKID, WPA)
- Cracked passwords/keys
- Network packet captures
- MAC addresses observed
- DNS queries/responses
- Payload execution results

**Special handling:**
- Never mirror to operational logs
- Encrypted when encryption is enabled
- Cleared only via explicit loot clearing
- Access controlled by file permissions

### 4. High-Volume Trace Logs

**Purpose:** Packet-level debugging
**Location:** In-memory or short-term files
**Retention:** Session-only or very short (1 hour)
**Access:** daemon only
**Enabled by:** Explicit debug flag or environment variable

**What to log:**
- DNS query/response details
- DHCP transactions
- hostapd handshake debug
- Netlink message dumps
- nftables packet logs (via kernel)

**When to enable:**
- Debugging specific issues
- Development/testing
- NOT in production by default

## Redaction Guidelines

### Automatic Redaction

Use the `redact!()` macro for sensitive fields:

```rust
use rustyjack_core::redact;

tracing::info!(
    "wifi_connect: ssid={}, psk={}",
    ssid,
    redact!(psk)
);
```

### Manual Redaction

For structured logging with `#[instrument]`:

```rust
#[tracing::instrument(skip(password, psk, key))]
fn connect_wifi(ssid: &str, psk: &str) {
    // psk is not logged
}
```

### Redaction Patterns

Always redact:
- `password`, `psk`, `key`, `secret`, `token`
- Anything with `_pass`, `_key`, `_secret` suffix
- Credit card numbers, personal data

Sometimes redact (context-dependent):
- SSIDs (in audit logs, may keep; in loot, keep)
- MAC addresses (attackers, keep; victims, consider redacting)
- IP addresses (internal networks, consider redacting)

## Log Access Control

### File Permissions

```
/var/lib/rustyjack/logs/
  drwxrws--- root:rustyjack     (0o2770)
  rustyjackd.log
  rustyjack-ui.log
  portal.log
  audit/
    drwxrws--- root:rustyjack   (0o2770)
    audit.log
```

### IPC Access

- Log tail: Available via daemon IPC (LogTailGet)
- Log export: Available via daemon IPC (SystemLogsGet)
- Log config: Available via daemon IPC (LoggingConfigGet/Set)
- UI reads logs through daemon (no direct file access needed)

## Anti-Forensics Integration

When `RUSTYJACK_LOGS_DISABLED=1`:
- Operational logs: Disabled
- Audit logs: **Still active** (security requirement)
- Loot logs: Still active (attack data, not system logs)
- Trace logs: Disabled

Rationale: Even in stealth mode, we need accountability for what the system did. Audit logs can be cleared separately via log clearing operations, which are themselves audited.

## Log Clearing Operations

Three levels of log clearing:

1. **Operational logs only:**
   - Truncates `/var/lib/rustyjack/logs/*.log`
   - Keeps audit logs intact
   - Audited

2. **All logs except loot:**
   - Operational + Audit logs
   - Audited (final entry before clearing audit log)

3. **Everything (full forensic wipe):**
   - Operational + Audit + Loot
   - Shreds files (if available)
   - Runs journalctl vacuum
   - Clears kernel ring buffer
   - Syncs filesystem

## Best Practices

### For Developers

1. Use `tracing::info!` not `println!` for operational events
2. Use audit module for privileged operations
3. Use `#[instrument(skip(...))]` for functions with secrets
4. Never log full command output without inspection
5. Test that sensitive data doesn't leak in error messages

### For Operators

1. Monitor audit log for unexpected operations
2. Export logs before log clearing if needed
3. Understand log clearing levels
4. Use debug/trace logging only when needed
5. Rotate logs regularly in production

## Future Enhancements

- [ ] Log rotation based on size (not just daily)
- [ ] Compressed log archives
- [ ] Remote log shipping (optional)
- [ ] Log integrity verification (signatures)
- [ ] Real-time log filtering/alerting
- [ ] Automatic PII detection and redaction
