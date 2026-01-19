# Rustyjack Daemon Security Updates - Deployment Guide
Created: 2026-01-07

**Version:** Post-Stages 0-3  
**Target:** Raspberry Pi Zero 2 W / Raspberry Pi OS

## Quick Start

### 1. Build and Deploy

On your Raspberry Pi:
```bash
cd /path/to/Rustyjack
cargo build --release --workspace
sudo systemctl stop rustyjackd.service rustyjack-ui.service
sudo cp target/release/rustyjackd /usr/local/bin/
sudo cp target/release/rustyjack-ui /usr/local/bin/
sudo systemctl start rustyjackd.service rustyjack-ui.service
```

### 2. Configure Group-Based Authorization

```bash
# Create admin group
sudo groupadd rustyjack-admin

# Add UI user to admin group (enables system updates from UI)
sudo usermod -aG rustyjack-admin rustyjack-ui

# Verify
groups rustyjack-ui
# Expected: rustyjack-ui gpio spi rustyjack rustyjack-admin
```

### 3. Enable System Updates (Optional)

Edit `/etc/systemd/system/rustyjackd.service`:
```ini
[Service]
Environment=RUSTYJACKD_DANGEROUS_OPS=true
```

Reload and restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart rustyjackd.service
```

### 4. Verify

```bash
# Check daemon is running
sudo systemctl status rustyjackd.service

# Check UI can perform admin actions
sudo -u rustyjack-ui rustyjack-client version
# Should show version info
```

---

## Configuration Reference

### Environment Variables (rustyjackd.service)

Add these to `[Service]` section in `/etc/systemd/system/rustyjackd.service`:

```ini
# Timeouts (milliseconds)
Environment=RUSTYJACKD_READ_TIMEOUT_MS=5000
Environment=RUSTYJACKD_WRITE_TIMEOUT_MS=5000

# Authorization groups
Environment=RUSTYJACKD_ADMIN_GROUP=rustyjack-admin
Environment=RUSTYJACKD_OPERATOR_GROUP=rustyjack

# Security
Environment=RUSTYJACKD_DANGEROUS_OPS=true

# Paths
Environment=RUSTYJACKD_SOCKET=/run/rustyjack/rustyjackd.sock

# Job retention
Environment=RUSTYJACKD_JOB_RETENTION=200
```

### Default Values

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTYJACKD_READ_TIMEOUT_MS` | 5000 | Socket read timeout (DoS protection) |
| `RUSTYJACKD_WRITE_TIMEOUT_MS` | 5000 | Socket write timeout (DoS protection) |
| `RUSTYJACKD_ADMIN_GROUP` | `rustyjack-admin` | Group name for Admin tier |
| `RUSTYJACKD_OPERATOR_GROUP` | `rustyjack` | Group name for Operator tier |
| `RUSTYJACKD_DANGEROUS_OPS` | `false` | Enable SystemUpdate job |
| `RUSTYJACKD_SOCKET` | `/run/rustyjack/rustyjackd.sock` | UDS path |
| `RUSTYJACKD_JOB_RETENTION` | 200 | Max jobs in history |

---

## Authorization Tiers

### ReadOnly
**Access:** Version, Health, Status endpoints (read-only queries)  
**How to grant:** No special groups needed

### Operator
**Access:** All ReadOnly + WiFi, Mount, Scan, Portal, Hotspot operations  
**How to grant:** Add user to `rustyjack` group
```bash
sudo usermod -aG rustyjack username
```

### Admin
**Access:** All Operator + System reboot/shutdown/update  
**How to grant (option 1):** Run as root
```bash
sudo rustyjack-client system-reboot
```

**How to grant (option 2):** Add user to `rustyjack-admin` group
```bash
sudo usermod -aG rustyjack-admin username
```

---

## Troubleshooting

### "Permission denied" connecting to socket
**Symptom:** `rustyjack-client` fails with permission error

**Check:**
```bash
ls -l /run/rustyjack/rustyjackd.sock
# Expected: srwxrw---- 1 root rustyjack ... rustyjackd.sock
```

**Fix:** Add user to `rustyjack` group
```bash
sudo usermod -aG rustyjack $USER
# Log out and back in for group to take effect
```

### "Forbidden" on SystemUpdate
**Symptom:** Job start returns `ErrorCode::Forbidden`

**Check 1:** User is in admin group
```bash
groups
# Should include rustyjack-admin
```

**Check 2:** Dangerous ops enabled
```bash
sudo systemctl show rustyjackd.service | grep DANGEROUS_OPS
# Should show Environment=RUSTYJACKD_DANGEROUS_OPS=true
```

**Fix:**
```bash
sudo usermod -aG rustyjack-admin $USER
# And/or enable dangerous ops (see step 3 above)
```

### Connection timeouts
**Symptom:** Client hangs or times out after 5 seconds

**Check:** Daemon logs
```bash
sudo journalctl -u rustyjackd.service -n 50
# Look for "Frame read timeout" or "Response write timeout"
```

**Possible causes:**
- Client not reading responses
- Network issue (shouldn't happen with UDS)
- Client sending malformed frames

**Fix:** Increase timeout if needed:
```ini
Environment=RUSTYJACKD_READ_TIMEOUT_MS=10000
Environment=RUSTYJACKD_WRITE_TIMEOUT_MS=10000
```

### Groups not taking effect
**Symptom:** User added to group but still gets "Forbidden"

**Check:** Current groups in active session
```bash
groups
# If rustyjack-admin not shown, log out and back in
```

**Fix:** Groups are evaluated at login. Either:
- Log out and back in
- Start new session: `su - $USER`
- (For testing) `newgrp rustyjack-admin`

---

## Security Best Practices

### 1. Restrict Admin Group Membership
The `rustyjack-admin` group grants full system control:
- System reboot/shutdown
- System updates (git clone with full filesystem access)
- All mount/unmount operations

**Recommendation:** Only add trusted users/services.

### 2. Disable Dangerous Ops in Production
If you don't need remote updates:
```ini
# Leave this commented or set to false
# Environment=RUSTYJACKD_DANGEROUS_OPS=true
```

This prevents SystemUpdate even for Admin users.

### 3. Monitor Timeout Events
Frequent timeout events may indicate:
- Buggy client code
- Intentional DoS attempts
- Resource exhaustion

Check logs regularly:
```bash
sudo journalctl -u rustyjackd.service | grep -i timeout
```

### 4. Socket Permissions
The default `SocketMode=0660` and `SocketGroup=rustyjack` means:
- Only `rustyjack` group members can connect
- No world access
- Root can always connect

This is correct for a dedicated device. Do NOT change to `0666`.

---

## Rollback Procedure

If you encounter issues after deployment:

```bash
# Stop services
sudo systemctl stop rustyjackd.service rustyjack-ui.service

# Restore previous binaries from backup
sudo cp /backup/rustyjackd /usr/local/bin/
sudo cp /backup/rustyjack-ui /usr/local/bin/

# Remove new environment variables from systemd units
sudo nano /etc/systemd/system/rustyjackd.service
# Remove RUSTYJACKD_*_TIMEOUT_MS and RUSTYJACKD_*_GROUP lines

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl start rustyjackd.service rustyjack-ui.service
```

---

## Change Log

### Stages 0-3 (2026-01-03)

**New features:**
- UDS read/write timeout protection (5s default)
- Group-based authorization (admin-group, operator-group)
- Configurable group names via environment variables

**Bug fixes:**
- Removed unused code warnings

**Breaking changes:**
- None (backward compatible)
- Users without special groups now get ReadOnly (not Operator)
- To restore old behavior: all users should be in `rustyjack` group

**Security improvements:**
- DoS protection via connection timeouts
- Fine-grained access control via groups
- Unprivileged admin operations

---

## Support

For issues or questions:
1. Check daemon logs: `sudo journalctl -u rustyjackd.service`
2. Check UI logs: `sudo journalctl -u rustyjack-ui.service`
3. Review stage documentation in `docs/STAGE_*_COMPLETION.md`
4. Review `docs/IMPLEMENTATION_SUMMARY.md`
