# Stage 5: Attack Surface Reduction - Planning & Analysis
Created: 2026-01-07

## Overview

Stage 5 addresses architectural security concerns by reducing the daemon's attack surface, improving privilege separation, and hardening the deployment configuration.

## Current Architecture Issues

### 1. WiFi Operations Outside Daemon Boundary

**Problem:**
- Real WiFi logic lives in `rustyjack-core/src/services/wifi.rs`
- Uses NetworkManager (`nmcli`) or wpa_supplicant (`wpa_cli`) directly
- Daemon has no control over subprocess execution
- No cancellation support for WiFi operations

**Current flow:**
```
UI/Client → Daemon (JobStart) → spawn_blocking → rustyjack-core → nmcli/wpa_cli
```

**Security implications:**
- Daemon runs as root with full network stack access
- WiFi operations bypass daemon's security controls
- No resource limits on WiFi subprocess spawns
- Limited observability into WiFi state changes

**Recommendation:**
Keep current architecture but add:
- Subprocess timeout wrappers in rustyjack-core
- Better error handling and logging
- Resource limits via cgroups (systemd)

**Why NOT to refactor:**
- WiFi operations are inherently privileged (need CAP_NET_ADMIN)
- NetworkManager already provides IPC boundary
- Separation would add complexity without security benefit
- Current approach is standard for system daemons

**Action items:**
- ✅ Document WiFi architecture as acceptable
- 🔲 Add subprocess timeouts (Stage 2B)
- 🔲 Improve error propagation
- 🔲 Add systemd resource limits

### 2. Portal Isolation

**Problem:**
- Portal (captive web server) runs in daemon process
- HTTP parsing and request handling in privileged process
- Potential for web vulnerabilities to compromise daemon

**Current flow:**
```
Client connects → Portal HTTP server → rustyjack-core → Daemon state
```

**Security implications:**
- Web server vulnerabilities = root compromise
- HTTP parsing bugs could crash daemon
- No privilege separation for web content
- Portal has access to all daemon state

**Recommendation:**
**Option A: Separate process (HIGH priority)**
```
rustyjackd (root) ← UDS → rustyjack-portal (unprivileged)
                                  ↓
                            HTTP :3000
```

Benefits:
- Portal runs as `rustyjack-portal` user (no root)
- Web vulnerabilities contained to portal process
- Can restart portal without daemon restart
- Portal can be sandboxed with seccomp

**Option B: Drop privileges before HTTP listen (MEDIUM)**
```rust
// In portal start
setuid(portal_uid);  // Drop to unprivileged user
start_http_server(); // Now running as portal user
```

Drawback: Still in same process, daemon crash = portal down

**Option C: Use reverse proxy (ALTERNATIVE)**
```
nginx (root, privileged port) → rustyjack-portal (unprivileged, :8080)
```

Benefit: Industry-standard hardened web server handles TLS, headers
Drawback: More complex deployment

**Recommended approach: Option A**

Implementation plan:
1. Create `rustyjack-portal` binary (new crate)
2. Add `rustyjack-portal.service` systemd unit
3. Portal binary:
   - Connects to daemon UDS for API calls
   - Runs HTTP server on configured port
   - Serves captive portal pages
4. Daemon delegates portal operations to separate process
5. Portal user/group: `rustyjack-portal` (no special privileges)

### 3. Systemd Hardening

**Current state:**
`rustyjackd.service` has minimal hardening:
```ini
[Service]
Type=notify
User=root
```

**Security implications:**
- Full filesystem access
- All capabilities
- Can load kernel modules
- Unrestricted syscalls

**Recommended hardening:**
```ini
[Service]
Type=notify
User=root
# Keep minimal privileges
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# Filesystem protection
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/rustyjack /run/rustyjack
PrivateTmp=true

# Kernel protection
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# Execution protection
NoNewPrivileges=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

# Network (allow all for WiFi)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET

# Syscall filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallArchitectures=native

# Resource limits
LimitNOFILE=1024
TasksMax=64
```

**Capabilities needed:**
- `CAP_NET_ADMIN` - WiFi, network configuration
- `CAP_NET_RAW` - Raw sockets for network operations
- `CAP_SYS_ADMIN` - Mount operations
- `CAP_DAC_OVERRIDE` - Access protected files (optional, remove if possible)

**Testing approach:**
1. Add hardening incrementally
2. Test each WiFi/mount/portal operation
3. Check `journalctl` for permission denials
4. Relax only what's necessary

### 4. Installer Improvements

**Current issues:**
- Installers modify system state (resolv.conf, NetworkManager)
- No rollback on failure
- Manual reboot required
- Limited error handling

**Recommendations:**

**A) Idempotency:**
```bash
# Check before modify
if ! grep -q "dns=none" /etc/NetworkManager/NetworkManager.conf; then
    # Backup before modify
    cp /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/NetworkManager.conf.backup
    # Modify
    sed -i '/\[main\]/a dns=none' /etc/NetworkManager/NetworkManager.conf
fi
```

**B) State tracking:**
```bash
# Track what we've done
STATE_FILE=/var/lib/rustyjack/install_state.txt
echo "modified_nm_config" >> $STATE_FILE
```

**C) Rollback function:**
```bash
rollback_install() {
    while read -r action; do
        case $action in
            modified_nm_config)
                mv /etc/NetworkManager/NetworkManager.conf.backup \
                   /etc/NetworkManager/NetworkManager.conf
                ;;
        esac
    done < $STATE_FILE
}
trap rollback_install ERR
```

**D) Version detection:**
```bash
# Check if already installed
if [ -f /usr/local/bin/rustyjackd ]; then
    INSTALLED_VERSION=$(/usr/local/bin/rustyjackd --version 2>/dev/null || echo "unknown")
    echo "Found existing installation: $INSTALLED_VERSION"
    read -p "Upgrade? [y/N] " -n 1 -r
fi
```

## Implementation Priority

### High Priority
1. **Portal isolation** - Separate process
2. **Systemd hardening** - Capability limits
3. **Installer idempotency** - Safer upgrades

### Medium Priority
4. **Subprocess timeouts** - Part of Stage 2B
5. **WiFi architecture documentation** - Clarify boundaries
6. **Resource limits** - CPU/memory via cgroups

### Low Priority
7. **Portal reverse proxy** - Optional production hardening
8. **Automated testing** - Integration tests for hardening

## Portal Isolation - Detailed Design

### New Architecture
```
┌─────────────────────┐
│  rustyjackd         │
│  (root)             │
│  CAP_NET_ADMIN      │
│                     │
│  ┌──────────────┐   │
│  │ WiFi/Network │   │
│  │ Mount        │   │
│  │ System       │   │
│  └──────────────┘   │
└──────────┬──────────┘
           │ UDS
           │ /run/rustyjack/rustyjackd.sock
           │
    ┌──────┴──────────────┐
    │                     │
    ▼                     ▼
┌─────────────┐   ┌─────────────────┐
│ rustyjack-ui│   │ rustyjack-portal│
│ (rustyjack- │   │ (rustyjack-     │
│  ui user)   │   │  portal user)   │
└─────────────┘   └────────┬────────┘
                           │
                           │ HTTP :3000
                           ▼
                    ┌──────────────┐
                    │   Clients    │
                    │ (Web Browser)│
                    └──────────────┘
```

### Portal Process Responsibilities
- HTTP server (axum/warp/tiny-http)
- Serve captive portal HTML/CSS/JS
- Handle device detection requests
- Forward admin commands to daemon via UDS
- No privileged operations

### Portal API Examples
```rust
// In rustyjack-portal binary
#[tokio::main]
async fn main() {
    // Connect to daemon
    let daemon_client = DaemonClient::connect(
        "/run/rustyjack/rustyjackd.sock",
        "rustyjack-portal",
        env!("CARGO_PKG_VERSION")
    ).await?;
    
    // Start HTTP server
    let app = Router::new()
        .route("/", get(portal_index))
        .route("/api/clients", get(list_clients))
        .layer(Extension(daemon_client));
    
    axum::Server::bind(&"0.0.0.0:3000".parse()?)
        .serve(app.into_make_service())
        .await?;
}

async fn list_clients(
    Extension(client): Extension<DaemonClient>
) -> Result<Json<Vec<Client>>, StatusCode> {
    // Forward to daemon
    let clients = client.hotspot_clients_list().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(clients))
}
```

### Migration Path
1. **Phase 1:** Create rustyjack-portal crate
2. **Phase 2:** Implement portal binary
3. **Phase 3:** Add systemd unit for portal
4. **Phase 4:** Update daemon to delegate portal ops
5. **Phase 5:** Remove portal code from daemon
6. **Phase 6:** Update installers

### Backward Compatibility
- Keep portal in daemon for one release
- Add `RUSTYJACKD_EXTERNAL_PORTAL=1` flag
- Deprecation warning if internal portal used
- Remove in next major version

## Acceptance Criteria

### Portal Isolation
- ✅ rustyjack-portal binary runs as separate process
- ✅ Portal process runs as unprivileged user
- ✅ Portal connects to daemon via UDS
- ✅ Captive portal functionality preserved
- ✅ Portal can be restarted independently

### Systemd Hardening
- ✅ Capabilities limited to minimum required
- ✅ Filesystem access restricted
- ✅ Kernel protections enabled
- ✅ Resource limits configured
- ✅ All operations still functional

### Installer Improvements
- ✅ Idempotent (safe to run multiple times)
- ✅ Backup existing config before modify
- ✅ Rollback on error
- ✅ Version detection
- ✅ Graceful handling of existing installation

## Risk Assessment

**Portal isolation:**
- **Complexity:** Medium (new process, IPC coordination)
- **Risk:** Low (well-understood pattern)
- **Testing:** High (requires functional tests)

**Systemd hardening:**
- **Complexity:** Low (configuration changes)
- **Risk:** Medium (may break functionality)
- **Testing:** High (test all operations)

**Installer improvements:**
- **Complexity:** Low (bash scripting)
- **Risk:** Low (safer than current)
- **Testing:** Medium (manual install/uninstall)

## Next Steps

1. Document current WiFi architecture as acceptable ✅
2. Design portal isolation (this document) ✅
3. Create systemd hardening config draft
4. Implement portal isolation (Phase 1-3)
5. Test hardening configuration
6. Update installers with idempotency

## Conclusion

Stage 5 focuses on defense-in-depth:
- **Portal isolation** reduces impact of web vulnerabilities
- **Systemd hardening** limits daemon privileges
- **Installer improvements** make deployment safer

These changes maintain functionality while significantly reducing attack surface. Portal isolation is the highest priority as it moves untrusted HTTP handling out of the privileged daemon process.
