# Rustyjack Test Run Summary

- Run ID: 20260215-204314
- Host: rustyjack
- Results Root: /var/tmp/rustyjack-tests/20260215-204314
- Suites Run: 17
- Suites Passed: 4
- Suites Failed: 13
- Tests Total: 98
- Tests Passed: 180
- Tests Failed: 51
- Tests Skipped: 45

## Suite Breakdown

| Suite | Status | RC | Duration | Tests | Pass | Fail | Skip |
|---|---|---:|---:|---:|---:|---:|---:|
| Discord Webhook | FAIL | 1 | 3s | 3 | 5 | 2 | 0 |
| Wireless | FAIL | 1 | 24s | 31 | 31 | 2 | 5 |
| Ethernet | FAIL | 1 | 37s | 8 | 7 | 2 | 4 |
| Interface Selection | FAIL | 1 | 23s | 18 | 22 | 8 | 1 |
| Encryption | PASS | 0 | 13s | 0 | 7 | 0 | 3 |
| Loot | FAIL | 1 | 14s | 9 | 9 | 1 | 3 |
| MAC Randomization | PASS | 0 | 1s | 1 | 1 | 0 | 8 |
| Evasion | FAIL | 1 | 3s | 6 | 0 | 12 | 0 |
| Anti-Forensics | FAIL | 1 | 2s | 4 | 1 | 8 | 2 |
| Physical Access | FAIL | 1 | 1s | 3 | 2 | 4 | 2 |
| Hotspot | FAIL | 127 | 0s | - | - | - | - |
| Daemon/IPC | FAIL | 1 | 4m14s | 6 | 11 | 5 | 4 |
| Daemon Deep Diagnostics | FAIL | 1 | 4m05s | - | - | - | - |
| Installers | PASS | 0 | 4s | 4 | 48 | 0 | 8 |
| USB Mount | FAIL | 1 | 5s | 3 | 4 | 6 | 0 |
| UI Layout/Display | PASS | 0 | 0s | 0 | 0 | 0 | 2 |
| Theme/Palette | FAIL | 1 | 22s | 2 | 32 | 1 | 3 |

## Failure Snippets

### Discord Webhook
- [FAIL] discord_send_test_message (rc=1)

### Wireless
- [FAIL] wifi_scan_wlan0 (rc=101)

### Ethernet
- [FAIL] eth_discover_eth0 (rc=101)

### Interface Selection
- [FAIL] set_active_eth0 (rc=0)

### Loot
- [FAIL] Isolation check failed: loot_readonly (route changed)

### Evasion
- [FAIL] evasion_mac_status (rc=2)

### Anti-Forensics
- [FAIL] audit_log_status (rc=2)

### Physical Access
- [FAIL] router_fingerprint_help (rc=2)

### Hotspot
- No [FAIL] lines captured. Check suite log.

### Daemon/IPC
- [FAIL] rpc_ok_A7 (expected Ok, got Err) err=operations are restricted to the UI runtime

### USB Mount
- [FAIL] usb_detectability_preflight (/dev/sda)

### Theme/Palette
- [FAIL] theme_restart_repair_invalid_config_active (service not active)

