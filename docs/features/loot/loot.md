# Loot Management

How Rustyjack stores, browses, exports, and reports loot.

## Storage layout
- `loot/Wireless/<target>/`: wireless captures (PCAP, handshakes, PMKIDs, logs, pipeline artifacts).
- `loot/Ethernet/<target>/`: Ethernet PCAPs/logs/reports from discovery/scan/mitm pipelines.
- `loot/reports/<network>/`: combined reports (Wi‑Fi/Ethernet summaries, insights).
- `loot/Hotspot/device_history.txt`: DHCP lease history for hotspot clients.
- Pipeline loot copied under `loot/Wireless/<target>/pipelines/<timestamp>/` for artifacts created after pipeline start.

## UI features
- Loot browser with scrollable viewer; supports Wireless/Ethernet targets and nested files.
- Reports builder and Discord upload helper (zips loot/Responder logs).
- USB export: copies loot and Responder logs to the first writable USB mount (`Rustyjack_Loot`).

## Encryption
- Controlled via `rustyjack-encryption`: process-wide key must be set; toggles for Wi‑Fi profiles and loot encryption. See `loot_encryption.md`.

## Notes
- Loot purge/log purge available via UI (anti-forensics); use carefully.
- Paths are reported after actions and included in reports/Discord uploads.
