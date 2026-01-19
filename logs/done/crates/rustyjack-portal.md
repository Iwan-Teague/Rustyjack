# rustyjack-portal
Created: 2026-01-07

Rust-only HTTP portal server used by DNS spoof and Ethernet site credential capture. Replaces the PHP-based portal and is compiled into the Rustyjack workspace.

## Responsibilities
- Serve static portal assets from `DNSSpoof/sites/<site>` (default `index.html`).
- Handle POST form capture (`username`/`password`) and write logs compatible with the legacy PHP format.
- Apply safety limits (request body size, timeout, concurrency) for embedded use.
- Provide a start/stop API for `rustyjack-core` without process-kill hacks.

## Main components
- `config.rs`: `PortalConfig` describing interface, bind address/port, paths, and limits.
- `logging.rs`: visit/credential log formatting and serialized append writes.
- `server.rs`: Axum router, middleware stack, GET/POST handlers, and static file serving.
- `state.rs`: global handle with start/stop lifecycle, dedicated Tokio runtime thread, optional DNAT rules.

## Dependencies/expectations
- Runs on Linux and assumes root/CAP_NET_ADMIN to bind port 80 and apply optional DNAT rules.
- Uses Axum + tower-http for routing and safety layers; Tokio runtime has net/fs enabled.
- Timestamps use local time RFC3339 seconds to match PHP `date('c')` formatting.

## Notes for contributors
- Preserve log line format and double-visit logging for POSTs (view + post).
- Never log credentials or request bodies to stdout/stderr.
- Keep middleware minimal; avoid tracing that captures headers/bodies.
- If you add new binaries to the flow, update installers to include them.
