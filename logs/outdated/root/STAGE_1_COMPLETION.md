# Stage 1 Completion Report
Created: 2026-01-07

## Goals
- Add UDS read/write timeout configuration
- Wrap all read_frame/write_frame calls in timeouts
- Add stable timeout error code mapping
- Log peer credentials on timeout

## Work Completed

### 1. Configuration Changes ✅

**File:** `rustyjack-daemon/src/config.rs`

Added timeout configuration with environment variable support:
- `RUSTYJACKD_READ_TIMEOUT_MS` (default: 5000ms)
- `RUSTYJACKD_WRITE_TIMEOUT_MS` (default: 5000ms)

Added to `DaemonConfig`:
```rust
pub read_timeout: Duration,
pub write_timeout: Duration,
```

Defaults:
```rust
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 5000;
pub const DEFAULT_WRITE_TIMEOUT_MS: u64 = 5000;
```

### 2. Server Timeout Wrappers ✅

**File:** `rustyjack-daemon/src/server.rs`

Added helper functions to wrap I/O operations with timeout:

```rust
async fn read_frame_timed(
    stream: &mut UnixStream,
    max_frame: u32,
    timeout_duration: Duration,
) -> io::Result<Vec<u8>>

async fn write_frame_timed(
    stream: &mut UnixStream,
    payload: &[u8],
    max_frame: u32,
    timeout_duration: Duration,
) -> io::Result<()>

async fn send_error_timed(
    stream: &mut UnixStream,
    version: u32,
    request_id: u64,
    err: DaemonError,
    max_frame: u32,
    timeout_duration: Duration,
) -> Result<()>
```

### 3. Request Loop Timeout Integration ✅

Replaced all frame I/O calls with timed versions:

**Hello ACK write:** Uses `write_frame_timed` with `state.config.write_timeout`

**Request loop read:** 
- Uses `read_frame_timed` with `state.config.read_timeout`
- On timeout: logs `"Frame read timeout from pid {} uid {}"` with peer credentials
- Sends `DaemonError::new(ErrorCode::Timeout, "read timeout", true)` with best-effort delivery
- Closes connection

**Response write:**
- Uses `write_frame_timed` with `state.config.write_timeout`
- On timeout: logs `"Response write timeout to pid {} for request {}"` 
- Closes connection

**Error responses:**
- All protocol violations, auth failures, and handshake errors use `send_error_timed`
- Best-effort delivery with timeout protection

### 4. Error Code Mapping ✅

**File:** `rustyjack-ipc/src/error.rs`

The `ErrorCode::Timeout` enum variant already exists:
```rust
Timeout = 7,
```

Marked as `retryable: true` when constructing timeout errors, allowing clients to implement retry logic.

### 5. Peer Credential Logging ✅

All timeout events log:
- `peer.pid` - Process ID of stalling client
- `peer.uid` - User ID of stalling client  
- `request.request_id` - Request being processed (for write timeouts)

This enables identifying and debugging misbehaving clients.

## DoS Protection

The timeout implementation provides robust protection against local DoS attacks:

1. **Stalled reads:** Client connects and stops sending → 5s timeout → connection closed
2. **Stalled writes:** Client stops reading responses → 5s timeout → connection closed
3. **Partial frames:** Client sends incomplete frame → read times out → connection closed
4. **Handshake stall:** Already protected by 2s handshake timeout (unchanged)

## Configuration Flexibility

Operators can tune timeouts for their environment:
```bash
# More aggressive (faster DoS detection, may affect slow clients)
RUSTYJACKD_READ_TIMEOUT_MS=2000 RUSTYJACKD_WRITE_TIMEOUT_MS=2000

# More lenient (slower DoS detection, tolerates slower clients)
RUSTYJACKD_READ_TIMEOUT_MS=10000 RUSTYJACKD_WRITE_TIMEOUT_MS=10000
```

## Testing Recommendations

On target Linux system, verify timeout behavior:

### Test 1: Read timeout
```bash
# Connect and stall
socat - UNIX-CONNECT:/run/rustyjack/rustyjackd.sock
# Send nothing, wait >5s → daemon should log timeout and close
```

### Test 2: Write timeout  
```bash
# Start long-running job, stop reading responses
echo '<valid-request>' | socat - UNIX-CONNECT:/run/rustyjack/rustyjackd.sock
# Don't read response → daemon should timeout on write
```

### Test 3: Partial frame
```python
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/rustyjack/rustyjackd.sock')
s.send(b'\x00\x00\x00\x10')  # Frame length 16
s.send(b'\x01\x02')          # Only 2 bytes
# Wait >5s → daemon should timeout
```

## Acceptance Criteria Status

- ✅ Read timeout configuration added
- ✅ Write timeout configuration added  
- ✅ All `read_frame` calls wrapped with timeout
- ✅ All `write_frame` calls wrapped with timeout
- ✅ Timeout errors use stable `ErrorCode::Timeout` (value 7)
- ✅ Timeout errors marked retryable
- ✅ Peer credentials logged on timeout
- ✅ Request ID logged on write timeout
- ⏳ Functional tests pending Linux environment

## Next Stage

Proceed to **Stage 2**: Real cancellation (cancellable blocking + subprocess kill)
