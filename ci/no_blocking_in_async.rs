//! CI check: Detect blocking operations in async contexts
//!
//! This tool scans Rust source files to find blocking operations that may freeze
//! the async runtime. The daemon uses `current_thread` Tokio runtime, making any
//! blocking call especially dangerous as it will halt all async tasks.
//!
//! Usage: rustc ci/no_blocking_in_async.rs -o /tmp/no_blocking_in_async && /tmp/no_blocking_in_async
//!
//! Detected patterns:
//! - std::thread::sleep (use tokio::time::sleep)
//! - std::fs::* operations (use tokio::fs or spawn_blocking)
//! - std::net::* synchronous networking (use tokio::net)
//! - std::sync::Mutex::lock (use tokio::sync::Mutex or spawn_blocking)
//! - std::io blocking operations
//! - std::sync::mpsc blocking channel recv
//!
//! Allowlisted contexts (blocking is OK here):
//! - Inside spawn_blocking closures
//! - Inside block_on calls
//! - Test code (#[test] or #[cfg(test)])
//! - Startup code (main function before async runtime)
//! - Explicitly marked with // allow-blocking comment

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;

/// Blocking patterns to detect with their suggested alternatives
const BLOCKING_PATTERNS: &[(&str, &str)] = &[
    // Thread sleep
    ("std::thread::sleep", "use tokio::time::sleep"),
    ("thread::sleep", "use tokio::time::sleep"),

    // Filesystem operations
    ("std::fs::read_to_string", "use tokio::fs::read_to_string or spawn_blocking"),
    ("std::fs::read_dir", "use tokio::fs::read_dir or spawn_blocking"),
    ("std::fs::read(", "use tokio::fs::read or spawn_blocking"),
    ("std::fs::write(", "use tokio::fs::write or spawn_blocking"),
    ("std::fs::create_dir", "use tokio::fs::create_dir or spawn_blocking"),
    ("std::fs::remove_file", "use tokio::fs::remove_file or spawn_blocking"),
    ("std::fs::remove_dir", "use tokio::fs::remove_dir or spawn_blocking"),
    ("std::fs::copy(", "use tokio::fs::copy or spawn_blocking"),
    ("std::fs::rename", "use tokio::fs::rename or spawn_blocking"),
    ("std::fs::metadata", "use tokio::fs::metadata or spawn_blocking"),
    ("std::fs::File::open", "use tokio::fs::File::open or spawn_blocking"),
    ("std::fs::File::create", "use tokio::fs::File::create or spawn_blocking"),
    ("std::fs::OpenOptions", "use tokio::fs or spawn_blocking"),
    ("fs::read_to_string", "use tokio::fs::read_to_string or spawn_blocking"),
    ("fs::read_dir", "use tokio::fs::read_dir or spawn_blocking"),
    ("fs::write(", "use tokio::fs::write or spawn_blocking"),
    ("fs::create_dir", "use tokio::fs::create_dir or spawn_blocking"),
    ("fs::remove_file", "use tokio::fs::remove_file or spawn_blocking"),
    ("fs::remove_dir", "use tokio::fs::remove_dir or spawn_blocking"),
    ("fs::copy(", "use tokio::fs::copy or spawn_blocking"),
    ("fs::rename", "use tokio::fs::rename or spawn_blocking"),
    ("fs::metadata", "use tokio::fs::metadata or spawn_blocking"),
    ("File::open", "use tokio::fs::File::open or spawn_blocking"),
    ("File::create", "use tokio::fs::File::create or spawn_blocking"),
    ("OpenOptions::new", "use tokio::fs or spawn_blocking"),

    // Synchronous networking
    ("std::net::TcpStream::connect", "use tokio::net::TcpStream"),
    ("std::net::TcpListener::bind", "use tokio::net::TcpListener"),
    ("std::net::UdpSocket::bind", "use tokio::net::UdpSocket"),
    ("TcpStream::connect", "use tokio::net::TcpStream"),
    ("TcpListener::bind", "use tokio::net::TcpListener"),
    ("UdpSocket::bind", "use tokio::net::UdpSocket"),

    // Blocking mutex
    ("std::sync::Mutex", "use tokio::sync::Mutex or spawn_blocking for StdMutex"),

    // Blocking channel recv
    ("mpsc::Receiver::recv()", "use tokio::sync::mpsc or spawn_blocking"),
    (".recv().unwrap()", "use tokio::sync::mpsc or async recv"),
    (".recv_timeout(", "use tokio::sync::mpsc with timeout"),

    // Blocking IO
    ("stdin().read_line", "use tokio::io::BufReader or spawn_blocking"),
    ("BufReader::new(std::io", "use tokio::io::BufReader"),

    // DNS resolution
    ("std::net::ToSocketAddrs", "use tokio::net::lookup_host"),
];

/// Patterns that indicate we're in a blocking-safe context
const BLOCKING_SAFE_PATTERNS: &[&str] = &[
    "spawn_blocking",
    "block_on(",
    "tokio::task::spawn_blocking",
    "#[test]",
    "#[cfg(test)]",
    "// allow-blocking",
    "//allow-blocking",
    "/* allow-blocking */",
];

/// Directories/files that are allowlisted for blocking operations
const ALLOWLISTED_PATHS: &[&str] = &[
    // UI is synchronous by design
    "crates/rustyjack-ui/",
    // External tools are expected to do blocking work
    "crates/rustyjack-core/src/external_tools/",
    // Test files
    "/tests/",
    // Build scripts
    "build.rs",
    // CI tools themselves
    "ci/",
];

/// Files that need special handling (async but with legitimate blocking at startup)
/// Note: Currently handled via path allowlist, but kept for potential future use
#[allow(dead_code)]
const STARTUP_ALLOWLIST: &[&str] = &[
    "main.rs",
];

fn main() {
    if let Err(err) = run() {
        eprintln!("no_blocking_in_async: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let repo = env::current_dir().map_err(|e| format!("cwd: {e}"))?;

    // Load custom allowlist if it exists
    let custom_allowlist = load_allowlist(&repo);

    let mut violations = Vec::new();
    let mut stats = ScanStats::default();

    visit_rs(&repo, &custom_allowlist, &mut violations, &mut stats)?;

    println!("no_blocking_in_async: Scanned {} files, {} async functions",
             stats.files_scanned, stats.async_functions);

    if !violations.is_empty() {
        eprintln!("\n========================================");
        eprintln!("BLOCKING OPERATIONS IN ASYNC CONTEXTS");
        eprintln!("========================================\n");
        eprintln!("Found {} violation(s):\n", violations.len());

        for v in &violations {
            eprintln!("{}:{}:", v.file, v.line);
            eprintln!("  Pattern: {}", v.pattern);
            eprintln!("  Context: {}", v.context.trim());
            eprintln!("  Suggestion: {}", v.suggestion);
            if let Some(ref func) = v.async_function {
                eprintln!("  In async fn: {}", func);
            }
            eprintln!();
        }

        eprintln!("========================================");
        eprintln!("HOW TO FIX");
        eprintln!("========================================\n");
        eprintln!("1. Wrap blocking code in spawn_blocking:");
        eprintln!("   let result = tokio::task::spawn_blocking(|| {{");
        eprintln!("       std::fs::read_to_string(path)");
        eprintln!("   }}).await??;\n");
        eprintln!("2. Use async alternatives:");
        eprintln!("   let content = tokio::fs::read_to_string(path).await?;\n");
        eprintln!("3. If blocking is intentional, add comment:");
        eprintln!("   // allow-blocking: reason here\n");
        eprintln!("4. Add to ci/async_blocking_allowlist.txt if permanently allowed\n");

        return Err(format!("Found {} blocking operation(s) in async context", violations.len()));
    }

    println!("no_blocking_in_async: OK (no violations)");
    Ok(())
}

#[derive(Default)]
struct ScanStats {
    files_scanned: usize,
    async_functions: usize,
}

#[derive(Debug)]
struct Violation {
    file: String,
    line: usize,
    pattern: String,
    context: String,
    suggestion: String,
    async_function: Option<String>,
}

fn visit_rs(
    dir: &Path,
    allowlist: &HashSet<String>,
    out: &mut Vec<Violation>,
    stats: &mut ScanStats,
) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("read dir {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry {}: {e}", dir.display()))?;
        let path = entry.path();

        if path.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            visit_rs(&path, allowlist, out, stats)?;
            continue;
        }

        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        // Check if path is in allowlist
        let path_str = path.display().to_string();
        let path_str_normalized = path_str.replace('\\', "/");

        if is_path_allowlisted(&path_str_normalized) {
            continue;
        }

        // Check custom allowlist (supports partial paths)
        let mut is_custom_allowed = false;
        for allowed in allowlist.iter() {
            if path_str_normalized.ends_with(allowed) || path_str_normalized.contains(allowed) {
                is_custom_allowed = true;
                break;
            }
        }
        if is_custom_allowed {
            continue;
        }

        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };

        stats.files_scanned += 1;

        // Parse the file to find async functions and check for blocking patterns
        check_file(&path_str_normalized, &text, out, stats)?;
    }

    Ok(())
}

fn check_file(
    path: &str,
    content: &str,
    out: &mut Vec<Violation>,
    stats: &mut ScanStats,
) -> Result<(), String> {
    let lines: Vec<&str> = content.lines().collect();

    // Track async function contexts
    let mut async_contexts: Vec<AsyncContext> = Vec::new();

    // Track blocking-safe contexts (spawn_blocking closures, etc.)
    let mut blocking_safe_contexts: Vec<BlockingSafeContext> = Vec::new();

    // Simple state machine to track async fn boundaries
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let line_num = i + 1;

        // Check if this line starts an async function
        if let Some(func_name) = detect_async_fn(line) {
            stats.async_functions += 1;

            // Find the opening brace and track the function body
            let start = find_function_body_start(&lines, i);
            if let Some(body_start) = start {
                async_contexts.push(AsyncContext {
                    name: func_name,
                    start_line: body_start,
                    brace_depth: 1,
                });
            }
        }

        // Check if this line starts a blocking-safe context (spawn_blocking, block_on, etc.)
        if detect_blocking_safe_start(line) {
            // Find the closure opening brace
            let closure_start = find_closure_body_start(&lines, i);
            if let Some(body_start) = closure_start {
                blocking_safe_contexts.push(BlockingSafeContext {
                    start_line: body_start,
                    brace_depth: 1,
                });
            }
        }

        // Update brace depth for active async contexts
        for ctx in &mut async_contexts {
            if line_num > ctx.start_line {
                for ch in line.chars() {
                    match ch {
                        '{' => ctx.brace_depth += 1,
                        '}' => ctx.brace_depth -= 1,
                        _ => {}
                    }
                }
            }
        }

        // Update brace depth for blocking-safe contexts
        for ctx in &mut blocking_safe_contexts {
            if line_num > ctx.start_line {
                for ch in line.chars() {
                    match ch {
                        '{' => ctx.brace_depth += 1,
                        '}' => ctx.brace_depth -= 1,
                        _ => {}
                    }
                }
            }
        }

        // Remove finished contexts
        async_contexts.retain(|ctx| ctx.brace_depth > 0);
        blocking_safe_contexts.retain(|ctx| ctx.brace_depth > 0);

        // If we're inside an async context but NOT inside a blocking-safe context,
        // check for blocking patterns
        let in_async = !async_contexts.is_empty();
        let in_blocking_safe = !blocking_safe_contexts.is_empty();

        if in_async && !in_blocking_safe {
            // Skip if line has blocking-safe pattern on this line
            if has_blocking_safe_pattern(line) {
                i += 1;
                continue;
            }

            // Check surrounding context for spawn_blocking (backup heuristic)
            let context_start = i.saturating_sub(5);
            let context_end = (i + 5).min(lines.len());
            let context_lines = &lines[context_start..context_end];
            let context_text = context_lines.join("\n");

            if is_in_spawn_blocking_context(&context_text) {
                i += 1;
                continue;
            }

            // Check for blocking patterns
            for (pattern, suggestion) in BLOCKING_PATTERNS {
                if line.contains(pattern) {
                    // Skip if it's a use/import statement
                    if line.trim().starts_with("use ") || line.trim().starts_with("//") {
                        continue;
                    }

                    // Skip if pattern is actually a tokio:: async version
                    if is_tokio_async_call(line, pattern) {
                        continue;
                    }

                    // Additional check: std::sync::Mutex is OK if used with spawn_blocking
                    if *pattern == "std::sync::Mutex" {
                        // Check if it's just a type annotation, not a lock call
                        if !line.contains(".lock()") && !line.contains("Mutex::new") {
                            continue;
                        }
                    }

                    // Skip .lock() if it's on a tokio mutex
                    if pattern.contains(".lock()") && line.contains("tokio::") {
                        continue;
                    }

                    // Skip duplicate patterns (e.g., std::thread::sleep and thread::sleep)
                    if is_substring_of_previous_pattern(pattern, &out, path, line_num) {
                        continue;
                    }

                    out.push(Violation {
                        file: path.to_string(),
                        line: line_num,
                        pattern: pattern.to_string(),
                        context: line.to_string(),
                        suggestion: suggestion.to_string(),
                        async_function: async_contexts.last().map(|c| c.name.clone()),
                    });
                }
            }
        }

        i += 1;
    }

    Ok(())
}

struct AsyncContext {
    name: String,
    start_line: usize,
    brace_depth: i32,
}

struct BlockingSafeContext {
    start_line: usize,
    brace_depth: i32,
}

fn detect_async_fn(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Match patterns like:
    // async fn name(
    // pub async fn name(
    // pub(crate) async fn name(
    // async move {  (closures - we'll skip these for now)

    if !trimmed.contains("async") {
        return None;
    }

    // Skip async blocks/closures
    if trimmed.contains("async move") || trimmed.contains("async {") {
        return None;
    }

    // Look for "async fn"
    if let Some(idx) = trimmed.find("async fn ") {
        let after_async_fn = &trimmed[idx + 9..];
        // Extract function name (up to < or ()
        let name_end = after_async_fn
            .find(|c: char| c == '(' || c == '<' || c.is_whitespace())
            .unwrap_or(after_async_fn.len());
        let name = &after_async_fn[..name_end];
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    None
}

fn find_function_body_start(lines: &[&str], fn_line: usize) -> Option<usize> {
    // Find the opening brace of the function
    for (offset, line) in lines[fn_line..].iter().enumerate() {
        if line.contains('{') {
            return Some(fn_line + offset + 1);
        }
        // If we hit another fn or the end, bail
        if offset > 10 {
            return None;
        }
    }
    None
}

/// Detect if a line starts a blocking-safe context
fn detect_blocking_safe_start(line: &str) -> bool {
    let trimmed = line.trim();

    // Patterns that start blocking-safe contexts:
    // - spawn_blocking(move ||
    // - spawn_blocking(||
    // - task::spawn_blocking(
    // - tokio::task::spawn_blocking(
    // - block_on(
    // - run_blocking(

    let blocking_safe_starts = [
        "spawn_blocking(",
        "spawn_blocking(move",
        "task::spawn_blocking(",
        "tokio::task::spawn_blocking(",
        "block_on(",
        "run_blocking(",
        "run_blocking_cancellable(",
        "run_blocking_cancellable_with_progress(",
    ];

    for pattern in blocking_safe_starts {
        if trimmed.contains(pattern) {
            return true;
        }
    }

    false
}

/// Find the start of a closure body (after || or move ||)
fn find_closure_body_start(lines: &[&str], start_line: usize) -> Option<usize> {
    // Look for the opening brace of the closure
    for (offset, line) in lines[start_line..].iter().enumerate() {
        // Check if this line has a closure with opening brace
        if line.contains("||") || line.contains("move |") {
            // If the brace is on the same line, return this line
            if line.contains('{') {
                return Some(start_line + offset + 1);
            }
            // Otherwise look ahead for the brace
            for (inner_offset, inner_line) in lines[start_line + offset + 1..].iter().enumerate() {
                if inner_line.contains('{') {
                    return Some(start_line + offset + inner_offset + 2);
                }
                if inner_offset > 5 {
                    break;
                }
            }
        }
        // Bail if we go too far without finding the closure
        if offset > 10 {
            return None;
        }
    }
    None
}

fn has_blocking_safe_pattern(line: &str) -> bool {
    for pattern in BLOCKING_SAFE_PATTERNS {
        if line.contains(pattern) {
            return true;
        }
    }
    false
}

fn is_in_spawn_blocking_context(context: &str) -> bool {
    // Check if spawn_blocking appears and we're likely inside its closure
    if context.contains("spawn_blocking") {
        // Simple heuristic: if spawn_blocking is in the context window
        // and there's an unmatched opening brace or |_| closure, we're inside
        return true;
    }

    // Check for block_on pattern (used in UI)
    if context.contains("block_on(") {
        return true;
    }

    // Check for run_blocking pattern (daemon's helper)
    if context.contains("run_blocking") {
        return true;
    }

    false
}

/// Check if a pattern match is actually a tokio async call (false positive)
fn is_tokio_async_call(line: &str, pattern: &str) -> bool {
    // Patterns like fs::read_to_string should not match tokio::fs::read_to_string
    // Check if "tokio::" appears before the pattern on this line

    if let Some(pattern_pos) = line.find(pattern) {
        // Look for tokio:: before this position
        let before = &line[..pattern_pos];

        // Check if tokio:: directly precedes the pattern
        if before.ends_with("tokio::") {
            return true;
        }

        // Also check if we have tokio::fs:: or tokio::net:: etc
        let tokio_prefixes = ["tokio::fs::", "tokio::net::", "tokio::io::", "tokio::time::"];
        for prefix in tokio_prefixes {
            if before.contains(prefix) || line.contains(&format!("{}{}", prefix.trim_end_matches("::"), pattern)) {
                return true;
            }
        }

        // Specific check for tokio methods
        if pattern.starts_with("fs::") && before.contains("tokio::") {
            return true;
        }
        if pattern.starts_with("File::") && line.contains("tokio::fs::File") {
            return true;
        }
        if pattern.starts_with("OpenOptions") && line.contains("tokio::fs::OpenOptions") {
            return true;
        }
    }

    false
}

/// Check if this pattern is a substring of an already-reported violation
/// (e.g., "thread::sleep" when "std::thread::sleep" was already reported)
fn is_substring_of_previous_pattern(pattern: &str, violations: &[Violation], file: &str, line: usize) -> bool {
    for v in violations {
        if v.file == file && v.line == line {
            // If the previous pattern contains this one, skip
            if v.pattern.contains(pattern) && v.pattern != pattern {
                return true;
            }
            // If this pattern contains the previous one, it's also a duplicate
            if pattern.contains(&v.pattern) && v.pattern != pattern {
                return true;
            }
        }
    }
    false
}

fn is_path_allowlisted(path: &str) -> bool {
    for allowed in ALLOWLISTED_PATHS {
        if path.contains(allowed) {
            return true;
        }
    }
    false
}

fn should_skip_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    matches!(
        name,
        ".git" | "ci" | "target" | "target-32" | "prebuilt" | "node_modules" | "vendor" | "tmp" | "DNSSpoof"
    )
}

fn load_allowlist(repo: &Path) -> HashSet<String> {
    let allowlist_path = repo.join("ci").join("async_blocking_allowlist.txt");
    let mut set = HashSet::new();

    if let Ok(content) = fs::read_to_string(&allowlist_path) {
        for line in content.lines() {
            let line = line.trim();
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            set.insert(line.to_string());
        }
    }

    set
}
