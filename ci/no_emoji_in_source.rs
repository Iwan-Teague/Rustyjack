use std::env;
use std::fs;
use std::path::Path;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "ci",
    "target",
    "target-32",
    "prebuilt",
    "node_modules",
    "vendor",
    "tmp",
    "wordlists",
    "img",
    "patched_analysis_docs",
    "docs",
    "DNSSpoof",
];

fn main() {
    if let Err(err) = run() {
        eprintln!("no_emoji_in_source: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let mut violations = Vec::new();
    scan_dir(&root, &mut violations)?;
    if !violations.is_empty() {
        eprintln!("no_emoji_in_source: found emoji/non-ASCII glyphs:");
        for v in &violations {
            eprintln!("{v}");
        }
        return Err(format!("{} file(s) contain emoji", violations.len()));
    }
    println!("no_emoji_in_source: OK");
    Ok(())
}

fn scan_dir(dir: &Path, violations: &mut Vec<String>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            if should_skip(&path) {
                continue;
            }
            scan_dir(&path, violations)?;
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "rs" | "sh" | "toml") {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (idx, line) in content.lines().enumerate() {
            if has_emoji(line) {
                violations.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
            }
        }
    }
    Ok(())
}

fn should_skip(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|name| SKIP_DIRS.contains(&name))
        .unwrap_or(false)
}

fn has_emoji(line: &str) -> bool {
    for ch in line.chars() {
        // Check for common emoji ranges (skip normal ASCII and Latin-1)
        let cp = ch as u32;
        if cp >= 0x1F300 && cp <= 0x1FAFF {
            return true;
        }
        // Miscellaneous symbols and dingbats
        if cp >= 0x2600 && cp <= 0x27BF {
            return true;
        }
    }
    false
}
