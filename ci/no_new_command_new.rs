use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const NEEDLE: &str = "Command::new(";
const BASELINE_FILE: &str = "ci/command_new_baseline.txt";
const SKIP_DIRS: &[&str] = &[
    ".git",
    "ci",
    "target",
    "prebuilt",
    "node_modules",
    "vendor",
];

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let baseline = read_baseline(&root)?;
    let count = count_in_dir(&root)?;
    if count > baseline {
        return Err(format!(
            "Command::new usage increased: baseline={} current={}",
            baseline, count
        ));
    }
    println!(
        "Command::new usage OK: baseline={} current={}",
        baseline, count
    );
    Ok(())
}

fn read_baseline(root: &Path) -> Result<u64, String> {
    let path = root.join(BASELINE_FILE);
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("read baseline {}: {e}", path.display()))?;
    content
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("parse baseline {}: {e}", path.display()))
}

fn count_in_dir(dir: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("read dir {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            total += count_in_dir(&path)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            total += count_in_file(&path)?;
        }
    }
    Ok(total)
}

fn should_skip_dir(path: &PathBuf) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|name| SKIP_DIRS.contains(&name))
        .unwrap_or(false)
}

fn count_in_file(path: &Path) -> Result<u64, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("read file {}: {e}", path.display()))?;
    Ok(count_occurrences(&content, NEEDLE))
}

fn count_occurrences(haystack: &str, needle: &str) -> u64 {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0u64;
    let mut rest = haystack;
    while let Some(pos) = rest.find(needle) {
        count += 1;
        rest = &rest[pos + needle.len()..];
    }
    count
}
