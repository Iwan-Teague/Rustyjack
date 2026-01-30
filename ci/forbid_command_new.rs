use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("forbid_command_new: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let repo = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let allow: [PathBuf; 0] = [];

    let mut violations = Vec::new();
    visit_rs(&repo, &allow, &mut violations)?;

    if !violations.is_empty() {
        eprintln!("forbid_command_new: found forbidden Command usage:");
        for v in violations {
            eprintln!("{v}");
        }
        return Err("Command usage outside allowlist".to_string());
    }

    println!("forbid_command_new: OK");
    Ok(())
}

fn visit_rs(dir: &Path, allow: &[PathBuf], out: &mut Vec<String>) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            visit_rs(&path, allow, out)?;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !(text.contains("Command::new") || text.contains("std::process::Command")) {
            continue;
        }

        let allowed = allow.iter().any(|a| path.starts_with(a));
        if allowed {
            continue;
        }

        for (idx, line) in text.lines().enumerate() {
            if line.contains("Command::new") || line.contains("std::process::Command") {
                out.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
            }
        }
    }
    Ok(())
}

fn should_skip_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    matches!(
        name,
        ".git" | "ci" | "target" | "prebuilt" | "node_modules" | "vendor" | "tmp"
    )
}
