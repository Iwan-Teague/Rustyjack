use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use rustyjack_install::{atomic_copy, atomic_write};

const APPLIANCE_BINS: &[&str] = &["rustyjackd", "rustyjack-ui", "rustyjack-portal"];
const WPA_CONF_PATH: &str = "/etc/rustyjack/wpa_supplicant.conf";

fn main() -> Result<()> {
    let src_root = env::var("RUSTYJACK_INSTALL_SRC")
        .map(PathBuf::from)
        .unwrap_or(env::current_dir().context("read current dir")?);
    let bin_dir = env::var("RUSTYJACK_INSTALL_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| src_root.clone());
    let services_dir = src_root.join("services");
    let socket_src = src_root.join("rustyjackd.socket");

    let workspace_bins = discover_workspace_bins(&src_root)?;
    ensure_expected_bins_in_workspace(&workspace_bins)?;
    ensure_expected_bins_present(&bin_dir)?;

    for bin in APPLIANCE_BINS {
        install_bin(&bin_dir, bin, true)?;
    }

    install_unit(
        &services_dir.join("rustyjackd.service"),
        Path::new("/etc/systemd/system/rustyjackd.service"),
        true,
    )?;
    install_unit(
        &services_dir.join("rustyjack-ui.service"),
        Path::new("/etc/systemd/system/rustyjack-ui.service"),
        true,
    )?;
    install_unit(
        &services_dir.join("rustyjack-portal.service"),
        Path::new("/etc/systemd/system/rustyjack-portal.service"),
        true,
    )?;
    install_wpa_unit(
        &services_dir.join("rustyjack-wpa_supplicant@.service"),
        Path::new("/etc/systemd/system/rustyjack-wpa_supplicant@.service"),
    )?;
    install_unit(
        &socket_src,
        Path::new("/etc/systemd/system/rustyjackd.socket"),
        true,
    )?;

    Ok(())
}

fn ensure_expected_bins_in_workspace(workspace_bins: &BTreeSet<String>) -> Result<()> {
    let mut missing = Vec::new();
    for bin in APPLIANCE_BINS {
        if !workspace_bins.contains(*bin) {
            missing.push(bin.to_string());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "workspace manifest missing expected appliance binaries: {}",
        missing.join(", ")
    );
}

fn ensure_expected_bins_present(bin_dir: &Path) -> Result<()> {
    let mut missing = Vec::new();
    for bin in APPLIANCE_BINS {
        let path = bin_dir.join(bin);
        if !path.is_file() {
            missing.push(path.display().to_string());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "missing appliance binaries in {}: {}",
        bin_dir.display(),
        missing.join(", ")
    );
}

fn install_bin(bin_dir: &Path, name: &str, required: bool) -> Result<()> {
    let src = bin_dir.join(name);
    if !src.exists() {
        if required {
            bail!("missing binary {}", src.display());
        }
        return Ok(());
    }
    let dest = Path::new("/usr/local/bin").join(name);
    atomic_copy(&src, &dest, 0o755).with_context(|| format!("install {}", name))?;
    Ok(())
}

fn install_unit(src: &Path, dest: &Path, required: bool) -> Result<()> {
    if !src.exists() {
        if required {
            bail!("missing unit {}", src.display());
        }
        return Ok(());
    }
    atomic_copy(src, dest, 0o644).with_context(|| format!("install {}", dest.display()))?;
    Ok(())
}

fn install_wpa_unit(src: &Path, dest: &Path) -> Result<()> {
    if !src.exists() {
        bail!("missing unit {}", src.display());
    }
    let template = fs::read_to_string(src).with_context(|| format!("read {}", src.display()))?;
    let wpa_path = resolve_wpa_supplicant_path()?;
    let rendered = rewrite_wpa_execstart(&template, &wpa_path)?;
    atomic_write(dest, rendered.as_bytes(), 0o644)
        .with_context(|| format!("install {}", dest.display()))?;
    Ok(())
}

fn resolve_wpa_supplicant_path() -> Result<PathBuf> {
    if let Ok(raw) = env::var("RUSTYJACK_WPA_SUPPLICANT_BIN") {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Ok(path);
        }
        bail!("RUSTYJACK_WPA_SUPPLICANT_BIN not found: {}", path.display());
    }

    let candidates = [
        "/usr/sbin/wpa_supplicant",
        "/sbin/wpa_supplicant",
        "/usr/local/sbin/wpa_supplicant",
    ];
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }

    bail!(
        "wpa_supplicant not found (checked: {}); install wpa_supplicant or set RUSTYJACK_WPA_SUPPLICANT_BIN",
        candidates.join(", ")
    )
}

fn rewrite_wpa_execstart(template: &str, wpa_path: &Path) -> Result<String> {
    let mut replaced = false;
    let mut output = String::with_capacity(template.len() + 64);
    for line in template.lines() {
        if line.starts_with("ExecStart=") {
            let exec = format!(
                "ExecStart={} -u -s -i %i -D nl80211 -c {}",
                wpa_path.display(),
                WPA_CONF_PATH
            );
            output.push_str(&exec);
            output.push('\n');
            replaced = true;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if !replaced {
        bail!("wpa_supplicant unit template missing ExecStart=");
    }
    Ok(output)
}

fn discover_workspace_bins(src_root: &Path) -> Result<BTreeSet<String>> {
    let manifest_path = src_root.join("Cargo.toml");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let members = parse_workspace_members(&raw)
        .ok_or_else(|| anyhow!("workspace.members missing in {}", manifest_path.display()))?;

    let mut bins = BTreeSet::new();
    for member in members {
        let member_dir = src_root.join(member);
        bins.extend(discover_member_bins(&member_dir)?);
    }
    Ok(bins)
}

fn discover_member_bins(member_dir: &Path) -> Result<BTreeSet<String>> {
    let manifest_path = member_dir.join("Cargo.toml");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let package_name = parse_package_name(&raw)
        .ok_or_else(|| anyhow!("package.name missing in {}", manifest_path.display()))?;

    let mut bins = BTreeSet::new();
    for entry in parse_bin_entries(&raw) {
        let name = entry
            .name
            .or_else(|| {
                entry
                    .path
                    .as_ref()
                    .and_then(|value| Path::new(value).file_stem())
                    .and_then(|stem| stem.to_str())
                    .map(|stem| stem.to_string())
            })
            .unwrap_or_else(|| package_name.clone());
        bins.insert(name);
    }

    let src_bin_dir = member_dir.join("src").join("bin");
    if src_bin_dir.is_dir() {
        for entry in
            fs::read_dir(&src_bin_dir).with_context(|| format!("read {}", src_bin_dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("read entry in {}", src_bin_dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                bins.insert(stem.to_string());
            }
        }
    }

    if member_dir.join("src").join("main.rs").is_file() {
        bins.insert(package_name);
    }

    Ok(bins)
}

#[derive(Debug, Default)]
struct BinEntry {
    name: Option<String>,
    path: Option<String>,
}

fn parse_workspace_members(raw: &str) -> Option<Vec<String>> {
    let mut in_workspace = false;
    let mut collecting = false;
    let mut buffer = String::new();

    for line in raw.lines() {
        let trimmed = strip_comment(line).trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            in_workspace = trimmed == "[workspace]";
            collecting = false;
            continue;
        }
        if !in_workspace {
            continue;
        }
        if collecting {
            buffer.push_str(trimmed);
            buffer.push(' ');
            if trimmed.contains(']') {
                break;
            }
            continue;
        }
        if trimmed.starts_with("members") {
            let (_, rest) = trimmed.split_once('=')?;
            buffer.push_str(rest.trim());
            buffer.push(' ');
            if rest.contains(']') {
                break;
            }
            collecting = true;
        }
    }

    if buffer.is_empty() {
        return None;
    }
    let members = extract_string_literals(&buffer);
    if members.is_empty() {
        return None;
    }
    Some(members)
}

fn parse_package_name(raw: &str) -> Option<String> {
    let mut in_package = false;
    for line in raw.lines() {
        let trimmed = strip_comment(line).trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(value) = parse_string_assignment(trimmed, "name") {
            return Some(value);
        }
    }
    None
}

fn parse_bin_entries(raw: &str) -> Vec<BinEntry> {
    let mut entries = Vec::new();
    let mut current: Option<BinEntry> = None;
    let mut in_bin = false;

    for line in raw.lines() {
        let trimmed = strip_comment(line).trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("[[bin]]") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = Some(BinEntry::default());
            in_bin = true;
            continue;
        }
        if trimmed.starts_with('[') {
            if in_bin {
                if let Some(entry) = current.take() {
                    entries.push(entry);
                }
            }
            in_bin = false;
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(value) = parse_string_assignment(trimmed, "name") {
            if let Some(ref mut entry) = current {
                entry.name = Some(value);
            }
        }
        if let Some(value) = parse_string_assignment(trimmed, "path") {
            if let Some(ref mut entry) = current {
                entry.path = Some(value);
            }
        }
    }

    if let Some(entry) = current.take() {
        entries.push(entry);
    }

    entries
}

fn parse_string_assignment(line: &str, key: &str) -> Option<String> {
    if !line.starts_with(key) {
        return None;
    }
    let (_, rest) = line.split_once('=')?;
    parse_quoted_string(rest.trim())
}

fn parse_quoted_string(raw: &str) -> Option<String> {
    let mut chars = raw.chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => break,
            _ => out.push(ch),
        }
    }
    Some(out)
}

fn extract_string_literals(raw: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        while let Some(next) = chars.next() {
            if escaped {
                value.push(next);
                escaped = false;
                continue;
            }
            match next {
                '\\' => escaped = true,
                '"' => break,
                _ => value.push(next),
            }
        }
        if !value.is_empty() {
            items.push(value);
        }
    }
    items
}

fn strip_comment(line: &str) -> &str {
    line.splitn(2, '#').next().unwrap_or(line)
}
