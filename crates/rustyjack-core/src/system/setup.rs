use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const FALLBACK_COUNTRY: &str = "IE";

#[derive(Debug, Clone)]
pub struct HostSetupOutcome {
    pub regdom: RegdomSetupOutcome,
    pub sysctl: SysctlSetupOutcome,
}

#[derive(Debug, Clone)]
pub struct RegdomSetupOutcome {
    pub country: String,
    pub source: String,
    pub fallback_used: bool,
    pub cfg80211_path: String,
    pub cmdline_checked: Vec<String>,
    pub cmdline_updated: Vec<String>,
    pub cmdline_missing: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SysctlSetupOutcome {
    pub config_path: String,
    pub runtime_applied: bool,
    pub runtime_errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct CountryDetection {
    country: String,
    source: String,
    fallback_used: bool,
}

pub fn configure_host(country_override: Option<&str>) -> Result<HostSetupOutcome> {
    ensure_root()?;
    let detection = detect_country(country_override);
    let regdom = configure_regdom(&detection)?;
    let sysctl = configure_forwarding_sysctl()?;
    Ok(HostSetupOutcome { regdom, sysctl })
}

fn ensure_root() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            bail!("Rustyjack system setup must run as root (uid 0)");
        }
    }
    Ok(())
}

fn detect_country(country_override: Option<&str>) -> CountryDetection {
    if let Some(raw) = country_override {
        if let Some(code) = normalize_country(raw) {
            return CountryDetection {
                country: code,
                source: "cli_override".to_string(),
                fallback_used: false,
            };
        }
    }

    if let Ok(raw) = env::var("RUSTYJACK_COUNTRY") {
        if let Some(code) = normalize_country(&raw) {
            return CountryDetection {
                country: code,
                source: "env:RUSTYJACK_COUNTRY".to_string(),
                fallback_used: false,
            };
        }
    }

    if let Some(code) = read_country_from_wpa_supplicant() {
        return CountryDetection {
            country: code,
            source: "wpa_supplicant.conf".to_string(),
            fallback_used: false,
        };
    }

    if let Some(code) = read_country_from_locale() {
        return CountryDetection {
            country: code,
            source: "locale".to_string(),
            fallback_used: false,
        };
    }

    if let Some(code) = read_country_from_timezone() {
        return CountryDetection {
            country: code,
            source: "timezone".to_string(),
            fallback_used: false,
        };
    }

    CountryDetection {
        country: FALLBACK_COUNTRY.to_string(),
        source: "fallback".to_string(),
        fallback_used: true,
    }
}

fn normalize_country(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() != 2 {
        return None;
    }
    let mut upper = String::with_capacity(2);
    for ch in trimmed.chars() {
        if !ch.is_ascii_alphabetic() {
            return None;
        }
        upper.push(ch.to_ascii_uppercase());
    }
    Some(upper)
}

fn read_country_from_wpa_supplicant() -> Option<String> {
    let paths = [
        Path::new("/etc/rustyjack/wpa_supplicant.conf"),
        Path::new("/etc/wpa_supplicant/wpa_supplicant.conf"),
    ];
    for path in paths {
        if let Some(code) = read_country_from_wpa_path(path) {
            return Some(code);
        }
    }
    None
}

fn read_country_from_wpa_path(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("country=") {
            if let Some(code) = normalize_country(value) {
                return Some(code);
            }
        }
    }
    None
}

fn read_country_from_locale() -> Option<String> {
    let candidates = ["/etc/default/locale", "/etc/locale.conf"];
    for path in candidates.iter() {
        let path = Path::new(path);
        if let Some(code) = read_country_from_locale_file(path) {
            return Some(code);
        }
    }
    None
}

fn read_country_from_locale_file(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key == "LANG" || key == "LANGUAGE" || key == "LC_ALL" {
                if let Some(code) = extract_country_from_locale(value) {
                    return Some(code);
                }
            }
        }
    }
    None
}

fn extract_country_from_locale(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'');
    let lang_part = trimmed.split('.').next().unwrap_or(trimmed);
    let mut parts = lang_part.split('_');
    let _lang = parts.next()?;
    let country = parts.next()?;
    normalize_country(country)
}

fn read_country_from_timezone() -> Option<String> {
    let tz = fs::read_to_string("/etc/timezone").ok()?;
    country_from_timezone(tz.trim())
}

fn country_from_timezone(tz: &str) -> Option<String> {
    let tz = tz.trim();
    if tz.is_empty() {
        return None;
    }
    match tz.to_ascii_lowercase().as_str() {
        "europe/dublin" => Some("IE".to_string()),
        "europe/london" => Some("GB".to_string()),
        "europe/berlin" => Some("DE".to_string()),
        "europe/paris" => Some("FR".to_string()),
        "america/new_york" => Some("US".to_string()),
        "america/chicago" => Some("US".to_string()),
        "america/los_angeles" => Some("US".to_string()),
        "america/toronto" => Some("CA".to_string()),
        "australia/sydney" => Some("AU".to_string()),
        "asia/tokyo" => Some("JP".to_string()),
        _ => None,
    }
}

fn configure_regdom(detection: &CountryDetection) -> Result<RegdomSetupOutcome> {
    let cfg_path = Path::new("/etc/modprobe.d/cfg80211.conf");
    let cfg_contents = format!(
        "# Managed by Rustyjack\noptions cfg80211 ieee80211_regdom={}\n",
        detection.country
    );
    write_atomic(cfg_path, &cfg_contents, 0o644)
        .with_context(|| format!("writing {}", cfg_path.display()))?;

    let cmdline_candidates = ["/boot/firmware/cmdline.txt", "/boot/cmdline.txt"];
    let mut cmdline_checked = Vec::new();
    let mut cmdline_updated = Vec::new();
    let mut cmdline_missing = Vec::new();

    for candidate in cmdline_candidates.iter() {
        let path = Path::new(candidate);
        if path.exists() {
            cmdline_checked.push(path.display().to_string());
            if update_cmdline(path, &detection.country)? {
                cmdline_updated.push(path.display().to_string());
            }
        } else {
            cmdline_missing.push(path.display().to_string());
        }
    }

    Ok(RegdomSetupOutcome {
        country: detection.country.clone(),
        source: detection.source.clone(),
        fallback_used: detection.fallback_used,
        cfg80211_path: cfg_path.display().to_string(),
        cmdline_checked,
        cmdline_updated,
        cmdline_missing,
    })
}

fn update_cmdline(path: &Path, country: &str) -> Result<bool> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut parts: Vec<String> = contents.split_whitespace().map(|s| s.to_string()).collect();
    let key = "cfg80211.ieee80211_regdom=";
    let desired = format!("{key}{country}");
    let mut found = false;
    let mut changed = false;

    for part in parts.iter_mut() {
        if part.starts_with(key) {
            found = true;
            if *part != desired {
                *part = desired.clone();
                changed = true;
            }
        }
    }

    if !found {
        parts.push(desired);
        changed = true;
    }

    if changed {
        let new_contents = format!("{}\n", parts.join(" "));
        write_atomic(path, &new_contents, 0o644)
            .with_context(|| format!("updating {}", path.display()))?;
    }

    Ok(changed)
}

fn configure_forwarding_sysctl() -> Result<SysctlSetupOutcome> {
    let path = Path::new("/etc/sysctl.d/99-rustyjack.conf");
    let contents =
        "# Managed by Rustyjack\nnet.ipv4.ip_forward=1\nnet.ipv4.conf.all.forwarding=1\n";
    write_atomic(path, contents, 0o644).with_context(|| format!("writing {}", path.display()))?;

    let mut runtime_errors = Vec::new();
    let mut runtime_applied = true;

    if let Err(err) = apply_sysctl_runtime("/proc/sys/net/ipv4/ip_forward", "1") {
        runtime_errors.push(err);
        runtime_applied = false;
    }
    if let Err(err) = apply_sysctl_runtime("/proc/sys/net/ipv4/conf/all/forwarding", "1") {
        runtime_errors.push(err);
        runtime_applied = false;
    }

    Ok(SysctlSetupOutcome {
        config_path: path.display().to_string(),
        runtime_applied,
        runtime_errors,
    })
}

fn apply_sysctl_runtime(path: &str, desired: &str) -> Result<(), String> {
    if let Ok(current) = fs::read_to_string(path) {
        if current.trim() == desired {
            return Ok(());
        }
    }

    fs::write(path, format!("{desired}\n")).map_err(|e| format!("{}: {}", path, e))?;
    Ok(())
}

fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing parent for {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let tmp_path = temp_path_for(path);
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("opening {}", tmp_path.display()))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp_path.display()))?;
    }

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(mode);
        fs::set_permissions(&tmp_path, perms)
            .with_context(|| format!("setting permissions on {}", tmp_path.display()))?;
    }

    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}
