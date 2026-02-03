use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use rustyjack_install::atomic_write;

const SYSUSERS_CANDIDATES: &[&str] = &[
    "/usr/bin/systemd-sysusers",
    "/bin/systemd-sysusers",
    "/usr/sbin/systemd-sysusers",
    "/sbin/systemd-sysusers",
];

fn main() -> Result<()> {
    let content = "\
# Socket access group (daemon)
g rustyjack -

# UI user+group
g rustyjack-ui -
u rustyjack-ui - \"RustyJack UI\" - -
m rustyjack-ui rustyjack

# Portal user+group
g rustyjack-portal -
u rustyjack-portal - \"RustyJack Portal\" - -
m rustyjack-portal rustyjack
";
    let path = Path::new("/etc/sysusers.d/rustyjack.conf");
    atomic_write(path, content.as_bytes(), 0o644)
        .with_context(|| format!("write {}", path.display()))?;
    apply_sysusers(path)?;
    Ok(())
}

fn apply_sysusers(config_path: &Path) -> Result<()> {
    let sysusers = find_sysusers_binary()?;
    if !config_path.is_absolute() {
        bail!(
            "sysusers config path must be absolute: {}",
            config_path.display()
        );
    }
    if !config_path.is_file() {
        bail!("sysusers config missing: {}", config_path.display());
    }

    let mut cmd = Command::new(&sysusers);
    cmd.arg(config_path);
    cmd.env_clear();
    cmd.env("LANG", "C");
    cmd.env("LC_ALL", "C");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    run_with_timeout(cmd, Duration::from_secs(5))
        .with_context(|| format!("running {}", sysusers.display()))
}

fn find_sysusers_binary() -> Result<PathBuf> {
    for candidate in SYSUSERS_CANDIDATES {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!(
        "systemd-sysusers not found (checked: {})",
        SYSUSERS_CANDIDATES.join(", ")
    )
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<()> {
    let mut child = cmd.spawn().context("spawn command")?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("poll command")? {
            if status.success() {
                return Ok(());
            }
            bail!("command exited with status {}", status);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            bail!("command timed out after {:?}", timeout);
        }
        thread::sleep(Duration::from_millis(50));
    }
}
