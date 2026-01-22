use anyhow::{anyhow, Result};
use std::process::{Child, Command, Output, Stdio};

pub fn run(program: &str, args: &[&str]) -> Result<Output> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| anyhow!("spawn {program} failed: {e}"))?;

    if !out.status.success() {
        return Err(anyhow!(
            "{program} failed (code={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    Ok(out)
}

pub fn run_allow_failure(program: &str, args: &[&str]) -> Result<Output> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|e| anyhow!("spawn {program} failed: {e}"))
}

pub fn run_with_env(program: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd.output().map_err(|e| anyhow!("spawn {program} failed: {e}"))?;

    if !out.status.success() {
        return Err(anyhow!(
            "{program} failed (code={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    Ok(out)
}

pub fn run_with_env_allow_failure(
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output()
        .map_err(|e| anyhow!("spawn {program} failed: {e}"))
}

pub fn spawn_piped(program: &str, args: &[&str]) -> Result<Child> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("spawn {program} failed: {e}"))
}
