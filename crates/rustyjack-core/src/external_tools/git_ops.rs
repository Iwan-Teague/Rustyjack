use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::external_tools::system_shell;

pub fn git_reset_to_remote(root: &Path, remote: &str, branch: &str) -> Result<()> {
    let root_str = root
        .to_str()
        .ok_or_else(|| anyhow!("Root path must be valid UTF-8"))?;

    system_shell::run("git", &["-C", root_str, "fetch", remote])
        .context("git fetch")?;

    let target = format!("{remote}/{branch}");
    system_shell::run("git", &["-C", root_str, "reset", "--hard", target.as_str()])
        .context("git reset")?;

    Ok(())
}
