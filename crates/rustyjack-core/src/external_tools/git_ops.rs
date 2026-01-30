use std::path::Path;

use anyhow::{Context, Result};
use git2::{Repository, ResetType};

pub fn git_reset_to_remote(root: &Path, remote: &str, branch: &str) -> Result<()> {
    let repo = Repository::open(root).context("opening git repository")?;
    let mut remote_ref = repo
        .find_remote(remote)
        .context("finding git remote")?;
    remote_ref
        .fetch(&[branch], None, None)
        .context("git fetch")?;
    let refname = format!("refs/remotes/{remote}/{branch}");
    let oid = repo.refname_to_id(&refname).context("resolving remote ref")?;
    let object = repo.find_object(oid, None).context("loading target commit")?;
    repo.reset(&object, ResetType::Hard, None)
        .context("git hard reset")?;

    Ok(())
}
