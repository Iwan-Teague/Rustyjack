use anyhow::Result;
use std::path::Path;

use rustyjack_install::atomic_write;

fn main() -> Result<()> {
    let content = "\
g rustyjack -
u rustyjack-ui - \"RustyJack UI\" - -
m rustyjack-ui rustyjack
";
    let path = Path::new("/etc/sysusers.d/rustyjack.conf");
    atomic_write(path, content.as_bytes(), 0o644)?;
    Ok(())
}
