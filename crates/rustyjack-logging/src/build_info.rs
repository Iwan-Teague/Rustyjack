#[derive(Debug, Clone, Copy)]
pub struct BuildInfo {
    pub pkg_version: &'static str,
    pub build_epoch: &'static str,
    pub build_iso: &'static str,
    pub git_hash: &'static str,
    pub git_dirty: &'static str,
    pub build_profile: &'static str,
    pub build_variant: &'static str,
    pub build_target: &'static str,
    pub build_arch: &'static str,
}

pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_EPOCH: &str = env!("RUSTYJACK_BUILD_EPOCH");
pub const BUILD_ISO: &str = env!("RUSTYJACK_BUILD_ISO");
pub const GIT_HASH: &str = env!("RUSTYJACK_GIT_HASH");
pub const GIT_DIRTY: &str = env!("RUSTYJACK_GIT_DIRTY");
pub const BUILD_PROFILE: &str = env!("RUSTYJACK_BUILD_PROFILE");
pub const BUILD_VARIANT: &str = env!("RUSTYJACK_BUILD_VARIANT");
pub const BUILD_TARGET: &str = env!("RUSTYJACK_BUILD_TARGET");
pub const BUILD_ARCH: &str = env!("RUSTYJACK_BUILD_ARCH");

pub const BUILD_INFO: BuildInfo = BuildInfo {
    pkg_version: PKG_VERSION,
    build_epoch: BUILD_EPOCH,
    build_iso: BUILD_ISO,
    git_hash: GIT_HASH,
    git_dirty: GIT_DIRTY,
    build_profile: BUILD_PROFILE,
    build_variant: BUILD_VARIANT,
    build_target: BUILD_TARGET,
    build_arch: BUILD_ARCH,
};

pub fn build_info() -> BuildInfo {
    BUILD_INFO
}

pub fn git_dirty() -> bool {
    matches!(GIT_DIRTY, "1" | "true" | "yes" | "dirty")
}

pub fn version_string() -> String {
    let dirty = if git_dirty() { " dirty" } else { "" };
    format!(
        "{} (build {} {}, git {}{})",
        PKG_VERSION, BUILD_ISO, BUILD_EPOCH, GIT_HASH, dirty
    )
}

#[used]
#[no_mangle]
pub static RUSTYJACK_BUILD_INFO: &str = concat!(
    "rustyjack_build_info:",
    "version=", env!("CARGO_PKG_VERSION"),
    ";build_epoch=", env!("RUSTYJACK_BUILD_EPOCH"),
    ";build_iso=", env!("RUSTYJACK_BUILD_ISO"),
    ";git_hash=", env!("RUSTYJACK_GIT_HASH"),
    ";git_dirty=", env!("RUSTYJACK_GIT_DIRTY"),
    ";build_profile=", env!("RUSTYJACK_BUILD_PROFILE"),
    ";build_variant=", env!("RUSTYJACK_BUILD_VARIANT"),
    ";build_target=", env!("RUSTYJACK_BUILD_TARGET"),
    ";build_arch=", env!("RUSTYJACK_BUILD_ARCH")
);
