fn set_env(key: &str, default: &str) {
    let value = std::env::var(key).unwrap_or_else(|_| default.to_string());
    println!("cargo:rustc-env={}={}", key, value);
}

fn main() {
    let keys = [
        ("RUSTYJACK_BUILD_EPOCH", "0"),
        ("RUSTYJACK_BUILD_ISO", "1970-01-01T00:00:00Z"),
        ("RUSTYJACK_GIT_HASH", "unknown"),
        ("RUSTYJACK_GIT_DIRTY", "0"),
        ("RUSTYJACK_BUILD_PROFILE", "unknown"),
        ("RUSTYJACK_BUILD_VARIANT", "unknown"),
        ("RUSTYJACK_BUILD_TARGET", "unknown"),
        ("RUSTYJACK_BUILD_ARCH", "unknown"),
    ];

    for (key, default) in keys {
        println!("cargo:rerun-if-env-changed={}", key);
        set_env(key, default);
    }
}
