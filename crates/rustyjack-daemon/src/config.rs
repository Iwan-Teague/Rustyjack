use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use rustyjack_ipc::MAX_FRAME;
use rustyjack_updater::parse_public_key_hex;

use crate::ops::OpsConfig;

pub const DEFAULT_SOCKET_PATH: &str = "/run/rustyjack/rustyjackd.sock";
pub const DEFAULT_JOB_RETENTION: usize = 200;
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 5000;
pub const DEFAULT_WRITE_TIMEOUT_MS: u64 = 5000;
pub const DEFAULT_ADMIN_GROUP: &str = "rustyjack-admin";
pub const DEFAULT_OPERATOR_GROUP: &str = "rustyjack";
pub const DEFAULT_ROOT_PATH: &str = "/opt/rustyjack";
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;
pub const DEFAULT_MAX_REQUESTS_PER_SECOND: u32 = 20;
pub const DEFAULT_UPDATE_PUBKEY_PATH: &str = "/etc/rustyjack/update_pubkey.ed25519";
pub const OPS_OVERRIDE_FILENAME: &str = "ops_override.json";

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub max_frame: u32,
    pub allow_core_dispatch: bool,
    pub job_retention: usize,
    pub socket_group: Option<String>,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub admin_group: String,
    pub operator_group: String,
    pub root_path: PathBuf,
    pub network_manager_integration: bool,
    pub max_connections: usize,
    pub max_requests_per_second: u32,
    pub ops: OpsConfig,
    pub update_pubkey: Option<[u8; 32]>,
    pub update_pubkey_path: PathBuf,
}

impl DaemonConfig {
    pub fn from_env() -> Self {
        let socket_path = env::var("RUSTYJACKD_SOCKET")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
        let max_frame = env::var("RUSTYJACKD_MAX_FRAME")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(MAX_FRAME);
        let allow_core_dispatch =
            cfg!(feature = "core_dispatch") && env_bool("RUSTYJACKD_ALLOW_CORE_DISPATCH", false);
        let job_retention = env::var("RUSTYJACKD_JOB_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_JOB_RETENTION);
        let socket_group = env::var("RUSTYJACKD_SOCKET_GROUP").ok();
        let read_timeout_ms = env::var("RUSTYJACKD_READ_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_READ_TIMEOUT_MS);
        let write_timeout_ms = env::var("RUSTYJACKD_WRITE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_WRITE_TIMEOUT_MS);
        let admin_group =
            env::var("RUSTYJACKD_ADMIN_GROUP").unwrap_or_else(|_| DEFAULT_ADMIN_GROUP.to_string());
        let operator_group = env::var("RUSTYJACKD_OPERATOR_GROUP")
            .unwrap_or_else(|_| DEFAULT_OPERATOR_GROUP.to_string());
        let root_path = env::var("RUSTYJACK_ROOT")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT_PATH));
        let network_manager_integration = env::var("RUSTYJACKD_NM_INTEGRATION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let max_connections = env::var("RUSTYJACKD_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_CONNECTIONS);
        let max_requests_per_second = env::var("RUSTYJACKD_MAX_REQUESTS_PER_SECOND")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_MAX_REQUESTS_PER_SECOND);

        let profile = env::var("RUSTYJACKD_OPS_PROFILE").unwrap_or_else(|_| "appliance".into());
        let mut ops = match profile.as_str() {
            "dev" => OpsConfig {
                wifi_ops: true,
                eth_ops: true,
                hotspot_ops: true,
                portal_ops: true,
                storage_ops: true,
                power_ops: true,
                system_ops: true,
                update_ops: true,
                dev_ops: true,
                offensive_ops: true,
                loot_ops: true,
                process_ops: true,
            },
            _ => OpsConfig::appliance_defaults(),
        };

        if let Some(list) = env_list("RUSTYJACKD_OPS") {
            ops = OpsConfig {
                wifi_ops: false,
                eth_ops: false,
                hotspot_ops: false,
                portal_ops: false,
                storage_ops: false,
                power_ops: false,
                system_ops: false,
                update_ops: false,
                dev_ops: false,
                offensive_ops: false,
                loot_ops: false,
                process_ops: false,
            };

            for item in list {
                match item.as_str() {
                    "wifi" => ops.wifi_ops = true,
                    "eth" | "ethernet" => ops.eth_ops = true,
                    "hotspot" => ops.hotspot_ops = true,
                    "portal" => ops.portal_ops = true,
                    "storage" | "mount" => ops.storage_ops = true,
                    "power" => ops.power_ops = true,
                    "system" => ops.system_ops = true,
                    "update" => ops.update_ops = true,
                    "dev" => ops.dev_ops = true,
                    "offensive" => ops.offensive_ops = true,
                    "loot" => ops.loot_ops = true,
                    "process" => ops.process_ops = true,
                    _ => {}
                }
            }
        }

        ops.wifi_ops = env_bool("RUSTYJACKD_OPS_WIFI", ops.wifi_ops);
        ops.eth_ops = env_bool("RUSTYJACKD_OPS_ETH", ops.eth_ops);
        ops.hotspot_ops = env_bool("RUSTYJACKD_OPS_HOTSPOT", ops.hotspot_ops);
        ops.portal_ops = env_bool("RUSTYJACKD_OPS_PORTAL", ops.portal_ops);
        ops.storage_ops = env_bool("RUSTYJACKD_OPS_STORAGE", ops.storage_ops);
        ops.power_ops = env_bool("RUSTYJACKD_OPS_POWER", ops.power_ops);
        ops.system_ops = env_bool("RUSTYJACKD_OPS_SYSTEM", ops.system_ops);
        ops.update_ops = env_bool("RUSTYJACKD_OPS_UPDATE", ops.update_ops);
        ops.dev_ops = env_bool("RUSTYJACKD_OPS_DEV", ops.dev_ops);
        ops.offensive_ops = env_bool("RUSTYJACKD_OPS_OFFENSIVE", ops.offensive_ops);
        ops.loot_ops = env_bool("RUSTYJACKD_OPS_LOOT", ops.loot_ops);
        ops.process_ops = env_bool("RUSTYJACKD_OPS_PROCESS", ops.process_ops);

        if let Some(override_ops) = load_ops_override(&root_path) {
            ops = override_ops;
        }

        let (update_pubkey, update_pubkey_path) = load_update_pubkey();

        Self {
            socket_path,
            max_frame,
            allow_core_dispatch,
            job_retention,
            socket_group,
            read_timeout: Duration::from_millis(read_timeout_ms),
            write_timeout: Duration::from_millis(write_timeout_ms),
            admin_group,
            operator_group,
            root_path,
            network_manager_integration,
            max_connections,
            max_requests_per_second,
            ops,
            update_pubkey,
            update_pubkey_path,
        }
    }
}

fn load_update_pubkey() -> (Option<[u8; 32]>, PathBuf) {
    let path = env::var("RUSTYJACKD_UPDATE_PUBKEY_FILE")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_UPDATE_PUBKEY_PATH));

    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) => return (None, path),
    };

    match parse_public_key_hex(text.trim()) {
        Ok(key) => (Some(key), path),
        Err(_) => (None, path),
    }
}

fn load_ops_override(root: &PathBuf) -> Option<OpsConfig> {
    let path = root.join(OPS_OVERRIDE_FILENAME);
    if !path.exists() {
        return None;
    }
    let text = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(default)
}

fn env_list(key: &str) -> Option<Vec<String>> {
    std::env::var(key).ok().map(|s| {
        s.split(',')
            .map(|x| x.trim().to_ascii_lowercase())
            .filter(|x| !x.is_empty())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        vars: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self { vars: Vec::new() }
        }

        fn set(&mut self, key: &str, value: &str) {
            if !self.vars.iter().any(|(k, _)| k == key) {
                self.vars.push((key.to_string(), std::env::var(key).ok()));
            }
            std::env::set_var(key, value);
        }

        fn remove(&mut self, key: &str) {
            if !self.vars.iter().any(|(k, _)| k == key) {
                self.vars.push((key.to_string(), std::env::var(key).ok()));
            }
            std::env::remove_var(key);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.vars.drain(..) {
                match value {
                    Some(val) => std::env::set_var(&key, val),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }

    #[test]
    fn test_ops_profile_appliance_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        let mut guard = EnvGuard::new();
        guard.set("RUSTYJACKD_OPS_PROFILE", "appliance");
        guard.remove("RUSTYJACKD_OPS");
        for key in [
            "RUSTYJACKD_OPS_WIFI",
            "RUSTYJACKD_OPS_ETH",
            "RUSTYJACKD_OPS_HOTSPOT",
            "RUSTYJACKD_OPS_PORTAL",
            "RUSTYJACKD_OPS_STORAGE",
            "RUSTYJACKD_OPS_SYSTEM",
            "RUSTYJACKD_OPS_UPDATE",
            "RUSTYJACKD_OPS_DEV",
            "RUSTYJACKD_OPS_OFFENSIVE",
            "RUSTYJACKD_OPS_LOOT",
            "RUSTYJACKD_OPS_PROCESS",
        ] {
            guard.remove(key);
        }

        let cfg = DaemonConfig::from_env();
        assert_eq!(cfg.ops, OpsConfig::appliance_defaults());
    }

    #[test]
    fn test_ops_allowlist_and_overrides() {
        let _lock = ENV_LOCK.lock().unwrap();
        let mut guard = EnvGuard::new();
        guard.set("RUSTYJACKD_OPS_PROFILE", "dev");
        guard.set("RUSTYJACKD_OPS", "wifi,portal");
        guard.set("RUSTYJACKD_OPS_WIFI", "false");
        guard.set("RUSTYJACKD_OPS_ETH", "true");

        let cfg = DaemonConfig::from_env();
        assert!(!cfg.ops.wifi_ops);
        assert!(cfg.ops.eth_ops);
        assert!(cfg.ops.portal_ops);
        assert!(!cfg.ops.hotspot_ops);
        assert!(!cfg.ops.storage_ops);
        assert!(!cfg.ops.system_ops);
        assert!(!cfg.ops.update_ops);
        assert!(!cfg.ops.dev_ops);
        assert!(!cfg.ops.offensive_ops);
        assert!(!cfg.ops.loot_ops);
        assert!(!cfg.ops.process_ops);
    }
}
