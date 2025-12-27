// This crate targets Linux only. Fail early on non-Linux targets to avoid
// platform-specific surprises (Windows/macOS users should not attempt to build
// or run Rusty-Jack components that operate on low-level network or system
// interfaces).
#[cfg(not(target_os = "linux"))]
compile_error!(
	"rustyjack-core is intended to be built on Linux only. Build with a Linux target (e.g. target_os = \"linux\") or develop on a Linux machine."
);

pub mod anti_forensics;

pub mod arp_helpers;
pub mod cli;
pub mod dhcp_helpers;
pub mod dns_helpers;
pub mod netlink_helpers;
pub mod operations;
pub mod system;
pub mod wireless_native;

pub mod evasion;
pub mod physical_access;

// Re-export encryption helpers from dedicated crate.
pub use rustyjack_encryption as crypto;

pub use cli::{
    Cli, Commands, OutputFormat, WifiCommand, WifiCrackArgs, WifiDeauthArgs, WifiEvilTwinArgs,
    WifiKarmaArgs, WifiPmkidArgs, WifiProbeSniffArgs, WifiScanArgs,
};
pub use operations::{dispatch_command, HandlerResult};
pub use rustyjack_evasion::{logs_disabled, logs_enabled};
pub use system::{
    apply_interface_isolation, enforce_single_interface, ensure_default_wifi_profiles,
    ensure_route_no_isolation, is_wireless_interface, resolve_root, rfkill_index_for_interface,
    InterfaceSummary,
};
pub use wireless_native::{
    check_capabilities, execute_deauth_attack, execute_evil_twin, execute_karma,
    execute_pmkid_capture, execute_probe_sniff, native_available, DeauthConfig, DeauthResult,
    EvilTwinAttackConfig, EvilTwinResult, KarmaAttackConfig, KarmaResult, PmkidCaptureConfig,
    PmkidResult, ProbeSniffConfig, ProbeSniffResult, WirelessCapabilities,
};
