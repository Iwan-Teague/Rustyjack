// This crate targets Linux only. Fail early on non-Linux targets to avoid
// platform-specific surprises (Windows/macOS users should not attempt to build
// or run Rusty-Jack components that operate on low-level network or system
// interfaces).
#[cfg(not(target_os = "linux"))]
compile_error!(
	"rustyjack-core is intended to be built on Linux only. Build with a Linux target (e.g. target_os = \"linux\") or develop on a Linux machine."
);

pub mod autopilot;
pub mod cli;
pub mod operations;
pub mod system;
pub mod wireless_native;

pub use cli::{
    Cli, Commands, OutputFormat, WifiCommand, WifiCrackArgs, WifiDeauthArgs, WifiEvilTwinArgs,
    WifiKarmaArgs, WifiPmkidArgs, WifiProbeSniffArgs, WifiScanArgs,
};
pub use operations::{dispatch_command, HandlerResult};
pub use system::{resolve_root, InterfaceSummary};
pub use wireless_native::{
    check_capabilities, execute_deauth_attack, execute_evil_twin, execute_karma,
    execute_pmkid_capture, execute_probe_sniff, is_wireless_interface, native_available,
    DeauthConfig, DeauthResult, EvilTwinAttackConfig, EvilTwinResult, KarmaAttackConfig,
    KarmaResult, PmkidCaptureConfig, PmkidResult, ProbeSniffConfig, ProbeSniffResult,
    WirelessCapabilities,
};
