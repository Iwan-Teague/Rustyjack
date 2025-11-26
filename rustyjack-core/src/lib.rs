// This crate targets Linux only. Fail early on non-Linux targets to avoid
// platform-specific surprises (Windows/macOS users should not attempt to build
// or run Rusty-Jack components that operate on low-level network or system
// interfaces).
#[cfg(not(target_os = "linux"))]
compile_error!(
	"rustyjack-core is intended to be built on Linux only. Build with a Linux target (e.g. target_os = \"linux\") or develop on a Linux machine."
);

pub mod cli;
pub mod operations;
pub mod system;
pub mod autopilot;
pub mod wireless_native;

pub use cli::{
    Cli, Commands, OutputFormat,
    WifiCommand, WifiEvilTwinArgs, WifiProbeSniffArgs, WifiPmkidArgs, WifiCrackArgs,
};
pub use operations::{HandlerResult, dispatch_command};
pub use system::{resolve_root, InterfaceSummary};
pub use wireless_native::{
    DeauthConfig, DeauthResult, WirelessCapabilities,
    check_capabilities, execute_deauth_attack, native_available,
    is_wireless_interface,
};
