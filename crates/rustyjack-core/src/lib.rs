#![deny(unsafe_op_in_unsafe_fn)]
// This crate targets Linux only. Fail early on non-Linux targets to avoid
// platform-specific surprises (Windows/macOS users should not attempt to build
// or run Rusty-Jack components that operate on low-level network or system
// interfaces).
#[cfg(not(target_os = "linux"))]
compile_error!(
	"rustyjack-core is intended to be built on Linux only. Build with a Linux target (e.g. target_os = \"linux\") or develop on a Linux machine."
);

// Production guardrail: forbid lab/external tooling features in release builds.
#[cfg(all(
    not(debug_assertions),
    any(
        feature = "lab",
        feature = "external_tools",
        feature = "dev_tools",
        feature = "offensive_tools"
    )
))]
compile_error!(
    "rustyjack-core: lab/dev/offensive/external_tools features are not allowed in release builds. Use the default appliance build for production."
);

pub mod mount;
pub mod mutation_guard;

pub mod arp_helpers;
pub mod audit;
pub mod cancel;
pub mod cli;
pub mod dhcp_helpers;
pub mod dns_helpers;
pub mod netlink_helpers;
pub mod operations;
pub mod redact;
pub mod runtime;
pub mod services;
pub mod system;
pub mod wireless_native;

#[cfg(feature = "external_tools")]
pub mod external_tools;

// Re-export encryption helpers from dedicated crate.
pub use rustyjack_encryption as crypto;

pub use cli::{
    Cli, Commands, OutputFormat, WifiCommand, WifiCrackArgs, WifiDeauthArgs, WifiEvilTwinArgs,
    WifiKarmaArgs, WifiPmkidArgs, WifiProbeSniffArgs, WifiScanArgs,
};
pub use operations::{
    dispatch_command, dispatch_command_with_cancel, is_cancelled_error, HandlerResult,
};
pub use rustyjack_evasion::{logs_disabled, logs_enabled};
pub use system::{
    apply_interface_isolation, enforce_single_interface, ensure_default_wifi_profiles,
    ensure_route_no_isolation, interface_gateway, is_wireless_interface, preferred_interface,
    resolve_root, rfkill_index_for_interface, route_interface, InterfaceSummary,
};
pub use wireless_native::{
    check_capabilities, execute_deauth_attack, execute_evil_twin, execute_karma,
    execute_pmkid_capture, execute_probe_sniff, native_available, DeauthConfig, DeauthResult,
    EvilTwinAttackConfig, EvilTwinResult, KarmaAttackConfig, KarmaResult, PmkidCaptureConfig,
    PmkidResult, ProbeSniffConfig, ProbeSniffResult, WirelessCapabilities,
};
