use crate::error::{Result, WirelessError};

pub fn pkill_pattern(pattern: &str) -> Result<usize> {
    use rustyjack_netlink::process;
    process::pkill(pattern).map_err(|e| {
        WirelessError::System(format!(
            "Failed to kill processes matching '{}': {}",
            pattern, e
        ))
    })
}

pub fn pkill_pattern_force(pattern: &str) -> Result<usize> {
    use rustyjack_netlink::process;
    process::pkill_force(pattern).map_err(|e| {
        WirelessError::System(format!(
            "Failed to kill -9 processes matching '{}': {}",
            pattern, e
        ))
    })
}

#[allow(dead_code)]
pub fn pkill_exact(name: &str) -> Result<usize> {
    use rustyjack_netlink::process;
    process::pkill_exact(name)
        .map_err(|e| WirelessError::System(format!("Failed to kill process '{}': {}", name, e)))
}

#[allow(dead_code)]
pub fn pkill_exact_force(name: &str) -> Result<usize> {
    use rustyjack_netlink::process;
    process::pkill_exact_force(name)
        .map_err(|e| WirelessError::System(format!("Failed to kill -9 process '{}': {}", name, e)))
}

#[allow(dead_code)]
pub fn pgrep_pattern(pattern: &str) -> Result<Vec<i32>> {
    use rustyjack_netlink::process;
    process::pgrep(pattern).map_err(|e| {
        WirelessError::System(format!(
            "Failed to find processes matching '{}': {}",
            pattern, e
        ))
    })
}

#[allow(dead_code)]
pub fn process_running(pattern: &str) -> Result<bool> {
    use rustyjack_netlink::process;
    process::process_running(pattern).map_err(|e| {
        WirelessError::System(format!(
            "Failed to check if process '{}' is running: {}",
            pattern, e
        ))
    })
}
