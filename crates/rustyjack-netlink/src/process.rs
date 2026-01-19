//! Process management via `/proc` filesystem.
//!
//! Pure Rust implementation of `pgrep` and `pkill` functionality without external commands.
//! Directly reads `/proc/[pid]` directories to find and signal processes.
//!
//! Supports exact name matching, pattern matching, and signal sending (SIGTERM, SIGKILL, custom).

use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("Failed to read /proc: {0}")]
    ProcRead(String),

    #[error("Failed to parse process info: {0}")]
    ParseError(String),

    #[error("Failed to signal process: {0}")]
    SignalError(String),

    #[error("Process not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, ProcessError>;

/// Process information from `/proc`.
///
/// Contains PID, process name (from `/proc/[pid]/comm`), and full command line (from `/proc/[pid]/cmdline`).
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: i32,
    /// Process name (truncated to 15 chars by kernel)
    pub name: String,
    /// Full command line with arguments
    pub cmdline: String,
}

/// Process manager for finding and signaling processes.
///
/// Provides `pgrep` and `pkill` functionality by directly reading `/proc` without shelling out.
///
/// # Examples
///
/// ```no_run
/// # use rustyjack_netlink::process::*;
/// # fn example() -> Result<()> {
/// let mgr = ProcessManager::new();
///
/// // Find all hostapd processes
/// let procs = mgr.find_by_name("hostapd")?;
/// for proc in procs {
///     println!("PID {}: {}", proc.pid, proc.cmdline);
/// }
///
/// // Kill all dnsmasq processes
/// let killed = mgr.kill_name_force("dnsmasq")?;
/// println!("Killed {} processes", killed);
/// # Ok(())
/// # }
/// ```
pub struct ProcessManager;

impl ProcessManager {
    /// Create a new process manager.
    pub fn new() -> Self {
        ProcessManager
    }

    /// Find all processes matching a pattern in their command line or name.
    ///
    /// Searches both process name (comm) and full command line (cmdline) for substring match.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Substring to search for (case-sensitive)
    ///
    /// # Errors
    ///
    /// * `ProcRead` - Cannot read /proc filesystem
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::process::*;
    /// # fn example() -> Result<()> {
    /// let mgr = ProcessManager::new();
    /// let procs = mgr.find_by_pattern("hostapd")?;
    /// for proc in procs {
    ///     println!("Found: {} ({})", proc.name, proc.pid);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn find_by_pattern(&self, pattern: &str) -> Result<Vec<ProcessInfo>> {
        if pattern.is_empty() {
            return Err(ProcessError::ParseError(
                "Pattern cannot be empty".to_string(),
            ));
        }

        let mut matches = Vec::new();

        let proc_dir = Path::new("/proc");
        if !proc_dir.exists() {
            return Err(ProcessError::ProcRead("/proc does not exist".to_string()));
        }

        let entries = fs::read_dir(proc_dir)
            .map_err(|e| ProcessError::ProcRead(format!("Cannot read /proc: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| ProcessError::ProcRead(e.to_string()))?;
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();

            // Only process numeric directories (PIDs)
            if let Ok(pid) = pid_str.parse::<i32>() {
                if let Ok(process) = self.read_process_info(pid) {
                    // Match against full command line
                    if process.cmdline.contains(pattern) || process.name.contains(pattern) {
                        matches.push(process);
                    }
                }
            }
        }

        Ok(matches)
    }

    /// Find processes by exact name match (from `/proc/[pid]/comm`).
    ///
    /// # Arguments
    ///
    /// * `name` - Exact process name (must match comm exactly, max 15 chars)
    ///
    /// # Errors
    ///
    /// * `ProcRead` - Cannot read /proc filesystem
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::process::*;
    /// # fn example() -> Result<()> {
    /// let mgr = ProcessManager::new();
    /// let procs = mgr.find_by_name("sshd")?;
    /// println!("Found {} sshd processes", procs.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn find_by_name(&self, name: &str) -> Result<Vec<ProcessInfo>> {
        if name.is_empty() {
            return Err(ProcessError::ParseError("Name cannot be empty".to_string()));
        }

        let mut matches = Vec::new();

        let proc_dir = Path::new("/proc");
        if !proc_dir.exists() {
            return Err(ProcessError::ProcRead("/proc does not exist".to_string()));
        }

        let entries = fs::read_dir(proc_dir)
            .map_err(|e| ProcessError::ProcRead(format!("Cannot read /proc: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| ProcessError::ProcRead(e.to_string()))?;
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();

            if let Ok(pid) = pid_str.parse::<i32>() {
                if let Ok(process) = self.read_process_info(pid) {
                    if process.name == name {
                        matches.push(process);
                    }
                }
            }
        }

        Ok(matches)
    }

    /// Check if any process matching the pattern exists.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Pattern to search for
    ///
    /// # Returns
    ///
    /// * `true` - At least one matching process found
    /// * `false` - No matching processes
    pub fn exists_pattern(&self, pattern: &str) -> Result<bool> {
        Ok(!self.find_by_pattern(pattern)?.is_empty())
    }

    /// Check if any process with exact name exists.
    ///
    /// # Arguments
    ///
    /// * `name` - Exact process name
    ///
    /// # Returns
    ///
    /// * `true` - At least one matching process found
    /// * `false` - No matching processes
    pub fn exists_name(&self, name: &str) -> Result<bool> {
        Ok(!self.find_by_name(name)?.is_empty())
    }

    /// Terminate processes matching a pattern with SIGTERM.
    ///
    /// Allows processes to clean up before exit.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Pattern to match
    ///
    /// # Returns
    ///
    /// Number of processes successfully signaled
    ///
    /// # Errors
    ///
    /// * `ProcRead` - Cannot read /proc
    pub fn kill_pattern(&self, pattern: &str) -> Result<usize> {
        self.signal_pattern(pattern, libc::SIGTERM)
    }

    /// Kill processes matching a pattern with SIGKILL (force).
    ///
    /// Immediately terminates processes without cleanup.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Pattern to match
    ///
    /// # Returns
    ///
    /// Number of processes successfully killed
    ///
    /// # Errors
    ///
    /// * `ProcRead` - Cannot read /proc
    pub fn kill_pattern_force(&self, pattern: &str) -> Result<usize> {
        self.signal_pattern(pattern, libc::SIGKILL)
    }

    /// Terminate processes by exact name with SIGTERM.
    ///
    /// # Arguments
    ///
    /// * `name` - Exact process name
    ///
    /// # Returns
    ///
    /// Number of processes successfully signaled
    pub fn kill_name(&self, name: &str) -> Result<usize> {
        self.signal_name(name, libc::SIGTERM)
    }

    /// Kill processes by exact name with SIGKILL (force).
    ///
    /// # Arguments
    ///
    /// * `name` - Exact process name
    ///
    /// # Returns
    ///
    /// Number of processes successfully killed
    pub fn kill_name_force(&self, name: &str) -> Result<usize> {
        self.signal_name(name, libc::SIGKILL)
    }

    /// Send a signal to all processes matching a pattern
    pub fn signal_pattern(&self, pattern: &str, signal: i32) -> Result<usize> {
        let processes = self.find_by_pattern(pattern)?;
        let mut killed = 0;

        for proc in processes {
            if self.signal_pid(proc.pid, signal).is_ok() {
                killed += 1;
                tracing::debug!("Signaled process {} ({}): {}", proc.pid, proc.name, pattern);
            }
        }

        Ok(killed)
    }

    /// Send a signal to all processes with exact name match
    pub fn signal_name(&self, name: &str, signal: i32) -> Result<usize> {
        let processes = self.find_by_name(name)?;
        let mut killed = 0;

        for proc in processes {
            if self.signal_pid(proc.pid, signal).is_ok() {
                killed += 1;
                tracing::debug!("Signaled process {} ({})", proc.pid, proc.name);
            }
        }

        Ok(killed)
    }

    /// Send a signal to a specific PID
    pub fn signal_pid(&self, pid: i32, signal: i32) -> Result<()> {
        unsafe {
            if libc::kill(pid, signal) == 0 {
                Ok(())
            } else {
                Err(ProcessError::SignalError(format!(
                    "Failed to signal PID {}: {}",
                    pid,
                    io::Error::last_os_error()
                )))
            }
        }
    }

    /// Read process information from /proc/[pid]
    fn read_process_info(&self, pid: i32) -> Result<ProcessInfo> {
        // Read /proc/[pid]/comm for process name
        let comm_path = format!("/proc/{}/comm", pid);
        let name = fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| String::from("unknown"));

        // Read /proc/[pid]/cmdline for full command line
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let cmdline = fs::read_to_string(&cmdline_path)
            .map(|s| {
                // cmdline uses null bytes as separators
                s.split('\0')
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|_| name.clone());

        Ok(ProcessInfo { pid, name, cmdline })
    }

    /// Get list of all process PIDs
    pub fn list_pids(&self) -> Result<Vec<i32>> {
        let mut pids = Vec::new();

        let proc_dir = Path::new("/proc");
        if !proc_dir.exists() {
            return Err(ProcessError::ProcRead("/proc does not exist".to_string()));
        }

        let entries = fs::read_dir(proc_dir)
            .map_err(|e| ProcessError::ProcRead(format!("Cannot read /proc: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| ProcessError::ProcRead(e.to_string()))?;
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();

            if let Ok(pid) = pid_str.parse::<i32>() {
                pids.push(pid);
            }
        }

        Ok(pids)
    }

    /// Get information about a specific PID
    pub fn get_process(&self, pid: i32) -> Result<ProcessInfo> {
        self.read_process_info(pid)
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience functions

/// Find all processes matching a pattern (`pgrep` equivalent).
///
/// Returns list of matching PIDs.
///
/// # Arguments
///
/// * `pattern` - Substring to search for in process name or command line
///
/// # Errors
///
/// * `ProcRead` - Cannot read /proc
///
/// # Examples
///
/// ```no_run
/// # use rustyjack_netlink::process::*;
/// # fn example() -> Result<()> {
/// let pids = pgrep("hostapd")?;
/// println!("Found {} hostapd processes", pids.len());
/// # Ok(())
/// # }
/// ```
pub fn pgrep(pattern: &str) -> Result<Vec<i32>> {
    let mgr = ProcessManager::new();
    Ok(mgr
        .find_by_pattern(pattern)?
        .into_iter()
        .map(|p| p.pid)
        .collect())
}

/// Find all processes with exact name match.
///
/// Returns list of matching PIDs.
///
/// # Arguments
///
/// * `name` - Exact process name (from `/proc/[pid]/comm`)
pub fn pgrep_exact(name: &str) -> Result<Vec<i32>> {
    let mgr = ProcessManager::new();
    Ok(mgr.find_by_name(name)?.into_iter().map(|p| p.pid).collect())
}

/// Kill all processes matching a pattern (`pkill` equivalent with SIGTERM).
///
/// # Arguments
///
/// * `pattern` - Substring to match
///
/// # Returns
///
/// Number of processes successfully signaled
///
/// # Examples
///
/// ```no_run
/// # use rustyjack_netlink::process::*;
/// # fn example() -> Result<()> {
/// let killed = pkill("dnsmasq")?;
/// println!("Killed {} dnsmasq processes", killed);
/// # Ok(())
/// # }
/// ```
pub fn pkill(pattern: &str) -> Result<usize> {
    let mgr = ProcessManager::new();
    mgr.kill_pattern(pattern)
}

/// Kill all processes matching a pattern with SIGKILL (`pkill -9` equivalent).
///
/// Immediately terminates processes without cleanup.
///
/// # Arguments
///
/// * `pattern` - Substring to match
///
/// # Returns
///
/// Number of processes successfully killed
pub fn pkill_force(pattern: &str) -> Result<usize> {
    let mgr = ProcessManager::new();
    mgr.kill_pattern_force(pattern)
}

/// Kill all processes with exact name match (SIGTERM).
///
/// # Arguments
///
/// * `name` - Exact process name
///
/// # Returns
///
/// Number of processes successfully signaled
pub fn pkill_exact(name: &str) -> Result<usize> {
    let mgr = ProcessManager::new();
    mgr.kill_name(name)
}

/// Kill all processes with exact name match using SIGKILL (force).
///
/// # Arguments
///
/// * `name` - Exact process name
///
/// # Returns
///
/// Number of processes successfully killed
pub fn pkill_exact_force(name: &str) -> Result<usize> {
    let mgr = ProcessManager::new();
    mgr.kill_name_force(name)
}

/// Check if any process matching pattern is running.
///
/// # Arguments
///
/// * `pattern` - Substring to search for
///
/// # Returns
///
/// * `true` - At least one matching process exists
/// * `false` - No matching processes found
///
/// # Examples
///
/// ```no_run
/// # use rustyjack_netlink::process::*;
/// # fn example() -> Result<()> {
/// if process_running("wpa_supplicant")? {
///     println!("wpa_supplicant is running");
/// }
/// # Ok(())
/// # }
/// ```
pub fn process_running(pattern: &str) -> Result<bool> {
    let mgr = ProcessManager::new();
    mgr.exists_pattern(pattern)
}
