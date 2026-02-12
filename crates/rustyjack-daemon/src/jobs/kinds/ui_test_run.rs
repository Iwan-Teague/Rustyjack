use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::state::DaemonState;
use rustyjack_ipc::{DaemonError, ErrorCode, UiTestRunRequestIpc};

const DEFAULT_SCRIPT_NAME: &str = "rj_run_tests.sh";

fn utc_run_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("ui-{}", now)
}

fn resolve_scripts_dir(req: &UiTestRunRequestIpc, state: &DaemonState) -> Option<PathBuf> {
    if let Some(raw) = req.scripts_dir.as_deref() {
        let candidate = PathBuf::from(raw);
        if candidate.join(DEFAULT_SCRIPT_NAME).exists() {
            return Some(candidate);
        }
    }

    if let Ok(raw) = std::env::var("RUSTYJACK_TEST_SCRIPTS_DIR") {
        let candidate = PathBuf::from(raw);
        if candidate.join(DEFAULT_SCRIPT_NAME).exists() {
            return Some(candidate);
        }
    }

    let defaults = [
        state.config.root_path.join("scripts"),
        PathBuf::from("/root/Rusty-Jack/scripts"),
        PathBuf::from("/home/rustyjack/Rusty-Jack/scripts"),
        PathBuf::from("/usr/local/share/rustyjack/scripts"),
    ];

    defaults
        .iter()
        .find(|candidate| candidate.join(DEFAULT_SCRIPT_NAME).exists())
        .cloned()
}

fn as_absolute(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn contains_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|value| value == flag)
}

pub async fn run<F, Fut>(
    req: UiTestRunRequestIpc,
    state: Arc<DaemonState>,
    cancel: &CancellationToken,
    progress: &mut F,
) -> Result<serde_json::Value, DaemonError>
where
    F: FnMut(&str, u8, &str) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if cancel.is_cancelled() {
        return Err(DaemonError::new(
            ErrorCode::Cancelled,
            "job cancelled",
            false,
        ));
    }

    progress("tests_prepare", 2, "Preparing UI test run").await;

    let scripts_dir = resolve_scripts_dir(&req, &state).ok_or_else(|| {
        DaemonError::new(
            ErrorCode::NotFound,
            "unable to find Rustyjack test scripts directory",
            false,
        )
        .with_detail("expected rj_run_tests.sh under scripts directory")
        .with_source("daemon.jobs.ui_test_run")
    })?;

    let runner = scripts_dir.join(DEFAULT_SCRIPT_NAME);
    if !runner.exists() {
        return Err(
            DaemonError::new(ErrorCode::NotFound, "test runner script missing", false)
                .with_detail(runner.display().to_string())
                .with_source("daemon.jobs.ui_test_run"),
        );
    }

    let run_id = req.run_id.clone().unwrap_or_else(utc_run_id);
    let outroot_path = req
        .outroot
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state.config.root_path.join("tests"));
    let results_root = outroot_path.join(&run_id);

    fs::create_dir_all(&results_root).map_err(|err| {
        DaemonError::new(
            ErrorCode::Internal,
            "failed to create ui test output directory",
            false,
        )
        .with_detail(err.to_string())
        .with_source("daemon.jobs.ui_test_run")
    })?;

    let launcher_log = results_root.join("ui_test_runner.log");
    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&launcher_log)
        .map_err(|err| {
            DaemonError::new(ErrorCode::Internal, "failed to open test runner log", false)
                .with_detail(err.to_string())
                .with_source("daemon.jobs.ui_test_run")
        })?;
    let stderr_file = stdout_file.try_clone().map_err(|err| {
        DaemonError::new(
            ErrorCode::Internal,
            "failed to clone test runner log handle",
            false,
        )
        .with_detail(err.to_string())
        .with_source("daemon.jobs.ui_test_run")
    })?;

    let mut args = req.args.clone();
    if !contains_flag(&args, "--all")
        && !args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--wireless"
                    | "--ethernet"
                    | "--iface-select"
                    | "--encryption"
                    | "--loot"
                    | "--mac"
                    | "--daemon"
                    | "--daemon-deep"
                    | "--installers"
                    | "--usb"
                    | "--ui-layout"
                    | "--theme"
            )
        })
    {
        args.push("--all".to_string());
    }
    if req.force_ui && !contains_flag(&args, "--ui") && !contains_flag(&args, "--no-ui") {
        args.push("--ui".to_string());
    }
    if !contains_flag(&args, "--outroot") {
        args.push("--outroot".to_string());
        args.push(as_absolute(&outroot_path));
    }

    progress("tests_start", 5, "Starting test runner").await;

    let mut command = Command::new("bash");
    command
        .current_dir(&scripts_dir)
        .arg(&runner)
        .args(&args)
        .env("RJ_NONINTERACTIVE", "1")
        .env("RJ_AUTO_INSTALL", "0")
        .env("RJ_RUN_ID", &run_id)
        .env("RJ_OUTROOT", as_absolute(&outroot_path))
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let mut child = command.spawn().map_err(|err| {
        DaemonError::new(ErrorCode::Internal, "failed to spawn test runner", false)
            .with_detail(err.to_string())
            .with_source("daemon.jobs.ui_test_run")
    })?;

    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut percent: u8 = 10;

    let status = loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = child.kill().await;
                return Err(
                    DaemonError::new(ErrorCode::Cancelled, "job cancelled", false)
                        .with_source("daemon.jobs.ui_test_run"),
                );
            }
            _ = tick.tick() => {
                percent = percent.saturating_add(2).min(95);
                progress("tests_running", percent, "Running test suites...").await;
            }
            status = child.wait() => {
                break status.map_err(|err| {
                    DaemonError::new(ErrorCode::Internal, "failed waiting for test runner", false)
                        .with_detail(err.to_string())
                        .with_source("daemon.jobs.ui_test_run")
                })?;
            }
        }
    };

    progress("tests_finalize", 100, "Collecting test artifacts").await;

    let exit_code = status.code().unwrap_or(-1);
    let success = status.success();
    Ok(serde_json::json!({
        "status": if success { "ok" } else { "failed" },
        "success": success,
        "exit_code": exit_code,
        "run_id": run_id,
        "scripts_dir": scripts_dir,
        "runner_path": runner,
        "outroot": outroot_path,
        "results_root": results_root,
        "runner_log": launcher_log,
        "args": args,
    }))
}
