use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use serde_json::Value;

use crate::ops::shared::preflight::preflight_only_summary;
use crate::{
    ops::OperationContext,
    ui::{input::UiInput, screens::cancel_confirm, screens::progress},
};
use rustyjack_commands::Commands;
use rustyjack_ipc::JobState;

pub enum JobRunResult {
    Completed { message: String, data: Value },
    Cancelled,
}

pub fn dispatch_cancellable(
    ctx: &mut OperationContext,
    label: &str,
    cmd: Commands,
    duration_secs: u64,
) -> Result<JobRunResult> {
    let job_id = ctx.ui.core.start_core_command(cmd)?;
    let start = Instant::now();
    let mut last_displayed_secs: u64 = u64::MAX;
    let poll_interval = Duration::from_millis(200);
    let mut last_poll = Instant::now() - poll_interval;
    let mut last_status = None;

    loop {
        let elapsed = start.elapsed().as_secs();

        if let Some(input) = ctx.ui.try_read_input()? {
            match input {
                UiInput::CancelKey2 => {
                    if cancel_confirm::show(&mut ctx.ui, label)? {
                        progress::draw(&mut ctx.ui, label, "Cancelling...", 0.0)?;
                        if !ctx.ui.core.cancel_job(job_id)? {
                            return Err(anyhow!("Cancel request failed"));
                        }

                        let cancel_start = Instant::now();
                        while cancel_start.elapsed() < Duration::from_secs(3) {
                            let st = ctx.ui.core.job_status(job_id)?;
                            if matches!(
                                st.state,
                                JobState::Cancelled | JobState::Failed | JobState::Completed
                            ) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        return Ok(JobRunResult::Cancelled);
                    }
                }
                UiInput::RebootKey3 => {
                    ctx.ui.confirm_reboot()?;
                }
                _ => {}
            }
        }

        if last_status.is_none() || last_poll.elapsed() >= poll_interval {
            last_status = Some(ctx.ui.core.job_status(job_id)?);
            last_poll = Instant::now();
        }

        if let Some(status) = last_status.as_ref() {
            match status.state {
                JobState::Completed => {
                    let value = status
                        .result
                        .clone()
                        .ok_or_else(|| anyhow!("Job completed without result"))?;
                    let message = value
                        .get("message")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Job result missing message"))?
                        .to_string();
                    let data = value.get("data").cloned().unwrap_or(Value::Null);
                    return Ok(JobRunResult::Completed { message, data });
                }
                JobState::Failed => {
                    let err_msg = status
                        .error
                        .as_ref()
                        .map(|e| e.message.clone())
                        .unwrap_or_else(|| "Job failed".to_string());
                    let detail = status.error.as_ref().and_then(|e| e.detail.clone());
                    let full = if let Some(detail) = detail {
                        format!("{} ({})", err_msg, detail)
                    } else {
                        err_msg
                    };
                    bail!("Job failed: {}", full);
                }
                JobState::Cancelled => return Ok(JobRunResult::Cancelled),
                JobState::Queued | JobState::Running => {}
            }
        }

        if elapsed != last_displayed_secs {
            last_displayed_secs = elapsed;
            let progress_percent = if duration_secs > 0 {
                (elapsed as f32 / duration_secs as f32).min(1.0) * 100.0
            } else {
                0.0
            };
            let msg = if duration_secs > 0 && elapsed < duration_secs {
                format!("{}s/{}s [KEY2=Cancel]", elapsed, duration_secs)
            } else if duration_secs > 0 {
                "Finalizing... [KEY2=Cancel]".to_string()
            } else {
                format!("Elapsed: {}s [KEY2=Cancel]", elapsed)
            };
            progress::draw(&mut ctx.ui, label, &msg, progress_percent)?;
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Helper for Operation trait implementors - dispatches a job and returns OperationOutcome
pub fn run_cancellable_job(
    ctx: &mut OperationContext,
    cmd: &Commands,
    title: &str,
    _running_message: &str,
) -> Result<crate::ops::OperationOutcome> {
    use crate::ops::OperationOutcome;

    // Duration is not used for progress display in new pattern - the job's state is
    let duration = 0; // 0 means show elapsed time only

    match dispatch_cancellable(ctx, title, cmd.clone(), duration)? {
        JobRunResult::Completed { message, data } => {
            if let Some(lines) = preflight_only_summary(&data) {
                return Ok(OperationOutcome::Success { summary: lines });
            }
            Ok(OperationOutcome::Success {
                summary: vec![message],
            })
        }
        JobRunResult::Cancelled => Ok(OperationOutcome::Cancelled {
            summary: vec!["Operation cancelled by user".to_string()],
        }),
    }
}
