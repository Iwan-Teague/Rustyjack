use anyhow::Result;

use crate::{
    ops::{Operation, OperationContext, OperationOutcome},
    ui::screens::{confirm, error, result},
};

pub struct OperationRunner;

impl OperationRunner {
    pub fn run<O: Operation>(ctx: &mut OperationContext, op: &mut O) -> Result<()> {
        if let Err(e) = op.preflight(ctx) {
            error::show(&mut ctx.ui, "Preflight failed", &e)?;
            return Ok(());
        }

        'setup: loop {
            if !op.setup(ctx)? {
                return Ok(());
            }

            loop {
                match confirm::show(&mut ctx.ui, op.title(), &op.confirm_lines())? {
                    confirm::ConfirmChoice::Yes => break 'setup,
                    confirm::ConfirmChoice::No => return Ok(()),
                    confirm::ConfirmChoice::Back => continue 'setup,
                    confirm::ConfirmChoice::Cancel => return Ok(()),
                }
            }
        }

        let outcome = match op.run(ctx) {
            Ok(outcome) => outcome,
            Err(err) => OperationOutcome::Failed { error: err },
        };

        let lines = format_outcome(&outcome);
        result::show(&mut ctx.ui, op.title(), &lines)?;

        Ok(())
    }
}

fn format_outcome(outcome: &OperationOutcome) -> Vec<String> {
    match outcome {
        OperationOutcome::Success { summary } => summary.clone(),
        OperationOutcome::Cancelled { summary } => summary.clone(),
        OperationOutcome::Failed { error } => {
            let mut lines = vec!["Failed".to_string()];
            for (idx, cause) in error.chain().enumerate() {
                if idx == 0 {
                    lines.push(format!("Error: {}", cause));
                } else {
                    lines.push(format!("Cause: {}", cause));
                }
            }
            lines
        }
    }
}
