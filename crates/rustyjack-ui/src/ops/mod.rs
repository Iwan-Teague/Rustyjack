pub mod ethernet;
pub mod recon;
pub mod runner;
pub mod shared;
pub mod wifi;

use anyhow::Result;

use crate::ui::UiContext;

pub struct OperationContext<'a> {
    pub ui: UiContext<'a>,
}

impl<'a> OperationContext<'a> {
    pub fn new(ui: UiContext<'a>) -> Self {
        Self { ui }
    }
}

pub enum OperationOutcome {
    Success { summary: Vec<String> },
    Cancelled { summary: Vec<String> },
    Failed { error: anyhow::Error },
}

pub trait Operation {
    #[allow(dead_code)]
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;

    fn preflight(&mut self, ctx: &mut OperationContext) -> Result<()>;

    /// Return false when setup is cancelled (Back or Cancel).
    fn setup(&mut self, ctx: &mut OperationContext) -> Result<bool>;

    /// Lines shown on the confirm screen.
    fn confirm_lines(&self) -> Vec<String>;

    fn run(&mut self, ctx: &mut OperationContext) -> Result<OperationOutcome>;
}
