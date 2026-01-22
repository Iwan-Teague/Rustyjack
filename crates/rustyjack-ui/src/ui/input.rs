use crate::input::Button;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiInput {
    Up,
    Down,
    LeftBack,
    Select,
    Refresh,
    CancelKey2,
    RebootKey3,
}

pub fn map_button(button: Button) -> UiInput {
    match button {
        Button::Up => UiInput::Up,
        Button::Down => UiInput::Down,
        Button::Left => UiInput::LeftBack,
        Button::Right | Button::Select => UiInput::Select,
        Button::Key1 => UiInput::Refresh,
        Button::Key2 => UiInput::CancelKey2,
        Button::Key3 => UiInput::RebootKey3,
    }
}
