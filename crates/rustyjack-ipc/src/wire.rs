#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    ZeroLength,
    TooLarge(u32),
}

pub fn decode_frame_length(prefix: [u8; 4], max_frame: u32) -> Result<u32, FrameError> {
    let len = u32::from_be_bytes(prefix);
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > max_frame {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}
