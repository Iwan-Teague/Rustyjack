use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

pub fn tail_lines_with_truncation(
    path: &Path,
    max_lines: usize,
    max_bytes: usize,
) -> io::Result<(String, bool)> {
    let mut file = File::open(path)?;
    let mut pos = file.seek(SeekFrom::End(0))?;
    let mut buf: Vec<u8> = Vec::new();

    let max_lines = max_lines.max(1);
    let max_bytes = max_bytes.max(1);

    while pos > 0 && buf.len() < max_bytes {
        if count_newlines(&buf) >= max_lines {
            break;
        }
        let step = std::cmp::min(4096, pos as usize);
        pos -= step as u64;
        file.seek(SeekFrom::Start(pos))?;
        let mut chunk = vec![0u8; step];
        file.read_exact(&mut chunk)?;
        buf.splice(0..0, chunk);
    }

    let truncated_scan = pos > 0 || buf.len() >= max_bytes;
    let content = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = content.lines().collect();
    let truncated_output = truncated_scan || lines.len() > max_lines;
    if lines.len() > max_lines {
        let start = lines.len() - max_lines;
        lines = lines[start..].to_vec();
    }

    Ok((lines.join("\n"), truncated_output))
}

fn count_newlines(buf: &[u8]) -> usize {
    buf.iter().filter(|&&b| b == b'\n').count()
}
