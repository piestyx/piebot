use crate::config::MAX_LOG_BYTES;
use crate::data::runtime::read_file_tail;
use ratatui::text::Line;
use std::fs;
use std::path::Path;

pub(crate) fn log_preview_lines(path: &Path) -> Vec<Line<'static>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return vec![Line::from("log metadata read failed")],
    };
    let size = meta.len();
    let bytes = match read_file_tail(path, MAX_LOG_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => return vec![Line::from("log read failed")],
    };
    let mut lines = Vec::new();
    lines.push(Line::from(format!("path: {}", path.display())));
    lines.push(Line::from(format!("size: {} bytes", size)));
    lines.push(Line::from("tail:"));
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        lines.push(Line::from(line.to_string()));
    }
    if size as usize > MAX_LOG_BYTES {
        lines.push(Line::from("[truncated]"));
    }
    lines
}
