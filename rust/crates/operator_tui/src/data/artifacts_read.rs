use crate::config::{MAX_JSON_BYTES, MAX_PREVIEW_BYTES};
use crate::data::runtime::read_file_prefix;
use ratatui::text::Line;
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(crate) fn artifact_schema_and_hash(path: &Path, size: u64) -> (Option<String>, Option<String>) {
    if size as usize > MAX_JSON_BYTES {
        return (None, None);
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return (None, None),
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return (None, None),
    };
    let schema = value
        .get("schema")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let hash = value
        .get("ref")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("hash").and_then(|v| v.as_str()))
        .or_else(|| value.get("artifact_ref").and_then(|v| v.as_str()))
        .or_else(|| value.get("artifact_hash").and_then(|v| v.as_str()))
        .map(|s| s.to_string());
    (schema, hash)
}

pub(crate) fn render_artifact_detail(path: &Path) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    lines.push(Line::from(format!("filename: {}", filename)));
    lines.push(Line::from(format!("path: {}", path.display())));
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => {
            lines.push(Line::from("metadata read failed"));
            return lines;
        }
    };
    let size = meta.len();
    lines.push(Line::from(format!("size: {} bytes", size)));
    let (schema, json_hash) = artifact_schema_and_hash(path, size);
    let schema = schema.unwrap_or_else(|| "unknown".to_string());
    lines.push(Line::from(format!("schema: {}", schema)));
    let file_hash = filename
        .strip_suffix(".json")
        .unwrap_or(filename)
        .strip_prefix("sha256:")
        .map(|value| format!("sha256:{}", value));
    let hash_value = file_hash
        .or(json_hash)
        .unwrap_or_else(|| "(unknown)".to_string());
    lines.push(Line::from(format!("hash: {}", hash_value)));
    lines.push(Line::from(""));
    lines.push(Line::from("preview:"));
    let preview = match read_file_prefix(path, MAX_PREVIEW_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => {
            lines.push(Line::from("preview read failed"));
            return lines;
        }
    };
    let preview_text = String::from_utf8_lossy(&preview);
    for line in preview_text.lines() {
        lines.push(Line::from(line.to_string()));
    }
    if size as usize > MAX_PREVIEW_BYTES {
        lines.push(Line::from("[truncated]"));
    }
    lines
}
