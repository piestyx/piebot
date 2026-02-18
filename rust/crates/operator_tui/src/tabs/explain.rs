use crate::app::{detail_scroll_mut, list_offset_mut, set_detail_height};
use crate::config::{MAX_JSON_BYTES, MAX_PREVIEW_BYTES};
use crate::data::runtime::read_file_prefix;
use crate::model::{App, Theme};
use crate::widgets::input::pretty_json_lines;
use crate::widgets::panel::{inner_height, render_error_panel, render_list, render_text_panel};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::ListItem;
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(crate) fn explain_lines(path: &Path) -> Vec<Line<'static>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return vec![Line::from("explain metadata read failed")],
    };
    let size = meta.len();
    if size as usize > MAX_JSON_BYTES {
        let mut lines = vec![Line::from(format!(
            "explain too large to render ({} bytes)",
            size
        ))];
        if let Ok(bytes) = read_file_prefix(path, MAX_PREVIEW_BYTES) {
            lines.push(Line::from("preview:"));
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines() {
                lines.push(Line::from(line.to_string()));
            }
            if size as usize > MAX_PREVIEW_BYTES {
                lines.push(Line::from("[truncated]"));
            }
        }
        return lines;
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return vec![Line::from("explain read failed")],
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return vec![Line::from("explain json invalid")],
    };
    pretty_json_lines(&value)
}

pub(crate) fn draw_explain_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    if app.explain.missing {
        render_error_panel(
            f,
            area,
            "Explain artifacts missing",
            "runtime/artifacts/explains not found",
            theme,
        );
        return;
    }
    if let Some(err) = app.explain.error.as_ref() {
        render_error_panel(f, area, "Explain error", err, theme);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(area);
    set_detail_height(app, crate::model::Tab::Explain, inner_height(chunks[1]));
    let items: Vec<ListItem> = app
        .explain
        .entries
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            ListItem::new(name.to_string())
        })
        .collect();
    render_list(
        f,
        chunks[0],
        items,
        app.explain.selected,
        "Explains",
        theme,
        list_offset_mut(app, crate::model::Tab::Explain),
    );
    let detail_lines = if app.explain.entries.is_empty() {
        vec![Line::from("no explain artifacts")]
    } else {
        explain_lines(&app.explain.entries[app.explain.selected])
    };
    render_text_panel(
        f,
        chunks[1],
        detail_lines,
        "Explain Detail",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Explain),
    );
}
