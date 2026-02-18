use ratatui::text::Line;
use serde_json::Value;

pub(crate) fn lines_from_string(value: &str) -> Vec<Line<'static>> {
    value
        .lines()
        .map(|line| Line::from(line.to_string()))
        .collect()
}

pub(crate) fn pretty_json_lines(value: &Value) -> Vec<Line<'static>> {
    match serde_json::to_string_pretty(value) {
        Ok(text) => lines_from_string(&text),
        Err(_) => vec![Line::from("failed to render json")],
    }
}
