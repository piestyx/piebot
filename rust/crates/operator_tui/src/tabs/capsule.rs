use crate::app::{detail_scroll_mut, list_offset_mut, set_detail_height};
use crate::config::{MAX_JSON_BYTES, MAX_PREVIEW_BYTES};
use crate::data::runtime::read_file_prefix;
use crate::model::{App, Theme};
use crate::widgets::panel::{inner_height, render_error_panel, render_list, render_text_panel};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::ListItem;
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(crate) fn capsule_summary_lines(path: &Path) -> Vec<Line<'static>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return vec![Line::from("capsule metadata read failed")],
    };
    let size = meta.len();
    if size as usize > MAX_JSON_BYTES {
        let mut lines = vec![
            Line::from(format!("capsule too large to parse ({} bytes)", size)),
            Line::from("preview:"),
        ];
        if let Ok(bytes) = read_file_prefix(path, MAX_PREVIEW_BYTES) {
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
        Err(_) => return vec![Line::from("capsule read failed")],
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return vec![Line::from("capsule json invalid")],
    };
    let mut lines = Vec::new();
    lines.push(Line::from(format!("path: {}", path.display())));
    if let Some(run) = value.get("run") {
        lines.push(Line::from("run:"));
        push_field(&mut lines, "run_id", run.get("run_id"));
        push_field(&mut lines, "mode", run.get("mode"));
        push_field(&mut lines, "ticks", run.get("ticks"));
        push_field(&mut lines, "delta_ref", run.get("delta_ref"));
    }
    if let Some(skill) = value.get("skill") {
        lines.push(Line::from("skill:"));
        push_field(&mut lines, "skill_id", skill.get("skill_id"));
        push_field(
            &mut lines,
            "skill_manifest_hash",
            skill.get("skill_manifest_hash"),
        );
        push_field(
            &mut lines,
            "output_contract_id",
            skill.get("output_contract_id"),
        );
        push_field(
            &mut lines,
            "output_contract_hash",
            skill.get("output_contract_hash"),
        );
    }
    if let Some(router) = value.get("router") {
        lines.push(Line::from("router:"));
        push_field(
            &mut lines,
            "router_config_hash",
            router.get("router_config_hash"),
        );
    }
    if let Some(tools) = value.get("tools") {
        lines.push(Line::from("tools:"));
        push_field(
            &mut lines,
            "tool_registry_hash",
            tools.get("tool_registry_hash"),
        );
        push_field(
            &mut lines,
            "tool_policy_hash",
            tools.get("tool_policy_hash"),
        );
    }
    if let Some(context) = value.get("context") {
        lines.push(Line::from("context:"));
        push_field(&mut lines, "policy_ref", context.get("policy_ref"));
        let context_refs = context
            .get("context_refs")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        let prompt_refs = context
            .get("prompt_refs")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        let template_refs = context
            .get("prompt_template_refs")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        lines.push(Line::from(format!("  context_refs: {}", context_refs)));
        lines.push(Line::from(format!("  prompt_refs: {}", prompt_refs)));
        lines.push(Line::from(format!(
            "  prompt_template_refs: {}",
            template_refs
        )));
    }
    if let Some(providers) = value.get("providers").and_then(|v| v.as_array()) {
        lines.push(Line::from(format!("providers: {}", providers.len())));
        for provider in providers {
            let mut line = "  - ".to_string();
            if let Some(id) = provider.get("provider_id").and_then(|v| v.as_str()) {
                line.push_str(&format!("{} ", id));
            }
            if let Some(req) = provider.get("request_ref").and_then(|v| v.as_str()) {
                line.push_str(&format!("request_ref={} ", req));
            }
            if let Some(resp) = provider.get("response_ref").and_then(|v| v.as_str()) {
                line.push_str(&format!("response_ref={} ", resp));
            }
            if let Some(out) = provider.get("output_ref").and_then(|v| v.as_str()) {
                line.push_str(&format!("output_ref={}", out));
            }
            lines.push(Line::from(line));
        }
    }
    if let Some(tool_io) = value.get("tool_io").and_then(|v| v.as_array()) {
        lines.push(Line::from(format!("tool_io: {}", tool_io.len())));
        for io_item in tool_io {
            let mut line = "  - ".to_string();
            if let Some(id) = io_item.get("tool_id").and_then(|v| v.as_str()) {
                line.push_str(&format!("{} ", id));
            }
            if let Some(input) = io_item.get("input_ref").and_then(|v| v.as_str()) {
                line.push_str(&format!("input_ref={} ", input));
            }
            if let Some(output) = io_item.get("output_ref").and_then(|v| v.as_str()) {
                line.push_str(&format!("output_ref={}", output));
            }
            lines.push(Line::from(line));
        }
    }
    if let Some(state) = value.get("state") {
        lines.push(Line::from("state:"));
        push_field(
            &mut lines,
            "initial_state_hash",
            state.get("initial_state_hash"),
        );
        push_field(
            &mut lines,
            "final_state_hash",
            state.get("final_state_hash"),
        );
        let delta_refs = state
            .get("state_delta_refs")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        lines.push(Line::from(format!("  state_delta_refs: {}", delta_refs)));
    }
    if let Some(audit) = value.get("audit") {
        lines.push(Line::from("audit:"));
        push_field(&mut lines, "audit_head_hash", audit.get("audit_head_hash"));
    }
    lines
}

fn push_field(lines: &mut Vec<Line<'static>>, name: &str, value: Option<&Value>) {
    match value {
        Some(Value::String(s)) => lines.push(Line::from(format!("  {}: {}", name, s))),
        Some(Value::Number(n)) => lines.push(Line::from(format!("  {}: {}", name, n))),
        Some(Value::Bool(b)) => lines.push(Line::from(format!("  {}: {}", name, b))),
        Some(Value::Null) => lines.push(Line::from(format!("  {}: null", name))),
        Some(other) => lines.push(Line::from(format!("  {}: {}", name, other))),
        None => {}
    }
}

pub(crate) fn draw_capsule_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    if app.capsule.missing {
        render_error_panel(
            f,
            area,
            "Run capsules missing",
            "runtime/artifacts/run_capsules not found",
            theme,
        );
        return;
    }
    if let Some(err) = app.capsule.error.as_ref() {
        render_error_panel(f, area, "Run capsules error", err, theme);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(area);
    set_detail_height(app, crate::model::Tab::Capsule, inner_height(chunks[1]));
    let items: Vec<ListItem> = app
        .capsule
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
        app.capsule.selected,
        "Capsules",
        theme,
        list_offset_mut(app, crate::model::Tab::Capsule),
    );
    let detail_lines = if app.capsule.entries.is_empty() {
        vec![Line::from("no capsules")]
    } else {
        capsule_summary_lines(&app.capsule.entries[app.capsule.selected])
    };
    render_text_panel(
        f,
        chunks[1],
        detail_lines,
        "Capsule Summary",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Capsule),
    );
}
