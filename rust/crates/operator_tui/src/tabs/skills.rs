use crate::app::{detail_scroll_mut, list_offset_mut, set_detail_height};
use crate::model::{App, SkillEntry, Theme};
use crate::widgets::panel::{inner_height, render_error_panel, render_list, render_text_panel};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::ListItem;
use serde_json::Value;

pub(crate) fn skill_detail_lines(entry: &SkillEntry) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(format!("skill_id: {}", entry.id)));
    if let Some(hash) = entry.manifest_hash.as_ref() {
        lines.push(Line::from(format!("manifest_hash: {}", hash)));
    }
    if let Some(err) = entry.error.as_ref() {
        lines.push(Line::from(format!("error: {}", err)));
        return lines;
    }
    let manifest = match entry.manifest.as_ref() {
        Some(manifest) => manifest,
        None => {
            lines.push(Line::from("manifest not loaded"));
            return lines;
        }
    };
    if let Some(schema) = manifest.get("schema").and_then(|v| v.as_str()) {
        lines.push(Line::from(format!("schema: {}", schema)));
    }
    if let Some(allowed_tools) = manifest.get("allowed_tools").and_then(|v| v.as_array()) {
        lines.push(Line::from(format!(
            "allowed_tools: {}",
            allowed_tools.len()
        )));
        for tool in allowed_tools {
            if let Some(tool_id) = tool.as_str() {
                lines.push(Line::from(format!("  - {}", tool_id)));
            }
        }
    }
    if let Some(constraints) = manifest.get("tool_constraints").and_then(|v| v.as_array()) {
        lines.push(Line::from(format!(
            "tool_constraints: {}",
            constraints.len()
        )));
        for constraint in constraints {
            let tool_id = constraint
                .get("tool_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let require = constraint.get("require").unwrap_or(&Value::Null);
            lines.push(Line::from(format!("  - {} require={}", tool_id, require)));
        }
    }
    if let Some(prompt_refs) = manifest
        .get("prompt_template_refs")
        .and_then(|v| v.as_array())
    {
        lines.push(Line::from(format!(
            "prompt_template_refs: {}",
            prompt_refs.len()
        )));
        for reference in prompt_refs {
            if let Some(value) = reference.as_str() {
                lines.push(Line::from(format!("  - {}", value)));
            }
        }
    }
    if let Some(output_contract) = manifest.get("output_contract").and_then(|v| v.as_str()) {
        lines.push(Line::from(format!("output_contract: {}", output_contract)));
    }
    lines
}

pub(crate) fn draw_skills_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    if app.skills.missing {
        render_error_panel(
            f,
            area,
            "Skills missing",
            "runtime/skills not found (or --skills-dir not provided)",
            theme,
        );
        return;
    }
    if let Some(err) = app.skills.error.as_ref() {
        render_error_panel(f, area, "Skills error", err, theme);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(area);
    set_detail_height(app, crate::model::Tab::Skills, inner_height(chunks[1]));
    let items: Vec<ListItem> = app
        .skills
        .entries
        .iter()
        .map(|entry| ListItem::new(entry.id.clone()))
        .collect();
    render_list(
        f,
        chunks[0],
        items,
        app.skills.selected,
        "Skills",
        theme,
        list_offset_mut(app, crate::model::Tab::Skills),
    );
    let detail_lines = if app.skills.entries.is_empty() {
        vec![Line::from("no skills")]
    } else {
        skill_detail_lines(&app.skills.entries[app.skills.selected])
    };
    render_text_panel(
        f,
        chunks[1],
        detail_lines,
        "Skill Detail",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Skills),
    );
}
