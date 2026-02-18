use crate::app::{detail_scroll_mut, list_offset_mut, set_detail_height};
use crate::data::audit_read::{apply_audit_filter, audit_event_label, tag_prefix};
use crate::model::{App, Theme};
use crate::widgets::input::pretty_json_lines;
use crate::widgets::panel::{inner_height, render_error_panel, render_list, render_text_panel};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::ListItem;

pub(crate) fn handle_filter_input(app: &mut App, key: crossterm::event::KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.filter_mode = false;
        }
        KeyCode::Enter => {
            app.audit.filter = app.filter_input.clone();
            apply_audit_filter(&mut app.audit);
            app.audit.selected = 0;
            *list_offset_mut(app, crate::model::Tab::Audit) = 0;
            *detail_scroll_mut(app, crate::model::Tab::Audit) = 0;
            app.filter_mode = false;
        }
        KeyCode::Backspace => {
            app.filter_input.pop();
        }
        KeyCode::Char(c) => {
            if key.modifiers == KeyModifiers::NONE || key.modifiers == KeyModifiers::SHIFT {
                app.filter_input.push(c);
            }
        }
        _ => {}
    }
}

pub(crate) fn draw_audit_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    if app.audit.missing {
        render_error_panel(
            f,
            area,
            "Audit log missing",
            "runtime/logs/audit_rust.jsonl not found",
            theme,
        );
        return;
    }
    if let Some(err) = app.audit.error.as_ref() {
        render_error_panel(f, area, "Audit error", err, theme);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(area);
    set_detail_height(app, crate::model::Tab::Audit, inner_height(chunks[1]));
    let mut items = Vec::new();
    for event_index in app.audit.filtered_indices.iter() {
        let event = &app.audit.events[*event_index];
        let label = audit_event_label(event);
        let display_index = event_index + 1;
        let hash_suffix = event.get("hash").and_then(|v| v.as_str()).map(tag_prefix);
        let text = match hash_suffix {
            Some(suffix) => format!("{:04} {} [{}]", display_index, label, suffix),
            None => format!("{:04} {}", display_index, label),
        };
        items.push(ListItem::new(text));
    }
    render_list(
        f,
        chunks[0],
        items,
        app.audit.selected,
        "Events",
        theme,
        list_offset_mut(app, crate::model::Tab::Audit),
    );
    let detail_lines = if app.audit.filtered_indices.is_empty() {
        vec![Line::from("no events")]
    } else {
        let idx = app.audit.filtered_indices[app.audit.selected];
        pretty_json_lines(&app.audit.events[idx])
    };
    render_text_panel(
        f,
        chunks[1],
        detail_lines,
        "Event Detail",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Audit),
    );
}
