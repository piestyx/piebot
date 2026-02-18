use crate::app::{detail_scroll_mut, list_offset_mut, set_detail_height};
use crate::data::artifacts_read::render_artifact_detail;
use crate::model::{App, Theme};
use crate::widgets::panel::{inner_height, render_error_panel, render_list, render_text_panel};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::ListItem;

pub(crate) fn draw_artifacts_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    if app.artifacts.missing {
        render_error_panel(
            f,
            area,
            "Artifacts missing",
            "runtime/artifacts not found",
            theme,
        );
        return;
    }
    if let Some(err) = app.artifacts.error.as_ref() {
        render_error_panel(f, area, "Artifacts error", err, theme);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(area);
    set_detail_height(app, crate::model::Tab::Artifacts, inner_height(chunks[1]));
    let items: Vec<ListItem> = app
        .artifacts
        .entries
        .iter()
        .map(|entry| ListItem::new(entry.display.clone()))
        .collect();
    render_list(
        f,
        chunks[0],
        items,
        app.artifacts.selected,
        "Namespaces",
        theme,
        list_offset_mut(app, crate::model::Tab::Artifacts),
    );
    let detail_lines = if app.artifacts.entries.is_empty() {
        vec![Line::from("no artifacts")]
    } else {
        let entry = &app.artifacts.entries[app.artifacts.selected];
        if entry.is_dir {
            vec![Line::from("select a file to view metadata")]
        } else {
            render_artifact_detail(&entry.path)
        }
    };
    render_text_panel(
        f,
        chunks[1],
        detail_lines,
        "Artifact Detail",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Artifacts),
    );
}
