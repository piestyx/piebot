use crate::app::list_offset_mut;
use crate::data::logs_read::log_preview_lines;
use crate::model::{App, LogsFocus, Theme};
use crate::widgets::panel::{inner_height, render_error_panel, render_list, render_text_panel};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::ListItem;

fn render_runtime_logs_panel(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    if app.logs.missing {
        render_error_panel(f, area, "Logs missing", "runtime/logs not found", theme);
        return;
    }
    if let Some(err) = app.logs.error.as_ref() {
        render_error_panel(f, area, "Logs error", err, theme);
        return;
    }
    if app.logs.entries.is_empty() {
        render_error_panel(f, area, "Logs", "no logs present", theme);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(area);
    app.logs_file_height = inner_height(chunks[1]);
    let items: Vec<ListItem> = app
        .logs
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
        app.logs.selected,
        "Logs",
        theme,
        list_offset_mut(app, crate::model::Tab::Logs),
    );
    let detail_lines = log_preview_lines(&app.logs.entries[app.logs.selected]);
    render_text_panel(
        f,
        chunks[1],
        detail_lines,
        "Log Detail",
        theme,
        &mut app.logs_file_scroll,
    );
}

pub(crate) fn draw_logs_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    let show_process =
        app.process.running || app.process.exit_status.is_some() || !app.process.output.is_empty();
    if !show_process {
        app.logs_focus = LogsFocus::Files;
    }
    if show_process {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)].as_ref())
            .split(area);
        app.logs_process_height = inner_height(chunks[0]);
        app.logs_file_height = inner_height(chunks[1]);
        let mut lines: Vec<Line<'static>> = Vec::new();

        let status = if app.process.running {
            let pid = app.process.pid.unwrap_or(0);
            let uptime = app
                .process
                .start_time
                .map(|t| t.elapsed().as_secs_f32())
                .unwrap_or(0.0);
            format!("RUNNING pid={} uptime={:.1}s", pid, uptime)
        } else if let Some(code) = app.process.exit_status {
            format!("EXIT code={}", code)
        } else {
            "IDLE".to_string()
        };
        lines.push(Line::from(status));
        if let Some(run_id) = app.process.current_run_id.as_ref() {
            lines.push(Line::from(format!("run_id: {}", run_id)));
        }
        let dropped = app.process.output.dropped();
        if dropped > 0 {
            lines.push(Line::from(format!(
                "dropped: {} lines (buffer {} bytes / {} lines)",
                dropped,
                crate::config::MAX_PROCESS_OUTPUT_BYTES,
                crate::config::MAX_PROCESS_LINES
            )));
        }
        lines.push(Line::from(""));
        if app.process.output.is_empty() {
            lines.push(Line::from("no process output yet"));
        } else {
            for line in app.process.output.lines() {
                lines.push(Line::from(line.clone()));
            }
        }
        render_text_panel(
            f,
            chunks[0],
            lines,
            "Process Output",
            theme,
            &mut app.logs_process_scroll,
        );
        render_runtime_logs_panel(f, chunks[1], app, theme);
        return;
    }
    render_runtime_logs_panel(f, area, app, theme);
}
