use crate::model::{App, Tab, Theme};
use crate::tabs::run::run_focus_label;
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use serde_json::Value;

fn audit_inner_event(root: &Value) -> Option<&Value> {
    if let Some(event) = root.get("event").and_then(|v| v.get("event")) {
        return Some(event);
    }
    if let Some(event) = root.get("event") {
        return Some(event);
    }
    Some(root)
}

fn latest_status_hints(app: &App) -> (Option<String>, Option<String>, Option<String>) {
    let mut run_id = app.process.current_run_id.clone();
    let mut task_id: Option<String> = None;
    let mut capsule_ref: Option<String> = None;
    for root in app.audit.events.iter().rev() {
        let event = match audit_inner_event(root) {
            Some(event) => event,
            None => continue,
        };
        if run_id.is_none() {
            run_id = event
                .get("run_id")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
        }
        if task_id.is_none() {
            task_id = event
                .get("task_id")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
        }
        if capsule_ref.is_none() {
            capsule_ref = event
                .get("capsule_ref")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
        }
        if run_id.is_some() && task_id.is_some() && capsule_ref.is_some() {
            break;
        }
    }
    (run_id, task_id, capsule_ref)
}

pub(crate) fn draw_status(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &App,
    theme: &Theme,
) {
    let mut status = Vec::new();
    status.push(Span::raw(format!(
        "runtime: {}",
        app.runtime_root.display()
    )));
    if app.process.running {
        if let Some(pid) = app.process.pid {
            status.push(Span::raw(format!(" | serverd: running pid={}", pid)));
        } else {
            status.push(Span::raw(" | serverd: running"));
        }
    } else if let Some(code) = app.process.exit_status {
        status.push(Span::raw(format!(" | serverd: exit {}", code)));
    }
    let (run_id_hint, task_id_hint, capsule_ref_hint) = latest_status_hints(app);
    if let Some(run_id) = run_id_hint.as_ref() {
        status.push(Span::raw(format!(" | run_id: {}", run_id)));
    }
    if let Some(task_id) = task_id_hint.as_ref() {
        status.push(Span::raw(format!(" | task_id: {}", task_id)));
    }
    if let Some(capsule_ref) = capsule_ref_hint.as_ref() {
        status.push(Span::raw(format!(" | capsule_ref: {}", capsule_ref)));
    }

    status.push(Span::raw(" | "));
    if app.active_tab == Tab::Audit {
        status.push(Span::raw(format!(
            "filter: {}",
            if app.filter_mode {
                app.filter_input.as_str()
            } else {
                app.audit.filter.as_str()
            }
        )));
        status.push(Span::raw(" | "));
        status.push(Span::raw(format!(
            "parse errors: {}",
            app.audit.error_count
        )));
    } else if app.active_tab == Tab::Run {
        status.push(Span::raw(format!(
            "focus: {}",
            run_focus_label(app.run.focus)
        )));
        status.push(Span::raw(" | "));
        status.push(Span::raw("A approvals"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("j/k change"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("enter/l launch"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("s stop"));
    } else if app.active_tab == Tab::Actions {
        status.push(Span::raw("A approvals"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("j/k select"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("Enter detail"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("R verify"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("E export"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("Y/N approve/refuse"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("L learnings"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("R replay-verify"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("E export"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("Y approve"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("N refuse"));
        status.push(Span::raw(" | "));
        status.push(Span::raw("L learnings"));
        if app.actions.prompt != crate::model::OperatorPrompt::None {
            status.push(Span::raw(" | "));
            status.push(Span::raw("prompt active"));
        }
    } else if app.active_tab == Tab::Logs {
        status.push(Span::raw(
            "tab switch panel | j/k select file | pgup/pgdn scroll",
        ));
    } else {
        status.push(Span::raw("press q to quit"));
    }
    let line = Line::from(status);
    let paragraph = Paragraph::new(Text::from(line))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(theme.text)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}
