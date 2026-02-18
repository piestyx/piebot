use crate::app::{detail_scroll_mut, list_offset_mut, move_selection, set_detail_height};
use crate::commands::spawn_serverd_action;
use crate::config::ACTION_COUNT;
use crate::model::{ActionsFocus, App, Theme};
use crate::widgets::panel::{inner_height, render_list, render_text_panel};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::ListItem;
use serde_json::Value;
use std::path::Path;

const APPROVE_FOCUS_ORDER: [ActionsFocus; 4] = [
    ActionsFocus::ApproveTool,
    ActionsFocus::ApproveInput,
    ActionsFocus::ApproveRunId,
    ActionsFocus::ApproveSubmit,
];
const LEARN_FOCUS_ORDER: [ActionsFocus; 4] = [
    ActionsFocus::LearnText,
    ActionsFocus::LearnTags,
    ActionsFocus::LearnSource,
    ActionsFocus::LearnSubmit,
];
const VERIFY_FOCUS_ORDER: [ActionsFocus; 2] =
    [ActionsFocus::VerifyRunId, ActionsFocus::VerifySubmit];
const REPLAY_FOCUS_ORDER: [ActionsFocus; 2] =
    [ActionsFocus::ReplayRunId, ActionsFocus::ReplaySubmit];
const EXPORT_FOCUS_ORDER: [ActionsFocus; 3] = [
    ActionsFocus::ExportRunId,
    ActionsFocus::ExportOut,
    ActionsFocus::ExportSubmit,
];

pub(crate) fn action_name(index: usize) -> &'static str {
    match index {
        0 => "approve",
        1 => "learn",
        2 => "verify",
        3 => "replay",
        4 => "export",
        _ => "approve",
    }
}

pub(crate) fn action_label(index: usize) -> &'static str {
    match index {
        0 => "Approve",
        1 => "Learn",
        2 => "Verify",
        3 => "Replay",
        4 => "Export",
        _ => "Approve",
    }
}

pub(crate) fn actions_focus_order(action: usize) -> &'static [ActionsFocus] {
    match action {
        0 => &APPROVE_FOCUS_ORDER,
        1 => &LEARN_FOCUS_ORDER,
        2 => &VERIFY_FOCUS_ORDER,
        3 => &REPLAY_FOCUS_ORDER,
        _ => &EXPORT_FOCUS_ORDER,
    }
}

pub(crate) fn actions_focus_for_action(action: usize) -> ActionsFocus {
    actions_focus_order(action)
        .first()
        .copied()
        .unwrap_or(ActionsFocus::ApproveTool)
}

pub(crate) fn actions_focus_is_input(focus: ActionsFocus) -> bool {
    matches!(
        focus,
        ActionsFocus::ApproveTool
            | ActionsFocus::ApproveInput
            | ActionsFocus::ApproveRunId
            | ActionsFocus::LearnText
            | ActionsFocus::LearnTags
            | ActionsFocus::LearnSource
            | ActionsFocus::VerifyRunId
            | ActionsFocus::ReplayRunId
            | ActionsFocus::ExportRunId
            | ActionsFocus::ExportOut
    )
}

pub(crate) fn actions_focus_is_submit(focus: ActionsFocus) -> bool {
    matches!(
        focus,
        ActionsFocus::ApproveSubmit
            | ActionsFocus::LearnSubmit
            | ActionsFocus::VerifySubmit
            | ActionsFocus::ReplaySubmit
            | ActionsFocus::ExportSubmit
    )
}

pub(crate) fn actions_next_focus(
    action: usize,
    focus: ActionsFocus,
    reverse: bool,
) -> ActionsFocus {
    let order = actions_focus_order(action);
    if order.is_empty() {
        return focus;
    }
    let current = order.iter().position(|v| *v == focus).unwrap_or(0);
    let next = if reverse {
        if current == 0 {
            order.len() - 1
        } else {
            current - 1
        }
    } else {
        (current + 1) % order.len()
    };
    order[next]
}

pub(crate) fn actions_input_mut<'a>(app: &'a mut App) -> Option<&'a mut String> {
    match app.actions.focus {
        ActionsFocus::ApproveTool => Some(&mut app.actions.approve_tool_id),
        ActionsFocus::ApproveInput => Some(&mut app.actions.approve_input_ref),
        ActionsFocus::ApproveRunId => Some(&mut app.actions.approve_run_id),
        ActionsFocus::LearnText => Some(&mut app.actions.learn_text),
        ActionsFocus::LearnTags => Some(&mut app.actions.learn_tags),
        ActionsFocus::LearnSource => Some(&mut app.actions.learn_source),
        ActionsFocus::VerifyRunId => Some(&mut app.actions.verify_run_id),
        ActionsFocus::ReplayRunId => Some(&mut app.actions.replay_run_id),
        ActionsFocus::ExportRunId => Some(&mut app.actions.export_run_id),
        ActionsFocus::ExportOut => Some(&mut app.actions.export_out),
        _ => None,
    }
}

pub(crate) fn submit_selected_action(app: &mut App) {
    match app.actions.selected_action {
        0 => submit_approve_action(app),
        1 => submit_learn_action(app),
        2 => submit_verify_action(app),
        3 => submit_replay_action(app),
        4 => submit_export_action(app),
        _ => {}
    }
}

pub(crate) fn submit_approve_action(app: &mut App) {
    let tool_id = app.actions.approve_tool_id.trim();
    if tool_id.is_empty() {
        app.actions.error = Some("tool id is required".to_string());
        return;
    }
    let input_ref = app.actions.approve_input_ref.trim();
    if input_ref.is_empty() {
        app.actions.error = Some("input ref is required".to_string());
        return;
    }
    let runtime = app.runtime_root.to_string_lossy().to_string();
    let mut args = vec![
        "approve".to_string(),
        "--runtime".to_string(),
        runtime,
        "--tool".to_string(),
        tool_id.to_string(),
        "--input-ref".to_string(),
        input_ref.to_string(),
    ];
    let run_id = app.actions.approve_run_id.trim();
    if !run_id.is_empty() {
        args.push("--run-id".to_string());
        args.push(run_id.to_string());
    }
    spawn_serverd_action(app, args, "approve");
}

pub(crate) fn submit_learn_action(app: &mut App) {
    let text = app.actions.learn_text.trim();
    if text.is_empty() {
        app.actions.error = Some("text is required".to_string());
        return;
    }
    let runtime = app.runtime_root.to_string_lossy().to_string();
    let mut args = vec![
        "learn".to_string(),
        "--runtime".to_string(),
        runtime,
        "--text".to_string(),
        app.actions.learn_text.clone(),
    ];
    let tags = app.actions.learn_tags.trim();
    if !tags.is_empty() {
        args.push("--tags".to_string());
        args.push(tags.to_string());
    }
    let source = app.actions.learn_source.trim();
    if !source.is_empty() {
        args.push("--source".to_string());
        args.push(source.to_string());
    }
    spawn_serverd_action(app, args, "learn");
}

pub(crate) fn submit_verify_action(app: &mut App) {
    let runtime = app.runtime_root.to_string_lossy().to_string();
    let mut args = vec!["verify".to_string(), "--runtime".to_string(), runtime];
    let run_id = app.actions.verify_run_id.trim();
    if !run_id.is_empty() {
        args.push("--run-id".to_string());
        args.push(run_id.to_string());
    }
    spawn_serverd_action(app, args, "verify");
}
fn audit_inner_event(root: &Value) -> Option<&Value> {
    if let Some(event) = root.get("event").and_then(|v| v.get("event")) {
        return Some(event);
    }
    if let Some(event) = root.get("event") {
        return Some(event);
    }
    Some(root)
}
fn is_safe_task_id(task_id: &str) -> bool {
    if task_id.is_empty() || task_id == "." || task_id == ".." {
        return false;
    }
    task_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn task_file_exists(runtime_root: &Path, task_id: &str) -> bool {
    if !is_safe_task_id(task_id) {
        return false;
    }
    runtime_root
        .join("tasks")
        .join(format!("{}.json", task_id))
        .is_file()
}

fn task_id_from_request_hash(request_hash: &str) -> Option<String> {
    let hash = request_hash.strip_prefix("sha256:").unwrap_or(request_hash);
    if hash.is_empty() {
        return None;
    }
    Some(format!("req-{}", hash))
}

fn task_id_from_task_files_for_run_id(runtime_root: &Path, run_id: &str) -> Option<String> {
    let tasks_dir = runtime_root.join("tasks");
    let read_dir = std::fs::read_dir(tasks_dir).ok()?;
    let mut matches: Vec<String> = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|v| v.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if !name.ends_with(".json") || name.ends_with(".status.json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let task_run_id = value.get("run_id").and_then(|v| v.as_str());
        if task_run_id != Some(run_id) {
            continue;
        }
        let task_id = match value.get("task_id").and_then(|v| v.as_str()) {
            Some(task_id) => task_id,
            None => continue,
        };
        if is_safe_task_id(task_id) {
            matches.push(task_id.to_string());
        }
    }
    if matches.is_empty() {
        return None;
    }
    matches.sort();
    matches.dedup();
    matches.into_iter().next()
}

fn has_persisted_task_files(runtime_root: &Path) -> bool {
    let tasks_dir = runtime_root.join("tasks");
    let read_dir = match std::fs::read_dir(tasks_dir) {
        Ok(read_dir) => read_dir,
        Err(_) => return false,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|v| v.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if name.ends_with(".json") && !name.ends_with(".status.json") {
            return true;
        }
    }
    false
}

fn replay_task_id_for_run_id(app: &App, run_id: &str) -> Option<String> {
    let mut in_run = false;
    let mut task_id: Option<String> = None;
    let mut request_hashes: Vec<String> = Vec::new();
    for root in app.audit.events.iter() {
        let event = match audit_inner_event(root) {
            Some(event) => event,
            None => continue,
        };
        let event_type = match event.get("event_type").and_then(|v| v.as_str()) {
            Some(event_type) => event_type,
            None => continue,
        };
        if event_type == "run_started" {
            let event_run_id = event.get("run_id").and_then(|v| v.as_str());
            if in_run {
                return None;
            }
            if event_run_id == Some(run_id) {
                in_run = true;
            }
            continue;
        }
        if !in_run {
            continue;
        }
        if task_id.is_none() {
            if let Some(candidate) = event.get("task_id").and_then(|v| v.as_str()) {
                if is_safe_task_id(candidate) {
                    task_id = Some(candidate.to_string());
                }
            }
        }
        if let Some(request_hash) = event.get("request_hash").and_then(|v| v.as_str()) {
            request_hashes.push(request_hash.to_string());
        }
        if event_type == "run_completed" {
            if let Some(completed_run_id) = event.get("run_id").and_then(|v| v.as_str()) {
                if completed_run_id != run_id {
                    return None;
                }
            }
            break;
        }
    }
    if task_id.is_some() {
        return task_id;
    }
    if let Some(task_id) = task_id_from_task_files_for_run_id(&app.runtime_root, run_id) {
        return Some(task_id);
    }
    for request_hash in request_hashes.iter().rev() {
        let candidate = match task_id_from_request_hash(request_hash) {
            Some(candidate) => candidate,
            None => continue,
        };
        if task_file_exists(&app.runtime_root, &candidate) {
            return Some(candidate);
        }
    }
    None
}

pub(crate) fn submit_replay_action(app: &mut App) {
    let run_id = app.actions.replay_run_id.trim();
    if run_id.is_empty() {
        app.actions.error = Some("run id is required".to_string());
        return;
    }
    let task_id = match replay_task_id_for_run_id(app, run_id) {
        Some(task_id) => task_id,
        None => {
            app.actions.error = Some("no replayable task found for run id".to_string());
            return;
        }
    };
    if task_id.is_empty() {
        app.actions.error = Some("no replayable task found for run id".to_string());
        return;
    }
    let runtime = app.runtime_root.to_string_lossy().to_string();
    let args = vec![
        "replay".to_string(),
        "--runtime".to_string(),
        runtime,
        "--task".to_string(),
        task_id,
    ];
    spawn_serverd_action(app, args, "replay");
}

pub(crate) fn submit_export_action(app: &mut App) {
    let run_id = app.actions.export_run_id.trim();
    if run_id.is_empty() {
        app.actions.error = Some("run id is required".to_string());
        return;
    }
    let runtime = app.runtime_root.to_string_lossy().to_string();
    let mut args = vec![
        "capsule".to_string(),
        "export".to_string(),
        "--runtime".to_string(),
        runtime,
        "--run-id".to_string(),
        run_id.to_string(),
    ];
    let out = app.actions.export_out.trim();
    if !out.is_empty() {
        args.push("--out".to_string());
        args.push(out.to_string());
    }
    spawn_serverd_action(app, args, "export");
}

pub(crate) fn handle_actions_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Tab => {
            app.actions.focus =
                actions_next_focus(app.actions.selected_action, app.actions.focus, false);
            return true;
        }
        KeyCode::BackTab => {
            app.actions.focus =
                actions_next_focus(app.actions.selected_action, app.actions.focus, true);
            return true;
        }
        KeyCode::Enter => {
            if actions_focus_is_submit(app.actions.focus) {
                submit_selected_action(app);
            }
            return true;
        }
        KeyCode::Backspace => {
            if let Some(target) = actions_input_mut(app) {
                target.pop();
                return true;
            }
        }
        KeyCode::Up => {
            move_selection(app, -1);
            return true;
        }
        KeyCode::Down => {
            move_selection(app, 1);
            return true;
        }
        KeyCode::Char(c) => {
            if actions_focus_is_input(app.actions.focus)
                && (key.modifiers == KeyModifiers::NONE || key.modifiers == KeyModifiers::SHIFT)
            {
                if let Some(target) = actions_input_mut(app) {
                    target.push(c);
                }
                return true;
            }
            match c {
                'j' => {
                    move_selection(app, 1);
                    return true;
                }
                'k' => {
                    move_selection(app, -1);
                    return true;
                }
                _ => {}
            }
        }
        _ => {}
    }
    false
}

pub(crate) fn push_action_input(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: &str,
    focused: bool,
    placeholder: &str,
    focus_style: Style,
    normal_style: Style,
) {
    let display = if value.is_empty() { placeholder } else { value };
    let mut text = format!("{}: {}", label, display);
    if focused {
        text.push('_');
    }
    let style = if focused { focus_style } else { normal_style };
    lines.push(Line::from(Span::styled(text, style)));
}

pub(crate) fn push_action_button(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    focused: bool,
    focus_style: Style,
    normal_style: Style,
) {
    let style = if focused { focus_style } else { normal_style };
    lines.push(Line::from(Span::styled(label.to_string(), style)));
}

pub(crate) fn draw_actions_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)].as_ref())
        .split(area);
    set_detail_height(app, crate::model::Tab::Actions, inner_height(chunks[1]));

    let items: Vec<ListItem> = (0..ACTION_COUNT)
        .map(|idx| ListItem::new(action_label(idx)))
        .collect();
    render_list(
        f,
        chunks[0],
        items,
        app.actions.selected_action,
        "Actions",
        theme,
        list_offset_mut(app, crate::model::Tab::Actions),
    );

    let focus_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default().fg(theme.text);
    let mut lines: Vec<Line<'static>> = Vec::new();

    if let Some(err) = app.actions.error.as_ref() {
        lines.push(Line::from(Span::styled(
            format!("Error: {}", err),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }

    lines.push(Line::from(Span::styled(
        format!("Action: {}", action_name(app.actions.selected_action)),
        Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    match app.actions.selected_action {
        0 => {
            lines.push(Line::from("Create tool approval"));
            lines.push(Line::from(""));
            push_action_input(
                &mut lines,
                "Tool ID",
                &app.actions.approve_tool_id,
                app.actions.focus == ActionsFocus::ApproveTool,
                "<required>",
                focus_style,
                normal_style,
            );
            push_action_input(
                &mut lines,
                "Input Ref",
                &app.actions.approve_input_ref,
                app.actions.focus == ActionsFocus::ApproveInput,
                "<required>",
                focus_style,
                normal_style,
            );
            push_action_input(
                &mut lines,
                "Run ID",
                &app.actions.approve_run_id,
                app.actions.focus == ActionsFocus::ApproveRunId,
                "(optional)",
                focus_style,
                normal_style,
            );
            lines.push(Line::from(""));
            push_action_button(
                &mut lines,
                "[ Approve ]",
                app.actions.focus == ActionsFocus::ApproveSubmit,
                focus_style,
                normal_style,
            );
        }
        1 => {
            lines.push(Line::from("Append learning entry"));
            lines.push(Line::from(""));
            push_action_input(
                &mut lines,
                "Text",
                &app.actions.learn_text,
                app.actions.focus == ActionsFocus::LearnText,
                "<required>",
                focus_style,
                normal_style,
            );
            push_action_input(
                &mut lines,
                "Tags (csv)",
                &app.actions.learn_tags,
                app.actions.focus == ActionsFocus::LearnTags,
                "(optional)",
                focus_style,
                normal_style,
            );
            push_action_input(
                &mut lines,
                "Source",
                &app.actions.learn_source,
                app.actions.focus == ActionsFocus::LearnSource,
                "(optional)",
                focus_style,
                normal_style,
            );
            lines.push(Line::from(""));
            push_action_button(
                &mut lines,
                "[ Learn ]",
                app.actions.focus == ActionsFocus::LearnSubmit,
                focus_style,
                normal_style,
            );
        }
        2 => {
            lines.push(Line::from("Verify runtime"));
            lines.push(Line::from(""));
            push_action_input(
                &mut lines,
                "Run ID",
                &app.actions.verify_run_id,
                app.actions.focus == ActionsFocus::VerifyRunId,
                "(optional)",
                focus_style,
                normal_style,
            );
            lines.push(Line::from(""));
            push_action_button(
                &mut lines,
                "[ Verify ]",
                app.actions.focus == ActionsFocus::VerifySubmit,
                focus_style,
                normal_style,
            );
        }
        3 => {
            lines.push(Line::from("Replay run"));
            lines.push(Line::from(""));
            push_action_input(
                &mut lines,
                "Run ID",
                &app.actions.replay_run_id,
                app.actions.focus == ActionsFocus::ReplayRunId,
                "<required>",
                focus_style,
                normal_style,
            );
            if !has_persisted_task_files(&app.runtime_root) {
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Hint: Replay requires persisted tasks under runtime/tasks.",
                ));
            }
            lines.push(Line::from(""));
            push_action_button(
                &mut lines,
                "[ Replay ]",
                app.actions.focus == ActionsFocus::ReplaySubmit,
                focus_style,
                normal_style,
            );
        }
        _ => {
            lines.push(Line::from("Export run capsule"));
            lines.push(Line::from(""));
            push_action_input(
                &mut lines,
                "Run ID",
                &app.actions.export_run_id,
                app.actions.focus == ActionsFocus::ExportRunId,
                "<required>",
                focus_style,
                normal_style,
            );
            push_action_input(
                &mut lines,
                "Out path",
                &app.actions.export_out,
                app.actions.focus == ActionsFocus::ExportOut,
                "(optional, under runtime/exports)",
                focus_style,
                normal_style,
            );
            lines.push(Line::from(""));
            push_action_button(
                &mut lines,
                "[ Export ]",
                app.actions.focus == ActionsFocus::ExportSubmit,
                focus_style,
                normal_style,
            );
        }
    }

    render_text_panel(
        f,
        chunks[1],
        lines,
        "Action Details",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Actions),
    );
}

#[cfg(test)]
mod tests {
    use super::replay_task_id_for_run_id;
    use crate::model::App;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_runtime_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "operator_tui_actions_{}_{}_{}",
            prefix,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(path.join("logs")).expect("create logs dir");
        std::fs::create_dir_all(path.join("state")).expect("create state dir");
        path
    }

    fn event(event_type: &str, fields: serde_json::Value) -> serde_json::Value {
        let mut event = serde_json::Map::new();
        event.insert(
            "event_type".to_string(),
            serde_json::Value::String(event_type.to_string()),
        );
        if let Some(object) = fields.as_object() {
            for (k, v) in object {
                event.insert(k.to_string(), v.clone());
            }
        }
        json!({
            "event": {
                "schema": "serverd.audit.v1",
                "event": serde_json::Value::Object(event)
            }
        })
    }

    #[test]
    fn replay_task_id_resolves_from_run_window_task_id() {
        let runtime_root = make_runtime_dir("window_task");
        let mut app = App::new(runtime_root.clone(), None);
        let run_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        app.audit.events = vec![
            event("run_started", json!({ "run_id": run_id })),
            event(
                "task_applied",
                json!({
                    "task_id": "req-1111111111111111111111111111111111111111111111111111111111111111",
                    "state_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }),
            ),
            event(
                "run_completed",
                json!({
                    "run_id": run_id,
                    "final_state_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                }),
            ),
        ];
        let resolved = replay_task_id_for_run_id(&app, run_id);
        assert_eq!(
            resolved.as_deref(),
            Some("req-1111111111111111111111111111111111111111111111111111111111111111")
        );
        let _ = std::fs::remove_dir_all(runtime_root);
    }

    #[test]
    fn replay_task_id_falls_back_to_task_file_run_id() {
        let runtime_root = make_runtime_dir("task_file_run_id");
        std::fs::create_dir_all(runtime_root.join("tasks")).expect("create tasks dir");
        let task_id = "req-2222222222222222222222222222222222222222222222222222222222222222";
        let run_id = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let task_value = json!({
            "task_id": task_id,
            "tick_index": 0,
            "intent": { "kind": "no_op" },
            "run_id": run_id
        });
        std::fs::write(
            runtime_root.join("tasks").join(format!("{}.json", task_id)),
            serde_json::to_vec(&task_value).expect("serialize task"),
        )
        .expect("write task file");

        let mut app = App::new(runtime_root.clone(), None);
        app.audit.events = vec![
            event("run_started", json!({ "run_id": run_id })),
            event(
                "run_completed",
                json!({
                    "run_id": run_id,
                    "final_state_hash": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                }),
            ),
        ];
        let resolved = replay_task_id_for_run_id(&app, run_id);
        assert_eq!(resolved.as_deref(), Some(task_id));
        let _ = std::fs::remove_dir_all(runtime_root);
    }

    #[test]
    fn replay_task_id_falls_back_to_request_hash_task_file() {
        let runtime_root = make_runtime_dir("request_hash");
        std::fs::create_dir_all(runtime_root.join("tasks")).expect("create tasks dir");
        let hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let request_hash = format!("sha256:{}", hash);
        let task_id = format!("req-{}", hash);
        let task_value = json!({
            "task_id": task_id,
            "tick_index": 0,
            "intent": { "kind": "no_op" }
        });
        std::fs::write(
            runtime_root.join("tasks").join(format!("{}.json", task_id)),
            serde_json::to_vec(&task_value).expect("serialize task"),
        )
        .expect("write task file");

        let run_id = "sha256:abababababababababababababababababababababababababababababababab";
        let mut app = App::new(runtime_root.clone(), None);
        app.audit.events = vec![
            event("run_started", json!({ "run_id": run_id })),
            event(
                "tick_completed",
                json!({
                    "tick_index": 0,
                    "request_hash": request_hash,
                    "state_hash": "sha256:1212121212121212121212121212121212121212121212121212121212121212"
                }),
            ),
            event(
                "run_completed",
                json!({
                    "run_id": run_id,
                    "final_state_hash": "sha256:3434343434343434343434343434343434343434343434343434343434343434"
                }),
            ),
        ];
        let resolved = replay_task_id_for_run_id(&app, run_id);
        assert_eq!(resolved.as_deref(), Some(task_id.as_str()));
        let _ = std::fs::remove_dir_all(runtime_root);
    }
    #[test]
    fn replay_task_id_ignores_unsafe_task_id_values() {
        let runtime_root = make_runtime_dir("unsafe_task_id");
        let run_id = "sha256:0101010101010101010101010101010101010101010101010101010101010101";
        let mut app = App::new(runtime_root.clone(), None);
        app.audit.events = vec![
            event("run_started", json!({ "run_id": run_id })),
            event(
                "task_replay_requested",
                json!({
                    "task_id": "sha256:badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"
                }),
            ),
            event(
                "run_completed",
                json!({
                    "run_id": run_id,
                    "final_state_hash": "sha256:2323232323232323232323232323232323232323232323232323232323232323"
                }),
            ),
        ];
        let resolved = replay_task_id_for_run_id(&app, run_id);
        assert_eq!(resolved, None);
        let _ = std::fs::remove_dir_all(runtime_root);
    }

    #[test]
    fn replay_task_id_returns_none_when_no_replayable_task() {
        let runtime_root = make_runtime_dir("no_match");
        let run_id = "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let mut app = App::new(runtime_root.clone(), None);
        app.audit.events = vec![
            event("run_started", json!({ "run_id": run_id })),
            event(
                "run_completed",
                json!({
                    "run_id": run_id,
                    "final_state_hash": "sha256:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
                }),
            ),
        ];
        let resolved = replay_task_id_for_run_id(&app, run_id);
        assert_eq!(resolved, None);
        let _ = std::fs::remove_dir_all(runtime_root);
    }
}
