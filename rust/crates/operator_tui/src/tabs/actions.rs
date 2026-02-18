use crate::app::{detail_scroll_mut, list_offset_mut, set_detail_height};
use crate::commands::run_serverd_operator;
use crate::data::operator_snapshot::{
    approval_file_path, artifact_path_for_ref, load_operator_snapshot, read_json_file,
};
use crate::model::{App, OperatorPrompt, Theme};
use crate::widgets::panel::{inner_height, render_error_panel, render_list, render_text_panel};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::ListItem;
use serde_json::Value;

pub(crate) fn refresh_operator_snapshot(app: &mut App) {
    match load_operator_snapshot(&app.runtime_root) {
        Ok(snapshot) => {
            app.actions.runs = snapshot.runs;
            app.actions.pending_approvals = snapshot.pending_approvals;
            if app.actions.selected_run >= app.actions.runs.len() {
                app.actions.selected_run = app.actions.runs.len().saturating_sub(1);
            }
            if app.actions.selected_approval >= app.actions.pending_approvals.len() {
                app.actions.selected_approval =
                    app.actions.pending_approvals.len().saturating_sub(1);
            }
            app.actions.error = None;
        }
        Err(err) => {
            app.actions.runs.clear();
            app.actions.pending_approvals.clear();
            app.actions.selected_run = 0;
            app.actions.selected_approval = 0;
            app.actions.error = Some(err);
        }
    }
}

pub(crate) fn operator_prompt_active(app: &App) -> bool {
    app.actions.prompt != OperatorPrompt::None
}

fn run_operator_with_args(app: &App, args: Vec<String>) -> Result<Value, String> {
    let refs: Vec<&str> = args.iter().map(|v| v.as_str()).collect();
    run_serverd_operator(app, &refs)
}

fn selected_run(app: &App) -> Option<&crate::model::RunSummary> {
    app.actions.runs.get(app.actions.selected_run)
}

fn selected_approval(app: &App) -> Option<&crate::model::PendingApproval> {
    app.actions
        .pending_approvals
        .get(app.actions.selected_approval)
}

fn prompt_title(prompt: OperatorPrompt) -> &'static str {
    match prompt {
        OperatorPrompt::ApproveReason => "approve reason",
        OperatorPrompt::RefuseReason => "refuse reason",
        OperatorPrompt::ExportDest => "export destination path",
        OperatorPrompt::LearnSkillId => "learning skill_id",
        OperatorPrompt::LearnText => "learning text",
        OperatorPrompt::None => "",
    }
}

fn clear_prompt(app: &mut App) {
    app.actions.prompt = OperatorPrompt::None;
    app.actions.prompt_input.clear();
    app.actions.prompt_aux_input.clear();
}

fn execute_replay_verify(app: &mut App) {
    let run_id = match selected_run(app).map(|run| run.run_id.clone()) {
        Some(value) => value,
        None => {
            app.actions.error = Some("no run selected".to_string());
            return;
        }
    };
    let output = run_operator_with_args(
        app,
        vec![
            "replay-verify".to_string(),
            "--run-id".to_string(),
            run_id.clone(),
        ],
    );
    match output {
        Ok(value) => {
            app.actions.last_output = Some(value);
            app.actions.info = Some(format!("replay-verify complete for {}", run_id));
            app.actions.error = None;
            refresh_operator_snapshot(app);
            app.actions.detail_open = true;
        }
        Err(err) => {
            app.actions.error = Some(err);
        }
    }
}

fn execute_capsule_export(app: &mut App, out_path: String) {
    let run_id = match selected_run(app).map(|run| run.run_id.clone()) {
        Some(value) => value,
        None => {
            app.actions.error = Some("no run selected".to_string());
            return;
        }
    };
    let output = run_operator_with_args(
        app,
        vec![
            "capsule-export".to_string(),
            "--run-id".to_string(),
            run_id.clone(),
            "--out".to_string(),
            out_path.clone(),
        ],
    );
    match output {
        Ok(value) => {
            app.actions.last_output = Some(value);
            app.actions.info = Some(format!("capsule-export complete -> {}", out_path));
            app.actions.error = None;
            refresh_operator_snapshot(app);
        }
        Err(err) => {
            app.actions.error = Some(err);
        }
    }
}

fn execute_approve(app: &mut App, reason: String) {
    let approval = match selected_approval(app).cloned() {
        Some(value) => value,
        None => {
            app.actions.error = Some("no pending approval selected".to_string());
            return;
        }
    };
    let mut args = vec![
        "approve".to_string(),
        "--run-id".to_string(),
        approval.run_id.clone(),
        "--tool-id".to_string(),
        approval.tool_id.clone(),
        "--reason".to_string(),
        reason,
    ];
    if let Some(input_ref) = approval.input_ref.as_ref() {
        args.push("--input-ref".to_string());
        args.push(input_ref.clone());
    }
    let output = run_operator_with_args(app, args);
    match output {
        Ok(value) => {
            app.actions.last_output = Some(value);
            app.actions.info = Some(format!("approved {}", approval.approval_ref));
            app.actions.error = None;
            refresh_operator_snapshot(app);
        }
        Err(err) => {
            app.actions.error = Some(err);
        }
    }
}

fn execute_refuse(app: &mut App, reason: String) {
    let approval = match selected_approval(app).cloned() {
        Some(value) => value,
        None => {
            app.actions.error = Some("no pending approval selected".to_string());
            return;
        }
    };
    let output = run_operator_with_args(
        app,
        vec![
            "refuse".to_string(),
            "--run-id".to_string(),
            approval.run_id.clone(),
            "--tool-id".to_string(),
            approval.tool_id.clone(),
            "--reason".to_string(),
            reason,
        ],
    );
    match output {
        Ok(value) => {
            app.actions.last_output = Some(value);
            app.actions.info = Some(format!("refused {}", approval.approval_ref));
            app.actions.error = None;
            refresh_operator_snapshot(app);
        }
        Err(err) => {
            app.actions.error = Some(err);
        }
    }
}

fn execute_learning_append(app: &mut App, skill_id: String, text: String) {
    let output = run_operator_with_args(
        app,
        vec![
            "learnings".to_string(),
            "append".to_string(),
            "--skill-id".to_string(),
            skill_id,
            "--learning-text".to_string(),
            text,
        ],
    );
    match output {
        Ok(value) => {
            app.actions.last_output = Some(value);
            app.actions.info = Some("learnings append completed".to_string());
            app.actions.error = None;
            refresh_operator_snapshot(app);
        }
        Err(err) => {
            app.actions.error = Some(err);
        }
    }
}

fn handle_prompt_enter(app: &mut App) {
    match app.actions.prompt {
        OperatorPrompt::ApproveReason => {
            let reason = app.actions.prompt_input.trim().to_string();
            if reason.is_empty() {
                app.actions.error = Some("reason is required".to_string());
                return;
            }
            execute_approve(app, reason);
            clear_prompt(app);
        }
        OperatorPrompt::RefuseReason => {
            let reason = app.actions.prompt_input.trim().to_string();
            if reason.is_empty() {
                app.actions.error = Some("reason is required".to_string());
                return;
            }
            execute_refuse(app, reason);
            clear_prompt(app);
        }
        OperatorPrompt::ExportDest => {
            let out_path = app.actions.prompt_input.trim().to_string();
            if out_path.is_empty() {
                app.actions.error = Some("export path is required".to_string());
                return;
            }
            execute_capsule_export(app, out_path);
            clear_prompt(app);
        }
        OperatorPrompt::LearnSkillId => {
            let skill_id = app.actions.prompt_input.trim().to_string();
            if skill_id.is_empty() {
                app.actions.error = Some("skill_id is required".to_string());
                return;
            }
            app.actions.prompt_aux_input = skill_id;
            app.actions.prompt_input.clear();
            app.actions.prompt = OperatorPrompt::LearnText;
        }
        OperatorPrompt::LearnText => {
            let text = app.actions.prompt_input.trim().to_string();
            if text.is_empty() {
                app.actions.error = Some("learning text is required".to_string());
                return;
            }
            let skill_id = app.actions.prompt_aux_input.trim().to_string();
            if skill_id.is_empty() {
                app.actions.error = Some("skill_id is required".to_string());
                return;
            }
            execute_learning_append(app, skill_id, text);
            clear_prompt(app);
        }
        OperatorPrompt::None => {}
    }
}

fn handle_prompt_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            clear_prompt(app);
            true
        }
        KeyCode::Enter => {
            handle_prompt_enter(app);
            true
        }
        KeyCode::Backspace => {
            app.actions.prompt_input.pop();
            true
        }
        KeyCode::Char(c)
            if key.modifiers == KeyModifiers::NONE || key.modifiers == KeyModifiers::SHIFT =>
        {
            app.actions.prompt_input.push(c);
            true
        }
        _ => true,
    }
}

fn move_selection(app: &mut App, delta: i32) {
    if app.actions.approvals_open {
        let len = app.actions.pending_approvals.len();
        if len == 0 {
            app.actions.selected_approval = 0;
            return;
        }
        let mut next = app.actions.selected_approval as i32 + delta;
        if next < 0 {
            next = 0;
        }
        if next as usize >= len {
            next = (len - 1) as i32;
        }
        app.actions.selected_approval = next as usize;
    } else {
        let len = app.actions.runs.len();
        if len == 0 {
            app.actions.selected_run = 0;
            return;
        }
        let mut next = app.actions.selected_run as i32 + delta;
        if next < 0 {
            next = 0;
        }
        if next as usize >= len {
            next = (len - 1) as i32;
        }
        app.actions.selected_run = next as usize;
    }
}

fn jump_top(app: &mut App) {
    if app.actions.approvals_open {
        app.actions.selected_approval = 0;
    } else {
        app.actions.selected_run = 0;
    }
}

fn jump_bottom(app: &mut App) {
    if app.actions.approvals_open {
        app.actions.selected_approval = app.actions.pending_approvals.len().saturating_sub(1);
    } else {
        app.actions.selected_run = app.actions.runs.len().saturating_sub(1);
    }
}

pub(crate) fn handle_actions_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    if app.actions.prompt != OperatorPrompt::None {
        return handle_prompt_key(app, key);
    }
    match key.code {
        KeyCode::Char('a') | KeyCode::Char('A') => {
            app.actions.approvals_open = !app.actions.approvals_open;
            true
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            execute_replay_verify(app);
            true
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            let default_out = selected_run(app)
                .map(|run| {
                    let trimmed = run
                        .run_id
                        .strip_prefix("sha256:")
                        .unwrap_or(run.run_id.as_str());
                    format!("exports/capsule_{}.json", trimmed)
                })
                .unwrap_or_else(|| "exports/capsule.json".to_string());
            app.actions.prompt = OperatorPrompt::ExportDest;
            app.actions.prompt_input = default_out;
            true
        }
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            if !app.actions.approvals_open {
                app.actions.error = Some("press A to open pending approvals".to_string());
                return true;
            }
            app.actions.prompt = OperatorPrompt::ApproveReason;
            app.actions.prompt_input.clear();
            true
        }
        KeyCode::Char('n') | KeyCode::Char('N') => {
            if !app.actions.approvals_open {
                app.actions.error = Some("press A to open pending approvals".to_string());
                return true;
            }
            app.actions.prompt = OperatorPrompt::RefuseReason;
            app.actions.prompt_input.clear();
            true
        }
        KeyCode::Char('l') | KeyCode::Char('L') => {
            app.actions.prompt = OperatorPrompt::LearnSkillId;
            app.actions.prompt_input.clear();
            app.actions.prompt_aux_input.clear();
            true
        }
        KeyCode::Esc => {
            app.actions.approvals_open = false;
            true
        }
        KeyCode::Enter => {
            app.actions.detail_open = !app.actions.detail_open;
            true
        }
        KeyCode::Char('j') | KeyCode::Down => {
            move_selection(app, 1);
            true
        }
        KeyCode::Char('k') | KeyCode::Up => {
            move_selection(app, -1);
            true
        }
        KeyCode::Char('g') => {
            jump_top(app);
            true
        }
        KeyCode::Char('G') => {
            jump_bottom(app);
            true
        }
        _ => false,
    }
}

fn render_verification_detail(
    lines: &mut Vec<Line<'static>>,
    runtime_root: &std::path::Path,
    verification_ref: &str,
) {
    let verification_path =
        artifact_path_for_ref(runtime_root, "operator_replay_verify", verification_ref);
    lines.push(Line::from(format!(
        "verification_ref: {}",
        verification_ref
    )));
    lines.push(Line::from(format!(
        "verification_path: {}",
        verification_path.display()
    )));
    match read_json_file(&verification_path) {
        Ok(value) => {
            let pass = value.get("pass").and_then(|v| v.as_bool());
            let mismatch_location = value.get("mismatch_location").and_then(|v| v.as_str());
            lines.push(Line::from(format!(
                "pass: {}",
                pass.map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            )));
            lines.push(Line::from(format!(
                "mismatch_location: {}",
                mismatch_location.unwrap_or("none")
            )));
            lines.push(Line::from("compared_hashes:"));
            if let Some(map) = value.get("compared_hashes").and_then(|v| v.as_object()) {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for key in keys {
                    let value = map.get(key).and_then(|v| v.as_str()).unwrap_or("?");
                    lines.push(Line::from(format!("  {} = {}", key, value)));
                }
            } else {
                lines.push(Line::from("  (missing compared_hashes)"));
            }
            lines.push(Line::from(""));
            lines.push(Line::from("verification_json:"));
            if let Ok(json_text) = serde_json::to_string_pretty(&value) {
                for line in json_text.lines() {
                    lines.push(Line::from(line.to_string()));
                }
            }
        }
        Err(err) => {
            lines.push(Line::from(format!("verification read error: {}", err)));
        }
    }
}

fn action_help_lines(lines: &mut Vec<Line<'static>>, approvals_open: bool) {
    lines.push(Line::from(""));
    lines.push(Line::from("keys:"));
    lines.push(Line::from("  A toggle approvals list"));
    lines.push(Line::from("  R replay-verify selected run"));
    lines.push(Line::from("  E capsule export selected run"));
    if approvals_open {
        lines.push(Line::from("  Y approve selected pending approval"));
        lines.push(Line::from("  N refuse selected pending approval"));
    } else {
        lines.push(Line::from("  Y/N require approvals modal (press A)"));
    }
    lines.push(Line::from("  L append learning"));
    lines.push(Line::from("  Enter toggle expanded detail"));
}

pub(crate) fn draw_actions_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    if app.actions.error.as_deref() == Some("audit_log_missing") {
        render_error_panel(
            f,
            area,
            "Operator View Error",
            "runtime/logs/audit_rust.jsonl not found",
            theme,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(area);
    set_detail_height(app, crate::model::Tab::Actions, inner_height(chunks[1]));

    let (left_title, selected_index, items): (&str, usize, Vec<ListItem>) =
        if app.actions.approvals_open {
            let items = app
                .actions
                .pending_approvals
                .iter()
                .map(|approval| {
                    let tick = approval
                        .requested_tick_index
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    ListItem::new(format!(
                        "{} {} [{}]",
                        approval.run_id, approval.tool_id, tick
                    ))
                })
                .collect::<Vec<_>>();
            ("Pending Approvals", app.actions.selected_approval, items)
        } else {
            let items = app
                .actions
                .runs
                .iter()
                .map(|run| {
                    let tick = run
                        .last_tick_index
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    ListItem::new(format!("{} [{}] {}", run.run_id, run.status, tick))
                })
                .collect::<Vec<_>>();
            ("Runs", app.actions.selected_run, items)
        };
    render_list(
        f,
        chunks[0],
        items,
        selected_index,
        left_title,
        theme,
        list_offset_mut(app, crate::model::Tab::Actions),
    );

    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(err) = app.actions.error.as_ref() {
        lines.push(Line::from(Span::styled(
            format!("error: {}", err),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }
    if let Some(info) = app.actions.info.as_ref() {
        lines.push(Line::from(format!("info: {}", info)));
        lines.push(Line::from(""));
    }
    if app.actions.prompt != OperatorPrompt::None {
        lines.push(Line::from(format!(
            "prompt [{}]: {}_",
            prompt_title(app.actions.prompt),
            app.actions.prompt_input
        )));
        lines.push(Line::from("enter submit | esc cancel"));
        lines.push(Line::from(""));
    }

    if app.actions.approvals_open {
        lines.push(Line::from("approval detail:"));
        if let Some(approval) = selected_approval(app) {
            lines.push(Line::from(format!("run_id: {}", approval.run_id)));
            lines.push(Line::from(format!("tool_id: {}", approval.tool_id)));
            lines.push(Line::from(format!(
                "approval_ref: {}",
                approval.approval_ref
            )));
            if let Some(input_ref) = approval.input_ref.as_ref() {
                lines.push(Line::from(format!("input_ref: {}", input_ref)));
            }
            if let Some(request_hash) = approval.request_hash.as_ref() {
                lines.push(Line::from(format!("request_hash: {}", request_hash)));
            }
            let approval_path = approval_file_path(&app.runtime_root, &approval.approval_ref);
            lines.push(Line::from(format!(
                "approval_file_path: {}",
                approval_path.display()
            )));
            lines.push(Line::from(format!(
                "approval_file_exists: {}",
                approval_path.is_file()
            )));
        } else {
            lines.push(Line::from("no pending approvals"));
        }
    } else {
        lines.push(Line::from("run detail:"));
        if let Some(run) = selected_run(app) {
            lines.push(Line::from(format!("run_id: {}", run.run_id)));
            lines.push(Line::from(format!("status: {}", run.status)));
            if let Some(last_tick) = run.last_tick_index {
                lines.push(Line::from(format!("last_tick_index: {}", last_tick)));
            }
            if let Some(final_state_hash) = run.final_state_hash.as_ref() {
                lines.push(Line::from(format!(
                    "final_state_hash: {}",
                    final_state_hash
                )));
            }
            if let Some(capsule_ref) = run.capsule_ref.as_ref() {
                let capsule_path =
                    artifact_path_for_ref(&app.runtime_root, "run_capsules", capsule_ref);
                lines.push(Line::from(format!("capsule_ref: {}", capsule_ref)));
                lines.push(Line::from(format!(
                    "capsule_path: {}",
                    capsule_path.display()
                )));
                lines.push(Line::from(format!(
                    "capsule_exists: {}",
                    capsule_path.is_file()
                )));
            }
            if let Some(verification_ref) = run.verification_ref.as_ref() {
                if app.actions.detail_open {
                    render_verification_detail(&mut lines, &app.runtime_root, verification_ref);
                } else {
                    lines.push(Line::from(format!(
                        "verification_ref: {}",
                        verification_ref
                    )));
                    lines.push(Line::from(
                        "press Enter to open verification artifact detail",
                    ));
                }
            } else {
                lines.push(Line::from("verification_ref: (none)"));
            }
        } else {
            lines.push(Line::from("no runs"));
        }
    }

    action_help_lines(&mut lines, app.actions.approvals_open);

    if let Some(last_output) = app.actions.last_output.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::from("last_command_output:"));
        if let Ok(text) = serde_json::to_string_pretty(last_output) {
            for line in text.lines() {
                lines.push(Line::from(line.to_string()));
            }
        }
    }

    render_text_panel(
        f,
        chunks[1],
        lines,
        "Operator Actions",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Actions),
    );
}
