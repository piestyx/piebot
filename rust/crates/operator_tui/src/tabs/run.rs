use crate::app::{detail_scroll_mut, set_detail_height};
use crate::commands::{launch_serverd, stop_process};
use crate::config::read_flag_envs;
use crate::model::{App, RunFocus, Theme};
use crate::widgets::panel::{inner_height, render_text_panel};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

pub(crate) fn run_focus_label(focus: RunFocus) -> &'static str {
    match focus {
        RunFocus::Skill => "skill",
        RunFocus::Mode => "mode",
        RunFocus::Delta => "delta",
        RunFocus::Launch => "launch",
    }
}

pub(crate) fn run_move_selection(app: &mut App, delta: i32) {
    match app.run.focus {
        RunFocus::Skill => {
            let len = app.run.skill_ids.len();
            if len == 0 {
                return;
            }
            let mut next = app.run.skill_selected as i32 + delta;
            if next < 0 {
                next = 0;
            }
            if next as usize >= len {
                next = (len - 1) as i32;
            }
            if app.run.skill_selected != next as usize {
                app.run.skill_selected = next as usize;
            }
        }
        RunFocus::Mode => {
            let len = 2;
            let mut next = app.run.mode_selected as i32 + delta;
            if next < 0 {
                next = 0;
            }
            if next as usize >= len {
                next = (len - 1) as i32;
            }
            app.run.mode_selected = next as usize;
        }
        _ => {}
    }
}

pub(crate) fn handle_run_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Tab => {
            app.run.focus = match app.run.focus {
                RunFocus::Skill => RunFocus::Mode,
                RunFocus::Mode => RunFocus::Delta,
                RunFocus::Delta => RunFocus::Launch,
                RunFocus::Launch => RunFocus::Skill,
            };
            return true;
        }
        KeyCode::BackTab => {
            app.run.focus = match app.run.focus {
                RunFocus::Skill => RunFocus::Launch,
                RunFocus::Mode => RunFocus::Skill,
                RunFocus::Delta => RunFocus::Mode,
                RunFocus::Launch => RunFocus::Delta,
            };
            return true;
        }
        KeyCode::Enter => {
            if matches!(app.run.focus, RunFocus::Launch) {
                launch_serverd(app);
            }
            return true;
        }
        KeyCode::Char('l') => {
            launch_serverd(app);
            return true;
        }
        KeyCode::Char('s') => {
            stop_process(app);
            return true;
        }
        KeyCode::Backspace => {
            if matches!(app.run.focus, RunFocus::Delta) {
                app.run.delta_input.pop();
                return true;
            }
        }
        KeyCode::Char(c) => {
            if matches!(app.run.focus, RunFocus::Delta)
                && key.modifiers == KeyModifiers::NONE
                && !matches!(c, 'q' | 'r' | 'g' | 'G')
            {
                app.run.delta_input.push(c);
                return true;
            }
        }
        _ => {}
    }
    false
}

pub(crate) fn draw_run_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    set_detail_height(app, crate::model::Tab::Run, inner_height(area));
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(err) = app.run.error.as_ref() {
        lines.push(Line::from(Span::styled(
            format!("Error: {}", err),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }
    let focus_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default().fg(theme.text);

    let skill_label = if app.run.skill_ids.is_empty() {
        "No skills present".to_string()
    } else {
        app.run.skill_ids[app.run.skill_selected].clone()
    };
    let skill_style = if matches!(app.run.focus, RunFocus::Skill) {
        focus_style
    } else {
        normal_style
    };
    lines.push(Line::from(Span::styled(
        format!("Skill: {}", skill_label),
        skill_style,
    )));

    let modes = ["null", "route"];
    let mode_value = modes.get(app.run.mode_selected).copied().unwrap_or("null");
    let mode_style = if matches!(app.run.focus, RunFocus::Mode) {
        focus_style
    } else {
        normal_style
    };
    lines.push(Line::from(Span::styled(
        format!("Mode: {}", mode_value),
        mode_style,
    )));

    let delta_display = if matches!(app.run.focus, RunFocus::Delta) {
        format!("Delta: {}_", app.run.delta_input)
    } else {
        format!("Delta: {}", app.run.delta_input)
    };
    let delta_style = if matches!(app.run.focus, RunFocus::Delta) {
        focus_style
    } else {
        normal_style
    };
    lines.push(Line::from(Span::styled(delta_display, delta_style)));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Flags:",
        Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
    )));
    for (name, value) in read_flag_envs() {
        lines.push(Line::from(Span::styled(
            format!("  {}={}", name, value),
            normal_style,
        )));
    }

    lines.push(Line::from(""));
    let run_style = if matches!(app.run.focus, RunFocus::Launch) {
        focus_style
    } else {
        normal_style
    };
    lines.push(Line::from(Span::styled("[ Run ]", run_style)));
    let stop_line = if app.process.running {
        "[ Stop ]".to_string()
    } else {
        "[ Stop ] (idle)".to_string()
    };
    let stop_style = if app.process.running {
        normal_style
    } else {
        normal_style.add_modifier(Modifier::DIM)
    };
    lines.push(Line::from(Span::styled(stop_line, stop_style)));

    render_text_panel(
        f,
        area,
        lines,
        "Run Launcher",
        theme,
        detail_scroll_mut(app, crate::model::Tab::Run),
    );
}
