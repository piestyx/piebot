pub mod actions;
pub mod artifacts;
pub mod audit;
pub mod capsule;
pub mod conversations;
pub mod explain;
pub mod logs;
pub mod run;
pub mod skills;

use crate::model::{App, Tab, Theme};

pub(crate) fn tab_titles() -> [&'static str; 8] {
    [
        "Run",
        "Audit",
        "Artifacts",
        "Capsule",
        "Explain",
        "Skills",
        "Logs",
        "Actions",
    ]
}

pub(crate) fn draw_current_tab(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    match app.active_tab {
        Tab::Run => run::draw_run_tab(f, area, app, theme),
        Tab::Audit => audit::draw_audit_tab(f, area, app, theme),
        Tab::Artifacts => artifacts::draw_artifacts_tab(f, area, app, theme),
        Tab::Capsule => capsule::draw_capsule_tab(f, area, app, theme),
        Tab::Explain => explain::draw_explain_tab(f, area, app, theme),
        Tab::Skills => skills::draw_skills_tab(f, area, app, theme),
        Tab::Logs => logs::draw_logs_tab(f, area, app, theme),
        Tab::Actions => actions::draw_actions_tab(f, area, app, theme),
    }
}

pub(crate) fn handle_current_tab_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    match app.active_tab {
        Tab::Run => run::handle_run_key(app, key),
        Tab::Actions => actions::handle_actions_key(app, key),
        _ => false,
    }
}
