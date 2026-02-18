use crate::model::{App, Theme};
use crate::tabs;
use crate::widgets::status::draw_status;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};

pub(crate) fn draw_ui(f: &mut ratatui::Frame, app: &mut App, theme: &Theme) {
    if !app.runtime_valid {
        let area = f.size();
        let block = Block::default()
            .title("Runtime Error")
            .borders(Borders::ALL)
            .style(Style::default().fg(theme.text));
        let message = app
            .runtime_error
            .clone()
            .unwrap_or_else(|| "runtime path invalid".to_string());
        let paragraph = Paragraph::new(message)
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(paragraph, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(2),
            ]
            .as_ref(),
        )
        .split(f.size());

    draw_tabs(f, chunks[0], app, theme);
    draw_content(f, chunks[1], app, theme);
    draw_status(f, chunks[2], app, theme);
}

pub(crate) fn draw_tabs(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &App,
    theme: &Theme,
) {
    let titles = tabs::tab_titles()
        .iter()
        .map(|title| Line::from(Span::raw(*title)))
        .collect::<Vec<Line>>();
    let tabs = Tabs::new(titles)
        .select(app.active_tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(theme.text)),
        )
        .highlight_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
        .style(Style::default().fg(theme.text));
    f.render_widget(tabs, area);
}

pub(crate) fn draw_content(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &mut App,
    theme: &Theme,
) {
    tabs::draw_current_tab(f, area, app, theme);
}
