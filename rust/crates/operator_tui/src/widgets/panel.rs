use crate::model::Theme;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use std::cmp::min;

pub(crate) fn inner_height(area: ratatui::layout::Rect) -> usize {
    area.height.saturating_sub(2) as usize
}

pub(crate) fn render_list(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    items: Vec<ListItem>,
    selected: usize,
    title: &str,
    theme: &Theme,
    offset: &mut usize,
) {
    let available = inner_height(area);
    if items.is_empty() || available == 0 {
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .style(Style::default().fg(theme.text)),
            )
            .highlight_style(
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            );
        let mut state = ListState::default();
        f.render_stateful_widget(list, area, &mut state);
        return;
    }
    if selected < *offset {
        *offset = selected;
    } else if selected >= *offset + available {
        *offset = selected + 1 - available;
    }
    let max_offset = items.len().saturating_sub(available);
    if *offset > max_offset {
        *offset = max_offset;
    }
    let end = min(*offset + available, items.len());
    let visible: Vec<ListItem> = items[*offset..end].to_vec();
    let mut state = ListState::default();
    state.select(Some(selected - *offset));
    let list = List::new(visible)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().fg(theme.text)),
        )
        .highlight_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut state);
}

pub(crate) fn render_text_panel(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    lines: Vec<Line<'static>>,
    title: &str,
    theme: &Theme,
    scroll: &mut usize,
) {
    let available = inner_height(area);
    let max_scroll = lines.len().saturating_sub(available);
    if *scroll > max_scroll {
        *scroll = max_scroll;
    }
    let scroll_u16 = min(*scroll, u16::MAX as usize) as u16;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().fg(theme.text));
    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .scroll((scroll_u16, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

pub(crate) fn render_error_panel(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    title: &str,
    message: &str,
    theme: &Theme,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().fg(theme.text));
    let paragraph = Paragraph::new(message)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}
