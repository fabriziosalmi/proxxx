use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::app::{AppMode, AppState};
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Search bar
            Constraint::Min(0),    // Results
        ])
        .split(area);

    // 1. Search Bar
    let input_style = if matches!(state.mode, AppMode::ConfigGrep) {
        Style::default().fg(Theme::ACCENT)
    } else {
        Style::default().fg(Theme::TEXT_MUTED)
    };

    let search_bar = Paragraph::new(format!(" Query: {}", state.grep_query)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(input_style)
            .title(" Cluster-wide Config Grep (Enter to search, Esc to exit) "),
    );
    f.render_widget(search_bar, chunks[0]);

    // 2. Results Table
    if state.grep_searching {
        let loading = Paragraph::new("\n\nSearching cluster configurations...")
            .style(Style::default().fg(Theme::ACCENT))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(loading, chunks[1]);
    } else if state.grep_results.is_empty() && !state.grep_query.is_empty() {
        let no_results = Paragraph::new("\n\nNo matches found.")
            .style(Style::default().fg(Theme::TEXT_MUTED))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(no_results, chunks[1]);
    } else {
        let rows: Vec<Row> = state
            .grep_results
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let style = if i == state.selected_index {
                    Theme::selected()
                } else {
                    Style::default().fg(Theme::TEXT)
                };

                Row::new(vec![
                    Cell::from(format!("{}", m.vmid)),
                    Cell::from(m.name.clone()),
                    Cell::from(m.key.clone()).style(Style::default().fg(Theme::ACCENT)),
                    Cell::from(m.value.clone()).style(Style::default().fg(Theme::TEXT_MUTED)),
                ])
                .style(style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(20),
                Constraint::Length(20),
                Constraint::Min(40),
            ],
        )
        .header(
            Row::new(vec!["VMID", "Name", "Key", "Value"])
                .style(
                    Style::default()
                        .fg(Theme::TEXT)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} Matches ", state.grep_results.len())),
        )
        .column_spacing(2);

        f.render_widget(table, chunks[1]);
    }
}
