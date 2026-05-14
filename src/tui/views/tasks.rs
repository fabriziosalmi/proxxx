use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;

/// Render the Live Task Log viewer
pub fn draw(f: &mut Frame, area: Rect, state: &AppState, upid: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(10),   // log view
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(" Live task log ", Theme::title()),
        Span::styled(format!(" upid {upid} "), Theme::dim()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(title, chunks[0]);

    if state.current_task_log.is_empty() {
        f.render_widget(
            Paragraph::new(" waiting for logs…").style(Theme::dim()),
            chunks[1],
        );
        return;
    }

    // Auto-scroll logic: keep the latest lines at the bottom if it exceeds height
    let visible_height = chunks[1].height.saturating_sub(2) as usize; // account for borders
    let total_lines = state.current_task_log.len();

    let start_idx = total_lines.saturating_sub(visible_height);

    let log_lines: Vec<Line> = state.current_task_log[start_idx..]
        .iter()
        .map(|log| {
            // highlight keywords like "TASK OK", "ERROR"
            let t = &log.t;
            let style = if t.contains("TASK OK") {
                Style::default().fg(Theme::SUCCESS)
            } else if t.contains("ERROR") || t.contains("FAILED") {
                Style::default().fg(Theme::DANGER)
            } else if t.contains("WARNING") {
                Style::default().fg(Theme::WARNING)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(format!("{:>4} | ", log.n), Theme::dim()),
                Span::styled(t.clone(), style),
            ])
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border());
    f.render_widget(Paragraph::new(log_lines).block(block), chunks[1]);
}
