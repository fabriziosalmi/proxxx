use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::app::{AppState, ApprovalStatus};
use crate::tui::theme::Theme;

/// Render the HITL Approval Queue
pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(8),    // table
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(" HITL approvals ", Theme::title()),
        Span::styled(
            format!(" {} pending ", state.pending_approvals.len()),
            Theme::dim(),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(title, chunks[0]);

    if state.pending_approvals.is_empty() {
        f.render_widget(
            Paragraph::new(" No pending approvals.").style(Theme::dim()),
            chunks[1],
        );
        return;
    }

    let header = Row::new(vec!["status", "txn id", "description"])
        .style(Theme::header())
        .height(1);

    let rows: Vec<Row> = state
        .pending_approvals
        .iter()
        .map(|approval| {
            let (label, style) = match approval.status {
                ApprovalStatus::Pending => ("pending", Theme::dim()),
                ApprovalStatus::Approved => ("approved", Style::default().fg(Theme::ONLINE)),
                ApprovalStatus::Denied => ("denied", Style::default().fg(Theme::DANGER)),
                ApprovalStatus::Timeout => ("timeout", Style::default().fg(Theme::WARNING)),
            };

            Row::new(vec![
                label.to_string(),
                approval.txn_id.clone(),
                approval.description.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(10), // status
        Constraint::Length(20), // txn
        Constraint::Min(30),    // desc
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        )
        .row_highlight_style(Theme::selected());

    f.render_widget(table, chunks[1]);
}
