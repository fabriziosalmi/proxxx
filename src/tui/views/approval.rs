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
        Span::styled(" 🛡️ ", Style::default().fg(Theme::ACCENT)),
        Span::styled("HITL Approval Gateway", Theme::title()),
        Span::styled(
            format!("  ({} operations)", state.pending_approvals.len()),
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

    let header = Row::new(vec!["STATUS", "TXN ID", "DESCRIPTION"])
        .style(Theme::header())
        .height(1);

    let rows: Vec<Row> = state
        .pending_approvals
        .iter()
        .map(|approval| {
            let (icon, style) = match approval.status {
                ApprovalStatus::Pending => ("⏳ PENDING", Theme::dim()),
                ApprovalStatus::Approved => ("✅ APPROVED", Style::default().fg(Theme::ONLINE)),
                ApprovalStatus::Denied => ("❌ DENIED", Style::default().fg(Theme::DANGER)),
                ApprovalStatus::Timeout => ("⏰ TIMEOUT", Style::default().fg(Theme::WARNING)),
            };

            Row::new(vec![
                icon.to_string(),
                approval.txn_id.clone(),
                approval.description.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(12), // status
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
