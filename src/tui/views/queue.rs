use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::app::queue::OpStatus;
use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header/Instructions
            Constraint::Min(5),    // Queue List
        ])
        .split(main_chunks[0]);

    // Truth-in-binds: pre-fix this said "[Q] Back" but Q opens the
    // queue (no-op when already here) and `q` triggers Quit. Esc /
    // h / ← are the actual back chord. "[D] Remove Selected" was
    // advertised but no key was wired — fixed by binding lowercase
    // `d` on this view to Action::DequeueOperation.
    let instruction_text =
        " [j/k] Nav · [d] Remove · [C] Commit & Execute · [R] Refresh · [Esc] Back ";
    let instruction_block = Paragraph::new(instruction_text)
        .style(Style::default().fg(Theme::TEXT_MUTED))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Operation Queue "),
        );
    f.render_widget(instruction_block, chunks[0]);

    if state.op_queue.is_empty() {
        let empty_msg = Paragraph::new(
            "Queue is empty. Press 's', 'S', 'r', 'd' in Guest List to enqueue operations.",
        )
        .style(Style::default().fg(Theme::TEXT_MUTED))
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(empty_msg, chunks[1]);
        let empty_block = Block::default()
            .borders(Borders::ALL)
            .title(" Replay-as-Script ");
        f.render_widget(empty_block, main_chunks[1]);
        return;
    }

    let rows: Vec<Row> = state
        .op_queue
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let style = if i == state.selected_index {
                Theme::selected()
            } else {
                Style::default().fg(Theme::TEXT)
            };

            let status_span = match op.status {
                OpStatus::Pending => {
                    Span::styled("Pending", Style::default().fg(Theme::TEXT_MUTED))
                }
                OpStatus::Running => Span::styled(
                    "Running...",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                OpStatus::Success => Span::styled("Success", Style::default().fg(Theme::SUCCESS)),
                OpStatus::Error(ref err) => {
                    Span::styled(format!("Error: {err}"), Style::default().fg(Theme::DANGER))
                }
            };

            Row::new(vec![
                Line::from(op.description.clone()),
                Line::from(Span::styled(
                    op.diff.clone(),
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(status_span),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(40),
        Constraint::Percentage(20),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Operation", "State Diff", "Status"])
                .style(
                    Style::default()
                        .fg(Theme::TEXT_MUTED)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
        )
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Theme::selected());

    f.render_widget(table, chunks[1]);

    if let Some(op) = state.op_queue.get(state.selected_index) {
        let script = op.export_script(state);
        let script_block = Paragraph::new(script)
            .style(Style::default().fg(Theme::TEXT))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Replay-as-Script "),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });
        f.render_widget(script_block, main_chunks[1]);
    } else {
        let empty_block = Block::default()
            .borders(Borders::ALL)
            .title(" Replay-as-Script ");
        f.render_widget(empty_block, main_chunks[1]);
    }
}
