use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    widgets::{Block, Borders, Clear, Paragraph, Row, Table},
    Frame,
};

use crate::app::search::SearchItem;
use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let query = &state.search_query;

    // Create centered modal rect
    let popup_area = centered_rect(60, 60, area);

    f.render_widget(Clear, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Input
            Constraint::Min(5),    // Results
        ])
        .split(popup_area);

    // 1. Input Box
    let input_text = format!("> {query}");
    let input_block = Paragraph::new(input_text)
        .style(Style::default().fg(Theme::TEXT))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border_focus())
                .title(" Instant Search (/ to filter, Enter to select) "),
        );
    f.render_widget(input_block, chunks[0]);

    // 2. Results
    let results = crate::app::search::get_search_results(state);

    let result_rows: Vec<Row> = results
        .iter()
        .enumerate()
        .map(|(i, (_score, item))| {
            let style = if i == state.selected_index {
                Theme::selected()
            } else {
                Style::default().fg(Theme::TEXT_MUTED)
            };

            let (icon, main_text, sub_text) = match item {
                SearchItem::Node { name, status } => ("node", name.clone(), status.clone()),
                SearchItem::Guest {
                    vmid, name, node, ..
                } => ("guest", format!("{vmid} ({name})"), format!("on {node}")),
                SearchItem::Storage { pool, type_str, .. } => {
                    ("stor", pool.clone(), format!("type: {type_str}"))
                }
                SearchItem::Command { desc, .. } => ("cmd", desc.clone(), "action".to_string()),
            };

            Row::new(vec![icon.to_string(), main_text, sub_text]).style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(5),
        Constraint::Min(20),
        Constraint::Length(20),
    ];

    let results_table = Table::new(result_rows, widths)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        )
        .row_highlight_style(Theme::selected());

    f.render_widget(results_table, chunks[1]);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
