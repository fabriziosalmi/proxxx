// Storage view — shows storage pools across all nodes
// PURE RENDER function.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;
use crate::tui::widgets::columns::{self, Column};
use crate::util::format::human_bytes;

/// Render the storage list
pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    // Bottom action-hint row removed in favour of the global
    // widgets::status_footer (avoids two-stacked-bars on screen);
    // table reclaims the row.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(8),    // storage table
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(" Storage pools ", Theme::title()),
        Span::styled(format!(" {} total ", state.storage.len()), Theme::dim()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(title, chunks[0]);

    draw_storage_table(f, chunks[1], state);
}

#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
fn draw_storage_table(f: &mut Frame, area: Rect, state: &AppState) {
    if state.storage.is_empty() {
        let msg = if state.is_loading {
            " loading storage…"
        } else {
            " no storage pools found."
        };
        f.render_widget(Paragraph::new(msg).style(Theme::dim()), area);
        return;
    }

    let visible_height = area.height.saturating_sub(3) as usize;
    let total = state.storage.len();
    // SPOF 3.1: shared scroll-window helper proves start <= end <= total.
    let window = super::guests::scroll_window(total, state.selected_index, visible_height);
    let scroll_offset = window.start;
    let visible_storage = &state.storage[window];

    // A storage is listed once per node, so the node is a column: the
    // view printed `local` twice with nothing to tell the two apart.
    // Names take the width of the longest one (`local-lvm` printed as
    // `local-lv`); on a narrow terminal the trend, the bar and the
    // active flag go before anything is cut.
    let node_w =
        columns::content_width("node", state.storage.iter().map(|p| p.node.as_str()), 4, 20);
    let name_w = columns::content_width(
        "storage",
        state.storage.iter().map(|p| p.storage.as_str()),
        7,
        24,
    );
    let type_w = columns::content_width(
        "type",
        state.storage.iter().map(|p| p.storage_type.as_str()),
        4,
        12,
    );
    let cols = [
        Column::new("", 1, 0),
        Column::new("node", node_w, 0),
        Column::new("storage", name_w, 0),
        Column::new("type", type_w, 0),
        Column::new("active", 6, 3),
        Column::new("used", 6, 0),
        Column::new("usage", 6, 0),
        Column::new("", 10, 4),
        Column::new("total", 6, 0),
        Column::new("trend", 8, 5),
        Column::new("eta", 5, 5),
        Column::new("content", 10, 1),
    ];
    let keep = columns::fit(&cols, area.width.saturating_sub(2));
    let header = Row::new(columns::pick(
        &cols.iter().map(|c| c.header).collect::<Vec<_>>(),
        &keep,
    ))
    .style(Theme::header())
    .height(1);

    let rows: Vec<Row> = visible_storage
        .iter()
        .enumerate()
        .map(|(vi, pool)| {
            let actual_index = scroll_offset + vi;

            let status_icon = if pool.active { "*" } else { " " };
            let active_str = if pool.active { "yes" } else { "no" };

            let usage_pct = if pool.total > 0 {
                (pool.used as f64 / pool.total as f64) * 100.0
            } else {
                0.0
            };

            let used_str = human_bytes(pool.used);
            let total_str = human_bytes(pool.total);
            let usage_bar = make_bar(usage_pct, 10);

            let style = if actual_index == state.selected_index {
                Theme::selected()
            } else if !pool.active {
                Theme::dim()
            } else {
                Style::default()
            };

            let mut trend_str = "-".to_string();
            let mut eta_str = "-".to_string();

            if let Some(&(past_time, past_used)) = state.storage_trend.get(&pool.storage) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let elapsed_secs = now.saturating_sub(past_time);

                if elapsed_secs > 3600 {
                    use std::cmp::Ordering;
                    match pool.used.cmp(&past_used) {
                        Ordering::Greater => {
                            let diff = pool.used - past_used;
                            let bytes_per_sec = diff as f64 / elapsed_secs as f64;
                            let bytes_per_day = bytes_per_sec * 86400.0;
                            trend_str = format!("+{}", human_bytes(bytes_per_day as u64));

                            let remaining = pool.total.saturating_sub(pool.used);
                            let days_left = remaining as f64 / bytes_per_day;
                            if days_left < 365.0 {
                                eta_str = format!("{days_left:.0}d");
                            } else {
                                eta_str = ">1y".to_string();
                            }
                        }
                        Ordering::Less => {
                            let diff = past_used - pool.used;
                            let bytes_per_sec = diff as f64 / elapsed_secs as f64;
                            let bytes_per_day = bytes_per_sec * 86400.0;
                            trend_str = format!("-{}", human_bytes(bytes_per_day as u64));
                            eta_str = "∞".to_string();
                        }
                        Ordering::Equal => {
                            trend_str = "0".to_string();
                            eta_str = "∞".to_string();
                        }
                    }
                }
            }

            let cells = [
                status_icon.to_string(),
                pool.node.clone(),
                pool.storage.clone(),
                pool.storage_type.clone(),
                active_str.to_string(),
                used_str,
                format!("{usage_pct:.1}%"),
                usage_bar,
                total_str,
                trend_str,
                eta_str,
                pool.content.replace(',', ", "),
            ];
            Row::new(columns::pick(&cells, &keep)).style(style)
        })
        .collect();

    let widths = columns::constraints(&cols, &keep);

    let scroll_info = if total > visible_height {
        format!(" Storage Pools [{}/{total}] ", state.selected_index + 1)
    } else {
        " Storage Pools ".to_string()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(scroll_info)
                .borders(Borders::ALL)
                .border_style(Theme::border_focus()),
        )
        .row_highlight_style(Theme::selected());

    f.render_widget(table, area);
}

// `draw_action_bar` removed: hints now live in the global
// `widgets::status_footer`.

fn make_bar(percent: f64, width: usize) -> String {
    let filled = ((percent / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}
