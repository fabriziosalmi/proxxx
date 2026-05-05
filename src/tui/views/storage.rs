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
        Span::styled(" 💾 ", Style::default().fg(Theme::ACCENT)),
        Span::styled("Storage Pools", Theme::title()),
        Span::styled(format!("  ({} total)", state.storage.len()), Theme::dim()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(title, chunks[0]);

    draw_storage_table(f, chunks[1], state);
}

fn draw_storage_table(f: &mut Frame, area: Rect, state: &AppState) {
    if state.storage.is_empty() {
        let msg = if state.is_loading {
            " ⏳ Loading storage..."
        } else {
            " No storage pools found."
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

    let header = Row::new(vec![
        "", "STORAGE", "TYPE", "ACTIVE", "USED", "USAGE", "TOTAL", "TREND", "ETA", "CONTENT",
    ])
    .style(Theme::header())
    .height(1);

    let rows: Vec<Row> = visible_storage
        .iter()
        .enumerate()
        .map(|(vi, pool)| {
            let actual_index = scroll_offset + vi;

            let status_icon = if pool.active { "🟢" } else { "🔴" };
            let active_str = if pool.active { "yes" } else { "no" };

            let usage_pct = if pool.total > 0 {
                (pool.used as f64 / pool.total as f64) * 100.0
            } else {
                0.0
            };

            let used_str = format_bytes(pool.used);
            let total_str = format_bytes(pool.total);
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
                            trend_str = format!("+{}", format_bytes(bytes_per_day as u64));

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
                            trend_str = format!("-{}", format_bytes(bytes_per_day as u64));
                            eta_str = "∞".to_string();
                        }
                        Ordering::Equal => {
                            trend_str = "0".to_string();
                            eta_str = "∞".to_string();
                        }
                    }
                }
            }

            Row::new(vec![
                status_icon.to_string(),
                pool.storage.clone(),
                pool.storage_type.clone(),
                active_str.to_string(),
                used_str,
                format!("{:.1}% {}", usage_pct, usage_bar),
                total_str,
                trend_str,
                eta_str,
                pool.content.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(3),  // icon
        Constraint::Length(15), // name
        Constraint::Length(10), // type
        Constraint::Length(8),  // active
        Constraint::Length(10), // used
        Constraint::Length(20), // usage bar
        Constraint::Length(10), // total
        Constraint::Length(12), // trend
        Constraint::Length(6),  // eta
        Constraint::Min(20),    // content
    ];

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
    let blocks = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"];
    let total_eighths = ((percent / 100.0) * (width * 8) as f64).round() as usize;
    let full_blocks = total_eighths / 8;
    let remainder = total_eighths % 8;

    let mut s = String::new();
    for _ in 0..full_blocks {
        s.push('█');
    }

    if full_blocks < width {
        s.push_str(blocks[remainder]);
    }

    let empty = width.saturating_sub(full_blocks + usize::from(remainder > 0));
    for _ in 0..empty {
        s.push(' ');
    }

    s
}

fn format_bytes(bytes: u64) -> String {
    const GB: u64 = 1_073_741_824;
    const TB: u64 = 1_099_511_627_776;
    if bytes >= TB {
        format!("{:.1}T", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else {
        format!("{:.0}M", bytes as f64 / 1_048_576.0)
    }
}
