// Node detail view — shows all guests on a selected node
// PURE RENDER function.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::api::types::{GuestStatus, NodeStatus};
use crate::app::AppState;
use crate::tui::theme::Theme;

/// Render the node list view. The bottom status row (mode pill +
/// keybind hints) is rendered by the global `widgets::status_footer`
/// — pre-fix this view called `super::dashboard::draw` to render its
/// own copy, which was a forgotten copy-paste from when nodes.rs was
/// forked from dashboard.rs (the call rendered the WHOLE dashboard
/// pipeline into a 1-row chunk, with everything but the trailing
/// status row clipped). Removed; the row is now reclaimed by the
/// node table.
pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(8),    // node table
        ])
        .split(area);

    // Title
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" Nodes ", Theme::title()),
        Span::styled(format!(" {} total ", state.nodes.len()), Theme::dim()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(title, chunks[0]);

    // Node table with more detail
    draw_node_table(f, chunks[1], state);
}

fn draw_node_table(f: &mut Frame, area: Rect, state: &AppState) {
    if state.nodes.is_empty() {
        let msg = if state.is_loading {
            " loading…"
        } else {
            " no nodes found."
        };
        f.render_widget(Paragraph::new(msg).style(Theme::dim()), area);
        return;
    }

    let header = Row::new(vec![
        "",
        "node",
        "status",
        "cpu",
        "cpu usage",
        "ram",
        "ram usage",
        "disk",
        "uptime",
        "guests",
    ])
    .style(Theme::header())
    .height(1);

    let rows: Vec<Row> = state
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let status_icon = match node.status {
                NodeStatus::Online => "●",
                NodeStatus::Offline => "○",
                NodeStatus::Unknown => "◐",
            };

            let cpu_pct = if node.maxcpu > 0 {
                (node.cpu / f64::from(node.maxcpu)) * 100.0
            } else {
                0.0
            };

            let mem_pct = if node.maxmem > 0 {
                (node.mem as f64 / node.maxmem as f64) * 100.0
            } else {
                0.0
            };

            let disk_pct = if node.maxdisk > 0 {
                (node.disk as f64 / node.maxdisk as f64) * 100.0
            } else {
                0.0
            };

            // Count guests on this node
            let guest_count = state.guests.iter().filter(|g| g.node == node.node).count();
            let running_count = state
                .guests
                .iter()
                .filter(|g| g.node == node.node && g.status == GuestStatus::Running)
                .count();

            let cpu_bar = make_bar(cpu_pct, 8);
            let mem_bar = make_bar(mem_pct, 8);

            let style = if i == state.selected_index {
                Theme::selected()
            } else {
                Style::default()
            };

            Row::new(vec![
                status_icon.to_string(),
                node.node.clone(),
                format!("{:?}", node.status).to_lowercase(),
                format!(
                    "{:.0}% ({}/{})",
                    cpu_pct,
                    format!("{:.1}", node.cpu),
                    node.maxcpu
                ),
                cpu_bar,
                format!("{:.0}%", mem_pct),
                mem_bar,
                format!("{:.0}%", disk_pct),
                format_uptime(node.uptime),
                format!("{running_count}/{guest_count}"),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Min(10),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(" Nodes ")
                .borders(Borders::ALL)
                .border_style(Theme::border_focus()),
        )
        .row_highlight_style(Theme::selected());

    f.render_widget(table, area);
}

/// Create a text-based bar chart: ████░░░░
fn make_bar(percent: f64, width: usize) -> String {
    let filled = ((percent / 100.0) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}
