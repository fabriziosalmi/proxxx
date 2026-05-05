// Dashboard view — cluster overview with node cards and aggregate stats
// PURE RENDER: reads AppState, writes Frame. Zero I/O.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Row, Table},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;

/// Render the main dashboard. The bottom status bar (mode pill +
/// keybind hints) is rendered globally by `status_footer`, not here
/// — pre-fix the dashboard had its own copy and we ended up with two
/// stacked rows on screen. Removed.
pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header bar
            Constraint::Length(5), // aggregate stats
            Constraint::Min(10),   // node cards
        ])
        .split(area);

    draw_header(f, chunks[0], state);
    draw_aggregate_stats(f, chunks[1], state);
    draw_node_cards(f, chunks[2], state);
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState) {
    let node_count = state.nodes.len();
    let guest_count = state.guests.len();
    let running = state
        .guests
        .iter()
        .filter(|g| matches!(g.status, crate::api::types::GuestStatus::Running))
        .count();
    let pending = state.pending_approvals.len();

    let header = Line::from(vec![
        Span::styled(
            " ⚡ proxxx ",
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!("{node_count} nodes"),
            Style::default().fg(Theme::TEXT),
        ),
        Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!("{running}/{guest_count} guests"),
            Style::default().fg(Theme::SUCCESS),
        ),
        if pending > 0 {
            Span::styled(
                format!(" │ ⏳ {pending} pending"),
                Style::default().fg(Theme::WARNING),
            )
        } else {
            Span::raw("")
        },
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Theme::border())
        .style(Style::default().bg(Theme::BG_ELEVATED));

    let paragraph = Paragraph::new(header).block(block);
    f.render_widget(paragraph, area);
}

fn draw_aggregate_stats(f: &mut Frame, area: Rect, state: &AppState) {
    if state.nodes.is_empty() {
        let loading = Paragraph::new(if state.is_loading {
            " ⏳ Loading cluster data..."
        } else {
            " ⚠ No nodes found. Check your configuration."
        })
        .style(Theme::dim());
        f.render_widget(loading, area);
        return;
    }

    let total_cpu: f64 = state.nodes.iter().map(|n| n.cpu).sum();
    let total_maxcpu: u32 = state.nodes.iter().map(|n| n.maxcpu).sum();
    let cpu_pct = if total_maxcpu > 0 {
        (total_cpu / f64::from(total_maxcpu)) * 100.0
    } else {
        0.0
    };

    let total_mem: u64 = state.nodes.iter().map(|n| n.mem).sum();
    let total_maxmem: u64 = state.nodes.iter().map(|n| n.maxmem).sum();
    let mem_pct = if total_maxmem > 0 {
        (total_mem as f64 / total_maxmem as f64) * 100.0
    } else {
        0.0
    };

    let total_disk: u64 = state.nodes.iter().map(|n| n.disk).sum();
    let total_maxdisk: u64 = state.nodes.iter().map(|n| n.maxdisk).sum();
    let disk_pct = if total_maxdisk > 0 {
        (total_disk as f64 / total_maxdisk as f64) * 100.0
    } else {
        0.0
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(area);

    // CPU gauge
    let cpu_gauge = Gauge::default()
        .block(
            Block::default()
                .title(" CPU ")
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        )
        .gauge_style(
            Style::default()
                .fg(Theme::gauge_color(cpu_pct))
                .bg(Theme::BG),
        )
        .ratio(cpu_pct.clamp(0.0, 100.0) / 100.0)
        .label(format!(
            "{cpu_pct:.0}%  ({total_cpu:.1}/{total_maxcpu} cores)"
        ));
    f.render_widget(cpu_gauge, cols[0]);

    // Memory gauge
    let mem_gauge = Gauge::default()
        .block(
            Block::default()
                .title(" RAM ")
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        )
        .gauge_style(
            Style::default()
                .fg(Theme::gauge_color(mem_pct))
                .bg(Theme::BG),
        )
        .ratio(mem_pct.clamp(0.0, 100.0) / 100.0)
        .label(format!(
            "{mem_pct:.0}%  ({}/{})",
            format_bytes(total_mem),
            format_bytes(total_maxmem)
        ));
    f.render_widget(mem_gauge, cols[1]);

    // Disk gauge
    let disk_gauge = Gauge::default()
        .block(
            Block::default()
                .title(" DISK ")
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        )
        .gauge_style(
            Style::default()
                .fg(Theme::gauge_color(disk_pct))
                .bg(Theme::BG),
        )
        .ratio(disk_pct.clamp(0.0, 100.0) / 100.0)
        .label(format!(
            "{disk_pct:.0}%  ({}/{})",
            format_bytes(total_disk),
            format_bytes(total_maxdisk)
        ));
    f.render_widget(disk_gauge, cols[2]);
}

fn draw_node_cards(f: &mut Frame, area: Rect, state: &AppState) {
    if state.nodes.is_empty() {
        return;
    }

    let header = Row::new(vec!["", "NODE", "STATUS", "CPU", "RAM", "DISK", "UPTIME"])
        .style(Theme::header())
        .height(1);

    let rows: Vec<Row> = state
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let status_str = format!("{:?}", node.status).to_lowercase();
            let status_icon = match node.status {
                crate::api::types::NodeStatus::Online => "●",
                crate::api::types::NodeStatus::Offline => "○",
                crate::api::types::NodeStatus::Unknown => "◐",
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

            let style = if i == state.selected_index {
                Theme::selected()
            } else {
                Style::default().bg(Theme::BG)
            };

            Row::new(vec![
                status_icon.to_string(),
                node.node.clone(),
                status_str,
                format!("{cpu_pct:.0}%"),
                format!("{mem_pct:.0}% ({})", format_bytes(node.maxmem)),
                format!("{disk_pct:.0}%"),
                format_uptime(node.uptime),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Min(12),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(" Nodes ")
                .borders(Borders::ALL)
                .border_style(Theme::border_focus())
                .style(Style::default().bg(Theme::BG)),
        )
        .row_highlight_style(Theme::selected());

    f.render_widget(table, area);
}

// `draw_status_bar` removed: status pill + keybind hints + error
// banner now live in the global `widgets::status_footer`. Pre-fix
// the dashboard rendered its own copy below the global footer,
// resulting in two stacked rows on screen.

// ── Helpers ─────────────────────────────────────────────

fn format_bytes(bytes: u64) -> String {
    const GB: u64 = 1_073_741_824;
    const MB: u64 = 1_048_576;
    const TB: u64 = 1_099_511_627_776;

    if bytes >= TB {
        format!("{:.1}T", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.0}M", bytes as f64 / MB as f64)
    } else {
        format!("{bytes}B")
    }
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;

    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}
