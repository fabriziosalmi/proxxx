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
use crate::tui::theme::{usage_level, Theme, UsageMetric};

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

#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
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

            let has_cpu = node.maxcpu > 0;
            let cpu_pct = if has_cpu {
                (node.cpu / f64::from(node.maxcpu)) * 100.0
            } else {
                0.0
            };

            let has_mem = node.maxmem > 0;
            let mem_pct = if has_mem {
                (node.mem as f64 / node.maxmem as f64) * 100.0
            } else {
                0.0
            };

            let has_disk = node.maxdisk > 0;
            let disk_pct = if has_disk {
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

            let cpu_span = Theme::usage_span(
                format!("{cpu_pct:.0}% ({:.1}/{})", node.cpu, node.maxcpu),
                UsageMetric::Cpu,
                cpu_pct,
                has_cpu,
            );
            let cpu_bar_span = if has_cpu {
                Span::styled(cpu_bar, usage_level(UsageMetric::Cpu, cpu_pct).style())
            } else {
                Span::raw(cpu_bar)
            };
            let mem_span = Theme::usage_span(
                format!("{mem_pct:.0}%"),
                UsageMetric::Memory,
                mem_pct,
                has_mem,
            );
            let mem_bar_span = if has_mem {
                Span::styled(mem_bar, usage_level(UsageMetric::Memory, mem_pct).style())
            } else {
                Span::raw(mem_bar)
            };
            let disk_span = Theme::usage_span(
                format!("{disk_pct:.0}%"),
                UsageMetric::Disk,
                disk_pct,
                has_disk,
            );

            Row::new(vec![
                Span::raw(status_icon.to_string()),
                Span::raw(node.node.clone()),
                Span::raw(format!("{:?}", node.status).to_lowercase()),
                cpu_span,
                cpu_bar_span,
                mem_span,
                mem_bar_span,
                disk_span,
                Span::raw(format_uptime(node.uptime)),
                Span::raw(format!("{running_count}/{guest_count}")),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::api::types::Node;
    use ratatui::{backend::TestBackend, buffer::Buffer, style::Color, Terminal};

    fn render_buffer(state: &AppState) -> Buffer {
        let backend = TestBackend::new(110, 15);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|f| draw(f, f.area(), state))
            .expect("draw succeeds");
        terminal.backend().buffer().clone()
    }

    fn row_string(buf: &Buffer, y: u16) -> String {
        (0..buf.area.width)
            .map(|x| buf[(x, y)].symbol())
            .collect::<String>()
    }

    fn find_col_of(buf: &Buffer, y: u16, needle: &str) -> u16 {
        let line = row_string(buf, y);
        let byte_idx = line
            .find(needle)
            .unwrap_or_else(|| panic!("expected {needle:?} in row {y}: {line:?}"));
        u16::try_from(line[..byte_idx].chars().count()).expect("col fits u16")
    }

    #[test]
    fn nodes_view_disk_usage_colours_and_critical_marker() {
        let mut state = AppState::new();
        state.nodes = vec![
            Node {
                node: "n-low".into(),
                status: NodeStatus::Online,
                cpu: 0.4,
                maxcpu: 4,
                mem: 20,
                maxmem: 100,
                disk: 10,
                maxdisk: 100,
                uptime: 3600,
            },
            Node {
                node: "n-high".into(),
                status: NodeStatus::Online,
                cpu: 0.4,
                maxcpu: 4,
                mem: 20,
                maxmem: 100,
                disk: 85,
                maxdisk: 100,
                uptime: 3600,
            },
            Node {
                node: "n-crit".into(),
                status: NodeStatus::Online,
                cpu: 0.4,
                maxcpu: 4,
                mem: 20,
                maxmem: 100,
                disk: 96,
                maxdisk: 100,
                uptime: 3600,
            },
        ];

        let buf = render_buffer(&state);
        let header_y = (0..buf.area.height)
            .find(|&y| row_string(&buf, y).contains("ram usage"))
            .expect("header row present");
        let disk_col = find_col_of(&buf, header_y, "disk");

        let r0 = header_y + 1;
        let r1 = header_y + 2;
        let r2 = header_y + 3;

        let cell_0: String = (disk_col..disk_col + 6)
            .map(|x| buf[(x, r0)].symbol())
            .collect();
        let cell_1: String = (disk_col..disk_col + 6)
            .map(|x| buf[(x, r1)].symbol())
            .collect();
        let cell_2: String = (disk_col..disk_col + 6)
            .map(|x| buf[(x, r2)].symbol())
            .collect();

        assert_eq!(cell_0.trim(), "10%");
        assert!(!cell_0.contains('!'));
        assert_eq!(buf[(disk_col, r0)].fg, Theme::SUCCESS);

        assert_eq!(cell_1.trim(), "85%");
        assert!(!cell_1.contains('!'));
        assert_eq!(buf[(disk_col, r1)].fg, Theme::ORANGE);

        assert_eq!(cell_2.trim(), "96%!");
        assert!(cell_2.contains('!'));
        assert_eq!(buf[(disk_col, r2)].fg, Theme::DANGER);
    }

    #[test]
    fn nodes_view_max_zero_has_no_marker_and_default_style() {
        let mut state = AppState::new();
        state.selected_index = 1; // keep row 0 unselected to verify default cell style
        state.nodes = vec![Node {
            node: "n-zero".into(),
            status: NodeStatus::Offline,
            cpu: 0.0,
            maxcpu: 0,
            mem: 0,
            maxmem: 0,
            disk: 0,
            maxdisk: 0,
            uptime: 0,
        }];

        let buf = render_buffer(&state);
        let header_y = (0..buf.area.height)
            .find(|&y| row_string(&buf, y).contains("ram usage"))
            .expect("header row present");
        let disk_col = find_col_of(&buf, header_y, "disk");
        let row_y = header_y + 1;

        let line = row_string(&buf, row_y);
        assert!(
            !line.contains('!'),
            "max==0 row must not contain '!': {line}"
        );
        assert_eq!(buf[(disk_col, row_y)].fg, Color::Reset);
    }
}
