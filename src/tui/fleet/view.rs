//! Pure render for the fleet view. `(Frame, Rect, &FleetState)` — no
//! business logic, no I/O, mirrors the `tui::views::*` contract.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use super::{FleetCluster, FleetFocus, FleetState};
use crate::api::types::{GuestStatus, GuestType};
use crate::tui::theme::Theme;
use crate::util::sanitize::{sanitize_display, truncate_ellipsis};

pub fn draw(f: &mut Frame, area: Rect, state: &FleetState) {
    let fatal_h: u16 = if state.fatal.is_some() { 2 } else { 0 };
    // Summary: borders (2) + header (1) + one row per cluster, capped.
    let summary_h = u16::try_from(state.clusters.len().clamp(1, 12)).unwrap_or(12) + 3;
    // Search line only takes a row when typing or a filter is active.
    let search_h: u16 = u16::from(state.search_active || !state.search_query.is_empty());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),         // 0 header
            Constraint::Length(fatal_h),   // 1 fatal banner (0 when none)
            Constraint::Length(summary_h), // 2 per-cluster summary
            Constraint::Length(search_h),  // 3 search line (0 when idle)
            Constraint::Min(3),            // 4 aggregated guests
            Constraint::Length(1),         // 5 footer
        ])
        .split(area);

    draw_header(f, chunks[0], state);
    if state.fatal.is_some() {
        draw_fatal(f, chunks[1], state);
    }
    draw_summary(f, chunks[2], state);
    if search_h == 1 {
        draw_search(f, chunks[3], state);
    }
    draw_guests(f, chunks[4], state);
    draw_footer(f, chunks[5], state);
}

fn draw_search(f: &mut Frame, area: Rect, state: &FleetState) {
    // Trailing cursor block while typing.
    let cursor = if state.search_active { "█" } else { "" };
    let style = if state.search_active {
        Style::default().fg(Theme::ACCENT)
    } else {
        Theme::dim()
    };
    let line = Line::from(Span::styled(
        format!(" /{}{cursor} ", sanitize_display(&state.search_query)),
        style,
    ));
    f.render_widget(Paragraph::new(line), area);
}

fn draw_header(f: &mut Frame, area: Rect, state: &FleetState) {
    let total = state.clusters.len();
    let reachable = state.clusters.iter().filter(|c| c.reachable).count();
    let line = Line::from(vec![
        Span::styled(" Fleet ", Theme::title()),
        Span::styled(format!(" {total} clusters "), Theme::dim()),
        Span::styled(
            format!(" {reachable} reachable "),
            Style::default().fg(Theme::SUCCESS),
        ),
        Span::styled(
            format!(" {} down ", total.saturating_sub(reachable)),
            Style::default().fg(if reachable == total {
                Theme::TEXT_DIM
            } else {
                Theme::DANGER
            }),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_fatal(f: &mut Frame, area: Rect, state: &FleetState) {
    let msg = state.fatal.as_deref().unwrap_or("");
    let line = Line::from(Span::styled(
        format!(" ⚠ {} ", sanitize_display(msg)),
        Style::default()
            .fg(Theme::DANGER)
            .add_modifier(Modifier::BOLD),
    ));
    f.render_widget(Paragraph::new(line), area);
}

fn draw_summary(f: &mut Frame, area: Rect, state: &FleetState) {
    let header = Row::new(vec![
        "", "cluster", "status", "nodes", "guests", "cpu", "mem", "storage",
    ])
    .style(Theme::header())
    .height(1);

    let rows: Vec<Row> = state
        .clusters
        .iter()
        .enumerate()
        .map(|(i, c)| summary_row(i, c, i == state.selected_index))
        .collect();

    let widths = [
        Constraint::Length(2),  // marker
        Constraint::Min(10),    // cluster
        Constraint::Min(14),    // status
        Constraint::Length(5),  // nodes
        Constraint::Length(9),  // guests R/S
        Constraint::Length(6),  // cpu cores
        Constraint::Length(13), // mem used/total
        Constraint::Length(15), // storage used/total
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(" Clusters ")
            .borders(Borders::ALL)
            .border_style(Theme::border_focus()),
    );
    f.render_widget(table, area);
}

fn summary_row(_idx: usize, c: &FleetCluster, selected: bool) -> Row<'static> {
    let marker = if selected { ">" } else { " " };

    let (status_text, status_style) = if c.reachable {
        ("● OK".to_string(), Style::default().fg(Theme::SUCCESS))
    } else {
        let detail = c.error.as_deref().unwrap_or("unreachable");
        (
            format!("● {}", truncate_ellipsis(detail, 30)),
            Style::default().fg(Theme::DANGER),
        )
    };

    let guests = format!("{}/{}", c.running_guests(), c.stopped_guests());
    let cpu = format!("{}c", c.total_cpu_cores());
    let mem = format!(
        "{}/{}",
        format_bytes(c.mem_used()),
        format_bytes(c.mem_total())
    );
    let storage = format!(
        "{}/{}",
        format_bytes(c.storage_used()),
        format_bytes(c.storage_total())
    );

    let row = Row::new(vec![
        Span::raw(marker.to_string()),
        Span::raw(truncate_ellipsis(&sanitize_display(&c.profile), 18)),
        Span::styled(status_text, status_style),
        Span::raw(c.nodes.len().to_string()),
        Span::raw(guests),
        Span::raw(cpu),
        Span::raw(mem),
        Span::raw(storage),
    ]);

    if selected {
        row.style(Theme::selected())
    } else {
        row
    }
}

fn draw_guests(f: &mut Frame, area: Rect, state: &FleetState) {
    let pairs = state.visible_guests();
    let total = pairs.len();

    // Borders (2) + header (1) consume 3 rows.
    let visible_height = (area.height.saturating_sub(3)) as usize;
    let shown = pairs.iter().take(visible_height.max(1));

    let scope = match state.focus {
        FleetFocus::SelectedCluster => state.clusters.get(state.selected_index).map_or_else(
            || "—".to_string(),
            |c| sanitize_display(&c.profile).into_owned(),
        ),
        FleetFocus::AllGuests => "all fleet".to_string(),
    };
    let filt = if state.search_query.is_empty() {
        String::new()
    } else {
        format!(" · match \"{}\"", sanitize_display(&state.search_query))
    };
    let sort = format!(" · sort:{}", state.sort.label());
    let mut title = format!(" Guests · {scope} [{total}]{filt}{sort} ");
    if total > visible_height {
        title = format!(" Guests · {scope} [showing {visible_height}/{total}]{filt}{sort} ");
    }

    let header = Row::new(vec![
        "cluster", "vmid", "name", "type", "status", "node", "cpu", "mem",
    ])
    .style(Theme::header())
    .height(1);

    let rows: Vec<Row> = shown
        .map(|(profile, g)| {
            let type_str = match g.guest_type {
                GuestType::Qemu => "VM",
                GuestType::Lxc => "LXC",
            };
            let status = format!("{:?}", g.status).to_lowercase();
            let style = match g.status {
                GuestStatus::Running => Style::default().fg(Theme::SUCCESS),
                GuestStatus::Stopped => Style::default().fg(Theme::DANGER),
                GuestStatus::Paused | GuestStatus::Suspended => Style::default().fg(Theme::INFO),
                GuestStatus::Unknown => Style::default().fg(Theme::WARNING),
            };
            Row::new(vec![
                truncate_ellipsis(&sanitize_display(profile), 12),
                g.vmid.to_string(),
                truncate_ellipsis(&sanitize_display(&g.name), 22),
                type_str.to_string(),
                status,
                truncate_ellipsis(&sanitize_display(&g.node), 12),
                format!("{:.0}%", g.cpu * 100.0),
                format_bytes(g.mem),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(12), // cluster
        Constraint::Length(6),  // vmid
        Constraint::Min(14),    // name
        Constraint::Length(4),  // type
        Constraint::Length(8),  // status
        Constraint::Length(12), // node
        Constraint::Length(5),  // cpu
        Constraint::Length(8),  // mem
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Theme::border()),
    );
    f.render_widget(table, area);
}

fn draw_footer(f: &mut Frame, area: Rect, state: &FleetState) {
    // While typing, the footer shows the input-mode hints instead.
    let text = if state.search_active {
        " type to filter · Enter apply · Esc cancel ".to_string()
    } else {
        let focus = match state.focus {
            FleetFocus::SelectedCluster => "selected-cluster guests",
            FleetFocus::AllGuests => "all-fleet guests",
        };
        let esc = if state.search_query.is_empty() {
            ""
        } else {
            "Esc clear · "
        };
        format!(
            " q quit · ↑↓ select · Enter open · Tab: {focus} · / search · s sort:{} · {esc}read-only ",
            state.sort.label()
        )
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(text, Theme::dim()))),
        area,
    );
}

/// IEC byte formatting, matching the per-view helper used across
/// `tui::views::*` (G/T thresholds, M for the remainder).
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
