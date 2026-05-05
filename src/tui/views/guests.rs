// Guest list view — unified VM + LXC table with virtual scrolling
// PURE RENDER function. No business logic.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::api::types::{GuestStatus, GuestType};
use crate::app::AppState;
use crate::tui::theme::Theme;
use crate::util::sanitize::sanitize_display;

/// Render the guest list or guest detail
pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    if let crate::app::View::GuestDetail { vmid } = state.current_view() {
        draw_guest_detail(f, area, state, *vmid);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title + counts
            Constraint::Min(8),    // guest table
            Constraint::Length(1), // action hints
        ])
        .split(area);

    draw_title(f, chunks[0], state);
    draw_guest_table(f, chunks[1], state);
    draw_action_bar(f, chunks[2]);
}

fn draw_title(f: &mut Frame, area: Rect, state: &AppState) {
    let total = state.guests.len();
    let running = state
        .guests
        .iter()
        .filter(|g| g.status == GuestStatus::Running)
        .count();
    let stopped = state
        .guests
        .iter()
        .filter(|g| g.status == GuestStatus::Stopped)
        .count();
    let vms = state
        .guests
        .iter()
        .filter(|g| g.guest_type == GuestType::Qemu)
        .count();
    let lxc = state
        .guests
        .iter()
        .filter(|g| g.guest_type == GuestType::Lxc)
        .count();

    let title = Line::from(vec![
        Span::styled(" ⚡ ", Style::default().fg(Theme::ACCENT)),
        Span::styled("Guests", Theme::title()),
        Span::styled(format!("  {total} total"), Theme::dim()),
        Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
        Span::styled(format!("🟢 {running}"), Style::default().fg(Theme::ONLINE)),
        Span::styled(
            format!(" 🔴 {stopped}"),
            Style::default().fg(Theme::OFFLINE),
        ),
        Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
        Span::styled(format!("VM:{vms} LXC:{lxc}"), Theme::dim()),
    ]);

    f.render_widget(
        Paragraph::new(title).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Theme::border()),
        ),
        area,
    );
}

fn draw_guest_table(f: &mut Frame, area: Rect, state: &AppState) {
    let visible_list = state.visible_guests();

    if visible_list.is_empty() {
        let msg = if state.is_loading {
            " ⏳ Loading guests..."
        } else {
            " No guests found."
        };
        f.render_widget(Paragraph::new(msg).style(Theme::dim()), area);
        return;
    }

    // ── Virtual Scrolling ───────────────────────────────
    //
    // Vector 24 (macro audit) — bounded-cost rendering contract.
    //
    // The heavy per-frame work (Row::new with format!, Style::default,
    // tag string mutation, status-icon dispatch) iterates ONLY over
    // `visible_guests`, which is sliced to `visible_height` rows by
    // `scroll_window`. So the dominant cost is O(terminal_height) —
    // typically 30–50 — regardless of total guest count.
    //
    // The peripheral O(N) work (`state.visible_guests()` collect,
    // `draw_title`'s filter().count() × 4) is constant-factor cheap:
    // for N = 15 000 guests this is ~60 000 trivial Vec/iter ops
    // per frame, well under 100 µs on a 2020-era CPU. Even at 100 Hz
    // sustained input rate that's < 10 ms/sec of CPU.
    let visible_height = area.height.saturating_sub(3) as usize; // minus header + borders
    let total = visible_list.len();
    let window = scroll_window(total, state.selected_index, visible_height);
    let scroll_offset = window.start;
    let visible_guests = &visible_list[window];

    let header = Row::new(vec![
        "", "VMID", "NAME", "TYPE", "STATUS", "CPU", "RAM", "DISK", "NODE", "TAGS",
    ])
    .style(Theme::header())
    .height(1);

    let rows: Vec<Row> = visible_guests
        .iter()
        .enumerate()
        .map(|(vi, guest)| {
            let actual_index = scroll_offset + vi;

            let mut status_icon = if state.selected_guests.contains(&guest.vmid) {
                "☑ "
            } else {
                match guest.status {
                    GuestStatus::Running => "🟢",
                    GuestStatus::Stopped => "🔴",
                    GuestStatus::Paused => "🟡",
                    GuestStatus::Suspended => "🟣",
                    GuestStatus::Unknown => "⚪",
                }
            };

            let type_str = match guest.guest_type {
                GuestType::Qemu => "VM",
                GuestType::Lxc => "LXC",
            };

            let cpu_pct = if guest.cpus > 0 {
                format!("{:.0}%", guest.cpu * 100.0)
            } else {
                "-".to_string()
            };

            let mem_pct = if guest.maxmem > 0 {
                format!("{:.0}%", (guest.mem as f64 / guest.maxmem as f64) * 100.0)
            } else {
                "-".to_string()
            };

            let disk_str = if guest.maxdisk > 0 {
                format_bytes(guest.maxdisk)
            } else {
                "-".to_string()
            };

            let tags = if guest.tags.is_empty() {
                "-".to_string()
            } else {
                sanitize_display(&guest.tags).replace(';', ", ")
            };

            let mut status_text = format!("{:?}", guest.status).to_lowercase();

            let mut style = if state.selected_guests.contains(&guest.vmid) {
                Style::default()
                    .bg(Theme::INFO)
                    .fg(ratatui::style::Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if actual_index == state.selected_index {
                Theme::selected()
            } else {
                match guest.status {
                    GuestStatus::Running => Style::default(),
                    GuestStatus::Stopped => Theme::dim(),
                    _ => Style::default().fg(Theme::STALE),
                }
            };

            if let Some(task) = state.active_tasks.get(&guest.vmid) {
                status_icon = "⏳";
                status_text = task.clone();
                if !state.selected_guests.contains(&guest.vmid) {
                    style = style.fg(Theme::WARNING);
                }
            }

            Row::new(vec![
                status_icon.to_string(),
                guest.vmid.to_string(),
                sanitize_display(&guest.name).into_owned(),
                type_str.to_string(),
                status_text,
                cpu_pct,
                mem_pct,
                disk_str,
                sanitize_display(&guest.node).into_owned(),
                tags,
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(3),  // icon
        Constraint::Length(6),  // vmid
        Constraint::Min(15),    // name
        Constraint::Length(4),  // type
        Constraint::Length(9),  // status
        Constraint::Length(5),  // cpu
        Constraint::Length(5),  // ram
        Constraint::Length(8),  // disk
        Constraint::Length(10), // node
        Constraint::Min(10),    // tags
    ];

    let scroll_info = if total > visible_height {
        format!(" Guests [{}/{total}] ", state.selected_index + 1)
    } else {
        " Guests ".to_string()
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

fn draw_action_bar(f: &mut Frame, area: Rect) {
    let bar = Line::from(vec![
        Span::styled(
            " s",
            Style::default()
                .fg(Theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("tart ", Style::default().fg(Theme::TEXT_DIM)),
        Span::styled(
            "S",
            Style::default()
                .fg(Theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("top ", Style::default().fg(Theme::TEXT_DIM)),
        Span::styled(
            "r",
            Style::default()
                .fg(Theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("estart ", Style::default().fg(Theme::TEXT_DIM)),
        Span::styled(
            "d",
            Style::default()
                .fg(Theme::DANGER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("elete ", Style::default().fg(Theme::TEXT_DIM)),
        Span::styled(
            "c",
            Style::default()
                .fg(Theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("onsole ", Style::default().fg(Theme::TEXT_DIM)),
        Span::styled(
            "/",
            Style::default()
                .fg(Theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" search", Style::default().fg(Theme::TEXT_DIM)),
    ]);

    f.render_widget(
        Paragraph::new(bar).style(Style::default().bg(Theme::BG_ELEVATED)),
        area,
    );
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

fn draw_guest_detail(f: &mut Frame, area: Rect, state: &AppState, vmid: u32) {
    let guest = state.guests.iter().find(|g| g.vmid == vmid);

    let Some(guest) = guest else {
        f.render_widget(
            Paragraph::new(" Guest not found.").style(Theme::dim()),
            area,
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(1), // Actions
        ])
        .split(area);

    // Header
    let status_icon = match guest.status {
        GuestStatus::Running => "🟢",
        GuestStatus::Stopped => "🔴",
        GuestStatus::Paused => "🟡",
        GuestStatus::Suspended => "🟣",
        GuestStatus::Unknown => "⚪",
    };

    let title = Line::from(vec![
        Span::styled(format!(" {status_icon} "), Style::default()),
        Span::styled(
            format!("{} ", sanitize_display(&guest.name)),
            Theme::title(),
        ),
        Span::styled(format!("(VMID: {})", guest.vmid), Theme::dim()),
    ]);

    f.render_widget(
        Paragraph::new(title).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Theme::border()),
        ),
        chunks[0],
    );

    // Main content split: Left (Info) / Right (Resources)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    // Info panel
    let type_str = match guest.guest_type {
        GuestType::Qemu => "Virtual Machine (QEMU)",
        GuestType::Lxc => "Container (LXC)",
    };

    let info_text = vec![
        Line::from(vec![
            Span::styled("Status:  ", Theme::dim()),
            Span::raw(format!("{:?}", guest.status).to_lowercase()),
        ]),
        Line::from(vec![
            Span::styled("Type:    ", Theme::dim()),
            Span::raw(type_str),
        ]),
        Line::from(vec![
            Span::styled("Node:    ", Theme::dim()),
            Span::raw(sanitize_display(&guest.node).into_owned()),
        ]),
        Line::from(vec![
            Span::styled("Tags:    ", Theme::dim()),
            Span::raw(sanitize_display(&guest.tags).replace(';', ", ")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Uptime:  ", Theme::dim()),
            Span::raw(format_uptime(guest.uptime)),
        ]),
    ];

    f.render_widget(
        Paragraph::new(info_text).block(
            Block::default()
                .title(" Configuration ")
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        ),
        main_chunks[0],
    );

    // Resources panel
    let cpu_bar = make_bar((guest.cpu * 100.0).clamp(0.0, 100.0), 20);
    let mem_pct = if guest.maxmem > 0 {
        (guest.mem as f64 / guest.maxmem as f64) * 100.0
    } else {
        0.0
    };
    let mem_bar = make_bar(mem_pct, 20);
    let disk_pct = if guest.maxdisk > 0 {
        (guest.disk as f64 / guest.maxdisk as f64) * 100.0
    } else {
        0.0
    };
    let disk_bar = make_bar(disk_pct, 20);

    let res_text = vec![
        Line::from(vec![
            Span::styled("CPU:  ", Theme::dim()),
            Span::raw(format!("{} cores", guest.cpus)),
        ]),
        Line::from(vec![
            Span::styled("      ", Theme::dim()),
            Span::raw(format!("{:<6.1}% {}", guest.cpu * 100.0, cpu_bar)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("RAM:  ", Theme::dim()),
            Span::raw(format!(
                "{} / {}",
                format_bytes(guest.mem),
                format_bytes(guest.maxmem)
            )),
        ]),
        Line::from(vec![
            Span::styled("      ", Theme::dim()),
            Span::raw(format!("{mem_pct:<6.1}% {mem_bar}")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Disk: ", Theme::dim()),
            Span::raw(format!(
                "{} / {}",
                format_bytes(guest.disk),
                format_bytes(guest.maxdisk)
            )),
        ]),
        Line::from(vec![
            Span::styled("      ", Theme::dim()),
            Span::raw(format!("{disk_pct:<6.1}% {disk_bar}")),
        ]),
    ];

    f.render_widget(
        Paragraph::new(res_text).block(
            Block::default()
                .title(" Resources ")
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        ),
        main_chunks[1],
    );

    // Action bar
    draw_action_bar(f, chunks[2]);
}

fn format_uptime(secs: u64) -> String {
    if secs == 0 {
        return "-".to_string();
    }
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

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
        s.push(' '); // or "░" but space looks much cleaner with high-def blocks
    }

    s
}

/// Compute the slice bounds for the virtual-scroll window. Pure math —
/// extracted from `draw_guest_table` so it can be unit-tested for the
/// edge cases that trigger SPOF 3.1: `selected` greater than `total`
/// (after a fetch shrank the list), `visible_height` of zero (terminal
/// resized below the dispatcher minimum), and any combination thereof.
///
/// Guarantees: `start <= end <= total`, so `&list[start..end]` is always
/// a valid slice for any `list` of length `total`.
pub(super) fn scroll_window(
    total: usize,
    selected: usize,
    visible_height: usize,
) -> std::ops::Range<usize> {
    let start = if selected >= visible_height {
        selected - visible_height + 1
    } else {
        0
    };
    let start = start.min(total);
    let end = start.saturating_add(visible_height).min(total);
    start..end
}

#[cfg(test)]
mod tests {
    use super::scroll_window;

    #[test]
    fn empty_list_returns_empty_window() {
        assert_eq!(scroll_window(0, 0, 10), 0..0);
        assert_eq!(scroll_window(0, 99, 10), 0..0);
    }

    #[test]
    fn selected_within_first_page() {
        assert_eq!(scroll_window(20, 3, 10), 0..10);
        assert_eq!(scroll_window(5, 0, 10), 0..5);
    }

    #[test]
    fn selected_below_page_shifts_window() {
        assert_eq!(scroll_window(20, 12, 10), 3..13);
        assert_eq!(scroll_window(20, 19, 10), 10..20);
    }

    #[test]
    fn stale_selected_past_total_clamps_to_end() {
        // SPOF 3.1: data shrank to 5 items but selected_index is still 12.
        // Pre-fix this produced start=12, end=5 → slice[12..5] panic.
        let w = scroll_window(5, 12, 10);
        assert!(w.start <= w.end);
        assert!(w.end <= 5);
    }

    #[test]
    fn zero_visible_height_does_not_panic() {
        // SPOF 3.1: terminal resized below minimum. Even though the
        // dispatcher gates this case, the math here must remain safe.
        let w = scroll_window(5, 12, 0);
        assert!(w.start <= w.end);
        assert!(w.end <= 5);
    }

    #[test]
    fn zero_visible_height_with_zero_total_is_empty() {
        assert_eq!(scroll_window(0, 0, 0), 0..0);
    }

    #[test]
    fn never_produces_inverted_range_under_random_inputs() {
        // Algebraic property: for ANY (total, selected, visible_height)
        // we must have start <= end <= total.
        for total in [0, 1, 5, 100, 1000] {
            for selected in [0, 1, 4, 99, 1001, usize::MAX / 2] {
                for visible in [0, 1, 5, 50, 1000, usize::MAX / 2] {
                    let w = scroll_window(total, selected, visible);
                    assert!(
                        w.start <= w.end,
                        "inverted range for total={total} selected={selected} visible={visible}: {w:?}"
                    );
                    assert!(
                        w.end <= total,
                        "out-of-bounds end for total={total} selected={selected} visible={visible}: {w:?}"
                    );
                }
            }
        }
    }
}
