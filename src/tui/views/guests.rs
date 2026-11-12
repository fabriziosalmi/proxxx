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
use crate::tui::theme::{usage_level, Theme, UsageMetric};
use crate::util::format::human_bytes;
use crate::util::sanitize::sanitize_display;

/// Render the guest list or guest detail. The bottom action-hint
/// row (s start · S stop · r restart · d delete · c console · /
/// search) is rendered globally by `widgets::status_footer`; pre-fix
/// this view rendered its own copy in `draw_action_bar`, which the
/// new global footer then duplicated below — two stacked rows of
/// hints. Removed; bottom row reclaimed by the guest table.
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
        ])
        .split(area);

    draw_title(f, chunks[0], state);
    draw_guest_table(f, chunks[1], state);
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
        Span::styled(" Guests ", Theme::title()),
        Span::styled(format!(" {total} total "), Theme::dim()),
        Span::styled(
            format!(" {running} running "),
            Style::default().fg(Theme::SUCCESS),
        ),
        Span::styled(format!(" {stopped} stopped "), Theme::dim()),
        Span::styled(format!(" {vms} VM  {lxc} LXC "), Theme::dim()),
    ]);
    // #378: guests of a node whose last fetch failed are last-known data.
    let title = if state.guests_stale_nodes.is_empty() {
        title
    } else {
        let nodes: Vec<String> = state
            .guests_stale_nodes
            .iter()
            .map(|n| sanitize_display(n).into_owned())
            .collect();
        let mut spans = title.spans;
        spans.push(Span::styled(
            format!(" stale (fetch failed): {} ", nodes.join(", ")),
            Style::default().fg(Theme::WARNING),
        ));
        Line::from(spans)
    };

    f.render_widget(
        Paragraph::new(title).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Theme::border()),
        ),
        area,
    );
}

#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
fn draw_guest_table(f: &mut Frame, area: Rect, state: &AppState) {
    let visible_list = state.visible_guests();

    if visible_list.is_empty() {
        let widget = if state.is_loading {
            Paragraph::new(" Loading guests...").style(Theme::dim())
        } else if !state.guests_fetch_errors.is_empty() {
            let n = state.guests_fetch_errors.len();
            let noun = if n == 1 { "node" } else { "nodes" };
            let detail = state.guests_fetch_errors.join("; ");
            let lines = vec![
                Line::from(Span::styled(
                    format!(" Access denied on {n} {noun} — token may lack VM.Audit scope"),
                    Style::default().fg(Theme::WARNING),
                )),
                Line::from(Span::styled(
                    format!(" {detail}"),
                    Style::default().fg(Theme::TEXT_DIM),
                )),
                Line::from(Span::styled(
                    " Hint: grant 'PVEVMAdmin' or 'PVEAuditor' role on /vms to the token",
                    Theme::dim(),
                )),
            ];
            Paragraph::new(lines)
        } else {
            Paragraph::new(" No guests found.").style(Theme::dim())
        };
        f.render_widget(widget, area);
        return;
    }

    // ── Virtual Scrolling ───────────────────────────────
    //
    // (macro audit) — bounded-cost rendering contract.
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
        "", "vmid", "name", "type", "status", "cpu", "ram", "disk", "node", "tags",
    ])
    .style(Theme::header())
    .height(1);

    let rows: Vec<Row> = visible_guests
        .iter()
        .enumerate()
        .map(|(vi, guest)| {
            let actual_index = scroll_offset + vi;

            let mut status_icon = if state.selected_guests.contains(&guest.vmid) {
                "*"
            } else {
                " "
            };

            let type_str = match guest.guest_type {
                GuestType::Qemu => "VM",
                GuestType::Lxc => "LXC",
            };

            // A guest that is not running has no CPU or memory use to
            // show: `-`, as in `ls guests`, not a 0% that reads as idle.
            let running = guest.status == GuestStatus::Running;
            let cpu_span = if running && guest.cpus > 0 {
                let cpu_pct = guest.cpu * 100.0;
                Theme::usage_span(format!("{cpu_pct:.0}%"), UsageMetric::Cpu, cpu_pct, true)
            } else {
                Span::raw("-".to_string())
            };

            let mem_span = if running && guest.maxmem > 0 {
                let mem_pct = (guest.mem as f64 / guest.maxmem as f64) * 100.0;
                Theme::usage_span(format!("{mem_pct:.0}%"), UsageMetric::Memory, mem_pct, true)
            } else {
                Span::raw("-".to_string())
            };

            let disk_span = if guest.maxdisk > 0 {
                let text = human_bytes(guest.maxdisk);
                if guest.disk > 0 {
                    let disk_pct = (guest.disk as f64 / guest.maxdisk as f64) * 100.0;
                    Theme::usage_span(text, UsageMetric::Disk, disk_pct, true)
                } else {
                    Span::raw(text)
                }
            } else {
                Span::raw("-".to_string())
            };

            let tags = if guest.tags.trim().is_empty() {
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
                Theme::guest_row(guest.status)
            };

            let status_cell = if let Some(task) = state.active_tasks.get(&guest.vmid) {
                status_icon = ">";
                status_text = task.clone();
                if !state.selected_guests.contains(&guest.vmid) {
                    style = style.fg(Theme::WARNING);
                }
                Span::raw(status_text)
            } else if state.selected_guests.contains(&guest.vmid) {
                // A multi-selected row has a coloured background; the
                // status colour on top of it would be unreadable.
                Span::raw(status_text)
            } else {
                Span::styled(status_text, Theme::guest_status(guest.status))
            };

            Row::new(vec![
                Span::raw(status_icon.to_string()),
                Span::raw(guest.vmid.to_string()),
                Span::raw(sanitize_display(&guest.name).into_owned()),
                Span::raw(type_str.to_string()),
                status_cell,
                cpu_span,
                mem_span,
                disk_span,
                if state.guests_stale_nodes.contains(&guest.node) {
                    Span::styled(
                        format!("{}?", sanitize_display(&guest.node)),
                        Style::default().fg(Theme::WARNING),
                    )
                } else {
                    Span::raw(sanitize_display(&guest.node).into_owned())
                },
                Span::raw(tags),
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

// `draw_action_bar` removed: action-key hints (s start · S stop ·
// r restart · d delete · c console · / search) now live in the
// global `widgets::status_footer`. Pre-fix this view rendered its
// own copy on top of the global footer — two stacked rows.

#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
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
        ])
        .split(area);

    // Header — status color carries semantic; row text shows the word.
    let status_style = Theme::guest_status(guest.status);
    let status_word = format!("{:?}", guest.status).to_lowercase();

    let title = Line::from(vec![
        Span::styled(format!(" {status_word} "), status_style),
        Span::styled(
            format!("{} ", sanitize_display(&guest.name)),
            Theme::title(),
        ),
        Span::styled(format!("vmid {}", guest.vmid), Theme::dim()),
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
    let has_cpu = guest.cpus > 0;
    let cpu_pct = if has_cpu { guest.cpu * 100.0 } else { 0.0 };
    let cpu_bar = make_bar(cpu_pct.clamp(0.0, 100.0), 20);
    let cpu_level = usage_level(UsageMetric::Cpu, cpu_pct);
    let cpu_res_span = if has_cpu {
        Span::styled(
            format!("{cpu_pct:>5.1}%{} {cpu_bar}", cpu_level.marker()),
            cpu_level.style(),
        )
    } else {
        Span::raw(format!("{cpu_pct:>5.1}% {cpu_bar}"))
    };

    let has_mem = guest.maxmem > 0;
    let mem_pct = if has_mem {
        (guest.mem as f64 / guest.maxmem as f64) * 100.0
    } else {
        0.0
    };
    let mem_bar = make_bar(mem_pct, 20);
    let mem_level = usage_level(UsageMetric::Memory, mem_pct);
    let mem_res_span = if has_mem {
        Span::styled(
            format!("{mem_pct:>5.1}%{} {mem_bar}", mem_level.marker()),
            mem_level.style(),
        )
    } else {
        Span::raw(format!("{mem_pct:>5.1}% {mem_bar}"))
    };

    let has_disk = guest.maxdisk > 0;
    let disk_pct = if has_disk {
        (guest.disk as f64 / guest.maxdisk as f64) * 100.0
    } else {
        0.0
    };
    let disk_bar = make_bar(disk_pct, 20);
    let disk_level = usage_level(UsageMetric::Disk, disk_pct);
    let disk_res_span = if has_disk {
        Span::styled(
            format!("{disk_pct:>5.1}%{} {disk_bar}", disk_level.marker()),
            disk_level.style(),
        )
    } else {
        Span::raw(format!("{disk_pct:>5.1}% {disk_bar}"))
    };

    let res_text = vec![
        Line::from(vec![
            Span::styled("CPU:  ", Theme::dim()),
            Span::raw(format!("{} cores", guest.cpus)),
        ]),
        Line::from(vec![Span::styled("      ", Theme::dim()), cpu_res_span]),
        Line::from(""),
        Line::from(vec![
            Span::styled("RAM:  ", Theme::dim()),
            Span::raw(format!(
                "{} / {}",
                human_bytes(guest.mem),
                human_bytes(guest.maxmem)
            )),
        ]),
        Line::from(vec![Span::styled("      ", Theme::dim()), mem_res_span]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Disk: ", Theme::dim()),
            Span::raw(format!(
                "{} / {}",
                human_bytes(guest.disk),
                human_bytes(guest.maxdisk)
            )),
        ]),
        Line::from(vec![Span::styled("      ", Theme::dim()), disk_res_span]),
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
    // Action bar moved to global widgets::status_footer.
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
    let filled = ((percent / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::api::types::Guest;
    use ratatui::{backend::TestBackend, buffer::Buffer, style::Color, Terminal};

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

    fn render_buffer(state: &AppState) -> Buffer {
        let backend = TestBackend::new(100, 15);
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
    fn guest_table_memory_usage_colours_and_critical_marker() {
        let mut state = AppState::new();
        state.nav_stack = vec![crate::app::View::GuestList];
        state.guests = vec![
            Guest {
                vmid: 100,
                name: "vm-low".into(),
                guest_type: GuestType::Qemu,
                status: GuestStatus::Running,
                node: "pve1".into(),
                cpus: 2,
                cpu: 0.10,
                mem: 10,
                maxmem: 100,
                ..Guest::default()
            },
            Guest {
                vmid: 101,
                name: "vm-high".into(),
                guest_type: GuestType::Qemu,
                status: GuestStatus::Running,
                node: "pve1".into(),
                cpus: 2,
                cpu: 0.10,
                mem: 85,
                maxmem: 100,
                ..Guest::default()
            },
            Guest {
                vmid: 102,
                name: "vm-crit".into(),
                guest_type: GuestType::Qemu,
                status: GuestStatus::Running,
                node: "pve1".into(),
                cpus: 2,
                cpu: 0.10,
                mem: 96,
                maxmem: 100,
                ..Guest::default()
            },
        ];

        let buf = render_buffer(&state);
        let header_y = (0..buf.area.height)
            .find(|&y| row_string(&buf, y).contains("vmid"))
            .expect("header row present");
        let ram_col = find_col_of(&buf, header_y, "ram");

        let r0 = header_y + 1;
        let r1 = header_y + 2;
        let r2 = header_y + 3;

        let cell_0: String = (ram_col..ram_col + 5)
            .map(|x| buf[(x, r0)].symbol())
            .collect();
        let cell_1: String = (ram_col..ram_col + 5)
            .map(|x| buf[(x, r1)].symbol())
            .collect();
        let cell_2: String = (ram_col..ram_col + 5)
            .map(|x| buf[(x, r2)].symbol())
            .collect();

        assert_eq!(cell_0.trim(), "10%");
        assert!(!cell_0.contains('!'));
        // An ok level keeps the row's text colour (row 0 is the selected row).
        assert_eq!(buf[(ram_col, r0)].fg, Theme::TEXT);

        assert_eq!(cell_1.trim(), "85%");
        assert!(!cell_1.contains('!'));
        assert_eq!(buf[(ram_col, r1)].fg, Theme::ORANGE);

        assert_eq!(cell_2.trim(), "96%!");
        assert!(cell_2.contains('!'));
        assert_eq!(buf[(ram_col, r2)].fg, Theme::DANGER);
    }

    #[test]
    fn guest_table_max_zero_has_no_marker_and_default_style() {
        let mut state = AppState::new();
        state.nav_stack = vec![crate::app::View::GuestList];
        state.selected_index = 1; // keep row 0 unselected to verify default cell style
        state.guests = vec![Guest {
            vmid: 200,
            name: "vm-zero".into(),
            guest_type: GuestType::Qemu,
            status: GuestStatus::Running,
            node: "pve1".into(),
            cpus: 0,
            cpu: 0.99,
            mem: 99,
            maxmem: 0,
            disk: 99,
            maxdisk: 0,
            ..Guest::default()
        }];

        let buf = render_buffer(&state);
        let header_y = (0..buf.area.height)
            .find(|&y| row_string(&buf, y).contains("vmid"))
            .expect("header row present");
        let ram_col = find_col_of(&buf, header_y, "ram");
        let row_y = header_y + 1;

        let line = row_string(&buf, row_y);
        assert!(
            !line.contains('!'),
            "max==0 row must not contain '!': {line}"
        );
        assert_eq!(buf[(ram_col, row_y)].fg, Color::Reset);
    }

    /// A stopped guest has no CPU or memory use: `-`, as in `ls guests`.
    /// Empty tags, or tags that are only blanks, read `-` alike.
    #[test]
    fn a_stopped_guest_shows_dashes_for_cpu_and_ram() {
        let mut state = AppState::new();
        state.push_view(crate::app::View::GuestList);
        state.guests = vec![
            Guest {
                vmid: 101,
                name: "off".into(),
                node: "pve1".into(),
                status: GuestStatus::Stopped,
                cpus: 2,
                maxmem: 512 << 20,
                maxdisk: 8 << 30,
                tags: " ".into(),
                ..Guest::default()
            },
            Guest {
                vmid: 102,
                name: "on".into(),
                node: "pve1".into(),
                status: GuestStatus::Running,
                cpus: 2,
                cpu: 0.25,
                mem: 256 << 20,
                maxmem: 512 << 20,
                maxdisk: 8 << 30,
                ..Guest::default()
            },
        ];
        let mut terminal = Terminal::new(TestBackend::new(110, 12)).expect("terminal");
        terminal.draw(|f| draw(f, f.area(), &state)).expect("draw");
        let buf: Buffer = terminal.backend().buffer().clone();
        let row = |name: &str| {
            (0..buf.area.height)
                .map(|y| {
                    (0..buf.area.width)
                        .map(|x| buf[(x, y)].symbol())
                        .collect::<String>()
                })
                .find(|l| l.contains(name))
                .unwrap_or_else(|| panic!("row {name}"))
        };
        let off: Vec<String> = row(" off ")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let on: Vec<String> = row(" on ").split_whitespace().map(str::to_string).collect();
        let cols = |r: &[String]| {
            r.iter()
                .skip_while(|c| !c.ends_with("stopped") && !c.ends_with("running"))
                .skip(1)
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(cols(&off), ["-", "-"], "{off:?}");
        assert_eq!(cols(&on), ["25%", "50%"], "{on:?}");
        assert_eq!(
            off.iter().rev().nth(1).map(String::as_str),
            Some("-"),
            "blank tags read `-`: {off:?}"
        );
    }
}
