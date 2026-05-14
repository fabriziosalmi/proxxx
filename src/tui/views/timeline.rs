use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Row, Table},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header / timeline instructions
            Constraint::Min(10),   // Diff table
            Constraint::Length(3), // Timeline slider
        ])
        .split(area);

    draw_header(f, chunks[0]);
    draw_diff_table(f, chunks[1], state);
    draw_timeline_slider(f, chunks[2], state);
}

fn draw_header(f: &mut Frame, area: Rect) {
    let text = Line::from(vec![
        Span::styled(
            " Audit timeline ",
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" scrub through historical cluster state "),
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Theme::border())
        .style(Style::default().bg(Theme::BG_ELEVATED));

    f.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_timeline_slider(f: &mut Frame, area: Rect, state: &AppState) {
    let total = state.timeline_timestamps.len();
    if total == 0 {
        return;
    }

    let current_idx = state.timeline_index;
    let ts = state.timeline_timestamps[current_idx];

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let elapsed = now.saturating_sub(ts);
    let dt = if elapsed < 3600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86400 {
        format!("{}h {}m ago", elapsed / 3600, (elapsed % 3600) / 60)
    } else {
        format!("{}d {}h ago", elapsed / 86400, (elapsed % 86400) / 3600)
    };

    let ratio = if total > 1 {
        current_idx as f64 / (total - 1) as f64
    } else {
        1.0
    };

    let label = format!(" [h/l] snapshot {}/{} : {} ", current_idx + 1, total, dt);

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Theme::border()),
        )
        .gauge_style(Style::default().fg(Theme::ACCENT).bg(Theme::BG_ELEVATED))
        .ratio(ratio)
        .label(Span::styled(
            label,
            Style::default()
                .fg(Theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ));

    f.render_widget(gauge, area);
}

fn draw_diff_table(f: &mut Frame, area: Rect, state: &AppState) {
    let current_snap = state.timeline_snapshot.as_ref();
    let prev_snap = state.timeline_prev_snapshot.as_ref();

    let Some(cur) = current_snap else {
        f.render_widget(
            Paragraph::new("No data for this snapshot.").style(Theme::dim()),
            area,
        );
        return;
    };
    let mut rows = Vec::new();

    // We will compare guests
    let cur_guests = &cur.guests;
    let prev_guests = prev_snap.map(|s| &s.guests);

    let mut all_vms = std::collections::HashSet::new();
    for g in cur_guests {
        all_vms.insert(g.vmid);
    }
    if let Some(pg) = prev_guests {
        for g in pg {
            all_vms.insert(g.vmid);
        }
    }

    let mut vms_sorted: Vec<u32> = all_vms.into_iter().collect();
    vms_sorted.sort_unstable();

    for vmid in vms_sorted {
        let cur_g = cur_guests.iter().find(|g| g.vmid == vmid);
        let prev_g = prev_guests.and_then(|pg| pg.iter().find(|g| g.vmid == vmid));

        match (prev_g, cur_g) {
            (None, Some(c)) => {
                // Newly created
                rows.push(Row::new(vec![
                    Span::styled(
                        "+",
                        Style::default()
                            .fg(Theme::SUCCESS)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{}", c.vmid)),
                    Span::raw(c.name.clone()),
                    Span::raw(c.node.clone()),
                    Span::styled("CREATED", Style::default().fg(Theme::SUCCESS)),
                ]));
            }
            (Some(p), None) => {
                // Deleted
                rows.push(Row::new(vec![
                    Span::styled(
                        "-",
                        Style::default()
                            .fg(Theme::DANGER)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{}", p.vmid)),
                    Span::raw(p.name.clone()),
                    Span::raw(p.node.clone()),
                    Span::styled("DELETED", Style::default().fg(Theme::DANGER)),
                ]));
            }
            (Some(p), Some(c)) => {
                // Changed?
                let mut changes = Vec::new();
                if p.status != c.status {
                    changes.push(format!("{:?} -> {:?}", p.status, c.status));
                }
                if p.node != c.node {
                    changes.push(format!("Migrated: {} -> {}", p.node, c.node));
                }
                if p.maxmem != c.maxmem {
                    changes.push(format!("RAM: {} -> {}", p.maxmem, c.maxmem));
                }

                if !changes.is_empty() {
                    let color = if changes.iter().any(|c| c.contains("Running")) {
                        Theme::SUCCESS
                    } else if changes.iter().any(|c| c.contains("Stopped")) {
                        Theme::WARNING
                    } else {
                        Theme::INFO
                    };

                    rows.push(Row::new(vec![
                        Span::styled("~", Style::default().fg(color).add_modifier(Modifier::BOLD)),
                        Span::raw(format!("{}", c.vmid)),
                        Span::raw(c.name.clone()),
                        Span::raw(c.node.clone()),
                        Span::styled(changes.join(", "), Style::default().fg(color)),
                    ]));
                }
            }
            _ => {}
        }
    }

    if rows.is_empty() {
        f.render_widget(
            Paragraph::new("No changes detected in this snapshot compared to the previous one.")
                .style(Theme::dim()),
            area,
        );
        return;
    }

    let widths = [
        Constraint::Length(3),
        Constraint::Length(8),
        Constraint::Length(20),
        Constraint::Length(15),
        Constraint::Min(40),
    ];

    let header = Row::new(vec!["", "VMID", "NAME", "NODE", "CHANGES"])
        .style(Theme::header())
        .height(1);

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Diff View "));

    f.render_widget(table, area);
}
