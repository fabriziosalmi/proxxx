//! Hardware passthrough inventory + conflicts (feature #4).
//!
//! Three sections:
//!   ┌── header (node + summary counts) ──┐
//!   ├── PCI devices (with assignment / IOMMU siblings) ─┤
//!   └── conflicts ──────────────────────┘
//!
//! Read-only. No "assign" / "unassign" affordances — the review's honest
//! cuts said writes go in a later iteration once we have proper SSH +
//! reboot-orchestration around modprobe and initramfs.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Wrap};

use crate::app::hw::{
    detect_pci_conflicts, label_for, pci_inventory, scan_assignments, PciConflict,
};
use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState, node: &str) {
    if state.hw_loading {
        let p = Paragraph::new(Line::from(Span::styled(
            "Loading hardware inventory…",
            Style::default().fg(Theme::TEXT_DIM),
        )))
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, area);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(10),
        ])
        .split(area);

    draw_header(f, layout[0], state, node);
    draw_pci_table(f, layout[1], state);
    draw_conflicts(f, layout[2], state);
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState, node: &str) {
    let gpus = state.hw_pci.iter().filter(|d| d.is_gpu()).count();
    let mdev_caps = state.hw_pci.iter().filter(|d| d.mdev).count();
    let lines = vec![
        Line::from(vec![
            Span::styled("node:    ", Style::default().fg(Theme::TEXT_DIM)),
            Span::styled(
                node.to_string(),
                Style::default()
                    .fg(Theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(
            format!(
                "{} PCI devices  ·  {} USB devices  ·  {} GPUs  ·  {} mdev-capable",
                state.hw_pci.len(),
                state.hw_usb.len(),
                gpus,
                mdev_caps,
            ),
            Style::default().fg(Theme::TEXT_DIM),
        )]),
    ];
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .title(" hardware inventory ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_pci_table(f: &mut Frame, area: Rect, state: &AppState) {
    let (assignments, _) = scan_assignments(&state.hw_guest_configs);
    let inventory = pci_inventory(&state.hw_pci, &assignments);

    let rows: Vec<Row> = inventory
        .into_iter()
        .map(|row| {
            let assigned_label = if row.assigned_to.is_empty() {
                "—".to_string()
            } else {
                row.assigned_to
                    .iter()
                    .map(|v| label_for(&state.guests, *v))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let group_label = if row.device.iommugroup >= 0 {
                let mut s = format!("g{}", row.device.iommugroup);
                if !row.iommu_siblings.is_empty() {
                    s.push_str(&format!(" (+{})", row.iommu_siblings.len()));
                }
                s
            } else {
                "—".into()
            };
            let mdev = if row.device.mdev { "mdev" } else { "" };
            let style = if !row.assigned_to.is_empty() {
                Style::default().fg(Theme::SUCCESS)
            } else if row.device.is_gpu() {
                Style::default().fg(Theme::ACCENT)
            } else {
                Style::default().fg(Theme::TEXT)
            };
            Row::new(vec![
                row.device.short_label(),
                group_label,
                mdev.to_string(),
                assigned_label,
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(36),
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["pci device", "iommu", "mdev", "assigned to"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(format!(
        " PCI ({} devices, {} GPUs) ",
        state.hw_pci.len(),
        state.hw_pci.iter().filter(|d| d.is_gpu()).count()
    )));
    f.render_widget(table, area);
}

fn draw_conflicts(f: &mut Frame, area: Rect, state: &AppState) {
    let (assignments, _) = scan_assignments(&state.hw_guest_configs);
    let conflicts = detect_pci_conflicts(&assignments, &state.hw_pci);

    if conflicts.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "✓ no passthrough conflicts detected",
            Style::default().fg(Theme::SUCCESS),
        )))
        .block(Block::default().borders(Borders::ALL).title(" conflicts "));
        f.render_widget(p, area);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    for c in &conflicts {
        match c {
            PciConflict::DirectShared { address, vmids } => {
                lines.push(Line::from(vec![
                    Span::styled(
                        "DIRECT  ",
                        Style::default()
                            .fg(Theme::DANGER)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "{} claimed by guests: {}",
                        address,
                        vmids
                            .iter()
                            .map(|v| label_for(&state.guests, *v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                ]));
            }
            PciConflict::IommuGroupSplit { group, members } => {
                lines.push(Line::from(vec![
                    Span::styled(
                        "IOMMU   ",
                        Style::default()
                            .fg(Theme::WARNING)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "group {} split across guests — kernel will refuse passthrough",
                        group
                    )),
                ]));
                for (addr, vmid) in members {
                    lines.push(Line::from(vec![
                        Span::raw("        · "),
                        Span::raw(format!(
                            "{addr} → guest {}",
                            label_for(&state.guests, *vmid)
                        )),
                    ]));
                }
            }
        }
    }

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" conflicts ({}) ", conflicts.len())),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}
