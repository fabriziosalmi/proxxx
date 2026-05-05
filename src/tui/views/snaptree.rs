//! Snapshot tree branching visualizer (feature #7).
//!
//! Renders a `snaptree::Tree` as an indented tree with `├─`/`└─` connectors,
//! highlights the selected node, and shows a side panel with the diff
//! summary against `current` (rollback impact preview).
//!
//! Read-only — create/delete go through the existing snapshot CLI/TUI
//! flows, intentionally separate to keep this view's blast radius zero.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::snaptree::{diff_between, Tree, TreeNode};
use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState, vmid: u32) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    draw_header(f, layout[0], state, vmid);

    if state.snap_tree_loading {
        let p = Paragraph::new(Line::from(Span::styled(
            "Loading snapshot tree…",
            Style::default().fg(Theme::TEXT_DIM),
        )))
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, layout[1]);
        return;
    }

    let Some(tree) = state.snap_tree.as_ref() else {
        let p = Paragraph::new(Line::from(Span::styled(
            "No snapshot data",
            Style::default().fg(Theme::TEXT_DIM),
        )))
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, layout[1]);
        return;
    };

    if tree.total_count() == 0 {
        let p = Paragraph::new(Line::from(Span::styled(
            "This guest has no snapshots.",
            Style::default().fg(Theme::TEXT_DIM),
        )))
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, layout[1]);
        return;
    }

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(layout[1]);

    draw_tree(f, body[0], tree, state.snap_tree_selected.as_deref());
    draw_diff_panel(f, body[1], tree, state.snap_tree_selected.as_deref());
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState, vmid: u32) {
    let name = state
        .guests
        .iter()
        .find(|g| g.vmid == vmid)
        .map(|g| g.name.clone())
        .unwrap_or_default();
    let title = if name.is_empty() {
        format!(" snapshot tree: {vmid} ")
    } else {
        format!(" snapshot tree: {vmid} ({name}) ")
    };
    let hint = if let Some(t) = state.snap_tree.as_ref() {
        format!(
            " {} snapshots, {} orphans │ j/k navigate │ Esc back ",
            t.total_count(),
            t.orphans.len()
        )
    } else {
        " — ".to_string()
    };
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .title(Line::from(Span::styled(
            title,
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )))
        .title_bottom(Line::from(Span::styled(
            hint,
            Style::default().fg(Theme::TEXT_DIM),
        )));
    f.render_widget(block, area);
}

fn draw_tree(f: &mut Frame, area: Rect, tree: &Tree, selected: Option<&str>) {
    // Flatten tree to (Line, name) pairs for List rendering. Connectors
    // are computed with a per-depth "is-last" stack so the right glyph
    // is used at every junction.
    let mut rows: Vec<(Line, String)> = Vec::new();
    let last_count = tree.roots.len();
    for (idx, root) in tree.roots.iter().enumerate() {
        let is_last = idx + 1 == last_count;
        render_node(root, &mut Vec::new(), is_last, &mut rows);
    }
    if !tree.orphans.is_empty() {
        rows.push((
            Line::from(Span::styled(
                " ── orphans ──".to_string(),
                Style::default()
                    .fg(Theme::WARNING)
                    .add_modifier(Modifier::BOLD),
            )),
            String::new(),
        ));
        for orphan in &tree.orphans {
            rows.push((
                Line::from(vec![
                    Span::styled("  · ", Style::default().fg(Theme::WARNING)),
                    Span::styled(orphan.name.clone(), Style::default().fg(Theme::TEXT)),
                    Span::styled(
                        format!(" (parent: {})", orphan.parent),
                        Style::default().fg(Theme::TEXT_DIM),
                    ),
                ]),
                orphan.name.clone(),
            ));
        }
    }

    let items: Vec<ListItem> = rows.iter().map(|(l, _)| ListItem::new(l.clone())).collect();
    let mut list_state = ListState::default();
    if let Some(sel) = selected {
        if let Some(idx) = rows.iter().position(|(_, n)| n == sel) {
            list_state.select(Some(idx));
        }
    }

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" tree "))
        .highlight_style(
            Style::default()
                .bg(Theme::ACCENT)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut list_state);
}

fn render_node(
    node: &TreeNode,
    ancestor_is_last: &mut Vec<bool>,
    is_last: bool,
    rows: &mut Vec<(Line, String)>,
) {
    let mut spans: Vec<Span> = Vec::with_capacity(ancestor_is_last.len() + 2);
    for last in ancestor_is_last.iter() {
        spans.push(Span::styled(
            if *last { "   " } else { "│  " }.to_string(),
            Style::default().fg(Theme::BORDER),
        ));
    }
    if !ancestor_is_last.is_empty() || !rows.is_empty() {
        spans.push(Span::styled(
            if is_last { "└─ " } else { "├─ " }.to_string(),
            Style::default().fg(Theme::BORDER),
        ));
    }
    let name_style = if node.snap.is_current() {
        Style::default()
            .fg(Theme::ACCENT)
            .add_modifier(Modifier::BOLD | Modifier::ITALIC)
    } else {
        Style::default().fg(Theme::TEXT)
    };
    spans.push(Span::styled(node.snap.name.clone(), name_style));
    if node.snap.snaptime > 0 {
        spans.push(Span::styled(
            format!("  ({})", format_relative_time(node.snap.snaptime)),
            Style::default().fg(Theme::TEXT_DIM),
        ));
    }
    if !node.snap.description.is_empty() {
        spans.push(Span::styled(
            format!("  — {}", trim_to(&node.snap.description, 40)),
            Style::default().fg(Theme::TEXT_DIM),
        ));
    }
    rows.push((Line::from(spans), node.snap.name.clone()));

    let n = node.children.len();
    ancestor_is_last.push(is_last);
    for (i, child) in node.children.iter().enumerate() {
        render_node(child, ancestor_is_last, i + 1 == n, rows);
    }
    ancestor_is_last.pop();
}

fn draw_diff_panel(f: &mut Frame, area: Rect, tree: &Tree, selected: Option<&str>) {
    let mut lines: Vec<Line> = Vec::new();

    let Some(sel) = selected else {
        lines.push(Line::from(Span::styled(
            "(no selection)",
            Style::default().fg(Theme::TEXT_DIM),
        )));
        let block = Block::default().borders(Borders::ALL).title(" details ");
        f.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    };

    if let Some(node) = tree.find(sel) {
        lines.push(Line::from(vec![
            Span::styled("name:    ", Style::default().fg(Theme::TEXT_DIM)),
            Span::styled(
                node.snap.name.clone(),
                Style::default()
                    .fg(Theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        if !node.snap.parent.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("parent:  ", Style::default().fg(Theme::TEXT_DIM)),
                Span::raw(node.snap.parent.clone()),
            ]));
        }
        if node.snap.snaptime > 0 {
            lines.push(Line::from(vec![
                Span::styled("taken:   ", Style::default().fg(Theme::TEXT_DIM)),
                Span::raw(format_absolute_time(node.snap.snaptime)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("vmstate: ", Style::default().fg(Theme::TEXT_DIM)),
            Span::raw(if node.snap.vmstate > 0 {
                "yes (live)"
            } else {
                "no"
            }),
        ]));
        if !node.snap.description.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("note:    ", Style::default().fg(Theme::TEXT_DIM)),
                Span::raw(node.snap.description.clone()),
            ]));
        }
        lines.push(Line::from(""));

        // Diff against `current` (rollback impact preview).
        if !node.snap.is_current() {
            if let Some(diff) = diff_between(tree, sel, "current") {
                lines.push(Line::from(Span::styled(
                    "→ rollback impact (vs current)".to_string(),
                    Style::default()
                        .fg(Theme::WARNING)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(format!(
                    "  common ancestor: {}",
                    if diff.common_ancestor.is_empty() {
                        "<none>".to_string()
                    } else {
                        diff.common_ancestor
                    }
                )));
                if diff.reverse_path.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "  no intermediate snapshots discarded",
                        Style::default().fg(Theme::TEXT_DIM),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("  discards on rollback: {}", diff.reverse_path.join(", ")),
                        Style::default().fg(Theme::DANGER),
                    )));
                }
                lines.push(Line::from(format!(
                    "  time delta: {}s ({})",
                    diff.time_delta_secs,
                    format_duration(diff.time_delta_secs)
                )));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            format!("snapshot '{sel}' not in tree (orphan?)"),
            Style::default().fg(Theme::WARNING),
        )));
    }

    let block = Block::default().borders(Borders::ALL).title(" details ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn format_relative_time(snaptime: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let elapsed = now.saturating_sub(snaptime);
    format_duration(elapsed) + " ago"
}

fn format_absolute_time(snaptime: u64) -> String {
    // Cheap timestamp formatter — full chrono crate would be overkill
    // for one tooltip. We display Unix seconds + relative.
    format!("{snaptime} ({})", format_relative_time(snaptime))
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

fn trim_to(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}
