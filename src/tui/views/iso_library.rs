//! Curated ISO/cloud-image library browser (feature #2).
//!
//! Two-pane layout: the table on the left lists library entries; the
//! right pane shows full metadata + URL + the SHA-256 we'll pin to. The
//! user navigates with j/k and presses Enter to enqueue a download to
//! the currently selected storage.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::iso_library::{IsoEntry, LIBRARY};
use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    draw_header(f, layout[0], state);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    draw_list(f, body[0], state);
    if let Some(entry) = LIBRARY.get(state.selected_index) {
        draw_detail(f, body[1], entry, state);
    }
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState) {
    let storage_hint = state
        .storage
        .first()
        .map_or_else(|| "<no storage>".to_string(), |s| s.storage.clone());
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .title(Line::from(vec![Span::styled(
            " ISO / cloud-image library ",
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )]))
        .title_bottom(Line::from(vec![Span::styled(
            format!(
                " {} entries  default storage: {storage_hint} ",
                LIBRARY.len()
            ),
            Style::default().fg(Theme::TEXT_DIM),
        )]));
    f.render_widget(block, area);
}

/// The library as a table whose columns fit the pane: each line was 70
/// fixed characters in a pane half the screen wide, so the size ran
/// past the border on 160 columns and the version was cut on 80. When
/// the pane is narrow the version, then the distro, are left out (the
/// detail pane shows both).
fn draw_list(f: &mut Frame, area: Rect, state: &AppState) {
    use crate::tui::widgets::columns::{self, Column};
    use ratatui::widgets::{Row, Table, TableState};

    let cols = [
        Column::new(
            "id",
            columns::content_width("id", LIBRARY.iter().map(|e| e.id), 8, 30),
            0,
        ),
        Column::new(
            "distro",
            columns::content_width("distro", LIBRARY.iter().map(|e| e.distro), 6, 16),
            1,
        ),
        Column::new("size", 8, 0),
        Column::new(
            "version",
            columns::content_width("version", LIBRARY.iter().map(|e| e.version), 7, 30),
            2,
        ),
    ];
    let keep = columns::fit(&cols, area.width.saturating_sub(2));
    let rows: Vec<Row> = LIBRARY
        .iter()
        .map(|e| {
            Row::new(columns::pick(
                &[
                    Span::styled(e.id.to_string(), Style::default().fg(Theme::ACCENT)),
                    Span::styled(e.distro.to_string(), Style::default().fg(Theme::TEXT)),
                    Span::styled(
                        format!("{:>4} MiB", e.size_mib),
                        Style::default().fg(Theme::TEXT_DIM),
                    ),
                    Span::styled(e.version.to_string(), Style::default().fg(Theme::TEXT)),
                ],
                &keep,
            ))
        })
        .collect();

    let mut list_state = TableState::default();
    if state.selected_index < LIBRARY.len() {
        list_state.select(Some(state.selected_index));
    }

    let list = Table::new(rows, columns::constraints(&cols, &keep))
        .block(Block::default().borders(Borders::ALL).title(" library "))
        .row_highlight_style(
            Style::default()
                .bg(Theme::ACCENT)
                .fg(ratatui::style::Color::Black)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut list_state);
}

fn draw_detail(f: &mut Frame, area: Rect, entry: &IsoEntry, state: &AppState) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("id:        ", Style::default().fg(Theme::TEXT_DIM)),
        Span::styled(
            entry.id.to_string(),
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("distro:    ", Style::default().fg(Theme::TEXT_DIM)),
        Span::raw(format!("{} {}", entry.distro, entry.version)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("arch:      ", Style::default().fg(Theme::TEXT_DIM)),
        Span::raw(entry.arch.to_string()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("content:   ", Style::default().fg(Theme::TEXT_DIM)),
        Span::raw(entry.content.to_string()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("size:      ", Style::default().fg(Theme::TEXT_DIM)),
        Span::raw(format!("~{} MiB", entry.size_mib)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "url:",
        Style::default().fg(Theme::TEXT_DIM),
    )]));
    lines.push(Line::from(Span::raw(entry.url.to_string())));
    lines.push(Line::from(""));
    // ISO supply-chain hardening: surface the checksum (algo + digest) when pinned;
    // emit a loud warning when not. Different distros use different
    // algorithms (Debian → sha512, others → sha256).
    let (sha_algo, sha_label, sha_style) = match entry.checksum {
        Some(c) => {
            let (algo, hex) = c.proxmox_pair();
            (
                format!("{algo}:"),
                hex.to_string(),
                Style::default().fg(Theme::TEXT_DIM),
            )
        }
        None => (
            "checksum:".into(),
            "NOT PINNED — download refused".to_string(),
            Style::default()
                .fg(Theme::WARNING)
                .add_modifier(Modifier::BOLD),
        ),
    };
    lines.push(Line::from(vec![
        Span::styled(
            format!("{sha_algo:<11}"),
            Style::default().fg(Theme::TEXT_DIM),
        ),
        Span::styled(sha_label, sha_style),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("notes:     ", Style::default().fg(Theme::TEXT_DIM)),
        Span::raw(entry.notes.to_string()),
    ]));
    lines.push(Line::from(""));

    // Already-on-storage indicator. We show the filename Proxmox would
    // assign if the user pressed Enter; the running TUI cache populates
    // `state.iso_existing` from periodic `list_storage_content` polls
    // (left as future work — for MVP we just hint).
    let filename = entry.url.rsplit('/').next().unwrap_or("download.img");
    lines.push(Line::from(vec![
        Span::styled("filename:  ", Style::default().fg(Theme::TEXT_DIM)),
        Span::raw(filename.to_string()),
    ]));
    lines.push(Line::from(""));
    if state.storage.is_empty() {
        lines.push(Line::from(Span::styled(
            "no storage available — connect to a cluster first",
            Style::default().fg(Theme::WARNING),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "Enter: server-side download to default storage",
            Style::default().fg(Theme::TEXT_DIM),
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
