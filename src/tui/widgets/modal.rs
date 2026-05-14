use crate::tui::theme::Theme;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn draw_confirm_modal(f: &mut Frame, area: Rect, description: &str) {
    // A modal is a centered window
    let modal_area = centered_rect(50, 20, area);

    // Clear background so text underneath doesn't show
    f.render_widget(Clear, modal_area);

    let content = vec![
        Line::from(description),
        Line::from(""),
        Line::from(vec![
            Span::styled("y", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" confirm   ", Theme::dim()),
            Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" cancel   ", Theme::dim()),
            Span::styled(
                "F",
                Style::default()
                    .fg(Theme::DANGER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" force (audit-logged)", Theme::dim()),
        ]),
    ];

    let block = Block::default()
        .title(" confirm ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::DANGER));

    let p = Paragraph::new(content)
        .block(block)
        .alignment(Alignment::Center);

    f.render_widget(p, modal_area);
}

/// Render the help overlay (`?` keybind). Static keymap reference —
/// generated from a literal table because the source-of-truth for
/// keybindings IS the match in `event::map_key`. Keeping them in lock-
/// step is a manual discipline, but we cap drift via this overlay being
/// a small flat list (≤30 lines) reviewed alongside any keymap change.
// Vec built incrementally with `push` (clippy::vec_init_then_push):
// the alternative `vec![…]` literal would be 30+ lines of
// immediate-mode struct literals harder to scan than the line-by-line
// `entry(...)` calls below. The lint applies at the function level
// (where the Vec ultimately escapes), not at the local binding.
#[allow(clippy::vec_init_then_push)]
pub fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let modal_area = centered_rect(70, 80, area);
    f.render_widget(Clear, modal_area);

    let bold = Style::default().add_modifier(Modifier::BOLD);
    let header = |s: &'static str| Line::from(Span::styled(s, bold.fg(Theme::ACCENT)));
    let entry = |key: &'static str, desc: &'static str| {
        Line::from(vec![
            Span::styled(format!("  {key:<10}"), bold),
            Span::raw(desc),
        ])
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    lines.push(header("Navigation"));
    lines.push(entry("j / Down", "move selection down"));
    lines.push(entry("k / Up", "move selection up"));
    lines.push(entry("Enter / l", "select / drill in"));
    lines.push(entry("h / Esc", "back / parent view"));
    lines.push(entry("q", "quit"));
    lines.push(entry("R", "force refresh"));
    lines.push(entry("Ctrl+L", "redraw (recover from SIGCONT)"));
    lines.push(Line::from(""));
    lines.push(header("Views"));
    lines.push(entry("1", "Dashboard"));
    lines.push(entry("2", "Nodes"));
    lines.push(entry("3", "Guests"));
    lines.push(entry("4", "Storage"));
    lines.push(entry("H", "Heatmap"));
    lines.push(entry("B", "Backup board"));
    lines.push(entry("G", "Config grep"));
    lines.push(entry("Q", "Operation queue"));
    lines.push(entry("T", "Audit timeline"));
    lines.push(Line::from(""));
    lines.push(header("Selection (Guest list)"));
    lines.push(entry("Space", "toggle guest selection"));
    lines.push(entry("V", "select all"));
    lines.push(entry("t", "select by tag (prompt)"));
    lines.push(Line::from(""));
    lines.push(header("Actions (Guest list)"));
    lines.push(entry("s", "start selected guest(s)"));
    lines.push(entry("S", "stop (graceful) selected"));
    lines.push(entry("X", "broadcast guest-agent cmd"));
    lines.push(entry("Z", "open snapshot tree"));
    lines.push(entry("c", "open SSH console for selected guest"));
    lines.push(entry("C", "execute queue (in queue view)"));
    lines.push(Line::from(""));
    lines.push(header("Modes"));
    lines.push(entry("/", "search"));
    lines.push(entry(":", "command"));
    lines.push(entry("Ctrl+K", "command palette"));
    lines.push(entry("Ctrl+]", "exit SSH session"));
    lines.push(entry("Ctrl+C", "quit (always)"));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press any key to dismiss",
        Theme::dim(),
    )));

    let block = Block::default()
        .title(" Help — keymap reference ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::ACCENT));

    let p = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Left);

    f.render_widget(p, modal_area);
}

/// Profile picker overlay. Shows a scrollable list of named profiles;
/// the highlighted row (selected) is rendered in reverse video.
/// `j`/`k` navigate, `Enter` confirms, `Esc`/`q` dismisses.
pub fn draw_profile_picker(f: &mut Frame, area: Rect, profiles: &[String], selected: usize) {
    let modal_area = centered_rect(40, 50, area);
    f.render_widget(Clear, modal_area);

    let lines: Vec<Line> = profiles
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let style = if i == selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Line::from(Span::styled(format!("  {name}  "), style))
        })
        .collect();

    let block = Block::default()
        .title(" Switch profile (Enter=confirm Esc=cancel) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::ACCENT));

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, modal_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(*popup_layout.get(1).unwrap_or(&r));

    *layout.get(1).unwrap_or(&r)
}
