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

/// Render the help overlay (`?` keybind): the keymap reference in
/// [`help_sections`], flowed into as many columns as the height needs.
/// The source of truth for the keys is the match in `event::map_key`;
/// a test checks that every key listed here maps to an action.
pub fn draw_help_overlay(f: &mut Frame, area: Rect) {
    use ratatui::layout::{Constraint, Direction, Layout};

    // Nearly the whole screen: at 70% x 80% the 41 lines of the old
    // single column stopped at "Selection" on 24 and 30 rows, with no
    // sign that more followed.
    let modal_area = Rect {
        x: area.x + area.width / 20,
        y: area.y + area.height / 20,
        width: area.width - area.width / 10,
        height: area.height - area.height / 10,
    };
    f.render_widget(Clear, modal_area);
    let block = Block::default()
        .title(" Help — keymap reference · any key closes ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::ACCENT));
    let inner = block.inner(modal_area);
    f.render_widget(block, modal_area);

    let columns = flow_into_columns(&help_sections(), usize::from(inner.height));
    let n = u32::try_from(columns.len().max(1)).unwrap_or(1);
    let areas = Layout::default()
        .direction(Direction::Horizontal)
        .constraints((0..n).map(|_| Constraint::Ratio(1, n)))
        .split(inner);
    for (lines, col_area) in columns.into_iter().zip(areas.iter()) {
        f.render_widget(Paragraph::new(lines).alignment(Alignment::Left), *col_area);
    }
}

/// The keymap reference, one block of lines per section. Descriptions
/// stay short so two sections fit side by side on an 80-column screen.
fn help_sections() -> Vec<Vec<Line<'static>>> {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let header = |s: &'static str| Line::from(Span::styled(s, bold.fg(Theme::ACCENT)));
    let entry = |key: &'static str, desc: &'static str| {
        Line::from(vec![
            Span::styled(format!(" {key:<10}"), bold),
            Span::raw(desc),
        ])
    };
    vec![
        vec![
            header("Navigation"),
            entry("j / Down", "move down"),
            entry("k / Up", "move up"),
            entry("Enter / l", "open / drill in"),
            entry("h / Esc", "back"),
            entry("q", "quit"),
            entry("R", "refresh now"),
            entry("Ctrl+L", "redraw the screen"),
        ],
        vec![
            header("Views"),
            entry("1", "dashboard"),
            entry("2", "nodes"),
            entry("3", "guests"),
            entry("4", "storage"),
            entry("H", "heatmap"),
            entry("B", "backup board"),
            entry("G", "config grep"),
            entry("Q", "operation queue"),
            entry("T", "audit timeline"),
            entry("W", "hardware (node list)"),
        ],
        vec![
            header("Guest list"),
            entry("Space", "select / unselect"),
            entry("V", "select all"),
            entry("t", "select by tag"),
            entry("s / S / r", "queue start/stop/restart"),
            entry("d", "queue delete"),
            entry("D", "compare 2+ selected"),
            entry("X", "guest-agent command"),
            entry("Z", "snapshot tree"),
            entry("c", "SSH console"),
            entry("C", "run the queue (queue)"),
        ],
        vec![
            header("Modes"),
            entry("/", "search"),
            entry(":", "command"),
            entry("Ctrl+K", "quick-open palette"),
            entry("Ctrl+]", "leave an SSH session"),
        ],
    ]
}

/// Lay sections out top to bottom, starting a new column when the next
/// section would not fit in `height` rows. A blank line separates two
/// sections in the same column; a section is never split.
fn flow_into_columns(sections: &[Vec<Line<'static>>], height: usize) -> Vec<Vec<Line<'static>>> {
    let mut columns: Vec<Vec<Line<'static>>> = vec![Vec::new()];
    for section in sections {
        let col = columns.last().map_or(0, Vec::len);
        let needed = section.len() + usize::from(col > 0);
        if col > 0 && col + needed > height {
            columns.push(Vec::new());
        }
        if let Some(last) = columns.last_mut() {
            if !last.is_empty() {
                last.push(Line::from(""));
            }
            last.extend(section.iter().cloned());
        }
    }
    columns
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod help_tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn screen(w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("terminal");
        terminal
            .draw(|f| draw_help_overlay(f, f.area()))
            .expect("draw");
        let buf = terminal.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every section and every entry is on screen at 80x24 and 100x30;
    /// the single column stopped at "Selection" on both.
    #[test]
    fn the_whole_keymap_fits_on_small_terminals() {
        for (w, h) in [(80, 24), (100, 30), (160, 45)] {
            let text = screen(w, h);
            for section in help_sections() {
                for line in section {
                    let want: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                    let want = want.trim();
                    if !want.is_empty() {
                        assert!(
                            text.contains(want),
                            "{w}x{h}: {want:?} not on screen:\n{text}"
                        );
                    }
                }
            }
        }
    }

    /// Each key the help lists does something in the view it belongs to.
    /// Ctrl chords are handled outside `map_key` (redraw, palette, SSH)
    /// and are left out.
    #[test]
    fn every_listed_key_maps_to_an_action() {
        use crate::api::types::{Guest, GuestStatus, Node, NodeStatus};
        use crate::app::View;
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let state_for = |key: char| {
            let mut state = crate::app::AppState::new();
            state.guests = vec![100, 101]
                .into_iter()
                .map(|vmid| Guest {
                    vmid,
                    name: format!("g{vmid}"),
                    node: "pve1".into(),
                    status: GuestStatus::Running,
                    ..Guest::default()
                })
                .collect();
            state.nodes = vec![Node {
                node: "pve1".into(),
                status: NodeStatus::Online,
                ..Node::default()
            }];
            match key {
                'W' => state.push_view(View::NodeList),
                'C' => {
                    state.push_view(View::OperationQueue);
                    let op = crate::app::queue::QueuedOp::new(
                        Box::new(crate::app::Action::StartGuest { vmid: 100 }),
                        &state,
                    );
                    state.op_queue.push(op);
                }
                _ => {
                    state.push_view(View::GuestList);
                    state.selected_guests.extend([100, 101]);
                }
            }
            state
        };
        for section in help_sections() {
            for line in section.iter().skip(1) {
                let key_col = line.spans[0].content.trim().to_string();
                for key in key_col.split(" / ") {
                    let code = match key {
                        "Enter" => KeyCode::Enter,
                        "Esc" => KeyCode::Esc,
                        "Down" => KeyCode::Down,
                        "Up" => KeyCode::Up,
                        "Space" => KeyCode::Char(' '),
                        k if k.starts_with("Ctrl+") => continue,
                        k if k.chars().count() == 1 => KeyCode::Char(k.chars().next().unwrap()),
                        other => panic!("help key {other:?} has no test mapping"),
                    };
                    let probe = match code {
                        KeyCode::Char(c) => c,
                        _ => ' ',
                    };
                    let state = state_for(probe);
                    let action =
                        crate::tui::event::map_key(KeyEvent::new(code, KeyModifiers::NONE), &state);
                    assert!(action.is_some(), "help lists `{key}` but it does nothing");
                }
            }
        }
    }
}
