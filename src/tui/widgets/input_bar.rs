use crate::app::AppMode;
use crate::tui::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn draw_input_bar(f: &mut Frame, area: Rect, mode: &AppMode, query: &str) {
    // `mask` hides the typed text behind bullets — used for the SSH key
    // passphrase so it never renders on screen (or in a screen-share).
    let (prefix, title, mask) = match mode {
        AppMode::Search => ("/", " Fuzzy Search ", false),
        AppMode::Command => (":", " Command ", false),
        AppMode::InputTag => ("tag: ", " Select By Tag ", false),
        AppMode::SshPassphrase { .. } => (
            "passphrase: ",
            " Unlock SSH key — Enter to connect, Esc to cancel ",
            true,
        ),
        _ => return,
    };
    // Render bullets, not the secret, when masking.
    let displayed = if mask {
        "•".repeat(query.chars().count())
    } else {
        query.to_string()
    };
    let query = displayed.as_str();

    // Place the input bar at the bottom — single divider line above
    // the input, no side/bottom chrome (the prefix `/` `:` glyph carries
    // the mode signal alongside the title).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(area);

    let input_area = *chunks.get(1).unwrap_or(&area);

    f.render_widget(Clear, input_area);

    let content = Line::from(vec![
        Span::styled(prefix, Style::default().fg(Theme::ACCENT)),
        Span::styled(query, Style::default()),
        Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED)),
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::TOP)
        .border_style(Theme::border_focus());

    f.render_widget(Paragraph::new(content).block(block), input_area);
}
