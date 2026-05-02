//! Render the active SSH PTY session.
//!
//! Layout:
//!   ┌── ssh: vmid 100 (root@10.0.0.5) ───────── Ctrl+] to exit ──┐
//!   │                                                            │
//!   │     <PTY contents — vt100::Screen rendered cell-by-cell>   │
//!   │                                                            │
//!   └────────────────────────────────────────────────────────────┘
//!
//! When no PTY parser is available yet (just-opened, still connecting),
//! we show a centered "connecting…" message inside the same border.

use ratatui::layout::Rect;
use ratatui::prelude::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::ssh::pty::SharedParser;
use crate::tui::theme::Theme;
use crate::tui::widgets::pty::PtyView;

/// Visible SSH session state passed to the renderer. The TUI loop owns the
/// real `PtySession`; we receive only what's needed to draw.
pub struct SessionFrameInput<'a> {
    pub vmid: u32,
    pub host: Option<&'a str>,
    pub user: Option<&'a str>,
    pub parser: Option<&'a SharedParser>,
    pub finished: bool,
}

pub fn draw(f: &mut Frame, area: Rect, input: SessionFrameInput) {
    let title = match (input.user, input.host) {
        (Some(u), Some(h)) => format!(" ssh: vmid {} ({u}@{h}) ", input.vmid),
        _ => format!(" ssh: vmid {} ", input.vmid),
    };

    let hint = if input.finished {
        " session ended — press Esc or Ctrl+] to return "
    } else {
        " Ctrl+] to exit "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Line::from(vec![Span::styled(
            title,
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )]))
        .title_bottom(Line::from(Span::styled(
            hint,
            Style::default().fg(Theme::TEXT_DIM),
        )));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(parser) = input.parser {
        f.render_widget(PtyView::new(parser), inner);
    } else {
        // Pre-connect placeholder.
        let msg = if input.finished {
            "Session closed."
        } else {
            "Connecting…"
        };
        let p = Paragraph::new(Line::from(Span::styled(
            msg,
            Style::default().fg(Theme::TEXT_DIM),
        )))
        .alignment(ratatui::layout::Alignment::Center);
        // Center vertically by carving a 1-row strip in the middle.
        let mid_y = inner.y + inner.height / 2;
        let strip = Rect {
            x: inner.x,
            y: mid_y,
            width: inner.width,
            height: 1,
        };
        f.render_widget(p, strip);
    }
}
