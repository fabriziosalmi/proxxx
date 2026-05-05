//! Render a `vt100::Screen` into a ratatui `Frame`.
//!
//! Goals:
//! - Faithful enough that bash, vim, htop, less, top all look right.
//! - Cell-by-cell color/attr translation. No fancy compositing — vt100
//!   already maintains the canonical grid.
//! - Cursor rendering via reverse-video on the cell under the cursor
//!   (we can't use ratatui's terminal cursor — it's owned by the parent
//!   terminal, not the PTY pane).

use ratatui::layout::Rect;
use ratatui::prelude::Buffer;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

use crate::ssh::pty::SharedParser;

/// A widget that renders the current state of a PTY parser into the given Rect.
/// On each draw, it locks the parser, copies the visible grid into ratatui's
/// buffer, and overlays the cursor.
pub struct PtyView<'a> {
    parser: &'a SharedParser,
}

impl<'a> PtyView<'a> {
    #[must_use]
    pub const fn new(parser: &'a SharedParser) -> Self {
        Self { parser }
    }
}

impl Widget for PtyView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let parser = match self.parser.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let screen = parser.screen();
        let (rows, cols) = screen.size();

        let visible_rows = area.height.min(rows);
        let visible_cols = area.width.min(cols);

        for row in 0..visible_rows {
            for col in 0..visible_cols {
                let Some(cell) = screen.cell(row, col) else {
                    continue;
                };
                let buf_cell = buf.cell_mut((area.x + col, area.y + row));
                let Some(buf_cell) = buf_cell else { continue };

                let contents = cell.contents();
                if contents.is_empty() {
                    buf_cell.set_char(' ');
                } else {
                    // vt100 cells can hold combining sequences; ratatui's Cell
                    // takes a string symbol so we forward the whole thing.
                    buf_cell.set_symbol(contents.as_ref());
                }

                let mut style = Style::default()
                    .fg(translate_color(cell.fgcolor()))
                    .bg(translate_color(cell.bgcolor()));
                if cell.bold() {
                    style = style.add_modifier(Modifier::BOLD);
                }
                if cell.italic() {
                    style = style.add_modifier(Modifier::ITALIC);
                }
                if cell.underline() {
                    style = style.add_modifier(Modifier::UNDERLINED);
                }
                if cell.inverse() {
                    style = style.add_modifier(Modifier::REVERSED);
                }
                buf_cell.set_style(style);
            }
        }

        // Cursor: render as reversed-video on the cell underneath, only if
        // the cursor is in the visible area and not hidden by the remote app.
        if !screen.hide_cursor() {
            let (cy, cx) = screen.cursor_position();
            if cy < visible_rows && cx < visible_cols {
                if let Some(cell) = buf.cell_mut((area.x + cx, area.y + cy)) {
                    cell.set_style(cell.style().add_modifier(Modifier::REVERSED));
                }
            }
        }
    }
}

const fn translate_color(c: vt100::Color) -> Color {
    match c {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(i) => Color::Indexed(i),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn renders_plain_text_into_buffer() {
        let parser = Arc::new(Mutex::new(vt100::Parser::new(5, 20, 0)));
        parser.lock().unwrap().process(b"hello");
        let area = Rect::new(0, 0, 20, 5);
        let mut buf = Buffer::empty(area);
        PtyView::new(&parser).render(area, &mut buf);
        let s: String = (0..5)
            .map(|i| buf.cell((i, 0)).unwrap().symbol().to_string())
            .collect();
        assert_eq!(s, "hello");
    }

    #[test]
    fn cursor_rendered_reversed() {
        let parser = Arc::new(Mutex::new(vt100::Parser::new(5, 20, 0)));
        parser.lock().unwrap().process(b"X");
        let area = Rect::new(0, 0, 20, 5);
        let mut buf = Buffer::empty(area);
        PtyView::new(&parser).render(area, &mut buf);
        // After "X", cursor sits at column 1, row 0.
        let cell = buf.cell((1, 0)).unwrap();
        assert!(cell.style().add_modifier.contains(Modifier::REVERSED));
    }
}
