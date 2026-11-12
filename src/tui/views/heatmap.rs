use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;
use crate::util::sanitize::sanitize_display;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled("Live Hotspot Heatmap", Theme::title()),
        Span::styled(" (Sorted by CPU+RAM Saturation)", Theme::dim()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(title, chunks[0]);

    if state.guests.is_empty() {
        f.render_widget(
            Paragraph::new(" No guests to monitor.").style(Theme::dim()),
            chunks[1],
        );
        return;
    }

    // Calculate heat and sort
    let mut heat_list: Vec<(&crate::api::types::Guest, f64, f64, f64)> = state
        .guests
        .iter()
        .map(|g| {
            let cpu_heat = g.cpu * 100.0;
            let mem_heat = if g.maxmem > 0 {
                (g.mem as f64 / g.maxmem as f64) * 100.0
            } else {
                0.0
            };
            // Simple average for total heat
            let total_heat = f64::midpoint(cpu_heat, mem_heat);
            (g, total_heat, cpu_heat, mem_heat)
        })
        .collect();

    // Sort descending by total heat
    heat_list.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // We render as a flowing paragraph of blocks
    let mut current_line = Vec::new();

    // We want boxes of fixed width, say 18 chars: "[100] webserver  "
    // To do this reliably with Paragraph wrap, we format each string to exact width.
    // Tiles as wide as the longest name (up to 24), so `alpine-existing-lxc`
    // is not `alpine-…` on a screen with room to spare. Names are cut by
    // characters, not bytes: `String::truncate(7)` panicked on a name
    // with a multi-byte character across byte 7.
    let name_w = heat_list
        .iter()
        .map(|(g, ..)| sanitize_display(&g.name).chars().count())
        .max()
        .unwrap_or(0)
        .clamp(8, 24);
    let vmid_w = heat_list
        .iter()
        .map(|(g, ..)| g.vmid.to_string().len())
        .max()
        .unwrap_or(0)
        .max(4);
    let cell_width = vmid_w + name_w + 9;

    for (guest, total_heat, _cpu_heat, _mem_heat) in heat_list {
        let bg = get_heat_color(total_heat);
        // Foreground stays white across the gradient because
        // backgrounds darken with temperature; black text would vanish
        // on the cold end.
        let fg = Color::White;

        // Sanitized first: an injected ESC sequence would garble the grid.
        let full = sanitize_display(&guest.name).into_owned();
        let name = if full.chars().count() > name_w {
            let mut cut: String = full.chars().take(name_w - 1).collect();
            cut.push('…');
            cut
        } else {
            full
        };

        let cell_text = format!(
            " {:<vmid_w$} {:<name_w$} {:>3.0}% ",
            guest.vmid, name, total_heat
        );

        let style = Style::default().bg(bg).fg(fg);

        // Add a small spacing between cells
        current_line.push(Span::styled(cell_text, style));
        current_line.push(Span::raw(" "));

        // Calculate if we need to wrap manually to keep it looking like a grid
        // Alternatively, let Paragraph's Wrap handle it
    }

    // Group into Lines
    let mut lines = Vec::new();
    let available_width = chunks[1].width.saturating_sub(2) as usize; // account for borders
    let cells_per_row = (available_width / (cell_width + 1)).max(1);

    for chunk in current_line.chunks(cells_per_row * 2) {
        lines.push(Line::from(chunk.to_vec()));
        lines.push(Line::from(vec![Span::raw("")])); // Empty line for vertical spacing
    }

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Theme::border()),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(p, chunks[1]);
}

fn get_heat_color(heat: f64) -> Color {
    if heat >= 90.0 {
        Color::Rgb(220, 38, 38) // Red 600
    } else if heat >= 75.0 {
        Color::Rgb(239, 68, 68) // Red 500
    } else if heat >= 60.0 {
        Color::Rgb(249, 115, 22) // Orange 500
    } else if heat >= 40.0 {
        Color::Rgb(234, 179, 8) // Yellow 500
    } else if heat >= 20.0 {
        Color::Rgb(132, 204, 22) // Lime 500
    } else if heat >= 5.0 {
        Color::Rgb(34, 197, 94) // Green 500
    } else {
        Color::Rgb(31, 41, 55) // Gray 800 (Cold/Idle)
    }
}
