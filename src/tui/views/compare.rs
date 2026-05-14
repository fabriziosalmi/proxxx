use ratatui::{
    layout::Constraint,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;
use crate::util::sanitize::sanitize_display;

pub fn draw(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState, guests: &[u32]) {
    // Collect the actual guests from state
    let mut selected_guests = Vec::new();
    for &vmid in guests {
        if let Some(guest) = state.guests.iter().find(|g| g.vmid == vmid) {
            selected_guests.push(guest);
        }
    }

    if selected_guests.is_empty() {
        let p = Paragraph::new("No guests selected for comparison.")
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(p, area);
        return;
    }

    // Properties to compare
    let properties = vec![
        "vmid",
        "name",
        "type",
        "status",
        "node",
        "cpu cores",
        "ram",
        "disk",
        "tags",
    ];

    let mut rows = Vec::new();

    for prop in properties {
        let mut row_cells = vec![CellContent::Str(prop.to_string())];

        let mut all_same = true;
        let mut first_val = None;

        for guest in &selected_guests {
            let val = match prop {
                "vmid" => guest.vmid.to_string(),
                "name" => sanitize_display(&guest.name).into_owned(),
                "type" => format!("{:?}", guest.guest_type),
                "status" => format!("{:?}", guest.status),
                "node" => sanitize_display(&guest.node).into_owned(),
                "cpu cores" => guest.cpus.to_string(),
                "ram" => format_bytes(guest.maxmem),
                "disk" => format_bytes(guest.maxdisk),
                "tags" => sanitize_display(&guest.tags).into_owned(),
                _ => String::new(),
            };

            if let Some(ref first) = first_val {
                if *first != val {
                    all_same = false;
                }
            } else {
                first_val = Some(val.clone());
            }

            row_cells.push(CellContent::Str(val));
        }

        let style = if all_same {
            Style::default().fg(Theme::TEXT)
        } else {
            Style::default().fg(Theme::WARNING)
        };

        let row = Row::new(row_cells.into_iter().map(|c| match c {
            CellContent::Str(s) => ratatui::widgets::Cell::from(s),
        }))
        .style(style);

        rows.push(row);
    }

    let mut widths = vec![Constraint::Min(15)];
    for _ in &selected_guests {
        widths.push(Constraint::Percentage(
            (100 / selected_guests.len() as u16).max(10),
        ));
    }

    let mut header_cells = vec!["Property".to_string()];
    for guest in &selected_guests {
        header_cells.push(format!(
            "{} ({})",
            guest.vmid,
            sanitize_display(&guest.name)
        ));
    }

    let header = Row::new(header_cells)
        .style(Theme::header())
        .bottom_margin(1);

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(Line::from(vec![
                Span::raw(" Config Drift Detector "),
                Span::styled(
                    format!("({} guests) ", selected_guests.len()),
                    Style::default().fg(Theme::ACCENT),
                ),
            ]))
            .borders(Borders::ALL)
            .border_style(Theme::border()),
    );

    f.render_widget(table, area);
}

enum CellContent {
    Str(String),
}

fn format_bytes(bytes: u64) -> String {
    const GB: u64 = 1_073_741_824;
    const TB: u64 = 1_099_511_627_776;
    if bytes >= TB {
        format!("{:.1}T", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else {
        format!("{:.0}M", bytes as f64 / 1_048_576.0)
    }
}
