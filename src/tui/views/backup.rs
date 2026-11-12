use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;
use crate::util::sanitize::sanitize_display;

#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(" Backup health ", Theme::title()),
        Span::styled(" cluster-wide vzdump audit ", Theme::dim()),
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

    let header = Row::new(vec![
        "vmid",
        "name",
        "node",
        "last ok",
        "duration",
        "fails (30d)",
        "health",
    ])
    .style(Theme::header())
    .height(1);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut rows = Vec::new();

    for guest in &state.guests {
        let vmid_str = guest.vmid.to_string();
        let mut guest_tasks: Vec<_> = state
            .cluster_tasks
            .iter()
            .filter(|t| t.task_type == "vzdump" && t.id == vmid_str)
            .collect();

        guest_tasks.sort_by_key(|t| t.starttime);
        guest_tasks.reverse();

        let mut last_ok_time = 0;
        let mut last_ok_duration = 0;
        let mut failures = 0;

        let thirty_days_ago = now.saturating_sub(30 * 24 * 3600);

        for task in &guest_tasks {
            if task.starttime < thirty_days_ago {
                continue;
            }

            let is_ok = task.status.as_deref().unwrap_or("").starts_with("OK");

            if is_ok && last_ok_time == 0 {
                last_ok_time = task.starttime;
                if let Some(end) = task.endtime {
                    last_ok_duration = end.saturating_sub(task.starttime);
                }
            }

            if !is_ok && task.endtime.is_some() {
                failures += 1;
            }
        }

        let days_since_ok = if last_ok_time > 0 {
            (now.saturating_sub(last_ok_time)) / 86400
        } else {
            999
        };

        let (health_str, health_style) = if last_ok_time == 0 {
            (
                "unprotected".to_string(),
                Style::default()
                    .fg(Theme::DANGER)
                    .add_modifier(Modifier::BOLD),
            )
        } else if days_since_ok > 7 {
            (
                format!("stale ({days_since_ok}d)"),
                Style::default().fg(Theme::WARNING),
            )
        } else if failures > 0 {
            ("degraded".to_string(), Style::default().fg(Theme::WARNING))
        } else {
            ("healthy".to_string(), Style::default().fg(Theme::SUCCESS))
        };

        let last_ok_str = if last_ok_time > 0 {
            let elapsed = now.saturating_sub(last_ok_time);
            if elapsed < 3600 {
                format!("{}m ago", elapsed / 60)
            } else if elapsed < 86400 {
                format!("{}h {}m ago", elapsed / 3600, (elapsed % 3600) / 60)
            } else {
                format!("{}d {}h ago", elapsed / 86400, (elapsed % 86400) / 3600)
            }
        } else {
            "-".to_string()
        };

        let duration_str = if last_ok_duration > 0 {
            let m = last_ok_duration / 60;
            let s = last_ok_duration % 60;
            format!("{m}m {s}s")
        } else {
            "-".to_string()
        };

        rows.push(Row::new(vec![
            Cell::from(guest.vmid.to_string()),
            Cell::from(sanitize_display(&guest.name).into_owned()),
            Cell::from(sanitize_display(&guest.node).into_owned()),
            Cell::from(last_ok_str),
            Cell::from(duration_str),
            Cell::from(if failures > 0 {
                failures.to_string()
            } else {
                "-".to_string()
            }),
            // Colour means "look here": only the health cell carries
            // it, not the vmid, name and node of the row.
            Cell::from(Span::styled(health_str, health_style)),
        ]));
    }

    let widths = [
        Constraint::Length(6),  // vmid
        Constraint::Length(20), // name
        Constraint::Length(12), // node
        Constraint::Length(18), // last ok
        Constraint::Length(10), // duration
        Constraint::Length(14), // failures
        Constraint::Length(15), // health
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Theme::border()),
    );

    f.render_widget(table, chunks[1]);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::api::types::{Guest, GuestStatus};
    use ratatui::{backend::TestBackend, Terminal};

    /// A guest with no backup is flagged in the health cell only: its
    /// vmid, name and node keep the default colour.
    #[test]
    fn only_the_health_cell_is_coloured() {
        let mut state = AppState::new();
        state.guests = vec![Guest {
            vmid: 4242,
            name: "nobackup".into(),
            node: "pve1".into(),
            status: GuestStatus::Running,
            ..Guest::default()
        }];
        let mut terminal = Terminal::new(TestBackend::new(110, 12)).expect("terminal");
        terminal.draw(|f| draw(f, f.area(), &state)).expect("draw");
        let buf = terminal.backend().buffer().clone();
        let y = (0..buf.area.height)
            .find(|&y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    .contains("4242")
            })
            .expect("guest row");
        let line: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
        let col = |needle: &str| {
            u16::try_from(line[..line.find(needle).expect(needle)].chars().count()).expect("u16")
        };
        assert_ne!(
            buf[(col("4242"), y)].fg,
            Theme::DANGER,
            "vmid must not be red: {line}"
        );
        assert_ne!(
            buf[(col("nobackup"), y)].fg,
            Theme::DANGER,
            "name must not be red: {line}"
        );
        assert_eq!(
            buf[(col("unprotected"), y)].fg,
            Theme::DANGER,
            "health is red: {line}"
        );
    }
}
